use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// Parses queried domain name and qtype (1 = A, 28 = AAAA, 65 = HTTPS) from a DNS wire-format query.
pub fn parse_question(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 12 {
        return None;
    }
    let mut idx = 12usize;
    let mut labels = Vec::new();

    while idx < data.len() {
        let len = data[idx] as usize;
        if len == 0 {
            idx += 1;
            break;
        }
        // Pointer compression shouldn't occur in first question QNAME
        if (len & 0xC0) == 0xC0 {
            return None;
        }
        idx += 1;
        if idx + len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[idx..idx + len]).ok()?;
        labels.push(label.to_lowercase());
        idx += len;
    }

    if idx + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[idx], data[idx + 1]]);
    Some((labels.join("."), qtype))
}

/// Builds a standard DNS wire-format query for an A record (qtype = 1, qclass = 1).
pub fn build_a_query(domain: &str, tx_id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&tx_id.to_be_bytes());
    // Flags: Standard query, Recursion Desired (0x0100)
    packet.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    for part in domain.split('.').filter(|s| !s.is_empty()) {
        let bytes = part.as_bytes();
        if bytes.len() >= 64 {
            continue;
        }
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
    }
    packet.push(0x00); // root label
    // QTYPE = A (1), QCLASS = IN (1)
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    packet
}

/// Skips a DNS compressed/uncompressed domain name starting at `start`.
pub fn skip_name(data: &[u8], start: usize) -> Option<usize> {
    let mut idx = start;
    let mut jumps = 0usize;
    while idx < data.len() {
        let len = data[idx] as usize;
        if len == 0 {
            return Some(idx + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if idx + 1 >= data.len() {
                return None;
            }
            return Some(idx + 2);
        }
        idx += 1 + len;
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
    None
}

/// Extracts all IPv4 A record strings from a DNS wire-format response.
pub fn extract_a_records(data: &[u8]) -> Vec<String> {
    if data.len() < 12 {
        return Vec::new();
    }
    let qd_count = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an_count = u16::from_be_bytes([data[6], data[7]]) as usize;
    if an_count == 0 {
        return Vec::new();
    }

    let mut idx = 12usize;
    for _ in 0..qd_count {
        let Some(next) = skip_name(data, idx) else {
            return Vec::new();
        };
        if next + 4 > data.len() {
            return Vec::new();
        }
        idx = next + 4;
    }

    let mut ips = Vec::new();
    for _ in 0..an_count {
        let Some(after_name) = skip_name(data, idx) else {
            break;
        };
        if after_name + 10 > data.len() {
            break;
        }
        idx = after_name;
        let rtype = u16::from_be_bytes([data[idx], data[idx + 1]]);
        let rd_length = u16::from_be_bytes([data[idx + 8], data[idx + 9]]) as usize;
        idx += 10;
        if idx + rd_length > data.len() {
            break;
        }
        if rtype == 1 && rd_length == 4 {
            ips.push(format!(
                "{}.{}.{}.{}",
                data[idx],
                data[idx + 1],
                data[idx + 2],
                data[idx + 3]
            ));
        }
        idx += rd_length;
    }
    ips
}

pub fn with_transaction_id(tx_id: u16, packet: &[u8]) -> Vec<u8> {
    if packet.len() < 2 {
        return packet.to_vec();
    }
    let mut copy = packet.to_vec();
    let bytes = tx_id.to_be_bytes();
    copy[0] = bytes[0];
    copy[1] = bytes[1];
    copy
}

pub fn transaction_id(packet: &[u8]) -> u16 {
    if packet.len() < 2 {
        return 0;
    }
    u16::from_be_bytes([packet[0], packet[1]])
}

pub fn rcode(packet: &[u8]) -> u8 {
    if packet.len() < 4 {
        return 0;
    }
    packet[3] & 0x0F
}

/// Synthesizes a direct DNS response for a bootstrap query (A records if qtype == 1/255, empty NOERROR for AAAA/HTTPS).
pub fn synthesize_bootstrap_response(query: &[u8], ipv4_list: &[String], ttl: u32) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let (_, qtype) = parse_question(query)?;
    let after_qname = skip_name(query, 12)?;
    if after_qname + 4 > query.len() {
        return None;
    }
    let question_section = &query[12..(after_qname + 4)];

    let valid_ips: Vec<[u8; 4]> = if qtype == 1 || qtype == 255 {
        ipv4_list
            .iter()
            .filter_map(|s| s.trim().parse::<std::net::Ipv4Addr>().ok().map(|ip| ip.octets()))
            .collect()
    } else {
        Vec::new()
    };

    let mut resp = Vec::with_capacity(64 + valid_ips.len() * 16);
    resp.push(query[0]);
    resp.push(query[1]);
    // Flags: QR=1, RD=1, RA=1, RCODE=0 -> 0x8180
    resp.extend_from_slice(&[0x81, 0x80]);
    // QDCOUNT = 1
    resp.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT
    let an_count = valid_ips.len() as u16;
    resp.extend_from_slice(&an_count.to_be_bytes());
    // NSCOUNT = 0, ARCOUNT = 0
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    resp.extend_from_slice(question_section);

    for octets in valid_ips {
        resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to offset 12
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE=A, CLASS=IN
        resp.extend_from_slice(&ttl.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        resp.extend_from_slice(&octets);
    }

    Some(resp)
}

pub fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        28 => "AAAA".to_string(),
        5 => "CNAME".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        65 => "HTTPS".to_string(),
        12 => "PTR".to_string(),
        33 => "SRV".to_string(),
        257 => "CAA".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE{other}"),
    }
}

pub fn extract_min_ttl(data: &[u8], default_ttl: u32) -> u32 {
    if data.len() < 12 {
        return default_ttl;
    }
    let qd_count = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an_count = u16::from_be_bytes([data[6], data[7]]) as usize;
    if an_count == 0 {
        return default_ttl;
    }

    let mut idx = 12usize;
    for _ in 0..qd_count {
        let Some(next) = skip_name(data, idx) else {
            return default_ttl;
        };
        if next + 4 > data.len() {
            return default_ttl;
        }
        idx = next + 4;
    }

    let mut min_ttl = u32::MAX;
    for _ in 0..an_count {
        let Some(after_name) = skip_name(data, idx) else {
            break;
        };
        if after_name + 10 > data.len() {
            break;
        }
        idx = after_name;
        let ttl = u32::from_be_bytes([data[idx + 4], data[idx + 5], data[idx + 6], data[idx + 7]]);
        let rd_length = u16::from_be_bytes([data[idx + 8], data[idx + 9]]) as usize;
        idx += 10;
        if ttl > 0 && ttl < min_ttl {
            min_ttl = ttl;
        }
        if idx + rd_length > data.len() {
            break;
        }
        idx += rd_length;
    }

    if min_ttl == u32::MAX {
        default_ttl
    } else {
        min_ttl
    }
}

pub fn build_failure_response(query: &[u8], rcode_val: u8) -> Vec<u8> {
    if query.len() < 12 {
        return vec![
            0x00,
            0x00,
            0x81,
            0x80 | (rcode_val & 0x0F),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];
    }
    let mut resp = Vec::with_capacity(query.len());
    resp.push(query[0]);
    resp.push(query[1]);
    let rd_bit = query[2] & 0x01;
    resp.push(0x80 | rd_bit);
    resp.push(0x80 | (rcode_val & 0x0F));
    resp.push(query[4]);
    resp.push(query[5]);
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    if let Some(after_q) = skip_name(query, 12) {
        if after_q + 4 <= query.len() {
            resp.extend_from_slice(&query[12..(after_q + 4)]);
        }
    }
    resp
}

pub fn base64url_encode(data: &[u8]) -> String {
    let zeroed = with_transaction_id(0, data);
    URL_SAFE_NO_PAD.encode(zeroed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_a_query() {
        let q = build_a_query("chatgpt.com", 0xABCD);
        assert_eq!(transaction_id(&q), 0xABCD);
        let (domain, qtype) = parse_question(&q).unwrap();
        assert_eq!(domain, "chatgpt.com");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn test_synthesize_bootstrap_and_extract_a() {
        let q = build_a_query("dns.comss.one", 0x1234);
        let ips = vec!["195.133.25.16".to_string(), "212.109.195.93".to_string()];
        let resp = synthesize_bootstrap_response(&q, &ips, 300).unwrap();
        assert_eq!(transaction_id(&resp), 0x1234);
        assert_eq!(rcode(&resp), 0);
        assert_eq!(extract_a_records(&resp), ips);
        assert_eq!(extract_min_ttl(&resp, 60), 300);
    }

    #[test]
    fn test_synthesize_aaaa_bootstrap_empty_noerror() {
        let mut q = build_a_query("dns.comss.one", 0x2222);
        let len = q.len();
        // Replace QTYPE=1 with QTYPE=28 (AAAA)
        q[len - 4] = 0x00;
        q[len - 3] = 0x1C;
        let resp = synthesize_bootstrap_response(&q, &["195.133.25.16".to_string()], 300).unwrap();
        assert_eq!(rcode(&resp), 0);
        assert!(extract_a_records(&resp).is_empty());
    }

    #[test]
    fn test_servfail_synthesis() {
        let q = build_a_query("test.local", 0xBEEF);
        let fail = build_failure_response(&q, 2);
        assert_eq!(transaction_id(&fail), 0xBEEF);
        assert_eq!(rcode(&fail), 2);
        let (domain, _) = parse_question(&fail).unwrap();
        assert_eq!(domain, "test.local");
    }

    #[test]
    fn test_base64url_zeroes_tx_id() {
        let q1 = build_a_query("example.com", 0x1111);
        let q2 = build_a_query("example.com", 0x9999);
        assert_eq!(base64url_encode(&q1), base64url_encode(&q2));
        assert!(!base64url_encode(&q1).contains('='));
    }
}
