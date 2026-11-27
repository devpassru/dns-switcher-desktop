use std::net::Ipv4Addr;

const PROXY_BUNDLE_KEYWORDS: &[&str] = &[
    "v2ray",
    "v2box",
    "happ",
    "outline",
    "sing-box",
    "singbox",
    "clash",
    "mihomo",
    "shadowrocket",
    "nekoray",
    "hiddify",
    "xray",
    "amnezia",
    "nekobox",
];

pub fn is_valid_non_loopback_ipv4(ip: &str) -> bool {
    let trimmed = ip.trim();
    if trimmed.is_empty() || trimmed.starts_with("127.") || trimmed == "0.0.0.0" {
        return false;
    }
    trimmed.parse::<Ipv4Addr>().is_ok()
}

/// Normalizes a user-entered domain exclusion rule
/// (e.g. `*.corp.example.com`, `.example.com`, `https://git.corp.local/path` -> `corp.example.com`, `example.com`, `git.corp.local`).
pub fn normalize_domain_rule(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_lowercase();
    if s.is_empty() {
        return None;
    }

    if s.contains("://") {
        if let Ok(url) = reqwest::Url::parse(&s) {
            if let Some(host) = url.host_str() {
                s = host.to_lowercase();
            }
        }
    } else if let Some(idx) = s.find('/') {
        s.truncate(idx);
    }

    if let Some(idx) = s.find(':') {
        s.truncate(idx);
    }

    loop {
        if let Some(rest) = s.strip_prefix("*.") {
            s = rest.to_string();
        } else if let Some(rest) = s.strip_prefix('.') {
            s = rest.to_string();
        } else if let Some(rest) = s.strip_prefix('*') {
            s = rest.to_string();
        } else {
            break;
        }
    }

    while s.ends_with('.') {
        s.pop();
    }

    let s = s.trim().to_string();
    if s.is_empty() || s.contains(' ') {
        return None;
    }
    Some(s)
}

/// Parses a comma/semicolon/whitespace-separated list of domain exclusion rules into normalized unique domains.
pub fn parse_domain_rules(raw: &str) -> Vec<String> {
    let mut result = Vec::new();
    for part in raw.split([',', ';', '\n', '\r', '\t', ' ']) {
        if let Some(normalized) = normalize_domain_rule(part) {
            if !result.contains(&normalized) {
                result.push(normalized);
            }
        }
    }
    result
}

/// Checks whether a queried domain matches any rule in `excluded_domains` (exact or subdomain match).
pub fn is_domain_excluded(domain: &str, excluded_domains: &[String]) -> bool {
    let clean = domain.trim().trim_matches('.').to_lowercase();
    if clean.is_empty() {
        return false;
    }
    for rule in excluded_domains {
        if rule.is_empty() {
            continue;
        }
        if clean == *rule || clean.ends_with(&format!(".{rule}")) {
            return true;
        }
    }
    false
}

/// Returns true for known FakeIP / virtual proxy DNS addresses used by proxy tunnels (198.18.0.0/15, 172.19.0.2).
pub fn is_fake_ip_address(ip: &str) -> bool {
    let trimmed = ip.trim();
    if trimmed == "172.19.0.2" {
        return true;
    }
    if !is_valid_non_loopback_ipv4(trimmed) {
        return false;
    }
    trimmed.starts_with("198.18.") || trimmed.starts_with("198.19.")
}

/// Returns true if an adapter/bundle/process identifier matches a known proxy / FakeIP tunnel client.
pub fn is_known_proxy_identifier(identifier: &str) -> bool {
    let lower = identifier.trim().to_lowercase();
    if lower.is_empty() {
        return false;
    }
    PROXY_BUNDLE_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_normalization_and_matching() {
        let rules = parse_domain_rules("*.company.ru, https://git.corp.local/repo; .internal");
        assert_eq!(rules, vec!["company.ru", "git.corp.local", "internal"]);
        assert!(is_domain_excluded("jira.company.ru", &rules));
        assert!(is_domain_excluded("company.ru", &rules));
        assert!(is_domain_excluded("app.internal", &rules));
        assert!(!is_domain_excluded("mycompany.ru", &rules));
    }

    #[test]
    fn test_ipv4_and_fake_ip() {
        assert!(is_valid_non_loopback_ipv4("77.88.8.8"));
        assert!(!is_valid_non_loopback_ipv4("127.0.0.1"));
        assert!(!is_valid_non_loopback_ipv4("0.0.0.0"));
        assert!(!is_valid_non_loopback_ipv4("999.1.1.1"));

        assert!(is_fake_ip_address("198.18.0.2"));
        assert!(is_fake_ip_address("198.19.0.1"));
        assert!(is_fake_ip_address("172.19.0.2"));
        assert!(!is_fake_ip_address("10.1.155.1"));
        assert!(!is_fake_ip_address("192.168.31.1"));
    }

    #[test]
    fn test_proxy_identifiers() {
        assert!(is_known_proxy_identifier("v2rayN TUN"));
        assert!(is_known_proxy_identifier("Clash Meta Tunnel"));
        assert!(is_known_proxy_identifier("sing-box tun0"));
        assert!(is_known_proxy_identifier("Outline VPN"));
        assert!(!is_known_proxy_identifier("WireGuard Tunnel"));
        assert!(!is_known_proxy_identifier("PANGP Virtual Ethernet Adapter"));
    }
}
