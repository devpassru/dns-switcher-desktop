use crate::rules::{
    is_fake_ip_address, is_known_proxy_identifier, is_valid_non_loopback_ipv4, normalize_domain_rule,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvectlLink {
    pub index: u32,
    pub name: String,
    pub dns_servers: Vec<String>,
    pub dns_domains: Vec<String>,
    pub default_route: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NmcliConnection {
    pub uuid: String,
    pub device: String,
    pub conn_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsAdapterSnapshot {
    pub interface_index: u32,
    pub name: String,
    pub interface_description: String,
    pub interface_guid: Option<String>,
    pub hardware_interface: bool,
    pub status: String,
    pub dns_servers: Vec<String>,
    pub dhcp_dns_servers: Vec<String>,
    pub connection_specific_suffix: Option<String>,
    pub interface_metric: Option<u32>,
}

pub fn is_linux_vpn_interface(name: &str) -> bool {
    let lower = name.trim().to_lowercase();
    lower.starts_with("tun")
        || lower.starts_with("tap")
        || lower.starts_with("wg")
        || lower.starts_with("ppp")
        || lower.starts_with("gpd")
        || lower.starts_with("utun")
        || lower.starts_with("nordlynx")
        || lower.starts_with("proton")
        || lower.starts_with("cscotun")
        || lower.starts_with("tailscale")
        || lower.starts_with("mullvad")
}

pub fn is_windows_virtual_or_excluded_physical(name: &str, desc: &str) -> bool {
    let combined = format!("{name} {desc}").to_lowercase();
    combined.contains("hyper-v")
        || combined.contains("vethernet")
        || combined.contains("wsl")
        || combined.contains("docker")
        || combined.contains("vmware")
        || combined.contains("virtualbox")
        || combined.contains("loopback")
        || combined.contains("bluetooth")
        || is_windows_vpn_adapter(name, desc)
}

pub fn is_windows_vpn_adapter(name: &str, desc: &str) -> bool {
    let combined = format!("{name} {desc}").to_lowercase();
    let keywords = [
        "wireguard",
        "wintun",
        "tap-windows",
        "openvpn",
        "pangp",
        "globalprotect",
        "anyconnect",
        "cisco",
        "fortinet",
        "forticlient",
        "pulse secure",
        "juniper",
        "tailscale",
        "nordlynx",
        "mullvad",
        "protonvpn",
        "tunnel",
        "vpn",
        "ppp",
        "wan miniport",
    ];
    keywords.iter().any(|k| combined.contains(k)) || is_known_proxy_identifier(&combined)
}

pub fn should_intercept_vpn_dns(
    adapter_name: &str,
    adapter_desc: &str,
    dns_servers: &[String],
    domains: &[String],
) -> bool {
    if is_known_proxy_identifier(adapter_name) || is_known_proxy_identifier(adapter_desc) {
        return false;
    }

    // Domain-scoped only (no catch-all "~." / "" / "*" / ".") -> leave alone
    if !domains.is_empty()
        && !domains
            .iter()
            .any(|d| matches!(d.trim(), "~." | "" | "*" | "."))
    {
        return false;
    }

    if dns_servers.iter().any(|ip| is_fake_ip_address(ip)) {
        return false;
    }

    dns_servers
        .iter()
        .any(|ip| is_valid_non_loopback_ipv4(ip))
}

/// Parses `resolvectl status` output into per-link records.
pub fn parse_resolvectl_status(output: &str) -> Vec<ResolvectlLink> {
    let mut links = Vec::new();
    let mut current: Option<ResolvectlLink> = None;

    for raw_line in output.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with("Link ") {
            if let Some(prev) = current.take() {
                links.push(prev);
            }
            if let Some(open_paren) = trimmed.find('(') {
                if let Some(close_paren) = trimmed[open_paren..].find(')') {
                    let num_part = trimmed["Link ".len()..open_paren].trim();
                    let index = num_part.parse::<u32>().unwrap_or(0);
                    let name = trimmed[open_paren + 1..open_paren + close_paren]
                        .trim()
                        .to_string();
                    current = Some(ResolvectlLink {
                        index,
                        name,
                        dns_servers: Vec::new(),
                        dns_domains: Vec::new(),
                        default_route: None,
                    });
                }
            }
            continue;
        }

        let Some(ref mut link) = current else {
            continue;
        };

        if let Some(rest) = trimmed.strip_prefix("Current DNS Server:") {
            let ip = rest.trim();
            if ip.parse::<std::net::Ipv4Addr>().is_ok() && !link.dns_servers.contains(&ip.to_string()) {
                link.dns_servers.push(ip.to_string());
            }
        } else if let Some(rest) = trimmed
            .strip_prefix("DNS Servers:")
            .or_else(|| trimmed.strip_prefix("Fallback DNS Servers:"))
        {
            for tok in rest.split_whitespace() {
                if tok.parse::<std::net::Ipv4Addr>().is_ok()
                    && !link.dns_servers.contains(&tok.to_string())
                {
                    link.dns_servers.push(tok.to_string());
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("DNS Domain:") {
            for tok in rest.split_whitespace() {
                if !link.dns_domains.contains(&tok.to_string()) {
                    link.dns_domains.push(tok.to_string());
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("Default Route:") {
            let v = rest.trim().to_lowercase();
            link.default_route = Some(v == "yes" || v == "true");
        }
    }

    if let Some(last) = current {
        links.push(last);
    }
    links
}

/// Parses `nmcli -t -f UUID,DEVICE,TYPE connection show --active`
pub fn parse_nmcli_connections(output: &str) -> Vec<NmcliConnection> {
    let mut res = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() >= 3 {
            let uuid = parts[0].trim().to_string();
            let device = parts[1].trim().to_string();
            let conn_type = parts[2].trim().to_string();
            if !uuid.is_empty() && !device.is_empty() && device != "--" {
                res.push(NmcliConnection {
                    uuid,
                    device,
                    conn_type,
                });
            }
        }
    }
    res
}

/// Parses `/etc/resolv.conf` `nameserver` and `search`/`domain` lines.
pub fn parse_resolv_conf(content: &str) -> (Vec<String>, Vec<String>) {
    let mut servers = Vec::new();
    let mut search_domains = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        if key == "nameserver" {
            if let Some(ip) = parts.next() {
                if ip.parse::<std::net::Ipv4Addr>().is_ok() && !servers.contains(&ip.to_string()) {
                    servers.push(ip.to_string());
                }
            }
        } else if key == "search" || key == "domain" {
            for dom in parts {
                if let Some(norm) = normalize_domain_rule(dom) {
                    if !search_domains.contains(&norm) {
                        search_domains.push(norm);
                    }
                }
            }
        }
    }

    (servers, search_domains)
}

/// Parses PowerShell `ConvertTo-Json` output of Windows adapters (handles single object or array).
pub fn parse_windows_adapters_json(json_str: &str) -> Vec<WindowsAdapterSnapshot> {
    let trimmed = json_str.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Vec::new();
    }
    if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<WindowsAdapterSnapshot>>(trimmed).unwrap_or_default()
    } else if trimmed.starts_with('{') {
        serde_json::from_str::<WindowsAdapterSnapshot>(trimmed)
            .map(|item| vec![item])
            .unwrap_or_default()
    } else {
        Vec::new()
    }
}

pub fn collect_unique_valid_ips(
    candidates: impl IntoIterator<Item = String>,
    ignoring: &HashSet<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for ip in candidates {
        let clean = ip.trim().to_string();
        if is_valid_non_loopback_ipv4(&clean)
            && !ignoring.contains(&clean)
            && !out.contains(&clean)
        {
            out.push(clean);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolvectl_status() {
        let sample = r#"
Global
       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported

Link 2 (enp3s0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS
Current DNS Server: 127.0.0.1
       DNS Servers: 127.0.0.1
        DNS Domain: ~.

Link 5 (tun0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS
     Default Route: yes
Current DNS Server: 10.16.5.200
       DNS Servers: 10.16.5.200 10.16.5.201
        DNS Domain: corp.local ~.
"#;
        let links = parse_resolvectl_status(sample);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].name, "enp3s0");
        assert_eq!(links[0].dns_servers, vec!["127.0.0.1"]);
        assert_eq!(links[1].name, "tun0");
        assert!(is_linux_vpn_interface(&links[1].name));
        assert_eq!(links[1].dns_servers, vec!["10.16.5.200", "10.16.5.201"]);
        assert_eq!(links[1].dns_domains, vec!["corp.local", "~."]);
        assert_eq!(links[1].default_route, Some(true));
    }

    #[test]
    fn test_parse_nmcli_and_resolv_conf() {
        let nmcli = "1111-2222:eth0:802-3-ethernet\n3333-4444:wg0:wireguard\n";
        let conns = parse_nmcli_connections(nmcli);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[1].device, "wg0");

        let resolv = "# Generated\nsearch corp.local internal.lan\nnameserver 127.0.0.1\nnameserver 77.88.8.8\n";
        let (servers, domains) = parse_resolv_conf(resolv);
        assert_eq!(servers, vec!["127.0.0.1", "77.88.8.8"]);
        assert_eq!(domains, vec!["corp.local", "internal.lan"]);
    }

    #[test]
    fn test_parse_windows_adapters_single_and_array() {
        let single = r#"{
            "interfaceIndex": 12,
            "name": "Ethernet",
            "interfaceDescription": "Intel(R) Ethernet Controller",
            "interfaceGuid": "{ABC-123}",
            "hardwareInterface": true,
            "status": "Up",
            "dnsServers": ["127.0.0.1"],
            "dhcpDnsServers": ["192.168.1.1"],
            "connectionSpecificSuffix": "home.arpa",
            "interfaceMetric": 25
        }"#;
        let parsed = parse_windows_adapters_json(single);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].interface_index, 12);
        assert!(!is_windows_virtual_or_excluded_physical(
            &parsed[0].name,
            &parsed[0].interface_description
        ));

        assert!(is_windows_vpn_adapter("wg-corp", "WireGuard Tunnel"));
        assert!(!should_intercept_vpn_dns(
            "v2rayN",
            "Wintun Userspace Tunnel",
            &["198.18.0.2".to_string()],
            &[]
        ));
        assert!(should_intercept_vpn_dns(
            "GlobalProtect",
            "PANGP Virtual Ethernet Adapter",
            &["10.1.155.1".to_string()],
            &["~.".to_string()]
        ));
    }
}
