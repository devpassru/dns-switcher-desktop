use super::parsers::{
    collect_unique_valid_ips, is_linux_vpn_interface, parse_nmcli_connections, parse_resolv_conf,
    parse_resolvectl_status, should_intercept_vpn_dns, ResolvectlLink,
};
use super::SystemDnsBackend;
use crate::bridge_ipc::BRIDGE_VERSION;
use crate::rules::{is_valid_non_loopback_ipv4, normalize_domain_rule};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const SYSTEMD_UNIT_NAME: &str = "dnsswitcher-bridge.service";
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/dnsswitcher-bridge.service";
const BRIDGE_INSTALL_DIR: &str = "/usr/local/lib/dnsswitcher";
const BRIDGE_BIN_PATH: &str = "/usr/local/lib/dnsswitcher/dns-switcher-bridge";
const BRIDGE_VERSION_PATH: &str = "/usr/local/lib/dnsswitcher/bridge.version";
const STATE_DIR: &str = "/var/lib/dnsswitcher";
const RESOLV_BACKUP_PATH: &str = "/var/lib/dnsswitcher/resolv.conf.backup";
const VPN_BACKUP_PATH: &str = "/var/lib/dnsswitcher/vpn-dns-backup.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxDnsStack {
    SystemdResolved,
    NetworkManager,
    ResolvConf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LinuxVpnBackup {
    links: HashMap<String, Vec<String>>,
}

pub struct LinuxDnsBackend;

impl Default for LinuxDnsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxDnsBackend {
    pub fn new() -> Self {
        Self
    }

    fn run_cmd(bin: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(bin).args(args).output().ok()?;
        if out.status.success() {
            Some(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            None
        }
    }

    fn run_cmd_res(bin: &str, args: &[&str]) -> Result<String, String> {
        let out = Command::new(bin)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run {bin}: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Err(if !err.is_empty() { err } else { stdout })
        }
    }

    fn detect_stack() -> LinuxDnsStack {
        let resolved_active = Command::new("systemctl")
            .args(["is-active", "--quiet", "systemd-resolved"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if resolved_active && Self::run_cmd("which", &["resolvectl"]).is_some() {
            return LinuxDnsStack::SystemdResolved;
        }

        let nm_active = Command::new("systemctl")
            .args(["is-active", "--quiet", "NetworkManager"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if nm_active && Self::run_cmd("which", &["nmcli"]).is_some() {
            return LinuxDnsStack::NetworkManager;
        }

        LinuxDnsStack::ResolvConf
    }

    fn list_physical_interfaces() -> Vec<String> {
        let mut ifaces = Vec::new();
        let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
            return ifaces;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo"
                || is_linux_vpn_interface(&name)
                || name.starts_with("docker")
                || name.starts_with("br-")
                || name.starts_with("virbr")
                || name.starts_with("veth")
            {
                continue;
            }
            let path = entry.path();
            if !path.join("device").exists() {
                continue;
            }
            let oper = std::fs::read_to_string(path.join("operstate"))
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            if oper == "up" || oper == "unknown" {
                ifaces.push(name);
            }
        }
        ifaces
    }

    fn list_vpn_interfaces() -> Vec<String> {
        let mut ifaces = Vec::new();
        let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
            return ifaces;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !is_linux_vpn_interface(&name) {
                continue;
            }
            let oper = std::fs::read_to_string(entry.path().join("operstate"))
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            if oper == "up" || oper == "unknown" {
                ifaces.push(name);
            }
        }
        ifaces
    }

    fn resolvectl_links() -> Vec<ResolvectlLink> {
        Self::run_cmd("resolvectl", &["status"])
            .map(|out| parse_resolvectl_status(&out))
            .unwrap_or_default()
    }

    fn load_vpn_backup() -> LinuxVpnBackup {
        let Ok(raw) = std::fs::read_to_string(VPN_BACKUP_PATH) else {
            return LinuxVpnBackup::default();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    fn save_vpn_backup(backup: &LinuxVpnBackup) {
        let _ = std::fs::create_dir_all(STATE_DIR);
        if backup.links.is_empty() {
            let _ = std::fs::remove_file(VPN_BACKUP_PATH);
        } else if let Ok(json) = serde_json::to_string_pretty(backup) {
            let _ = std::fs::write(VPN_BACKUP_PATH, json);
        }
    }

    fn shell_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

impl SystemDnsBackend for LinuxDnsBackend {
    fn platform_name(&self) -> &'static str {
        "linux"
    }

    fn service_kind(&self) -> &'static str {
        "systemd"
    }

    fn dns_stack_description(&self) -> String {
        match Self::detect_stack() {
            LinuxDnsStack::SystemdResolved => "systemd-resolved (resolvectl)".to_string(),
            LinuxDnsStack::NetworkManager => "NetworkManager (nmcli)".to_string(),
            LinuxDnsStack::ResolvConf => "/etc/resolv.conf".to_string(),
        }
    }

    fn detect_dhcp_dns_server(&self) -> Option<String> {
        let physical: HashSet<String> = Self::list_physical_interfaces().into_iter().collect();

        if let Some(out) = Self::run_cmd("nmcli", &["-g", "IP4.DNS", "device", "show"]) {
            for line in out.lines() {
                for tok in line.split(['|', ',', ' ']) {
                    if is_valid_non_loopback_ipv4(tok) {
                        return Some(tok.trim().to_string());
                    }
                }
            }
        }

        for link in Self::resolvectl_links() {
            if physical.contains(&link.name) {
                for ip in link.dns_servers {
                    if is_valid_non_loopback_ipv4(&ip) {
                        return Some(ip);
                    }
                }
            }
        }

        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            let (servers, _) = parse_resolv_conf(&content);
            for ip in servers {
                if is_valid_non_loopback_ipv4(&ip) {
                    return Some(ip);
                }
            }
        }

        // Default gateway from `ip route show default`
        if let Some(route) = Self::run_cmd("ip", &["route", "show", "default"]) {
            let tokens: Vec<&str> = route.split_whitespace().collect();
            if let Some(pos) = tokens.iter().position(|&t| t == "via") {
                if let Some(gw) = tokens.get(pos + 1) {
                    if is_valid_non_loopback_ipv4(gw) {
                        return Some((*gw).to_string());
                    }
                }
            }
        }

        None
    }

    fn detect_active_vpn_dns_servers(&self, ignoring_bootstrap_ips: &HashSet<String>) -> Vec<String> {
        let mut candidates = Vec::new();
        let backup = Self::load_vpn_backup();

        for link in Self::resolvectl_links() {
            if is_linux_vpn_interface(&link.name) {
                if let Some(orig) = backup.links.get(&link.name) {
                    candidates.extend(orig.clone());
                }
                candidates.extend(link.dns_servers);
            }
        }

        collect_unique_valid_ips(candidates, ignoring_bootstrap_ips)
    }

    fn detect_active_vpn_search_domains(&self) -> Vec<String> {
        let mut out = Vec::new();
        for link in Self::resolvectl_links() {
            if is_linux_vpn_interface(&link.name) {
                for raw in link.dns_domains {
                    let clean = raw.trim().trim_start_matches('~');
                    if clean == "." || clean.is_empty() {
                        continue;
                    }
                    if let Some(norm) = normalize_domain_rule(clean) {
                        if !out.contains(&norm) {
                            out.push(norm);
                        }
                    }
                }
            }
        }
        out
    }

    fn has_active_vpn_interface(&self) -> bool {
        !Self::list_vpn_interfaces().is_empty()
    }

    fn is_global_dns_overridden_by_vpn(&self) -> bool {
        for link in Self::resolvectl_links() {
            if is_linux_vpn_interface(&link.name)
                && link.default_route == Some(true)
                && should_intercept_vpn_dns(&link.name, "", &link.dns_servers, &link.dns_domains)
            {
                return true;
            }
        }
        false
    }

    fn detect_system_and_vpn_dns_servers(
        &self,
        fallback_ip: Option<&str>,
        ignoring_bootstrap_ips: &HashSet<String>,
    ) -> Vec<String> {
        let mut candidates = self.detect_active_vpn_dns_servers(ignoring_bootstrap_ips);
        let physical: HashSet<String> = Self::list_physical_interfaces().into_iter().collect();

        for link in Self::resolvectl_links() {
            if physical.contains(&link.name) {
                candidates.extend(link.dns_servers);
            }
        }
        if let Some(dhcp) = self.detect_dhcp_dns_server() {
            candidates.push(dhcp);
        }
        if let Some(fb) = fallback_ip {
            candidates.push(fb.to_string());
        }
        collect_unique_valid_ips(candidates, ignoring_bootstrap_ips)
    }

    fn current_system_dns_servers(&self) -> Vec<String> {
        match Self::detect_stack() {
            LinuxDnsStack::SystemdResolved => {
                let physical: HashSet<String> = Self::list_physical_interfaces().into_iter().collect();
                let mut fallback = Vec::new();
                for link in Self::resolvectl_links() {
                    if physical.contains(&link.name) {
                        if link.dns_servers.iter().any(|ip| ip == "127.0.0.1") {
                            return link.dns_servers;
                        }
                        if fallback.is_empty() && !link.dns_servers.is_empty() {
                            fallback = link.dns_servers;
                        }
                    }
                }
                fallback
            }
            LinuxDnsStack::NetworkManager => {
                if let Some(out) = Self::run_cmd("nmcli", &["-g", "IP4.DNS", "device", "show"]) {
                    let mut servers = Vec::new();
                    for line in out.lines() {
                        for tok in line.split(['|', ',', ' ']) {
                            let clean = tok.trim();
                            if clean.parse::<std::net::Ipv4Addr>().is_ok()
                                && !servers.contains(&clean.to_string())
                            {
                                servers.push(clean.to_string());
                            }
                        }
                    }
                    return servers;
                }
                Vec::new()
            }
            LinuxDnsStack::ResolvConf => std::fs::read_to_string("/etc/resolv.conf")
                .map(|c| parse_resolv_conf(&c).0)
                .unwrap_or_default(),
        }
    }

    fn has_port53_conflict(&self) -> Option<String> {
        // systemd-resolved uses 127.0.0.53:53, which does NOT conflict with 127.0.0.1:53
        if let Some(out) = Self::run_cmd("ss", &["-H", "-ulnp", "sport", "=", ":53"]) {
            for line in out.lines() {
                if (line.contains("127.0.0.1:53") || line.contains("0.0.0.0:53") || line.contains("*:53"))
                    && !line.contains("dns-switcher-bridge")
                {
                    return Some("Порт 127.0.0.1:53 занят другой службой (например dnsmasq/unbound)".to_string());
                }
            }
        }
        None
    }

    fn set_system_dns(&self, servers: &[String]) -> Result<(), String> {
        let physical = Self::list_physical_interfaces();
        match Self::detect_stack() {
            LinuxDnsStack::SystemdResolved => {
                if physical.is_empty() {
                    return Err("Активные физические сетевые интерфейсы не найдены".to_string());
                }
                if servers.is_empty() {
                    for iface in &physical {
                        Self::run_cmd_res("resolvectl", &["revert", iface])?;
                    }
                } else {
                    for iface in &physical {
                        let mut dns_args = vec!["dns", iface.as_str()];
                        for s in servers {
                            dns_args.push(s.as_str());
                        }
                        Self::run_cmd_res("resolvectl", &dns_args)?;
                        Self::run_cmd_res("resolvectl", &["domain", iface, "~."])?;
                    }
                }
                let _ = self.flush_dns_cache();
                Ok(())
            }
            LinuxDnsStack::NetworkManager => {
                let raw = Self::run_cmd_res(
                    "nmcli",
                    &["-t", "-f", "UUID,DEVICE,TYPE", "connection", "show", "--active"],
                )?;
                let conns = parse_nmcli_connections(&raw);
                let phys_set: HashSet<String> = physical.into_iter().collect();
                let mut touched = 0usize;

                for conn in conns {
                    if !phys_set.contains(&conn.device) {
                        continue;
                    }
                    if servers.is_empty() {
                        Self::run_cmd_res(
                            "nmcli",
                            &["connection", "modify", &conn.uuid, "ipv4.ignore-auto-dns", "no", "ipv4.dns", ""],
                        )?;
                    } else {
                        let joined = servers.join(" ");
                        Self::run_cmd_res(
                            "nmcli",
                            &["connection", "modify", &conn.uuid, "ipv4.ignore-auto-dns", "yes", "ipv4.dns", &joined],
                        )?;
                    }
                    let _ = Self::run_cmd("nmcli", &["device", "reapply", &conn.device]);
                    touched += 1;
                }
                if touched == 0 {
                    return Err("Не найдено активных подключений NetworkManager".to_string());
                }
                Ok(())
            }
            LinuxDnsStack::ResolvConf => {
                let _ = std::fs::create_dir_all(STATE_DIR);
                if servers.is_empty() {
                    if Path::new(RESOLV_BACKUP_PATH).exists() {
                        std::fs::copy(RESOLV_BACKUP_PATH, "/etc/resolv.conf")
                            .map_err(|e| format!("Ошибка восстановления /etc/resolv.conf: {e}"))?;
                    }
                } else {
                    if !Path::new(RESOLV_BACKUP_PATH).exists() {
                        let _ = std::fs::copy("/etc/resolv.conf", RESOLV_BACKUP_PATH);
                    }
                    let mut body = String::from("# Managed by AI DNS Switcher\n");
                    for s in servers {
                        body.push_str(&format!("nameserver {s}\n"));
                    }
                    std::fs::write("/etc/resolv.conf", body)
                        .map_err(|e| format!("Ошибка записи /etc/resolv.conf: {e}"))?;
                }
                Ok(())
            }
        }
    }

    fn reset_to_system_default(&self) -> Result<(), String> {
        self.set_system_dns(&[])
    }

    fn flush_dns_cache(&self) -> Result<(), String> {
        if Self::detect_stack() == LinuxDnsStack::SystemdResolved {
            let _ = Self::run_cmd("resolvectl", &["flush-caches"]);
        }
        Ok(())
    }

    fn reconcile_vpn_guard(&self, enabled: bool, doh_active: bool) -> Result<bool, String> {
        if Self::detect_stack() != LinuxDnsStack::SystemdResolved {
            return Ok(false);
        }

        if !enabled || !doh_active {
            let backup = Self::load_vpn_backup();
            if backup.links.is_empty() {
                return Ok(false);
            }
            self.restore_vpn_guard()?;
            return Ok(true);
        }

        let mut backup = Self::load_vpn_backup();
        let mut modified = false;

        for link in Self::resolvectl_links() {
            if !is_linux_vpn_interface(&link.name) {
                continue;
            }
            if link.dns_servers == ["127.0.0.1"] {
                continue;
            }
            if should_intercept_vpn_dns(&link.name, "", &link.dns_servers, &link.dns_domains) {
                backup
                    .links
                    .entry(link.name.clone())
                    .or_insert_with(|| link.dns_servers.clone());
                if Self::run_cmd_res("resolvectl", &["dns", &link.name, "127.0.0.1"]).is_ok() {
                    let _ = Self::run_cmd("resolvectl", &["domain", &link.name, "~."]);
                    modified = true;
                }
            }
        }

        if modified {
            Self::save_vpn_backup(&backup);
            let _ = self.flush_dns_cache();
        }
        Ok(modified)
    }

    fn restore_vpn_guard(&self) -> Result<(), String> {
        let backup = Self::load_vpn_backup();
        if backup.links.is_empty() {
            return Ok(());
        }
        if Self::detect_stack() == LinuxDnsStack::SystemdResolved {
            for (iface, orig) in backup.links {
                if orig.is_empty() {
                    let _ = Self::run_cmd("resolvectl", &["revert", &iface]);
                } else {
                    let mut args = vec!["dns", iface.as_str()];
                    for s in &orig {
                        args.push(s.as_str());
                    }
                    let _ = Self::run_cmd("resolvectl", &args);
                }
            }
        }
        Self::save_vpn_backup(&LinuxVpnBackup::default());
        let _ = self.flush_dns_cache();
        Ok(())
    }

    fn is_bridge_binary_up_to_date(&self) -> bool {
        if !PathBuf::from(BRIDGE_BIN_PATH).exists() {
            return false;
        }
        let Ok(ver_str) = std::fs::read_to_string(BRIDGE_VERSION_PATH) else {
            return false;
        };
        ver_str
            .trim()
            .parse::<u32>()
            .map(|v| v >= BRIDGE_VERSION)
            .unwrap_or(false)
    }

    fn install_bridge_service(&self, source_bridge_bin: &Path) -> Result<(), String> {
        if !source_bridge_bin.exists() {
            return Err(format!(
                "Не найден бинарный файл моста: {}",
                source_bridge_bin.display()
            ));
        }

        let unit_content = format!(
            "[Unit]\n\
Description=AI DNS Switcher Bridge (127.0.0.1:53 -> DoH)\n\
After=network-online.target\n\
Wants=network-online.target\n\n\
[Service]\n\
Type=simple\n\
ExecStart={BRIDGE_BIN_PATH} --service\n\
Restart=always\n\
RestartSec=2\n\n\
[Install]\n\
WantedBy=multi-user.target\n"
        );

        let temp_unit = std::env::temp_dir().join(SYSTEMD_UNIT_NAME);
        std::fs::write(&temp_unit, unit_content)
            .map_err(|e| format!("Не удалось создать systemd unit: {e}"))?;

        let shell_script = format!(
            "mkdir -p {dir} {state} && \
cp -f {src} {dst} && \
chmod 755 {dst} && \
echo {ver} > {ver_file} && \
chmod 644 {ver_file} && \
cp -f {tmp_unit} {unit_path} && \
chmod 644 {unit_path} && \
systemctl daemon-reload && \
systemctl enable --now {unit_name}",
            dir = Self::shell_quote(BRIDGE_INSTALL_DIR),
            state = Self::shell_quote(STATE_DIR),
            src = Self::shell_quote(&source_bridge_bin.to_string_lossy()),
            dst = Self::shell_quote(BRIDGE_BIN_PATH),
            ver = BRIDGE_VERSION,
            ver_file = Self::shell_quote(BRIDGE_VERSION_PATH),
            tmp_unit = Self::shell_quote(&temp_unit.to_string_lossy()),
            unit_path = Self::shell_quote(SYSTEMD_UNIT_PATH),
            unit_name = SYSTEMD_UNIT_NAME,
        );

        let res = Self::run_cmd_res("pkexec", &["/bin/sh", "-c", &shell_script]);
        let _ = std::fs::remove_file(&temp_unit);
        res.map(|_| ()).map_err(|e| {
            if e.contains("dismissed") || e.is_empty() {
                "Установка отменена пользователем (pkexec)".to_string()
            } else {
                e
            }
        })
    }

    fn uninstall_bridge_service(&self) -> Result<(), String> {
        let shell_script = format!(
            "systemctl disable --now {unit_name} 2>/dev/null || true; \
rm -f {unit_path}; \
rm -rf {dir}; \
systemctl daemon-reload",
            unit_name = SYSTEMD_UNIT_NAME,
            unit_path = Self::shell_quote(SYSTEMD_UNIT_PATH),
            dir = Self::shell_quote(BRIDGE_INSTALL_DIR),
        );
        Self::run_cmd_res("pkexec", &["/bin/sh", "-c", &shell_script]).map(|_| ())
    }
}
