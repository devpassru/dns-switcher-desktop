use super::parsers::{
    collect_unique_valid_ips, is_windows_virtual_or_excluded_physical, is_windows_vpn_adapter,
    parse_windows_adapters_json, should_intercept_vpn_dns, WindowsAdapterSnapshot,
};
use super::SystemDnsBackend;
use crate::bridge_ipc::BRIDGE_VERSION;
use crate::rules::{is_valid_non_loopback_ipv4, normalize_domain_rule};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SERVICE_NAME: &str = "DNSSwitcherBridge";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VpnBackupState {
    // interface_index -> original static DNS servers (empty = was DHCP)
    adapters: HashMap<u32, Vec<String>>,
}

pub struct WindowsDnsBackend;

impl Default for WindowsDnsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsDnsBackend {
    pub fn new() -> Self {
        Self
    }

    fn program_data_dir() -> PathBuf {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(base).join("DNSSwitcher")
    }

    fn bridge_exe_path() -> PathBuf {
        Self::program_data_dir().join("dns-switcher-bridge.exe")
    }

    fn bridge_version_path() -> PathBuf {
        Self::program_data_dir().join("bridge.version")
    }

    fn vpn_backup_path() -> PathBuf {
        Self::program_data_dir().join("vpn-dns-backup.json")
    }

    fn run_powershell(script: &str) -> Result<String, String> {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-Command",
                script,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to run PowerShell: {e}"))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Err(if !stderr.is_empty() { stderr } else { stdout })
        }
    }

    fn query_adapters(&self) -> Vec<WindowsAdapterSnapshot> {
        let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$items = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
    $idx = $_.ifIndex
    $guid = $_.InterfaceGuid
    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)
    $ipCfg = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4
    $dhcpList = @()
    if ($guid) {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
        $reg = Get-ItemProperty -Path $regPath
        if ($reg -and $reg.DhcpNameServer) {
            $dhcpList = @($reg.DhcpNameServer -split '[\s,]+' | Where-Object { $_ -ne '' })
        }
    }
    $suffix = (Get-DnsClient -InterfaceIndex $idx).ConnectionSpecificSuffix
    [PSCustomObject]@{
        interfaceIndex = [int]$idx
        name = [string]$_.Name
        interfaceDescription = [string]$_.InterfaceDescription
        interfaceGuid = [string]$guid
        hardwareInterface = [bool]$_.HardwareInterface
        status = [string]$_.Status
        dnsServers = @($dns)
        dhcpDnsServers = @($dhcpList)
        connectionSpecificSuffix = [string]$suffix
        interfaceMetric = if ($ipCfg) { [int]$ipCfg.InterfaceMetric } else { $null }
    }
}
@($items) | ConvertTo-Json -Depth 4 -Compress
"#;
        match Self::run_powershell(script) {
            Ok(out) => parse_windows_adapters_json(&out),
            Err(_) => Vec::new(),
        }
    }

    fn load_backup() -> VpnBackupState {
        let Ok(raw) = std::fs::read_to_string(Self::vpn_backup_path()) else {
            return VpnBackupState::default();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    fn save_backup(state: &VpnBackupState) {
        let dir = Self::program_data_dir();
        let _ = std::fs::create_dir_all(&dir);
        if state.adapters.is_empty() {
            let _ = std::fs::remove_file(Self::vpn_backup_path());
        } else if let Ok(json) = serde_json::to_string_pretty(state) {
            let _ = std::fs::write(Self::vpn_backup_path(), json);
        }
    }

    fn ps_single_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "''"))
    }
}

impl SystemDnsBackend for WindowsDnsBackend {
    fn platform_name(&self) -> &'static str {
        "windows"
    }

    fn service_kind(&self) -> &'static str {
        "Windows Service"
    }

    fn dns_stack_description(&self) -> String {
        "Windows DNS Client (Win32 / NetAdapter)".to_string()
    }

    fn detect_dhcp_dns_server(&self) -> Option<String> {
        let adapters = self.query_adapters();
        for a in &adapters {
            if a.hardware_interface && !is_windows_virtual_or_excluded_physical(&a.name, &a.interface_description) {
                for ip in &a.dhcp_dns_servers {
                    if is_valid_non_loopback_ipv4(ip) {
                        return Some(ip.clone());
                    }
                }
            }
        }
        // Fallback to default IPv4 gateway NextHop
        let gw = Self::run_powershell(
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop",
        )
        .ok()?;
        let clean = gw.trim().to_string();
        if is_valid_non_loopback_ipv4(&clean) {
            Some(clean)
        } else {
            None
        }
    }

    fn detect_active_vpn_dns_servers(&self, ignoring_bootstrap_ips: &HashSet<String>) -> Vec<String> {
        let adapters = self.query_adapters();
        let backup = Self::load_backup();
        let mut candidates = Vec::new();

        for a in adapters {
            if is_windows_vpn_adapter(&a.name, &a.interface_description) {
                if let Some(orig) = backup.adapters.get(&a.interface_index) {
                    candidates.extend(orig.clone());
                }
                candidates.extend(a.dns_servers);
                candidates.extend(a.dhcp_dns_servers);
            }
        }
        collect_unique_valid_ips(candidates, ignoring_bootstrap_ips)
    }

    fn detect_active_vpn_search_domains(&self) -> Vec<String> {
        let adapters = self.query_adapters();
        let mut out = Vec::new();
        for a in adapters {
            if is_windows_vpn_adapter(&a.name, &a.interface_description) {
                if let Some(suffix) = a.connection_specific_suffix {
                    if let Some(norm) = normalize_domain_rule(&suffix) {
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
        self.query_adapters()
            .iter()
            .any(|a| is_windows_vpn_adapter(&a.name, &a.interface_description))
    }

    fn is_global_dns_overridden_by_vpn(&self) -> bool {
        let adapters = self.query_adapters();
        let mut min_physical_metric = u32::MAX;
        let mut vpn_overrides = false;

        for a in &adapters {
            if a.hardware_interface && !is_windows_virtual_or_excluded_physical(&a.name, &a.interface_description) {
                if let Some(m) = a.interface_metric {
                    min_physical_metric = min_physical_metric.min(m);
                }
            }
        }

        for a in &adapters {
            if is_windows_vpn_adapter(&a.name, &a.interface_description)
                && should_intercept_vpn_dns(&a.name, &a.interface_description, &a.dns_servers, &[])
            {
                let m = a.interface_metric.unwrap_or(100);
                if m <= min_physical_metric || !a.dns_servers.iter().any(|ip| ip == "127.0.0.1") {
                    vpn_overrides = true;
                }
            }
        }

        vpn_overrides
    }

    fn detect_system_and_vpn_dns_servers(
        &self,
        fallback_ip: Option<&str>,
        ignoring_bootstrap_ips: &HashSet<String>,
    ) -> Vec<String> {
        let mut candidates = self.detect_active_vpn_dns_servers(ignoring_bootstrap_ips);
        let adapters = self.query_adapters();
        for a in adapters {
            if a.hardware_interface && !is_windows_virtual_or_excluded_physical(&a.name, &a.interface_description) {
                candidates.extend(a.dhcp_dns_servers);
                candidates.extend(a.dns_servers);
            }
        }
        if let Some(fb) = fallback_ip {
            candidates.push(fb.to_string());
        }
        collect_unique_valid_ips(candidates, ignoring_bootstrap_ips)
    }

    fn current_system_dns_servers(&self) -> Vec<String> {
        let adapters = self.query_adapters();
        let mut physical = Vec::new();
        for a in adapters {
            if a.hardware_interface && !is_windows_virtual_or_excluded_physical(&a.name, &a.interface_description) {
                if a.dns_servers.iter().any(|s| s == "127.0.0.1") {
                    return a.dns_servers;
                }
                if physical.is_empty() && !a.dns_servers.is_empty() {
                    physical = a.dns_servers;
                }
            }
        }
        physical
    }

    fn has_port53_conflict(&self) -> Option<String> {
        // Check if another process (e.g. ICS SharedAccess or dnscrypt-proxy) owns 127.0.0.1:53 or 0.0.0.0:53
        let script = r#"
$p = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq '127.0.0.1' -or $_.LocalAddress -eq '0.0.0.0' } | Select-Object -First 1 -ExpandProperty OwningProcess
if ($p) { (Get-Process -Id $p -ErrorAction SilentlyContinue).ProcessName }
"#;
        if let Ok(proc_name) = Self::run_powershell(script) {
            let clean = proc_name.trim();
            if !clean.is_empty() && !clean.eq_ignore_ascii_case("dns-switcher-bridge") {
                return Some(format!("Порт 53 занят процессом: {clean}"));
            }
        }
        None
    }

    fn set_system_dns(&self, servers: &[String]) -> Result<(), String> {
        let adapters = self.query_adapters();
        let physical_indices: Vec<u32> = adapters
            .iter()
            .filter(|a| {
                a.hardware_interface
                    && !is_windows_virtual_or_excluded_physical(&a.name, &a.interface_description)
            })
            .map(|a| a.interface_index)
            .collect();

        if physical_indices.is_empty() {
            return Err("Активные физические сетевые адаптеры не найдены".to_string());
        }

        let mut script_lines = Vec::new();
        if servers.is_empty() {
            for idx in physical_indices {
                script_lines.push(format!(
                    "Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses"
                ));
            }
        } else {
            let formatted: Vec<String> = servers.iter().map(|s| Self::ps_single_quote(s)).collect();
            let array_expr = format!("@({})", formatted.join(","));
            for idx in physical_indices {
                script_lines.push(format!(
                    "Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses {array_expr}"
                ));
            }
        }
        script_lines.push("Clear-DnsClientCache".to_string());
        Self::run_powershell(&script_lines.join("; "))?;
        Ok(())
    }

    fn reset_to_system_default(&self) -> Result<(), String> {
        self.set_system_dns(&[])
    }

    fn flush_dns_cache(&self) -> Result<(), String> {
        Self::run_powershell("Clear-DnsClientCache")?;
        Ok(())
    }

    fn reconcile_vpn_guard(&self, enabled: bool, doh_active: bool) -> Result<bool, String> {
        if !enabled || !doh_active {
            let prev = Self::load_backup();
            if prev.adapters.is_empty() {
                return Ok(false);
            }
            self.restore_vpn_guard()?;
            return Ok(true);
        }

        let adapters = self.query_adapters();
        let mut backup = Self::load_backup();
        let mut modified = false;

        for a in &adapters {
            if !is_windows_vpn_adapter(&a.name, &a.interface_description) {
                continue;
            }
            if a.dns_servers == ["127.0.0.1"] {
                continue;
            }
            if should_intercept_vpn_dns(&a.name, &a.interface_description, &a.dns_servers, &[]) {
                backup
                    .adapters
                    .entry(a.interface_index)
                    .or_insert_with(|| a.dns_servers.clone());
                let cmd = format!(
                    "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses @('127.0.0.1')",
                    a.interface_index
                );
                if Self::run_powershell(&cmd).is_ok() {
                    modified = true;
                }
            }
        }

        if modified {
            Self::save_backup(&backup);
            let _ = self.flush_dns_cache();
        }
        Ok(modified)
    }

    fn restore_vpn_guard(&self) -> Result<(), String> {
        let backup = Self::load_backup();
        if backup.adapters.is_empty() {
            return Ok(());
        }
        for (idx, orig) in backup.adapters {
            let cmd = if orig.is_empty() {
                format!("Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses")
            } else {
                let arr = orig
                    .iter()
                    .map(|s| Self::ps_single_quote(s))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses @({arr})")
            };
            let _ = Self::run_powershell(&cmd);
        }
        Self::save_backup(&VpnBackupState::default());
        let _ = self.flush_dns_cache();
        Ok(())
    }

    fn is_bridge_binary_up_to_date(&self) -> bool {
        if !Self::bridge_exe_path().exists() {
            return false;
        }
        let Ok(ver_str) = std::fs::read_to_string(Self::bridge_version_path()) else {
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

        let target_dir = Self::program_data_dir();
        let target_exe = Self::bridge_exe_path();
        let ver_path = Self::bridge_version_path();
        let script_path = std::env::temp_dir().join("dnsswitcher-install-service.ps1");

        let bin_path_arg = format!("\"{}\" --service", target_exe.display());
        let ps_script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$dir = {dir}
$src = {src}
$dst = {dst}
$verFile = {ver_file}
New-Item -ItemType Directory -Path $dir -Force | Out-Null
sc.exe stop {svc} 2>$null | Out-Null
Start-Sleep -Milliseconds 500
sc.exe delete {svc} 2>$null | Out-Null
Start-Sleep -Milliseconds 400
Copy-Item -Path $src -Destination $dst -Force
Set-Content -Path $verFile -Value '{ver}' -NoNewline -Encoding UTF8
sc.exe create {svc} binPath= {bin_arg} start= auto DisplayName= 'AI DNS Switcher Bridge' | Out-Null
sc.exe description {svc} 'Local DNS-over-HTTPS port 53 bridge and VPN DNS guard for AI DNS Switcher' | Out-Null
sc.exe failure {svc} reset= 86400 actions= restart/3000/restart/5000/restart/10000 | Out-Null
sc.exe start {svc} | Out-Null
Clear-DnsClientCache
"#,
            dir = Self::ps_single_quote(&target_dir.to_string_lossy()),
            src = Self::ps_single_quote(&source_bridge_bin.to_string_lossy()),
            dst = Self::ps_single_quote(&target_exe.to_string_lossy()),
            ver_file = Self::ps_single_quote(&ver_path.to_string_lossy()),
            svc = SERVICE_NAME,
            ver = BRIDGE_VERSION,
            bin_arg = Self::ps_single_quote(&bin_path_arg),
        );

        std::fs::write(&script_path, ps_script)
            .map_err(|e| format!("Не удалось записать скрипт установки: {e}"))?;

        let launch_elevated = format!(
            "$p = Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',{script} -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
            script = Self::ps_single_quote(&script_path.to_string_lossy())
        );
        let res = Self::run_powershell(&launch_elevated);
        let _ = std::fs::remove_file(&script_path);
        res.map(|_| ()).map_err(|e| {
            if e.is_empty() {
                "Установка отменена пользователем (UAC)".to_string()
            } else {
                e
            }
        })
    }

    fn uninstall_bridge_service(&self) -> Result<(), String> {
        let target_dir = Self::program_data_dir();
        let script_path = std::env::temp_dir().join("dnsswitcher-uninstall-service.ps1");
        let ps_script = format!(
            r#"
$ErrorActionPreference = 'SilentlyContinue'
sc.exe stop {svc} | Out-Null
Start-Sleep -Milliseconds 500
sc.exe delete {svc} | Out-Null
Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true }} | ForEach-Object {{
    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
}}
Clear-DnsClientCache
Remove-Item -Path {dir} -Recurse -Force
"#,
            svc = SERVICE_NAME,
            dir = Self::ps_single_quote(&target_dir.to_string_lossy()),
        );

        std::fs::write(&script_path, ps_script)
            .map_err(|e| format!("Не удалось записать скрипт удаления: {e}"))?;

        let launch_elevated = format!(
            "$p = Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',{script} -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
            script = Self::ps_single_quote(&script_path.to_string_lossy())
        );
        let res = Self::run_powershell(&launch_elevated);
        let _ = std::fs::remove_file(&script_path);
        res.map(|_| ())
    }
}
