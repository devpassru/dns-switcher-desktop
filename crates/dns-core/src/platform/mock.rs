use super::SystemDnsBackend;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;

#[derive(Default)]
struct MockState {
    dns_servers: Vec<String>,
    bridge_installed: bool,
    vpn_active: bool,
    vpn_overridden: bool,
}

pub struct MockDnsBackend {
    state: Mutex<MockState>,
}

impl Default for MockDnsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDnsBackend {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MockState::default()),
        }
    }
}

impl SystemDnsBackend for MockDnsBackend {
    fn platform_name(&self) -> &'static str {
        "macos-dev"
    }

    fn service_kind(&self) -> &'static str {
        "Dev Mock Service"
    }

    fn dns_stack_description(&self) -> String {
        "Dev Mock (превью на macOS; целевые ОС: Windows / Linux)".to_string()
    }

    fn detect_dhcp_dns_server(&self) -> Option<String> {
        Some("192.168.1.1".to_string())
    }

    fn detect_active_vpn_dns_servers(&self, ignoring_bootstrap_ips: &HashSet<String>) -> Vec<String> {
        let _ = ignoring_bootstrap_ips;
        Vec::new()
    }

    fn detect_active_vpn_search_domains(&self) -> Vec<String> {
        Vec::new()
    }

    fn has_active_vpn_interface(&self) -> bool {
        self.state.lock().map(|g| g.vpn_active).unwrap_or(false)
    }

    fn is_global_dns_overridden_by_vpn(&self) -> bool {
        self.state.lock().map(|g| g.vpn_overridden).unwrap_or(false)
    }

    fn detect_system_and_vpn_dns_servers(
        &self,
        fallback_ip: Option<&str>,
        ignoring_bootstrap_ips: &HashSet<String>,
    ) -> Vec<String> {
        let mut out = vec!["192.168.1.1".to_string()];
        if let Some(fb) = fallback_ip {
            if !ignoring_bootstrap_ips.contains(fb) && !out.contains(&fb.to_string()) {
                out.push(fb.to_string());
            }
        }
        out
    }

    fn current_system_dns_servers(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|g| g.dns_servers.clone())
            .unwrap_or_default()
    }

    fn has_port53_conflict(&self) -> Option<String> {
        None
    }

    fn set_system_dns(&self, servers: &[String]) -> Result<(), String> {
        if let Ok(mut g) = self.state.lock() {
            g.dns_servers = servers.to_vec();
        }
        Ok(())
    }

    fn reset_to_system_default(&self) -> Result<(), String> {
        self.set_system_dns(&[])
    }

    fn flush_dns_cache(&self) -> Result<(), String> {
        Ok(())
    }

    fn reconcile_vpn_guard(&self, _enabled: bool, _doh_active: bool) -> Result<bool, String> {
        Ok(false)
    }

    fn restore_vpn_guard(&self) -> Result<(), String> {
        Ok(())
    }

    fn is_bridge_binary_up_to_date(&self) -> bool {
        self.state
            .lock()
            .map(|g| g.bridge_installed)
            .unwrap_or(false)
    }

    fn install_bridge_service(&self, _source_bridge_bin: &Path) -> Result<(), String> {
        if let Ok(mut g) = self.state.lock() {
            g.bridge_installed = true;
        }
        Ok(())
    }

    fn uninstall_bridge_service(&self) -> Result<(), String> {
        if let Ok(mut g) = self.state.lock() {
            g.bridge_installed = false;
            g.dns_servers.clear();
        }
        Ok(())
    }
}
