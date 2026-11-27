pub mod parsers;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub mod mock;

use crate::models::FallbackDNSOption;
use crate::rules::is_valid_non_loopback_ipv4;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

pub trait SystemDnsBackend: Send + Sync {
    fn platform_name(&self) -> &'static str;
    fn service_kind(&self) -> &'static str;
    fn dns_stack_description(&self) -> String;

    fn detect_dhcp_dns_server(&self) -> Option<String>;
    fn detect_active_vpn_dns_servers(&self, ignoring_bootstrap_ips: &HashSet<String>) -> Vec<String>;
    fn detect_active_vpn_search_domains(&self) -> Vec<String>;
    fn has_active_vpn_interface(&self) -> bool;
    fn is_global_dns_overridden_by_vpn(&self) -> bool;
    fn detect_system_and_vpn_dns_servers(
        &self,
        fallback_ip: Option<&str>,
        ignoring_bootstrap_ips: &HashSet<String>,
    ) -> Vec<String>;
    fn current_system_dns_servers(&self) -> Vec<String>;
    fn has_port53_conflict(&self) -> Option<String>;

    fn set_system_dns(&self, servers: &[String]) -> Result<(), String>;
    fn reset_to_system_default(&self) -> Result<(), String>;
    fn flush_dns_cache(&self) -> Result<(), String>;

    fn reconcile_vpn_guard(&self, enabled: bool, doh_active: bool) -> Result<bool, String>;
    fn restore_vpn_guard(&self) -> Result<(), String>;

    fn is_bridge_binary_up_to_date(&self) -> bool;
    fn install_bridge_service(&self, source_bridge_bin: &Path) -> Result<(), String>;
    fn uninstall_bridge_service(&self) -> Result<(), String>;
}

pub fn default_backend() -> Arc<dyn SystemDnsBackend> {
    #[cfg(target_os = "windows")]
    {
        Arc::new(windows::WindowsDnsBackend::new())
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(linux::LinuxDnsBackend::new())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Arc::new(mock::MockDnsBackend::new())
    }
}

pub fn resolve_fallback_dns_ip(
    backend: &dyn SystemDnsBackend,
    option: FallbackDNSOption,
    custom_ip: &str,
) -> String {
    match option {
        FallbackDNSOption::Disabled => "disabled".to_string(),
        FallbackDNSOption::System => backend
            .detect_dhcp_dns_server()
            .unwrap_or_else(|| "77.88.8.8".to_string()),
        FallbackDNSOption::Yandex => "77.88.8.8".to_string(),
        FallbackDNSOption::Cloudflare => "1.1.1.1".to_string(),
        FallbackDNSOption::Google => "8.8.8.8".to_string(),
        FallbackDNSOption::Custom => {
            let clean = custom_ip.trim();
            if is_valid_non_loopback_ipv4(clean) {
                clean.to_string()
            } else {
                backend
                    .detect_dhcp_dns_server()
                    .unwrap_or_else(|| "77.88.8.8".to_string())
            }
        }
    }
}
