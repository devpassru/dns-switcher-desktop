use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FallbackDNSOption {
    Disabled,
    #[default]
    System,
    Yandex,
    Cloudflare,
    Google,
    Custom,
}

impl FallbackDNSOption {
    pub fn title(&self) -> &'static str {
        match self {
            Self::Disabled => "Отключить (без фоллбэка)",
            Self::System => "Системный (DHCP роутера)",
            Self::Yandex => "Яндекс.DNS (77.88.8.8)",
            Self::Cloudflare => "Cloudflare (1.1.1.1)",
            Self::Google => "Google (8.8.8.8)",
            Self::Custom => "Указать свой IPv4…",
        }
    }

    pub fn static_ip(&self) -> Option<&'static str> {
        match self {
            Self::Yandex => Some("77.88.8.8"),
            Self::Cloudflare => Some("1.1.1.1"),
            Self::Google => Some("8.8.8.8"),
            Self::Disabled | Self::System | Self::Custom => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionSource {
    Doh,
    Cache,
    StaleCache,
    Excluded,
    Fallback,
    Error,
}

impl ResolutionSource {
    pub fn title(&self) -> &'static str {
        match self {
            Self::Doh => "DoH",
            Self::Cache => "Кэш",
            Self::StaleCache => "Кэш (резервный)",
            Self::Excluded => "Исключение",
            Self::Fallback => "Фоллбэк",
            Self::Error => "Ошибка",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DNSResolutionRecord {
    pub id: String,
    pub timestamp_ms: i64,
    pub domain: String,
    pub qtype: String,
    pub source: ResolutionSource,
    pub server_name: String,
    pub latency_ms: u64,
    pub resolved_ips: Vec<String>,
    pub is_success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DNSProvider {
    pub id: String,
    pub name: String,
    pub subtitle: String,
    pub doh_url: String,
    pub dot_host: String,
    pub bootstrap_ips: Vec<String>,
    pub plain_dns_supported: bool,
    pub website_url: String,
    #[serde(default)]
    pub is_built_in: bool,
    #[serde(default = "default_true")]
    pub is_enabled_in_menu_bar: bool,
}

fn default_true() -> bool {
    true
}

impl DNSProvider {
    pub fn doh_host(&self) -> String {
        reqwest::Url::parse(&self.doh_url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .unwrap_or_else(|| self.dot_host.clone())
    }

    pub fn built_in_providers() -> Vec<DNSProvider> {
        Vec::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProviderHealth {
    #[default]
    Unknown,
    Checking,
    Healthy {
        #[serde(rename = "latencyMs")]
        latency_ms: u64,
        #[serde(rename = "resolvedIP")]
        resolved_ip: String,
    },
    Degraded {
        #[serde(rename = "latencyMs")]
        latency_ms: u64,
        reason: String,
    },
    Unreachable {
        reason: String,
    },
}

impl ProviderHealth {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy { .. })
    }

    pub fn latency_ms(&self) -> Option<u64> {
        match self {
            Self::Healthy { latency_ms, .. } | Self::Degraded { latency_ms, .. } => Some(*latency_ms),
            _ => None,
        }
    }

    pub fn badge_text(&self) -> String {
        match self {
            Self::Unknown => "Не проверен".to_string(),
            Self::Checking => "Проверка…".to_string(),
            Self::Healthy { latency_ms, .. } => format!("{latency_ms} мс"),
            Self::Degraded { latency_ms, reason } => format!("{latency_ms} мс • {reason}"),
            Self::Unreachable { reason } => reason.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub providers: Vec<DNSProvider>,
    pub selected_provider_id: Option<String>,
    pub last_selected_provider_id: Option<String>,
    #[serde(default)]
    pub fallback_option: FallbackDNSOption,
    #[serde(default)]
    pub custom_fallback_ip: String,
    #[serde(default)]
    pub excluded_domains: Vec<String>,
    #[serde(default = "default_true")]
    pub keep_doh_over_vpn: bool,
    #[serde(default)]
    pub auto_failover_enabled: bool,
    #[serde(default = "default_true")]
    pub reset_dns_on_quit: bool,
    #[serde(default)]
    pub autostart_enabled: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            providers: DNSProvider::built_in_providers(),
            selected_provider_id: None,
            last_selected_provider_id: None,
            fallback_option: FallbackDNSOption::System,
            custom_fallback_ip: String::new(),
            excluded_domains: Vec::new(),
            keep_doh_over_vpn: true,
            auto_failover_enabled: false,
            reset_dns_on_quit: true,
            autostart_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum UpdateStatus {
    #[default]
    Idle,
    Checking,
    UpToDate,
    Available {
        version: String,
        #[serde(rename = "tagName")]
        tag_name: String,
        #[serde(rename = "releaseUrl")]
        release_url: String,
        #[serde(rename = "downloadUrl")]
        download_url: String,
    },
    Failed {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateSnapshot {
    pub app_version: String,
    pub platform: String,
    pub dns_stack: String,
    pub service_kind: String,
    pub required_bridge_version: u32,
    pub providers: Vec<DNSProvider>,
    pub selected_provider_id: Option<String>,
    pub health_map: HashMap<String, ProviderHealth>,
    pub is_bridge_installed: bool,
    pub is_bridge_up_to_date: bool,
    pub port53_conflict: Option<String>,
    pub auto_failover_enabled: bool,
    pub autostart_enabled: bool,
    pub reset_dns_on_quit: bool,
    pub keep_doh_over_vpn: bool,
    pub is_dns_overridden_by_vpn: bool,
    pub is_vpn_active: bool,
    pub fallback_option: FallbackDNSOption,
    pub custom_fallback_ip: String,
    pub resolved_fallback_ip: String,
    pub excluded_domains: Vec<String>,
    pub status_message: String,
    pub active_mode_text: String,
    pub short_status_text: String,
    pub is_checking_all: bool,
    pub consecutive_failures: u32,
    pub total_resolved_count: u64,
    pub history_count: usize,
    pub update_status: UpdateStatus,
}
