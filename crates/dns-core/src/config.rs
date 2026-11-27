use crate::models::{AppSettings, DNSProvider};
use crate::rules::normalize_domain_rule;
use directories::ProjectDirs;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub fn config_dir() -> PathBuf {
    if let Some(proj) = ProjectDirs::from("ru", "devpass", "DNSSwitcher") {
        return proj.config_dir().to_path_buf();
    }
    std::env::temp_dir().join("dnsswitcher")
}

pub fn settings_path() -> PathBuf {
    config_dir().join("settings.json")
}

pub fn load_settings() -> AppSettings {
    load_settings_from(&settings_path())
}

pub fn load_settings_from(path: &Path) -> AppSettings {
    let Ok(raw) = std::fs::read_to_string(path) else {
        let defaults = AppSettings::default();
        let _ = save_settings_to(path, &defaults);
        return defaults;
    };

    let Ok(mut parsed) = serde_json::from_str::<AppSettings>(&raw) else {
        return AppSettings::default();
    };

    synchronize_providers(&mut parsed);
    parsed.excluded_domains = parsed
        .excluded_domains
        .iter()
        .filter_map(|d| normalize_domain_rule(d))
        .collect();
    parsed
}

pub fn save_settings(settings: &AppSettings) -> Result<(), String> {
    save_settings_to(&settings_path(), settings)
}

pub fn save_settings_to(path: &Path, settings: &AppSettings) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {e}"))?;
    }
    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("Failed to write settings: {e}"))
}

fn synchronize_providers(settings: &mut AppSettings) {
    let built_ins = DNSProvider::built_in_providers();
    let mut updated = Vec::new();
    let mut seen_ids = HashSet::new();

    for item in settings.providers.drain(..) {
        if let Some(built_in) = built_ins.iter().find(|b| b.id == item.id) {
            let mut fresh = built_in.clone();
            fresh.is_enabled_in_menu_bar = item.is_enabled_in_menu_bar;
            seen_ids.insert(fresh.id.clone());
            updated.push(fresh);
        } else if !item.is_built_in {
            let mut custom = item;
            if custom.bootstrap_ips.is_empty()
                && custom.doh_host().to_lowercase().contains("tunnelhunt.ru")
            {
                custom.bootstrap_ips = vec!["135.106.164.115".to_string()];
            }
            if seen_ids.insert(custom.id.clone()) {
                updated.push(custom);
            }
        }
    }

    for built_in in built_ins {
        if !seen_ids.contains(&built_in.id) {
            updated.push(built_in);
        }
    }

    settings.providers = updated;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_roundtrip_and_sync() {
        let dir = std::env::temp_dir().join(format!("dnsswitcher-cfg-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("settings.json");

        let mut settings = AppSettings::default();
        assert!(settings.providers.is_empty());
        settings.providers.push(DNSProvider {
            id: "custom-test".to_string(),
            name: "Custom Test".to_string(),
            subtitle: "dns.example.com".to_string(),
            doh_url: "https://dns.example.com/dns-query".to_string(),
            dot_host: "dns.example.com".to_string(),
            bootstrap_ips: vec!["1.1.1.1".to_string()],
            plain_dns_supported: true,
            website_url: "https://example.com/".to_string(),
            is_built_in: false,
            is_enabled_in_menu_bar: false,
        });
        settings.excluded_domains = vec!["*.Corp.Local".to_string()];
        save_settings_to(&path, &settings).unwrap();

        let loaded = load_settings_from(&path);
        assert!(!loaded.providers[0].is_enabled_in_menu_bar);
        assert_eq!(loaded.excluded_domains, vec!["corp.local"]);
        assert_eq!(loaded.providers.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
