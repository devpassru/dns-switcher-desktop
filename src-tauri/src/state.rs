use dns_core::bridge_ipc::{
    is_bridge_running, send_ipc_request, BridgeRequest, BridgeResponse, BRIDGE_VERSION,
};
use dns_core::config::{load_settings, save_settings};
use dns_core::doh_proxy::LocalDoHProxy;
use dns_core::history::DNSHistoryStore;
use dns_core::models::{
    AppSettings, AppStateSnapshot, DNSProvider, DNSResolutionRecord, FallbackDNSOption,
    ProviderHealth, UpdateStatus,
};
use dns_core::platform::{default_backend, resolve_fallback_dns_ip, SystemDnsBackend};
use dns_core::rules::{is_valid_non_loopback_ipv4, parse_domain_rules};
use dns_core::updater;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::Mutex;

struct RuntimeState {
    settings: AppSettings,
    health_map: HashMap<String, ProviderHealth>,
    is_bridge_installed: bool,
    is_bridge_up_to_date: bool,
    port53_conflict: Option<String>,
    is_dns_overridden_by_vpn: bool,
    is_vpn_active: bool,
    resolved_fallback_ip: String,
    status_message: String,
    active_mode_text: String,
    is_checking_all: bool,
    consecutive_failures: u32,
    update_status: UpdateStatus,
    last_network_fingerprint: String,
}

#[derive(Clone)]
pub struct AppController {
    app: AppHandle,
    backend: Arc<dyn SystemDnsBackend>,
    proxy: LocalDoHProxy,
    history: DNSHistoryStore,
    state: Arc<Mutex<RuntimeState>>,
    failure_streak: Arc<AtomicU32>,
}

impl AppController {
    pub async fn new(app: AppHandle) -> Self {
        let backend = default_backend();
        let history = DNSHistoryStore::new();
        let proxy = LocalDoHProxy::new(backend.clone(), history.clone());
        let settings = load_settings();

        let initial_fb = resolve_fallback_dns_ip(
            backend.as_ref(),
            settings.fallback_option,
            &settings.custom_fallback_ip,
        );
        proxy.set_fallback_server(&initial_fb);
        proxy.set_excluded_domains(&settings.excluded_domains);

        if let Some(active) = settings
            .selected_provider_id
            .as_ref()
            .and_then(|id| settings.providers.iter().find(|p| &p.id == id))
            .or_else(|| settings.providers.first())
        {
            proxy.configure(active.clone(), settings.providers.clone());
        }

        let runtime = RuntimeState {
            settings,
            health_map: HashMap::new(),
            is_bridge_installed: false,
            is_bridge_up_to_date: false,
            port53_conflict: None,
            is_dns_overridden_by_vpn: false,
            is_vpn_active: false,
            resolved_fallback_ip: if initial_fb == "disabled" {
                "Отключен".to_string()
            } else {
                initial_fb
            },
            status_message: "Готов к работе".to_string(),
            active_mode_text: "Системный DNS (по умолчанию)".to_string(),
            is_checking_all: false,
            consecutive_failures: 0,
            update_status: UpdateStatus::Idle,
            last_network_fingerprint: String::new(),
        };

        let controller = Self {
            app: app.clone(),
            backend,
            proxy,
            history,
            state: Arc::new(Mutex::new(runtime)),
            failure_streak: Arc::new(AtomicU32::new(0)),
        };

        // History updates -> notify frontend
        let hist_app = app.clone();
        controller.history.set_on_record(move |_| {
            let _ = hist_app.emit("history-updated", ());
        });

        // Query failure tracker (>= 3 consecutive failures -> auto-failover or warning)
        let outcome_ctrl = controller.clone();
        controller.proxy.set_on_query_outcome(move |is_success, server_name| {
            if is_success {
                outcome_ctrl.failure_streak.store(0, Ordering::Relaxed);
                return;
            }
            let streak = outcome_ctrl.failure_streak.fetch_add(1, Ordering::Relaxed) + 1;
            if streak >= 3 {
                let ctrl = outcome_ctrl.clone();
                tokio::spawn(async move {
                    ctrl.handle_consecutive_failures(streak, &server_name).await;
                });
            }
        });

        controller.proxy.start_if_needed();
        controller.refresh_system_state().await;
        controller.sync_bridge_settings().await;
        controller.start_background_tasks();

        controller
    }

    fn start_background_tasks(&self) {
        let ctrl_health = self.clone();
        tokio::spawn(async move {
            ctrl_health.check_all_providers_health().await;
            ctrl_health.check_for_updates(true).await;
        });

        let ctrl_net = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                ctrl_net.poll_network_changes().await;
            }
        });
    }

    async fn poll_network_changes(&self) {
        let backend = self.backend.clone();
        let (servers, vpn_active, vpn_overridden, dhcp) = tokio::task::spawn_blocking(move || {
            (
                backend.current_system_dns_servers(),
                backend.has_active_vpn_interface(),
                backend.is_global_dns_overridden_by_vpn(),
                backend.detect_dhcp_dns_server(),
            )
        })
        .await
        .unwrap_or_default();

        let fingerprint = format!("{servers:?}|{vpn_active}|{vpn_overridden}|{dhcp:?}");
        let changed = {
            let mut g = self.state.lock().await;
            if g.last_network_fingerprint.is_empty() {
                g.last_network_fingerprint = fingerprint;
                false
            } else if g.last_network_fingerprint != fingerprint {
                g.last_network_fingerprint = fingerprint;
                true
            } else {
                false
            }
        };

        if changed {
            self.proxy.reset_network_connections();
            let active_id = {
                let g = self.state.lock().await;
                g.settings.selected_provider_id.clone()
            };
            if active_id.is_some() && !servers.iter().any(|s| s == "127.0.0.1") && is_bridge_running().await {
                let _ = self.apply_system_dns(vec!["127.0.0.1".to_string()]).await;
            }
            self.refresh_system_state().await;
        }
    }

    async fn sync_bridge_settings(&self) {
        let (fb_opt, custom_ip, keep_vpn) = {
            let g = self.state.lock().await;
            (
                g.settings.fallback_option,
                g.settings.custom_fallback_ip.clone(),
                g.settings.keep_doh_over_vpn,
            )
        };
        let backend = self.backend.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            resolve_fallback_dns_ip(backend.as_ref(), fb_opt, &custom_ip)
        })
        .await
        .unwrap_or_else(|_| "77.88.8.8".to_string());

        if is_bridge_running().await {
            let _ = send_ipc_request(&BridgeRequest::SetFallback {
                server: resolved.clone(),
            })
            .await;
            let _ = send_ipc_request(&BridgeRequest::SetVpnGuard { enabled: keep_vpn }).await;
        }
    }

    async fn handle_consecutive_failures(&self, streak: u32, server_name: &str) {
        let (auto_failover, active_name) = {
            let mut g = self.state.lock().await;
            g.consecutive_failures = streak;
            let active = g
                .settings
                .selected_provider_id
                .as_ref()
                .and_then(|id| g.settings.providers.iter().find(|p| &p.id == id))
                .map(|p| p.name.clone());
            (g.settings.auto_failover_enabled, active)
        };

        if auto_failover {
            self.select_best_healthy_provider(&format!(
                "Авто-переключение (сервер {server_name} не отвечает)"
            ))
            .await;
        } else if let Some(name) = active_name {
            {
                let mut g = self.state.lock().await;
                g.status_message = format!(
                    "⚠️ Ошибка DoH ({name}): проверьте токен или смените сервер"
                );
            }
            self.emit_state().await;
        }
    }

    pub async fn snapshot(&self) -> AppStateSnapshot {
        let (total_resolved_count, history_count) = self.history.stats();
        let g = self.state.lock().await;
        let active_provider = g
            .settings
            .selected_provider_id
            .as_ref()
            .and_then(|id| g.settings.providers.iter().find(|p| &p.id == id));

        let short_status_text = match active_provider {
            Some(p) => {
                if g.is_bridge_installed {
                    format!("{} • DoH", p.name)
                } else {
                    format!("{} • IPv4", p.name)
                }
            }
            None => "Выключен (системный)".to_string(),
        };

        AppStateSnapshot {
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            platform: self.backend.platform_name().to_string(),
            dns_stack: self.backend.dns_stack_description(),
            service_kind: self.backend.service_kind().to_string(),
            required_bridge_version: BRIDGE_VERSION,
            providers: g.settings.providers.clone(),
            selected_provider_id: g.settings.selected_provider_id.clone(),
            health_map: g.health_map.clone(),
            is_bridge_installed: g.is_bridge_installed,
            is_bridge_up_to_date: g.is_bridge_up_to_date,
            port53_conflict: g.port53_conflict.clone(),
            auto_failover_enabled: g.settings.auto_failover_enabled,
            autostart_enabled: g.settings.autostart_enabled,
            reset_dns_on_quit: g.settings.reset_dns_on_quit,
            keep_doh_over_vpn: g.settings.keep_doh_over_vpn,
            is_dns_overridden_by_vpn: g.is_dns_overridden_by_vpn,
            is_vpn_active: g.is_vpn_active,
            fallback_option: g.settings.fallback_option,
            custom_fallback_ip: g.settings.custom_fallback_ip.clone(),
            resolved_fallback_ip: g.resolved_fallback_ip.clone(),
            excluded_domains: g.settings.excluded_domains.clone(),
            status_message: g.status_message.clone(),
            active_mode_text: g.active_mode_text.clone(),
            short_status_text,
            is_checking_all: g.is_checking_all,
            consecutive_failures: g.consecutive_failures,
            total_resolved_count,
            history_count,
            update_status: g.update_status.clone(),
        }
    }

    pub async fn emit_state(&self) {
        let snap = self.snapshot().await;
        let _ = self.app.emit("state-changed", &snap);
        crate::tray::refresh_tray(&self.app, &snap);
    }

    pub async fn refresh_system_state(&self) {
        let (fb_opt, custom_ip) = {
            let g = self.state.lock().await;
            (
                g.settings.fallback_option,
                g.settings.custom_fallback_ip.clone(),
            )
        };

        let bridge_running = is_bridge_running().await;
        let backend = self.backend.clone();
        let (resolved_fb, up_to_date, conflict, current_servers, vpn_overridden, vpn_active) =
            tokio::task::spawn_blocking(move || {
                (
                    resolve_fallback_dns_ip(backend.as_ref(), fb_opt, &custom_ip),
                    backend.is_bridge_binary_up_to_date(),
                    backend.has_port53_conflict(),
                    backend.current_system_dns_servers(),
                    backend.is_global_dns_overridden_by_vpn(),
                    backend.has_active_vpn_interface(),
                )
            })
            .await
            .unwrap_or_else(|_| ("77.88.8.8".to_string(), false, None, Vec::new(), false, false));

        self.proxy.set_fallback_server(&resolved_fb);

        {
            let mut g = self.state.lock().await;
            g.is_bridge_installed = bridge_running;
            g.is_bridge_up_to_date = bridge_running && up_to_date;
            g.port53_conflict = conflict;
            g.is_vpn_active = vpn_active;
            g.resolved_fallback_ip = if fb_opt == FallbackDNSOption::Disabled {
                "Отключен".to_string()
            } else {
                resolved_fb
            };
            g.is_dns_overridden_by_vpn = current_servers.iter().any(|s| s == "127.0.0.1") && vpn_overridden;

            if current_servers.iter().any(|s| s == "127.0.0.1") {
                let target_id = g
                    .settings
                    .last_selected_provider_id
                    .clone()
                    .or_else(|| g.settings.providers.first().map(|p| p.id.clone()));
                g.settings.selected_provider_id = target_id.clone();

                if let Some(provider) = target_id
                    .as_ref()
                    .and_then(|id| g.settings.providers.iter().find(|p| &p.id == id))
                    .cloned()
                {
                    self.proxy.configure(provider.clone(), g.settings.providers.clone());
                    if g.is_dns_overridden_by_vpn {
                        g.active_mode_text = "DoH приостановлен • VPN перехватил DNS".to_string();
                        if g.is_bridge_installed && !g.is_bridge_up_to_date {
                            g.status_message = format!(
                                "Обновите DoH-мост (v{BRIDGE_VERSION}) для работы поверх VPN"
                            );
                        } else if !g.settings.keep_doh_over_vpn {
                            g.status_message =
                                "Удержание DoH поверх VPN выключено в настройках".to_string();
                        } else {
                            g.status_message = "Туннель VPN перехватил системный DNS".to_string();
                        }
                    } else if vpn_active {
                        g.active_mode_text = format!("Активен DoH • {} (VPN активен)", provider.name);
                        g.status_message = "DoH 127.0.0.1 + Split-DNS для VPN".to_string();
                    } else {
                        g.active_mode_text = format!("Активен DoH • {}", provider.name);
                        g.status_message = "Трафик DNS зашифрован (DoH 127.0.0.1)".to_string();
                    }
                }
            } else if let Some(matched) = g
                .settings
                .providers
                .iter()
                .find(|p| !p.bootstrap_ips.is_empty() && current_servers.first() == p.bootstrap_ips.first())
                .cloned()
            {
                g.settings.selected_provider_id = Some(matched.id.clone());
                g.active_mode_text = format!("Активен IPv4 • {}", matched.name);
                g.status_message = format!("Прямой DNS: {}", current_servers.join(", "));
            } else {
                g.settings.selected_provider_id = None;
                if current_servers.is_empty() {
                    g.active_mode_text = "Системный DNS (DHCP роутера)".to_string();
                } else {
                    g.active_mode_text = format!("Сторонний DNS: {}", current_servers.join(", "));
                }
            }
        }

        self.emit_state().await;
    }

    async fn apply_system_dns(&self, servers: Vec<String>) -> Result<(), String> {
        if is_bridge_running().await {
            let req = if servers.is_empty() {
                BridgeRequest::ResetSystemDns
            } else {
                BridgeRequest::SetSystemDns {
                    servers: servers.clone(),
                }
            };
            match send_ipc_request(&req).await {
                Ok(BridgeResponse::Ok) => return Ok(()),
                Ok(BridgeResponse::Error { message }) => return Err(message),
                _ => {}
            }
        }
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || {
            if servers.is_empty() {
                backend.reset_to_system_default()
            } else {
                backend.set_system_dns(&servers)
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }

    fn resolve_sidecar_bridge_path(&self) -> Result<PathBuf, String> {
        let exe_dir = std::env::current_exe()
            .map_err(|e| format!("Не удалось определить путь приложения: {e}"))?
            .parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| "Некорректная директория приложения".to_string())?;

        let bin_name = if cfg!(windows) {
            "dns-switcher-bridge.exe"
        } else {
            "dns-switcher-bridge"
        };

        let direct = exe_dir.join(bin_name);
        if direct.exists() {
            return Ok(direct);
        }

        if let Ok(res_dir) = self.app.path().resource_dir() {
            let candidate = res_dir.join("binaries").join(bin_name);
            if candidate.exists() {
                return Ok(candidate);
            }
            let flat = res_dir.join(bin_name);
            if flat.exists() {
                return Ok(flat);
            }
        }

        Err(format!("Не найден бинарник моста {bin_name} рядом с приложением"))
    }

    pub async fn select_provider(&self, provider_id: String) {
        let (provider, all_providers) = {
            let mut g = self.state.lock().await;
            let Some(p) = g.settings.providers.iter().find(|p| p.id == provider_id).cloned() else {
                return;
            };
            g.settings.last_selected_provider_id = Some(p.id.clone());
            let _ = save_settings(&g.settings);
            (p, g.settings.providers.clone())
        };

        self.proxy.configure(provider.clone(), all_providers);

        if is_bridge_running().await {
            self.proxy.clear_cache();
            let res = self.apply_system_dns(vec!["127.0.0.1".to_string()]).await;
            {
                let mut g = self.state.lock().await;
                g.is_bridge_installed = true;
                g.settings.selected_provider_id = Some(provider.id.clone());
                let _ = save_settings(&g.settings);
                g.active_mode_text = format!("Активен DoH • {}", provider.name);
                g.status_message = match res {
                    Ok(()) => format!("Переключено на {} (DoH)", provider.name),
                    Err(e) => format!("Ошибка применения настроек сети: {e}"),
                };
            }
            self.sync_bridge_settings().await;
            self.emit_state().await;
            return;
        }

        {
            let mut g = self.state.lock().await;
            g.status_message = "Установка системного DoH-моста (1 раз)…".to_string();
        }
        self.emit_state().await;

        let install_res = match self.resolve_sidecar_bridge_path() {
            Ok(bin_path) => {
                let backend = self.backend.clone();
                tokio::task::spawn_blocking(move || backend.install_bridge_service(&bin_path))
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()))
            }
            Err(e) => Err(e),
        };

        if install_res.is_ok() {
            for _ in 0..30 {
                if is_bridge_running().await {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let bridge_ready = is_bridge_running().await;
        if bridge_ready {
            let _ = self.apply_system_dns(vec!["127.0.0.1".to_string()]).await;
            self.sync_bridge_settings().await;
            {
                let mut g = self.state.lock().await;
                g.is_bridge_installed = true;
                g.is_bridge_up_to_date = true;
                g.settings.selected_provider_id = Some(provider.id.clone());
                let _ = save_settings(&g.settings);
                g.active_mode_text = format!("Активен DoH • {}", provider.name);
                g.status_message = format!("DoH-мост установлен! Активен {}", provider.name);
            }
        } else if provider.plain_dns_supported && !provider.bootstrap_ips.is_empty() {
            let ips: Vec<String> = provider.bootstrap_ips.iter().take(2).cloned().collect();
            let _ = self.apply_system_dns(ips).await;
            {
                let mut g = self.state.lock().await;
                g.is_bridge_installed = false;
                g.settings.selected_provider_id = Some(provider.id.clone());
                let _ = save_settings(&g.settings);
                g.active_mode_text = format!("Активен IPv4 • {}", provider.name);
                g.status_message = format!(
                    "Включён прямой IPv4 для {} (без DoH-моста)",
                    provider.name
                );
            }
        } else {
            let err_msg = install_res
                .err()
                .unwrap_or_else(|| "Не удалось запустить DoH-мост на 127.0.0.1:53".to_string());
            let mut g = self.state.lock().await;
            g.is_bridge_installed = false;
            g.status_message = format!("Для {} нужен DoH-мост: {err_msg}", provider.name);
        }

        self.emit_state().await;
    }

    pub async fn enable_last_or_default_provider(&self) {
        let target_id = {
            let g = self.state.lock().await;
            let visible: Vec<&DNSProvider> = g
                .settings
                .providers
                .iter()
                .filter(|p| p.is_enabled_in_menu_bar)
                .collect();
            let pool = if visible.is_empty() {
                g.settings.providers.iter().collect()
            } else {
                visible
            };
            g.settings
                .last_selected_provider_id
                .as_ref()
                .and_then(|id| pool.iter().find(|p| &p.id == id))
                .or_else(|| pool.first())
                .map(|p| p.id.clone())
        };
        if let Some(id) = target_id {
            self.select_provider(id).await;
        }
    }

    pub async fn disable_custom_dns(&self) {
        let _ = self.apply_system_dns(Vec::new()).await;
        self.proxy.clear_cache();
        {
            let mut g = self.state.lock().await;
            g.settings.selected_provider_id = None;
            let _ = save_settings(&g.settings);
            g.active_mode_text = "Системный DNS (DHCP роутера)".to_string();
            g.status_message = "Возвращён стандартный системный DNS".to_string();
        }
        self.emit_state().await;
    }

    pub async fn install_bridge_manually(&self) {
        {
            let mut g = self.state.lock().await;
            g.status_message = "Запрос прав для установки DoH-моста…".to_string();
        }
        self.emit_state().await;

        let res = match self.resolve_sidecar_bridge_path() {
            Ok(bin_path) => {
                let backend = self.backend.clone();
                tokio::task::spawn_blocking(move || backend.install_bridge_service(&bin_path))
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()))
            }
            Err(e) => Err(e),
        };

        if res.is_ok() {
            for _ in 0..30 {
                if is_bridge_running().await {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let running = is_bridge_running().await;
        let backend = self.backend.clone();
        let up_to_date = tokio::task::spawn_blocking(move || backend.is_bridge_binary_up_to_date())
            .await
            .unwrap_or(false);

        let active_id = {
            let mut g = self.state.lock().await;
            g.is_bridge_installed = running;
            g.is_bridge_up_to_date = running && up_to_date;
            match res {
                Ok(()) => {
                    g.status_message = if running {
                        "DoH-мост (127.0.0.1:53) успешно установлен и запущен!".to_string()
                    } else {
                        "Служба установлена, проверьте статус порта 53".to_string()
                    };
                }
                Err(e) => {
                    g.status_message = format!("Установка отменена: {e}");
                }
            }
            g.settings.selected_provider_id.clone()
        };

        if running {
            self.sync_bridge_settings().await;
            if let Some(id) = active_id {
                self.select_provider(id).await;
                return;
            }
        }
        self.emit_state().await;
    }

    pub async fn uninstall_bridge_manually(&self) {
        let _ = self.apply_system_dns(Vec::new()).await;
        let backend = self.backend.clone();
        let res = tokio::task::spawn_blocking(move || backend.uninstall_bridge_service())
            .await
            .unwrap_or_else(|e| Err(e.to_string()));

        tokio::time::sleep(Duration::from_millis(300)).await;
        let running = is_bridge_running().await;
        {
            let mut g = self.state.lock().await;
            g.is_bridge_installed = running;
            g.is_bridge_up_to_date = false;
            g.settings.selected_provider_id = None;
            let _ = save_settings(&g.settings);
            g.active_mode_text = "Системный DNS (DHCP роутера)".to_string();
            g.status_message = match res {
                Ok(()) => "DoH-мост удалён, восстановлен системный DNS".to_string(),
                Err(e) => format!("Ошибка удаления службы: {e}"),
            };
        }
        self.emit_state().await;
    }

    pub async fn check_all_providers_health(&self) {
        let providers = {
            let mut g = self.state.lock().await;
            if g.is_checking_all {
                return;
            }
            g.is_checking_all = true;
            let ids: Vec<String> = g.settings.providers.iter().map(|p| p.id.clone()).collect();
            for id in ids {
                g.health_map.insert(id, ProviderHealth::Checking);
            }
            g.settings.providers.clone()
        };
        self.emit_state().await;

        let mut handles = Vec::with_capacity(providers.len());
        for provider in providers {
            let proxy = self.proxy.clone();
            handles.push(tokio::spawn(async move {
                let health = proxy.check_provider_health(&provider, "chatgpt.com").await;
                (provider.id, health)
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            if let Ok(pair) = h.await {
                results.push(pair);
            }
        }

        let should_failover = {
            let mut g = self.state.lock().await;
            for (id, health) in results {
                g.health_map.insert(id, health);
            }
            g.is_checking_all = false;
            if g.settings.auto_failover_enabled {
                g.settings
                    .selected_provider_id
                    .as_ref()
                    .and_then(|id| g.health_map.get(id))
                    .map(|h| !h.is_healthy())
                    .unwrap_or(false)
            } else {
                false
            }
        };

        self.emit_state().await;

        if should_failover {
            self.select_best_healthy_provider("Авто-переключение (текущий сервер недоступен)")
                .await;
        }
    }

    pub async fn select_best_smart_provider(&self) {
        {
            let mut g = self.state.lock().await;
            g.status_message = "Тестируем все сервисы (DoH + доступность прокси)…".to_string();
        }
        self.emit_state().await;
        self.check_all_providers_health().await;
        self.select_best_healthy_provider("Выбран самый быстрый рабочий сервер")
            .await;
    }

    async fn select_best_healthy_provider(&self, reason: &str) {
        let best = {
            let g = self.state.lock().await;
            let mut menu_candidates: Vec<(String, String, u64)> = g
                .settings
                .providers
                .iter()
                .filter(|p| p.is_enabled_in_menu_bar)
                .filter_map(|p| match g.health_map.get(&p.id) {
                    Some(ProviderHealth::Healthy { latency_ms, .. }) => {
                        Some((p.id.clone(), p.name.clone(), *latency_ms))
                    }
                    _ => None,
                })
                .collect();
            menu_candidates.sort_by_key(|x| x.2);

            if menu_candidates.is_empty() {
                let mut all_candidates: Vec<(String, String, u64)> = g
                    .settings
                    .providers
                    .iter()
                    .filter_map(|p| match g.health_map.get(&p.id) {
                        Some(ProviderHealth::Healthy { latency_ms, .. }) => {
                            Some((p.id.clone(), p.name.clone(), *latency_ms))
                        }
                        _ => None,
                    })
                    .collect();
                all_candidates.sort_by_key(|x| x.2);
                all_candidates.into_iter().next()
            } else {
                menu_candidates.into_iter().next()
            }
        };

        if let Some((best_id, best_name, ms)) = best {
            let already_active = {
                let g = self.state.lock().await;
                g.settings.selected_provider_id.as_deref() == Some(best_id.as_str())
            };
            if !already_active {
                self.select_provider(best_id).await;
                let mut g = self.state.lock().await;
                g.status_message = format!("{reason}: {best_name} ({ms} мс)");
            } else {
                let mut g = self.state.lock().await;
                g.status_message = format!("{best_name} уже активен и работает отлично ({ms} мс)");
            }
        } else {
            let mut g = self.state.lock().await;
            g.status_message = "Ни один из сервисов сейчас не прошёл полную проверку".to_string();
        }
        self.emit_state().await;
    }

    pub async fn add_custom_provider(
        &self,
        name: String,
        doh_url: String,
        bootstrap_ip: String,
    ) -> Result<(), String> {
        let clean_name = name.trim().to_string();
        let clean_url = doh_url.trim().to_string();
        let mut clean_ip = bootstrap_ip.trim().to_string();
        if clean_name.is_empty() || !clean_url.starts_with("https://") {
            return Err("Укажите корректное название и https:// адрес DoH".to_string());
        }
        let Ok(parsed) = reqwest::Url::parse(&clean_url) else {
            return Err("Некорректный URL DoH".to_string());
        };
        let Some(host) = parsed.host_str().map(|s| s.to_string()) else {
            return Err("Некорректный хост в URL DoH".to_string());
        };
        if clean_ip.is_empty() && host.to_lowercase().contains("tunnelhunt.ru") {
            clean_ip = "135.106.164.115".to_string();
        }
        if !clean_ip.is_empty() && !is_valid_non_loopback_ipv4(&clean_ip) {
            return Err("Некорректный Bootstrap IPv4".to_string());
        }

        let new_provider = DNSProvider {
            id: format!("custom-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            name: clean_name,
            subtitle: format!("{host} • Пользовательский DoH"),
            doh_url: clean_url,
            dot_host: host,
            bootstrap_ips: if clean_ip.is_empty() {
                Vec::new()
            } else {
                vec![clean_ip]
            },
            plain_dns_supported: !bootstrap_ip.trim().is_empty(),
            website_url: format!("https://{}/", parsed.host_str().unwrap_or_default()),
            is_built_in: false,
            is_enabled_in_menu_bar: true,
        };

        {
            let mut g = self.state.lock().await;
            g.settings.providers.push(new_provider.clone());
            g.health_map
                .insert(new_provider.id.clone(), ProviderHealth::Checking);
            let _ = save_settings(&g.settings);
        }
        self.emit_state().await;

        let ctrl = self.clone();
        tokio::spawn(async move {
            let health = ctrl
                .proxy
                .check_provider_health(&new_provider, "chatgpt.com")
                .await;
            {
                let mut g = ctrl.state.lock().await;
                g.health_map.insert(new_provider.id, health);
            }
            ctrl.emit_state().await;
        });

        Ok(())
    }

    pub async fn remove_provider(&self, provider_id: String) {
        let was_active = {
            let g = self.state.lock().await;
            g.settings.selected_provider_id.as_deref() == Some(provider_id.as_str())
        };
        if was_active {
            self.disable_custom_dns().await;
        }
        {
            let mut g = self.state.lock().await;
            g.settings.providers.retain(|p| p.id != provider_id);
            g.health_map.remove(&provider_id);
            let _ = save_settings(&g.settings);
        }
        self.emit_state().await;
    }

    pub async fn toggle_provider_in_menu_bar(&self, provider_id: String) {
        {
            let mut g = self.state.lock().await;
            if let Some(p) = g.settings.providers.iter_mut().find(|p| p.id == provider_id) {
                p.is_enabled_in_menu_bar = !p.is_enabled_in_menu_bar;
            }
            let _ = save_settings(&g.settings);
        }
        self.emit_state().await;
    }

    pub async fn restore_default_providers(&self) {
        {
            let mut g = self.state.lock().await;
            for bp in DNSProvider::built_in_providers() {
                if !g.settings.providers.iter().any(|p| p.id == bp.id) {
                    g.settings.providers.push(bp);
                }
            }
            let _ = save_settings(&g.settings);
        }
        self.check_all_providers_health().await;
    }

    pub async fn add_excluded_domains(&self, raw_input: String) {
        let parsed = parse_domain_rules(&raw_input);
        let mut added = 0usize;
        let updated_domains = {
            let mut g = self.state.lock().await;
            for norm in parsed {
                if !g.settings.excluded_domains.contains(&norm) {
                    g.settings.excluded_domains.push(norm);
                    added += 1;
                }
            }
            if added > 0 {
                let _ = save_settings(&g.settings);
                g.status_message = format!("Добавлено в исключения: {added} дом.");
            }
            g.settings.excluded_domains.clone()
        };
        if added > 0 {
            self.proxy.set_excluded_domains(&updated_domains);
            let _ = self.flush_dns_cache_internal().await;
            self.emit_state().await;
        }
    }

    pub async fn remove_excluded_domain(&self, domain: String) {
        let updated = {
            let mut g = self.state.lock().await;
            g.settings.excluded_domains.retain(|d| d != &domain);
            let _ = save_settings(&g.settings);
            g.settings.excluded_domains.clone()
        };
        self.proxy.set_excluded_domains(&updated);
        let _ = self.flush_dns_cache_internal().await;
        self.emit_state().await;
    }

    pub async fn clear_excluded_domains(&self) {
        {
            let mut g = self.state.lock().await;
            g.settings.excluded_domains.clear();
            let _ = save_settings(&g.settings);
        }
        self.proxy.set_excluded_domains(&[]);
        let _ = self.flush_dns_cache_internal().await;
        self.emit_state().await;
    }

    pub async fn set_fallback_option(&self, option: FallbackDNSOption) {
        {
            let mut g = self.state.lock().await;
            g.settings.fallback_option = option;
            let _ = save_settings(&g.settings);
        }
        self.refresh_system_state().await;
        self.sync_bridge_settings().await;
    }

    pub async fn set_custom_fallback_ip(&self, ip: String) {
        {
            let mut g = self.state.lock().await;
            g.settings.custom_fallback_ip = ip;
            let _ = save_settings(&g.settings);
        }
        self.refresh_system_state().await;
        self.sync_bridge_settings().await;
    }

    pub async fn set_keep_doh_over_vpn(&self, enabled: bool) {
        {
            let mut g = self.state.lock().await;
            g.settings.keep_doh_over_vpn = enabled;
            let _ = save_settings(&g.settings);
        }
        self.proxy.reset_network_connections();
        self.sync_bridge_settings().await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        self.refresh_system_state().await;
    }

    pub async fn set_auto_failover(&self, enabled: bool) {
        {
            let mut g = self.state.lock().await;
            g.settings.auto_failover_enabled = enabled;
            let _ = save_settings(&g.settings);
        }
        self.emit_state().await;
    }

    pub async fn set_reset_dns_on_quit(&self, enabled: bool) {
        {
            let mut g = self.state.lock().await;
            g.settings.reset_dns_on_quit = enabled;
            let _ = save_settings(&g.settings);
        }
        self.emit_state().await;
    }

    pub async fn set_autostart_enabled(&self, enabled: bool) {
        use tauri_plugin_autostart::ManagerExt;
        let autostart = self.app.autolaunch();
        let res = if enabled {
            autostart.enable()
        } else {
            autostart.disable()
        };
        if res.is_ok() {
            let mut g = self.state.lock().await;
            g.settings.autostart_enabled = enabled;
            let _ = save_settings(&g.settings);
        }
        self.emit_state().await;
    }

    async fn flush_dns_cache_internal(&self) -> Result<(), String> {
        self.proxy.clear_cache();
        if is_bridge_running().await {
            let _ = send_ipc_request(&BridgeRequest::FlushDnsCache).await;
            return Ok(());
        }
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || backend.flush_dns_cache())
            .await
            .map_err(|e| e.to_string())?
    }

    pub async fn flush_dns_cache(&self) {
        let _ = self.flush_dns_cache_internal().await;
        {
            let mut g = self.state.lock().await;
            g.status_message = "Кэш DNS успешно очищен".to_string();
        }
        self.emit_state().await;
    }

    pub fn history_records(&self) -> Vec<DNSResolutionRecord> {
        self.history.records()
    }

    pub async fn clear_history(&self) {
        self.history.clear();
        let _ = self.app.emit("history-updated", ());
        self.emit_state().await;
    }

    pub async fn check_for_updates(&self, silent: bool) {
        if !silent {
            {
                let mut g = self.state.lock().await;
                g.update_status = UpdateStatus::Checking;
            }
            self.emit_state().await;
        }

        let current_ver = env!("CARGO_PKG_VERSION");
        let result = updater::check_for_updates(current_ver).await;
        {
            let mut g = self.state.lock().await;
            if !silent || matches!(result, UpdateStatus::Available { .. }) {
                g.update_status = result;
            }
        }
        self.emit_state().await;
    }

    pub async fn handle_app_termination(&self) {
        let should_reset = {
            let g = self.state.lock().await;
            g.settings.reset_dns_on_quit && g.settings.selected_provider_id.is_some()
        };
        if should_reset {
            let _ = self.apply_system_dns(Vec::new()).await;
        }
    }
}
