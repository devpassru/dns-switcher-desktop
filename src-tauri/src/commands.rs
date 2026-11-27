use crate::state::AppController;
use dns_core::models::{AppStateSnapshot, DNSResolutionRecord, FallbackDNSOption};
use tauri::{AppHandle, State};

#[tauri::command]
pub async fn get_app_state(ctrl: State<'_, AppController>) -> Result<AppStateSnapshot, String> {
    Ok(ctrl.snapshot().await)
}

#[tauri::command]
pub async fn select_provider(ctrl: State<'_, AppController>, id: String) -> Result<(), String> {
    ctrl.select_provider(id).await;
    Ok(())
}

#[tauri::command]
pub async fn toggle_dns_enabled(
    ctrl: State<'_, AppController>,
    enabled: bool,
) -> Result<(), String> {
    if enabled {
        ctrl.enable_last_or_default_provider().await;
    } else {
        ctrl.disable_custom_dns().await;
    }
    Ok(())
}

#[tauri::command]
pub async fn check_all_providers_health(ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.check_all_providers_health().await;
    Ok(())
}

#[tauri::command]
pub async fn select_best_smart_provider(ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.select_best_smart_provider().await;
    Ok(())
}

#[tauri::command]
pub async fn install_bridge_manually(ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.install_bridge_manually().await;
    Ok(())
}

#[tauri::command]
pub async fn uninstall_bridge_manually(ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.uninstall_bridge_manually().await;
    Ok(())
}

#[tauri::command]
pub async fn add_custom_provider(
    ctrl: State<'_, AppController>,
    name: String,
    doh_url: String,
    bootstrap_ip: String,
) -> Result<(), String> {
    ctrl.add_custom_provider(name, doh_url, bootstrap_ip).await
}

#[tauri::command]
pub async fn remove_provider(ctrl: State<'_, AppController>, id: String) -> Result<(), String> {
    ctrl.remove_provider(id).await;
    Ok(())
}

#[tauri::command]
pub async fn toggle_provider_in_menu_bar(
    ctrl: State<'_, AppController>,
    id: String,
) -> Result<(), String> {
    ctrl.toggle_provider_in_menu_bar(id).await;
    Ok(())
}

#[tauri::command]
pub async fn restore_default_providers(ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.restore_default_providers().await;
    Ok(())
}

#[tauri::command]
pub async fn add_excluded_domains(
    ctrl: State<'_, AppController>,
    raw_input: String,
) -> Result<(), String> {
    ctrl.add_excluded_domains(raw_input).await;
    Ok(())
}

#[tauri::command]
pub async fn remove_excluded_domain(
    ctrl: State<'_, AppController>,
    domain: String,
) -> Result<(), String> {
    ctrl.remove_excluded_domain(domain).await;
    Ok(())
}

#[tauri::command]
pub async fn clear_excluded_domains(ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.clear_excluded_domains().await;
    Ok(())
}

#[tauri::command]
pub async fn set_fallback_option(
    ctrl: State<'_, AppController>,
    option: FallbackDNSOption,
) -> Result<(), String> {
    ctrl.set_fallback_option(option).await;
    Ok(())
}

#[tauri::command]
pub async fn set_custom_fallback_ip(
    ctrl: State<'_, AppController>,
    ip: String,
) -> Result<(), String> {
    ctrl.set_custom_fallback_ip(ip).await;
    Ok(())
}

#[tauri::command]
pub async fn set_keep_doh_over_vpn(
    ctrl: State<'_, AppController>,
    enabled: bool,
) -> Result<(), String> {
    ctrl.set_keep_doh_over_vpn(enabled).await;
    Ok(())
}

#[tauri::command]
pub async fn set_auto_failover(
    ctrl: State<'_, AppController>,
    enabled: bool,
) -> Result<(), String> {
    ctrl.set_auto_failover(enabled).await;
    Ok(())
}

#[tauri::command]
pub async fn set_reset_dns_on_quit(
    ctrl: State<'_, AppController>,
    enabled: bool,
) -> Result<(), String> {
    ctrl.set_reset_dns_on_quit(enabled).await;
    Ok(())
}

#[tauri::command]
pub async fn set_autostart_enabled(
    ctrl: State<'_, AppController>,
    enabled: bool,
) -> Result<(), String> {
    ctrl.set_autostart_enabled(enabled).await;
    Ok(())
}

#[tauri::command]
pub async fn flush_dns_cache(ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.flush_dns_cache().await;
    Ok(())
}

#[tauri::command]
pub async fn get_history(
    ctrl: State<'_, AppController>,
) -> Result<Vec<DNSResolutionRecord>, String> {
    Ok(ctrl.history_records())
}

#[tauri::command]
pub async fn clear_history(ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.clear_history().await;
    Ok(())
}

#[tauri::command]
pub async fn check_for_updates(ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.check_for_updates(false).await;
    Ok(())
}

#[tauri::command]
pub fn open_window(app: AppHandle, label: String) -> Result<(), String> {
    crate::tray::show_or_focus_window(&app, &label);
    Ok(())
}

#[tauri::command]
pub async fn quit_app(app: AppHandle, ctrl: State<'_, AppController>) -> Result<(), String> {
    ctrl.handle_app_termination().await;
    app.exit(0);
    Ok(())
}
