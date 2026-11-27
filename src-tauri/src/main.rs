#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;
mod tray;

use dns_core::dns_packet::{
    build_a_query, build_failure_response, extract_a_records, rcode, transaction_id,
};
use dns_core::doh_proxy::LocalDoHProxy;
use dns_core::history::DNSHistoryStore;
use dns_core::models::DNSProvider;
use dns_core::platform::default_backend;
use dns_core::rules::{is_domain_excluded, is_fake_ip_address, is_known_proxy_identifier, parse_domain_rules};
use dns_core::updater::is_version_newer;
use state::AppController;
use tauri::{Manager, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--self-test") {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(run_self_test());
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .setup(|app| {
            let handle = app.handle().clone();
            let controller = tauri::async_runtime::block_on(AppController::new(handle.clone()));
            let initial_snap = tauri::async_runtime::block_on(controller.snapshot());

            app.manage(controller);
            tray::setup_tray(&handle, &initial_snap)?;

            // Show main window on initial manual launch unless --minimized was passed
            let minimized = std::env::args().any(|a| a == "--minimized");
            if !minimized {
                tray::show_or_focus_window(&handle, "main");
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_state,
            commands::select_provider,
            commands::toggle_dns_enabled,
            commands::check_all_providers_health,
            commands::select_best_smart_provider,
            commands::install_bridge_manually,
            commands::uninstall_bridge_manually,
            commands::add_custom_provider,
            commands::remove_provider,
            commands::toggle_provider_in_menu_bar,
            commands::restore_default_providers,
            commands::add_excluded_domains,
            commands::remove_excluded_domain,
            commands::clear_excluded_domains,
            commands::set_fallback_option,
            commands::set_custom_fallback_ip,
            commands::set_keep_doh_over_vpn,
            commands::set_auto_failover,
            commands::set_reset_dns_on_quit,
            commands::set_autostart_enabled,
            commands::flush_dns_cache,
            commands::get_history,
            commands::clear_history,
            commands::check_for_updates,
            commands::open_window,
            commands::quit_app,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AI DNS Switcher");
}

async fn run_self_test() {
    let backend = default_backend();
    println!(
        "[Platform] {} ({})",
        backend.platform_name(),
        backend.dns_stack_description()
    );

    let rules = parse_domain_rules("*.company.ru, https://git.corp.local/repo; .internal");
    assert_eq!(rules, vec!["company.ru", "git.corp.local", "internal"]);
    assert!(is_domain_excluded("jira.company.ru", &rules));
    assert!(!is_domain_excluded("mycompany.ru", &rules));
    assert!(is_fake_ip_address("198.18.0.2"));
    assert!(is_known_proxy_identifier("v2rayN"));
    assert!(is_version_newer("v1.7.8", "1.7.7"));

    let q = build_a_query("test.local", 0xABCD);
    let fail = build_failure_response(&q, 2);
    assert_eq!(transaction_id(&fail), 0xABCD);
    assert_eq!(rcode(&fail), 2);

    let history = DNSHistoryStore::new();
    let proxy = LocalDoHProxy::new(backend, history);
    for p in DNSProvider::built_in_providers() {
        let health = proxy.check_provider_health(&p, "chatgpt.com").await;
        println!("[{}] {} -> {}", p.name, p.doh_url, health.badge_text());
        if let dns_core::models::ProviderHealth::Healthy { resolved_ip, .. } = health {
            assert!(!resolved_ip.is_empty());
        }
    }
    let _ = extract_a_records(&fail);
    println!("[SelfTest] Completed.");
}
