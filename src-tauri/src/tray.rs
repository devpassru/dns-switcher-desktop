use crate::state::AppController;
use dns_core::models::{AppStateSnapshot, ProviderHealth};
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, PhysicalPosition};

const TRAY_ID: &str = "main-tray";

pub fn setup_tray(app: &AppHandle, initial: &AppStateSnapshot) -> tauri::Result<()> {
    let menu = build_tray_menu(app, initial)?;
    let icon = load_tray_icon(initial.selected_provider_id.is_some());

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .menu(&menu)
        .tooltip(format!("AI DNS Switcher • {}", initial.short_status_text))
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            let id = event.id().as_ref().to_string();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let ctrl = app_handle.state::<AppController>();
                match id.as_str() {
                    "toggle-off" => ctrl.disable_custom_dns().await,
                    "fastest" => ctrl.select_best_smart_provider().await,
                    "open-main" => show_or_focus_window(&app_handle, "main"),
                    "open-settings" => show_or_focus_window(&app_handle, "settings"),
                    "open-history" => show_or_focus_window(&app_handle, "history"),
                    "quit" => {
                        ctrl.handle_app_termination().await;
                        app_handle.exit(0);
                    }
                    other if other.starts_with("provider:") => {
                        let pid = other.trim_start_matches("provider:").to_string();
                        ctrl.select_provider(pid).await;
                    }
                    _ => {}
                }
            });
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                position,
                ..
            } = event
            {
                toggle_main_popover(tray.app_handle(), Some(position));
            }
        })
        .build(app)?;

    Ok(())
}

pub fn refresh_tray(app: &AppHandle, snap: &AppStateSnapshot) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let icon = load_tray_icon(snap.selected_provider_id.is_some());
    let _ = tray.set_icon(Some(icon));
    let _ = tray.set_tooltip(Some(format!(
        "AI DNS Switcher • {}",
        snap.short_status_text
    )));
    if let Ok(menu) = build_tray_menu(app, snap) {
        let _ = tray.set_menu(Some(menu));
    }
}

fn build_tray_menu(app: &AppHandle, snap: &AppStateSnapshot) -> tauri::Result<Menu<tauri::Wry>> {
    let menu = Menu::new(app)?;

    let status_item = MenuItem::with_id(
        app,
        "open-main",
        format!("AI DNS: {}", snap.short_status_text),
        true,
        None::<&str>,
    )?;
    menu.append(&status_item)?;

    if snap.selected_provider_id.is_some() {
        let off_item = MenuItem::with_id(
            app,
            "toggle-off",
            "Выключить (системный DNS)",
            true,
            None::<&str>,
        )?;
        menu.append(&off_item)?;
    }

    menu.append(&PredefinedMenuItem::separator(app)?)?;

    for p in snap.providers.iter().filter(|p| p.is_enabled_in_menu_bar) {
        let checked = snap.selected_provider_id.as_deref() == Some(p.id.as_str());
        let suffix = match snap.health_map.get(&p.id) {
            Some(ProviderHealth::Healthy { latency_ms, .. }) => format!(" ({latency_ms} мс)"),
            Some(ProviderHealth::Degraded { latency_ms, .. }) => format!(" ({latency_ms} мс ⚠️)"),
            Some(ProviderHealth::Unreachable { .. }) => " (недоступен)".to_string(),
            _ => String::new(),
        };
        let item = CheckMenuItem::with_id(
            app,
            format!("provider:{}", p.id),
            format!("{}{}", p.name, suffix),
            true,
            checked,
            None::<&str>,
        )?;
        menu.append(&item)?;
    }

    let fastest = MenuItem::with_id(
        app,
        "fastest",
        "⚡ Выбрать самый быстрый сервер",
        true,
        None::<&str>,
    )?;
    menu.append(&fastest)?;

    menu.append(&PredefinedMenuItem::separator(app)?)?;

    let settings = MenuItem::with_id(app, "open-settings", "Настройки AI DNS…", true, None::<&str>)?;
    let history = MenuItem::with_id(app, "open-history", "История DNS-запросов…", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;

    menu.append(&settings)?;
    menu.append(&history)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&quit)?;

    Ok(menu)
}

fn load_tray_icon(active: bool) -> Image<'static> {
    let bytes: &[u8] = if active {
        include_bytes!("../icons/tray-active.png")
    } else {
        include_bytes!("../icons/tray-inactive.png")
    };
    Image::from_bytes(bytes).expect("Valid embedded tray PNG")
}

pub fn show_or_focus_window(app: &AppHandle, label: &str) {
    if label != "main" {
        if let Some(main_win) = app.get_webview_window("main") {
            let _ = main_win.hide();
        }
    }
    if let Some(win) = app.get_webview_window(label) {
        if label != "main" {
            let _ = win.center();
        }
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

pub fn toggle_main_popover(app: &AppHandle, click_pos: Option<PhysicalPosition<f64>>) {
    let Some(win) = app.get_webview_window("main") else {
        return;
    };
    let visible = win.is_visible().unwrap_or(false);
    if visible {
        let _ = win.hide();
        return;
    }

    if let Some(pos) = click_pos {
        if let Ok(size) = win.outer_size() {
            if let Ok(Some(monitor)) = win.current_monitor() {
                let m_pos = monitor.position();
                let m_size = monitor.size();
                let mut x = pos.x as i32 - (size.width as i32 / 2);
                let min_x = m_pos.x + 12;
                let max_x = m_pos.x + m_size.width as i32 - size.width as i32 - 12;
                x = x.clamp(min_x, max_x.max(min_x));

                // Place above taskbar if clicked in lower half (Windows), else below top bar (Linux/macOS)
                let mid_y = m_pos.y + (m_size.height as i32 / 2);
                let y = if (pos.y as i32) > mid_y {
                    (pos.y as i32 - size.height as i32 - 12).max(m_pos.y + 12)
                } else {
                    (pos.y as i32 + 12).min(m_pos.y + m_size.height as i32 - size.height as i32 - 12)
                };
                let _ = win.set_position(PhysicalPosition::new(x, y));
            }
        }
    } else {
        let _ = win.center();
    }

    let _ = win.show();
    let _ = win.set_focus();
}
