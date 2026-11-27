use dns_core::bridge_ipc::{
    run_ipc_server, run_port53_bridge, BridgeRuntimeConfig, APP_PROXY_ADDR, BRIDGE_DNS_ADDR,
    BRIDGE_IPC_ADDR, BRIDGE_VERSION, DEFAULT_FALLBACK_DNS,
};
use dns_core::platform::{default_backend, SystemDnsBackend};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--bridge-version") {
        println!("{BRIDGE_VERSION}");
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    #[cfg(target_os = "windows")]
    if args.iter().any(|a| a == "--service") {
        if let Err(e) = windows_svc::run_windows_service() {
            tracing::error!("Windows service exited with error: {e}");
            std::process::exit(1);
        }
        return;
    }

    // Linux systemd (--service) or --standalone on any OS
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    rt.block_on(async move {
        run_bridge_loop(None).await;
    });
}

async fn run_bridge_loop(mut shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>) {
    let backend = default_backend();
    let upstream: SocketAddr = APP_PROXY_ADDR.parse().unwrap();
    let dns_addr: SocketAddr = BRIDGE_DNS_ADDR.parse().unwrap();
    let ipc_addr: SocketAddr = BRIDGE_IPC_ADDR.parse().unwrap();

    let initial_fallback = backend
        .detect_dhcp_dns_server()
        .unwrap_or_else(|| DEFAULT_FALLBACK_DNS.to_string());
    let cfg = BridgeRuntimeConfig::new(upstream, Some(initial_fallback));

    tracing::info!(
        "[DNSSwitcher Bridge v{}] Starting on {} -> {} (IPC {})",
        BRIDGE_VERSION,
        dns_addr,
        upstream,
        ipc_addr
    );

    let dns_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = run_port53_bridge(dns_addr, dns_addr, dns_cfg).await {
            tracing::error!("[DNSSwitcher Bridge] Port 53 listener error: {e}");
        }
    });

    let ipc_backend = backend.clone();
    let ipc_cfg = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = run_ipc_server(ipc_addr, ipc_backend, ipc_cfg).await {
            tracing::error!("[DNSSwitcher Bridge] IPC listener error: {e}");
        }
    });

    // Periodic VPN DNS Guard reconciliation (every 3s)
    let guard_backend = backend.clone();
    let guard_cfg = cfg.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        loop {
            interval.tick().await;
            let enabled = guard_cfg.is_vpn_guard_enabled();
            let b = guard_backend.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let doh_active = b
                    .current_system_dns_servers()
                    .iter()
                    .any(|s| s == "127.0.0.1");
                let _ = b.reconcile_vpn_guard(enabled, doh_active);
            })
            .await;
        }
    });

    match shutdown_rx {
        Some(ref mut rx) => {
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
        None => {
            wait_for_unix_or_ctrlc_signal().await;
        }
    }

    tracing::info!("[DNSSwitcher Bridge] Shutting down, restoring VPN DNS state...");
    cleanup_on_exit(backend).await;
}

async fn cleanup_on_exit(backend: Arc<dyn SystemDnsBackend>) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = backend.restore_vpn_guard();
    })
    .await;
}

#[cfg(unix)]
async fn wait_for_unix_or_ctrlc_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {},
    }
}

#[cfg(not(unix))]
async fn wait_for_unix_or_ctrlc_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(target_os = "windows")]
mod windows_svc {
    use super::*;
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    const SERVICE_NAME: &str = "DNSSwitcherBridge";

    define_windows_service!(ffi_service_main, service_main);

    pub fn run_windows_service() -> Result<(), windows_service::Error> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            tracing::error!("Service execution failed: {e}");
        }
    }

    fn run_service() -> Result<(), windows_service::Error> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let status_handle = service_control_handler::register(SERVICE_NAME, move |control_event| {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = shutdown_tx.send(true);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let rt = tokio::runtime::Runtime::new().expect("Tokio runtime");
        rt.block_on(async move {
            run_bridge_loop(Some(shutdown_rx)).await;
        });

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }
}
