use crate::dns_packet::{build_failure_response, rcode};
use crate::platform::SystemDnsBackend;
use crate::rules::is_valid_non_loopback_ipv4;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

pub const BRIDGE_VERSION: u32 = 1;
pub const BRIDGE_DNS_ADDR: &str = "127.0.0.1:53";
pub const APP_PROXY_ADDR: &str = "127.0.0.1:53535";
pub const BRIDGE_IPC_ADDR: &str = "127.0.0.1:53536";
pub const DEFAULT_FALLBACK_DNS: &str = "77.88.8.8";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum BridgeRequest {
    Ping,
    GetStatus,
    SetSystemDns { servers: Vec<String> },
    ResetSystemDns,
    FlushDnsCache,
    SetFallback { server: String },
    SetVpnGuard { enabled: bool },
    GetNetworkInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInfoPayload {
    pub current_dns_servers: Vec<String>,
    pub dhcp_dns: Option<String>,
    pub vpn_active: bool,
    pub vpn_overridden: bool,
    pub vpn_dns_servers: Vec<String>,
    pub vpn_search_domains: Vec<String>,
    pub dns_stack: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BridgeResponse {
    Ok,
    Pong {
        version: u32,
    },
    Status {
        version: u32,
        fallback: Option<String>,
        vpn_guard_enabled: bool,
    },
    NetworkInfo(NetworkInfoPayload),
    Error {
        message: String,
    },
}

pub fn validate_dns_server_list(servers: &[String]) -> Result<(), String> {
    if servers.len() > 4 {
        return Err("Слишком много DNS-серверов (максимум 4)".to_string());
    }
    for s in servers {
        let trimmed = s.trim();
        if trimmed.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(format!("Некорректный IPv4-адрес DNS: {trimmed}"));
        }
    }
    Ok(())
}

pub async fn send_udp_dns(query: &[u8], target: SocketAddr, timeout_ms: u64) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect(target).await.ok()?;
    sock.send(query).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_millis(timeout_ms), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n < 12 {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

#[derive(Clone)]
pub struct BridgeRuntimeConfig {
    pub upstream_proxy: SocketAddr,
    pub fallback_server: Arc<RwLock<Option<String>>>,
    pub vpn_guard_enabled: Arc<RwLock<bool>>,
}

impl BridgeRuntimeConfig {
    pub fn new(upstream_proxy: SocketAddr, fallback: Option<String>) -> Self {
        Self {
            upstream_proxy,
            fallback_server: Arc::new(RwLock::new(fallback)),
            vpn_guard_enabled: Arc::new(RwLock::new(true)),
        }
    }

    pub fn set_fallback(&self, raw: &str) -> Result<(), String> {
        let clean = raw.trim().to_lowercase();
        let next = if clean == "disabled" || clean == "none" {
            None
        } else if is_valid_non_loopback_ipv4(&clean) {
            Some(clean)
        } else {
            return Err(format!("Некорректный fallback DNS: {raw}"));
        };
        if let Ok(mut g) = self.fallback_server.write() {
            *g = next;
        }
        Ok(())
    }

    pub fn current_fallback(&self) -> Option<String> {
        self.fallback_server.read().ok().and_then(|g| g.clone())
    }

    pub fn set_vpn_guard(&self, enabled: bool) {
        if let Ok(mut g) = self.vpn_guard_enabled.write() {
            *g = enabled;
        }
    }

    pub fn is_vpn_guard_enabled(&self) -> bool {
        self.vpn_guard_enabled.read().map(|g| *g).unwrap_or(true)
    }
}

pub async fn forward_dns_query(query: &[u8], cfg: &BridgeRuntimeConfig) -> Vec<u8> {
    if let Some(reply) = send_udp_dns(query, cfg.upstream_proxy, 4000).await {
        return reply;
    }

    let Some(fb_ip) = cfg.current_fallback() else {
        return build_failure_response(query, 2);
    };

    if let Ok(ip) = fb_ip.parse::<std::net::IpAddr>() {
        let addr = SocketAddr::new(ip, 53);
        if let Some(reply) = send_udp_dns(query, addr, 2000).await {
            return reply;
        }
    }

    build_failure_response(query, 2)
}

pub async fn run_port53_bridge(
    udp_bind: SocketAddr,
    tcp_bind: SocketAddr,
    cfg: BridgeRuntimeConfig,
) -> Result<(), String> {
    let udp_sock = Arc::new(
        UdpSocket::bind(udp_bind)
            .await
            .map_err(|e| format!("Failed to bind UDP {udp_bind}: {e}"))?,
    );
    let tcp_listener = TcpListener::bind(tcp_bind)
        .await
        .map_err(|e| format!("Failed to bind TCP {tcp_bind}: {e}"))?;

    let udp_cfg = cfg.clone();
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = udp_sock.recv_from(&mut buf).await else {
                continue;
            };
            if n < 12 {
                continue;
            }
            let query = buf[..n].to_vec();
            let sock = udp_sock.clone();
            let req_cfg = udp_cfg.clone();
            tokio::spawn(async move {
                let resp = forward_dns_query(&query, &req_cfg).await;
                let _ = sock.send_to(&resp, peer).await;
            });
        }
    });

    let tcp_cfg = cfg;
    let tcp_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp_listener.accept().await else {
                continue;
            };
            let req_cfg = tcp_cfg.clone();
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let msg_len = u16::from_be_bytes(len_buf) as usize;
                if msg_len == 0 || msg_len > 65535 {
                    return;
                }
                let mut query = vec![0u8; msg_len];
                if stream.read_exact(&mut query).await.is_err() {
                    return;
                }
                let resp = forward_dns_query(&query, &req_cfg).await;
                let resp_len = (resp.len() as u16).to_be_bytes();
                let mut out = Vec::with_capacity(2 + resp.len());
                out.extend_from_slice(&resp_len);
                out.extend_from_slice(&resp);
                let _ = stream.write_all(&out).await;
            });
        }
    });

    let _ = tokio::join!(udp_task, tcp_task);
    Ok(())
}

pub async fn run_ipc_server(
    bind_addr: SocketAddr,
    backend: Arc<dyn SystemDnsBackend>,
    cfg: BridgeRuntimeConfig,
) -> Result<(), String> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("Failed to bind IPC {bind_addr}: {e}"))?;

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let backend = backend.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            handle_ipc_client(stream, backend, cfg).await;
        });
    }
}

async fn handle_ipc_client(
    stream: TcpStream,
    backend: Arc<dyn SystemDnsBackend>,
    cfg: BridgeRuntimeConfig,
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let Ok(Some(line)) = timeout(Duration::from_secs(5), lines.next_line()).await.unwrap_or(Ok(None)) else {
        return;
    };

    let response = match serde_json::from_str::<BridgeRequest>(&line) {
        Ok(req) => execute_ipc_request(req, backend, cfg).await,
        Err(e) => BridgeResponse::Error {
            message: format!("Invalid IPC JSON: {e}"),
        },
    };

    if let Ok(mut json) = serde_json::to_string(&response) {
        json.push('\n');
        let _ = writer.write_all(json.as_bytes()).await;
    }
}

async fn execute_ipc_request(
    req: BridgeRequest,
    backend: Arc<dyn SystemDnsBackend>,
    cfg: BridgeRuntimeConfig,
) -> BridgeResponse {
    match req {
        BridgeRequest::Ping => BridgeResponse::Pong {
            version: BRIDGE_VERSION,
        },
        BridgeRequest::GetStatus => BridgeResponse::Status {
            version: BRIDGE_VERSION,
            fallback: cfg.current_fallback(),
            vpn_guard_enabled: cfg.is_vpn_guard_enabled(),
        },
        BridgeRequest::SetSystemDns { servers } => {
            if let Err(e) = validate_dns_server_list(&servers) {
                return BridgeResponse::Error { message: e };
            }
            let guard_enabled = cfg.is_vpn_guard_enabled();
            let doh_active = servers.iter().any(|s| s == "127.0.0.1");
            let res = tokio::task::spawn_blocking(move || {
                backend.set_system_dns(&servers)?;
                let _ = backend.reconcile_vpn_guard(guard_enabled, doh_active);
                Ok::<(), String>(())
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task error: {e}")));

            match res {
                Ok(()) => BridgeResponse::Ok,
                Err(message) => BridgeResponse::Error { message },
            }
        }
        BridgeRequest::ResetSystemDns => {
            let res = tokio::task::spawn_blocking(move || {
                backend.reset_to_system_default()?;
                let _ = backend.restore_vpn_guard();
                Ok::<(), String>(())
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task error: {e}")));

            match res {
                Ok(()) => BridgeResponse::Ok,
                Err(message) => BridgeResponse::Error { message },
            }
        }
        BridgeRequest::FlushDnsCache => {
            let res = tokio::task::spawn_blocking(move || backend.flush_dns_cache())
                .await
                .unwrap_or_else(|e| Err(format!("Task error: {e}")));
            match res {
                Ok(()) => BridgeResponse::Ok,
                Err(message) => BridgeResponse::Error { message },
            }
        }
        BridgeRequest::SetFallback { server } => match cfg.set_fallback(&server) {
            Ok(()) => BridgeResponse::Ok,
            Err(message) => BridgeResponse::Error { message },
        },
        BridgeRequest::SetVpnGuard { enabled } => {
            cfg.set_vpn_guard(enabled);
            let res = tokio::task::spawn_blocking(move || {
                let doh_active = backend
                    .current_system_dns_servers()
                    .iter()
                    .any(|s| s == "127.0.0.1");
                let _ = backend.reconcile_vpn_guard(enabled, doh_active);
            })
            .await;
            match res {
                Ok(()) => BridgeResponse::Ok,
                Err(e) => BridgeResponse::Error {
                    message: format!("Task error: {e}"),
                },
            }
        }
        BridgeRequest::GetNetworkInfo => {
            let info = tokio::task::spawn_blocking(move || NetworkInfoPayload {
                current_dns_servers: backend.current_system_dns_servers(),
                dhcp_dns: backend.detect_dhcp_dns_server(),
                vpn_active: backend.has_active_vpn_interface(),
                vpn_overridden: backend.is_global_dns_overridden_by_vpn(),
                vpn_dns_servers: backend.detect_active_vpn_dns_servers(&Default::default()),
                vpn_search_domains: backend.detect_active_vpn_search_domains(),
                dns_stack: backend.dns_stack_description(),
            })
            .await;

            match info {
                Ok(payload) => BridgeResponse::NetworkInfo(payload),
                Err(e) => BridgeResponse::Error {
                    message: format!("Task error: {e}"),
                },
            }
        }
    }
}

pub async fn send_ipc_request(req: &BridgeRequest) -> Result<BridgeResponse, String> {
    let addr: SocketAddr = BRIDGE_IPC_ADDR.parse().unwrap();
    send_ipc_request_to(addr, req).await
}

pub async fn send_ipc_request_to(
    addr: SocketAddr,
    req: &BridgeRequest,
) -> Result<BridgeResponse, String> {
    let mut stream = timeout(Duration::from_millis(800), TcpStream::connect(addr))
        .await
        .map_err(|_| "Таймаут подключения к DoH-мосту".to_string())?
        .map_err(|e| format!("DoH-мост недоступен: {e}"))?;

    let mut payload = serde_json::to_string(req).map_err(|e| e.to_string())?;
    payload.push('\n');
    stream
        .write_all(payload.as_bytes())
        .await
        .map_err(|e| format!("Ошибка отправки команды мосту: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    timeout(Duration::from_secs(6), reader.read_line(&mut line))
        .await
        .map_err(|_| "Таймаут ответа DoH-моста".to_string())?
        .map_err(|e| format!("Ошибка чтения ответа моста: {e}"))?;

    serde_json::from_str::<BridgeResponse>(line.trim())
        .map_err(|e| format!("Некорректный ответ DoH-моста: {e}"))
}

pub async fn is_bridge_running() -> bool {
    let ipc_ok = matches!(
        send_ipc_request(&BridgeRequest::Ping).await,
        Ok(BridgeResponse::Pong { .. })
    );
    if ipc_ok {
        return true;
    }
    let dns_addr: SocketAddr = BRIDGE_DNS_ADDR.parse().unwrap();
    timeout(Duration::from_millis(50), TcpStream::connect(dns_addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

pub fn is_ipv4_reply_ok(reply: &[u8]) -> bool {
    reply.len() >= 12 && rcode(reply) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_packet::{build_a_query, synthesize_bootstrap_response, transaction_id};
    use crate::platform::mock::MockDnsBackend;

    #[test]
    fn test_ipc_json_roundtrip_and_validation() {
        let req = BridgeRequest::SetSystemDns {
            servers: vec!["127.0.0.1".to_string()],
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: BridgeRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, BridgeRequest::SetSystemDns { .. }));

        assert!(validate_dns_server_list(&["127.0.0.1".to_string()]).is_ok());
        assert!(validate_dns_server_list(&["bad-ip".to_string()]).is_err());
        assert!(validate_dns_server_list(&vec!["1.1.1.1".to_string(); 5]).is_err());
    }

    #[tokio::test]
    async fn test_bridge_udp_and_tcp_forwarding() {
        // Mock upstream proxy on ephemeral port
        let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, peer)) = upstream_sock.recv_from(&mut buf).await else {
                    break;
                };
                if let Some(resp) = synthesize_bootstrap_response(&buf[..n], &["1.2.3.4".to_string()], 60) {
                    let _ = upstream_sock.send_to(&resp, peer).await;
                }
            }
        });

        // Reserve ephemeral UDP & TCP ports for bridge test
        let udp_probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp_probe.local_addr().unwrap();
        drop(udp_probe);

        let tcp_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_addr = tcp_probe.local_addr().unwrap();
        drop(tcp_probe);

        let cfg = BridgeRuntimeConfig::new(upstream_addr, None);
        tokio::spawn(async move {
            let _ = run_port53_bridge(udp_addr, tcp_addr, cfg).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let query = build_a_query("example.com", 0x4242);
        let udp_reply = send_udp_dns(&query, udp_addr, 1000).await.unwrap();
        assert_eq!(transaction_id(&udp_reply), 0x4242);
        assert_eq!(
            crate::dns_packet::extract_a_records(&udp_reply),
            vec!["1.2.3.4".to_string()]
        );

        // TCP DNS test
        let mut tcp = TcpStream::connect(tcp_addr).await.unwrap();
        let len_bytes = (query.len() as u16).to_be_bytes();
        tcp.write_all(&len_bytes).await.unwrap();
        tcp.write_all(&query).await.unwrap();
        let mut resp_len = [0u8; 2];
        tcp.read_exact(&mut resp_len).await.unwrap();
        let mut tcp_reply = vec![0u8; u16::from_be_bytes(resp_len) as usize];
        tcp.read_exact(&mut tcp_reply).await.unwrap();
        assert_eq!(transaction_id(&tcp_reply), 0x4242);
        assert_eq!(
            crate::dns_packet::extract_a_records(&tcp_reply),
            vec!["1.2.3.4".to_string()]
        );
    }

    #[tokio::test]
    async fn test_ipc_server_with_mock_backend() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ipc_addr = probe.local_addr().unwrap();
        drop(probe);

        let backend = Arc::new(MockDnsBackend::new());
        let cfg = BridgeRuntimeConfig::new("127.0.0.1:53535".parse().unwrap(), None);
        tokio::spawn(async move {
            let _ = run_ipc_server(ipc_addr, backend, cfg).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let pong = send_ipc_request_to(ipc_addr, &BridgeRequest::Ping).await.unwrap();
        assert!(matches!(pong, BridgeResponse::Pong { version } if version == BRIDGE_VERSION));

        let set_res = send_ipc_request_to(
            ipc_addr,
            &BridgeRequest::SetSystemDns {
                servers: vec!["127.0.0.1".to_string()],
            },
        )
        .await
        .unwrap();
        assert!(matches!(set_res, BridgeResponse::Ok));

        let info = send_ipc_request_to(ipc_addr, &BridgeRequest::GetNetworkInfo)
            .await
            .unwrap();
        match info {
            BridgeResponse::NetworkInfo(payload) => {
                assert_eq!(payload.current_dns_servers, vec!["127.0.0.1".to_string()]);
            }
            other => panic!("Unexpected response: {other:?}"),
        }
    }
}
