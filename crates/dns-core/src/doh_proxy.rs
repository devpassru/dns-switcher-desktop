use crate::bridge_ipc::{send_udp_dns, APP_PROXY_ADDR, DEFAULT_FALLBACK_DNS};
use crate::dns_packet::{
    base64url_encode, build_a_query, build_failure_response, extract_a_records, extract_min_ttl,
    parse_question, qtype_name, rcode, synthesize_bootstrap_response, transaction_id,
    with_transaction_id,
};
use crate::history::DNSHistoryStore;
use crate::models::{DNSProvider, ProviderHealth, ResolutionSource};
use crate::platform::SystemDnsBackend;
use crate::rules::{is_domain_excluded, is_valid_non_loopback_ipv4, normalize_domain_rule};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tokio::time::timeout;

#[derive(Clone)]
struct CacheEntry {
    data: Vec<u8>,
    fresh_until: Instant,
    stale_until: Instant,
    ips: Vec<String>,
}

#[derive(Clone)]
struct BootstrapEntry {
    ips: Vec<String>,
    expires_at: Instant,
}

#[derive(Clone)]
struct TimedListCache {
    items: Vec<String>,
    expires_at: Instant,
}

struct ProxyConfig {
    active_provider: DNSProvider,
    all_providers: Vec<DNSProvider>,
    fallback_server: String,
    is_fallback_enabled: bool,
    excluded_domains: Vec<String>,
}

struct SharedState {
    config: RwLock<ProxyConfig>,
    cache: Mutex<HashMap<String, CacheEntry>>,
    bootstrap_cache: Mutex<HashMap<String, BootstrapEntry>>,
    system_servers_cache: Mutex<Option<TimedListCache>>,
    vpn_search_cache: Mutex<Option<TimedListCache>>,
    in_flight: Mutex<HashMap<String, broadcast::Sender<Option<(Vec<u8>, Vec<String>)>>>>,
    client: RwLock<reqwest::Client>,
    backend: Arc<dyn SystemDnsBackend>,
    history: DNSHistoryStore,
    on_query_outcome: Mutex<Option<Arc<dyn Fn(bool, String) + Send + Sync>>>,
}

#[derive(Debug)]
enum DoHResult {
    Success(Vec<u8>),
    HttpError { status: u16, message: String },
    Timeout,
    Failed(String),
}

struct BootstrapDnsResolver {
    state: Arc<std::sync::Weak<SharedState>>,
}

impl Resolve for BootstrapDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().trim_end_matches('.').to_lowercase();
        let weak = self.state.clone();
        Box::pin(async move {
            let mut ips: Vec<IpAddr> = Vec::new();
            if let Ok(ip) = host.parse::<Ipv4Addr>() {
                ips.push(IpAddr::V4(ip));
            } else if let Some(state) = weak.upgrade() {
                let resolved = resolve_bootstrap_ips_for_host(&state, &host).await;
                for s in resolved {
                    if let Ok(ip) = s.parse::<Ipv4Addr>() {
                        ips.push(IpAddr::V4(ip));
                    }
                }
            }

            if ips.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Bootstrap DNS resolution failed for {host}"),
                )) as Box<dyn std::error::Error + Send + Sync>);
            }

            let addrs: Addrs = Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

#[derive(Clone)]
pub struct LocalDoHProxy {
    state: Arc<SharedState>,
    started: Arc<Mutex<bool>>,
}

impl LocalDoHProxy {
    pub fn new(backend: Arc<dyn SystemDnsBackend>, history: DNSHistoryStore) -> Self {
        let initial_provider = DNSProvider::built_in_providers().into_iter().next().unwrap();
        let all_providers = DNSProvider::built_in_providers();

        let state = Arc::new_cyclic(|weak| {
            let weak_arc = Arc::new(weak.clone());
            let client = build_http_client(weak_arc);
            SharedState {
                config: RwLock::new(ProxyConfig {
                    active_provider: initial_provider,
                    all_providers,
                    fallback_server: DEFAULT_FALLBACK_DNS.to_string(),
                    is_fallback_enabled: true,
                    excluded_domains: Vec::new(),
                }),
                cache: Mutex::new(HashMap::new()),
                bootstrap_cache: Mutex::new(HashMap::new()),
                system_servers_cache: Mutex::new(None),
                vpn_search_cache: Mutex::new(None),
                in_flight: Mutex::new(HashMap::new()),
                client: RwLock::new(client),
                backend,
                history,
                on_query_outcome: Mutex::new(None),
            }
        });

        Self {
            state,
            started: Arc::new(Mutex::new(false)),
        }
    }

    pub fn set_on_query_outcome<F>(&self, cb: F)
    where
        F: Fn(bool, String) + Send + Sync + 'static,
    {
        if let Ok(mut g) = self.state.on_query_outcome.lock() {
            *g = Some(Arc::new(cb));
        }
    }

    pub fn configure(&self, active: DNSProvider, all: Vec<DNSProvider>) {
        let changed = {
            let mut cfg = self.state.config.write().unwrap();
            let ch = cfg.active_provider.id != active.id || cfg.active_provider.doh_url != active.doh_url;
            cfg.active_provider = active.clone();
            cfg.all_providers = all;
            ch
        };
        if changed {
            if let Ok(mut cache) = self.state.cache.lock() {
                cache.clear();
            }
        }
        if active.bootstrap_ips.is_empty() {
            let host = active.doh_host().trim_matches('.').to_lowercase();
            if !host.is_empty() {
                let state = self.state.clone();
                tokio::spawn(async move {
                    let _ = resolve_bootstrap_ips_for_host(&state, &host).await;
                });
            }
        }
    }

    pub fn set_fallback_server(&self, ip_or_disabled: &str) {
        let trimmed = ip_or_disabled.trim().to_lowercase();
        let mut cfg = self.state.config.write().unwrap();
        if trimmed == "disabled" || trimmed == "none" {
            cfg.is_fallback_enabled = false;
        } else if is_valid_non_loopback_ipv4(&trimmed) {
            cfg.is_fallback_enabled = true;
            cfg.fallback_server = trimmed;
        }
        if let Ok(mut sys) = self.state.system_servers_cache.lock() {
            *sys = None;
        }
    }

    pub fn set_excluded_domains(&self, domains: &[String]) {
        let normalized: Vec<String> = domains
            .iter()
            .filter_map(|d| normalize_domain_rule(d))
            .collect();
        {
            let mut cfg = self.state.config.write().unwrap();
            cfg.excluded_domains = normalized;
        }
        self.clear_cache();
    }

    pub fn clear_cache(&self) {
        if let Ok(mut g) = self.state.cache.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.state.system_servers_cache.lock() {
            *g = None;
        }
        if let Ok(mut g) = self.state.vpn_search_cache.lock() {
            *g = None;
        }
    }

    pub fn reset_network_connections(&self) {
        let weak = Arc::new(Arc::downgrade(&self.state));
        let fresh_client = build_http_client(weak);
        if let Ok(mut c) = self.state.client.write() {
            *c = fresh_client;
        }
        if let Ok(mut g) = self.state.in_flight.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.state.bootstrap_cache.lock() {
            g.clear();
        }
        self.clear_cache();
    }

    pub fn start_if_needed(&self) {
        let mut started = self.started.lock().unwrap();
        if *started {
            return;
        }
        *started = true;
        drop(started);

        let proxy = self.clone();
        tokio::spawn(async move {
            let addr: SocketAddr = APP_PROXY_ADDR.parse().unwrap();
            let sock = match UdpSocket::bind(addr).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    tracing::error!("[LocalDoHProxy] Failed to bind {addr}: {e}");
                    return;
                }
            };
            tracing::info!("[LocalDoHProxy] Listening on {addr}");

            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                if n < 12 {
                    continue;
                }
                let query = buf[..n].to_vec();
                let sock_clone = sock.clone();
                let proxy_clone = proxy.clone();
                tokio::spawn(async move {
                    if let Some(reply) = proxy_clone.resolve_dns_query(&query).await {
                        let _ = sock_clone.send_to(&reply, peer).await;
                    }
                });
            }
        });
    }

    pub async fn resolve_dns_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        let tx_id = transaction_id(query);
        let (provider, providers, fallback_host, fallback_active, excluded) = {
            let cfg = self.state.config.read().unwrap();
            (
                cfg.active_provider.clone(),
                cfg.all_providers.clone(),
                cfg.fallback_server.clone(),
                cfg.is_fallback_enabled,
                cfg.excluded_domains.clone(),
            )
        };

        let Some((domain, qtype)) = parse_question(query) else {
            if fallback_active {
                if let Ok(ip) = fallback_host.parse::<IpAddr>() {
                    return send_udp_dns(query, SocketAddr::new(ip, 53), 2000).await;
                }
            }
            return Some(build_failure_response(query, 2));
        };

        let qtype_str = qtype_name(qtype);
        let clean_domain = domain.trim_matches('.').to_lowercase();

        // 1. Bootstrap anti-recursion check
        if let Some(matched) = providers.iter().find(|p| {
            let doh_h = p.doh_host().trim_matches('.').to_lowercase();
            let dot_h = p.dot_host.trim_matches('.').to_lowercase();
            (!doh_h.is_empty() && doh_h == clean_domain) || (!dot_h.is_empty() && dot_h == clean_domain)
        }) {
            if !matched.bootstrap_ips.is_empty() {
                if let Some(synth) = synthesize_bootstrap_response(query, &matched.bootstrap_ips, 300) {
                    self.log_resolution(
                        domain,
                        qtype_str,
                        ResolutionSource::Cache,
                        "Bootstrap (Static)".to_string(),
                        1,
                        matched.bootstrap_ips.clone(),
                        true,
                    );
                    return Some(synth);
                }
            }

            let start = Instant::now();
            let ips = resolve_bootstrap_ips_for_host(&self.state, &clean_domain).await;
            if !ips.is_empty() {
                if let Some(synth) = synthesize_bootstrap_response(query, &ips, 300) {
                    let ms = start.elapsed().as_millis().max(1) as u64;
                    self.log_resolution(
                        domain,
                        qtype_str,
                        ResolutionSource::Cache,
                        "Bootstrap".to_string(),
                        ms,
                        ips,
                        true,
                    );
                    return Some(synth);
                }
            }
            let ms = start.elapsed().as_millis().max(1) as u64;
            self.log_resolution(
                domain,
                qtype_str,
                ResolutionSource::Error,
                "Bootstrap".to_string(),
                ms,
                Vec::new(),
                false,
            );
            return Some(build_failure_response(query, 2));
        }

        // 1b. Excluded domains check -> bypass DoH via system/VPN DNS
        if is_domain_excluded(&domain, &excluded) {
            let start = Instant::now();
            let fb_opt = if fallback_active {
                Some(fallback_host.as_str())
            } else {
                None
            };
            if let Some(reply) = resolve_via_system_dns(&self.state, query, fb_opt, &providers).await {
                let ms = start.elapsed().as_millis().max(1) as u64;
                let rc = rcode(&reply);
                let ips = extract_a_records(&reply);
                self.log_resolution(
                    domain,
                    qtype_str,
                    ResolutionSource::Excluded,
                    "VPN / DHCP".to_string(),
                    ms,
                    ips,
                    rc == 0 || rc == 3,
                );
                return Some(with_transaction_id(tx_id, &reply));
            }
            self.log_resolution(
                domain,
                qtype_str,
                ResolutionSource::Error,
                "VPN / DHCP".to_string(),
                50,
                Vec::new(),
                false,
            );
            return Some(build_failure_response(query, 2));
        }

        // 1c. Active VPN SearchDomains Split-DNS check
        let vpn_search = get_active_vpn_search_domains(&self.state).await;
        if !vpn_search.is_empty() && is_domain_excluded(&domain, &vpn_search) {
            let bootstrap_set: HashSet<String> = providers.iter().flat_map(|p| p.bootstrap_ips.clone()).collect();
            let vpn_servers = self.state.backend.detect_active_vpn_dns_servers(&bootstrap_set);
            if !vpn_servers.is_empty() {
                let start = Instant::now();
                if let Some(reply) = resolve_via_specific_dns_allowing_nxdomain(query, &vpn_servers).await {
                    let ms = start.elapsed().as_millis().max(1) as u64;
                    let rc = rcode(&reply);
                    let ips = extract_a_records(&reply);
                    self.log_resolution(
                        domain,
                        qtype_str,
                        ResolutionSource::Excluded,
                        "VPN DNS".to_string(),
                        ms,
                        ips,
                        rc == 0 || rc == 3,
                    );
                    return Some(with_transaction_id(tx_id, &reply));
                }
            }
        }

        // 2. Fresh in-memory TTL cache
        let cache_key = format!("{}:{}:{}", provider.id, domain, qtype);
        if let Some(entry) = get_fresh_cached(&self.state, &cache_key) {
            self.log_resolution(
                domain,
                qtype_str,
                ResolutionSource::Cache,
                provider.name.clone(),
                1,
                entry.ips,
                true,
            );
            return Some(with_transaction_id(tx_id, &entry.data));
        }

        // 3. Coalesced RFC 8484 DoH request
        let start = Instant::now();
        if let Some((doh_reply, ips)) =
            perform_coalesced_doh_request(&self.state, &cache_key, query, qtype, &provider.doh_url).await
        {
            let rc = rcode(&doh_reply);
            // Auto-fallback to VPN DNS on NXDOMAIN (rcode 3) or empty A answer (qtype 1)
            // Do NOT fall back on empty AAAA (qtype 28)
            if rc == 3 || (rc == 0 && ips.is_empty() && qtype == 1) {
                let bootstrap_set: HashSet<String> =
                    providers.iter().flat_map(|p| p.bootstrap_ips.clone()).collect();
                let vpn_servers = self.state.backend.detect_active_vpn_dns_servers(&bootstrap_set);
                if !vpn_servers.is_empty() {
                    if let Some(vpn_reply) = resolve_via_specific_dns(query, &vpn_servers).await {
                        let vpn_ips = extract_a_records(&vpn_reply);
                        if rcode(&vpn_reply) == 0 && !vpn_ips.is_empty() {
                            let ttl = extract_min_ttl(&vpn_reply, 60).min(60);
                            set_cached(&self.state, &cache_key, vpn_reply.clone(), ttl, vpn_ips.clone());
                            let ms = start.elapsed().as_millis().max(1) as u64;
                            self.log_resolution(
                                domain,
                                qtype_str,
                                ResolutionSource::Excluded,
                                "VPN DNS".to_string(),
                                ms,
                                vpn_ips,
                                true,
                            );
                            return Some(with_transaction_id(tx_id, &vpn_reply));
                        }
                    }
                }
                if self.state.backend.has_active_vpn_interface() {
                    let short_ttl = extract_min_ttl(&doh_reply, 30).min(30);
                    set_cached(&self.state, &cache_key, doh_reply.clone(), short_ttl, ips.clone());
                }
            }

            let ms = start.elapsed().as_millis().max(1) as u64;
            self.log_resolution(
                domain,
                qtype_str,
                ResolutionSource::Doh,
                provider.name.clone(),
                ms,
                ips,
                true,
            );
            return Some(with_transaction_id(tx_id, &doh_reply));
        }

        let failed_ms = start.elapsed().as_millis().max(1) as u64;

        // 4. Serve-Stale cache (RFC 8767)
        if let Some(stale) = get_stale_cached(&self.state, &cache_key) {
            self.log_resolution(
                domain,
                qtype_str,
                ResolutionSource::StaleCache,
                format!("{} (кэш)", provider.name),
                failed_ms,
                stale.ips,
                true,
            );
            return Some(with_transaction_id(tx_id, &stale.data));
        }

        // 5. Fallback DNS if enabled
        if fallback_active {
            if let Ok(ip) = fallback_host.parse::<IpAddr>() {
                let fb_start = Instant::now();
                if let Some(fb_reply) = send_udp_dns(query, SocketAddr::new(ip, 53), 2000).await {
                    let fb_ms = fb_start.elapsed().as_millis().max(1) as u64;
                    let ips = extract_a_records(&fb_reply);
                    self.log_resolution(
                        domain,
                        qtype_str,
                        ResolutionSource::Fallback,
                        fallback_host,
                        fb_ms,
                        ips,
                        true,
                    );
                    return Some(with_transaction_id(tx_id, &fb_reply));
                }
            }
        }

        self.log_resolution(
            domain,
            qtype_str,
            ResolutionSource::Error,
            provider.name,
            failed_ms,
            Vec::new(),
            false,
        );
        Some(build_failure_response(query, 2))
    }

    pub async fn check_provider_health(&self, provider: &DNSProvider, test_domain: &str) -> ProviderHealth {
        let query = build_a_query(test_domain, 0x1234);
        let start = Instant::now();
        let result = perform_doh_request_detailed(&self.state, &query, &provider.doh_url).await;
        let doh_ms = start.elapsed().as_millis().max(1) as u64;

        match result {
            DoHResult::Success(resp_data) => {
                let ips = extract_a_records(&resp_data);
                let Some(first_ip) = ips.first().cloned() else {
                    return ProviderHealth::Degraded {
                        latency_ms: doh_ms,
                        reason: "Пустой ответ DNS".to_string(),
                    };
                };

                if check_tcp_port_443(&first_ip, 1800).await {
                    ProviderHealth::Healthy {
                        latency_ms: doh_ms,
                        resolved_ip: first_ip,
                    }
                } else {
                    ProviderHealth::Degraded {
                        latency_ms: doh_ms,
                        reason: format!("Прокси {first_ip}:443 не отвечает"),
                    }
                }
            }
            DoHResult::HttpError { status, message } => {
                let reason = match status {
                    401 => "Ошибка 401 (токен истёк или не авторизован)".to_string(),
                    403 => "Ошибка 403 (доступ запрещён)".to_string(),
                    429 => "Ошибка 429 (лимит запросов)".to_string(),
                    _ => format!("HTTP {status} ({message})"),
                };
                ProviderHealth::Unreachable { reason }
            }
            DoHResult::Timeout => ProviderHealth::Unreachable {
                reason: "Таймаут DoH (>2.5с)".to_string(),
            },
            DoHResult::Failed(err) => ProviderHealth::Unreachable {
                reason: if err.is_empty() {
                    "DoH недоступен".to_string()
                } else {
                    err
                },
            },
        }
    }

    fn log_resolution(
        &self,
        domain: String,
        qtype: String,
        source: ResolutionSource,
        server_name: String,
        latency_ms: u64,
        resolved_ips: Vec<String>,
        is_success: bool,
    ) {
        self.state.history.log_resolution(
            domain,
            qtype,
            source,
            server_name.clone(),
            latency_ms,
            resolved_ips,
            is_success,
        );
        if let Ok(guard) = self.state.on_query_outcome.lock() {
            if let Some(cb) = guard.as_ref() {
                cb(is_success, server_name);
            }
        }
    }
}

fn build_http_client(weak_state: Arc<std::sync::Weak<SharedState>>) -> reqwest::Client {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(BootstrapDnsResolver { state: weak_state }))
        .timeout(Duration::from_millis(2400))
        .connect_timeout(Duration::from_millis(1800))
        .pool_max_idle_per_host(16)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn check_tcp_port_443(ip: &str, timeout_ms: u64) -> bool {
    let Ok(parsed_ip) = ip.parse::<IpAddr>() else {
        return false;
    };
    let addr = SocketAddr::new(parsed_ip, 443);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

async fn perform_coalesced_doh_request(
    state: &Arc<SharedState>,
    key: &str,
    query: &[u8],
    qtype: u16,
    doh_url: &str,
) -> Option<(Vec<u8>, Vec<String>)> {
    let rx_opt = {
        let mut map = state.in_flight.lock().unwrap();
        if let Some(tx) = map.get(key) {
            Some(tx.subscribe())
        } else {
            let (tx, _) = broadcast::channel(8);
            map.insert(key.to_string(), tx);
            None
        }
    };

    if let Some(mut rx) = rx_opt {
        return rx.recv().await.ok().flatten();
    }

    let result = match perform_doh_request_detailed(state, query, doh_url).await {
        DoHResult::Success(reply) => {
            let rc = rcode(&reply);
            let ips = extract_a_records(&reply);
            let defer_cache =
                (rc == 3 || (rc == 0 && ips.is_empty() && qtype == 1)) && state.backend.has_active_vpn_interface();
            if !defer_cache {
                let ttl = extract_min_ttl(&reply, 60);
                set_cached(state, key, reply.clone(), ttl, ips.clone());
            }
            Some((reply, ips))
        }
        _ => None,
    };

    if let Some(tx) = state.in_flight.lock().unwrap().remove(key) {
        let _ = tx.send(result.clone());
    }
    result
}

async fn perform_doh_request_detailed(
    state: &Arc<SharedState>,
    query: &[u8],
    doh_url: &str,
) -> DoHResult {
    let Ok(_) = reqwest::Url::parse(doh_url) else {
        return DoHResult::Failed("Некорректный URL".to_string());
    };

    let client = state.client.read().unwrap().clone();
    let b64 = base64url_encode(query);
    let sep = if doh_url.contains('?') { '&' } else { '?' };
    let get_url = format!("{doh_url}{sep}dns={b64}");

    let get_res = execute_http_request(
        client
            .get(&get_url)
            .header("Accept", "application/dns-message"),
    )
    .await;

    match get_res {
        DoHResult::Success(_) => return get_res,
        DoHResult::HttpError { status, .. } if matches!(status, 401 | 403 | 429) => {
            return get_res;
        }
        _ => {}
    }

    // RFC 8484 POST fallback
    let post_res = execute_http_request(
        client
            .post(doh_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query.to_vec()),
    )
    .await;

    if matches!(post_res, DoHResult::Success(_)) {
        return post_res;
    }

    get_res
}

async fn execute_http_request(req: reqwest::RequestBuilder) -> DoHResult {
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.bytes().await {
                    Ok(bytes) if bytes.len() >= 12 => DoHResult::Success(bytes.to_vec()),
                    Ok(_) => DoHResult::Failed("Слишком короткий ответ DNS".to_string()),
                    Err(e) => DoHResult::Failed(e.to_string()),
                }
            } else {
                DoHResult::HttpError {
                    status: status.as_u16(),
                    message: status.canonical_reason().unwrap_or("Error").to_string(),
                }
            }
        }
        Err(e) => {
            if e.is_timeout() {
                DoHResult::Timeout
            } else {
                DoHResult::Failed(e.to_string())
            }
        }
    }
}

async fn resolve_bootstrap_ips_for_host(state: &Arc<SharedState>, clean_domain: &str) -> Vec<String> {
    if is_valid_non_loopback_ipv4(clean_domain) {
        return vec![clean_domain.to_string()];
    }

    // 1. Check static bootstrap IPs on configured providers
    let (providers, fallback_opt) = {
        let cfg = state.config.read().unwrap();
        let fb = if cfg.is_fallback_enabled {
            Some(cfg.fallback_server.clone())
        } else {
            None
        };
        (cfg.all_providers.clone(), fb)
    };

    if let Some(p) = providers.iter().find(|p| {
        let doh_h = p.doh_host().trim_matches('.').to_lowercase();
        let dot_h = p.dot_host.trim_matches('.').to_lowercase();
        doh_h == clean_domain || dot_h == clean_domain
    }) {
        if !p.bootstrap_ips.is_empty() {
            return p.bootstrap_ips.clone();
        }
    }

    // 2. Check dynamic bootstrap cache
    if let Ok(cache) = state.bootstrap_cache.lock() {
        if let Some(entry) = cache.get(clean_domain) {
            if entry.expires_at > Instant::now() && !entry.ips.is_empty() {
                return entry.ips.clone();
            }
        }
    }

    // 3. Query system/DHCP DNS directly via UDP
    let query = build_a_query(clean_domain, 0x7788);
    if let Some(reply) = resolve_via_system_dns(state, &query, fallback_opt.as_deref(), &providers).await {
        let ips = extract_a_records(&reply);
        if !ips.is_empty() {
            let ttl = extract_min_ttl(&reply, 3600).max(1800) as u64;
            if let Ok(mut cache) = state.bootstrap_cache.lock() {
                cache.insert(
                    clean_domain.to_string(),
                    BootstrapEntry {
                        ips: ips.clone(),
                        expires_at: Instant::now() + Duration::from_secs(ttl),
                    },
                );
            }
            return ips;
        }
    }

    // 4. Emergency rescue DNS for DoH host bootstrap
    for rescue in ["77.88.8.8", "1.1.1.1", "8.8.8.8"] {
        if let Ok(ip) = rescue.parse::<IpAddr>() {
            if let Some(reply) = send_udp_dns(&query, SocketAddr::new(ip, 53), 1500).await {
                let ips = extract_a_records(&reply);
                if !ips.is_empty() {
                    if let Ok(mut cache) = state.bootstrap_cache.lock() {
                        cache.insert(
                            clean_domain.to_string(),
                            BootstrapEntry {
                                ips: ips.clone(),
                                expires_at: Instant::now() + Duration::from_secs(3600),
                            },
                        );
                    }
                    return ips;
                }
            }
        }
    }

    Vec::new()
}

async fn resolve_via_system_dns(
    state: &Arc<SharedState>,
    query: &[u8],
    fallback_host: Option<&str>,
    providers: &[DNSProvider],
) -> Option<Vec<u8>> {
    let servers = get_system_and_vpn_dns_servers(state, fallback_host, providers).await;
    let mut first_reply = None;
    for srv in servers {
        let Ok(ip) = srv.parse::<IpAddr>() else {
            continue;
        };
        if let Some(reply) = send_udp_dns(query, SocketAddr::new(ip, 53), 900).await {
            if rcode(&reply) == 0 {
                return Some(reply);
            }
            if first_reply.is_none() {
                first_reply = Some(reply);
            }
        }
    }
    first_reply
}

async fn resolve_via_specific_dns(query: &[u8], servers: &[String]) -> Option<Vec<u8>> {
    for srv in servers {
        let Ok(ip) = srv.parse::<IpAddr>() else {
            continue;
        };
        if let Some(reply) = send_udp_dns(query, SocketAddr::new(ip, 53), 1200).await {
            if rcode(&reply) == 0 {
                return Some(reply);
            }
        }
    }
    None
}

async fn resolve_via_specific_dns_allowing_nxdomain(query: &[u8], servers: &[String]) -> Option<Vec<u8>> {
    let mut first_nxd = None;
    for srv in servers {
        let Ok(ip) = srv.parse::<IpAddr>() else {
            continue;
        };
        if let Some(reply) = send_udp_dns(query, SocketAddr::new(ip, 53), 900).await {
            let rc = rcode(&reply);
            if rc == 0 {
                return Some(reply);
            }
            if rc == 3 && first_nxd.is_none() {
                first_nxd = Some(reply);
            }
        }
    }
    first_nxd
}

async fn get_active_vpn_search_domains(state: &Arc<SharedState>) -> Vec<String> {
    if let Ok(g) = state.vpn_search_cache.lock() {
        if let Some(cached) = g.as_ref() {
            if cached.expires_at > Instant::now() {
                return cached.items.clone();
            }
        }
    }
    let backend = state.backend.clone();
    let detected = tokio::task::spawn_blocking(move || backend.detect_active_vpn_search_domains())
        .await
        .unwrap_or_default();
    if let Ok(mut g) = state.vpn_search_cache.lock() {
        *g = Some(TimedListCache {
            items: detected.clone(),
            expires_at: Instant::now() + Duration::from_secs(30),
        });
    }
    detected
}

async fn get_system_and_vpn_dns_servers(
    state: &Arc<SharedState>,
    fallback_host: Option<&str>,
    providers: &[DNSProvider],
) -> Vec<String> {
    if let Ok(g) = state.system_servers_cache.lock() {
        if let Some(cached) = g.as_ref() {
            if cached.expires_at > Instant::now() {
                return cached.items.clone();
            }
        }
    }
    let backend = state.backend.clone();
    let bootstrap_set: HashSet<String> = providers.iter().flat_map(|p| p.bootstrap_ips.clone()).collect();
    let fb = fallback_host.map(|s| s.to_string());
    let detected = tokio::task::spawn_blocking(move || {
        backend.detect_system_and_vpn_dns_servers(fb.as_deref(), &bootstrap_set)
    })
    .await
    .unwrap_or_default();
    if let Ok(mut g) = state.system_servers_cache.lock() {
        *g = Some(TimedListCache {
            items: detected.clone(),
            expires_at: Instant::now() + Duration::from_secs(60),
        });
    }
    detected
}

fn get_fresh_cached(state: &Arc<SharedState>, key: &str) -> Option<CacheEntry> {
    let g = state.cache.lock().ok()?;
    let entry = g.get(key)?;
    if entry.fresh_until > Instant::now() {
        Some(entry.clone())
    } else {
        None
    }
}

fn get_stale_cached(state: &Arc<SharedState>, key: &str) -> Option<CacheEntry> {
    let mut g = state.cache.lock().ok()?;
    let entry = g.get(key)?.clone();
    if entry.stale_until > Instant::now() {
        Some(entry)
    } else {
        g.remove(key);
        None
    }
}

fn set_cached(state: &Arc<SharedState>, key: &str, data: Vec<u8>, fresh_ttl: u32, ips: Vec<String>) {
    let Ok(mut g) = state.cache.lock() else {
        return;
    };
    let now = Instant::now();
    if g.len() >= 1024 {
        g.retain(|_, v| v.stale_until > now);
        if g.len() >= 1024 {
            g.retain(|_, v| v.fresh_until > now);
        }
        if g.len() >= 1024 {
            let to_remove: Vec<String> = g.keys().take(256).cloned().collect();
            for k in to_remove {
                g.remove(&k);
            }
        }
    }
    let fresh_secs = fresh_ttl.clamp(15, 1800) as u64;
    g.insert(
        key.to_string(),
        CacheEntry {
            data,
            fresh_until: now + Duration::from_secs(fresh_secs),
            stale_until: now + Duration::from_secs(86400),
            ips,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockDnsBackend;

    #[tokio::test]
    async fn test_proxy_bootstrap_and_disabled_fallback_servfail() {
        let backend = Arc::new(MockDnsBackend::new());
        let history = DNSHistoryStore::new();
        let proxy = LocalDoHProxy::new(backend, history.clone());

        // 1. Bootstrap static synthesis
        let q_boot = build_a_query("dns.comss.one", 0x1111);
        let resp_boot = proxy.resolve_dns_query(&q_boot).await.unwrap();
        assert_eq!(transaction_id(&resp_boot), 0x1111);
        assert_eq!(rcode(&resp_boot), 0);
        assert!(extract_a_records(&resp_boot).contains(&"195.133.25.16".to_string()));

        // 2. Broken provider + disabled fallback => SERVFAIL (rcode 2)
        proxy.set_fallback_server("disabled");
        let broken = DNSProvider {
            id: "broken".to_string(),
            name: "Broken".to_string(),
            subtitle: "broken".to_string(),
            doh_url: "https://127.0.0.1:59999/dns-query".to_string(),
            dot_host: "broken.invalid".to_string(),
            bootstrap_ips: vec![],
            plain_dns_supported: false,
            website_url: "".to_string(),
            is_built_in: false,
            is_enabled_in_menu_bar: true,
        };
        proxy.configure(broken.clone(), vec![broken]);

        let q_fail = build_a_query("nonexistent-test.example", 0x3333);
        let resp_fail = proxy.resolve_dns_query(&q_fail).await.unwrap();
        assert_eq!(transaction_id(&resp_fail), 0x3333);
        assert_eq!(rcode(&resp_fail), 2);
        let records = history.records();
        assert_eq!(records.first().unwrap().source, ResolutionSource::Error);
    }
}
