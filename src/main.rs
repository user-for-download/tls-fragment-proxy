use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use dashmap::DashMap;
use humansize::{format_size, BINARY};
use parking_lot::RwLock;
use rand::Rng;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex, Semaphore};
use tokio::time::{interval, timeout, sleep};
use tracing::{debug, error, info, warn, trace};
use tracing::Level;

const VERSION: &str = "1.0.1";
const BUFFER_SIZE: usize = 65536;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Error, Debug)]
enum ProxyError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Timeout")]
    Timeout,

    #[error("Rate limited")]
    RateLimited,

    #[error("Configuration error: {0}")]
    Configuration(String),
}

// Check if error is expected/normal
fn is_expected_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::ConnectionReset |
        ErrorKind::ConnectionAborted |
        ErrorKind::BrokenPipe |
        ErrorKind::UnexpectedEof
    )
}

#[derive(Parser, Debug)]
#[command(name = "tls-fragment-proxy")]
#[command(version = VERSION)]
#[command(about = "HTTP/HTTPS proxy with TLS fragmentation")]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    #[arg(long, default_value_t = 8888)]
    port: u16,

    #[arg(long)]
    blacklist: Option<PathBuf>,

    #[arg(long)]
    whitelist: Option<PathBuf>,

    #[arg(long, default_value_t = 1000)]
    max_connections: usize,

    #[arg(long, default_value_t = 1000)]
    rate_limit_per_second: usize,

    #[arg(short, long)]
    quiet: bool,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Clone)]
struct Stats {
    total_connections: Arc<AtomicUsize>,
    active_connections: Arc<AtomicUsize>,
    fragmented_connections: Arc<AtomicUsize>,
    whitelisted_connections: Arc<AtomicUsize>,
    blacklisted_blocks: Arc<AtomicUsize>,
    failed_connections: Arc<AtomicUsize>,
    rate_limited_connections: Arc<AtomicUsize>,
    client_disconnects: Arc<AtomicUsize>,
    traffic_in: Arc<AtomicU64>,
    traffic_out: Arc<AtomicU64>,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_connections: Arc::new(AtomicUsize::new(0)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            fragmented_connections: Arc::new(AtomicUsize::new(0)),
            whitelisted_connections: Arc::new(AtomicUsize::new(0)),
            blacklisted_blocks: Arc::new(AtomicUsize::new(0)),
            failed_connections: Arc::new(AtomicUsize::new(0)),
            rate_limited_connections: Arc::new(AtomicUsize::new(0)),
            client_disconnects: Arc::new(AtomicUsize::new(0)),
            traffic_in: Arc::new(AtomicU64::new(0)),
            traffic_out: Arc::new(AtomicU64::new(0)),
        }
    }

    fn log_stats(&self) {
        let active = self.active_connections.load(Ordering::Relaxed);
        let total = self.total_connections.load(Ordering::Relaxed);
        let fragmented = self.fragmented_connections.load(Ordering::Relaxed);

        if total > 0 && total % 100 == 0 {
            info!(
                "Stats: Active={}, Total={}, Fragmented={}, Disconnects={}",
                active,
                total,
                fragmented,
                self.client_disconnects.load(Ordering::Relaxed)
            );
        }
    }
}

struct RateLimiter {
    limits: Arc<DashMap<IpAddr, Arc<Mutex<RateLimitEntry>>>>,
    max_per_second: usize,
}

#[derive(Debug)]
struct RateLimitEntry {
    tokens: usize,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(max_per_second: usize) -> Self {
        let limiter = Self {
            limits: Arc::new(DashMap::new()),
            max_per_second,
        };

        // Cleanup task
        let limits_clone = Arc::clone(&limiter.limits);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = Instant::now();
                limits_clone.retain(|_, entry| {
                    if let Ok(e) = entry.try_lock() {
                        now.duration_since(e.last_refill) < Duration::from_secs(300)
                    } else {
                        true
                    }
                });
            }
        });

        limiter
    }

    async fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let entry = self.limits.entry(ip)
            .or_insert_with(|| Arc::new(Mutex::new(RateLimitEntry {
                tokens: self.max_per_second,
                last_refill: Instant::now(),
            })));

        let mut entry = entry.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(entry.last_refill);

        if elapsed >= Duration::from_secs(1) {
            entry.tokens = self.max_per_second;
            entry.last_refill = now;
        }

        if entry.tokens > 0 {
            entry.tokens -= 1;
            true
        } else {
            false
        }
    }
}

struct DomainFilter {
    blacklist: Arc<RwLock<HashSet<String>>>,
    whitelist: Arc<RwLock<HashSet<String>>>,
    stats: Arc<DomainFilterStats>,
}

struct DomainFilterStats {
    blacklist_domains: AtomicUsize,
    whitelist_domains: AtomicUsize,
}

impl DomainFilter {
    async fn new(args: &Args) -> Result<Self> {
        let mut filter = Self {
            blacklist: Arc::new(RwLock::new(HashSet::new())),
            whitelist: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(DomainFilterStats {
                blacklist_domains: AtomicUsize::new(0),
                whitelist_domains: AtomicUsize::new(0),
            }),
        };

        // Load blacklist if specified
        if let Some(blacklist_path) = &args.blacklist {
            info!("Loading blacklist from: {}", blacklist_path.display());
            filter.load_list(blacklist_path, ListType::Blacklist).await
                .context(format!("Failed to load blacklist from {}", blacklist_path.display()))?;
        } else {
            info!("No blacklist specified, all domains allowed except whitelisted ones");
        }

        // Load whitelist if specified
        if let Some(whitelist_path) = &args.whitelist {
            info!("Loading whitelist from: {}", whitelist_path.display());
            filter.load_list(whitelist_path, ListType::Whitelist).await
                .context(format!("Failed to load whitelist from {}", whitelist_path.display()))?;
        } else {
            info!("No whitelist specified, fragmentation will be applied to all non-blacklisted domains");
        }

        Ok(filter)
    }

    async fn load_list(&mut self, path: &PathBuf, list_type: ListType) -> Result<()> {
        if !path.exists() {
            return Err(ProxyError::Configuration(
                format!("File not found: {}", path.display())
            ).into());
        }

        let content = tokio::fs::read_to_string(path).await
            .context(format!("Failed to read file: {}", path.display()))?;

        let domains: HashSet<String> = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_lowercase())
            .collect();

        let count = domains.len();

        match list_type {
            ListType::Blacklist => {
                *self.blacklist.write() = domains;
                self.stats.blacklist_domains.store(count, Ordering::Relaxed);
                info!("✓ Loaded {} domains from blacklist", count);
            }
            ListType::Whitelist => {
                *self.whitelist.write() = domains;
                self.stats.whitelist_domains.store(count, Ordering::Relaxed);
                info!("✓ Loaded {} domains from whitelist", count);
            }
        }

        Ok(())
    }

    fn is_whitelisted(&self, domain: &str) -> bool {
        self.check_domain_match(domain, &self.whitelist)
    }

    fn is_blacklisted(&self, domain: &str) -> bool {
        self.check_domain_match(domain, &self.blacklist)
    }

    fn check_domain_match(&self, domain: &str, list: &Arc<RwLock<HashSet<String>>>) -> bool {
        let domain_lower = domain.to_lowercase();
        let list_guard = list.read();

        // Check exact match
        if list_guard.contains(&domain_lower) {
            return true;
        }

        // Check wildcard subdomain matching
        for listed_domain in list_guard.iter() {
            if let Some(suffix) = listed_domain.strip_prefix("*.") {
                // Match if domain is exactly the suffix or is a proper subdomain
                if domain_lower == suffix ||
                    domain_lower.ends_with(&format!(".{}", suffix)) {
                    return true;
                }
            }
        }

        false
    }

    fn get_stats(&self) -> (usize, usize) {
        (
            self.stats.blacklist_domains.load(Ordering::Relaxed),
            self.stats.whitelist_domains.load(Ordering::Relaxed)
        )
    }
}

enum ListType {
    Blacklist,
    Whitelist,
}

struct ConnectionHandler {
    stats: Stats,
    filter: Arc<DomainFilter>,
    rate_limiter: Arc<RateLimiter>,
    connection_semaphore: Arc<Semaphore>,
}

impl ConnectionHandler {
    async fn handle_client(
        &self,
        mut client_stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<()> {
        // Set TCP keepalive
        let sock_ref = socket2::SockRef::from(&client_stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(10));
        let _ = sock_ref.set_tcp_keepalive(&keepalive);

        // Rate limiting
        if let Ok(ip) = client_addr.ip().to_string().parse::<IpAddr>() {
            if !self.rate_limiter.check_rate_limit(ip).await {
                self.stats.rate_limited_connections.fetch_add(1, Ordering::Relaxed);
                trace!("Rate limited connection from {}", client_addr);
                return Err(ProxyError::RateLimited.into());
            }
        }

        let _permit = self.connection_semaphore.acquire().await?;

        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);

        struct Guard<'a>(&'a AtomicUsize);
        impl<'a> Drop for Guard<'a> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        let _guard = Guard(&self.stats.active_connections);

        let mut buffer = vec![0u8; BUFFER_SIZE];

        let n = match timeout(CLIENT_TIMEOUT, client_stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => n,
            Ok(Ok(_)) => {
                trace!("Client {} closed connection", client_addr);
                self.stats.client_disconnects.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Ok(Err(e)) if is_expected_error(&e) => {
                trace!("Client {} disconnected: {}", client_addr, e);
                self.stats.client_disconnects.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Ok(Err(e)) => {
                debug!("Failed to read from client {}: {}", client_addr, e);
                return Err(e.into());
            }
            Err(_) => {
                trace!("Timeout reading from client {}", client_addr);
                return Err(ProxyError::Timeout.into());
            }
        };

        let request_data = &buffer[..n];
        let (method, host, port) = match parse_http_request(request_data) {
            Ok(data) => data,
            Err(e) => {
                trace!("Invalid request from {}: {}", client_addr, e);
                return Err(e);
            }
        };

        // Check blacklist
        if self.filter.is_blacklisted(&host) {
            debug!("Blocked blacklisted domain: {}", host);
            self.stats.blacklisted_blocks.fetch_add(1, Ordering::Relaxed);
            let _ = client_stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Ok(());
        }

        let is_whitelisted = self.filter.is_whitelisted(&host);
        if is_whitelisted {
            self.stats.whitelisted_connections.fetch_add(1, Ordering::Relaxed);
            debug!("Whitelisted domain: {} - bypassing fragmentation", host);
        }

        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
        self.stats.log_stats();

        let remote_addr = format!("{}:{}", host, port);

        trace!("Handling {} request to {} from {}", method, remote_addr, client_addr);

        let result = if method == "CONNECT" {
            self.handle_connect(client_stream, &remote_addr, is_whitelisted).await
        } else {
            self.handle_http(client_stream, &remote_addr, request_data).await
        };

        if let Err(ref e) = result {
            match e.downcast_ref::<std::io::Error>() {
                Some(io_err) if is_expected_error(io_err) => {
                    trace!("Expected disconnection for {}: {}", remote_addr, io_err);
                    self.stats.client_disconnects.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                _ => {}
            }
        }

        result
    }

    async fn handle_connect(
        &self,
        mut client_stream: TcpStream,
        remote_addr: &str,
        is_whitelisted: bool,
    ) -> Result<()> {
        let remote_stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(remote_addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!("Failed to connect to {}: {}", remote_addr, e);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(ProxyError::Connection(format!("Failed to connect to {}", remote_addr)).into());
            }
            Err(_) => {
                debug!("Timeout connecting to {}", remote_addr);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream.write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n").await;
                return Err(ProxyError::Timeout.into());
            }
        };

        // Set TCP keepalive for remote connection
        let sock_ref = socket2::SockRef::from(&remote_stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(10));
        let _ = sock_ref.set_tcp_keepalive(&keepalive);

        if let Err(e) = client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await {
            if is_expected_error(&e) {
                trace!("Client disconnected during CONNECT response");
                self.stats.client_disconnects.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            return Err(e.into());
        }

        client_stream.flush().await?;

        if !is_whitelisted {
            self.fragment_tls_handshake(client_stream, remote_stream).await
        } else {
            self.pipe_connections(client_stream, remote_stream).await
        }
    }

    async fn handle_http(
        &self,
        mut client_stream: TcpStream,
        remote_addr: &str,
        request_data: &[u8],
    ) -> Result<()> {
        let mut remote_stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(remote_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!("Failed to connect to {}: {}", remote_addr, e);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err(ProxyError::Connection(format!("Failed to connect to {}", remote_addr)).into());
            }
            Err(_) => {
                debug!("Timeout connecting to {}", remote_addr);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream
                    .write_all(b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err(ProxyError::Timeout.into());
            }
        };

        if let Err(e) = remote_stream.write_all(request_data).await {
            if is_expected_error(&e) {
                trace!("Remote disconnected while sending request");
                return Ok(());
            }
            return Err(e.into());
        }

        remote_stream.flush().await?;

        self.pipe_connections(client_stream, remote_stream).await
    }

    async fn fragment_tls_handshake(
        &self,
        mut client_stream: TcpStream,
        mut remote_stream: TcpStream,
    ) -> Result<()> {
        // Read TLS ClientHello
        let mut header = [0u8; 5];
        match timeout(Duration::from_secs(5), client_stream.read_exact(&mut header)).await {
            Ok(Ok(_)) => {},
            Ok(Err(_)) => {
                // Not enough data, pass through
                let _ = remote_stream.write_all(&header).await;
                return self.pipe_connections(client_stream, remote_stream).await;
            },
            Err(_) => return Err(ProxyError::Timeout.into()),
        }

        if header[0] != 0x16 {
            // Not TLS handshake, pass through
            remote_stream.write_all(&header).await?;
            return self.pipe_connections(client_stream, remote_stream).await;
        }

        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Sanity check
        if record_len > 16384 {
            warn!("Suspicious TLS record length: {}", record_len);
            remote_stream.write_all(&header).await?;
            return self.pipe_connections(client_stream, remote_stream).await;
        }

        let mut body = vec![0u8; record_len];
        match timeout(Duration::from_secs(5), client_stream.read_exact(&mut body)).await {
            Ok(Ok(_)) => {},
            Ok(Err(e)) => {
                // Failed to read full body
                remote_stream.write_all(&header).await?;
                return Err(e.into());
            },
            Err(_) => return Err(ProxyError::Timeout.into()),
        }

        self.stats.fragmented_connections.fetch_add(1, Ordering::Relaxed);
        trace!("Fragmenting TLS handshake ({}bytes)", record_len);

        // Fragment the ClientHello
        let fragments = fragment_tls_data(&body);

        // Send fragmented data with new TLS frames
        for fragment in fragments {
            let frame = create_tls_frame(&fragment);
            remote_stream.write_all(&frame).await?;
            remote_stream.flush().await?;
        }

        // Continue with normal pipe
        self.pipe_connections(client_stream, remote_stream).await
    }

    async fn pipe_connections(&self, mut client: TcpStream, mut remote: TcpStream) -> Result<()> {
        match tokio::io::copy_bidirectional(&mut client, &mut remote).await {
            Ok((bytes_to_server, bytes_to_client)) => {
                self.stats.traffic_out.fetch_add(bytes_to_server, Ordering::Relaxed);
                self.stats.traffic_in.fetch_add(bytes_to_client, Ordering::Relaxed);
                trace!("Connection closed: {}b up, {}b down", bytes_to_server, bytes_to_client);
                Ok(())
            }
            Err(e) if is_expected_error(&e) => {
                trace!("Connection closed: {}", e);
                Ok(())
            }
            Err(e) => Err(e.into())
        }
    }
}

fn parse_http_request(data: &[u8]) -> Result<(String, String, u16)> {
    let request = String::from_utf8_lossy(data);
    let lines: Vec<&str> = request.lines().collect();

    if lines.is_empty() {
        return Err(ProxyError::Connection("Empty request".into()).into());
    }

    let first_line: Vec<&str> = lines[0].split_whitespace().collect();
    if first_line.len() < 2 {
        return Err(ProxyError::Connection("Invalid request line".into()).into());
    }

    let method = first_line[0].to_string();
    let url = first_line[1];

    let (host, port) = if method == "CONNECT" {
        // CONNECT method: host:port
        let parts: Vec<&str> = url.split(':').collect();
        let host = parts[0].to_string();
        let port = parts.get(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        (host, port)
    } else {
        // Regular HTTP: extract from Host header
        let host_header = lines.iter()
            .find(|line| line.to_lowercase().starts_with("host:"))
            .ok_or_else(|| ProxyError::Connection("Missing Host header".into()))?;

        let host_value = host_header.split(':').nth(1)
            .ok_or_else(|| ProxyError::Connection("Invalid Host header".into()))?
            .trim();

        let parts: Vec<&str> = host_value.split(':').collect();
        let host = parts[0].to_string();
        let port = parts.get(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(80);
        (host, port)
    };

    Ok((method, host, port))
}

fn fragment_tls_data(data: &[u8]) -> Vec<Vec<u8>> {
    let mut fragments = Vec::new();

    // Look for SNI extension to fragment at domain boundary
    if let Some(sni_pos) = find_sni_position(data) {
        if sni_pos < data.len() {
            fragments.push(data[..sni_pos + 1].to_vec());
            fragments.push(data[sni_pos + 1..].to_vec());
            return fragments;
        }
    }

    // Random fragmentation
    let mut rng = rand::rng();
    if data.len() <= 512 {
        let cut = data.len() / 2;
        fragments.push(data[..cut].to_vec());
        fragments.push(data[cut..].to_vec());
    } else {
        let cut1 = rng.random_range(32..128).min(data.len());
        let cut2 = (cut1 + rng.random_range(128..512)).min(data.len());
        fragments.push(data[..cut1].to_vec());
        if cut2 > cut1 {
            fragments.push(data[cut1..cut2].to_vec());
        }
        if cut2 < data.len() {
            fragments.push(data[cut2..].to_vec());
        }
    }

    fragments
}

fn find_sni_position(data: &[u8]) -> Option<usize> {
    for (i, window) in data.windows(2).enumerate() {
        if window[0] != 0x00 && window[1] == 0x00 {
            return Some(i + 1);
        }
    }
    None
}

fn create_tls_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + data.len());
    frame.push(0x16); // TLS handshake
    frame.push(0x03); // TLS version
    frame.push(0x04); // TLS 1.3
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn print_banner(args: &Args, filter: &DomainFilter) {
    let (blacklist_count, whitelist_count) = filter.get_stats();

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║       \x1b[92mTLS Fragment Proxy v{}\x1b[0m                     ║", VERSION);
    println!("║       \x1b[97mOptimized Fragmentation Mode\x1b[0m                ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    println!("\x1b[92m[CONFIG]\x1b[0m");
    println!("  \x1b[97m├─ Address:\x1b[0m {}:{}", args.host, args.port);
    println!("  \x1b[97m├─ Fragment Mode:\x1b[0m Smart SNI Detection");
    println!("  \x1b[97m├─ Max Connections:\x1b[0m {}", args.max_connections);
    println!("  \x1b[97m├─ Rate Limit:\x1b[0m {}/sec per IP", args.rate_limit_per_second);

    if blacklist_count > 0 {
        println!("  \x1b[97m├─ Blacklist:\x1b[0m {} domains loaded", blacklist_count);
    } else {
        println!("  \x1b[97m├─ Blacklist:\x1b[0m Not configured");
    }

    if whitelist_count > 0 {
        println!("  \x1b[97m├─ Whitelist:\x1b[0m {} domains loaded", whitelist_count);
    } else {
        println!("  \x1b[97m├─ Whitelist:\x1b[0m Not configured");
    }

    println!("  \x1b[97m├─ Health Check:\x1b[0m http://127.0.0.1:8882/health");
    println!("  \x1b[97m└─ Started:\x1b[0m {}", Local::now().format("%Y-%m-%d %H:%M:%S"));
    println!("\n\x1b[92m[INFO]\x1b[0m Press \x1b[93mCtrl+C\x1b[0m to stop the proxy\n");
}

async fn health_check_server(stats: Stats) {
    if let Ok(health_listener) = TcpListener::bind("127.0.0.1:8882").await {
        info!("Health check endpoint listening on 127.0.0.1:8882");
        loop {
            if let Ok((mut stream, _)) = health_listener.accept().await {
                let active = stats.active_connections.load(Ordering::Relaxed);
                let total = stats.total_connections.load(Ordering::Relaxed);
                let fragmented = stats.fragmented_connections.load(Ordering::Relaxed);
                let traffic_in = stats.traffic_in.load(Ordering::Relaxed);
                let traffic_out = stats.traffic_out.load(Ordering::Relaxed);
                let disconnects = stats.client_disconnects.load(Ordering::Relaxed);
                let blacklisted = stats.blacklisted_blocks.load(Ordering::Relaxed);
                let whitelisted = stats.whitelisted_connections.load(Ordering::Relaxed);

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
                    {{\"status\":\"healthy\",\"active\":{},\"total\":{},\"fragmented\":{},\
                    \"traffic_in\":{},\"traffic_out\":{},\"client_disconnects\":{},\
                    \"blacklisted_blocks\":{},\"whitelisted_connections\":{}}}\n",
                    active, total, fragmented, traffic_in, traffic_out, disconnects,
                    blacklisted, whitelisted
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        }
    } else {
        warn!("Failed to bind health check endpoint on 127.0.0.1:8882");
    }
}

async fn stats_reporter(stats: Stats, filter: Arc<DomainFilter>) {
    let mut interval = interval(Duration::from_secs(300)); // Report every 5 minutes
    loop {
        interval.tick().await;

        let active = stats.active_connections.load(Ordering::Relaxed);
        let total = stats.total_connections.load(Ordering::Relaxed);
        let fragmented = stats.fragmented_connections.load(Ordering::Relaxed);
        let whitelisted = stats.whitelisted_connections.load(Ordering::Relaxed);
        let blacklisted = stats.blacklisted_blocks.load(Ordering::Relaxed);
        let failed = stats.failed_connections.load(Ordering::Relaxed);
        let disconnects = stats.client_disconnects.load(Ordering::Relaxed);
        let traffic_in = stats.traffic_in.load(Ordering::Relaxed);
        let traffic_out = stats.traffic_out.load(Ordering::Relaxed);

        let (bl_count, wl_count) = filter.get_stats();

        info!(
            "Stats Report: Active={}, Total={}, Fragmented={}, Whitelisted={}, Blacklisted Blocks={}, Failed={}, Disconnects={}, Traffic In={}, Traffic Out={}, Lists: BL={} domains, WL={} domains",
            active,
            total,
            fragmented,
            whitelisted,
            blacklisted,
            failed,
            disconnects,
            format_size(traffic_in, BINARY),
            format_size(traffic_out, BINARY),
            bl_count,
            wl_count
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging with better filtering
    let filter_level = if args.verbose {
        Level::TRACE
    } else {
        Level::INFO
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new(format!("tls_fragment_proxy={}", filter_level))
        });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .init();

    // Print initial loading messages
    info!("Starting TLS Fragment Proxy v{}", VERSION);

    let filter = Arc::new(DomainFilter::new(&args).await?);
    let stats = Stats::new();
    let rate_limiter = Arc::new(RateLimiter::new(args.rate_limit_per_second));
    let connection_semaphore = Arc::new(Semaphore::new(args.max_connections));

    let handler = Arc::new(ConnectionHandler {
        stats: stats.clone(),
        filter: Arc::clone(&filter),
        rate_limiter: Arc::clone(&rate_limiter),
        connection_semaphore: Arc::clone(&connection_semaphore),
    });

    if !args.quiet {
        print_banner(&args, &filter);
    }

    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind to {}", addr))?;

    info!("Proxy listening on {}", addr);

    // Start health check endpoint
    tokio::spawn(health_check_server(stats.clone()));

    // Start stats reporter
    tokio::spawn(stats_reporter(stats.clone(), Arc::clone(&filter)));

    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Graceful shutdown handler
    let shutdown_signal = async {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutdown signal received");
    };

    // Main accept loop
    tokio::select! {
        _ = shutdown_signal => {
            info!("Initiating graceful shutdown...");
        },
        _ = async {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            if let Err(e) = handler.handle_client(stream, addr).await {
                                match e.downcast_ref::<ProxyError>() {
                                    Some(ProxyError::RateLimited) => {},
                                    Some(ProxyError::Timeout) => {
                                        trace!("Connection timeout from {}", addr);
                                    },
                                    _ => {
                                        // Check if it's an expected IO error
                                        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                                            if !is_expected_error(io_err) {
                                                debug!("Unexpected error handling client {}: {}", addr, e);
                                            }
                                        } else {
                                            debug!("Error handling client {}: {}", addr, e);
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        // Brief pause to avoid tight loop on persistent errors
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        } => {}
    }

    let _ = shutdown_tx.send(());

    // Wait for active connections with timeout
    let shutdown_timeout = Duration::from_secs(30);
    let shutdown_start = Instant::now();

    while stats.active_connections.load(Ordering::Relaxed) > 0 {
        if shutdown_start.elapsed() > shutdown_timeout {
            warn!("Shutdown timeout reached, {} connections still active",
                stats.active_connections.load(Ordering::Relaxed));
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    let (bl_count, wl_count) = filter.get_stats();

    if !args.quiet {
        println!("\n╔══════════════════════════════════════════════════════╗");
        println!("║                 \x1b[92mFINAL STATISTICS\x1b[0m                    ║");
        println!("╚══════════════════════════════════════════════════════╝\n");

        println!("  \x1b[97mTotal Connections:\x1b[0m      {}",
                 stats.total_connections.load(Ordering::Relaxed));
        println!("  \x1b[97mFragmented Connections:\x1b[0m {}",
                 stats.fragmented_connections.load(Ordering::Relaxed));
        println!("  \x1b[97mWhitelisted Connections:\x1b[0m {}",
                 stats.whitelisted_connections.load(Ordering::Relaxed));
        println!("  \x1b[97mBlacklisted Blocks:\x1b[0m     {}",
                 stats.blacklisted_blocks.load(Ordering::Relaxed));
        println!("  \x1b[97mFailed Connections:\x1b[0m     {}",
                 stats.failed_connections.load(Ordering::Relaxed));
        println!("  \x1b[97mClient Disconnects:\x1b[0m     {}",
                 stats.client_disconnects.load(Ordering::Relaxed));
        println!("  \x1b[97mRate Limited:\x1b[0m           {}",
                 stats.rate_limited_connections.load(Ordering::Relaxed));
        println!("  \x1b[97mTotal Downloaded:\x1b[0m       {}",
                 format_size(stats.traffic_in.load(Ordering::Relaxed), BINARY));
        println!("  \x1b[97mTotal Uploaded:\x1b[0m         {}",
                 format_size(stats.traffic_out.load(Ordering::Relaxed), BINARY));
        println!("  \x1b[97mBlacklist Domains:\x1b[0m      {}", bl_count);
        println!("  \x1b[97mWhitelist Domains:\x1b[0m      {}", wl_count);

        println!("\n\x1b[92m[SUCCESS]\x1b[0m Proxy shut down gracefully\n");
    }

    Ok(())
}