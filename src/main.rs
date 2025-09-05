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
use tracing::{debug, error, info, warn};
use tracing::Level;

const VERSION: &str = "1.0.0";
const BUFFER_SIZE: usize = 65536;

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
}

#[derive(Parser, Debug)]
#[command(name = "tls-fragment-proxy")]
#[command(version = VERSION)]
#[command(about = "HTTP/HTTPS proxy with TLS fragmentation")]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    #[arg(long, default_value_t = 8881)]
    port: u16,

    #[arg(long, default_value = "blacklist.txt")]
    blacklist: PathBuf,

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
    failed_connections: Arc<AtomicUsize>,
    rate_limited_connections: Arc<AtomicUsize>,
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
            failed_connections: Arc::new(AtomicUsize::new(0)),
            rate_limited_connections: Arc::new(AtomicUsize::new(0)),
            traffic_in: Arc::new(AtomicU64::new(0)),
            traffic_out: Arc::new(AtomicU64::new(0)),
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
}

impl DomainFilter {
    async fn new(args: &Args) -> Result<Self> {
        let mut filter = Self {
            blacklist: Arc::new(RwLock::new(HashSet::new())),
            whitelist: Arc::new(RwLock::new(HashSet::new())),
        };

        filter.load_blacklist(&args.blacklist).await?;
        if let Some(whitelist_path) = &args.whitelist {
            filter.load_whitelist(whitelist_path).await?;
        }

        Ok(filter)
    }

    async fn load_blacklist(&mut self, path: &PathBuf) -> Result<()> {
        if path.exists() {
            let content = tokio::fs::read_to_string(path).await?;
            let mut blacklist = self.blacklist.write();
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    blacklist.insert(line.to_lowercase());
                }
            }
            info!("Loaded {} domains from blacklist", blacklist.len());
        }
        Ok(())
    }

    async fn load_whitelist(&mut self, path: &PathBuf) -> Result<()> {
        if path.exists() {
            let content = tokio::fs::read_to_string(path).await?;
            let mut whitelist = self.whitelist.write();
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    whitelist.insert(line.to_lowercase());
                }
            }
            info!("Loaded {} domains from whitelist", whitelist.len());
        }
        Ok(())
    }

    fn is_whitelisted(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        let whitelist = self.whitelist.read();
        
        if whitelist.contains(&domain_lower) {
            return true;
        }
        
        // Check subdomain matching
        for whitelisted in whitelist.iter() {
            if whitelisted.starts_with("*.") {
                let suffix = &whitelisted[2..];
                if domain_lower.ends_with(suffix) || domain_lower == suffix {
                    return true;
                }
            }
        }
        
        false
    }

    fn is_blacklisted(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        let blacklist = self.blacklist.read();
        
        if blacklist.contains(&domain_lower) {
            return true;
        }
        
        // Check subdomain matching
        for blacklisted in blacklist.iter() {
            if blacklisted.starts_with("*.") {
                let suffix = &blacklisted[2..];
                if domain_lower.ends_with(suffix) || domain_lower == suffix {
                    return true;
                }
            }
        }
        
        false
    }
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
        // Rate limiting
        if let Ok(ip) = client_addr.ip().to_string().parse::<IpAddr>() {
            if !self.rate_limiter.check_rate_limit(ip).await {
                self.stats.rate_limited_connections.fetch_add(1, Ordering::Relaxed);
                warn!("Rate limited connection from {}", client_addr);
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
        
        let n = match timeout(Duration::from_secs(10), client_stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                debug!("Failed to read from client: {}", e);
                return Err(e.into());
            }
            Err(_) => {
                debug!("Timeout reading from client");
                return Err(ProxyError::Timeout.into());
            }
        };

        if n == 0 {
            return Ok(());
        }

        let request_data = &buffer[..n];
        let (method, host, port) = parse_http_request(request_data)?;

        // Check blacklist
        if self.filter.is_blacklisted(&host) {
            debug!("Blocked blacklisted domain: {}", host);
            let _ = client_stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Ok(());
        }

        let is_whitelisted = self.filter.is_whitelisted(&host);
        if is_whitelisted {
            self.stats.whitelisted_connections.fetch_add(1, Ordering::Relaxed);
            info!("Whitelisted domain: {} - bypassing fragmentation", host);
        }

        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);

        let remote_addr = format!("{}:{}", host, port);
        
        if method == "CONNECT" {
            self.handle_connect(client_stream, &remote_addr, is_whitelisted).await
        } else {
            self.handle_http(client_stream, &remote_addr, request_data).await
        }
    }

    async fn handle_connect(
        &self,
        mut client_stream: TcpStream,
        remote_addr: &str,
        is_whitelisted: bool,
    ) -> Result<()> {
        let remote_stream = match timeout(Duration::from_secs(5), TcpStream::connect(remote_addr)).await {
            Ok(Ok(stream)) => stream,
            _ => {
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(ProxyError::Connection(format!("Failed to connect to {}", remote_addr)).into());
            }
        };

        client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
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
        let mut remote_stream = match timeout(Duration::from_secs(5), TcpStream::connect(remote_addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err(ProxyError::Connection(format!("Failed to connect to {}", remote_addr)).into());
            }
        };

        remote_stream.write_all(request_data).await?;
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
                remote_stream.write_all(&header).await?;
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

        // Fragment the ClientHello
        let fragments = fragment_tls_data(&body);

        // Send fragmented data
        for fragment in fragments {
            let frame = create_tls_frame(&fragment);
            remote_stream.write_all(&frame).await?;
            remote_stream.flush().await?;
        }

        // Continue with normal pipe
        self.pipe_connections(client_stream, remote_stream).await
    }

    async fn pipe_connections(&self, mut client: TcpStream, mut remote: TcpStream) -> Result<()> {
        let (bytes_to_server, bytes_to_client) = tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
        
        self.stats.traffic_out.fetch_add(bytes_to_server, Ordering::Relaxed);
        self.stats.traffic_in.fetch_add(bytes_to_client, Ordering::Relaxed);
        
        Ok(())
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
    let mut rng = rand::thread_rng();
    if data.len() <= 512 {
        let cut = data.len() / 2;
        fragments.push(data[..cut].to_vec());
        fragments.push(data[cut..].to_vec());
    } else {
        let cut1 = rng.gen_range(32..128).min(data.len());
        let cut2 = (cut1 + rng.gen_range(128..512)).min(data.len());
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
    // Simple SNI detection - look for 0x00 after potential domain name
    for (i, window) in data.windows(2).enumerate() {
        if window[0] != 0x00 && window[1] == 0x00 {
            // Likely end of domain name
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

fn print_banner(args: &Args) {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║       \x1b[92mTLS Fragment Proxy v{}\x1b[0m                     ║", VERSION);
    println!("║       \x1b[97mRandom Fragmentation Mode\x1b[0m                   ║");
    println!("╚══════════════════════════════════════════════════════╝\n");
    
    println!("\x1b[92m[CONFIG]\x1b[0m");
    println!("  \x1b[97m├─ Address:\x1b[0m {}:{}", args.host, args.port);
    println!("  \x1b[97m├─ Fragment Mode:\x1b[0m Random (Working Method)");
    println!("  \x1b[97m├─ Max Connections:\x1b[0m {}", args.max_connections);
    println!("  \x1b[97m├─ Rate Limit:\x1b[0m {}/sec per IP", args.rate_limit_per_second);
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
                
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
                    {{\"status\":\"healthy\",\"active\":{},\"total\":{},\"fragmented\":{},\"traffic_in\":{},\"traffic_out\":{}}}\n",
                    active, total, fragmented, traffic_in, traffic_out
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        }
    } else {
        warn!("Failed to bind health check endpoint on 127.0.0.1:8882");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let filter_level = if args.verbose { 
        Level::DEBUG 
    } else { 
        Level::INFO 
    };

    tracing_subscriber::fmt()
        .with_max_level(filter_level)
        .with_target(false)
        .with_thread_ids(false)
        .init();

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
        print_banner(&args);
    }

    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind to {}", addr))?;

    info!("Proxy listening on {}", addr);

    // Start health check endpoint
    let health_stats = stats.clone();
    tokio::spawn(health_check_server(health_stats));

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
                                    _ => {
                                        debug!("Error handling client {}: {}", addr, e);
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        } => {}
    }

    let _ = shutdown_tx.send(());

    // Wait for active connections
    let shutdown_timeout = Duration::from_secs(30);
    let shutdown_start = Instant::now();
    
    while stats.active_connections.load(Ordering::Relaxed) > 0 {
        if shutdown_start.elapsed() > shutdown_timeout {
            warn!("Shutdown timeout reached");
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

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
        println!("  \x1b[97mFailed Connections:\x1b[0m     {}", 
            stats.failed_connections.load(Ordering::Relaxed));
        println!("  \x1b[97mRate Limited:\x1b[0m           {}", 
            stats.rate_limited_connections.load(Ordering::Relaxed));
        println!("  \x1b[97mTotal Downloaded:\x1b[0m       {}", 
            format_size(stats.traffic_in.load(Ordering::Relaxed), BINARY));
        println!("  \x1b[97mTotal Uploaded:\x1b[0m         {}", 
            format_size(stats.traffic_out.load(Ordering::Relaxed), BINARY));
        
        println!("\n\x1b[92m[SUCCESS]\x1b[0m Proxy shut down gracefully\n");
    }

    Ok(())
}