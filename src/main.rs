use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context, Result};
use bincode::config;
use bloomfilter::Bloom;
use bytes::Bytes;
use chrono::Local;
use clap::Parser;
use httparse;
use humansize::{format_size, BINARY};
use moka::sync::Cache;
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder as TokioBuilder;
use tokio::sync::{broadcast, Semaphore};
use tokio::time::{interval, sleep, timeout};
use tracing::Level;
use tracing::{debug, error, info, trace, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

const VERSION: &str = "1.1.0";
const BUFFER_SIZE: usize = 65536;
const PIPE_BUF: usize = 262_144;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(60);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.001;

#[derive(Error, Debug)]
enum ProxyError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Timeout")]
    Timeout,

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("HTTP parse error: {0}")]
    HttpParse(#[from] httparse::Error),
}

enum DisconnectType {
    Expected,
    Unexpected,
}

fn is_expected_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
    )
}

#[derive(Parser, Debug)]
#[command(name = "tls-fragment-proxy")]
#[command(version = VERSION)]
#[command(about = "HTTP/HTTPS proxy with TLS fragmentation (optimized)")]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    #[arg(long, default_value_t = 8888)]
    port: u16,

    #[arg(long)]
    blacklist: Option<PathBuf>,

    #[arg(long)]
    whitelist: Option<PathBuf>,

    #[arg(long)]
    blacklist_binary: Option<PathBuf>,

    #[arg(long)]
    whitelist_binary: Option<PathBuf>,

    #[arg(long, default_value_t = 1000)]
    max_connections: usize,

    #[arg(short, long)]
    quiet: bool,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long, default_value_t = 4)]
    worker_threads: usize,

    #[arg(long)]
    preprocess_lists: bool,

    #[arg(long, default_value_t = 10000)]
    cache_size: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct RadixNode {
    prefix: String,
    is_end: bool,
    children: HashMap<char, Box<RadixNode>>,
}

impl RadixNode {
    fn new() -> Self {
        Self {
            prefix: String::new(),
            is_end: false,
            children: HashMap::new(),
        }
    }

    fn insert(&mut self, key: &str) {
        if !key.is_ascii() {
            warn!("Non-ASCII domain attempted: {}", key);
            return;
        }

        if key.is_empty() {
            self.is_end = true;
            return;
        }

        let first_char = key.chars().next().unwrap();

        if let Some(child) = self.children.get_mut(&first_char) {
            let common_len = key.chars()
                .zip(child.prefix.chars())
                .take_while(|(a, b)| a == b)
                .count();

            let child_prefix_chars = child.prefix.chars().count();

            if common_len == child_prefix_chars {
                let remaining: String = key.chars().skip(common_len).collect();
                child.insert(&remaining);
            } else {
                let mut new_child = RadixNode::new();
                new_child.prefix = child.prefix.chars().skip(common_len).collect();
                new_child.is_end = child.is_end;
                new_child.children = std::mem::take(&mut child.children);

                child.prefix = child.prefix.chars().take(common_len).collect();
                child.is_end = false;

                let split_char = new_child.prefix.chars().next().unwrap();
                child.children.insert(split_char, Box::new(new_child));

                let key_chars = key.chars().count();
                if key_chars > common_len {
                    let remaining: String = key.chars().skip(common_len).collect();
                    child.insert(&remaining);
                } else {
                    child.is_end = true;
                }
            }
        } else {
            let mut new_node = Box::new(RadixNode::new());
            new_node.prefix = key.to_string();
            new_node.is_end = true;
            self.children.insert(first_char, new_node);
        }
    }

    fn contains(&self, key: &str) -> bool {
        if key.is_empty() {
            return self.is_end;
        }

        let first_char = match key.chars().next() {
            Some(c) => c,
            None => return self.is_end,
        };

        if let Some(child) = self.children.get(&first_char) {
            if key.chars().zip(child.prefix.chars()).all(|(a, b)| a == b)
                && key.chars().count() >= child.prefix.chars().count()
            {
                let remaining: String = key.chars()
                    .skip(child.prefix.chars().count())
                    .collect();
                return child.contains(&remaining);
            }
        }

        false
    }
}
#[derive(Clone)]
struct DomainFilterStats {
    blacklist_domains: Arc<AtomicUsize>,
    whitelist_domains: Arc<AtomicUsize>,
    cache_hits: Arc<AtomicUsize>,
    cache_misses: Arc<AtomicUsize>,
    bloom_false_positives: Arc<AtomicUsize>,
}

impl DomainFilterStats {
    fn new() -> Self {
        Self {
            blacklist_domains: Arc::new(AtomicUsize::new(0)),
            whitelist_domains: Arc::new(AtomicUsize::new(0)),
            cache_hits: Arc::new(AtomicUsize::new(0)),
            cache_misses: Arc::new(AtomicUsize::new(0)),
            bloom_false_positives: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct OptimizedDomainFilter {
    // Tier 1: Bloom filters for fast negative lookups
    blacklist_bloom: Option<Arc<Bloom<String>>>,
    whitelist_bloom: Option<Arc<Bloom<String>>>,

    // Tier 2: Concurrent cache (no Mutex/try_lock contention)
    blacklist_cache: Cache<String, bool>,
    whitelist_cache: Cache<String, bool>,

    // Tier 3: Radix trees for exact matches
    blacklist_tree: Arc<RwLock<RadixNode>>,
    whitelist_tree: Arc<RwLock<RadixNode>>,

    // Tier 4: Aho-Corasick for wildcard patterns
    blacklist_wildcard: Option<Arc<AhoCorasick>>,
    whitelist_wildcard: Option<Arc<AhoCorasick>>,

    stats: DomainFilterStats,
}

impl OptimizedDomainFilter {
    async fn new(args: &Args) -> Result<Self> {
        let mut filter = Self {
            blacklist_bloom: None,
            whitelist_bloom: None,
            blacklist_cache: Cache::new(args.cache_size as u64),
            whitelist_cache: Cache::new(args.cache_size as u64),
            blacklist_tree: Arc::new(RwLock::new(RadixNode::new())),
            whitelist_tree: Arc::new(RwLock::new(RadixNode::new())),
            blacklist_wildcard: None,
            whitelist_wildcard: None,
            stats: DomainFilterStats::new(),
        };

        if let Some(path) = &args.blacklist_binary {
            info!("Loading binary blacklist from: {}", path.display());
            filter.load_binary_list(path, ListType::Blacklist).await?;
        } else if let Some(path) = &args.blacklist {
            info!("Loading text blacklist from: {}", path.display());
            filter.load_text_list(path, ListType::Blacklist).await?;
        }

        if let Some(path) = &args.whitelist_binary {
            info!("Loading binary whitelist from: {}", path.display());
            filter.load_binary_list(path, ListType::Whitelist).await?;
        } else if let Some(path) = &args.whitelist {
            info!("Loading text whitelist from: {}", path.display());
            filter.load_text_list(path, ListType::Whitelist).await?;
        }

        Ok(filter)
    }

    fn update_tree_and_stats(&mut self, tree: RadixNode, domain_count: usize, list_type: ListType) {
        match list_type {
            ListType::Blacklist => {
                *self.blacklist_tree.write() = tree;
                self.stats
                    .blacklist_domains
                    .store(domain_count, Ordering::Relaxed);
            }
            ListType::Whitelist => {
                *self.whitelist_tree.write() = tree;
                self.stats
                    .whitelist_domains
                    .store(domain_count, Ordering::Relaxed);
            }
        }
    }
    fn normalize_and_validate_domain(domain: &str) -> Option<String> {
        let trimmed = domain.trim().to_lowercase();

        // Skip empty or comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        // Validate ASCII (domain names should be ASCII or punycode)
        if !trimmed.is_ascii() {
            warn!("Skipping non-ASCII domain (use punycode): {}", trimmed);
            return None;
        }

        // Basic domain validation
        if trimmed.contains("..") || trimmed.starts_with('.') {
            warn!("Skipping invalid domain format: {}", trimmed);
            return None;
        }

        Some(trimmed)
    }

    fn set_bloom_filter(&mut self, bloom: Bloom<String>, list_type: ListType) {
        match list_type {
            ListType::Blacklist => self.blacklist_bloom = Some(Arc::new(bloom)),
            ListType::Whitelist => self.whitelist_bloom = Some(Arc::new(bloom)),
        }
    }

    fn set_wildcard_automaton(&mut self, ac: AhoCorasick, list_type: ListType) {
        match list_type {
            ListType::Blacklist => self.blacklist_wildcard = Some(Arc::new(ac)),
            ListType::Whitelist => self.whitelist_wildcard = Some(Arc::new(ac)),
        }
    }

    fn list_type_name(list_type: &ListType) -> &'static str {
        match list_type {
            ListType::Blacklist => "blacklist",
            ListType::Whitelist => "whitelist",
        }
    }

    fn build_wildcard_automaton(wildcard_patterns: &[String]) -> Result<AhoCorasick> {
        let patterns_iter = wildcard_patterns.iter().map(|p| {
            if p.starts_with("*.") {
                &p[2..]
            } else {
                p.as_str()
            }
        });
        AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns_iter)
            .context("Failed to build Aho-Corasick automaton")
    }

    async fn load_text_list(&mut self, path: &PathBuf, list_type: ListType) -> Result<()> {
        if !path.exists() {
            return Err(
                ProxyError::Configuration(format!("File not found: {}", path.display())).into(),
            );
        }

        let start = Instant::now();
        let content = tokio::fs::read_to_string(path)
            .await
            .context(format!("Failed to read file: {}", path.display()))?;

        let lines: Vec<&str> = content.lines().collect();
        let chunk_size = 10_000;
        let processed: Vec<Vec<(String, bool)>> = lines
            .par_chunks(chunk_size)
            .map(|chunk| {
                chunk
                    .iter()
                    .filter_map(|line| {
                        OptimizedDomainFilter::normalize_and_validate_domain(line).map(|domain| {
                            let is_wildcard = domain.starts_with("*.");
                            (domain, is_wildcard)
                        })
                    })
                    .collect()
            })
            .collect();

        let mut exact_domains = Vec::new();
        let mut wildcard_patterns = Vec::new();
        for chunk in processed {
            for (domain, is_wildcard) in chunk {
                if is_wildcard {
                    wildcard_patterns.push(domain);
                } else {
                    exact_domains.push(domain);
                }
            }
        }

        if !exact_domains.is_empty() {
            let mut bloom: Bloom<String> =
                Bloom::new_for_fp_rate(exact_domains.len(), BLOOM_FALSE_POSITIVE_RATE)
                    .map_err(|e| anyhow::anyhow!("Failed to create bloom filter: {}", e))?;
            for domain in &exact_domains {
                bloom.set(domain);
            }
            self.set_bloom_filter(bloom, list_type);
        }

        let mut tree = RadixNode::new();
        for domain in &exact_domains {
            tree.insert(domain);
        }

        let total_count = exact_domains.len() + wildcard_patterns.len();
        self.update_tree_and_stats(tree, total_count, list_type);

        if !wildcard_patterns.is_empty() {
            let ac = Self::build_wildcard_automaton(&wildcard_patterns)?;
            self.set_wildcard_automaton(ac, list_type);
        }

        let elapsed = start.elapsed();
        info!(
            "✓ Loaded {} domains ({} exact, {} wildcard) from {} in {:.2}s",
            total_count,
            exact_domains.len(),
            wildcard_patterns.len(),
            Self::list_type_name(&list_type),
            elapsed.as_secs_f64()
        );

        Ok(())
    }

    async fn load_binary_list(&mut self, path: &Path, list_type: ListType) -> Result<()> {
        let start = Instant::now();

        if !path.exists() {
            return Err(ProxyError::Configuration(format!(
                "Binary list file not found: {}",
                path.display()
            ))
            .into());
        }

        let data = tokio::fs::read(path).await.context(format!(
            "Failed to read binary list file: {}",
            path.display()
        ))?;

        let ((tree, wildcard_patterns), bytes_read): ((RadixNode, Vec<String>), usize) =
            bincode::serde::decode_from_slice(&data, config::standard()).context(
                "Failed to deserialize binary domain list. Re-run with --preprocess-lists.",
            )?;

        if bytes_read != data.len() {
            warn!(
                "Binary list file {} may have trailing data (read {} of {} bytes).",
                path.display(),
                bytes_read,
                data.len()
            );
        }

        let exact_count = count_domains_in_tree(&tree);

        if !wildcard_patterns.is_empty() {
            let ac = Self::build_wildcard_automaton(&wildcard_patterns)?;
            self.set_wildcard_automaton(ac, list_type);
        }

        if exact_count > 0 {
            let mut exact_domains = Vec::with_capacity(exact_count);
            let mut acc = String::new();
            collect_domains(&tree, &mut acc, &mut exact_domains);

            let mut bloom: Bloom<String> =
                Bloom::new_for_fp_rate(exact_domains.len(), BLOOM_FALSE_POSITIVE_RATE)
                    .map_err(|e| anyhow::anyhow!("Failed to create bloom filter: {}", e))?;
            for d in &exact_domains {
                bloom.set(d);
            }
            self.set_bloom_filter(bloom, list_type);
        }

        let total_count = exact_count + wildcard_patterns.len();
        self.update_tree_and_stats(tree, total_count, list_type);

        let elapsed = start.elapsed();
        info!(
            "✓ Loaded {} domains ({} exact, {} wildcard) from binary {} in {:.2}s",
            total_count,
            exact_count,
            wildcard_patterns.len(),
            Self::list_type_name(&list_type),
            elapsed.as_secs_f64()
        );

        Ok(())
    }

    fn check_domain(&self, domain_lower: &str, list_type: ListType) -> bool {
        let (cache, bloom, tree, wildcard) = match list_type {
            ListType::Blacklist => (&self.blacklist_cache, &self.blacklist_bloom, &self.blacklist_tree, &self.blacklist_wildcard),
            ListType::Whitelist => (&self.whitelist_cache, &self.whitelist_bloom, &self.whitelist_tree, &self.whitelist_wildcard),
        };

        if let Some(result) = cache.get(domain_lower) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return result;
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        if let Some(bloom_filter) = bloom {
            if bloom_filter.check(&domain_lower.to_string()) {
                let tree_guard = tree.read();
                if tree_guard.contains(domain_lower) {
                    cache.insert(domain_lower.to_owned(), true);
                    return true;
                }
                self.stats.bloom_false_positives.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            let tree_guard = tree.read();
            if tree_guard.contains(domain_lower) {
                cache.insert(domain_lower.to_owned(), true);
                return true;
            }
        }

        if let Some(ac) = wildcard {
            for mat in ac.find_iter(domain_lower) {
                if mat.end() == domain_lower.len() {
                    if mat.start() == 0 || domain_lower.as_bytes()[mat.start() - 1] == b'.' {
                        cache.insert(domain_lower.to_owned(), true);
                        return true;
                    }
                }
            }
        }

        cache.insert(domain_lower.to_owned(), false);
        false
    }
    fn is_blacklisted(&self, domain_lower: &str) -> bool {
        self.check_domain(domain_lower, ListType::Blacklist)
    }

    fn is_whitelisted(&self, domain_lower: &str) -> bool {
        self.check_domain(domain_lower, ListType::Whitelist)
    }

    fn get_stats(&self) -> (usize, usize) {
        (
            self.stats.blacklist_domains.load(Ordering::Relaxed),
            self.stats.whitelist_domains.load(Ordering::Relaxed),
        )
    }

    fn get_cache_stats(&self) -> (usize, usize, usize) {
        (
            self.stats.cache_hits.load(Ordering::Relaxed),
            self.stats.cache_misses.load(Ordering::Relaxed),
            self.stats.bloom_false_positives.load(Ordering::Relaxed),
        )
    }
}

#[derive(Clone, Copy)]
enum ListType {
    Blacklist,
    Whitelist,
}

fn count_domains_in_tree(node: &RadixNode) -> usize {
    let mut count = if node.is_end { 1 } else { 0 };
    for child in node.children.values() {
        count += count_domains_in_tree(child);
    }
    count
}

fn collect_domains(node: &RadixNode, acc: &mut String, out: &mut Vec<String>) {
    let len = acc.len();
    acc.push_str(&node.prefix);
    if node.is_end {
        out.push(acc.clone());
    }
    for child in node.children.values() {
        collect_domains(child, acc, out);
    }
    acc.truncate(len);
}

async fn preprocess_domain_list(input: &Path, output: &Path) -> Result<()> {
    info!(
        "Preprocessing domain list: {} -> {}",
        input.display(),
        output.display()
    );

    let start = Instant::now();
    let content = tokio::fs::read_to_string(input).await?;

    let lines: Vec<String> = content
        .lines()
        .collect::<Vec<_>>()
        .into_par_iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_lowercase())
        .collect();

    let (exact_domains, wildcard_patterns): (Vec<String>, Vec<String>) = lines
        .into_par_iter()
        .partition(|line| !line.starts_with("*."));

    info!(
        "Building radix tree from {} exact domains and processing {} wildcard patterns...",
        exact_domains.len(),
        wildcard_patterns.len()
    );

    let mut tree = RadixNode::new();
    for domain in &exact_domains {
        tree.insert(domain);
    }

    let data_to_serialize = (tree, wildcard_patterns);
    let encoded = bincode::serde::encode_to_vec(&data_to_serialize, config::standard())?;
    tokio::fs::write(output, encoded).await?;

    let total_domains = exact_domains.len() + data_to_serialize.1.len();
    let elapsed = start.elapsed();
    let meta = std::fs::metadata(output)?;
    info!(
        "✓ Preprocessed {} domains in {:.2}s, output size: {}",
        total_domains,
        elapsed.as_secs_f64(),
        format_size(meta.len(), BINARY)
    );

    Ok(())
}

#[derive(Clone)]
struct Stats {
    total_connections: Arc<AtomicUsize>,
    active_connections: Arc<AtomicUsize>,
    fragmented_connections: Arc<AtomicUsize>,
    whitelisted_connections: Arc<AtomicUsize>,
    blacklisted_blocks: Arc<AtomicUsize>,
    failed_connections: Arc<AtomicUsize>,
    client_disconnects: Arc<AtomicUsize>,
    traffic_in: Arc<AtomicU64>,
    traffic_out: Arc<AtomicU64>,
    pending_traffic_in: Arc<AtomicU64>,
    pending_traffic_out: Arc<AtomicU64>,
    last_flush: Arc<tokio::sync::Mutex<Instant>>,
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
            client_disconnects: Arc::new(AtomicUsize::new(0)),
            traffic_in: Arc::new(AtomicU64::new(0)),
            traffic_out: Arc::new(AtomicU64::new(0)),
            pending_traffic_in: Arc::new(AtomicU64::new(0)),
            pending_traffic_out: Arc::new(AtomicU64::new(0)),
            last_flush: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        }
    }

    async fn update_traffic(&self, bytes_in: u64, bytes_out: u64) {
        self.pending_traffic_in
            .fetch_add(bytes_in, Ordering::Relaxed);
        self.pending_traffic_out
            .fetch_add(bytes_out, Ordering::Relaxed);

        let should_flush = {
            let last_flush = self.last_flush.lock().await;
            last_flush.elapsed() > Duration::from_secs(1)
                || self.pending_traffic_in.load(Ordering::Relaxed) > 10_000_000
                || self.pending_traffic_out.load(Ordering::Relaxed) > 10_000_000
        };

        if should_flush {
            self.flush_traffic_stats().await;
        }
    }

    async fn flush_traffic_stats(&self) {
        let in_bytes = self.pending_traffic_in.swap(0, Ordering::Relaxed);
        let out_bytes = self.pending_traffic_out.swap(0, Ordering::Relaxed);
        if in_bytes > 0 {
            self.traffic_in.fetch_add(in_bytes, Ordering::Relaxed);
        }
        if out_bytes > 0 {
            self.traffic_out.fetch_add(out_bytes, Ordering::Relaxed);
        }
        *self.last_flush.lock().await = Instant::now();
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

struct ConnectionHandler {
    stats: Arc<Stats>,
    filter: Arc<OptimizedDomainFilter>,
    connection_semaphore: Arc<Semaphore>,
    resolver: Arc<TokioAsyncResolver>,
}

impl ConnectionHandler {
    fn log_disconnect(&self, addr: SocketAddr, reason: &str, disconnect_type: DisconnectType) {
        match disconnect_type {
            DisconnectType::Expected => {
                trace!("Client {} disconnected (expected): {}", addr, reason);
                self.stats
                    .client_disconnects
                    .fetch_add(1, Ordering::Relaxed);
            }
            DisconnectType::Unexpected => {
                debug!("Client {} disconnected (unexpected): {}", addr, reason);
                self.stats
                    .failed_connections
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn resolve_and_connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        use std::io::{Error, ErrorKind};

        let lookup = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("DNS error: {e}")))?;

        let mut ips: Vec<IpAddr> = lookup.iter().collect();
        ips.sort_by_key(|ip| match ip {
            IpAddr::V4(_) => 0,
            IpAddr::V6(_) => 1,
        });

        let mut last_err: Option<std::io::Error> = None;

        for ip in ips {
            let addr = SocketAddr::new(ip, port);
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => {
                    last_err = Some(Error::new(ErrorKind::TimedOut, "connect timeout"));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| Error::new(ErrorKind::NotFound, "no DNS A/AAAA records")))
    }

    async fn handle_client(
        &self,
        mut client_stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<()> {
        let sock_ref = socket2::SockRef::from(&client_stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(TCP_KEEPALIVE_TIME)
            .with_interval(TCP_KEEPALIVE_INTERVAL);
        let _ = sock_ref.set_tcp_keepalive(&keepalive);
        let _ = sock_ref.set_tcp_nodelay(true);
        let _permit = self.connection_semaphore.acquire().await?;
        self.stats
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
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
                self.log_disconnect(client_addr, "graceful close", DisconnectType::Expected);
                return Ok(());
            }
            Ok(Err(e)) if is_expected_error(&e) => {
                self.log_disconnect(client_addr, &e.to_string(), DisconnectType::Expected);
                return Ok(());
            }
            Ok(Err(e)) => {
                self.log_disconnect(client_addr, &e.to_string(), DisconnectType::Unexpected);
                return Err(e.into());
            }
            Err(_) => {
                debug!("Client {} read timeout", client_addr);
                return Err(ProxyError::Timeout.into());
            }
        };

        let request_data = &buffer[..n];
        let (method, host_lower, port) = match parse_http_request(request_data) {
            Ok(data) => data,
            Err(e) => {
                debug!("Invalid request from {}: {}", client_addr, e);
                return Err(e);
            }
        };

        let initial_request_copy = if method != "CONNECT" {
            Some(Bytes::copy_from_slice(request_data))
        } else {
            None
        };

        if self.filter.is_blacklisted(&host_lower) {
            debug!("Blocked blacklisted domain: {}", host_lower);
            self.stats
                .blacklisted_blocks
                .fetch_add(1, Ordering::Relaxed);
            let _ = client_stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Ok(());
        }

        let is_whitelisted = self.filter.is_whitelisted(&host_lower);
        if is_whitelisted {
            self.stats
                .whitelisted_connections
                .fetch_add(1, Ordering::Relaxed);
            debug!(
                "Whitelisted domain: {} - bypassing fragmentation",
                host_lower
            );
        }

        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
        self.stats.log_stats();

        let remote_str = format!("{}:{}", host_lower, port);
        trace!(
            "Handling {} request to {} from {}",
            method,
            remote_str,
            client_addr
        );

        let result = if method == "CONNECT" {
            self.handle_connect(client_stream, &host_lower, port, is_whitelisted)
                .await
        } else {
            self.handle_http(
                client_stream,
                &host_lower,
                port,
                &initial_request_copy.unwrap(),
            )
            .await
        };

        if let Err(ref e) = result {
            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                if is_expected_error(io_err) {
                    self.log_disconnect(client_addr, &io_err.to_string(), DisconnectType::Expected);
                    return Ok(());
                }
            }
        }

        result
    }

    async fn handle_connect(
        &self,
        mut client_stream: TcpStream,
        host: &str,
        port: u16,
        is_whitelisted: bool,
    ) -> Result<()> {
        let remote_stream = match self.resolve_and_connect(host, port).await {
            Ok(stream) => stream,
            Err(e) => {
                debug!("Failed to connect to remote {}:{}: {}", host, port, e);
                self.stats
                    .failed_connections
                    .fetch_add(1, Ordering::Relaxed);
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await;
                return Err(ProxyError::Connection(format!(
                    "Failed to connect to {}:{}",
                    host, port
                ))
                .into());
            }
        };

        let sock_ref = socket2::SockRef::from(&remote_stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(TCP_KEEPALIVE_TIME)
            .with_interval(TCP_KEEPALIVE_INTERVAL);
        let _ = sock_ref.set_tcp_keepalive(&keepalive);
        let _ = sock_ref.set_tcp_nodelay(true);

        if let Err(e) = client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
        {
            if is_expected_error(&e) {
                trace!(
                    "Client disconnected during CONNECT response (expected): {}",
                    e
                );
                self.stats
                    .client_disconnects
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            debug!("Failed to send CONNECT response (unexpected): {}", e);
            return Err(e.into());
        }
        client_stream.flush().await?;

        if !is_whitelisted {
            self.fragment_tls_handshake(client_stream, remote_stream)
                .await
        } else {
            self.pipe_connections_large(client_stream, remote_stream)
                .await
        }
    }

    async fn handle_http(
        &self,
        mut client_stream: TcpStream,
        host: &str,
        port: u16,
        request_data: &[u8],
    ) -> Result<()> {
        let mut remote_stream = match self.resolve_and_connect(host, port).await {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to connect to remote {}:{}: {}", host, port, e);
                self.stats
                    .failed_connections
                    .fetch_add(1, Ordering::Relaxed);
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err(ProxyError::Connection(format!(
                    "Failed to connect to {}:{}",
                    host, port
                ))
                .into());
            }
        };

        let sock_ref = socket2::SockRef::from(&remote_stream);
        let _ = sock_ref.set_tcp_nodelay(true);

        if let Err(e) = remote_stream.write_all(request_data).await {
            if is_expected_error(&e) {
                trace!(
                    "Remote disconnected while sending request (expected): {}",
                    e
                );
                return Ok(());
            }
            debug!("Failed to send request to remote (unexpected): {}", e);
            return Err(e.into());
        }
        remote_stream.flush().await?;

        self.pipe_connections_large(client_stream, remote_stream)
            .await
    }

    async fn fragment_tls_handshake(
        &self,
        mut client_stream: TcpStream,
        mut remote_stream: TcpStream,
    ) -> Result<()> {
        let mut header = [0u8; 5];

        match timeout(
            Duration::from_secs(5),
            client_stream.read_exact(&mut header),
        )
            .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if is_expected_error(&e) => {
                trace!("Client disconnected before TLS handshake (expected): {}", e);
                self.stats
                    .client_disconnects
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e.into());
            }
            Ok(Err(e)) => {
                debug!("Failed to read TLS header (unexpected): {}", e);
                return Err(e.into());
            }
            Err(_) => {
                debug!("Timeout reading TLS header");
                return Err(ProxyError::Timeout.into());
            }
        }

        // Not TLS handshake, pass through
        if header[0] != 0x16 {
            remote_stream.write_all(&header).await?;
            return self
                .pipe_connections_large(client_stream, remote_stream)
                .await;
        }

        let tls_version_major = header[1];
        let tls_version_minor = header[2];
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        const MAX_TLS_RECORD_SIZE: usize = 16384;
        if record_len == 0 || record_len > MAX_TLS_RECORD_SIZE {
            warn!(
            "Invalid TLS record length: {} (version: {}.{})",
            record_len, tls_version_major, tls_version_minor
        );
            remote_stream.write_all(&header).await?;
            return self
                .pipe_connections_large(client_stream, remote_stream)
                .await;
        }

        let mut body = vec![0u8; record_len];

        if let Err(e) = timeout(Duration::from_secs(5), client_stream.read_exact(&mut body)).await {
            debug!(
            "Failed to read TLS record body ({} bytes) after header: {:?}",
            record_len, e
        );
            return Err(
                ProxyError::Connection("Incomplete TLS handshake from client".into()).into(),
            );
        }

        self.stats
            .fragmented_connections
            .fetch_add(1, Ordering::Relaxed);
        trace!(
        "Fragmenting TLS {}.{} handshake ({} bytes)",
        tls_version_major,
        tls_version_minor,
        record_len
    );

        let fragments = fragment_tls_data(&body);
        for fragment in &fragments {
            let len = fragment.len() as u16;
            let mut frame_header = [0u8; 5];
            frame_header[0] = 0x16; // TLS handshake type
            frame_header[1] = tls_version_major; // Preserve original version
            frame_header[2] = tls_version_minor;
            frame_header[3] = (len >> 8) as u8;
            frame_header[4] = (len & 0xFF) as u8;

            remote_stream.write_all(&frame_header).await?;
            remote_stream.write_all(fragment).await?;
        }
        remote_stream.flush().await?;

        self.pipe_connections_large(client_stream, remote_stream)
            .await
    }

    async fn pipe_connections_large(&self, client: TcpStream, remote: TcpStream) -> Result<()> {
        use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
        let (cr, cw) = client.into_split();
        let (rr, rw) = remote.into_split();

        #[derive(Clone, Copy)]
        enum Dir {
            Upload,
            Download,
        }

        async fn copy_dir(
            mut reader: OwnedReadHalf,
            mut writer: OwnedWriteHalf,
            buf_size: usize,
            stats: Arc<Stats>,
            dir: Dir,
        ) -> std::io::Result<u64> {
            let mut buf = vec![0u8; buf_size];
            let mut total = 0u64;
            let mut batch = 0u64;

            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                writer.write_all(&buf[..n]).await?;
                total += n as u64;
                batch += n as u64;

                if batch >= 1_048_576 {
                    match dir {
                        Dir::Upload => stats.update_traffic(0, batch).await,
                        Dir::Download => stats.update_traffic(batch, 0).await,
                    }
                    batch = 0;
                }
            }

            if batch > 0 {
                match dir {
                    Dir::Upload => stats.update_traffic(0, batch).await,
                    Dir::Download => stats.update_traffic(batch, 0).await,
                }
            }

            let _ = writer.flush().await;
            Ok(total)
        }

        let stats_up = self.stats.clone();
        let stats_down = self.stats.clone();

        let mut up = tokio::spawn(copy_dir(cr, rw, PIPE_BUF, stats_up, Dir::Upload));
        let mut down = tokio::spawn(copy_dir(rr, cw, PIPE_BUF, stats_down, Dir::Download));

        tokio::select! {
            res = &mut up => {
                down.abort();
                match res {
                    Ok(Ok(_)) => { /* ok */ }
                    Ok(Err(e)) => {
                        if !is_expected_error(&e) { debug!("Upload pipe error: {}", e); }
                    }
                    Err(_) => {}
                }
            }
            res = &mut down => {
                up.abort();
                match res {
                    Ok(Ok(_)) => { /* ok */ }
                    Ok(Err(e)) => {
                        if !is_expected_error(&e) { debug!("Download pipe error: {}", e); }
                    }
                    Err(_) => {}
                }
            }
        }

        self.stats.flush_traffic_stats().await;
        Ok(())
    }
}

fn parse_http_request(data: &[u8]) -> Result<(String, String, u16)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let status = req.parse(data)?;
    if status.is_partial() {
        return Err(ProxyError::Connection("Partial HTTP request".into()).into());
    }

    let method = req.method.context("Missing HTTP method")?.to_string();
    let path = req.path.context("Missing HTTP path")?;

    let (mut host, port) = if method.eq_ignore_ascii_case("CONNECT") {
        let mut parts = path.splitn(2, ':');
        let host = parts.next().context("Invalid CONNECT path")?.to_string();
        let port = parts.next().and_then(|p| p.parse().ok()).unwrap_or(443);
        (host, port)
    } else {
        let host_header = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("Host"))
            .context("Missing Host header")?;

        let host_str =
            std::str::from_utf8(host_header.value).context("Host header contains invalid UTF-8")?;

        let mut parts = host_str.splitn(2, ':');
        let host = parts
            .next()
            .context("Invalid Host header value")?
            .to_string();
        let port = parts.next().and_then(|p| p.parse().ok()).unwrap_or(80);
        (host, port)
    };

    host = host.to_ascii_lowercase();

    Ok((method, host, port))
}

fn fragment_tls_data(data: &[u8]) -> Vec<Vec<u8>> {
    let mut fragments = Vec::new();
    // Example fragmentation pattern (tunable)
    let chunk_sizes = [1, 5, 10];
    let mut offset = 0;

    for &size in &chunk_sizes {
        if offset + size <= data.len() {
            fragments.push(data[offset..offset + size].to_vec());
            offset += size;
        }
    }

    if offset < data.len() {
        fragments.push(data[offset..].to_vec());
    }

    fragments
}

fn print_banner(args: &Args, filter: &OptimizedDomainFilter) {
    let (blacklist_count, whitelist_count) = filter.get_stats();
    let (cache_hits, cache_misses, bloom_fps) = filter.get_cache_stats();

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!(
        "║       \x1b[92mTLS Fragment Proxy v{}\x1b[0m                      ║",
        VERSION
    );
    println!("╚══════════════════════════════════════════════════════╝\n");

    println!("\x1b[92m[CONFIG]\x1b[0m");
    println!("  \x1b[97m├─ Address:\x1b[0m {}:{}", args.host, args.port);
    println!(
        "  \x1b[97m├─ Max Connections:\x1b[0m {}",
        args.max_connections
    );
    println!(
        "  \x1b[97m├─ Worker Threads:\x1b[0m {}",
        args.worker_threads
    );
    println!("  \x1b[97m├─ LRU/Cache Size:\x1b[0m {}", args.cache_size);

    if blacklist_count > 0 {
        println!(
            "  \x1b[97m├─ Blacklist:\x1b[0m {} domains loaded",
            blacklist_count
        );
    } else {
        println!("  \x1b[97m├─ Blacklist:\x1b[0m Not configured");
    }

    if whitelist_count > 0 {
        println!(
            "  \x1b[97m├─ Whitelist:\x1b[0m {} domains loaded",
            whitelist_count
        );
    } else {
        println!("  \x1b[97m├─ Whitelist:\x1b[0m Not configured");
    }

    if cache_hits > 0 || cache_misses > 0 {
        let hit_rate = if cache_hits + cache_misses > 0 {
            (cache_hits as f64 / (cache_hits + cache_misses) as f64) * 100.0
        } else {
            0.0
        };
        println!("  \x1b[97m├─ Cache Hit Rate:\x1b[0m {:.1}%", hit_rate);
    }

    if bloom_fps > 0 {
        println!("  \x1b[97m├─ Bloom False Positives:\x1b[0m {}", bloom_fps);
    }

    println!("  \x1b[97m├─ Health Check:\x1b[0m http://127.0.0.1:8882/health");
    println!(
        "  \x1b[97m└─ Started:\x1b[0m {}",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    );
    println!("\n\x1b[92m[INFO]\x1b[0m Press \x1b[93mCtrl+C\x1b[0m to stop the proxy\n");
}

async fn health_check_server(stats: Arc<Stats>, filter: Arc<OptimizedDomainFilter>) {
    if let Ok(health_listener) = TcpListener::bind("127.0.0.1:8882").await {
        info!("Health check endpoint listening on 127.0.0.1:8882");
        loop {
            if let Ok((mut stream, _)) = health_listener.accept().await {
                stats.flush_traffic_stats().await;

                let active = stats.active_connections.load(Ordering::Relaxed);
                let total = stats.total_connections.load(Ordering::Relaxed);
                let fragmented = stats.fragmented_connections.load(Ordering::Relaxed);
                let traffic_in = stats.traffic_in.load(Ordering::Relaxed);
                let traffic_out = stats.traffic_out.load(Ordering::Relaxed);
                let disconnects = stats.client_disconnects.load(Ordering::Relaxed);
                let blacklisted = stats.blacklisted_blocks.load(Ordering::Relaxed);
                let whitelisted = stats.whitelisted_connections.load(Ordering::Relaxed);

                let (cache_hits, cache_misses, bloom_fps) = filter.get_cache_stats();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
                    {{\"status\":\"healthy\",\"active\":{},\"total\":{},\"fragmented\":{},\
                    \"traffic_in\":{},\"traffic_out\":{},\"client_disconnects\":{},\
                    \"blacklisted_blocks\":{},\"whitelisted_connections\":{},\
                    \"cache_hits\":{},\"cache_misses\":{},\"bloom_false_positives\":{}}}\n",
                    active,
                    total,
                    fragmented,
                    traffic_in,
                    traffic_out,
                    disconnects,
                    blacklisted,
                    whitelisted,
                    cache_hits,
                    cache_misses,
                    bloom_fps
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        }
    } else {
        warn!("Failed to bind health check endpoint on 127.0.0.1:8882");
    }
}

async fn stats_reporter(stats: Arc<Stats>, filter: Arc<OptimizedDomainFilter>) {
    let mut interval = interval(Duration::from_secs(300));
    loop {
        interval.tick().await;

        stats.flush_traffic_stats().await;

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
        let (cache_hits, cache_misses, bloom_fps) = filter.get_cache_stats();

        let cache_hit_rate = if cache_hits + cache_misses > 0 {
            (cache_hits as f64 / (cache_hits + cache_misses) as f64) * 100.0
        } else {
            0.0
        };

        info!(
            "Stats: Active={}, Total={}, Fragmented={}, WL={}, BL-Blocks={}, Failed={}, Disconnects={}, \
             Traffic: In={}, Out={}, Lists: BL={}, WL={}, Cache: {:.1}% hit rate, Bloom FPs={}",
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
            wl_count,
            cache_hit_rate,
            bloom_fps
        );
    }
}

fn bind_tcp_listener(addr: &str) -> Result<TcpListener> {
    let addr: SocketAddr = addr.parse().context("invalid listen addr")?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    socket.listen(4096)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Build runtime with explicit worker threads
    let rt = TokioBuilder::new_multi_thread()
        .worker_threads(args.worker_threads.max(1))
        .enable_io()
        .enable_time()
        .build()
        .context("failed to build tokio runtime")?;

    rt.block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    // Handle preprocessing mode
    if args.preprocess_lists {
        if let Some(blacklist_path) = &args.blacklist {
            let output_path = blacklist_path.with_extension("bin");
            preprocess_domain_list(blacklist_path, &output_path).await?;
        }
        if let Some(whitelist_path) = &args.whitelist {
            let output_path = whitelist_path.with_extension("bin");
            preprocess_domain_list(whitelist_path, &output_path).await?;
        }
        info!("Preprocessing complete!");
        return Ok(());
    }

    // Setup logging
    let filter_level = if args.verbose {
        Level::TRACE
    } else {
        Level::INFO
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!("tls_fragment_proxy={}", filter_level))
    });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .init();

    info!("Starting TLS Fragment Proxy v{}", VERSION);

    let filter = Arc::new(OptimizedDomainFilter::new(&args).await?);
    let stats = Arc::new(Stats::new());
    let connection_semaphore = Arc::new(Semaphore::new(args.max_connections));
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), ResolverOpts::default());
    let resolver = Arc::new(resolver);

    let handler = Arc::new(ConnectionHandler {
        stats: stats.clone(),
        filter: Arc::clone(&filter),
        connection_semaphore: Arc::clone(&connection_semaphore),
        resolver: Arc::clone(&resolver),
    });

    if !args.quiet {
        print_banner(&args, &filter);
    }

    let addr = format!("{}:{}", args.host, args.port);
    let listener = bind_tcp_listener(&addr).context(format!("Failed to bind to {}", addr))?;

    info!("Proxy listening on {}", addr);

    // Health check endpoint
    let _filter_clone = Arc::clone(&filter);
    tokio::spawn(health_check_server(stats.clone(), filter.clone()));

    // Stats reporter
    let filter_clone = Arc::clone(&filter);
    tokio::spawn(stats_reporter(stats.clone(), filter_clone));

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
                                    Some(ProxyError::Timeout) => {
                                        debug!("Connection timeout from {}", addr);
                                    },
                                    _ => {
                                        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                                            if !is_expected_error(io_err) {
                                                debug!("Unexpected connection error from {}: {}", addr, e);
                                            }
                                        } else {
                                            warn!("Non-IO error from {}: {}", addr, e);
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        } => {}
    }

    let _ = shutdown_tx.send(());

    stats.flush_traffic_stats().await;

    let shutdown_timeout = Duration::from_secs(30);
    let shutdown_start = Instant::now();

    while stats.active_connections.load(Ordering::Relaxed) > 0 {
        if shutdown_start.elapsed() > shutdown_timeout {
            warn!(
                "Shutdown timeout reached, {} connections still active",
                stats.active_connections.load(Ordering::Relaxed)
            );
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    let (bl_count, wl_count) = filter.get_stats();
    let (cache_hits, cache_misses, bloom_fps) = filter.get_cache_stats();

    if !args.quiet {
        println!("\n╔══════════════════════════════════════════════════════╗");
        println!("║                 \x1b[92mFINAL STATISTICS\x1b[0m                     ║");
        println!("╚══════════════════════════════════════════════════════╝\n");

        println!(
            "  \x1b[97mTotal Connections:\x1b[0m      {}",
            stats.total_connections.load(Ordering::Relaxed)
        );
        println!(
            "  \x1b[97mFragmented Connections:\x1b[0m {}",
            stats.fragmented_connections.load(Ordering::Relaxed)
        );
        println!(
            "  \x1b[97mWhitelisted Connections:\x1b[0m {}",
            stats.whitelisted_connections.load(Ordering::Relaxed)
        );
        println!(
            "  \x1b[97mBlacklisted Blocks:\x1b[0m     {}",
            stats.blacklisted_blocks.load(Ordering::Relaxed)
        );
        println!(
            "  \x1b[97mFailed Connections:\x1b[0m     {}",
            stats.failed_connections.load(Ordering::Relaxed)
        );
        println!(
            "  \x1b[97mClient Disconnects:\x1b[0m     {}",
            stats.client_disconnects.load(Ordering::Relaxed)
        );
        println!(
            "  \x1b[97mTotal Downloaded:\x1b[0m       {}",
            format_size(stats.traffic_in.load(Ordering::Relaxed), BINARY)
        );
        println!(
            "  \x1b[97mTotal Uploaded:\x1b[0m         {}",
            format_size(stats.traffic_out.load(Ordering::Relaxed), BINARY)
        );
        println!("  \x1b[97mBlacklist Domains:\x1b[0m      {}", bl_count);
        println!("  \x1b[97mWhitelist Domains:\x1b[0m      {}", wl_count);
        println!("  \x1b[97mCache Hits:\x1b[0m             {}", cache_hits);
        println!("  \x1b[97mCache Misses:\x1b[0m           {}", cache_misses);
        if cache_hits + cache_misses > 0 {
            println!(
                "  \x1b[97mCache Hit Rate:\x1b[0m         {:.1}%",
                (cache_hits as f64 / (cache_hits + cache_misses) as f64) * 100.0
            );
        }
        println!("  \x1b[97mBloom False Positives:\x1b[0m  {}", bloom_fps);

        println!("\n\x1b[92m[SUCCESS]\x1b[0m Proxy shut down gracefully\n");
    }

    Ok(())
}
