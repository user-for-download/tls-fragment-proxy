use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use chrono::Local;
use clap::Parser;
use dashmap::DashMap;
use humansize::{format_size, BINARY};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Semaphore};
use tokio::time::{interval, timeout, sleep};
use tracing::{debug, error, info, warn, trace};
use tracing::Level;
use bloomfilter::Bloom;
use lru::LruCache;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use bincode::{config};
use httparse;

const VERSION: &str = "1.0.4";
const BUFFER_SIZE: usize = 65536;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(60);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const TCP_BUFFER_SIZE: usize = 262144; // 256KB
const LRU_CACHE_SIZE: usize = 10000;
const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.001;

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

    #[error("HTTP parse error: {0}")]
    HttpParse(#[from] httparse::Error),
}

// Disconnect type for consistent logging
enum DisconnectType {
    Expected,    // Normal client disconnects - trace level
    Unexpected,  // Unexpected errors - debug level
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

    #[arg(long)]
    blacklist_binary: Option<PathBuf>,

    #[arg(long)]
    whitelist_binary: Option<PathBuf>,

    #[arg(long, default_value_t = 1000)]
    max_connections: usize,

    #[arg(long, default_value_t = 1000)]
    rate_limit_per_second: usize,

    #[arg(short, long)]
    quiet: bool,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long, default_value_t = 4)]
    worker_threads: usize,

    #[arg(long, default_value_t = 100)]
    buffer_pool_size: usize,

    #[arg(long)]
    preprocess_lists: bool,

    #[arg(long, default_value_t = LRU_CACHE_SIZE)]
    cache_size: usize,
}

// Compressed Radix Tree Node
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
        if key.is_empty() {
            self.is_end = true;
            return;
        }

        let first_char = key.chars().next().unwrap();

        if let Some(child) = self.children.get_mut(&first_char) {
            // Find common prefix
            let common_len = key.chars()
                .zip(child.prefix.chars())
                .take_while(|(a, b)| a == b)
                .count();

            if common_len == child.prefix.len() {
                // Continue with remaining key
                child.insert(&key[common_len..]);
            } else {
                // Split the node
                let mut new_child = RadixNode::new();
                new_child.prefix = child.prefix[common_len..].to_string();
                new_child.is_end = child.is_end;
                new_child.children = std::mem::take(&mut child.children);

                child.prefix = child.prefix[..common_len].to_string();
                child.is_end = false;

                let split_char = new_child.prefix.chars().next().unwrap();
                child.children.insert(split_char, Box::new(new_child));

                if key.len() > common_len {
                    child.insert(&key[common_len..]);
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
            if key.starts_with(&child.prefix) {
                return child.contains(&key[child.prefix.len()..]);
            }
        }

        false
    }
}

// Domain filter statistics
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

// Optimized domain filter with multiple tiers
struct OptimizedDomainFilter {
    // Tier 1: Bloom filters for fast negative lookups
    blacklist_bloom: Option<Arc<Bloom<Vec<u8>>>>,
    whitelist_bloom: Option<Arc<Bloom<Vec<u8>>>>,

    // Tier 2: LRU cache for recent lookups
    blacklist_cache: Arc<Mutex<LruCache<String, bool>>>,
    whitelist_cache: Arc<Mutex<LruCache<String, bool>>>,

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
            blacklist_cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(args.cache_size).unwrap()
            ))),
            whitelist_cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(args.cache_size).unwrap()
            ))),
            blacklist_tree: Arc::new(RwLock::new(RadixNode::new())),
            whitelist_tree: Arc::new(RwLock::new(RadixNode::new())),
            blacklist_wildcard: None,
            whitelist_wildcard: None,
            stats: DomainFilterStats::new(),
        };

        // Load lists based on format
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
                self.stats.blacklist_domains.store(domain_count, Ordering::Relaxed);
            }
            ListType::Whitelist => {
                *self.whitelist_tree.write() = tree;
                self.stats.whitelist_domains.store(domain_count, Ordering::Relaxed);
            }
        }
    }

    fn set_bloom_filter(&mut self, bloom: Bloom<Vec<u8>>, list_type: ListType) {
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
            return Err(ProxyError::Configuration(
                format!("File not found: {}", path.display())
            ).into());
        }

        let start = Instant::now();
        let content = tokio::fs::read_to_string(path).await
            .context(format!("Failed to read file: {}", path.display()))?;

        // Parse domains in parallel
        let lines: Vec<&str> = content.lines().collect();
        let chunk_size = 10000;

        let processed: Vec<Vec<(String, bool)>> = lines
            .par_chunks(chunk_size)
            .map(|chunk| {
                chunk.iter()
                    .filter_map(|line| {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            None
                        } else {
                            let is_wildcard = trimmed.starts_with("*.");
                            Some((trimmed.to_lowercase(), is_wildcard))
                        }
                    })
                    .collect()
            })
            .collect();

        // Flatten results
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
            let mut bloom = Bloom::new_for_fp_rate(exact_domains.len(), BLOOM_FALSE_POSITIVE_RATE)
                .map_err(|e| anyhow::anyhow!("Failed to create bloom filter: {}", e))?;

            for domain in &exact_domains {
                bloom.set(&domain.as_bytes().to_vec());
            }

            self.set_bloom_filter(bloom, list_type);
        }

        // Build radix tree for exact domains
        let mut tree = RadixNode::new();
        for domain in &exact_domains {
            tree.insert(domain);
        }

        // Update tree and stats using helper method
        let total_count = exact_domains.len() + wildcard_patterns.len();
        self.update_tree_and_stats(tree, total_count, list_type);

        // Build Aho-Corasick automaton for wildcard patterns
        if !wildcard_patterns.is_empty() {
            // --- REFACTORED: Use the new helper function ---
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
            return Err(ProxyError::Configuration(
                format!("Binary list file not found: {}", path.display())
            ).into());
        }

        let data = tokio::fs::read(path)
            .await
            .context(format!("Failed to read binary list file: {}", path.display()))?;

        let ((tree, wildcard_patterns), bytes_read): ((RadixNode, Vec<String>), usize) =
            bincode::serde::decode_from_slice(&data, config::standard())
                .context("Failed to deserialize binary domain list. The file might be outdated or corrupt. Please re-run with --preprocess-lists.")?;

        if bytes_read != data.len() {
            warn!(
            "Binary list file {} may have trailing data (read {} of {} bytes). The file could be corrupt.",
            path.display(),
            bytes_read,
            data.len()
        );
        }

        let exact_count = count_domains_in_tree(&tree);

        if !wildcard_patterns.is_empty() {
            // --- REFACTORED: Use the new helper function ---
            let ac = Self::build_wildcard_automaton(&wildcard_patterns)?;
            self.set_wildcard_automaton(ac, list_type);
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

    fn check_domain(&self, domain: &str, list_type: ListType) -> bool {
        let domain_lower = domain.to_lowercase();

        let (cache, bloom, tree, wildcard) = match list_type {
            ListType::Blacklist => (
                &self.blacklist_cache,
                &self.blacklist_bloom,
                &self.blacklist_tree,
                &self.blacklist_wildcard,
            ),
            ListType::Whitelist => (
                &self.whitelist_cache,
                &self.whitelist_bloom,
                &self.whitelist_tree,
                &self.whitelist_wildcard,
            ),
        };

        // Tier 1: Check cache
        if let Some(mut cache_guard) = cache.try_lock() {
            if let Some(&result) = cache_guard.get(&domain_lower) {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return result;
            }
        }

        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        if let Some(bloom_filter) = bloom {
            if !bloom_filter.check(&domain_lower.as_bytes().to_vec()) {
            }
        }

        let tree_guard = tree.read();
        if tree_guard.contains(&domain_lower) {
            if let Some(mut cache_guard) = cache.try_lock() {
                cache_guard.put(domain_lower.clone(), true);
            }
            return true;
        }

        if let Some(ac) = wildcard {
            for mat in ac.find_iter(&domain_lower) {
                if mat.end() == domain_lower.len() {
                    if mat.start() == 0 || domain_lower.as_bytes()[mat.start() - 1] == b'.' {
                        if let Some(mut cache_guard) = cache.try_lock() {
                            cache_guard.put(domain_lower.clone(), true);
                        }
                        return true;
                    }
                }
            }
        }
        if let Some(mut cache_guard) = cache.try_lock() {
            cache_guard.put(domain_lower, false);
        }

        false
    }

    fn is_blacklisted(&self, domain: &str) -> bool {
        self.check_domain(domain, ListType::Blacklist)
    }

    fn is_whitelisted(&self, domain: &str) -> bool {
        self.check_domain(domain, ListType::Whitelist)
    }

    fn get_stats(&self) -> (usize, usize) {
        (
            self.stats.blacklist_domains.load(Ordering::Relaxed),
            self.stats.whitelist_domains.load(Ordering::Relaxed)
        )
    }

    fn get_cache_stats(&self) -> (usize, usize, usize) {
        (
            self.stats.cache_hits.load(Ordering::Relaxed),
            self.stats.cache_misses.load(Ordering::Relaxed),
            self.stats.bloom_false_positives.load(Ordering::Relaxed)
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

// Preprocessing utility for converting text lists to optimized binary format
async fn preprocess_domain_list(input: &Path, output: &Path) -> Result<()> {
    info!("Preprocessing domain list: {} -> {}", input.display(), output.display());

    let start = Instant::now();
    let content = tokio::fs::read_to_string(input).await?;

    // --- REWRITTEN FOR COMPILER STABILITY ---
    // Step 1: Process all lines into a clean vector in parallel.
    // This avoids a single, overly long chain of method calls that can confuse the compiler.
    let lines: Vec<String> = content
        .par_lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_lowercase())
        .collect();

    // Step 2: Partition the clean vector into exact domains and wildcard patterns.
    let (exact_domains, wildcard_patterns): (Vec<String>, Vec<String>) = lines
        .into_par_iter()
        .partition(|line| !line.starts_with("*."));

    info!(
        "Building radix tree from {} exact domains and processing {} wildcard patterns...",
        exact_domains.len(),
        wildcard_patterns.len()
    );

    // Build radix tree from exact domains
    let mut tree = RadixNode::new();
    for domain in &exact_domains {
        tree.insert(domain);
    }

    // The data to be serialized is a tuple containing both structures
    let data_to_serialize = (tree, wildcard_patterns);

    // Serialize to binary
    let encoded = bincode::serde::encode_to_vec(&data_to_serialize, config::standard())?;

    // Write to file
    tokio::fs::write(output, encoded).await?;

    let total_domains = exact_domains.len() + data_to_serialize.1.len();
    let elapsed = start.elapsed();
    info!(
        "✓ Preprocessed {} domains in {:.2}s, output size: {}",
        total_domains,
        elapsed.as_secs_f64(),
        format_size(output.metadata()?.len(), BINARY)
    );

    Ok(())
}
struct BufferPool {
    pool: Arc<tokio::sync::Mutex<Vec<BytesMut>>>,
    buffer_size: usize,
    max_pool_size: usize,
}

impl BufferPool {
    fn new(initial_capacity: usize, buffer_size: usize, max_pool_size: usize) -> Self {
        let mut pool = Vec::with_capacity(initial_capacity);
        for _ in 0..initial_capacity.min(max_pool_size) {
            pool.push(BytesMut::with_capacity(buffer_size));
        }
        Self {
            pool: Arc::new(tokio::sync::Mutex::new(pool)),
            buffer_size,
            max_pool_size,
        }
    }

    async fn get(&self) -> BytesMut {
        let mut pool = self.pool.lock().await;
        pool.pop().unwrap_or_else(|| BytesMut::with_capacity(self.buffer_size))
    }

    async fn put(&self, mut buffer: BytesMut) {
        buffer.clear();
        let mut pool = self.pool.lock().await;
        if pool.len() < self.max_pool_size {
            pool.push(buffer);
        }
    }
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
            rate_limited_connections: Arc::new(AtomicUsize::new(0)),
            client_disconnects: Arc::new(AtomicUsize::new(0)),
            traffic_in: Arc::new(AtomicU64::new(0)),
            traffic_out: Arc::new(AtomicU64::new(0)),
            pending_traffic_in: Arc::new(AtomicU64::new(0)),
            pending_traffic_out: Arc::new(AtomicU64::new(0)),
            last_flush: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        }
    }

    async fn update_traffic(&self, bytes_in: u64, bytes_out: u64) {
        self.pending_traffic_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.pending_traffic_out.fetch_add(bytes_out, Ordering::Relaxed);

        let should_flush = {
            let last_flush = self.last_flush.lock().await;
            last_flush.elapsed() > Duration::from_secs(1) ||
                self.pending_traffic_in.load(Ordering::Relaxed) > 10_000_000 ||
                self.pending_traffic_out.load(Ordering::Relaxed) > 10_000_000
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

// Optimized lock-free rate limiter
struct RateLimiter {
    limits: Arc<DashMap<IpAddr, Arc<AtomicRateLimit>>>,
    max_per_second: usize,
}

struct AtomicRateLimit {
    tokens: AtomicUsize,
    last_refill_ms: AtomicU64,
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
            let mut interval = interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;

                limits_clone.retain(|_, entry| {
                    let last_refill = entry.last_refill_ms.load(Ordering::Relaxed);
                    now_ms - last_refill < 300_000
                });

                if limits_clone.len() > 10000 {
                    limits_clone.shrink_to_fit();
                }
            }
        });

        limiter
    }

    fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let entry = self.limits.entry(ip)
            .or_insert_with(|| Arc::new(AtomicRateLimit {
                tokens: AtomicUsize::new(self.max_per_second),
                last_refill_ms: AtomicU64::new(now_ms),
            }));

        let last_refill = entry.last_refill_ms.load(Ordering::Relaxed);
        let elapsed_ms = now_ms.saturating_sub(last_refill);

        if elapsed_ms >= 1000 {
            entry.tokens.store(self.max_per_second, Ordering::Relaxed);
            entry.last_refill_ms.store(now_ms, Ordering::Relaxed);
        }

        loop {
            let current = entry.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }

            match entry.tokens.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }
}

struct ConnectionHandler {
    stats: Stats,
    filter: Arc<OptimizedDomainFilter>,
    rate_limiter: Arc<RateLimiter>,
    connection_semaphore: Arc<Semaphore>,
    buffer_pool: Arc<BufferPool>,
}

impl ConnectionHandler {
    fn log_disconnect(&self, addr: SocketAddr, reason: &str, disconnect_type: DisconnectType) {
        match disconnect_type {
            DisconnectType::Expected => {
                trace!("Client {} disconnected (expected): {}", addr, reason);
                self.stats.client_disconnects.fetch_add(1, Ordering::Relaxed);
            }
            DisconnectType::Unexpected => {
                debug!("Client {} disconnected (unexpected): {}", addr, reason);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn handle_client(
        &self,
        mut client_stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<()> {
        // TCP optimizations
        let sock_ref = socket2::SockRef::from(&client_stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(TCP_KEEPALIVE_TIME)
            .with_interval(TCP_KEEPALIVE_INTERVAL);
        let _ = sock_ref.set_tcp_keepalive(&keepalive);
        let _ = sock_ref.set_tcp_nodelay(true);
        let _ = sock_ref.set_recv_buffer_size(TCP_BUFFER_SIZE);
        let _ = sock_ref.set_send_buffer_size(TCP_BUFFER_SIZE);

        // Rate limiting
        if !self.rate_limiter.check_rate_limit(client_addr.ip()) {
            self.stats.rate_limited_connections.fetch_add(1, Ordering::Relaxed);
            debug!("Rate limited connection from {}", client_addr);
            return Err(ProxyError::RateLimited.into());
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

        // Use buffer pool
        let mut buffer = self.buffer_pool.get().await;
        buffer.resize(BUFFER_SIZE, 0);

        let n = match timeout(CLIENT_TIMEOUT, client_stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => n,
            Ok(Ok(_)) => {
                self.log_disconnect(client_addr, "graceful close", DisconnectType::Expected);
                self.buffer_pool.put(buffer).await;
                return Ok(());
            }
            Ok(Err(e)) if is_expected_error(&e) => {
                self.log_disconnect(client_addr, &e.to_string(), DisconnectType::Expected);
                self.buffer_pool.put(buffer).await;
                return Ok(());
            }
            Ok(Err(e)) => {
                self.log_disconnect(client_addr, &e.to_string(), DisconnectType::Unexpected);
                self.buffer_pool.put(buffer).await;
                return Err(e.into());
            }
            Err(_) => {
                debug!("Client {} read timeout", client_addr);
                self.buffer_pool.put(buffer).await;
                return Err(ProxyError::Timeout.into());
            }
        };

        let request_data = &buffer[..n];
        let (method, host, port) = match parse_http_request(request_data) {
            Ok(data) => data,
            Err(e) => {
                debug!("Invalid request from {}: {}", client_addr, e);
                self.buffer_pool.put(buffer).await;
                return Err(e);
            }
        };

        let initial_request_copy = if method != "CONNECT" {
            Some(Bytes::copy_from_slice(request_data))
        } else {
            None
        };

        self.buffer_pool.put(buffer).await;

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
            self.handle_http(client_stream, &remote_addr, &initial_request_copy.unwrap()).await
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
        remote_addr: &str,
        is_whitelisted: bool,
    ) -> Result<()> {
        let remote_stream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(remote_addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!("Failed to connect to remote {}: {}", remote_addr, e);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(ProxyError::Connection(format!("Failed to connect to {}", remote_addr)).into());
            }
            Err(_) => {
                debug!("Connection timeout to remote {}", remote_addr);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream.write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n").await;
                return Err(ProxyError::Timeout.into());
            }
        };

        // TCP optimizations for remote connection
        let sock_ref = socket2::SockRef::from(&remote_stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(TCP_KEEPALIVE_TIME)
            .with_interval(TCP_KEEPALIVE_INTERVAL);
        let _ = sock_ref.set_tcp_keepalive(&keepalive);
        let _ = sock_ref.set_tcp_nodelay(true);
        let _ = sock_ref.set_recv_buffer_size(TCP_BUFFER_SIZE);
        let _ = sock_ref.set_send_buffer_size(TCP_BUFFER_SIZE);

        if let Err(e) = client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await {
            if is_expected_error(&e) {
                trace!("Client disconnected during CONNECT response (expected): {}", e);
                self.stats.client_disconnects.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            debug!("Failed to send CONNECT response (unexpected): {}", e);
            return Err(e.into());
        }

        client_stream.flush().await?;

        if !is_whitelisted {
            self.fragment_tls_handshake(client_stream, remote_stream).await
        } else {
            self.pipe_connections_optimized(client_stream, remote_stream).await
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
                debug!("Failed to connect to remote {}: {}", remote_addr, e);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err(ProxyError::Connection(format!("Failed to connect to {}", remote_addr)).into());
            }
            Err(_) => {
                debug!("Connection timeout to remote {}", remote_addr);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                let _ = client_stream
                    .write_all(b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err(ProxyError::Timeout.into());
            }
        };

        let sock_ref = socket2::SockRef::from(&remote_stream);
        let _ = sock_ref.set_tcp_nodelay(true);

        if let Err(e) = remote_stream.write_all(request_data).await {
            if is_expected_error(&e) {
                trace!("Remote disconnected while sending request (expected): {}", e);
                return Ok(());
            }
            debug!("Failed to send request to remote (unexpected): {}", e);
            return Err(e.into());
        }

        remote_stream.flush().await?;

        self.pipe_connections_optimized(client_stream, remote_stream).await
    }

    async fn fragment_tls_handshake(
        &self,
        mut client_stream: TcpStream,
        mut remote_stream: TcpStream,
    ) -> Result<()> {
        let mut header = [0u8; 5];

        match timeout(Duration::from_secs(5), client_stream.read_exact(&mut header)).await {
            Ok(Ok(_)) => {
                // Successfully read 5 bytes.
            }
            Ok(Err(e)) if is_expected_error(&e) => {
                trace!("Client disconnected before TLS handshake (expected): {}", e);
                self.stats.client_disconnects.fetch_add(1, Ordering::Relaxed);
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

        if header[0] != 0x16 {
            remote_stream.write_all(&header).await?;
            return self.pipe_connections_optimized(client_stream, remote_stream).await;
        }

        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        const MAX_TLS_RECORD_SIZE: usize = 16384;
        if record_len == 0 || record_len > MAX_TLS_RECORD_SIZE {
            warn!("Invalid TLS record length received: {}", record_len);
            remote_stream.write_all(&header).await?;
            return self.pipe_connections_optimized(client_stream, remote_stream).await;
        }

        let mut body = vec![0u8; record_len];

        if let Err(e) = timeout(Duration::from_secs(5), client_stream.read_exact(&mut body)).await {
            debug!("Failed to read TLS body from client after header: {:?}", e);
            return Err(ProxyError::Connection("Incomplete TLS handshake from client".into()).into());
        }

        self.stats.fragmented_connections.fetch_add(1, Ordering::Relaxed);
        trace!("Fragmenting TLS handshake ({} bytes)", record_len);

        let fragments = fragment_tls_data(&body);

        for fragment in fragments {
            let frame = create_tls_frame(&fragment);
            remote_stream.write_all(&frame).await?;
            remote_stream.flush().await?;
        }

        self.pipe_connections_optimized(client_stream, remote_stream).await
    }

    async fn pipe_connections_optimized(&self, client: TcpStream, remote: TcpStream) -> Result<()> {
        let (client_read, client_write) = client.into_split();
        let (remote_read, remote_write) = remote.into_split();

        let buffer_pool1 = Arc::clone(&self.buffer_pool);
        let buffer_pool2 = Arc::clone(&self.buffer_pool);
        let stats1 = self.stats.clone();
        let stats2 = self.stats.clone();

        let client_to_remote = async move {
            let mut buffer = buffer_pool1.get().await;
            buffer.resize(65536, 0);
            let result = copy_with_buffer(client_read, remote_write, &mut buffer, &stats1, true).await;
            buffer_pool1.put(buffer).await;
            result
        };

        let remote_to_client = async move {
            let mut buffer = buffer_pool2.get().await;
            buffer.resize(65536, 0);
            let result = copy_with_buffer(remote_read, client_write, &mut buffer, &stats2, false).await;
            buffer_pool2.put(buffer).await;
            result
        };

        let (c2r_result, r2c_result) = tokio::join!(client_to_remote, remote_to_client);

        self.stats.flush_traffic_stats().await;

        match (c2r_result, r2c_result) {
            (Ok(bytes_up), Ok(bytes_down)) => {
                trace!("Connection closed gracefully: {}b up, {}b down", bytes_up, bytes_down);
                Ok(())
            }
            (Err(e), _) | (_, Err(e)) if is_expected_error(&e) => {
                trace!("Connection closed (expected): {}", e);
                Ok(())
            }
            (Err(e), _) | (_, Err(e)) => {
                debug!("Connection error (unexpected): {}", e);
                Err(e.into())
            }
        }
    }
}

async fn copy_with_buffer(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    buffer: &mut BytesMut,
    stats: &Stats,
    is_upload: bool,
) -> std::io::Result<u64> {
    let mut total = 0u64;
    let mut batch_bytes = 0u64;

    loop {
        match reader.read(buffer).await {
            Ok(0) => break,
            Ok(n) => {
                writer.write_all(&buffer[..n]).await?;
                total += n as u64;
                batch_bytes += n as u64;

                if batch_bytes >= 1_048_576 {
                    if is_upload {
                        stats.update_traffic(0, batch_bytes).await;
                    } else {
                        stats.update_traffic(batch_bytes, 0).await;
                    }
                    batch_bytes = 0;
                }
            }
            Err(e) => {
                if batch_bytes > 0 {
                    if is_upload {
                        stats.update_traffic(0, batch_bytes).await;
                    } else {
                        stats.update_traffic(batch_bytes, 0).await;
                    }
                }
                return Err(e);
            }
        }
    }

    if batch_bytes > 0 {
        if is_upload {
            stats.update_traffic(0, batch_bytes).await;
        } else {
            stats.update_traffic(batch_bytes, 0).await;
        }
    }

    Ok(total)
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

    let (host, port) = if method.eq_ignore_ascii_case("CONNECT") {
        let mut parts = path.splitn(2, ':');
        let host = parts.next().context("Invalid CONNECT path")?.to_string();
        let port = parts.next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        (host, port)
    } else {
        let host_header = req.headers.iter()
            .find(|h| h.name.eq_ignore_ascii_case("Host"))
            .context("Missing Host header")?;

        let host_str = std::str::from_utf8(host_header.value)
            .context("Host header contains invalid UTF-8")?;

        let mut parts = host_str.splitn(2, ':');
        let host = parts.next().context("Invalid Host header value")?.to_string();
        let port = parts.next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(80);
        (host, port)
    };

    Ok((method, host, port))
}

fn fragment_tls_data(data: &[u8]) -> Vec<Vec<u8>> {

    let mut fragments = Vec::new();

    // Example: Split into multiple smaller chunks
    let chunk_sizes = [1, 5, 10]; // Configurable
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

fn create_tls_frame(data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + data.len());
    frame.push(0x16); // TLS handshake
    frame.push(0x03); // TLS version
    frame.push(0x04); // TLS 1.3
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn print_banner(args: &Args, filter: &OptimizedDomainFilter) {
    let (blacklist_count, whitelist_count) = filter.get_stats();
    let (cache_hits, cache_misses, bloom_fps) = filter.get_cache_stats();

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║       \x1b[92mTLS Fragment Proxy v{}\x1b[0m                      ║", VERSION);
    println!("╚══════════════════════════════════════════════════════╝\n");

    println!("\x1b[92m[CONFIG]\x1b[0m");
    println!("  \x1b[97m├─ Address:\x1b[0m {}:{}", args.host, args.port);
    println!("  \x1b[97m├─ Fragment Mode:\x1b[0m Smart SNI Detection");
    println!("  \x1b[97m├─ Max Connections:\x1b[0m {}", args.max_connections);
    println!("  \x1b[97m├─ Rate Limit:\x1b[0m {}/sec per IP", args.rate_limit_per_second);
    println!("  \x1b[97m├─ Worker Threads:\x1b[0m {}", args.worker_threads);
    println!("  \x1b[97m├─ Buffer Pool Size:\x1b[0m {}", args.buffer_pool_size);
    println!("  \x1b[97m├─ LRU Cache Size:\x1b[0m {}", args.cache_size);

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
    println!("  \x1b[97m└─ Started:\x1b[0m {}", Local::now().format("%Y-%m-%d %H:%M:%S"));
    println!("\n\x1b[92m[INFO]\x1b[0m Press \x1b[93mCtrl+C\x1b[0m to stop the proxy\n");
}

async fn health_check_server(stats: Stats, filter: Arc<OptimizedDomainFilter>) {
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
                    active, total, fragmented, traffic_in, traffic_out, disconnects,
                    blacklisted, whitelisted, cache_hits, cache_misses, bloom_fps
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        }
    } else {
        warn!("Failed to bind health check endpoint on 127.0.0.1:8882");
    }
}

async fn stats_reporter(stats: Stats, filter: Arc<OptimizedDomainFilter>) {
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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new(format!("tls_fragment_proxy={}", filter_level))
        });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .init();

    info!("Starting TLS Fragment Proxy v{}", VERSION);

    let filter = Arc::new(OptimizedDomainFilter::new(&args).await?);
    let stats = Stats::new();
    let rate_limiter = Arc::new(RateLimiter::new(args.rate_limit_per_second));
    let connection_semaphore = Arc::new(Semaphore::new(args.max_connections));
    let buffer_pool = Arc::new(BufferPool::new(
        args.buffer_pool_size,
        BUFFER_SIZE,
        args.buffer_pool_size * 2
    ));

    let handler = Arc::new(ConnectionHandler {
        stats: stats.clone(),
        filter: Arc::clone(&filter),
        rate_limiter: Arc::clone(&rate_limiter),
        connection_semaphore: Arc::clone(&connection_semaphore),
        buffer_pool: Arc::clone(&buffer_pool),
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
    let filter_clone = Arc::clone(&filter);
    tokio::spawn(health_check_server(stats.clone(), filter_clone));

    // Start stats reporter
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
                                    Some(ProxyError::RateLimited) => {
                                        // Already logged at debug level
                                    },
                                    Some(ProxyError::Timeout) => {
                                        debug!("Connection timeout from {}", addr);
                                    },
                                    _ => {
                                        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                                            if !is_expected_error(io_err) {
                                                debug!("Unexpected connection error from {}: {}", addr, e);
                                            }
                                            // Expected errors already logged at trace level
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
            warn!("Shutdown timeout reached, {} connections still active",
                stats.active_connections.load(Ordering::Relaxed));
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
        println!("  \x1b[97mCache Hits:\x1b[0m             {}", cache_hits);
        println!("  \x1b[97mCache Misses:\x1b[0m           {}", cache_misses);
        if cache_hits + cache_misses > 0 {
            println!("  \x1b[97mCache Hit Rate:\x1b[0m         {:.1}%",
                     (cache_hits as f64 / (cache_hits + cache_misses) as f64) * 100.0);
        }
        println!("  \x1b[97mBloom False Positives:\x1b[0m  {}", bloom_fps);

        println!("\n\x1b[92m[SUCCESS]\x1b[0m Proxy shut down gracefully\n");
    }

    Ok(())
}
