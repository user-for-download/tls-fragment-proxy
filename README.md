# TLS Fragment Proxy

High-performance HTTP/HTTPS proxy with TLS fragmentation.

## Features

- TLS handshake fragmentation
- Multi-tiered domain filtering (blacklist/whitelist)
- Memory-efficient buffer pooling
- Lock-free rate limiting
- Real-time statistics
- Health check endpoint

## Build

```bash
git clone https://github.com/user-for-download/tls-fragment-proxy.git
cd  tls-fragment-proxy
cargo build --release
```
## Usage

```bash
# Basic
./tls-fragment-proxy

# With domain filtering
./tls-fragment-proxy --blacklist blocked.txt --whitelist allowed.txt

# Custom port and rate limiting
./tls-fragment-proxy --port 8080 --rate-limit-per-second 100 --max-connections 5000

# Preprocess large domain lists for faster loading
./tls-fragment-proxy --preprocess-lists --blacklist domains.txt
# Then use the binary version
./tls-fragment-proxy --blacklist-binary blocked.bin

# Verbose logging
./tls-fragment-proxy -v

# Quiet mode
./tls-fragment-proxy -q
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | 0.0.0.0 | Bind address |
| `--port` | 8888 | Proxy port |
| `--blacklist` | - | Path to blacklist file |
| `--whitelist` | - | Path to whitelist file |
| `--blacklist-binary` | - | Path to preprocessed blacklist |
| `--whitelist-binary` | - | Path to preprocessed whitelist |
| `--max-connections` | 1000 | Maximum concurrent connections |
| `--rate-limit-per-second` | 1000 | Requests per second per IP |
| `--worker-threads` | 4 | Number of worker threads |
| `--buffer-pool-size` | 100 | Buffer pool size |
| `--cache-size` | 10000 | LRU cache size |
| `--preprocess-lists` | false | Convert text lists to binary format |
| `-v, --verbose` | false | Enable trace logging |
| `-q, --quiet` | false | Disable banner |

## Client Configuration

### Browser (Firefox/Chrome)
```
HTTP Proxy: 127.0.0.1:8888
HTTPS Proxy: 127.0.0.1:8888
```

### System-wide (Linux)
```bash
export http_proxy=http://127.0.0.1:8888
export https_proxy=http://127.0.0.1:8888
```

### curl
```bash
curl -x http://127.0.0.1:8888 https://example.com
```

## Domain List Format

```
# Exact match
example.com

# Wildcard (matches all subdomains)
*.subdomain.com

# Comments supported
# blocked-site.net
```

## use binary
###INFO ✓ Loaded 938471 domains from binary blacklist in 0.32s
```bash
2025-09-24T07:39:45.119449Z  INFO Starting TLS Fragment Proxy v1.0.4
2025-09-24T07:39:45.119612Z  INFO Loading binary blacklist from: /home/ubuntu/git/dip/blacklist.bin
2025-09-24T07:39:45.437229Z  INFO ✓ Loaded 938471 domains from binary blacklist in 0.32s
2025-09-24T07:39:45.438353Z  INFO Loading binary whitelist from: /home/ubuntu/git/dip/whitelist.bin
2025-09-24T07:39:45.438570Z  INFO ✓ Loaded 89 domains from binary whitelist in 0.00s
```
## Architecture

```
Client → Proxy → [Domain Filter] → [TLS Fragmenter] → Remote Server
                        ↓
                 [Cache | Bloom | Radix Tree | Aho-Corasick]
```

### Domain Filter Tiers
1. **LRU Cache** - Recent lookups (microseconds)
2. **Bloom Filter** - Fast negative checks (nanoseconds)
3. **Radix Tree** - Exact domain matches (microseconds)
4. **Aho-Corasick** - Wildcard patterns (microseconds)

## Example

```bash
[ubuntu@rust01]$ ./target/release/tls-fragment-proxy --port 8888 --host 0.0.0.0 --verbose --blacklist-binary /home/ubuntu/git/dip/blacklist.bin --whitelist-binary /home/ubuntu/git/dip/whitelist.bin --worker-threads 2
2025-09-24T07:39:45.119449Z  INFO Starting TLS Fragment Proxy v1.0.4
2025-09-24T07:39:45.119612Z  INFO Loading binary blacklist from: /home/ubuntu/git/dip/blacklist.bin
2025-09-24T07:39:45.437229Z  INFO ✓ Loaded 938471 domains from binary blacklist in 0.32s
2025-09-24T07:39:45.438353Z  INFO Loading binary whitelist from: /home/ubuntu/git/dip/whitelist.bin
2025-09-24T07:39:45.438570Z  INFO ✓ Loaded 89 domains from binary whitelist in 0.00s

╔══════════════════════════════════════════════════════╗
║       TLS Fragment Proxy v1.0.4                      ║
╚══════════════════════════════════════════════════════╝

[CONFIG]
  ├─ Address: 0.0.0.0:8888
  ├─ Fragment Mode: Smart SNI Detection
  ├─ Max Connections: 1000
  ├─ Rate Limit: 1000/sec per IP
  ├─ Worker Threads: 2
  ├─ Buffer Pool Size: 100
  ├─ LRU Cache Size: 10000
  ├─ Blacklist: 938471 domains loaded
  ├─ Whitelist: 89 domains loaded
  ├─ Health Check: http://127.0.0.1:8882/health
  └─ Started: 2025-09-24 10:39:45

[INFO] Press Ctrl+C to stop the proxy

2025-09-24T07:39:45.438923Z  INFO Proxy listening on 0.0.0.0:8888
2025-09-24T07:39:45.439047Z  INFO Health check endpoint listening on 127.0.0.1:8882
2025-09-24T07:39:45.439969Z  INFO Stats: Active=0, Total=0, Fragmented=0, WL=0, BL-Blocks=0, Failed=0, Disconnects=0, Traffic: In=0 B, Out=0 B, Lists: BL=938471, WL=89, Cache: 0.0% hit rate, Bloom FPs=0
^C2025-09-24T07:39:46.364009Z  INFO Shutdown signal received
2025-09-24T07:39:46.364090Z  INFO Initiating graceful shutdown...

╔══════════════════════════════════════════════════════╗
║                 FINAL STATISTICS                    ║
╚══════════════════════════════════════════════════════╝

  Total Connections:      0
  Fragmented Connections: 0
  Whitelisted Connections: 0
  Blacklisted Blocks:     0
  Failed Connections:     0
  Client Disconnects:     0
  Rate Limited:           0
  Total Downloaded:       0 B
  Total Uploaded:         0 B
  Blacklist Domains:      938471
  Whitelist Domains:      89
  Cache Hits:             0
  Cache Misses:           0
  Bloom False Positives:  0

[SUCCESS] Proxy shut down gracefully

```
```bash
[ubuntu@rust]$ watch -n 1 'curl -s http://127.0.0.1:8882/health | jq .'
{
  "status": "healthy",
  "active": 2,
  "total": 5,
  "fragmented": 5,
  "traffic_in": 19344,
  "traffic_out": 2061,
  "client_disconnects": 0,
  "blacklisted_blocks": 0,
  "whitelisted_connections": 0,
  "cache_hits": 4,
  "cache_misses": 6,
  "bloom_false_positives": 0
}
```
## Performance
- Handles 10K+ concurrent connections
- Sub-millisecond domain filtering with millions of entries
- Zero-copy buffer operations where possible
- Memory-mapped files for lists >100MB
- ~5-10% overhead vs direct connection


## Troubleshooting

### High Memory Usage
- Preprocess large domain lists: `--preprocess-lists`
- Reduce cache size: `--cache-size 1000`
- Use binary format for domain lists

### Connection Refused
- Check if port is already in use: `lsof -i:8888`
- Verify bind address: `--host 0.0.0.0`

### Slow Performance
- Increase worker threads: `--worker-threads 8`
- Increase buffer pool: `--buffer-pool-size 200`
- Use binary domain lists instead of text

## Docker

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/tls-fragment-proxy /usr/local/bin/
EXPOSE 8888
CMD ["tls-fragment-proxy"]
```

```bash
docker build -t tls-fragment-proxy .
docker run -p 8888:8888 tls-fragment-proxy
```

## License

MIT