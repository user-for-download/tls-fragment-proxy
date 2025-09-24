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
cargo build --release

# Or with optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Installation

```bash
# Install from source
cargo install --path .

# Or download binary
wget https://github.com/user/tls-fragment-proxy/releases/latest/download/tls-fragment-proxy
chmod +x tls-fragment-proxy
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
[ubuntu@rust]$ ./target/release/tls-fragment-proxy --port 8888 --host 0.0.0.0 --verbose --blacklist blacklist.txt --whitelist whitelist.txt --worker-threads 8 --buffer-pool-size 400
2025-09-24T06:52:59.871020Z  INFO Starting TLS Fragment Proxy v1.0.4
2025-09-24T06:52:59.871176Z  INFO Loading text blacklist from: /home/ubuntu/git/dip/blacklist.txt
2025-09-24T06:53:00.609835Z  INFO ✓ Loaded 93850 domains (93850 exact, 0 wildcard) from blacklist in 0.74s
2025-09-24T06:53:00.628875Z  INFO Loading text whitelist from: /home/ubuntu/git/dip/whitelist.txt
2025-09-24T06:53:00.633410Z  INFO ✓ Loaded 89 domains (39 exact, 50 wildcard) from whitelist in 0.00s

╔══════════════════════════════════════════════════════╗
║       TLS Fragment Proxy v1.0.4                      ║
╚══════════════════════════════════════════════════════╝

[CONFIG]
  ├─ Address: 0.0.0.0:8888
  ├─ Fragment Mode: Smart SNI Detection
  ├─ Max Connections: 1000
  ├─ Rate Limit: 1000/sec per IP
  ├─ Worker Threads: 8
  ├─ Buffer Pool Size: 400
  ├─ LRU Cache Size: 10000
  ├─ Blacklist: 93850 domains loaded
  ├─ Whitelist: 89 domains loaded
  ├─ Health Check: http://127.0.0.1:8882/health
  └─ Started: 2025-09-24 09:53:00

[INFO] Press Ctrl+C to stop the proxy

2025-09-24T06:53:00.634321Z  INFO Proxy listening on 0.0.0.0:8888
2025-09-24T06:53:00.634448Z  INFO Health check endpoint listening on 127.0.0.1:8882
2025-09-24T06:53:00.635840Z  INFO Stats: Active=0, Total=0, Fragmented=0, WL=0, BL-Blocks=0, Failed=0, Disconnects=0, Traffic: In=0 B, Out=0 B, Lists: BL=93850, WL=89, Cache: 0.0% hit rate, Bloom FPs=0
^C2025-09-24T06:53:01.804164Z  INFO Shutdown signal received
2025-09-24T06:53:01.804198Z  INFO Initiating graceful shutdown...

╔══════════════════════════════════════════════════════╗
║                 FINAL STATISTICS                     ║
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
  Blacklist Domains:      93850
  Whitelist Domains:      89
  Cache Hits:             0
  Cache Misses:           0
  Bloom False Positives:  0

[SUCCESS] Proxy shut down gracefully

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