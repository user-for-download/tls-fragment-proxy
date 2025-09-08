# 🔒 TLS Fragment Proxy

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/user-for-download/tls-fragment-proxy/releases)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com/user-for-download/tls-fragment-proxy)

A lightweight, high-performance HTTP/HTTPS proxy that uses TLS fragmentation to bypass DPI (Deep Packet Inspection) systems. Built with Rust and Tokio for maximum efficiency and reliability.

## 🎯 Key Features

- **TLS Fragmentation** - Splits TLS handshakes at SNI boundary to evade DPI
- **Smart Detection** - Automatically detects and fragments at optimal positions
- **High Performance** - Async I/O with Tokio, handles thousands of concurrent connections
- **Domain Filtering** - Blacklist/whitelist support with wildcard patterns
- **Rate Limiting** - Per-IP rate limiting to prevent abuse
- **Real-time Monitoring** - Health check endpoint with JSON metrics
- **Zero Configuration** - Works out of the box with sensible defaults

## 🚀 Quick Start

### Installation

```bash
# Clone and build
git clone https://github.com/user-for-download/tls-fragment-proxy.git
cd tls-fragment-proxy
cargo build --release

# Or install directly
cargo install --git https://github.com/user-for-download/tls-fragment-proxy.git
```

### Basic Usage

```bash
# Start the proxy (listens on 127.0.0.1:8881 by default)
./target/release/tls-fragment-proxy

# Configure your system to use the proxy
export http_proxy=http://127.0.0.1:8881
export https_proxy=http://127.0.0.1:8881

# Test it
curl https://www.google.com
```

### Docker

```bash
# Or build locally
docker build -t tls-fragment-proxy .
docker run -d -p 8881:8881 -p 8882:8882 tls-fragment-proxy
```

## 📋 Configuration

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `8881` | Proxy port |
| `--max-connections` | `1000` | Maximum concurrent connections |
| `--rate-limit-per-second` | `1000` | Requests per second per IP |
| `--blacklist` | `blacklist.txt` | Path to blacklist file |
| `--whitelist` | - | Path to whitelist file (optional) |
| `--verbose` | `false` | Enable debug logging |
| `--quiet` | `false` | Suppress output |

### Example with Options

```bash
./tls-fragment-proxy \
  --host 0.0.0.0 \
  --port 8080 \
  --max-connections 5000 \
  --blacklist ./my-blacklist.txt \
  --whitelist ./my-whitelist.txt \
  --verbose
```

## 🔧 How It Works

The proxy uses a proven fragmentation technique that:

1. **Intercepts HTTPS connections** via HTTP CONNECT tunneling
2. **Analyzes TLS ClientHello** packets to find the SNI extension
3. **Fragments at the SNI boundary** - splits right after the domain name
4. **Falls back to random fragmentation** when SNI detection fails
5. **Reassembles transparently** at the destination

This approach is effective because many DPI systems:
- Only inspect the first few packets
- Have limited buffer space for reassembly
- Fail to handle fragmented SNI fields correctly

## 🌐 Client Configuration

### Browser Setup

**Firefox:**
1. Settings → Network Settings → Settings
2. Manual proxy configuration
3. HTTP Proxy: `127.0.0.1` Port: `8881`
4. Check "Also use this proxy for HTTPS"

**Chrome/Chromium:**
```bash
google-chrome --proxy-server="http://127.0.0.1:8881"
```

### System-wide (Linux/macOS)

```bash
# Add to ~/.bashrc or ~/.zshrc
export http_proxy=http://127.0.0.1:8881
export https_proxy=http://127.0.0.1:8881
export HTTP_PROXY=http://127.0.0.1:8881
export HTTPS_PROXY=http://127.0.0.1:8881
```

### System-wide (Windows)

```powershell
# PowerShell (temporary)
$env:HTTP_PROXY="http://127.0.0.1:8881"
$env:HTTPS_PROXY="http://127.0.0.1:8881"

# Or use system settings
netsh winhttp set proxy 127.0.0.1:8881
```

## 📊 Monitoring

### Health Check

```bash
# Check if proxy is healthy
curl http://127.0.0.1:8882/health
```

Response:
```json
{
  "status": "healthy",
  "active": 42,
  "total": 1337,
  "fragmented": 1250,
  "traffic_in": 104857600,
  "traffic_out": 524288000
}
```

### Real-time Statistics

The proxy displays statistics on shutdown:

```
╔══════════════════════════════════════════════════════╗
║                 FINAL STATISTICS                      ║
╚══════════════════════════════════════════════════════╝

  Total Connections:      1523
  Fragmented Connections: 1456
  Whitelisted Connections: 67
  Failed Connections:     12
  Rate Limited:           0
  Total Downloaded:       1.2 GB
  Total Uploaded:         245 MB
```

## 🔒 Domain Filtering

### Blacklist Format

Create `blacklist.txt`:
```
# Block specific domains
ads.example.com
tracking.site.com

# Block with wildcards
*.doubleclick.net
*.facebook.com
```

### Whitelist Format

Create `whitelist.txt`:
```
# Bypass fragmentation for trusted sites
*.mycompany.com
*.local
api.trusted-service.com
```

## 🐳 Docker Deployment

### Dockerfile

```dockerfile
FROM rust:1.70-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/tls-fragment-proxy /usr/local/bin/
EXPOSE 8881 8882
ENTRYPOINT ["tls-fragment-proxy"]
CMD ["--host", "0.0.0.0"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  tls-proxy:
    build: .
    container_name: tls-fragment-proxy
    ports:
      - "8881:8881"  # Proxy port
      - "8882:8882"  # Health check port
    volumes:
      - ./blacklist.txt:/blacklist.txt:ro
      - ./whitelist.txt:/whitelist.txt:ro
    command:
      - --host=0.0.0.0
      - --blacklist=/blacklist.txt
      - --whitelist=/whitelist.txt
      - --max-connections=5000
    restart: unless-stopped
```

## 🔧 Systemd Service

Create `/etc/systemd/system/tls-fragment-proxy.service`:

```ini
[Unit]
Description=TLS Fragment Proxy
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/tls-fragment-proxy --host 0.0.0.0
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable tls-fragment-proxy
sudo systemctl start tls-fragment-proxy
```

## 🧪 Testing

### Basic Connectivity Test

```bash
# Test HTTP
curl -x http://127.0.0.1:8881 http://httpbin.org/ip

# Test HTTPS
curl -x http://127.0.0.1:8881 https://httpbin.org/ip

# Verbose test
curl -v -x http://127.0.0.1:8881 https://www.google.com
```

### Performance Test

```bash
# Using Apache Bench
ab -n 1000 -c 100 -X 127.0.0.1:8881 https://example.com/

# Using wrk
wrk -t12 -c400 -d30s --latency http://127.0.0.1:8881
```

## 🛠️ Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| "Address already in use" | Another service is using port 8881. Change with `--port` |
| "Too many open files" | Increase ulimit: `ulimit -n 65535` |
| Sites not loading | Check if domain is blacklisted, try adding to whitelist |
| High CPU usage | Reduce `--max-connections` |
| Connection refused | Check firewall settings, ensure proxy is running |

### Debug Mode

```bash
# Enable verbose logging
./tls-fragment-proxy --verbose

# Check logs
journalctl -f | grep tls-fragment

# Monitor connections
ss -tnp | grep 8881
```


## 🏗️ Building from Source

### Requirements

- Rust 1.70+ (via [rustup](https://rustup.rs/))
- Git

### Build Steps

```bash
# Clone repository
git clone https://github.com/user-for-download/tls-fragment-proxy.git
cd tls-fragment-proxy

# Build debug version
cargo build

# Build optimized release version
cargo build --release

# Run tests
cargo test

# Install locally
cargo install --path .
```

## 📚 Technical Details

### Dependencies

- **tokio** - Async runtime
- **clap** - Command line parsing
- **dashmap** - Concurrent hashmap
- **tracing** - Structured logging
- **anyhow** - Error handling
- **thiserror** - Custom error types

### Architecture

The proxy uses a multi-threaded async architecture:
- Main thread handles incoming connections
- Tokio runtime spawns tasks for each connection
- Shared state protected by Arc/Mutex
- Lock-free data structures where possible

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
