# 🛡️ TLS Fragment Proxy

**Version:** `1.1.0`

`tls-fragment-proxy` is a high-performance, multi-threaded HTTP/HTTPS proxy with support for **TLS handshake fragmentation**, **domain blacklisting/whitelisting**, and **wildcard filtering** optimized through Bloom filters, radix trees, and Aho-Corasick pattern matching.

---

## 🚀 Features

- ✅ Supports both HTTP and HTTPS proxying (CONNECT tunnel).
- 🚫 Powerful **blacklist** and **whitelist** system:
    - Exact domain matches via radix trees.
    - `*.wildcard.domain` support via Aho-Corasick.
    - Fast Bloom filter for negative lookup optimization.
    - Caching via high-performance concurrent LRU cache (`moka`).
- 🔐 TLS Fragments:
    - Automatically fragments TLS ClientHello for privacy/obfuscation.
    - Whitelisted domains are exempt from fragmentation.
- ⚡ Ultra-fast I/O:
    - Built on `tokio`, the async runtime.
    - Custom I/O pipe buffer handling to maximize throughput.
- 📊 Real-time statistics + `/health` endpoint.
- 🛠️ Preprocessing utility to precompile large domain lists into a fast load binary format.

---

## 🧰 Configuration

Set options at runtime using CLI flags.

```bash
tls-fragment-proxy --port 8888 \
  --blacklist domains.txt \
  --whitelist trusted.txt \
  --max-connections 2048 \
  --worker-threads 8 \
  --cache-size 10000
```

### CLI Options

| Option                    | Description                          | Default         |
|--------------------------|--------------------------------------|-----------------|
| `--host`                 | Listen address                       | `0.0.0.0`       |
| `--port`                 | Listening port                       | `8888`          |
| `--blacklist`            | Path to blacklist file (text)       |                 |
| `--whitelist`            | Path to whitelist file (text)       |                 |
| `--blacklist-binary`     | Precompiled blacklist .bin file     |                 |
| `--whitelist-binary`     | Precompiled whitelist .bin file     |                 |
| `--max-connections`      | Max concurrent client connections   | `1000`          |
| `--quiet`                | Suppress output                     | off             |
| `--verbose`              | Enable debug logging                | off             |
| `--worker-threads`       | Number of worker threads (tokio)    | `4`             |
| `--cache-size`           | Concurrent LRU cache size           | `10000`         |
| `--preprocess-lists`     | Compile lists into binary           | off             |

---

## 🔂 Domain Preprocessing (Optional)

Once for large lists, you can compile them into a compact binary format for fastest startup:

```bash
# Compile text to binary
tls-fragment-proxy --preprocess-lists \
  --blacklist domains.txt \
  --whitelist trusted.txt
```

This creates `domains.bin` and `trusted.bin` that can be loaded with:

```bash
--blacklist-binary domains.bin --whitelist-binary trusted.bin
```

---

## 🩺 Health Check Endpoint

A built-in health endpoint is available at:

📍 `http://127.0.0.1:8882/health`

Returns a JSON payload:

```json
{
  "status": "healthy",
  "active": 4,
  "total": 109,
  "fragmented": 37,
  "traffic_in": 495017,
  "traffic_out": 993820,
  "client_disconnects": 8,
  "blacklisted_blocks": 14,
  "whitelisted_connections": 22,
  "cache_hits": 812,
  "cache_misses": 204,
  "bloom_false_positives": 11
}
```

---

## 📋 Example Output

```bash
[INFO] Proxy listening on 0.0.0.0:8888
✓ Loaded 50000 domains (47800 exact, 1200 wildcard) from blacklist in 1.17s
✓ Loaded 1200 domains (1120 exact, 80 wildcard) from whitelist in 0.20s

╔═════════════════════════════════════════════╗
║       TLS Fragment Proxy v1.1.0             ║
╚═════════════════════════════════════════════╝

[CONFIG]
  ├─ Address:           0.0.0.0:8888
  ├─ Max Connections:   1000
  ├─ Worker Threads:    4
  ├─ LRU/Cache Size:    10000
  ├─ Blacklist:         50000 domains loaded
  ├─ Whitelist:         1200 domains loaded
  ├─ Cache Hit Rate:    92.4%
  ├─ Bloom False Positives: 3
  ├─ Health Check:      http://127.0.0.1:8882/health
  └─ Started:           2025-10-01 20:22:33
```

---

## 👨‍🔧 Build & Run

### Prerequisites

- Rust 1.74+
- [Cargo](https://doc.rust-lang.org/cargo/)
- Linux, macOS or Windows

### Build

```bash
cargo clean
RUSTFLAGS='-C target-cpu=native' cargo build --release
strip target/release/tls-fragment-proxy
upx --best --lzma target/release/tls-fragment-proxy
# Check size
ls -lh target/release/tls-fragment-proxy
```

### Run

```bash
./target/release/tls-fragment-proxy --port 8888 --blacklist domains.txt
```

---

## 📦 Dependencies

- [`tokio`](https://docs.rs/tokio) - async runtime
- [`moka`](https://docs.rs/moka) - fast concurrent LRU cache
- [`bloomfilter`](https://docs.rs/bloomfilter) - probabilistic lookup
- [`aho_corasick`](https://docs.rs/aho-corasick) - wildcard matcher
- [`parking_lot`](https://docs.rs/parking_lot) - ultra-fast RwLock
- [`rayon`](https://docs.rs/rayon) - parallel list parsing
- [`clap`](https://docs.rs/clap/latest/clap/) - CLI parsing
- [`anyhow`](https://docs.rs/anyhow) - error context
- [`bincode`](https://docs.rs/bincode) - compact data serialization
- [`tracing`](https://docs.rs/tracing) - structured logging

---

## 🧪 Architecture Highlights

```
Client ↔ Proxy (TLS Fragmentation + Filtering) ↔ Remote Server
                    │
                    └── DomainFilter (4 tiers):
                        ├─ Bloom filter (fast skip)
                        ├─ LRU cache (moka)
                        ├─ Radix tree (prefix match)
                        └─ Aho-Corasick (wildcard match)
```

---

## 🔒 TLS Fragmentation (Why?)

Fragmentation bypasses DPI, censorship, or traffic shaping equipment by breaking the TLS ClientHello into smaller packets.

- Reduces protocol fingerprinting
- Increases resistance to SNI filtering

---

## 🏁 Graceful Shutdown

The proxy supports `Ctrl+C` handling to flush final statistics and allow in-flight connections to complete before terminating.

---

## 📃 License

**MIT**

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!

Please open an issue or PR on [GitHub](https://github.com/your-repo/tls-fragment-proxy).

---

## 📫 Contact

Built with ❤️ by Security & Performance enthusiasts.

---

Let me know if you'd like this exported as an actual `README.md` file or want a version tailored toward users (vs. developers).