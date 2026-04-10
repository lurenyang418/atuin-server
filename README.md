# Atuin Server

A high-performance Atuin sync server implementation using Salvo web framework with SQLite backend.

## Features

- **Salvo Web Framework** - Modern, fast Rust web framework
- **SQLite Backend** - Lightweight, embedded database
- **Official Database Layer** - Reuses `atuin-server-sqlite` for migrations and operations
- **Multi-platform** - Supports Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64)
- **Docker Ready** - Multi-platform Docker images via GitHub Actions
- **Prometheus Metrics** - Built-in `/metrics` endpoint
- **Graceful Shutdown** - Handles SIGTERM/SIGINT properly
- **Webhook Support** - Notify external services on user registration
- **Client Compatibility** - Full compatibility with official Atuin client

## Quick Start

### Binary

```bash
# Build
cargo build --release

# Run
./target/release/atuin-server start

# Or with config
./target/release/atuin-server start --port 8888

# Print default configuration
./target/release/atuin-server default-config
```

### Docker

Images are pushed to both GitHub Container Registry and Docker Hub.

```bash
# GitHub Container Registry
docker pull ghcr.io/lurenyang418/atuin-server:latest

# Docker Hub
docker pull lurenyang/atuin-server:latest

# Run with persistent data
docker run -p 8888:8888 \
  -v /path/to/data:/app \
  ghcr.io/lurenyang418/atuin-server:latest
```

## Configuration

Configuration file location (in order of priority):
1. `ATUIN_CONFIG_DIR/server.toml` environment variable (default: `/app`)
2. `./atuin.toml` (current directory)

```toml
# host to bind, can also be passed via CLI args
host = "0.0.0.0"

# port to bind, can also be passed via CLI args
port = 8888

# whether to allow anyone to register an account
open_registration = true

# sqlite
db_uri = "sqlite:///var/lib/atuin/atuin.db"

# Maximum size for one history entry
max_history_length = 8192

# Maximum size for one record entry
max_record_size = 1073741824

# Default page size for requests
page_size = 1100

# Enable legacy sync v1 routes
sync_v1_enabled = true

# Optional: webhook for new user registration
# register_webhook_url = "https://your-webhook.com/webhook"
# register_webhook_username = "bot"
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `host` | `"0.0.0.0"` | Bind address |
| `port` | `8888` | Bind port |
| `open_registration` | `true` | Allow public registration |
| `max_history_length` | `8192` | Max history entries per command |
| `max_record_size` | `1073741824` | Max record size (bytes) |
| `page_size` | `1100` | Sync page size |
| `sync_v1_enabled` | `true` | Enable legacy sync API |
| `db_uri` | `sqlite:///var/lib/atuin/atuin.db` | Database URI |
| `register_webhook_url` | - | Webhook URL for new registrations |
| `register_webhook_username` | - | Webhook username |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Server info |
| `/healthz` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/register` | POST | User registration |
| `/login` | POST | User login |
| `/user/<username>` | GET | Get user info |
| `/account` | DELETE | Delete account |
| `/account/password` | PATCH | Change password |
| `/sync/count` | GET | History count (cached) |
| `/sync/history` | GET | List history |
| `/sync/status` | GET | Sync status |
| `/sync/calendar/<focus>` | GET | Calendar statistics |
| `/history` | POST | Add history |
| `/history` | DELETE | Delete history |
| `/record` | POST | Add record |
| `/record` | GET | List records |
| `/record/next` | GET | Get next record |
| `/api/v0/me` | GET | Current user info |
| `/api/v0/record` | POST | Add v0 record |
| `/api/v0/record` | GET | List v0 records |
| `/api/v0/record/next` | GET | Get next v0 records |
| `/api/v0/store` | DELETE | Delete v0 store |

### Response Headers

All responses include:
- `X-Clacks-Overhead: GNU Terry Pratchett, Kris Nova`
- `Atuin-Version: <version>`

## Building

### Prerequisites

- Rust 1.94+
- musl-tools (for static musl binary)
- SQLite development libraries

### Local Build

```bash
# Build native binary
cargo build --release

# Build musl static binary (for Docker/Alpine)
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

### Docker Build

Docker image is built via GitHub Actions on push to main/tag. For local multi-platform build:

```bash
# Create builder
docker buildx create --name atuin-builder --use

# Build locally
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg RUST_TARGET=x86_64-unknown-linux-musl \
  -t atuin-server:latest --load .
```

## License

MIT
