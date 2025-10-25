# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

### Development
```bash
# Run in development mode (uses run_dev.sh with default config)
./run_dev.sh

# Manual run with environment variables
export IP_ADDR="127.0.0.1:3000"
export DATA_DIR="db"
export DOMAIN="http://localhost:3000"
export PRESIGN_API_KEY="secret-api-key"
cargo run

# Run with config file
cargo run -- --config examples/config.toml
```

### Building & Testing
```bash
# Build release version
cargo build --release

# Run tests
cargo test

# Run with coverage (if cargo-tarpaulin is available)
cargo tarpaulin

# Check formatting
cargo fmt --check

# Lint code
cargo clippy -- -D warnings
```

### Nix Development (if available)
```bash
# Enter development shell
nix develop
# OR (legacy)
nix-shell

# Build with nix
nix build .#borderless-storage

# Build docker image
nix build .#docker
```

## Architecture Overview

This is a minimal S3-style object storage server written in Rust using Axum/Tokio. The system follows a pre-signed URL pattern for secure uploads and downloads.

### Core Components

**main.rs** - Entry point with signal handling, cleanup task coordination, and configuration initialization.

**server.rs** - HTTP server implementation with middleware layers:
- Request ID generation and tracing
- CORS handling  
- Authentication (API key for presign, HMAC for pre-signed URLs)
- Request size limits and timeouts
- Upload/download handlers with chunked upload support

**storage.rs** - Filesystem controller (`FsController`) managing:
- File storage in `<DATA_DIR>/full/` (final blobs)
- Chunk storage in `<DATA_DIR>/chunks/<uuid>/` (multi-part uploads)
- Atomic writes using `.tmp` files
- Orphan cleanup of abandoned uploads
- Integration with metadata store for blob information

**metadata.rs** - SQLite-based metadata store managing:
- Content-Type and Content-Disposition headers for proper browser downloads
- File size and SHA-256 hash tracking
- Timestamp tracking for creation and updates
- ACID-compliant storage with WAL mode
- Metadata cleanup for orphaned blobs

**config.rs** - Configuration handling with precedence: config file → CLI args → environment variables

**utils.rs** - Utilities including:
- Pre-signed URL generation/verification (HMAC-SHA256)
- Directory access validation
- Format helpers for bytes and time

### Data Flow

1. **Upload**: Client requests pre-signed upload URL via `/presign` (requires API key)
2. **Storage**: Client uploads to pre-signed URL with optional Content-Type/Content-Disposition headers, data stored atomically via `.tmp` → rename
3. **Metadata**: Headers are extracted, SHA-256 hash calculated, and all metadata stored in SQLite database
4. **Download**: Client requests pre-signed download URL, then downloads via pre-signed URL with original headers restored
5. **Chunked Uploads**: Multi-part uploads stored in chunks directory, metadata saved during merge operation
6. **Cleanup**: Background task removes orphaned `.tmp` files, stale chunk directories, and orphaned metadata entries

### Security Model

- API key authentication for presign endpoints (constant-time comparison)
- HMAC-SHA256 signatures for pre-signed URLs with expiry validation
- Constant-time signature verification to prevent timing attacks
- Request size limits and timeouts for DoS protection

### Storage Layout

```
<DATA_DIR>/
├── full/                    # Final blob storage
│   ├── <uuid>              # Complete blobs
│   └── <uuid>.tmp          # Temporary upload files
├── chunks/                  # Chunked upload staging
│   └── <uuid>/             # Per-blob chunk directory
│       └── chunk_1_3       # Individual chunks (idx_total format)
└── metadata.db             # SQLite database for blob metadata
```

## Configuration

Configuration sources (in order of precedence):
1. `--config <file>` (TOML format)
2. CLI flags (when all required flags present)  
3. Environment variables

Required settings:
- `ip_addr` / `IP_ADDR`: Socket address to bind
- `data_dir` / `DATA_DIR`: Data directory path (must exist and be writable)
- `domain` / `DOMAIN`: Full domain for pre-signed URLs
- `presign_api_key` / `PRESIGN_API_KEY`: API key for presign endpoints

Optional settings include request size limits, timeouts, CORS origins, cleanup intervals, and metadata database path. See `examples/config.toml` for full configuration options.

### Metadata Headers

The server now supports proper browser downloads by storing and retrieving metadata headers:

- **Content-Type**: Set during upload via standard HTTP Content-Type header (e.g., `image/png`, `application/pdf`)
- **Content-Disposition**: Set during upload via standard HTTP Content-Disposition header (e.g., `attachment; filename="document.pdf"`, `inline`)
- **SHA-256 Hash**: Automatically calculated during upload for both single and chunked uploads
- **Backward Compatibility**: Blobs without metadata use default `Content-Type: application/octet-stream`
- **Database Location**: Metadata stored in SQLite database at `<DATA_DIR>/metadata.db` by default

## Testing

The project includes comprehensive tests:
- Unit tests in each module covering core functionality
- Integration tests in `server.rs` testing full HTTP request/response cycles
- Error handling and edge case validation
- Round-trip testing of pre-signed URL generation and validation

Run tests with `cargo test`. Some storage tests use temporary directories and may require filesystem access.