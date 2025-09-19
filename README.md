# Borderless-Storage — Minimal S3-style Object Store

A tiny, production-ready object storage server written in Rust. It exposes an S3-like model (objects identified by UUIDs, pre-signed uploads/downloads), 
persists data on the local filesystem, and includes an automatic janitor for cleaning up failed uploads.

> ️**Platform:** Uses Unix signal handling via `tokio::signal::unix`, so it currently targets Linux/macOS and other Unix-like systems.

---

## ✨ Features

* **Pre-signed URL flow** using HMAC-SHA256 (signature and expiry check, constant-time compare)
* **Clean API** all errors and responses are uniformly json, data upload and download uses http-streams for performance
* **Chunked uploads** with server-side merge and crash‑safe temp files
* **Automatic cleanup** of orphaned `.tmp` files and stale chunk directories
* **Configurable limits** (request size caps, request timeout, TTL for orphans)
* **Graceful shutdown** on `SIGINT`/`SIGTERM`
* **Structured logging** with latency measurement and request-ids

---

## 🚀 Quickstart

You can use the `run_dev.sh` to run the service locally in develop mode. See section [building](#manual-build), deploying and [configuration](#required-settings) for more advanced options.

The actions are similar to s3, so before you can upload or download anything, you have to generate a presigned url via the `/presign` endpoint.
Assuming you have your server locally available, it would look something like this:

```bash
curl 127.0.0.1:3000/presign \
    -H "authorization: Bearer secret-api-key" \
    -H "content-type: application/json" \
    -d '{ "action": "upload" }'
```

This will produce a response like this:

``` json
{
  "success": true,
  "action": "upload",
  "blob_id": "01996168-e738-7552-9662-2041482b96c3",
  "url": "http://localhost:3000/upload/01996168-e738-7552-9662-2041482b96c3?expires=1758276788&sig=BDtmjKQ2iImF5emvbyqPdivEojq60UI6gYuKDRQBSO4=",
  "method": "POST",
  "expires_in": 900
}
```

You can now use the pre-signed url to upload your data (which will be stored under the given `blob_id`):


```bash
curl -X POST "http://localhost:3000/upload/01996168-e738-7552-9662-2041482b96c3?expires=1758276788&sig=BDtmjKQ2iImF5emvbyqPdivEojq60UI6gYuKDRQBSO4=" \
    --data-binary @My_Fancy_File.pdf
```

Note: The data is not encoded via JSON or anything, instead the raw data is streamed over to the storage server in the body.
Internally, we use the http stream to directly write the blob to disk, without copying the entire content of the file into RAM.
This process is very efficient and allows for quick and fast uploads, even with large files.

The response of an upload returns the number of bytes written and blob-id:

``` json
{
  "success": true,
  "message": "uploaded blob",
  "blob_id": "01996168-e738-7552-9662-2041482b96c3",
  "bytes_written": 714300
}
```

To retrive the data, you have to presign a download url, and then you can download the file:

```bash
curl 127.0.0.1:3000/presign \
    -H "authorization: Bearer secret-api-key" \
    -H "content-type: application/json" \
    -d '{ "action": "download", "blob_id": "01996168-e738-7552-9662-2041482b96c3" }'
    
# The response looks identical to the upload response - the most important path is the presigned url, which you need to download:
curl "http://localhost:3000/files/01996168-e738-7552-9662-2041482b96c3?expires=1758277521&sig=QjRyPQUAQ9QwtKGiKg_4oUwK3QiuL3_X13UXiKs86W8=" -o My_Fancy_File.pdf
```

### Chunked upload

If you want to upload very large files, or upload from a very unstable connection (like a mobile device) you can use the chunked upload.
This effectively allows you to upload your file piece by piece, while the server merges all chunks into a single file when you are done.

This is done via the same upload endpoint, but using special request headers to indicate the upload type and chunk-index:

``` shell
curl -X POST "http://localhost:3000/upload/01996168-e738-7552-9662-2041482b96c3?expires=1758276788&sig=BDtmjKQ2iImF5emvbyqPdivEojq60UI6gYuKDRQBSO4=" \
    -H "X-Upload-Type: chunked" \ 
    -H "X-Chunk-Index: 1" \ 
    -H "X-Chunk-Total: 3" \ 
    --data-binary @File-Chunk_1_3
```

After all chunks are uploaded, a last request advises the server to perform the merge:

``` shell
curl -X POST "http://localhost:3000/upload/01996168-e738-7552-9662-2041482b96c3?expires=1758276788&sig=BDtmjKQ2iImF5emvbyqPdivEojq60UI6gYuKDRQBSO4=" \
    -H "X-Upload-Type: chunked" \ 
    -H "X-Chunk-Merge: true" \ 
    -H "X-Chunk-Total: 3"
```

You can then download the file like normal.

## 🏗 Build & Deploy

You have several options of how do build and deploy this project. We use [nix](https://nixos.org/) as our build system.

To get a development shell with all required dependencies:
``` shell
nix-shell
# or (if you have flakes enabled)
nix develop
```

To build the application natively with nix ( requires flakes )
``` shell
nix build .#borderless-storage
```

### Docker

You can also build a minimal docker image based on nix ( requires flakes to be enabled ):

``` shell
nix build .#docker
# This creates a ./result symlink, which you can use to load the image into docker
docker load < result
```

The service is exposed under port 8080 inside the docker container. 
You can execute it via docker like this:

``` shell
docker run --rm -p 8080:8080 \
    -e DOMAIN="http://localhost:8080" \
    -e PRESIGN_API_KEY="secret-api-key" \
    -e PRESIGN_HMAC_SECRET="your-very-long-and-secret-hmac-secret"  \
    -v "$PWD/data:/data" \
    borderless/borderless-storage:0.1.0
```

Note: You don't have to specify `IP_ADDR` and `DATA_DIR`, as they are fixed inside the container.

### Manual build

You can build this project manually like any rust project.

#### Prerequisites

* Rust 1.75+ (stable) and Cargo
* A Unix-like OS (Linux/macOS)
* A writable data directory (e.g. `/var/lib/storage`)

#### Build & run

```bash
# 1) Build
cargo build --release

# 2) Prepare data dir
sudo mkdir -p /var/lib/storage
sudo chown "$USER" /var/lib/storage

# 3) Run (choose one of the config methods)
./target/release/borderless-storage --ip-addr 0.0.0.0:8080 --data-dir /var/lib/storage --domain https://storage.example.com
```

## ⚙️ Configuration

You can configure borderless-storage via **(1) config file**, **(2) CLI flags**, or **(3) environment variables**. The precedence is:

1. `--config <file>` (TOML)
2. CLI flags (when *all* required are present)
3. Environment variables

### Required settings

* **IP address** and port to bind: e.g. `0.0.0.0:8080`
* **Data directory**: existing, writable path
* **Domain**: full origin used to mint pre-signed URLs (e.g. `https://storage.example.com`)

### Configuration keys & defaults

| Key                   | Env var               | Default                | Notes                              |
| --------------------- | --------------------- | ---------------------- | ---------------------------------- |
| `ip_addr`             | `IP_ADDR`             | — (required)           | Must parse as socket address       |
| `data_dir`            | `DATA_DIR`            | — (required)           | Directory must exist & be writable |
| `domain`              | `DOMAIN`              | — (required)           | Parsed as `http::Uri`              |
| `presign_api_key`     | `PRESIGN_API_KEY`     | — (required)           | Use a secure API-Key in production |
| `presign_hmac_secret` | `PRESIGN_HMAC_SECRET` | generate random secret | Use a secure secret in production  |
| `ttl_orphan_secs`     | `TTL_ORPHAN_SECS`     | `43200` (12h)          | Orphan TTL for temp files/chunks   |
| `max_data_rq_size`    | `MAX_DATA_RQ_SIZE`    | `4 * 1024^3` (4 GiB)   | Hard cap for data API requests     |
| `max_presign_rq_size` | `MAX_PRESIGN_RQ_SIZE` | `100 * 1024` (100 KiB) | Hard cap for pre‑sign endpoints    |
| `rq_timeout_secs`     | `RQ_TIMEOUT_SECS`     | `30` seconds           | Per‑request timeout                |

> The server validates the data directory is writable by creating and removing a small probe file.

See [configuration examples](examples/configuration.md) for more information.

### Logging

* Default log level: `INFO`
* Use `--verbose` for `DEBUG` level with extra details during cleanup and chunk checks


## 🔎 Implementation Notes

* **Constant‑time compare** for signatures via `subtle::ConstantTimeEq` to mitigate timing attacks
* **Atomic writes**: single‑part uploads write to `*.tmp`, then `rename` to the final path
* **Chunk verification**: `check_chunks` ensures all `chunk_{i}_{total}` exist before merge
* **Filesystem sanity**: data directory probed for writability on startup

---

## 🔐 Security Considerations

* Keep your HMAC secret **out of source control** and rotate when appropriate
* Set tight `rq_timeout_secs` and request size caps (`max_*`) to protect resources
* Serve over HTTPS in production; set `domain` to an HTTPS origin
* Consider placing this service behind an authenticating proxy and rate limiter

---

## 📈 Performance Tips

* Put the data directory on fast storage (NVMe)
* Tune the janitor TTL and cadence for your workload
* Consider mounting the data directory on a network filesystem only if it provides strong POSIX semantics

---

## 🤝 Contributing

Issues and PRs are welcome! Please open an Issue if you encounter a bug, or if you have an idea, how we could make the borderless-storage even better.

---

## 📜 License

The project is published under MIT or Apache License.

---

## 🙌 Acknowledgements

Thanks to the Rust and Tokio communities for fantastic tooling and libraries.

The project is mainly built on top of `axum` and `tower`, which are fantastic project for building high-performance web applications.

---

> If you build something cool with borderless-storage, let us know via an issue. ✨
