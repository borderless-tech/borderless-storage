//! # Borderless-Storage
//!
//! Simple and easy to use storage solution to store binary blobs in an s3-like fashion.
//!
//! ## 🗺️ Architecture Overview
//!
//! ```text
//! +-------------------------------+         +---------------------------+
//! |          HTTP Server          |  ---->  |      FsController         |
//! |  (Axum/Tokio, pre-sign check) |         |  /data
//! |                               |         |   ├─ full/   (final objs) |
//! | - verifies pre-signed URLs    |         |   └─ chunks/ (per-UUID)   |
//! | - streams uploads/downloads   |         +---------------------------+
//! | - merges chunks when complete |
//! +-------------------------------+
//!               │
//!               ├── background task: cleans orphaned temp files & chunks
//!               │
//!               └── shutdown token: graceful stop on SIGINT/SIGTERM
//! ```
//!
//! ### Storage layout
//!
//! * `<DATA_DIR>/full/` — final, complete blobs; filename = `<uuid>`
//! * `<DATA_DIR>/full/<uuid>.tmp` — in‑progress single‑part upload temp file
//! * `<DATA_DIR>/chunks/<uuid>/chunk_{idx}_{total}` — chunked upload parts
//!
//! When all chunks are present, the server merges them into a single file under `full/` and deletes the `chunks/<uuid>/` directory.
//!
//! The janitor periodically deletes:
//!
//! * old `*.tmp` files in `full/` if `last_modified` > `TTL_ORPHAN_SECS`
//! * entire `chunks/<uuid>/` directories if **all** files inside are older than the TTL
//!
//! ---
//!
//! ## 🔐 Pre‑signed URLs
//!
//! Pre‑signed URLs are of the form:
//!
//! ```text
//! {domain}{path}?expires={unix_seconds}&sig={base64url_hmac}
//! ```
//!
//! The string to sign is:
//!
//! ```text
//! {METHOD}|{PATH}|{EXPIRES}
//! ```
//!
//! HMAC‑SHA256 over that string (with your secret bytes) is Base64 URL‑safe encoded.
//!
//! The server verifies:
//!
//! * `expires` is in the future
//! * the signature matches (constant‑time compare)
//! * method and path match the ones signed
//!
//! ### Utility functions (available in this repo)
//!
//! The `src/utils.rs` exposes helpers you can reuse:
//!
//! * `generate_presigned_url(method, domain, path, secret, expiry_seconds) -> String`
//! * `extract_sig_from_query(query) -> Result<(expires, sig), String>`
//! * `verify_presigned_signature(method, path, sig, expires, secret) -> Result<(), String>`
//!
//! > See unit tests in `src/utils.rs` for round‑trip samples and expiry checks.
//!
//! ---
//! ## 🧩 API Shape (High‑Level)
//!
//! This project follows an S3‑style flow with **pre‑signed operations**. While the concrete routes may evolve, the intended patterns are:
//!
//! * **Single‑part upload**
//!
//!   * Client obtains a pre‑signed `PUT` URL for a target object path (e.g., `/objects/{uuid}`)
//!   * Client `PUT`s bytes to that URL within `expires`
//!   * Server writes to `<uuid>.tmp` then atomically renames to `<uuid>`
//!
//! * **Chunked (multi‑part) upload**
//!
//!   * Client obtains N pre‑signed `PUT` URLs for `/objects/{uuid}/chunks/{idx}/{total}`
//!   * Upload each chunk independently
//!   * Server merges when all parts are present
//!
//! * **Download**
//!
//!   * Client obtains a pre‑signed `GET` URL for `/objects/{uuid}` and downloads the blob
//!
//! All pre‑signed requests include `?expires=...&sig=...` and are validated server‑side.
//!
//! ---
//!
//! ## 🧹 Cleanup Task
//!
//! * Starts automatically at boot
//! * Logs: `🪣 Started cleanup task - orphan timeout …`
//! * Runs a cleanup cycle every `2 * ttl_orphan_secs`
//! * Removes orphaned temp files and stale chunk directories
//! * Runs filesystem work in a blocking thread to avoid starving the async runtime
//!
//! ---
//!
//! ## 🛑 Shutdown
//!
//! * Catches `SIGTERM` and `SIGINT` and **gracefully** cancels the server via a `CancellationToken`
//! * The janitor task is aborted once the server exits

use std::{
    fs::{remove_dir_all, remove_file},
    path::PathBuf,
    time::Duration,
};

use anyhow::Result;
use clap::Parser;
use config::Config;
use storage::FsController;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing::{Level, debug, error, info, warn};
use utils::{byte_size_str, large_secs_str};

mod config;
mod server;
mod storage;
mod utils;

/// Commandline arguments
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long)]
    data_dir: Option<PathBuf>,

    #[arg(long)]
    ip_addr: Option<String>,

    #[arg(long)]
    domain: Option<String>,

    #[arg(long)]
    presign_api_key: Option<String>,

    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    tracing_subscriber::fmt().with_max_level(level).init();

    let config = Config::init(args)?;
    info!("📦 Data-Directory: {}", config.data_dir.display());
    info!("🔒 Domain: {}", config.domain);
    info!("🌐 Listening on {}", config.ip_addr);
    info!(
        "🌐 Presign-API request size limit: {}",
        byte_size_str(config.max_presign_rq_size)
    );
    info!(
        "🌐 Data-API request size limit: {}",
        byte_size_str(config.max_data_rq_size)
    );
    info!("🌐 Request-Timeout: {}s", config.rq_timeout_secs);

    let fs_controller = FsController::init(&config.data_dir)?;

    // --- Create shutdown token
    let shutdown_token = CancellationToken::new();

    // Start cleanup task
    let fs = fs_controller.clone();
    let ttl_orphan_secs = config.ttl_orphan_secs;
    let cleanup_task = tokio::spawn(async move {
        info!(
            "🪣 Started cleanup task - orphan timeout {}",
            large_secs_str(ttl_orphan_secs)
        );
        loop {
            info!("🧹 Performing cleanup routine...");
            cleanup_routine(fs.clone(), ttl_orphan_secs).await;
            tokio::time::sleep(Duration::from_secs(2 * ttl_orphan_secs)).await;
        }
    });

    // Spawn a detached ctrl+c handler
    tokio::spawn(signal_handler(shutdown_token.clone()));

    server::start(config, fs_controller, shutdown_token).await?;

    // If the server returns, we can abort the cleanup task
    cleanup_task.abort();
    Ok(())
}

/// Helper function for the cleanup routine.
///
/// Spawns a blocking task for the fs operations and fetched all errors,
/// since we don't want the cleanup task to return and shutdown.
async fn cleanup_routine(fs_controller: FsController, ttl_orphan_secs: u64) {
    let blocking = tokio::task::spawn_blocking(move || -> Result<()> {
        let orphaned_files = fs_controller.find_orphaned_tmp_files(ttl_orphan_secs)?;
        for file in &orphaned_files {
            debug!("🧹 Removing {}", file.display());
            remove_file(file)?;
        }

        let orphaned_dirs = fs_controller.find_orphaned_chunks(ttl_orphan_secs)?;
        for dir in &orphaned_dirs {
            debug!("🧹 Removing {}", dir.display());
            remove_dir_all(dir)?;
        }
        info!(
            "🧹 Removed {} orphaned files and {} orphaned chunk directories",
            orphaned_files.len(),
            orphaned_dirs.len()
        );
        Ok(())
    });
    match blocking.await {
        Ok(Ok(())) => (),
        Ok(Err(e)) => warn!("🧹 Error while executing cleanup routine: {e}"),
        Err(e) => error!("❌ Error while waiting for cleanup task: {e}"),
    }
}

async fn signal_handler(shutdown_token: CancellationToken) {
    let mut sigterm =
        signal(SignalKind::terminate()).expect("failed to register interrupt handler for SIGTERM");
    let mut sigint =
        signal(SignalKind::interrupt()).expect("failed to register interrupt handler for SIGINT");

    tokio::select! {
        _ = sigterm.recv() => {
            info!("🪦 Termination signal received (SIGTERM), gracefully shutting down.");
        }
        _ = sigint.recv() => {
            info!("⛔ Interrupt received (SIGINT), gracefully shutting down.");
        }
    }
    shutdown_token.cancel();
}
