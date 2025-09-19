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

    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

/*
* TODOs
[x] Request size limits
[x] Timeout
[x] Request-IDs
[x] Cleanup service

[x] Graceful shutdown
[ ] Metrics
[ ] Configurable limits
*
*/

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
