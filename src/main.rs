use std::{
    fs::{remove_dir_all, remove_file},
    path::PathBuf,
    time::Duration,
};

use anyhow::Result;
use clap::Parser;
use config::Config;
use storage::FsController;
use tracing::{Level, debug, error, info, warn};
use utils::large_secs_str;

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
}

/*
* TODOs
Request size limits
Rate limiting
Cleanup service

Graceful shutdown
Metrics
Configurable limits
*
*/

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let config = Config::init(args)?;
    info!("📦 Data-Directory: {}", config.data_dir.display());
    info!("🔒 Domain: {}", config.domain);
    info!("🌐 Listening on {}", config.ip_addr);

    let fs_controller = FsController::init(&config.data_dir)?;

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
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });

    server::start(config, fs_controller).await?;
    // If the server returns, we can abort the cleanup task
    cleanup_task.abort();
    Ok(())
}

async fn cleanup_routine(fs_controller: FsController, ttl_orphan_secs: u64) {
    let blocking = tokio::task::spawn_blocking(move || -> Result<()> {
        let orphaned_files = fs_controller.find_orphaned_tmp_files(ttl_orphan_secs)?;
        for file in &orphaned_files {
            debug!("-- Removing {}", file.display());
            remove_file(file)?;
        }

        let orphaned_dirs = fs_controller.find_orphaned_chunks(ttl_orphan_secs)?;
        for dir in &orphaned_dirs {
            debug!("-- Removing {}", dir.display());
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
