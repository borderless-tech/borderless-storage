use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use config::Config;
use storage::FsController;
use tracing::{Level, info};

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

    let config = Config::init(args)?;

    let fs_controller = FsController::init(&config.data_dir)?;

    // TODO: Implement periodic cleanup logic

    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    info!("📦 Data-Directory: {}", config.data_dir.display());
    info!("🔒 Domain: {}", config.domain);
    info!("🌐 Listening on {}...", config.ip_addr);

    server::start(config, fs_controller).await?;
    Ok(())
}
