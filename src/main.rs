use std::{net::ToSocketAddrs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use storage::FsController;
use tracing::{Level, info};
use utils::check_directory_access;

mod server;
mod storage;
mod utils;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    data_dir: PathBuf,
    ip_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    check_directory_access(&args.data_dir)?;

    let socket_addr = args
        .ip_addr
        .to_socket_addrs()?
        .filter(|s| s.is_ipv4())
        .next()
        .context("Failed to parse socket address")?;

    let fs_controller = FsController::init(&args.data_dir)?;

    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    info!("Initializing webserver on {}...", socket_addr);

    server::start(socket_addr, fs_controller).await?;
    Ok(())
}
