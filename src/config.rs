use std::{net::ToSocketAddrs, path::PathBuf};

use anyhow::{Context, Result};
use axum::http::Uri;
use serde::{Deserialize, de::DeserializeOwned};
use tracing::info;

use crate::{Args, utils::check_directory_access};

/// Default config value for ttl-orphan-secs
const DEFAULT_TTL_ORPHAN_SECS: u64 = 12 * 60 * 60;

/// Service configuration
#[derive(Deserialize)]
pub struct Config {
    /// IP-Address (+ port) that the web-service listens on
    pub ip_addr: String,

    /// Data directory
    pub data_dir: PathBuf,

    /// Domain, under which the service is reachable
    /// (important to give out correct pre-signed urls)
    pub domain: String,

    /// Time-to-live (in seconds) for `.tmp` files and chunk-directories,
    /// before they are considered orphanaged.
    /// Defaults to `12 * 60 * 60` - which is 12 hours
    pub ttl_orphan_secs: u64,
}

impl Config {
    /// Initializes the configuration
    ///
    /// If the `--config` option is set, the config file is used.
    /// In case no config-file is specified, the config is parsed via basic cmdline arguments,
    /// and if those are not present, the config is initialized via environment variables.
    pub fn init(args: Args) -> Result<Self> {
        // Try to init configuration in that order:
        //
        // 1. Try from config-file
        // 2. Try from arguments
        // 3. Try from environment
        let config = if let Some(config_path) = args.config {
            info!("⚙ Parsing config from file: {}", config_path.display());
            let content = std::fs::read_to_string(&config_path).context(format!(
                "failed to read config file at '{}'",
                config_path.display()
            ))?;
            let config: Config = toml::from_str(&content).context("failed to parse config file")?;
            config
        } else if args.ip_addr.is_some() && args.data_dir.is_some() && args.domain.is_some() {
            info!("⚙ Parsing config from cmdline arguments");
            Config {
                ip_addr: args.ip_addr.unwrap(),
                data_dir: args.data_dir.unwrap(),
                domain: args.domain.unwrap(),
                ttl_orphan_secs: DEFAULT_TTL_ORPHAN_SECS, // No option to set this via cmdline
            }
        } else {
            info!("⚙ Parsing config from environment variables");
            Config::try_from_env()?
        };

        // --- Do some sanity checks and parsing
        check_directory_access(&config.data_dir)?;

        let _socket_addr = config
            .ip_addr
            .to_socket_addrs()
            .context("failed to parse ip-addr")?;

        let _domain: Uri = config
            .domain
            .parse()
            .context("domain is not a proper URI")?;

        Ok(config)
    }

    fn try_from_env() -> Result<Self> {
        let ip_addr = get_from_env("IP_ADDR")?;
        let data_dir = get_from_env("DATA_DIR")?;
        let domain = get_from_env("DOMAIN")?;
        let ttl_orphan_secs = get_from_env("TTL_ORPHAN_SECS").unwrap_or(DEFAULT_TTL_ORPHAN_SECS);
        Ok(Config {
            ip_addr,
            data_dir,
            domain,
            ttl_orphan_secs,
        })
    }
}

/// Helper function to parse a value from the environment
fn get_from_env<T: DeserializeOwned>(var: &'static str) -> Result<T> {
    let value_string = std::env::var(var).context(format!("Missing required variable '{var}'"))?;
    let quoted = format!("'{}'", value_string.trim());
    let value: toml::Value = quoted.parse()?;
    Ok(value.try_into()?)
}
