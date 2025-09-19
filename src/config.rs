use std::{net::ToSocketAddrs, path::PathBuf};

use anyhow::{Context, Result};
use axum::http::Uri;
use serde::{Deserialize, de::DeserializeOwned};
use tracing::info;

use crate::{Args, utils::check_directory_access};

/// Default config value for ttl-orphan-secs
const DEFAULT_TTL_ORPHAN_SECS: u64 = 12 * 60 * 60;

/// Maximum size (in bytes) for data-requests (4GB)
const DEFAULT_MAX_DATA_RQ_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// Maximum size (in bytes) for presign-requests (100kB)
const DEFAULT_MAX_PRESIGN_RQ_SIZE: usize = 100 * 1024;

/// Default timeout for incoming http-requests
const DEFAULT_RQ_TIMEOUT_SECS: u64 = 30;

/// Service configuration
#[derive(Debug, Deserialize)]
pub struct Config {
    /// IP-Address (+ port) that the web-service listens on
    pub ip_addr: String,

    /// Data directory
    pub data_dir: PathBuf,

    /// Domain, under which the service is reachable
    /// (important to give out correct pre-signed urls)
    pub domain: String,

    /// API-Key used to authenticate the presign endpoint
    pub presign_api_key: String,

    /// Secret used to generate the presigned URLs
    ///
    /// If empty, the server generates a random secret upon start.
    /// However, if your presigned urls should also be valid after service restarts,
    /// you should provide a fixed secret. And please ensure you used enough entropy (usually 256 bit).
    pub presign_hmac_secret: Option<String>,

    /// Time-to-live (in seconds) for `.tmp` files and chunk-directories,
    /// before they are considered orphanaged.
    /// Defaults to `12 * 60 * 60` - which is 12 hours
    pub ttl_orphan_secs: u64,

    /// Maximum size (in bytes) for data-requests
    pub max_data_rq_size: usize,

    /// Maximum size (in bytes) for presign-requests
    pub max_presign_rq_size: usize,

    /// Request Timeout in seconds
    pub rq_timeout_secs: u64,
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
        } else if args.ip_addr.is_some()
            && args.data_dir.is_some()
            && args.domain.is_some()
            && args.presign_api_key.is_some()
        {
            info!("⚙ Parsing config from cmdline arguments");
            // Not all options are available via cmdline
            Config {
                ip_addr: args.ip_addr.unwrap(),
                data_dir: args.data_dir.unwrap(),
                domain: args.domain.unwrap(),
                presign_api_key: args.presign_api_key.unwrap(),
                presign_hmac_secret: None,
                ttl_orphan_secs: DEFAULT_TTL_ORPHAN_SECS,
                max_data_rq_size: DEFAULT_MAX_DATA_RQ_SIZE,
                max_presign_rq_size: DEFAULT_MAX_PRESIGN_RQ_SIZE,
                rq_timeout_secs: DEFAULT_RQ_TIMEOUT_SECS,
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
        let presign_api_key = get_from_env("PRESIGN_API_KEY")?;
        let presign_hmac_secret = get_from_env("PRESIGN_HMAC_SECRET").ok(); // default is 'None'
        let ttl_orphan_secs = get_from_env("TTL_ORPHAN_SECS").unwrap_or(DEFAULT_TTL_ORPHAN_SECS);
        let max_data_rq_size = get_from_env("MAX_DATA_RQ_SIZE").unwrap_or(DEFAULT_MAX_DATA_RQ_SIZE);
        let max_presign_rq_size =
            get_from_env("MAX_PRESIGN_RQ_SIZE").unwrap_or(DEFAULT_MAX_PRESIGN_RQ_SIZE);
        let rq_timeout_secs = get_from_env("RQ_TIMEOUT_SECS").unwrap_or(DEFAULT_RQ_TIMEOUT_SECS);
        Ok(Config {
            ip_addr,
            data_dir,
            domain,
            presign_api_key,
            presign_hmac_secret,
            ttl_orphan_secs,
            max_data_rq_size,
            max_presign_rq_size,
            rq_timeout_secs,
        })
    }
}

/// Helper function to parse a value from the environment
fn get_from_env<T: DeserializeOwned>(var: &'static str) -> Result<T> {
    let value_string = std::env::var(var).context(format!("Missing required variable '{var}'"))?;
    // Check, if string is only numbers
    if value_string.chars().all(|c| c.is_numeric()) {
        // in this case don't quote
        let value: toml::Value = value_string.parse()?;
        Ok(value.try_into()?)
    } else {
        let quoted = format!("'{}'", value_string.trim());
        let value: toml::Value = quoted.parse()?;
        Ok(value.try_into()?)
    }
}

#[cfg(test)]
mod tests {
    use crate::Args;

    use super::*;
    use parking_lot::Mutex;
    use std::io::Write;
    use tempfile::{NamedTempFile, tempdir};

    // Serialize tests that mutate process environment to avoid cross-talk.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // Small helper: clear a list of env vars
    fn unset(vars: &[&str]) {
        for v in vars {
            unsafe {
                std::env::remove_var(v);
            }
        }
    }

    // Small wrapper to avoid the unsafe blocks everywhere
    fn set_env(key: &str, value: &str) {
        unsafe {
            std::env::set_var(key, value);
        }
    }

    // Build an Args instance for CLI-path tests
    fn mk_args_cmdline(ip: &str, data_dir: &std::path::Path, domain: &str, api_key: &str) -> Args {
        Args {
            data_dir: Some(data_dir.to_path_buf()),
            ip_addr: Some(ip.to_string()),
            domain: Some(domain.to_string()),
            presign_api_key: Some(api_key.to_string()),
            config: None,
            verbose: false,
        }
    }

    // Build an Args instance pointing to a config file
    fn mk_args_config(path: &std::path::Path) -> Args {
        Args {
            data_dir: None,
            ip_addr: None,
            domain: None,
            presign_api_key: None,
            config: Some(path.to_path_buf()),
            verbose: true,
        }
    }

    // Build an Args instance that triggers env-based init
    fn mk_args_env() -> Args {
        Args {
            data_dir: None,
            ip_addr: None,
            domain: None,
            config: None,
            presign_api_key: None,
            verbose: false,
        }
    }

    #[test]
    fn init_from_config_file_ok() {
        let _guard = ENV_LOCK.lock();

        // Writable data dir for check_directory_access
        let datadir = tempdir().expect("tempdir");
        let data_path = datadir.path().to_path_buf();

        // Create config file
        let mut cfg = NamedTempFile::new().expect("tmp file");
        writeln!(
            cfg,
            r#"
ip_addr = "127.0.0.1:9876"
data_dir = "{}"
domain  = "https://example.test"
presign_api_key = "secret-key"
ttl_orphan_secs = 111
max_data_rq_size = 222
max_presign_rq_size = 333
rq_timeout_secs = 444
"#,
            data_path.display()
        )
        .unwrap();

        // Initialize
        let args = mk_args_config(cfg.path());
        let c = Config::init(args).expect("config init");

        assert_eq!(c.ip_addr, "127.0.0.1:9876");
        assert_eq!(c.data_dir, data_path);
        assert_eq!(c.domain, "https://example.test");
        assert_eq!(c.ttl_orphan_secs, 111);
        assert_eq!(c.max_data_rq_size, 222);
        assert_eq!(c.max_presign_rq_size, 333);
        assert_eq!(c.rq_timeout_secs, 444);
    }

    #[test]
    fn init_from_cmdline_ok_with_defaults() {
        let _guard = ENV_LOCK.lock();

        // Clean env to ensure no bleed-through
        unset(&[
            "IP_ADDR",
            "DATA_DIR",
            "DOMAIN",
            "TTL_ORPHAN_SECS",
            "MAX_DATA_RQ_SIZE",
            "MAX_PRESIGN_RQ_SIZE",
            "RQ_TIMEOUT_SECS",
        ]);

        let datadir = tempdir().expect("tempdir");

        let args = mk_args_cmdline(
            "0.0.0.0:5555",
            datadir.path(),
            "https://storage.example",
            "super-secret-key",
        );
        let c = Config::init(args).expect("config init");

        assert_eq!(c.ip_addr, "0.0.0.0:5555");
        assert_eq!(c.data_dir, datadir.path());
        assert_eq!(c.domain, "https://storage.example");
        assert_eq!(c.presign_api_key, "super-secret-key");

        // Defaults from this module
        assert_eq!(c.ttl_orphan_secs, super::DEFAULT_TTL_ORPHAN_SECS);
        assert_eq!(c.max_data_rq_size, super::DEFAULT_MAX_DATA_RQ_SIZE);
        assert_eq!(c.max_presign_rq_size, super::DEFAULT_MAX_PRESIGN_RQ_SIZE);
        assert_eq!(c.rq_timeout_secs, super::DEFAULT_RQ_TIMEOUT_SECS);
    }

    #[test]
    fn init_from_env_ok() {
        let _guard = ENV_LOCK.lock();

        let datadir = tempdir().expect("tempdir");

        // Set required env vars
        set_env("IP_ADDR", "127.0.0.1:7070");
        set_env("DATA_DIR", datadir.path().to_str().unwrap());
        set_env("DOMAIN", "https://env.example");
        set_env("PRESIGN_API_KEY", "secret-key");
        set_env("PRESIGN_HMAC_SECRET", "hmac-secret");

        // Optional numeric vars (exercise numeric parsing path in get_from_env)
        set_env("TTL_ORPHAN_SECS", "12345");
        set_env("MAX_DATA_RQ_SIZE", "1024");
        set_env("MAX_PRESIGN_RQ_SIZE", "2048");
        set_env("RQ_TIMEOUT_SECS", "9");

        let args = mk_args_env();
        let c = Config::init(args).expect("config init");

        assert_eq!(c.ip_addr, "127.0.0.1:7070");
        assert_eq!(c.data_dir, datadir.path());
        assert_eq!(c.domain, "https://env.example");
        assert_eq!(c.presign_api_key, "secret-key");
        assert_eq!(c.presign_hmac_secret.unwrap(), "hmac-secret");
        assert_eq!(c.ttl_orphan_secs, 12345);
        assert_eq!(c.max_data_rq_size, 1024);
        assert_eq!(c.max_presign_rq_size, 2048);
        assert_eq!(c.rq_timeout_secs, 9);
    }

    #[test]
    fn init_from_env_missing_required_vars_errors() {
        let _guard = ENV_LOCK.lock();

        unset(&["IP_ADDR", "DATA_DIR", "DOMAIN"]);
        // Set only one to prove failure still bubbles
        set_env("IP_ADDR", "127.0.0.1:9090");

        let args = mk_args_env();
        let res = Config::init(args);
        assert!(res.is_err(), "missing required env vars should error");
    }

    #[test]
    fn invalid_socket_addr_rejected() {
        let _guard = ENV_LOCK.lock();

        let datadir = tempdir().expect("tempdir");
        let mut cfg = NamedTempFile::new().expect("tmp file");

        // ip_addr is invalid (no port)
        writeln!(
            cfg,
            r#"
ip_addr = "127.0.0.1"
data_dir = "{}"
domain  = "https://example.test"
presign_api_key = "foo"
ttl_orphan_secs = 43200           # 12 h
max_data_rq_size = 4294967296     # 4 GiB
max_presign_rq_size = 102400      # 100 KiB
rq_timeout_secs = 30
"#,
            datadir.path().display()
        )
        .unwrap();

        let args = mk_args_config(cfg.path());
        let err = Config::init(args).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("failed to parse ip-addr"),
            "expected socket parse failure, got: {msg}"
        );
    }

    #[test]
    fn invalid_domain_rejected() {
        let _guard = ENV_LOCK.lock();

        let datadir = tempdir().expect("tempdir");
        let mut cfg = NamedTempFile::new().expect("tmp file");

        // domain is not a valid URI
        writeln!(
            cfg,
            r#"
ip_addr = "0.0.0.0:1234"
data_dir = "{}"
domain  = "not a uri"
presign_api_key = "foo"
ttl_orphan_secs = 43200           # 12 h
max_data_rq_size = 4294967296     # 4 GiB
max_presign_rq_size = 102400      # 100 KiB
rq_timeout_secs = 30
"#,
            datadir.path().display()
        )
        .unwrap();

        let args = mk_args_config(cfg.path());
        let err = Config::init(args).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("domain is not a proper URI"),
            "expected URI parse failure, got: {msg}"
        );
    }

    #[test]
    fn non_existent_data_dir_rejected() {
        let _guard = ENV_LOCK.lock();

        // Create a temp dir, but point config to a *non-existent* child
        let datadir = tempdir().expect("tempdir");
        let nonexist = datadir.path().join("nope/does/not/exist");

        let mut cfg = NamedTempFile::new().expect("tmp file");
        writeln!(
            cfg,
            r#"
ip_addr = "127.0.0.1:3333"
data_dir = "{}"
domain  = "https://example.test"
presign_api_key = "foo"
ttl_orphan_secs = 43200           # 12 h
max_data_rq_size = 4294967296     # 4 GiB
max_presign_rq_size = 102400      # 100 KiB
rq_timeout_secs = 30
"#,
            nonexist.display()
        )
        .unwrap();

        let args = mk_args_config(cfg.path());
        let err = Config::init(args).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Directory does not exist"),
            "expected data dir access check to fail, got: {msg}"
        );
    }

    #[test]
    fn get_from_env_numeric_vs_string_behavior() {
        let _guard = ENV_LOCK.lock();

        // NUMERIC: all digits -> parsed as number (no quoting)
        set_env("TTL_ORPHAN_SECS", "600");
        let ttl: u64 = super::get_from_env("TTL_ORPHAN_SECS").expect("parse numeric");
        assert_eq!(ttl, 600);

        // STRING (contains non-digits) -> quoted internally to preserve value
        set_env("IP_ADDR", "127.0.0.1:8080");
        let ip: String = super::get_from_env("IP_ADDR").expect("parse stringy");
        assert_eq!(ip, "127.0.0.1:8080");
    }

    #[test]
    fn args_parsing_via_clap() {
        use clap::Parser;
        // Simulate: binary name and CLI args
        let fake = [
            "bin",
            "--data-dir",
            "/tmp/data",
            "--ip-addr",
            "0.0.0.0:8080",
            "--domain",
            "https://example.test",
            "--presign-api-key",
            "abc123",
            "--verbose",
        ];
        // Clap will parse into our Args struct
        let args = crate::Args::try_parse_from(&fake).expect("parse args");
        assert_eq!(args.data_dir.unwrap(), PathBuf::from("/tmp/data"));
        assert_eq!(args.ip_addr.as_deref(), Some("0.0.0.0:8080"));
        assert_eq!(args.domain.as_deref(), Some("https://example.test"));
        assert_eq!(args.presign_api_key.as_deref(), Some("abc123"));
        assert!(args.verbose);
    }
}
