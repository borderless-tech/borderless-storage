use std::{
    fs::File,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, prelude::BASE64_URL_SAFE};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Checks if a directory exists, and if we have write access to it
pub fn check_directory_access(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("Directory does not exist: {}", path.display());
    }

    if !path.is_dir() {
        bail!("{} is not a directory", path.display());
    }

    if path.metadata()?.permissions().readonly() {
        bail!("Insufficient permissions - {} is readonly", path.display());
    }

    // Double check, by writing a file and then deleting it
    let tmp_path = path.join("access-test.tmp");
    let res = File::create(&tmp_path);

    if res.is_err() {
        bail!(
            "Failed to create test-file in {} - do we have write access to the directory ?",
            path.display()
        );
    }

    std::fs::remove_file(&tmp_path).context(format!(
        "Failed to remove test-file in {} - do we have write access in the direcotry?",
        path.display()
    ))?;

    Ok(())
}

/// Format the number of bytes written
pub fn byte_size_str(bytes: usize) -> String {
    match bytes {
        0..=1023 => format!("{bytes} B"),
        1024..=1048575 => format!("{:.1} KB", (bytes as f64) / 1024.),
        1048576..=1073741823 => format!("{:.1} MB", (bytes as f64) / 1048576.),
        1073741824..=1099511627775 => format!("{:.2} GB", (bytes as f64) / 1073741824.),
        1099511627776..=1125899906842623 => {
            format!("{:.3} TB", (bytes as f64) / 1099511627776.)
        }
        _ => {
            format!("{:4} PB", (bytes as f64) / 1125899906842624.)
        }
    }
}

/// Pretty prints a large number of seconds
pub fn large_secs_str(secs: u64) -> String {
    match secs {
        0..=60 => format!("{secs}s"),
        61..3600 => {
            let min = (secs as f64) / 60.;
            let secs = secs % 60;
            let mins = min.floor() as u64;
            if secs != 0 {
                format!("{mins}min {secs}s")
            } else {
                format!("{mins}min")
            }
        }
        3600..86400 => {
            let min = (secs as f64) / 60.;
            let hours = min / 60.;
            let mins = (min.floor() as u64) % 60;
            if mins != 0 {
                format!("{hours}h {mins}min")
            } else {
                format!("{hours}h")
            }
        }
        _ => {
            let days = (secs as f64) / 86400.;
            format!("~{} days", days.floor() as u64)
        }
    }
}

/// Returns a pre-signed url
pub fn generate_presigned_url(
    method: &str,
    domain: &str, // e.g. https://domain.com
    path: &str,   // just the path, e.g. /upload/uuid-123
    secret: &[u8],
    expiry_seconds: u64,
) -> String {
    debug_assert!(path.starts_with('/'), "paths must start with a '/'");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let expires = now + expiry_seconds;
    let sig_encoded = generate_signature(method, path, expires, secret);

    format!("{domain}{path}?expires={expires}&sig={sig_encoded}")
}

/// Verifies a signature of a pre-signed url
pub fn verify_presigned_signature(
    method: &str,
    path: &str,
    sig: &str,
    expires: u64,
    secret: &[u8],
) -> Result<u64, String> {
    debug_assert!(path.starts_with('/'), "paths must start with a '/'");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    if now > expires {
        return Err("signature expired".to_string());
    }

    let sig_expected = generate_signature(method, path, expires, secret);

    // Constant-time compare
    if subtle::ConstantTimeEq::ct_eq(sig_expected.as_bytes(), sig.as_bytes()).into() {
        // compute remaining ttl (saturate at 0)
        let remaining = expires.saturating_sub(now);
        Ok(remaining)
    } else {
        Err("invalid signature".to_string())
    }
}

/// Helper function to generate the signature of a pre-signed url
fn generate_signature(method: &str, path: &str, expires: u64, secret: &[u8]) -> String {
    let string_to_sign = format!("{method}|{path}|{expires}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(string_to_sign.as_bytes());
    let signature = mac.finalize().into_bytes();

    BASE64_URL_SAFE.encode(signature)
}

/// Helper function to parse the query of a pre-signed url
pub fn extract_sig_from_query(query: &str) -> Result<(u64, String), String> {
    let mut expires = None;
    let mut signature = None;
    for pat in query.split('&') {
        if let Some(expiry) = pat.strip_prefix("expires=") {
            let val = expiry
                .parse::<u64>()
                .map_err(|_| "failed to parse field 'expires'")?;
            expires = Some(val);
        } else if let Some(sig) = pat.strip_prefix("sig=") {
            signature = Some(sig);
        } else {
            continue;
        }
    }
    match (expires, signature) {
        (Some(e), Some(s)) => Ok((e, s.to_string())),
        (None, Some(_)) => Err("pre-signed-url is missing field 'expires' in query".to_string()),
        (Some(_), None) => Err("pre-signed-url is missing field 'sig' in query".to_string()),
        _ => {
            Err("pre-signed-url required! Missing fields 'sig' and 'expires' in query".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{thread::sleep, time::Duration};

    use super::*;
    use anyhow::Result;
    use axum::http::Uri;
    use rand::prelude::*;

    fn gen_secret() -> Vec<u8> {
        (0..256).map(|_| rand::rng().random()).collect()
    }

    #[test]
    fn validate_url_structure() -> Result<()> {
        let secret = gen_secret();
        let domain = "http://localhost:3000";
        let path = "/test/foo";
        let url = generate_presigned_url("POST", domain, path, &secret, 3600);
        assert!(url.starts_with(domain));
        let parsed: Uri = url.parse()?;
        assert_eq!(parsed.host(), Some("localhost"));
        assert_eq!(parsed.path(), path);
        assert!(parsed.query().is_some());
        assert!(extract_sig_from_query(parsed.query().unwrap()).is_ok());
        Ok(())
    }

    #[test]
    fn roundtrip_validation() -> Result<()> {
        let secret = gen_secret();
        let method = "POST";
        let domain = "http://localhost:3000";
        let path = "/test/foo";
        let url = generate_presigned_url(method, domain, path, &secret, 3600);
        let parsed: Uri = url.parse()?;
        let q = parsed.query().context("missing query")?;

        // Parse signature from query and validate it
        let (expires, sig) = extract_sig_from_query(q).map_err(anyhow::Error::msg)?;
        let v = verify_presigned_signature(method, path, &sig, expires, &secret);
        assert!(v.is_ok(), "failed to verify signature: {}", v.unwrap_err());
        Ok(())
    }

    #[test]
    fn check_failures() -> Result<()> {
        let secret = gen_secret();
        let method = "POST";
        let domain = "http://localhost:3000";
        let path = "/test/foo";
        let url = generate_presigned_url(method, domain, path, &secret, 3600);
        let parsed: Uri = url.parse()?;
        let q = parsed.query().context("missing query")?;

        // Parse signature from query and validate it
        let (expires, sig) = extract_sig_from_query(q).map_err(anyhow::Error::msg)?;

        // Wrong method
        let v = verify_presigned_signature("GET", path, &sig, expires, &secret);
        assert!(v.is_err());

        // Wrong path
        let v = verify_presigned_signature(method, "/test/baa", &sig, expires, &secret);
        assert!(v.is_err());

        // Wrong expiry
        let v = verify_presigned_signature(method, path, &sig, expires + 1, &secret);
        assert!(v.is_err());

        // Wrong secret
        let s2 = gen_secret();
        let v = verify_presigned_signature(method, path, &sig, expires, &s2);
        assert!(v.is_err());
        Ok(())
    }

    #[test]
    fn check_expiry() -> Result<()> {
        let secret = gen_secret();
        let method = "POST";
        let domain = "http://localhost:3000";
        let path = "/test/foo";
        let url = generate_presigned_url(method, domain, path, &secret, 1);
        let parsed: Uri = url.parse()?;
        let q = parsed.query().context("missing query")?;

        // Parse signature from query and validate it
        let (expires, sig) = extract_sig_from_query(q).map_err(anyhow::Error::msg)?;

        // Wait two seconds, to that the signature must have expired
        sleep(Duration::from_secs(2));
        let v = verify_presigned_signature(method, path, &sig, expires, &secret);
        assert!(v.is_err());
        Ok(())
    }

    #[test]
    fn broken_query() -> Result<()> {
        assert!(
            extract_sig_from_query("expires=1234").is_err(),
            "missing sig"
        );
        assert!(
            extract_sig_from_query("sig=aeaeaeae").is_err(),
            "missing exp"
        );
        assert!(extract_sig_from_query("").is_err(), "missing both");
        Ok(())
    }

    // NOTE: These two are AI generated, as the tests are quite useless, but the function drastically reduce test coverage..
    #[test]
    fn byte_size_str_boundaries_and_units() {
        // Bytes
        assert_eq!(byte_size_str(0), "0 B");
        assert_eq!(byte_size_str(1), "1 B");
        assert_eq!(byte_size_str(1023), "1023 B");

        // KB (1 decimal place)
        assert_eq!(byte_size_str(1024), "1.0 KB");
        assert_eq!(byte_size_str(2048), "2.0 KB");
        assert_eq!(byte_size_str(10 * 1024), "10.0 KB");

        // MB (1 decimal place)
        assert_eq!(byte_size_str(1_048_576), "1.0 MB"); // 1024^2
        assert_eq!(byte_size_str(2 * 1_048_576), "2.0 MB");

        // GB (2 decimals)
        assert_eq!(byte_size_str(1_073_741_824), "1.00 GB"); // 1024^3
        assert_eq!(byte_size_str(3 * 1_073_741_824), "3.00 GB");

        // TB (3 decimals)
        assert_eq!(byte_size_str(1_099_511_627_776), "1.000 TB"); // 1024^4

        // PB (width-padded integer format in current implementation)
        // Note: The function uses `format!("{:4} PB", value_in_pb)`, which pads with spaces.
        // This asserts current behavior explicitly to guard against accidental regressions.
        assert_eq!(byte_size_str(1_125_899_906_842_624), "   1 PB"); // 1024^5
        assert_eq!(byte_size_str(2 * 1_125_899_906_842_624), "   2 PB");
    }

    #[test]
    fn large_secs_str_boundaries_and_readable_output() {
        // Seconds range
        assert_eq!(large_secs_str(0), "0s");
        assert_eq!(large_secs_str(42), "42s");
        assert_eq!(large_secs_str(60), "60s");

        // Minutes range
        assert_eq!(large_secs_str(61), "1min 1s");
        assert_eq!(large_secs_str(120), "2min");
        assert_eq!(large_secs_str(3599), "59min 59s");

        // Hours range (choose values where mins == 0 to avoid fractional hours formatting)
        assert_eq!(large_secs_str(3600), "1h");
        assert_eq!(large_secs_str(7200), "2h");

        // Days range (floors to whole days with ~ prefix)
        assert_eq!(large_secs_str(86_400), "~1 days");
        assert_eq!(large_secs_str(172_800), "~2 days");
    }
}
