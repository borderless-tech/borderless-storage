use std::{fs::File, path::Path};

use anyhow::{Context, Result, bail};

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
