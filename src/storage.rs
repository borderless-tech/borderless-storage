use std::{
    fs::{File, create_dir_all},
    io::{BufReader, BufWriter, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use thiserror::Error;
use uuid::Uuid;

/// Sub-Directory, where all data is stored to
const FS_DATA_DIR: &str = "full";

/// Sub-Directory, where we start storing received parts, before combining them
const FS_META_DIR: &str = "parts";

/// Storage Controller Error
#[derive(Debug, Error)]
pub enum Error {
    #[error("Duplicate ID - refuse to overwrite")]
    Duplicate,
    #[error("Item is not a file (but should be)")]
    NotAFile,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Storage Controller Result
type Result<T> = std::result::Result<T, Error>;

/// Controller for filesystem based local storage
///
/// Encapsulates all storage related logic.
///
/// For now we simply save everything to the disk,
/// but later more elaborate things can happen here, like connecting to s3 buckets etc.
#[derive(Debug, Clone)]
struct FsController {
    base_path: Arc<PathBuf>,
}

impl FsController {
    pub fn init(base_path: &Path) -> Result<Self> {
        // Create base directories
        create_dir_all(base_path.join(FS_DATA_DIR))?;
        create_dir_all(base_path.join(FS_META_DIR))?;
        Ok(FsController {
            base_path: Arc::new(base_path.to_path_buf()),
        })
    }

    pub fn write_data(&self, blob_id: Uuid, data: &[u8]) -> Result<()> {
        let path = self.base_path.join(FS_DATA_DIR).join(blob_id.to_string());
        if path.exists() {
            return Err(Error::Duplicate);
        }
        let f = File::create_new(path)?;
        let mut writer = BufWriter::new(f);
        writer.write_all(data)?;
        Ok(())
    }

    // Oneshot receive
    pub fn read_data(&self, blob_id: Uuid) -> Result<Option<Vec<u8>>> {
        let path = self.base_path.join(FS_DATA_DIR).join(blob_id.to_string());
        if !path.exists() {
            return Ok(None);
        }
        if !path.is_file() {
            return Err(Error::NotAFile);
        }
        let f = File::open(path)?;
        let mut buf = Vec::with_capacity(f.metadata()?.size() as usize);
        let mut reader = BufReader::new(f);
        reader.read_to_end(&mut buf)?;
        Ok(Some(buf))
    }
}

#[cfg(test)]
mod test {
    use super::FsController;
    use anyhow::Result;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn create_fs_controller() -> Result<(FsController, TempDir)> {
        let tmp_dir = tempfile::tempdir()?;
        let controller = FsController::init(tmp_dir.path())?;
        Ok((controller, tmp_dir))
    }

    #[test]
    fn read_write() -> Result<()> {
        let (controller, _guard) = create_fs_controller()?;
        let blob_id = Uuid::now_v7();
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        controller.write_data(blob_id, &data)?;

        let read = controller.read_data(blob_id)?;
        assert!(read.is_some());
        assert_eq!(read.unwrap(), data);
        Ok(())
    }

    #[test]
    fn read_non_existing() -> Result<()> {
        let (controller, _guard) = create_fs_controller()?;
        let blob_id = Uuid::now_v7();
        let read = controller.read_data(blob_id)?;
        assert!(read.is_none());
        Ok(())
    }
}
