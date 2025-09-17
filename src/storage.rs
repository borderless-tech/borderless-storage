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
const FS_CHUNK_DIR: &str = "chunks";

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
pub struct FsController {
    base_path: Arc<PathBuf>,
}

impl FsController {
    pub fn init(base_path: &Path) -> Result<Self> {
        // Create base directories
        create_dir_all(base_path.join(FS_DATA_DIR))?;
        create_dir_all(base_path.join(FS_CHUNK_DIR))?;
        Ok(FsController {
            base_path: Arc::new(base_path.to_path_buf()),
        })
    }

    pub fn blob_path(&self, blob_id: &Uuid) -> (PathBuf, PathBuf) {
        let full = self.base_path.join(FS_DATA_DIR).join(blob_id.to_string());
        let tmp = self
            .base_path
            .join(FS_DATA_DIR)
            .join(format!("{blob_id}.tmp"));
        (full, tmp)
    }

    pub fn chunk_path(
        &self,
        blob_id: &Uuid,
        chunk_idx: usize,
        chunk_total: usize,
    ) -> std::result::Result<(PathBuf, PathBuf), std::io::Error> {
        let chunk_sub_dir = self.base_path.join(FS_CHUNK_DIR).join(blob_id.to_string());

        if !chunk_sub_dir.exists() {
            std::fs::create_dir(&chunk_sub_dir)?;
        }
        // Random double check
        if !chunk_sub_dir.is_dir() {
            std::fs::remove_file(&chunk_sub_dir)?;
            std::fs::create_dir(&chunk_sub_dir)?;
        }

        // Now return the two paths
        let full = chunk_sub_dir.join(format!("chunk_{chunk_idx}_{chunk_total}"));
        let tmp = chunk_sub_dir.join(format!("chunk_{chunk_idx}_{chunk_total}.tmp"));
        Ok((full, tmp))
    }

    /// Checks if all chunks are present or not.
    ///
    /// Returns a list of missing chunk-ids in case there are still chunks missing
    pub fn check_chunks(
        &self,
        blob_id: &Uuid,
        chunk_total: usize,
    ) -> std::result::Result<(), Vec<usize>> {
        let chunk_sub_dir = self.base_path.join(FS_CHUNK_DIR).join(blob_id.to_string());
        if !chunk_sub_dir.exists() || !chunk_sub_dir.is_dir() {
            // No chunk is uploaded - return the list of all chunks
            return Err((1..=chunk_total).collect());
        }

        let mut missing = Vec::new();
        for chunk_idx in 1..=chunk_total {
            // Check every chunk
            let chunk = chunk_sub_dir.join(format!("chunk_{chunk_idx}_{chunk_total}"));
            if !chunk.exists() || !chunk.is_file() {
                missing.push(chunk_idx);
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }

    // NOTE: Maybe we start writing a .tmp version of the file and then rename in the end ?
    // pub fn prepare_blob(&self, blob_id: &Uuid) -> Result<File> {
    //     let path = self.base_path.join(FS_DATA_DIR).join(blob_id.to_string());
    //     if path.exists() {
    //         return Err(Error::Duplicate);
    //     }
    //     let f = File::create_new(path)?;
    //     Ok(f)
    // }

    // pub fn write_blob(&self, blob_id: Uuid, data: &[u8]) -> Result<()> {
    //     let path = self.base_path.join(FS_DATA_DIR).join(blob_id.to_string());
    //     if path.exists() {
    //         return Err(Error::Duplicate);
    //     }
    //     let f = File::create_new(path)?;
    //     let mut writer = BufWriter::new(f);
    //     writer.write_all(data)?;
    //     Ok(())
    // }

    // pub fn update_blob(&self, blob_id: Uuid, data: &[u8]) -> Result<()> {
    //     let path = self.base_path.join(FS_DATA_DIR).join(blob_id.to_string());
    //     // No check for existence - nothing
    //     let f = File::create(path)?;
    //     let mut writer = BufWriter::new(f);
    //     writer.write_all(data)?;
    //     Ok(())
    // }

    // // Oneshot receive
    // pub fn read_blob(&self, blob_id: Uuid) -> Result<Option<Vec<u8>>> {
    //     let path = self.base_path.join(FS_DATA_DIR).join(blob_id.to_string());
    //     if !path.exists() {
    //         return Ok(None);
    //     }
    //     if !path.is_file() {
    //         return Err(Error::NotAFile);
    //     }
    //     let f = File::open(path)?;
    //     let mut buf = Vec::with_capacity(f.metadata()?.size() as usize);
    //     let mut reader = BufReader::new(f);
    //     reader.read_to_end(&mut buf)?;
    //     Ok(Some(buf))
    // }
}

// #[cfg(test)]
// mod test {
//     use super::FsController;
//     use anyhow::Result;
//     use tempfile::TempDir;
//     use uuid::Uuid;

//     fn create_fs_controller() -> Result<(FsController, TempDir)> {
//         let tmp_dir = tempfile::tempdir()?;
//         let controller = FsController::init(tmp_dir.path())?;
//         Ok((controller, tmp_dir))
//     }

//     #[test]
//     fn read_write() -> Result<()> {
//         let (controller, _guard) = create_fs_controller()?;
//         let blob_id = Uuid::now_v7();
//         let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
//         controller.write_blob(blob_id, &data)?;

//         let read = controller.read_blob(blob_id)?;
//         assert!(read.is_some());
//         assert_eq!(read.unwrap(), data);
//         Ok(())
//     }

//     #[test]
//     fn read_non_existing() -> Result<()> {
//         let (controller, _guard) = create_fs_controller()?;
//         let blob_id = Uuid::now_v7();
//         let read = controller.read_blob(blob_id)?;
//         assert!(read.is_none());
//         Ok(())
//     }
// }
