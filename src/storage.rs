use std::{
    fs::{File, create_dir, create_dir_all, remove_dir_all, remove_file, rename},
    io::{self, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use uuid::Uuid;

/// Sub-Directory, where all data is stored to
const FS_DATA_DIR: &str = "full";

/// Sub-Directory, where we start storing received parts, before combining them
const FS_CHUNK_DIR: &str = "chunks";

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
    pub fn init(base_path: &Path) -> Result<Self, io::Error> {
        // Create base directories
        create_dir_all(base_path.join(FS_DATA_DIR))?;
        create_dir_all(base_path.join(FS_CHUNK_DIR))?;
        Ok(FsController {
            base_path: Arc::new(base_path.to_path_buf()),
        })
    }

    /// Returns the path and tmp-path for a storage blob
    pub fn blob_path(&self, blob_id: &Uuid) -> (PathBuf, PathBuf) {
        let full = self.base_path.join(FS_DATA_DIR).join(blob_id.to_string());
        let tmp = self
            .base_path
            .join(FS_DATA_DIR)
            .join(format!("{blob_id}.tmp"));
        (full, tmp)
    }

    /// Returns the path and tmp-path for a chunk
    ///
    /// All chunks are uploaded into their own directory (which makes it easier to manage) based on the `blob_id`.
    /// If the chunk directory has not been created yet, this function will create it, which is why it can fail.
    pub fn chunk_path(
        &self,
        blob_id: &Uuid,
        chunk_idx: usize,
        chunk_total: usize,
    ) -> Result<(PathBuf, PathBuf), io::Error> {
        let chunk_sub_dir = self.base_path.join(FS_CHUNK_DIR).join(blob_id.to_string());

        if !chunk_sub_dir.exists() {
            create_dir(&chunk_sub_dir)?;
        }
        // Random double check
        if !chunk_sub_dir.is_dir() {
            remove_file(&chunk_sub_dir)?;
            create_dir(&chunk_sub_dir)?;
        }

        // Now return the two paths
        let full = chunk_sub_dir.join(format!("chunk_{chunk_idx}_{chunk_total}"));
        let tmp = chunk_sub_dir.join(format!("chunk_{chunk_idx}_{chunk_total}.tmp"));
        Ok((full, tmp))
    }

    /// Checks if all chunks are present or not.
    ///
    /// Returns a list of missing chunk-ids in case there are still chunks missing
    pub fn check_chunks(&self, blob_id: &Uuid, chunk_total: usize) -> Result<(), Vec<usize>> {
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

    /// Merges all chunks into a single file
    ///
    /// Note: Callers must ensure, that all chunks are present - see [`check_chunks`].
    pub fn merge_chunks(&self, blob_id: &Uuid, chunk_total: usize) -> Result<usize, io::Error> {
        let chunk_sub_dir = self.base_path.join(FS_CHUNK_DIR).join(blob_id.to_string());
        let (final_path, final_tmp) = self.blob_path(blob_id);

        let f = File::create(&final_tmp)?;
        let mut writer = BufWriter::new(f);
        let mut bytes_written = 0;
        for chunk_idx in 1..=chunk_total {
            let chunk = chunk_sub_dir.join(format!("chunk_{chunk_idx}_{chunk_total}"));
            let part_file = File::open(&chunk)?;
            let mut reader = BufReader::new(part_file);

            // Copy the content of the part file into the writer
            bytes_written += io::copy(&mut reader, &mut writer)?;
        }

        // Write blob file and cleanup chunks
        writer.flush()?;
        rename(&final_tmp, &final_path)?;
        remove_dir_all(chunk_sub_dir)?;

        Ok(bytes_written as usize)
    }
}
