use std::{
    fs::{File, create_dir, create_dir_all, read_dir, remove_dir_all, remove_file, rename},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use anyhow::Context;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use crate::metadata::{BlobMetadata, MetadataStore};

/// Sub-Directory, where all data is stored to
const FS_DATA_DIR: &str = "full";

/// Sub-Directory, where we start storing received parts, before combining them
const FS_CHUNK_DIR: &str = "chunks";

/// Controller for filesystem based local storage
///
/// Encapsulates all storage related logic, where and how we save the data.
///
/// For now we simply save everything to the disk,
/// but later more elaborate things can happen here, like connecting to s3 buckets etc.
#[derive(Debug, Clone)]
pub struct FsController {
    base_path: Arc<PathBuf>,
    metadata_store: Arc<MetadataStore>,
}

impl FsController {
    pub fn init(
        base_path: &Path,
        metadata_db_path: &Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create base directories
        create_dir_all(base_path.join(FS_DATA_DIR))?;
        create_dir_all(base_path.join(FS_CHUNK_DIR))?;

        // Initialize metadata store
        let metadata_store = MetadataStore::init(metadata_db_path)?;

        Ok(FsController {
            base_path: Arc::new(base_path.to_path_buf()),
            metadata_store: Arc::new(metadata_store),
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
    /// Note: Callers must ensure, that all chunks are present - see [`FsController::check_chunks`].
    pub fn merge_chunks(
        &self,
        blob_id: &Uuid,
        chunk_total: usize,
    ) -> Result<(usize, [u8; 32]), io::Error> {
        let chunk_sub_dir = self.base_path.join(FS_CHUNK_DIR).join(blob_id.to_string());
        let (final_path, final_tmp) = self.blob_path(blob_id);

        let f = File::create(&final_tmp)?;
        let mut writer = BufWriter::new(f);
        let mut bytes_written = 0;
        let mut hash = Sha256::new();
        for chunk_idx in 1..=chunk_total {
            let chunk = chunk_sub_dir.join(format!("chunk_{chunk_idx}_{chunk_total}"));
            let part_file = File::open(&chunk)?;
            let mut reader = BufReader::new(part_file);

            // Copy the content while updating the hash
            let mut buffer = [0u8; 8192]; // 8KB buffer
            loop {
                let bytes_read = reader.read(&mut buffer)?;
                if bytes_read == 0 {
                    break; // EOF
                }
                let data = &buffer[..bytes_read];
                hash.update(data);
                writer.write_all(data)?;
                bytes_written += bytes_read;
            }
        }

        // Write blob file and cleanup chunks
        writer.flush()?;
        let sha256_hash = hash.finalize();
        rename(&final_tmp, &final_path)?;
        remove_dir_all(chunk_sub_dir)?;

        Ok((bytes_written, sha256_hash.into()))
    }

    /// Walks through the [`FS_DATA_DIR`] to find `.tmp` files that can be deleted
    ///
    /// Uses the fs metadata to check the timestamp, when the file was last modified.
    /// If this is older than the given ttl, we return the path here.
    ///
    /// Note: The returned paths all belong to files.
    pub fn find_orphaned_tmp_files(&self, ttl_orphan_secs: u64) -> Result<Vec<PathBuf>, io::Error> {
        let mut out = Vec::new();
        for file in read_dir(self.base_path.join(FS_DATA_DIR))? {
            let file = file?;
            trace!("checking {}", file.path().display());

            // Check for .tmp extension ( in files )
            if file.path().extension().unwrap_or_default() != "tmp" || !file.file_type()?.is_file()
            {
                trace!("ignoring {}", file.path().display());
                continue;
            }

            // Check metadata to get the modified timestamp
            let meta = file.metadata()?;
            let modified = meta.modified()?;

            let now = SystemTime::now();
            if now.duration_since(modified).unwrap_or_default().as_secs() > ttl_orphan_secs {
                out.push(file.path());
            }
        }
        Ok(out)
    }

    /// Walks through the [`FS_CHUNK_DIR`] to find chunk directories that can be deleted.
    ///
    /// Uses the fs metadata to check the timestamp, when the directory and its files were last modified.
    /// If this is older than `ttl_orphan_secs`, we return the path here.
    ///
    /// Note: The returned paths all belong to directories.
    pub fn find_orphaned_chunks(&self, ttl_orphan_secs: u64) -> Result<Vec<PathBuf>, io::Error> {
        let mut out = Vec::new();
        'directory: for dir in read_dir(self.base_path.join(FS_CHUNK_DIR))? {
            let dir = dir?;
            trace!("checking {}", dir.path().display());

            // Only check directories
            if !dir.file_type()?.is_dir() {
                trace!("ignoring {}", dir.path().display());
                continue;
            }

            // Check all files in the directory
            for file in read_dir(dir.path())? {
                let file = file?;

                // Check metadata to get the modified timestamp
                let meta = file.metadata()?;
                let modified = meta.modified()?;

                let now = SystemTime::now();
                if now.duration_since(modified).unwrap_or_default().as_secs() < ttl_orphan_secs {
                    // Skip to the next directory entry,
                    // as this directory contains at least one file that is not orphaned
                    continue 'directory;
                }
            }
            // If we end up here, all files inside the directory are orphaned,
            // so the directory itself is considered orphaned
            out.push(dir.path());
        }
        Ok(out)
    }

    /// Store metadata for a blob
    pub fn store_metadata(&self, metadata: &BlobMetadata) -> Result<(), rusqlite::Error> {
        self.metadata_store.store_metadata(metadata)?;
        Ok(())
    }

    /// Retrieve metadata for a blob
    pub fn get_metadata(&self, blob_id: &Uuid) -> Result<Option<BlobMetadata>, rusqlite::Error> {
        Ok(self.metadata_store.get_metadata(blob_id)?)
    }

    #[allow(unused)]
    /// Delete metadata for a blob
    pub fn delete_metadata(&self, blob_id: &Uuid) -> Result<bool, rusqlite::Error> {
        Ok(self.metadata_store.delete_metadata(blob_id)?)
    }

    /// Cleanup orphaned metadata entries
    pub fn cleanup_orphaned_metadata(&self) -> Result<usize, rusqlite::Error> {
        // Get all blob IDs with metadata
        let blob_ids = self.metadata_store.get_all_blob_ids()?;
        let mut deleted_count = 0;

        // Check if the blob files still exist
        for blob_id in blob_ids {
            let (blob_path, _) = self.blob_path(&blob_id);
            if !blob_path.exists() {
                // Blob file doesn't exist, remove its metadata
                if self.metadata_store.delete_metadata(&blob_id)? {
                    debug!("🧹 Removing metadata of {}", blob_id);
                    deleted_count += 1;
                }
            }
        }

        Ok(deleted_count)
    }
}

/// Helper function for the cleanup routine.
///
/// Spawns a blocking task for the fs operations and fetched all errors,
/// since we don't want the cleanup task to return and shutdown.
pub async fn cleanup_routine(fs_controller: FsController, ttl_orphan_secs: u64) {
    let blocking = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let orphaned_files = fs_controller.find_orphaned_tmp_files(ttl_orphan_secs)?;
        for file in &orphaned_files {
            debug!("🧹 Removing {}", file.display());
            remove_file(file)?;
        }

        let orphaned_dirs = fs_controller.find_orphaned_chunks(ttl_orphan_secs)?;
        for dir in &orphaned_dirs {
            debug!("🧹 Removing {}", dir.display());
            remove_dir_all(dir)?;
        }

        // Clean up orphaned metadata entries
        let orphaned_metadata = fs_controller
            .cleanup_orphaned_metadata()
            .context("Failed to cleanup orphaned metadata")?;

        info!(
            "🧹 Removed {} orphaned files, {} orphaned chunk directories, and {} orphaned metadata entries",
            orphaned_files.len(),
            orphaned_dirs.len(),
            orphaned_metadata
        );
        Ok(())
    });
    match blocking.await {
        Ok(Ok(())) => (),
        Ok(Err(e)) => warn!("🧹 Error while executing cleanup routine: {e}"),
        Err(e) => error!("❌ Error while waiting for cleanup task: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Read, thread::sleep, time::Duration};

    use tempfile::{TempDir, tempdir};

    use super::*;

    fn read_to_string(p: &std::path::Path) -> String {
        let mut s = String::new();
        let mut f = File::open(p).expect("open");
        f.read_to_string(&mut s).expect("read");
        s
    }

    #[test]
    fn init_creates_required_directories() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        let metadata_db = base.join("metadata.db");
        let fs = FsController::init(base, &metadata_db).expect("init fs");
        let full = base.join("full");
        let chunks = base.join("chunks");

        assert!(full.is_dir(), "full/ should exist and be a directory");
        assert!(chunks.is_dir(), "chunks/ should exist and be a directory");

        // Sanity: blob_path points into full/
        let id = Uuid::new_v4();
        let (final_path, tmp_path) = fs.blob_path(&id);
        assert!(final_path.starts_with(&full));
        assert!(tmp_path.starts_with(&full));
        assert!(final_path.file_name().unwrap().to_str().unwrap() == id.to_string());
        assert!(
            tmp_path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(".tmp")
        );
    }

    #[test]
    fn chunk_path_creates_directory_and_returns_paths() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        let metadata_db = base.join("metadata.db");
        let fs = FsController::init(base, &metadata_db).expect("init fs");
        let id = Uuid::new_v4();

        // Call chunk_path for the first time; it should create chunks/<uuid> dir
        let (full, tmp) = fs.chunk_path(&id, 1, 3).expect("chunk path");
        assert!(full.parent().unwrap().is_dir(), "chunk subdir should exist");
        assert!(full.file_name().unwrap().to_str().unwrap() == "chunk_1_3");
        assert!(tmp.file_name().unwrap().to_str().unwrap() == "chunk_1_3.tmp");

        // Simulate a broken state where chunks/<uuid> is a file, not a dir
        let broken = base.join("chunks").join(id.to_string());
        if broken.exists() {
            fs::remove_dir_all(&broken).ok();
        }
        File::create(&broken).expect("create broken file");
        let (_full2, _tmp2) = fs.chunk_path(&id, 2, 3).expect("chunk path after fix");
        assert!(
            broken.is_dir(),
            "chunk_path should replace a file with a directory"
        );
    }

    #[test]
    fn check_chunks_reports_missing_correctly_and_ok_when_complete() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        let metadata_db = base.join("metadata.db");
        let fs = FsController::init(base, &metadata_db).expect("init fs");
        let id = Uuid::new_v4();
        let total = 4;

        // No directory yet -> should report all missing
        let missing = fs.check_chunks(&id, total).expect_err("should be missing");
        assert_eq!(missing, vec![1, 2, 3, 4]);

        // Create only some parts
        for i in [1usize, 3].iter().copied() {
            let (p, _tmp) = fs.chunk_path(&id, i, total).expect("paths");
            File::create(p).expect("create part");
        }
        let missing = fs.check_chunks(&id, total).expect_err("still missing");
        assert_eq!(missing, vec![2, 4]);

        // Create remaining parts -> Ok(())
        for i in [2usize, 4].iter().copied() {
            let (p, _tmp) = fs.chunk_path(&id, i, total).expect("paths");
            File::create(p).expect("create part");
        }
        fs.check_chunks(&id, total).expect("all present");
    }

    #[test]
    fn merge_chunks_concatenates_and_cleans_up() {
        let dir = tempdir().unwrap();
        let base = dir.path();

        let metadata_db = base.join("metadata.db");
        let fs = FsController::init(base, &metadata_db).expect("init fs");
        let id = Uuid::new_v4();
        let total = 3;

        // Create chunk files with known content
        let contents = ["alpha", "beta", "gamma"];
        for (idx, data) in contents.iter().enumerate() {
            let (p, _tmp) = fs.chunk_path(&id, idx + 1, total).expect("paths");
            let mut f = File::create(&p).expect("create part");
            f.write_all(data.as_bytes()).expect("write");
        }

        // Merge
        let (bytes, _sha256) = fs.merge_chunks(&id, total).expect("merge");
        let (final_path, _tmp_path) = fs.blob_path(&id);

        assert!(final_path.is_file(), "final blob should exist");
        assert_eq!(
            read_to_string(&final_path),
            contents.concat(),
            "merged content should be concatenation in order"
        );

        let expected_len: usize = contents.iter().map(|s| s.len()).sum();
        assert_eq!(bytes, expected_len, "returned bytes_written should match");

        // Chunks directory should be removed
        let chunk_subdir = base.join("chunks").join(id.to_string());
        assert!(
            !chunk_subdir.exists(),
            "chunk directory should be deleted after merge"
        );
    }

    #[test]
    fn find_orphaned_tmp_files_filters_by_extension_and_ttl() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let metadata_db = base.join("metadata.db");
        let fs = FsController::init(base, &metadata_db).expect("init fs");

        // Create one tmp file and one regular file in full/
        let (final_path, tmp_path) = fs.blob_path(&Uuid::new_v4());

        let _tmp = File::create(&tmp_path).expect("create tmp");
        let mut f = File::create(&final_path).expect("create regular");
        f.write_all(b"live").unwrap();

        // Sleep one second, so 1 > 0 in ttl comparison
        sleep(Duration::from_secs(1));

        // With ttl=0, anything older than 0s is orphaned; the `.tmp` should be returned, the other not
        let orphans = fs.find_orphaned_tmp_files(0).expect("scan");
        assert!(
            orphans.iter().any(|p| p == &tmp_path),
            "should include tmp file"
        );
        assert!(
            !orphans.iter().any(|p| p == &final_path),
            "should not include non-tmp files"
        );
    }

    #[test]
    fn find_orphaned_chunks_behaves_with_ttl() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let metadata_db = base.join("metadata.db");
        let fs = FsController::init(base, &metadata_db).expect("init fs");

        // Create two different chunk directories with a file inside each
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let (p1, _t1) = fs.chunk_path(&id1, 1, 1).expect("paths");
        File::create(&p1).expect("create chunk 1");
        let (p2, _t2) = fs.chunk_path(&id2, 1, 1).expect("paths");
        File::create(&p2).expect("create chunk 2");

        // ttl = 0 -> both are orphaned
        let orphaned_now = fs.find_orphaned_chunks(0).expect("scan ttl0");
        let sub1 = base.join("chunks").join(id1.to_string());
        let sub2 = base.join("chunks").join(id2.to_string());
        assert!(orphaned_now.contains(&sub1));
        assert!(orphaned_now.contains(&sub2));

        // ttl = very large -> nothing is orphaned (everything is "too recent")
        let none = fs
            .find_orphaned_chunks(u64::MAX / 2)
            .expect("scan large ttl");
        assert!(
            none.is_empty(),
            "no chunk dirs should be orphaned with huge ttl"
        );
    }

    // Build a minimal FsController on a temp dir
    fn make_fs() -> (FsController, TempDir) {
        let dir = tempdir().expect("tempdir");
        let metadata_db = dir.path().join("metadata.db");
        // Create the base structure via FsController::init
        (
            FsController::init(dir.path(), &metadata_db).expect("init fs"),
            dir,
        )
    }

    /// Create a normal (non-tmp) blob and a tmp blob in `full/`, plus a chunk dir
    /// with files; return their paths for assertions.
    fn seed_files(fs: &FsController) -> (PathBuf, PathBuf, PathBuf) {
        let id_full = Uuid::new_v4();
        let id_tmp = Uuid::new_v4();
        let id_chunks = Uuid::new_v4();

        // Normal blob
        let (full_path, _full_tmp) = fs.blob_path(&id_full);
        {
            let mut f = File::create(&full_path).expect("create full file");
            f.write_all(b"live").unwrap();
        }

        // .tmp blob
        let (_tmp_final, tmp_path) = fs.blob_path(&id_tmp);
        {
            let mut f = File::create(&tmp_path).expect("create tmp file");
            f.write_all(b"tmp").unwrap();
        }

        // Chunk dir with two files
        let (c1, _t1) = fs.chunk_path(&id_chunks, 1, 2).expect("chunk path 1");
        let (c2, _t2) = fs.chunk_path(&id_chunks, 2, 2).expect("chunk path 2");
        File::create(&c1).unwrap();
        File::create(&c2).unwrap();

        // Return: normal file path, tmp file path, chunk subdir path
        let chunk_subdir = fs
            .clone()
            .base_path
            .join("chunks")
            .join(id_chunks.to_string());
        (full_path, tmp_path, chunk_subdir)
    }

    #[tokio::test]
    async fn cleanup_routine_removes_orphans_with_ttl_0() {
        let (fs, _guard) = make_fs();
        let (full_path, tmp_path, chunk_subdir) = seed_files(&fs);

        // Ensure mtime is at least 1s old so ttl=0 will catch them
        sleep(Duration::from_secs(1));

        // Run cleanup with ttl=0 (anything older than now)
        cleanup_routine(fs.clone(), 0).await;

        // .tmp should be gone
        assert!(
            !tmp_path.exists(),
            "orphan .tmp should be deleted by cleanup"
        );
        // chunk dir should be gone
        assert!(
            !chunk_subdir.exists(),
            "orphan chunk directory should be deleted"
        );
        // normal file should remain
        assert!(full_path.exists(), "non-tmp full blob should remain");
    }

    #[tokio::test]
    async fn cleanup_routine_respects_large_ttl_keeps_recent() {
        let (fs, _guard) = make_fs();
        let (full_path, tmp_path, chunk_subdir) = seed_files(&fs);

        // Run cleanup with a huge TTL so nothing counts as orphaned yet
        cleanup_routine(fs.clone(), u64::MAX / 2).await;

        assert!(tmp_path.exists(), "recent tmp should not be deleted");
        assert!(
            chunk_subdir.exists(),
            "recent chunk dir should not be deleted"
        );
        assert!(full_path.exists(), "normal file should remain");
    }
}
