use std::{
    fs::{File, create_dir, create_dir_all, read_dir, remove_dir_all, remove_file},
    io::{self, BufReader, BufWriter, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use anyhow::Context;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use crate::utils::calculate_relative_path;
use crate::{
    metadata::{BlobMetadata, MetadataStore},
    utils::calculate_file_hash,
};

/// Sub-Directory, where all buckets are stored
pub const FS_BUCKETS_DIR: &str = "buckets";

/// Sub-Directory, where we start storing received parts, before combining them
const FS_CHUNK_DIR: &str = "chunks";

/// Sub-Directory for content-addressable storage (deduplication)
const FS_CONTENT_DIR: &str = "content";

/// Legacy directory (for migration)
const FS_LEGACY_DATA_DIR: &str = "full";

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
    pub create_symlinks: bool,
}

impl FsController {
    pub fn init(
        base_path: &Path,
        metadata_db_path: &Path,
        create_symlinks: bool,
    ) -> Result<Self, anyhow::Error> {
        // Create base directories
        create_dir_all(base_path.join(FS_BUCKETS_DIR))?;
        create_dir_all(base_path.join(FS_CHUNK_DIR))?;
        create_dir_all(base_path.join(FS_CONTENT_DIR))?;

        // Initialize metadata store
        let metadata_store = MetadataStore::init(metadata_db_path)?;

        let controller = FsController {
            base_path: Arc::new(base_path.to_path_buf()),
            metadata_store: Arc::new(metadata_store),
            create_symlinks,
        };

        // Run filesystem migration if needed
        controller.migrate_to_bucket_fs()?;

        // Check, if metadata-db is in sync with filesystem
        controller.check_metadata_consistency()?;

        // Run content-addressable migration if needed
        controller.migrate_to_content_addressable()?;

        Ok(controller)
    }

    /// Migrate from old flat structure to bucket-based structure
    fn migrate_to_bucket_fs(&self) -> Result<(), io::Error> {
        info!("🔄 Check if filesystem requires migration...");
        let old_full_dir = self.base_path.join(FS_LEGACY_DATA_DIR);
        let new_buckets_dir = self.base_path.join(FS_BUCKETS_DIR);
        let default_bucket_dir = new_buckets_dir.join("default");

        // Step 1: Check, if we actually need a migration
        if default_bucket_dir.exists() {
            // No, we already have a buckets directory
            // -> We *could* do a consistency check here, if the files are all properly migrated
            return Ok(());
        }

        if !old_full_dir.exists() {
            // Nothing to migrate
            return Ok(());
        }

        // Step 2: Migrate files to new bucket dir
        info!("🔄 Migrating filesystem to bucket-based storage...");

        // Create default bucket directory
        create_dir_all(&default_bucket_dir)?;

        let mut migrated_count = 0;
        for entry in read_dir(&old_full_dir)? {
            let entry = entry?;
            let old_path = entry.path();
            let file_name = entry.file_name();
            let new_path = default_bucket_dir.join(&file_name);
            // Skip if already exists in new location
            if new_path.exists() {
                debug!(
                    "Skipping (already exists) {} -> {}",
                    old_path.display(),
                    new_path.display()
                );
                continue;
            }
            debug!("Moving {} -> {}", old_path.display(), new_path.display());
            std::fs::rename(old_path, new_path)?;
            migrated_count += 1;
        }

        if migrated_count > 0 {
            info!(
                "✅ Migrated {} files to new bucket structure",
                migrated_count
            );
        } else {
            info!(
                "✅ Migration was performed before. You can delete the old 'full' directory to supress this message.",
            );
        }
        Ok(())
    }

    fn check_metadata_consistency(&self) -> Result<(), anyhow::Error> {
        info!("🔄 Check metadata consistency...");
        let buckets_dir = self.base_path.join(FS_BUCKETS_DIR);

        // Iterate over all buckets
        let mut bucket_cnt = 0;
        let mut blob_cnt = 0;
        for entry in read_dir(buckets_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                debug!("Ignoring non-bucket-directory: {}", path.display());
                continue;
            }
            // Extract bucket-name from path
            let bucket_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.to_owned())
                .unwrap_or_default();

            // Iterate over all files in the bucket
            let mut blob_bucket_cnt = 0;
            for blob in read_dir(path)? {
                let blob = blob?;
                let blob_path = blob.path();
                if !blob_path.is_file() && !blob_path.is_symlink() {
                    debug!(
                        "Ignoring non blob-file in bucket directory: {}",
                        blob_path.display()
                    );
                    continue;
                }
                let blob_id = match blob_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<Uuid>().ok())
                {
                    Some(id) => id,
                    None => {
                        debug!("Failed to parse blob-id from path: {}", blob_path.display());
                        continue;
                    }
                };
                // Check, if metadata is present for this file
                if let Some(_meta) = self.metadata_store.get_metadata(&bucket_name, &blob_id)? {
                    /* NOTE:
                     * We could do a double check,
                     * if the metadata is actually correct,
                     * but for now we assume that it is.
                     * */
                    continue;
                }

                // Re-calculate metadata for blob
                let file_size = blob_path.metadata()?.size();
                let sha256_hash = hex::encode(calculate_file_hash(&blob_path)?);
                let meta = BlobMetadata::new(&bucket_name, blob_id)
                    .with_file_size(file_size as i64)
                    .with_sha256_hash(sha256_hash);
                debug!("Recalculated metadata for {}", blob_path.display());
                self.metadata_store.store_metadata(&meta)?;
                blob_bucket_cnt += 1;
            }
            if blob_bucket_cnt != 0 {
                bucket_cnt += 1;
                blob_cnt += blob_bucket_cnt;
            }
        }
        if blob_cnt > 0 {
            info!("🔄 Rebuilt metadata for {blob_cnt} entries in {bucket_cnt} buckets");
        } else {
            info!("🔄 Metadata-DB is consistent with filesystem");
        }
        Ok(())
    }

    /// Migrate existing blobs to content-addressable storage
    fn migrate_to_content_addressable(&self) -> Result<(), anyhow::Error> {
        info!("🔄 Checking for blobs to migrate to content-addressable storage...");
        let all_blobs = self.metadata_store.get_all_blob_ids()?;
        let mut migrated_count = 0;
        let mut dedup_count = 0;
        debug!("-- all-blobs: {}", all_blobs.len());

        for (bucket, blob_id) in all_blobs {
            let (blob_path, _) = self.blob_path(&bucket, &blob_id);
            debug!(
                "-- looking at: {blob_id}, {bucket} in {}",
                blob_path.display()
            );

            let metadata = self
                .metadata_store
                .get_metadata(&bucket, &blob_id)?
                .context("expect metadata to be present")?;

            let hash_str = metadata
                .sha256_hash
                .as_ref()
                .context("expect hash to be present")?;
            let hash_bytes = hex::decode(&hash_str)
                .ok()
                .map(|b| {
                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(&b);
                    hash_array
                })
                .context("expect hash to be 32 bytes")?;

            // Skip if blob_path doesn't exist - handle symlinks if configured
            if !blob_path.exists() {
                // NOTE: Double check, if the content path exists.
                // If not, there is nothing we can do - except deleting the blob-metadata.
                let content_path = self.content_path(&hash_bytes);
                if content_path.exists() {
                    debug!("-- check symlink & skip: {}", blob_path.display());
                    self.handle_symlinks(&bucket, &blob_id, &hash_bytes);
                } else {
                    debug!(%blob_id, "-- found broken relation - blob has no content or blob-file attached to it. Deleting metadata...");
                    self.metadata_store.delete_metadata(&bucket, &blob_id)?;
                }
                continue;
            }

            // Check if blob_path is a regular file (needs migration) or symlink (already migrated)
            let path_metadata = std::fs::symlink_metadata(&blob_path)?;

            if path_metadata.is_symlink() {
                debug!("-- skipping - symlink exists");
                continue;
            }

            // Not a symlink, check if it's a regular file that needs migration
            if !path_metadata.is_file() {
                debug!("-- skipping - not-a-file");
                continue;
            }

            // Calculate hash from existing file
            let hash = calculate_file_hash(&blob_path)?;
            let hash_hex = hex::encode(hash);
            let content_path = self.content_path(&hash);

            // Get file size
            let file_size = std::fs::metadata(&blob_path)?.len() as i64;

            // Check if content already exists (dedup during migration!)
            let renamed_file = if content_path.exists() {
                // Content exists, just increment refcount
                dedup_count += 1;
                false
            } else {
                // Move content to content/ directory
                // Try hard link first (instant, no copy), fall back to copy
                if let Err(e) = std::fs::rename(&blob_path, &content_path) {
                    warn!(%blob_id, "failed to create symlink: {e}");
                }
                true
            };

            // Update metadata (just to be sure)
            let metadata = metadata
                .with_sha256_hash(hash_hex.clone())
                .with_file_size(file_size);

            self.metadata_store.store_metadata(&metadata)?;

            // Only increment content refcount
            self.metadata_store
                .increment_content_ref(&hash_hex, file_size)?;

            // Remove old blob file if it hasn't been renamed
            if !renamed_file {
                std::fs::remove_file(&blob_path)?;
            }

            // Create symlink if configured
            self.handle_symlinks(&metadata.bucket, &blob_id, &hash);

            migrated_count += 1;

            if migrated_count % 100 == 0 {
                info!("Migration progress: {} blobs processed...", migrated_count);
            }
        }

        if migrated_count > 0 {
            info!(
                "✅ Migrated {} blobs to content-addressable storage",
                migrated_count
            );
            if dedup_count > 0 {
                info!("🔗 Deduplicated {} blobs during migration", dedup_count);
            }
        } else {
            info!("✅ No migrations required.");
        }
        Ok(())
    }

    /// Returns a copy of the pointer to the metadata store
    pub fn get_metadata_store(&self) -> Arc<MetadataStore> {
        self.metadata_store.clone()
    }

    /// Returns the path and tmp-path for a storage blob in a bucket
    pub fn blob_path(&self, bucket: &str, blob_id: &Uuid) -> (PathBuf, PathBuf) {
        let bucket_dir = self.base_path.join(FS_BUCKETS_DIR).join(bucket);
        let full = bucket_dir.join(blob_id.to_string());
        let tmp = bucket_dir.join(format!("{blob_id}.tmp"));
        (full, tmp)
    }

    /// Ensure a bucket directory exists
    pub fn ensure_bucket_dir(&self, bucket: &str) -> io::Result<()> {
        let bucket_dir = self.base_path.join(FS_BUCKETS_DIR).join(bucket);
        create_dir_all(bucket_dir)
    }

    /// Get the path to a bucket directory
    pub fn bucket_dir(&self, bucket: &str) -> PathBuf {
        self.base_path.join(FS_BUCKETS_DIR).join(bucket)
    }

    /// Get the path to content storage file (content-addressable by hash)
    pub fn content_path(&self, hash: &[u8; 32]) -> PathBuf {
        let hash_hex = hex::encode(hash);
        self.base_path.join(FS_CONTENT_DIR).join(hash_hex)
    }

    /// Get the path to content storage file from hex-encoded hash string
    pub fn content_path_from_hex(&self, hash_hex: &str) -> PathBuf {
        self.base_path.join(FS_CONTENT_DIR).join(hash_hex)
    }

    /// Get the directory path for content storage
    pub fn content_dir(&self) -> PathBuf {
        self.base_path.join(FS_CONTENT_DIR)
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

    /// Merges all chunks into a temporary file
    ///
    /// Note: Callers must ensure, that all chunks are present - see [`FsController::check_chunks`].
    /// Returns (tmp_path, bytes_written, sha256_hash). Caller must handle final placement.
    pub fn merge_chunks(
        &self,
        bucket: &str,
        blob_id: &Uuid,
        chunk_total: usize,
    ) -> Result<(PathBuf, usize, [u8; 32]), io::Error> {
        let chunk_sub_dir = self.base_path.join(FS_CHUNK_DIR).join(blob_id.to_string());
        let (_final_path, final_tmp) = self.blob_path(bucket, blob_id);

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

        // Flush and cleanup chunks
        writer.flush()?;
        let sha256_hash = hash.finalize();
        remove_dir_all(chunk_sub_dir)?;

        Ok((final_tmp, bytes_written, sha256_hash.into()))
    }

    /// Optionally create a symlink from the bucket dir to the content
    ///
    /// Does nothing if `create_symlinks` is set to `false`.
    /// Since symlinks are simply there for human visibility, this function will not fail,
    /// even if the symlink creation failed.
    pub fn handle_symlinks(&self, bucket: &str, blob_id: &Uuid, sha256: &[u8; 32]) {
        if !self.create_symlinks {
            return;
        }
        #[cfg(unix)]
        {
            let handle_links = || {
                let symlink_path = self.blob_path(bucket, blob_id).0;
                let content_path = self.content_path(sha256);

                // Calculate the relative path dynamically
                let relative_content_path = calculate_relative_path(&symlink_path, &content_path);

                // Check, if the symlink already exists, and early return if it does and points to the correct path
                if symlink_path.exists() {
                    // Check, if the symlink already exists or must be created
                    let symlink_metadata = std::fs::symlink_metadata(&symlink_path)?;
                    if symlink_metadata.is_symlink() {
                        // Okay, it exists, now check if the content path exists aswell
                        let target_path = std::fs::read_link(&symlink_path)?;
                        if target_path == content_path {
                            return Ok(());
                        }
                    }
                    debug!(
                        "Removing old and broken symlink: {}",
                        symlink_path.display(),
                    );
                    std::fs::remove_file(&symlink_path)?;
                }

                debug!(
                    "Creating symlink: {} -> {} (relative: {})",
                    symlink_path.display(),
                    content_path.display(),
                    relative_content_path.display()
                );
                std::os::unix::fs::symlink(&relative_content_path, &symlink_path)
            };
            if let Err(e) = handle_links() {
                // Continue - blob still works without symlink
                warn!(%blob_id, "Failed to create symlink: {}", e);
            }
        }
    }

    /// Walks through all bucket directories to find `.tmp` files that can be deleted
    ///
    /// Uses the fs metadata to check the timestamp, when the file was last modified.
    /// If this is older than the given ttl, we return the path here.
    ///
    /// Note: The returned paths all belong to files.
    pub fn find_orphaned_tmp_files(&self, ttl_orphan_secs: u64) -> Result<Vec<PathBuf>, io::Error> {
        let mut out = Vec::new();
        let buckets_dir = self.base_path.join(FS_BUCKETS_DIR);

        // Ensure buckets directory exists
        if !buckets_dir.exists() {
            return Ok(out);
        }

        // Iterate through all bucket directories
        for bucket_entry in read_dir(&buckets_dir)? {
            let bucket_entry = bucket_entry?;
            let bucket_path = bucket_entry.path();

            // Skip if not a directory
            if !bucket_path.is_dir() {
                continue;
            }

            // Check all files in this bucket
            for file in read_dir(&bucket_path)? {
                let file = file?;
                trace!("checking {}", file.path().display());

                // Check for .tmp extension ( in files )
                if file.path().extension().unwrap_or_default() != "tmp"
                    || !file.file_type()?.is_file()
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

    /// Retrieve metadata for a blob in a bucket
    pub fn get_metadata(
        &self,
        bucket: &str,
        blob_id: &Uuid,
    ) -> Result<Option<BlobMetadata>, rusqlite::Error> {
        self.metadata_store.get_metadata(bucket, blob_id)
    }

    #[allow(unused)]
    /// Delete metadata for a blob in a bucket
    /// Returns (deleted: bool, content_hash: Option<String>, new_refcount: i64)
    pub fn delete_metadata(
        &self,
        bucket: &str,
        blob_id: &Uuid,
    ) -> Result<(bool, Option<String>, i64), rusqlite::Error> {
        self.metadata_store.delete_metadata(bucket, blob_id)
    }

    /// Delete a blob from both filesystem and metadata store
    pub fn delete_blob(
        &self,
        bucket: &str,
        blob_id: &Uuid,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let (blob_path, blob_tmp) = self.blob_path(bucket, blob_id);

        // Delete metadata (also decrements refcount)
        let (metadata_existed, content_hash, new_refcount) =
            self.metadata_store.delete_metadata(bucket, blob_id)?;

        if !metadata_existed {
            return Ok(false);
        }

        // Delete symlink if it exists
        #[cfg(unix)]
        if self.create_symlinks && blob_path.exists() {
            let _ = std::fs::remove_file(&blob_path);
        }

        // Clean up .tmp file if it exists
        if blob_tmp.exists() {
            let _ = std::fs::remove_file(&blob_tmp);
        }

        // If content refcount is 0, delete the physical content file
        if new_refcount == 0
            && let Some(hash) = content_hash
        {
            let content_path = self.content_path_from_hex(&hash);
            if content_path.exists() {
                std::fs::remove_file(&content_path)?;
                debug!(hash = %hash, "deleted content file (refcount=0)");
            }

            // Clean up content_refs entry
            let _ = self.metadata_store.delete_content_ref(&hash);
        }

        Ok(true)
    }

    /// Cleanup orphaned metadata entries
    pub fn cleanup_orphaned_metadata(&self) -> Result<usize, rusqlite::Error> {
        // Get all blob IDs with metadata
        let blob_ids = self.metadata_store.get_all_blob_ids()?;
        let mut deleted_count = 0;

        // Check if the content files still exist
        for (bucket, blob_id) in blob_ids {
            if let Some(metadata) = self.metadata_store.get_metadata(&bucket, &blob_id)? {
                // Check both possible locations for the content
                let mut content_exists = false;

                // First check content-addressed storage (if hash is available)
                if let Some(hash) = &metadata.sha256_hash {
                    let content_path = self.content_path_from_hex(hash);
                    if content_path.exists() {
                        content_exists = true;
                    }
                }

                // Also check old blob path (could be unmigrated or migration in progress)
                if !content_exists {
                    let (blob_path, _) = self.blob_path(&bucket, &blob_id);
                    if blob_path.exists() {
                        content_exists = true;
                    }
                }

                if !content_exists {
                    // Content file doesn't exist in either location, remove its metadata
                    let (deleted, _, _) = self.metadata_store.delete_metadata(&bucket, &blob_id)?;
                    if deleted {
                        debug!("🧹 Removing orphaned metadata of {}/{}", bucket, blob_id);
                        deleted_count += 1;
                    }
                }
            }
        }

        Ok(deleted_count)
    }

    /// Cleanup orphaned content files and zombie refs
    pub fn cleanup_orphaned_content(&self, ttl_orphan_secs: u64) -> Result<usize, anyhow::Error> {
        let mut cleaned_count = 0;
        let content_dir = self.content_dir();

        if !content_dir.exists() {
            return Ok(0);
        }

        // 1. Find content files without refs in content_refs table
        for entry in read_dir(&content_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let hash = entry.file_name().to_string_lossy().to_string();

            // Check if ref exists in content_refs table
            if !self.metadata_store.content_ref_exists(&hash)? {
                // Check if file is old enough (ttl)
                let metadata = std::fs::metadata(&path)?;
                if let Ok(modified) = metadata.modified()
                    && let Ok(elapsed) = modified.elapsed()
                    && elapsed.as_secs() > ttl_orphan_secs
                {
                    debug!("🧹 Removing orphaned content file: {}", hash);
                    std::fs::remove_file(&path)?;
                    cleaned_count += 1;
                }
            }
        }

        // 2. Clean up zombie refs (refcount=0)
        let zombie_refs = self.metadata_store.get_zombie_refs()?;
        for hash in zombie_refs {
            let content_path = self.content_path_from_hex(&hash);
            if content_path.exists() {
                debug!("🧹 Removing zombie content file: {}", hash);
                std::fs::remove_file(&content_path)?;
                cleaned_count += 1;
            }

            // Clean up content_refs entry
            self.metadata_store.delete_content_ref(&hash)?;
        }

        Ok(cleaned_count)
    }

    /// Cleanup orphaned symlinks (where metadata doesn't exist)
    #[cfg(unix)]
    pub fn cleanup_orphaned_symlinks(&self) -> Result<usize, anyhow::Error> {
        if !self.create_symlinks {
            return Ok(0);
        }

        let mut cleaned_count = 0;
        let buckets_dir = self.base_path.join(FS_BUCKETS_DIR);

        if !buckets_dir.exists() {
            return Ok(0);
        }

        // Iterate through all bucket directories
        for bucket_entry in read_dir(&buckets_dir)? {
            let bucket_entry = bucket_entry?;
            if !bucket_entry.path().is_dir() {
                continue;
            }

            let bucket = bucket_entry.file_name().to_string_lossy().to_string();

            // Check all files in bucket directory
            for entry in read_dir(bucket_entry.path())? {
                let entry = entry?;
                let path = entry.path();
                // Check if it's a symlink
                if !path.is_symlink() {
                    debug!("found non-symlink in bucket directory - ignoring");
                    continue;
                }

                // Try to parse blob_id from filename
                let filename = match path.file_name() {
                    Some(f) => f,
                    None => continue,
                };
                let blob_id = match filename.to_string_lossy().parse::<Uuid>() {
                    Ok(id) => id,
                    Err(e) => {
                        debug!("Failed to parse blob-id from symlink: {e}");
                        continue;
                    }
                };
                // Check if metadata exists
                if self
                    .metadata_store
                    .get_metadata(&bucket, &blob_id)?
                    .is_none()
                {
                    debug!("🧹 Removing orphaned symlink: {}/{}", bucket, blob_id);
                    std::fs::remove_file(&path)?;
                    cleaned_count += 1;
                }
            }
        }

        Ok(cleaned_count)
    }

    /// No-op on non-Unix systems
    #[cfg(not(unix))]
    pub fn cleanup_orphaned_symlinks(&self) -> Result<usize, anyhow::Error> {
        Ok(0)
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

        // Clean up orphaned content files and zombie refs
        let orphaned_content = fs_controller
            .cleanup_orphaned_content(ttl_orphan_secs)
            .context("Failed to cleanup orphaned content")?;

        // Clean up orphaned symlinks
        let orphaned_symlinks = fs_controller
            .cleanup_orphaned_symlinks()
            .context("Failed to cleanup orphaned symlinks")?;

        info!(
            "🧹 Removed {} orphaned files, {} orphaned chunk directories, {} orphaned metadata entries, {} orphaned content files, and {} orphaned symlinks",
            orphaned_files.len(),
            orphaned_dirs.len(),
            orphaned_metadata,
            orphaned_content,
            orphaned_symlinks
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
        let fs = FsController::init(base, &metadata_db, false).expect("init fs");
        let buckets = base.join("buckets");
        let chunks = base.join("chunks");

        assert!(buckets.is_dir(), "buckets/ should exist and be a directory");
        assert!(chunks.is_dir(), "chunks/ should exist and be a directory");

        // Sanity: blob_path points into buckets/<bucket>/
        let bucket = "test";
        let id = Uuid::new_v4();
        let (final_path, tmp_path) = fs.blob_path(bucket, &id);
        let bucket_dir = buckets.join(bucket);
        assert!(final_path.starts_with(&bucket_dir));
        assert!(tmp_path.starts_with(&bucket_dir));
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
        let fs = FsController::init(base, &metadata_db, false).expect("init fs");
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
        let fs = FsController::init(base, &metadata_db, false).expect("init fs");
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
        let fs = FsController::init(base, &metadata_db, false).expect("init fs");
        let id = Uuid::new_v4();
        let total = 3;

        // Create chunk files with known content
        let contents = ["alpha", "beta", "gamma"];
        for (idx, data) in contents.iter().enumerate() {
            let (p, _tmp) = fs.chunk_path(&id, idx + 1, total).expect("paths");
            let mut f = File::create(&p).expect("create part");
            f.write_all(data.as_bytes()).expect("write");
        }

        // Ensure bucket directory exists
        let bucket = "default";
        fs.ensure_bucket_dir(bucket).expect("create bucket dir");

        // Merge
        let (tmp_path, bytes, _sha256) = fs.merge_chunks(bucket, &id, total).expect("merge");

        // Note: merge_chunks now returns temp file path - actual placement happens in server.rs
        // For test purposes, we can check the tmp file exists and has correct content
        assert_eq!(
            read_to_string(&tmp_path),
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
        let fs = FsController::init(base, &metadata_db, false).expect("init fs");

        // Create one tmp file and one regular file in default bucket
        let bucket = "default";
        fs.ensure_bucket_dir(bucket).expect("create bucket dir");
        let (final_path, tmp_path) = fs.blob_path(bucket, &Uuid::new_v4());

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
        let fs = FsController::init(base, &metadata_db, false).expect("init fs");

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
            FsController::init(dir.path(), &metadata_db, false).expect("init fs"),
            dir,
        )
    }

    /// Create a normal (non-tmp) blob and a tmp blob in bucket directory, plus a chunk dir
    /// with files; return their paths for assertions.
    fn seed_files(fs: &FsController) -> (PathBuf, PathBuf, PathBuf) {
        let bucket = "default";
        let id_full = Uuid::new_v4();
        let id_tmp = Uuid::new_v4();
        let id_chunks = Uuid::new_v4();

        // Ensure bucket directory exists
        fs.ensure_bucket_dir(bucket).expect("create bucket dir");

        // Normal blob
        let (full_path, _full_tmp) = fs.blob_path(bucket, &id_full);
        {
            let mut f = File::create(&full_path).expect("create full file");
            f.write_all(b"live").unwrap();
        }

        // .tmp blob
        let (_tmp_final, tmp_path) = fs.blob_path(bucket, &id_tmp);
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
