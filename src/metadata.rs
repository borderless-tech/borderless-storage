use std::path::Path;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, Result as SqliteResult, params};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

/// Information about a bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bucket {
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub object_count: i64,
    pub total_size: i64,
}

/// Statistics for a single bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketStats {
    pub name: String,
    pub object_count: i64,
    pub logical_size: i64,          // Size as if no deduplication
    pub logical_size_human: String, // Human-readable size
}

/// Comprehensive storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub buckets: Vec<BucketStats>,
    pub total_objects: i64,
    pub total_logical_size: i64,
    pub total_logical_size_human: String,
    pub unique_content_count: i64,
    pub actual_storage_size: i64,
    pub actual_storage_size_human: String,
    pub total_references: i64,
    pub deduplication_ratio: f64,
    pub deduplication_percentage: String,
    pub space_saved: i64,
    pub space_saved_human: String,
}

/// Metadata associated with a blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub bucket: String,
    pub blob_id: Uuid,
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub file_size: Option<i64>,
    pub sha256_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BlobMetadata {
    pub fn new(bucket: impl AsRef<str>, blob_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            bucket: bucket.as_ref().to_string(),
            blob_id,
            content_type: None,
            content_disposition: None,
            file_size: None,
            sha256_hash: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_content_type(mut self, content_type: Option<String>) -> Self {
        self.content_type = content_type;
        self
    }

    pub fn with_content_disposition(mut self, content_disposition: Option<String>) -> Self {
        self.content_disposition = content_disposition;
        self
    }

    pub fn with_file_size(mut self, file_size: i64) -> Self {
        self.file_size = Some(file_size);
        self
    }

    pub fn with_sha256_hash(mut self, sha256_hash: String) -> Self {
        self.sha256_hash = Some(sha256_hash);
        self
    }
}

/// SQLite-based metadata store for blob metadata
#[derive(Debug)]
pub struct MetadataStore {
    connection: Mutex<Connection>,
}

impl MetadataStore {
    /// Initialize the metadata store with SQLite database at the given path
    pub fn init(db_path: &Path) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;

        // Enable WAL mode for better concurrent access
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "cache_size", 1000)?;
        conn.pragma_update(None, "temp_store", "memory")?;

        // Execute migrations - if necessary
        check_migration(&conn)?;

        info!("📊 Initialized metadata store at {}", db_path.display());

        Ok(Self {
            connection: Mutex::new(conn),
        })
    }

    /// Store metadata for a blob
    pub fn store_metadata(&self, metadata: &BlobMetadata) -> SqliteResult<()> {
        let mut conn = self.connection.lock();

        // Begin transaction for atomicity
        let tx = conn.transaction()?;

        // Ensure bucket exists
        tx.execute(
            "INSERT OR IGNORE INTO buckets (name, created_at) VALUES (?1, strftime('%s', 'now'))",
            params![metadata.bucket],
        )?;

        // Check if this is an insert or update to properly update bucket stats
        let existing_size: Option<i64> = tx
            .query_row(
                "SELECT file_size FROM objects WHERE bucket = ?1 AND blob_id = ?2",
                params![metadata.bucket, metadata.blob_id.to_string()],
                |row| row.get(0),
            )
            .ok();

        // Insert or replace the object metadata
        tx.execute(
            r#"
            INSERT OR REPLACE INTO objects
            (bucket, blob_id, content_type, content_disposition, file_size, sha256_hash, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                metadata.bucket,
                metadata.blob_id.to_string(),
                metadata.content_type,
                metadata.content_disposition,
                metadata.file_size,
                metadata.sha256_hash,
                metadata.created_at.timestamp(),
                metadata.updated_at.timestamp(),
            ],
        )?;

        // Update bucket stats
        match (existing_size, metadata.file_size) {
            (None, Some(new_size)) => {
                // New object, increment count and size
                tx.execute(
                    "UPDATE buckets SET object_count = object_count + 1, total_size = total_size + ?1 WHERE name = ?2",
                    params![new_size, metadata.bucket],
                )?;
            }
            (Some(old_size), Some(new_size)) => {
                // Update existing object, adjust size delta
                let delta = new_size - old_size;
                tx.execute(
                    "UPDATE buckets SET total_size = total_size + ?1 WHERE name = ?2",
                    params![delta, metadata.bucket],
                )?;
            }
            (Some(old_size), None) => {
                // Size removed, decrease
                tx.execute(
                    "UPDATE buckets SET total_size = total_size - ?1 WHERE name = ?2",
                    params![old_size, metadata.bucket],
                )?;
            }
            (None, None) => {
                // New object without size, just increment count
                tx.execute(
                    "UPDATE buckets SET object_count = object_count + 1 WHERE name = ?1",
                    params![metadata.bucket],
                )?;
            }
        }

        // Commit transaction
        tx.commit()?;

        debug!(
            bucket = %metadata.bucket,
            blob_id = %metadata.blob_id,
            content_type = metadata.content_type.as_deref().unwrap_or("none"),
            "stored blob metadata"
        );

        Ok(())
    }

    /// Retrieve metadata for a blob in a specific bucket
    pub fn get_metadata(&self, bucket: &str, blob_id: &Uuid) -> SqliteResult<Option<BlobMetadata>> {
        let conn = self.connection.lock();

        let mut stmt = conn.prepare(
            r#"
            SELECT bucket, blob_id, content_type, content_disposition, file_size, sha256_hash, created_at, updated_at
            FROM objects
            WHERE bucket = ?1 AND blob_id = ?2
            "#,
        )?;

        let mut rows = stmt.query_map(params![bucket, blob_id.to_string()], |row| {
            let bucket: String = row.get(0)?;
            let blob_id: String = row.get(1)?;
            let content_type: Option<String> = row.get(2)?;
            let content_disposition: Option<String> = row.get(3)?;
            let file_size: Option<i64> = row.get(4)?;
            let sha256_hash: Option<String> = row.get(5)?;
            let created_at: i64 = row.get(6)?;
            let updated_at: i64 = row.get(7)?;

            Ok(BlobMetadata {
                bucket,
                blob_id: Uuid::parse_str(&blob_id).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                content_type,
                content_disposition,
                file_size,
                sha256_hash,
                created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_else(Utc::now),
                updated_at: DateTime::from_timestamp(updated_at, 0).unwrap_or_else(Utc::now),
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Returns only the hash of the blob-id (if any)
    pub fn get_sha256(&self, bucket: &str, blob_id: &Uuid) -> SqliteResult<Option<String>> {
        let conn = self.connection.lock();

        let mut stmt =
            conn.prepare("SELECT sha256_hash FROM objects WHERE bucket = ?1 AND blob_id = ?2")?;

        let mut rows = stmt.query_map(params![bucket, blob_id.to_string()], |row| {
            let sha256_hash: Option<String> = row.get(0)?;
            Ok(sha256_hash)
        })?;

        match rows.next() {
            Some(row) => row,
            None => Ok(None),
        }
    }

    /// Delete metadata for a blob and decrement content refcount
    /// Returns (deleted: bool, content_hash: Option<String>, new_refcount: i64)
    pub fn delete_metadata(
        &self,
        bucket: &str,
        blob_id: &Uuid,
    ) -> SqliteResult<(bool, Option<String>, i64)> {
        let mut conn = self.connection.lock();

        // Begin transaction for atomicity
        let tx = conn.transaction()?;

        // Get current file size and content hash before deletion
        let metadata: Option<(Option<i64>, Option<String>)> = tx
            .query_row(
                "SELECT file_size, sha256_hash FROM objects WHERE bucket = ?1 AND blob_id = ?2",
                params![bucket, blob_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        let changes = tx.execute(
            "DELETE FROM objects WHERE bucket = ?1 AND blob_id = ?2",
            params![bucket, blob_id.to_string()],
        )?;

        let mut new_refcount = 0i64;
        let content_hash = if let Some((file_size, hash)) = metadata {
            // Update bucket stats if deletion was successful
            if changes > 0 {
                tx.execute(
                    "UPDATE buckets SET object_count = object_count - 1 WHERE name = ?1",
                    params![bucket],
                )?;

                if let Some(size) = file_size {
                    tx.execute(
                        "UPDATE buckets SET total_size = total_size - ?1 WHERE name = ?2",
                        params![size, bucket],
                    )?;
                }

                // Decrement content refcount if hash exists
                if let Some(ref h) = hash {
                    tx.execute(
                        "UPDATE content_refs SET ref_count = ref_count - 1 WHERE content_hash = ?1",
                        params![h],
                    )?;

                    // Get new refcount
                    new_refcount = tx
                        .query_row(
                            "SELECT ref_count FROM content_refs WHERE content_hash = ?1",
                            params![h],
                            |row| row.get(0),
                        )
                        .unwrap_or(0);
                }
            }
            hash
        } else {
            None
        };

        // Commit transaction
        tx.commit()?;

        debug!(bucket = %bucket, blob_id = %blob_id, content_hash = ?content_hash, new_refcount, "deleted blob metadata");
        Ok((changes > 0, content_hash, new_refcount))
    }

    /// Get all (bucket, blob_id) pairs that have metadata but might be orphaned
    /// (for cleanup purposes)
    pub fn get_all_blob_ids(&self) -> SqliteResult<Vec<(String, Uuid)>> {
        let conn = self.connection.lock();
        let mut stmt = conn.prepare("SELECT bucket, blob_id FROM objects")?;
        let rows = stmt.query_map([], |row| {
            let bucket: String = row.get(0)?;
            let blob_id: String = row.get(1)?;
            let uuid = Uuid::parse_str(&blob_id).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok((bucket, uuid))
        })?;

        let mut blob_ids = Vec::new();
        for row in rows {
            blob_ids.push(row?);
        }

        Ok(blob_ids)
    }

    /// Get bucket information
    pub fn get_bucket(&self, bucket: &str) -> SqliteResult<Option<Bucket>> {
        let conn = self.connection.lock();

        let mut stmt = conn.prepare(
            "SELECT name, created_at, object_count, total_size FROM buckets WHERE name = ?1",
        )?;

        let mut rows = stmt.query_map(params![bucket], |row| {
            let name: String = row.get(0)?;
            let created_at: i64 = row.get(1)?;
            let object_count: i64 = row.get(2)?;
            let total_size: i64 = row.get(3)?;

            Ok(Bucket {
                name,
                created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_else(Utc::now),
                object_count,
                total_size,
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// List all buckets
    pub fn list_buckets(&self) -> SqliteResult<Vec<Bucket>> {
        let conn = self.connection.lock();

        let mut stmt = conn.prepare(
            "SELECT name, created_at, object_count, total_size FROM buckets ORDER BY created_at",
        )?;

        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let created_at: i64 = row.get(1)?;
            let object_count: i64 = row.get(2)?;
            let total_size: i64 = row.get(3)?;

            Ok(Bucket {
                name,
                created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_else(Utc::now),
                object_count,
                total_size,
            })
        })?;

        let mut buckets = Vec::new();
        for row in rows {
            buckets.push(row?);
        }

        Ok(buckets)
    }

    /// Delete a bucket (only if empty)
    pub fn delete_bucket(&self, bucket: &str) -> SqliteResult<bool> {
        let conn = self.connection.lock();

        // Check if bucket is empty
        let object_count: i64 = conn.query_row(
            "SELECT object_count FROM buckets WHERE name = ?1",
            params![bucket],
            |row| row.get(0),
        )?;

        if object_count > 0 {
            return Ok(false); // Cannot delete non-empty bucket
        }

        let changes = conn.execute("DELETE FROM buckets WHERE name = ?1", params![bucket])?;

        Ok(changes > 0)
    }

    /// List objects in a specific bucket with pagination
    pub fn list_objects_in_bucket(
        &self,
        bucket: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> SqliteResult<Vec<BlobMetadata>> {
        let conn = self.connection.lock();

        let limit = limit.unwrap_or(100).min(1000);
        let offset = offset.unwrap_or(0);

        let mut stmt = conn.prepare(
            r#"
            SELECT bucket, blob_id, content_type, content_disposition, file_size, sha256_hash, created_at, updated_at
            FROM objects
            WHERE bucket = ?1
            ORDER BY created_at DESC
            LIMIT ?2 OFFSET ?3
            "#,
        )?;

        let rows = stmt.query_map(params![bucket, limit, offset], |row| {
            let bucket: String = row.get(0)?;
            let blob_id: String = row.get(1)?;
            let content_type: Option<String> = row.get(2)?;
            let content_disposition: Option<String> = row.get(3)?;
            let file_size: Option<i64> = row.get(4)?;
            let sha256_hash: Option<String> = row.get(5)?;
            let created_at: i64 = row.get(6)?;
            let updated_at: i64 = row.get(7)?;

            Ok(BlobMetadata {
                bucket,
                blob_id: Uuid::parse_str(&blob_id).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                content_type,
                content_disposition,
                file_size,
                sha256_hash,
                created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_else(Utc::now),
                updated_at: DateTime::from_timestamp(updated_at, 0).unwrap_or_else(Utc::now),
            })
        })?;

        let mut objects = Vec::new();
        for row in rows {
            objects.push(row?);
        }

        Ok(objects)
    }

    /// List all objects across all buckets with pagination
    pub fn list_all_objects(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> SqliteResult<Vec<BlobMetadata>> {
        let conn = self.connection.lock();

        let limit = limit.unwrap_or(100).min(1000);
        let offset = offset.unwrap_or(0);

        let mut stmt = conn.prepare(
            r#"
            SELECT bucket, blob_id, content_type, content_disposition, file_size, sha256_hash, created_at, updated_at
            FROM objects
            ORDER BY created_at DESC
            LIMIT ?1 OFFSET ?2
            "#,
        )?;

        let rows = stmt.query_map(params![limit, offset], |row| {
            let bucket: String = row.get(0)?;
            let blob_id: String = row.get(1)?;
            let content_type: Option<String> = row.get(2)?;
            let content_disposition: Option<String> = row.get(3)?;
            let file_size: Option<i64> = row.get(4)?;
            let sha256_hash: Option<String> = row.get(5)?;
            let created_at: i64 = row.get(6)?;
            let updated_at: i64 = row.get(7)?;

            Ok(BlobMetadata {
                bucket,
                blob_id: Uuid::parse_str(&blob_id).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                content_type,
                content_disposition,
                file_size,
                sha256_hash,
                created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_else(Utc::now),
                updated_at: DateTime::from_timestamp(updated_at, 0).unwrap_or_else(Utc::now),
            })
        })?;

        let mut objects = Vec::new();
        for row in rows {
            objects.push(row?);
        }

        Ok(objects)
    }

    // ============================================================================
    // Content Reference Counting (for deduplication)
    // ============================================================================

    /// Increment reference count for content, or create new entry if doesn't exist
    pub fn increment_content_ref(&self, content_hash: &str, file_size: i64) -> SqliteResult<()> {
        let conn = self.connection.lock();

        // Try to increment existing ref
        let updated = conn.execute(
            "UPDATE content_refs SET ref_count = ref_count + 1, last_accessed_at = strftime('%s', 'now') WHERE content_hash = ?1",
            params![content_hash],
        )?;

        // If no row was updated, create new entry
        if updated == 0 {
            conn.execute(
                "INSERT INTO content_refs (content_hash, ref_count, file_size, created_at, last_accessed_at)
                 VALUES (?1, 1, ?2, strftime('%s', 'now'), strftime('%s', 'now'))",
                params![content_hash, file_size],
            )?;
        }

        Ok(())
    }

    #[allow(unused)]
    /// Decrement reference count for content, returns new ref_count
    pub fn decrement_content_ref(&self, content_hash: &str) -> SqliteResult<i64> {
        let conn = self.connection.lock();

        conn.execute(
            "UPDATE content_refs SET ref_count = ref_count - 1 WHERE content_hash = ?1",
            params![content_hash],
        )?;

        let ref_count: i64 = conn.query_row(
            "SELECT ref_count FROM content_refs WHERE content_hash = ?1",
            params![content_hash],
            |row| row.get(0),
        )?;

        Ok(ref_count)
    }

    /// Check if content reference exists
    pub fn content_ref_exists(&self, content_hash: &str) -> SqliteResult<bool> {
        let conn = self.connection.lock();

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM content_refs WHERE content_hash = ?1",
            params![content_hash],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }

    /// Get content hashes with ref_count = 0 (zombie refs, can be cleaned up)
    pub fn get_zombie_refs(&self) -> SqliteResult<Vec<String>> {
        let conn = self.connection.lock();

        let mut stmt = conn.prepare("SELECT content_hash FROM content_refs WHERE ref_count = 0")?;

        let rows = stmt.query_map([], |row| {
            let hash: String = row.get(0)?;
            Ok(hash)
        })?;

        let mut hashes = Vec::new();
        for row in rows {
            hashes.push(row?);
        }

        Ok(hashes)
    }

    /// Delete content reference entry
    pub fn delete_content_ref(&self, content_hash: &str) -> SqliteResult<bool> {
        let conn = self.connection.lock();

        let changes = conn.execute(
            "DELETE FROM content_refs WHERE content_hash = ?1",
            params![content_hash],
        )?;

        Ok(changes > 0)
    }

    /// Get comprehensive storage statistics
    pub fn get_storage_stats(&self) -> SqliteResult<StorageStats> {
        use crate::utils::byte_size_str;

        let conn = self.connection.lock();

        // Get bucket stats with logical sizes
        let mut stmt = conn.prepare(
            "SELECT bucket, COUNT(*) as object_count, COALESCE(SUM(file_size), 0) as total_size
             FROM objects
             GROUP BY bucket",
        )?;

        let bucket_rows = stmt.query_map([], |row| {
            let size: i64 = row.get(2)?;
            Ok(BucketStats {
                name: row.get(0)?,
                object_count: row.get(1)?,
                logical_size: size,
                logical_size_human: byte_size_str(size as usize),
            })
        })?;

        let mut buckets = Vec::new();
        for bucket in bucket_rows {
            buckets.push(bucket?);
        }

        // Get content stats (actual storage after deduplication)
        let (content_count, actual_size): (i64, i64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(file_size), 0)
             FROM content_refs
             WHERE ref_count > 0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        // Get deduplication stats
        let total_refs: i64 = conn.query_row(
            "SELECT COALESCE(SUM(ref_count), 0) FROM content_refs",
            [],
            |row| row.get(0),
        )?;

        // Calculate totals
        let total_objects: i64 = buckets.iter().map(|b| b.object_count).sum();
        let total_logical_size: i64 = buckets.iter().map(|b| b.logical_size).sum();
        let space_saved = total_logical_size - actual_size;

        let dedup_ratio = if total_logical_size > 0 {
            (total_logical_size - actual_size) as f64 / total_logical_size as f64
        } else {
            0.0
        };

        Ok(StorageStats {
            buckets,
            total_objects,
            total_logical_size,
            total_logical_size_human: byte_size_str(total_logical_size as usize),
            unique_content_count: content_count,
            actual_storage_size: actual_size,
            actual_storage_size_human: byte_size_str(actual_size as usize),
            total_references: total_refs,
            deduplication_ratio: dedup_ratio,
            deduplication_percentage: format!("{:.1}%", dedup_ratio * 100.0),
            space_saved,
            space_saved_human: byte_size_str(space_saved.unsigned_abs() as usize),
        })
    }

    /// Get database statistics (used for testing)
    #[cfg(test)]
    pub fn get_stats(&self) -> SqliteResult<MetadataStats> {
        let conn = self.connection.lock();

        let mut stmt = conn.prepare(
            r#"
            SELECT
                COUNT(*) as total_entries,
                COUNT(content_type) as entries_with_content_type,
                COUNT(content_disposition) as entries_with_content_disposition
            FROM objects
            "#,
        )?;

        let stats = stmt.query_row([], |row| {
            Ok(MetadataStats {
                total_entries: row.get(0)?,
                entries_with_content_type: row.get(1)?,
                entries_with_content_disposition: row.get(2)?,
            })
        })?;

        Ok(stats)
    }
}

/// Helper function to apply necessary migrations
///
/// Also creates the tables, if they don't exist yet.
fn check_migration(conn: &Connection) -> SqliteResult<()> {
    // Create the buckets table
    conn.execute(
        r#"
            CREATE TABLE IF NOT EXISTS buckets (
                name TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                object_count INTEGER DEFAULT 0,
                total_size INTEGER DEFAULT 0
            );
            "#,
        [],
    )?;

    // Ensure default bucket exists
    conn.execute(
        r#"
            INSERT OR IGNORE INTO buckets (name, created_at)
            VALUES ('default', strftime('%s', 'now'))
            "#,
        [],
    )?;

    // Create content_refs table for deduplication
    conn.execute(
        r#"
            CREATE TABLE IF NOT EXISTS content_refs (
                content_hash TEXT PRIMARY KEY,
                ref_count INTEGER NOT NULL DEFAULT 0,
                file_size INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed_at INTEGER NOT NULL
            );
            "#,
        [],
    )?;

    // Create index on ref_count for efficient cleanup queries
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_content_refs_refcount ON content_refs(ref_count)",
        [],
    )?;

    // Check if we need to migrate from old schema to new schema
    // We check if the old blob_metadata table exists (not if it has a bucket column)
    let old_table_exists: bool = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='blob_metadata'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);

    // Check if the new objects table already exists
    let new_table_exists: bool = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='objects'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);

    // We need migration if old table exists but new table doesn't
    let needs_migration = old_table_exists && !new_table_exists;

    if needs_migration {
        info!("🔄 Migrating database schema to support buckets...");

        // Create new objects table with bucket support
        conn.execute(
            r#"
                CREATE TABLE IF NOT EXISTS objects (
                    bucket TEXT NOT NULL DEFAULT 'default',
                    blob_id TEXT NOT NULL,
                    content_type TEXT,
                    content_disposition TEXT,
                    file_size INTEGER,
                    sha256_hash TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (bucket, blob_id)
                );
                "#,
            [],
        )?;

        // Migrate data from blob_metadata to objects if blob_metadata exists and has data
        let has_old_data: bool = conn
            .query_row("SELECT COUNT(*) FROM blob_metadata", [], |row| {
                let count: i64 = row.get(0)?;
                Ok(count > 0)
            })
            .unwrap_or(false);

        if has_old_data {
            conn.execute(
                    r#"
                    INSERT OR IGNORE INTO objects (bucket, blob_id, content_type, content_disposition, file_size, sha256_hash, created_at, updated_at)
                    SELECT 'default', blob_id, content_type, content_disposition, file_size, sha256_hash, created_at, updated_at
                    FROM blob_metadata
                    "#,
                    [],
                )?;

            // Recalculate bucket stats after migration
            conn.execute(
                r#"
                UPDATE buckets SET
                    object_count = (SELECT COUNT(*) FROM objects WHERE bucket = buckets.name),
                    total_size = (SELECT COALESCE(SUM(file_size), 0) FROM objects WHERE bucket = buckets.name)
                WHERE name = 'default'
                "#,
                [],
            )?;

            info!("✅ Migrated existing metadata to new schema");
        }

        // Drop old table (after successful migration)
        conn.execute("DROP TABLE IF EXISTS blob_metadata", [])?;
    }

    // Always ensure objects table exists (for new installs or after migration)
    conn.execute(
        r#"
            CREATE TABLE IF NOT EXISTS objects (
                bucket TEXT NOT NULL DEFAULT 'default',
                blob_id TEXT NOT NULL,
                content_type TEXT,
                content_disposition TEXT,
                file_size INTEGER,
                sha256_hash TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (bucket, blob_id)
            );
            "#,
        [],
    )?;

    // Create indexes
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_objects_bucket ON objects(bucket)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_objects_created_at ON objects(created_at)",
        [],
    )?;

    // Recalculate bucket stats to ensure consistency
    // (This handles cases where stats might be out of sync after migration or manual DB edits)
    conn.execute(
        r#"
        UPDATE buckets SET
            object_count = (SELECT COUNT(*) FROM objects WHERE bucket = buckets.name),
            total_size = (SELECT COALESCE(SUM(file_size), 0) FROM objects WHERE bucket = buckets.name)
        "#,
        [],
    )?;

    Ok(())
}

#[cfg(test)]
#[derive(Debug)]
pub struct MetadataStats {
    pub total_entries: i64,
    pub entries_with_content_type: i64,
    pub entries_with_content_disposition: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_metadata_store_init() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let store = MetadataStore::init(&db_path).expect("failed to init metadata store");

        // Should be able to get stats from empty database
        let stats = store.get_stats().expect("failed to get stats");
        assert_eq!(stats.total_entries, 0);
    }

    #[test]
    fn test_store_and_retrieve_metadata() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = MetadataStore::init(&db_path).unwrap();

        let bucket = "test-bucket";
        let blob_id = Uuid::new_v4();
        let metadata = BlobMetadata::new(bucket.to_string(), blob_id)
            .with_content_type(Some("image/png".to_string()))
            .with_content_disposition(Some("attachment; filename=\"test.png\"".to_string()))
            .with_file_size(Some(1024))
            .with_sha256_hash(Some("abc123def456".to_string()));

        // Store metadata
        store
            .store_metadata(&metadata)
            .expect("failed to store metadata");

        // Retrieve metadata
        let retrieved = store
            .get_metadata(bucket, &blob_id)
            .expect("failed to get metadata");
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.bucket, bucket);
        assert_eq!(retrieved.blob_id, blob_id);
        assert_eq!(retrieved.content_type, Some("image/png".to_string()));
        assert_eq!(
            retrieved.content_disposition,
            Some("attachment; filename=\"test.png\"".to_string())
        );
        assert_eq!(retrieved.file_size, Some(1024));
        assert_eq!(retrieved.sha256_hash, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_delete_metadata() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = MetadataStore::init(&db_path).unwrap();

        let bucket = "default";
        let blob_id = Uuid::new_v4();
        let metadata = BlobMetadata::new(bucket.to_string(), blob_id);

        // Store metadata
        store.store_metadata(&metadata).unwrap();

        // Verify it exists
        assert!(store.get_metadata(bucket, &blob_id).unwrap().is_some());

        // Delete metadata
        let (deleted, _hash, _refcount) = store.delete_metadata(bucket, &blob_id).unwrap();
        assert!(deleted);

        // Verify it's gone
        assert!(store.get_metadata(bucket, &blob_id).unwrap().is_none());

        // Delete again should return false
        let (deleted_again, _, _) = store.delete_metadata(bucket, &blob_id).unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn test_get_all_blob_ids() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = MetadataStore::init(&db_path).unwrap();

        let bucket = "default";
        let blob_ids = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        // Store metadata for each blob
        for blob_id in &blob_ids {
            let metadata = BlobMetadata::new(bucket.to_string(), *blob_id);
            store.store_metadata(&metadata).unwrap();
        }

        // Get all blob IDs
        let retrieved_ids = store.get_all_blob_ids().unwrap();
        assert_eq!(retrieved_ids.len(), 3);

        for blob_id in &blob_ids {
            assert!(
                retrieved_ids
                    .iter()
                    .any(|(b, id)| b == bucket && id == blob_id)
            );
        }
    }

    #[test]
    fn test_get_sha256_hash() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = MetadataStore::init(&db_path).unwrap();

        let bucket = "default";
        let blob_id = Uuid::new_v4();
        let expected_hash = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456";

        // Store metadata with hash
        let metadata = BlobMetadata::new(bucket.to_string(), blob_id)
            .with_sha256_hash(Some(expected_hash.to_string()));
        store.store_metadata(&metadata).unwrap();

        // Test retrieving the hash
        let retrieved_hash = store.get_sha256(bucket, &blob_id).unwrap();
        assert_eq!(retrieved_hash, Some(expected_hash.to_string()));

        // Test non-existent blob
        let non_existent_id = Uuid::new_v4();
        let no_hash = store.get_sha256(bucket, &non_existent_id).unwrap();
        assert_eq!(no_hash, None);

        // Test blob with no hash stored
        let blob_id_no_hash = Uuid::new_v4();
        let metadata_no_hash = BlobMetadata::new(bucket.to_string(), blob_id_no_hash);
        store.store_metadata(&metadata_no_hash).unwrap();

        let retrieved_no_hash = store.get_sha256(bucket, &blob_id_no_hash).unwrap();
        assert_eq!(retrieved_no_hash, None);
    }

    #[test]
    fn test_metadata_stats() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = MetadataStore::init(&db_path).unwrap();

        let bucket = "default";
        // Add metadata with different combinations
        let metadata1 = BlobMetadata::new(bucket.to_string(), Uuid::new_v4())
            .with_content_type(Some("text/plain".to_string()));
        let metadata2 = BlobMetadata::new(bucket.to_string(), Uuid::new_v4())
            .with_content_disposition(Some("attachment; filename=\"test.txt\"".to_string()));
        let metadata3 = BlobMetadata::new(bucket.to_string(), Uuid::new_v4())
            .with_content_type(Some("image/jpeg".to_string()))
            .with_content_disposition(Some("inline".to_string()));

        store.store_metadata(&metadata1).unwrap();
        store.store_metadata(&metadata2).unwrap();
        store.store_metadata(&metadata3).unwrap();

        let stats = store.get_stats().unwrap();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.entries_with_content_type, 2);
        assert_eq!(stats.entries_with_content_disposition, 2);
    }
}
