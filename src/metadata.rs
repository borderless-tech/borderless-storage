use std::path::Path;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, Result as SqliteResult, params};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

/// Metadata associated with a blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub blob_id: Uuid,
    pub content_type: Option<String>,
    pub content_disposition: Option<String>,
    pub file_size: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BlobMetadata {
    pub fn new(blob_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            blob_id,
            content_type: None,
            content_disposition: None,
            file_size: None,
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

    pub fn with_file_size(mut self, file_size: Option<i64>) -> Self {
        self.file_size = file_size;
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
    pub fn init(db_path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let conn = Connection::open(db_path)?;

        // Enable WAL mode for better concurrent access
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "cache_size", 1000)?;
        conn.pragma_update(None, "temp_store", "memory")?;

        // Create the metadata table if it doesn't exist
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS blob_metadata (
                blob_id TEXT PRIMARY KEY,
                content_type TEXT,
                content_disposition TEXT,
                file_size INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            "#,
            [],
        )?;

        // Create index on created_at for cleanup operations
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blob_metadata_created_at ON blob_metadata(created_at)",
            [],
        )?;

        info!("📊 Initialized metadata store at {}", db_path.display());

        Ok(Self {
            connection: Mutex::new(conn),
        })
    }

    /// Store metadata for a blob
    pub fn store_metadata(&self, metadata: &BlobMetadata) -> SqliteResult<()> {
        let conn = self.connection.lock();

        conn.execute(
            r#"
            INSERT OR REPLACE INTO blob_metadata 
            (blob_id, content_type, content_disposition, file_size, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                metadata.blob_id.to_string(),
                metadata.content_type,
                metadata.content_disposition,
                metadata.file_size,
                metadata.created_at.timestamp(),
                metadata.updated_at.timestamp(),
            ],
        )?;

        debug!(
            blob_id = %metadata.blob_id,
            content_type = metadata.content_type.as_deref().unwrap_or("none"),
            "stored blob metadata"
        );

        Ok(())
    }

    /// Retrieve metadata for a blob
    pub fn get_metadata(&self, blob_id: &Uuid) -> SqliteResult<Option<BlobMetadata>> {
        let conn = self.connection.lock();

        let mut stmt = conn.prepare(
            r#"
            SELECT blob_id, content_type, content_disposition, file_size, created_at, updated_at
            FROM blob_metadata
            WHERE blob_id = ?1
            "#,
        )?;

        let mut rows = stmt.query_map(params![blob_id.to_string()], |row| {
            let blob_id: String = row.get(0)?;
            let content_type: Option<String> = row.get(1)?;
            let content_disposition: Option<String> = row.get(2)?;
            let file_size: Option<i64> = row.get(3)?;
            let created_at: i64 = row.get(4)?;
            let updated_at: i64 = row.get(5)?;

            Ok(BlobMetadata {
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
                created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_else(|| Utc::now()),
                updated_at: DateTime::from_timestamp(updated_at, 0).unwrap_or_else(|| Utc::now()),
            })
        })?;

        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Delete metadata for a blob
    pub fn delete_metadata(&self, blob_id: &Uuid) -> SqliteResult<bool> {
        let conn = self.connection.lock();

        let changes = conn.execute(
            "DELETE FROM blob_metadata WHERE blob_id = ?1",
            params![blob_id.to_string()],
        )?;

        debug!(blob_id = %blob_id, "deleted blob metadata");
        Ok(changes > 0)
    }

    /// Get all blob IDs that have metadata but might be orphaned
    /// (for cleanup purposes)
    pub fn get_all_blob_ids(&self) -> SqliteResult<Vec<Uuid>> {
        let conn = self.connection.lock();

        let mut stmt = conn.prepare("SELECT blob_id FROM blob_metadata")?;
        let rows = stmt.query_map([], |row| {
            let blob_id: String = row.get(0)?;
            Uuid::parse_str(&blob_id).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })
        })?;

        let mut blob_ids = Vec::new();
        for row in rows {
            blob_ids.push(row?);
        }

        Ok(blob_ids)
    }

    // /// Get database statistics
    // pub fn get_stats(&self) -> SqliteResult<MetadataStats> {
    //     let conn = self.connection.lock();

    //     let mut stmt = conn.prepare(
    //         r#"
    //         SELECT
    //             COUNT(*) as total_entries,
    //             COUNT(content_type) as entries_with_content_type,
    //             COUNT(content_disposition) as entries_with_content_disposition
    //         FROM blob_metadata
    //         "#,
    //     )?;

    //     let stats = stmt.query_row([], |row| {
    //         Ok(MetadataStats {
    //             total_entries: row.get(0)?,
    //             entries_with_content_type: row.get(1)?,
    //             entries_with_content_disposition: row.get(2)?,
    //         })
    //     })?;

    //     Ok(stats)
    // }
}

// #[derive(Debug)]
// pub struct MetadataStats {
//     pub total_entries: i64,
//     pub entries_with_content_type: i64,
//     pub entries_with_content_disposition: i64,
// }

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

        let blob_id = Uuid::new_v4();
        let metadata = BlobMetadata::new(blob_id)
            .with_content_type(Some("image/png".to_string()))
            .with_content_disposition(Some("attachment; filename=\"test.png\"".to_string()))
            .with_file_size(Some(1024));

        // Store metadata
        store
            .store_metadata(&metadata)
            .expect("failed to store metadata");

        // Retrieve metadata
        let retrieved = store
            .get_metadata(&blob_id)
            .expect("failed to get metadata");
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.blob_id, blob_id);
        assert_eq!(retrieved.content_type, Some("image/png".to_string()));
        assert_eq!(
            retrieved.content_disposition,
            Some("attachment; filename=\"test.png\"".to_string())
        );
        assert_eq!(retrieved.file_size, Some(1024));
    }

    #[test]
    fn test_delete_metadata() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = MetadataStore::init(&db_path).unwrap();

        let blob_id = Uuid::new_v4();
        let metadata = BlobMetadata::new(blob_id);

        // Store metadata
        store.store_metadata(&metadata).unwrap();

        // Verify it exists
        assert!(store.get_metadata(&blob_id).unwrap().is_some());

        // Delete metadata
        let deleted = store.delete_metadata(&blob_id).unwrap();
        assert!(deleted);

        // Verify it's gone
        assert!(store.get_metadata(&blob_id).unwrap().is_none());

        // Delete again should return false
        let deleted_again = store.delete_metadata(&blob_id).unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn test_get_all_blob_ids() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = MetadataStore::init(&db_path).unwrap();

        let blob_ids = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        // Store metadata for each blob
        for blob_id in &blob_ids {
            let metadata = BlobMetadata::new(*blob_id);
            store.store_metadata(&metadata).unwrap();
        }

        // Get all blob IDs
        let retrieved_ids = store.get_all_blob_ids().unwrap();
        assert_eq!(retrieved_ids.len(), 3);

        for blob_id in &blob_ids {
            assert!(retrieved_ids.contains(blob_id));
        }
    }

    #[test]
    fn test_metadata_stats() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let store = MetadataStore::init(&db_path).unwrap();

        // Add metadata with different combinations
        let metadata1 =
            BlobMetadata::new(Uuid::new_v4()).with_content_type(Some("text/plain".to_string()));
        let metadata2 = BlobMetadata::new(Uuid::new_v4())
            .with_content_disposition(Some("attachment; filename=\"test.txt\"".to_string()));
        let metadata3 = BlobMetadata::new(Uuid::new_v4())
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
