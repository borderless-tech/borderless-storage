# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-11-19

### Added

- **Bucket Support**: Organize files into isolated namespaces
  - New bucket-aware routes: `/{bucket}/{blob_id}` for upload, download, update, and delete
  - Default bucket automatically used if no bucket specified
  - Validation: only alphanumeric characters, hyphens, and underscores allowed - characters normalized to lowercase
  - Automatic creation: When writing an object to a bucket that does not exists, it automatically creates the bucket for you

- **Content-Addressable Storage with Deduplication**: Automatic storage optimization
  - Files with identical content are stored only once (uses sha256 hash to determine identical files)
  - Deduplication happens across buckets, while blob-ids still are associated with the correct bucket
  - Migrations are performed automatically upon startup
  - Internal optimization: Clients can simply use the API without worrying or knowing about this.
  - Admin-friendly: By default, the data directory still mirrors the blob to bucket relation by symlinking to the content
    - E.g. `/buckets/{bucket_name}/{blob_id}` symlinks to `/content/{sha256_hash}`
    - the metadata storage is used match the blob-id to the content internally
    - allows you to 'quick-check' by looking at the directory how many data is in which bucket (useful in small deployments)

- **Admin API**: Comprehensive management endpoints
  - `GET /admin/stats` - Storage statistics including deduplication metrics
  - `GET /admin/objects` - List all objects across buckets (paginated)
  - `GET /admin/objects/{bucket}` - List objects in specific bucket
  - `GET /admin/buckets` - List all buckets with object counts and sizes
  - `GET /admin/buckets/{bucket}` - Get detailed bucket information
  - `DELETE /admin/buckets/{bucket}` - Delete empty buckets

- **E2E Test Suite**: To keep operations running, we introduced an extensive end-to-end test-suite
  - Upload/download verification with SHA-256 checking
  - Chunked upload testing
  - Bucket validation and normalization tests
  - Metadata preservation verification
  - Deduplication functionality tests

### Changed

- **Storage Layout**: Re-structured internal storage for content deduplication (backward compatible with existing files)
- **Legacy Routes**: Maintained for backward compatibility - old routes (`/upload/{blob_id}`, `/files/{blob_id}`) continue to work

### Configuration

- `CREATE_BUCKET_SYMLINKS` - Enable/disable symlink creation for content deduplication (default: true)

## [0.2.1] - 2025-10-25

### Hotfix

- Fix: Header `content-disposition` was blocked by cors policy

## [0.2.0] - 2025-10-25

### Added

- **Metadata Storage System**: Complete SQLite-based metadata storage for blob files
  - Store and retrieve Content-Type headers for proper MIME type handling
  - Store and retrieve Content-Disposition headers with original filenames
  - Automatic metadata extraction from HTTP headers during upload
  - Metadata restoration during download for proper browser file handling
  - Database migrations support for existing installations

- **SHA-256 Hash Calculation and Storage**: 
  - Automatic SHA-256 hash calculation for all uploaded files
  - Hash calculation for both single uploads and chunked uploads
  - Hash storage in metadata database for data integrity verification
  - `get_sha256()` function to retrieve hash for specific blobs
  - Hash included in upload response for client verification

- **Enhanced Browser Download Support**:
  - Proper filename preservation when downloading files in browsers
  - Correct MIME type detection and Content-Type headers
  - Content-Disposition header support for attachment/inline handling

- **New Dependencies**:
  - `rusqlite` with chrono and bundled features for metadata storage
  - `chrono` for timestamp handling
  - `hex` for SHA-256 hash encoding
  - `sha2` for cryptographic hash calculation

- **Configuration Options**:
  - `metadata_db_path` configuration option (defaults to `<data_dir>/metadata.db`)
  - Automatic database initialization and schema creation

### Enhanced

- **Upload Endpoints**: Now extract and store metadata during file uploads
- **Download Endpoints**: Apply stored metadata headers to responses
- **Chunked Upload**: SHA-256 calculation during chunk merging process
- **Cleanup Routines**: Remove orphaned metadata entries when blob files are deleted
- **API Responses**: Include SHA-256 hash in successful upload responses

### Technical Details

- SQLite database with WAL mode for better concurrent access
- Buffered I/O for efficient hash calculation during large file processing
- Atomic operations using temporary files and database transactions
- Backward compatibility with existing blob storage without metadata

## [0.1.2] - Previous Version

- Initial S3-style object store implementation
- Pre-signed URL support
- Chunked upload functionality
- Filesystem-based storage backend
- Cleanup routines for orphaned files and chunks
