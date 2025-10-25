# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
