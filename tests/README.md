# E2E Test Suite

End-to-end tests for borderless-storage using shell scripts.

## Prerequisites

- **Server running** on `localhost:3000`
- **Required tools**:
  - `curl`
  - `jq`
  - `sha256sum`
  - `mktemp`
  - `uuidgen` (for chunked upload test)

## Quick Start

### Run All Tests

```bash
./run-all-tests.sh
```

This will run all tests sequentially and provide a summary at the end. Tests stop on first failure.

### Run Individual Test

```bash
./test-01-upload-download.sh
```

## Test Suite

| Test | Description |
|------|-------------|
| `test-01-upload-download.sh` | Upload a file and download it, verify SHA256 hash matches |
| `test-02-delete.sh` | Upload, delete, then verify download fails |
| `test-03-double-upload.sh` | Upload twice - POST fails, PUT succeeds and updates content |
| `test-04-chunked-upload.sh` | Upload file in chunks, download and verify hash |
| `test-05-bucket-upload.sh` | Upload to specific bucket, verify bucket size increases |
| `test-06-admin-objects.sh` | Upload and verify it appears in admin/objects endpoint |
| `test-07-deduplication.sh` | Upload same file twice, verify deduplication in stats |
| `test-08-metadata-headers.sh` | Upload with Content-Type/Content-Disposition, verify preserved |
| `test-09-authentication.sh` | Verify authentication required for admin endpoints |
| `test-10-healthcheck.sh` | Test health check and stats endpoints |

## Configuration

Edit `utils.sh` to change:

- `API_KEY` - Authentication key (default: "secret-api-key")
- `HOST` - Server host (default: "http://127.0.0.1:3000")

## Test Data

The `data/` directory contains test files:

- `manifesto.md` - Larger text file (~211 bytes)
- `number-1` - Small file (2 bytes)
- `number-2` - Small file (2 bytes)

## Writing New Tests

1. Create a new file `test-XX-description.sh`
2. Follow this template:

```bash
#!/usr/bin/env bash
#
# Test: Description of what this test does
#

set -e
cd "$(dirname "$0")"
source utils.sh

assertSetup
test_start "Test Name"

# Your test logic here

test_success "Test Name"
```

3. Use helper functions from `utils.sh`:
   - `presign_rq(action, [blob_id], [bucket])` - Get presigned URL
   - `upload_file(file, url)` - Upload file, returns blob_id
   - `download_file(url, output)` - Download file
   - `delete_file(url)` - Delete file
   - `assert_hash_match(file1, file2, desc)` - Verify SHA256 match
   - `assert_fails(desc, command...)` - Assert command fails
   - `get_stats()` - Get admin stats
   - `get_objects([bucket])` - Get object list
   - `get_bucket(bucket)` - Get bucket info

4. Make executable: `chmod +x test-XX-description.sh`

## CI Integration

Add to your CI pipeline:

```yaml
- name: Run E2E Tests
  run: |
    cd tests
    ./start-server.sh &
    sleep 3
    ./run-all-tests.sh
```

## Troubleshooting

### Server not running

```bash
# Start server manually
./start-server.sh

# Or use the main run_dev.sh script
cd .. && ./run_dev.sh
```

### Tests fail with "Server is not reachable"

Ensure the server is listening on `localhost:3000`:

```bash
curl http://localhost:3000/healthz
```

### Tests fail with authentication errors

Check that `API_KEY` in `utils.sh` matches the server's `PRESIGN_API_KEY` environment variable.

## Example Output

```
╔════════════════════════════════════════════════════════════╗
║         Borderless Storage E2E Test Suite                 ║
╚════════════════════════════════════════════════════════════╝

✓ Server is running

Found 10 tests to run

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Running: test-01-upload-download.sh
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

==========================================
TEST: Upload and Download - SHA256 verification
==========================================
→ Requesting presigned upload URL...
→ Uploading file...
  Blob ID: 019a9657-4b56-77a1-9450-dd720a59f4d2
→ Requesting presigned download URL...
→ Downloading file...
→ Verifying SHA256 hash...
✓ Hash match for uploaded and downloaded file

✅ TEST PASSED: Upload and Download

...
```
