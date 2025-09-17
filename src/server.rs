use std::{
    fs::File,
    io::{BufWriter, Write},
    net::SocketAddr,
    time::Instant,
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Request, State},
    http::HeaderMap,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use futures::StreamExt;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};
use uuid::Uuid;

use self::error::Error;
use crate::{storage::FsController, utils::byte_size_str};

/// Http-header to specify the upload type
const UPLOAD_TYPE: &str = "X-Upload-Type";

/// Http-header value that indicates a 'full' upload (all bytes in one request)
const UPLOAD_TYPE_FULL: &str = "full";

/// Http-header value that indicates a 'chunked' upload (multiple requests per file)
const UPLOAD_TYPE_CHUNK: &str = "chunked";

/// Http-header to specify the chunk-index
const CHUNK_IDX: &str = "X-Chunk-Index";

/// Http-header to specify the total amount of chunks
const CHUNK_TOTAL: &str = "X-Chunk-Total";

/// Http-header that is used in the last request of a chunk upload to advice the server to merge the chunks
const CHUNK_MERGE: &str = "X-Chunk-Merge";

/// Entrypoint to start the webserver
///
/// This function basically never returns - it only does in case of an error.
pub async fn start(addr: SocketAddr, fs_controller: FsController) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;

    let service = Router::new()
        .route("/upload/{blob_id}", post(write_blob).put(write_blob))
        .layer(middleware::from_fn(auth_middleware_dummy))
        .layer(middleware::from_fn(metrics))
        .with_state(fs_controller);

    axum::serve(listener, service).await?;

    Ok(())
}

/// Dummy authentication middleware ( to be implemented )
async fn auth_middleware_dummy(request: Request, next: Next) -> Response {
    // let user_id = UserAuth(12345);
    // request.extensions_mut().insert(user_id);
    next.run(request).await
}

/// Metrics middleware
async fn metrics(request: Request, next: Next) -> Response {
    let now = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let response = next.run(request).await;
    let elapsed = now.elapsed();
    let status = response.status();
    info!(%method, %path, %status, ?elapsed, "Served request");
    response
}

// The basic idea is to have a crud interface for file blobs

mod error {
    use super::Success;
    use axum::{
        http::{StatusCode, header::CONTENT_TYPE},
        response::{IntoResponse, Response},
    };
    use thiserror::Error;

    /// API Error
    #[derive(Debug, Error)]
    pub enum Error {
        #[error("Duplicate ID - refuse to overwrite")]
        Duplicate,
        // #[error("Item is not a file (but should be)")]
        // NotAFile,
        #[error("stream was interrupted or broken")]
        BrokenStream,
        #[error("failed to parse header values: {0}")]
        Headers(String),
        #[error(transparent)]
        Io(#[from] std::io::Error),
    }

    impl IntoResponse for Error {
        fn into_response(self) -> Response {
            let status = match &self {
                Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_REQUEST,
            };
            let message = self.to_string();
            let s = Success::new_false(message);
            let body = serde_json::to_vec(&s).unwrap_or_default();
            Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "application/json")
                .body(body.into())
                .unwrap_or_else(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "{\"success\":false,\"message\":\"failed to generate response\"}",
                    )
                        .into_response()
                })
        }
    }
}

#[derive(Serialize)]
struct Success {
    success: bool,
    message: String,
}

impl Success {
    pub fn new_false(message: impl AsRef<str>) -> Self {
        Success {
            success: false,
            message: message.as_ref().to_string(),
        }
    }

    pub fn new_true(message: impl AsRef<str>) -> Self {
        Success {
            success: true,
            message: message.as_ref().to_string(),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;
type JResult = Result<Json<Success>>;

async fn read_blob(
    State(storage): State<FsController>,
    Path(blob_id): Path<Uuid>,
) -> impl IntoResponse {
    axum::http::StatusCode::OK
}

enum UploadType {
    Full,
    Chunked {
        chunk_idx: usize,
        chunk_total: usize,
    },
    Merge {
        chunk_total: usize,
    },
}

impl UploadType {
    fn from_headers(headers: &HeaderMap) -> Result<Self> {
        // If no header is present, we assume a 'full' upload
        let utype = match headers.get(UPLOAD_TYPE) {
            Some(v) => v,
            None => return Ok(UploadType::Full),
        };

        // Early return for non-chunk uploads
        if utype != UPLOAD_TYPE_CHUNK {
            if utype == UPLOAD_TYPE_FULL {
                return Ok(UploadType::Full);
            } else {
                return Err(Error::Headers(format!(
                    "require header X-Upload-Type to be either '{UPLOAD_TYPE_FULL}' or '{UPLOAD_TYPE_CHUNK}'"
                )));
            }
        }

        // Parse chunked upload values
        let chunk_total = headers
            .get(CHUNK_TOTAL)
            .ok_or_else(|| Error::Headers(format!("missing required header {CHUNK_TOTAL}")))?
            .to_str()
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or_else(|| {
                Error::Headers(format!("header-value {CHUNK_TOTAL} must be a number"))
            })?;

        // If the merge header is present, we can return here ( the value is not important )
        if headers.get(CHUNK_MERGE).is_some() {
            return Ok(UploadType::Merge { chunk_total });
        }

        // Otherwise we need to parse the chunk-index
        let chunk_idx = headers
            .get(CHUNK_IDX)
            .ok_or_else(|| Error::Headers(format!("missing required header {CHUNK_IDX}")))?
            .to_str()
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or_else(|| Error::Headers(format!("header-value {CHUNK_IDX} must be a number")))?;

        if chunk_idx > chunk_total {
            return Err(Error::Headers(format!(
                "{CHUNK_IDX} must not be greater than {CHUNK_TOTAL}: {chunk_idx} > {chunk_total}"
            )));
        }

        Ok(UploadType::Chunked {
            chunk_idx,
            chunk_total,
        })
    }
}

async fn write_blob(
    State(storage): State<FsController>,
    Path(blob_id): Path<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> JResult {
    // 1. Determine file upload type from headers
    let upload_type = UploadType::from_headers(&headers)?;

    match upload_type {
        UploadType::Full => upload_full(storage, blob_id, body).await,
        UploadType::Chunked {
            chunk_idx,
            chunk_total,
        } => upload_chunk(storage, blob_id, chunk_idx, chunk_total, body).await,
        UploadType::Merge { chunk_total } => todo!(),
    }
}

// TODO: Other return type here
async fn upload_chunk(
    storage: FsController,
    blob_id: Uuid,
    chunk_idx: usize,
    chunk_total: usize,
    body: Body,
) -> JResult {
    let (chunk_path, chunk_tmp) = storage.chunk_path(&blob_id, chunk_idx, chunk_total)?;
    let f = File::create(&chunk_tmp)?;
    let mut writer = BufWriter::new(f);
    let mut stream = body.into_data_stream();
    let mut bytes_written = 0;
    while let Some(result) = stream.next().await {
        match result {
            Ok(b) => {
                writer.write_all(&b)?;
                bytes_written += b.len();
            }
            Err(e) => {
                warn!(%blob_id, "Error receiving blob: {e}");
                return Err(Error::BrokenStream);
            }
        }
    }
    writer.flush()?;
    std::fs::rename(&chunk_tmp, &chunk_path)?;
    let bytes = byte_size_str(bytes_written);
    debug!(%blob_id, %bytes, "uploaded chunk {chunk_idx}/{chunk_total}");
    Ok(Json(Success::new_true(format!(
        "received chunk {chunk_idx}/{chunk_total} for {blob_id}, size {bytes}"
    ))))
}

async fn merge_chunks(storage: FsController, blob_id: Uuid, chunk_total: usize) -> JResult {
    // 1. Check that all chunks are present
    if let Err(missing_chunks) = storage.check_chunks(&blob_id, chunk_total) {
        todo!("return missing list of chunks")
    }
    todo!()
}

/// Helper function to perform the oneshot (full) upload
async fn upload_full(storage: FsController, blob_id: Uuid, body: Body) -> JResult {
    // TODO: Move that function somewhere else
    // ++ use ".tmp" and create cleanup routine
    let (blob_path, blob_tmp) = storage.blob_path(&blob_id);

    if blob_path.exists() {
        return Err(Error::Duplicate);
    }

    // TODO: Can we count the bytes here ?
    let f = File::create(&blob_tmp)?;
    let mut writer = BufWriter::new(f);
    let mut stream = body.into_data_stream();
    let mut bytes_written = 0;
    while let Some(result) = stream.next().await {
        match result {
            Ok(b) => {
                writer.write_all(&b)?;
                bytes_written += b.len();
            }
            Err(e) => {
                warn!(%blob_id, "Error receiving blob: {e}");
                return Err(Error::BrokenStream);
            }
        }
    }
    writer.flush()?;
    std::fs::rename(&blob_tmp, &blob_path)?;
    let bytes = byte_size_str(bytes_written);
    debug!(%blob_id, %bytes, "uploaded blob");
    Ok(Json(Success::new_true(format!(
        "received {blob_id}, size {bytes}"
    ))))
}
