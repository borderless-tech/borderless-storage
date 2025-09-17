use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Request, State},
    http::{
        HeaderMap, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;
use tracing::{debug, info, warn};
use uuid::Uuid;

use self::error::Error;
use crate::{
    storage::FsController,
    utils::{
        byte_size_str, extract_sig_from_query, generate_presigned_url, verify_presigned_signature,
    },
};

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
pub async fn start(config: super::Config, fs_controller: FsController) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.ip_addr).await?;

    let auth = Arc::new(AuthState {
        hmac_secret: (0..255).collect(),
        domain: config.domain,
        api_key: "secret-api-key".to_string(),
    });

    let api_key_protected = Router::new()
        .route("/presign", post(presign_url))
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            require_api_key_auth,
        ))
        .with_state(auth.clone());

    let pre_sign_protected = Router::new()
        .route("/upload/{blob_id}", post(upload_data))
        .route("/files/{blob_id}", get(read_blob))
        .layer(middleware::from_fn_with_state(auth, require_presign_auth))
        .with_state(fs_controller);

    let service = Router::new()
        .merge(api_key_protected)
        .merge(pre_sign_protected)
        .fallback(reject_404) // NOTE: Without the fallback, we would always hit the authorization layer
        .layer(middleware::from_fn(metrics));

    axum::serve(listener, service).await?;

    Ok(())
}

struct AuthState {
    /// HMAC Secret
    hmac_secret: Vec<u8>,
    /// The domain under which the server is reachable
    domain: String,
    /// API-Key to generate pre-signed urls
    api_key: String,
}

async fn reject_404() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// Middleware that checks if the request is authorized with the proper API-key
async fn require_api_key_auth(
    State(auth): State<Arc<AuthState>>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse> {
    // Parse the authorization header
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or_else(|| Error::Unauthorized("missing header 'authorization'".to_string()))?;

    // Parse header value as string
    let auth_str = auth_header.to_str().map_err(|e| {
        Error::Unauthorized(format!("Auth-header is not a valid utf-8 string: {e}"))
    })?;

    // Check if string is "Bearer TOKEN" and return TOKEN
    let key = auth_str
        .strip_prefix("Bearer ")
        .ok_or_else(|| Error::Unauthorized("Auth-header: Expected 'Bearer TOKEN'".to_string()))?;

    // Compare API keys and reject invalid ones
    // NOTE: We use constant-time equality here to prevent timing attacks on the backend!
    if auth.api_key.as_bytes().ct_eq(key.as_bytes()).unwrap_u8() != 1 {
        return Err(Error::Unauthorized("Invalid API-Key".to_string()));
    }

    Ok(next.run(req).await)
}

/// Middleware that checks if the request uses a pre-signed-url
async fn require_presign_auth(
    State(auth): State<Arc<AuthState>>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse> {
    let method = req.method().as_str();
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or_default();

    // Extract signature and verify it
    let (expires, sig) = extract_sig_from_query(query).map_err(Error::Unauthorized)?;
    verify_presigned_signature(method, path, &sig, expires, &auth.hmac_secret)
        .map_err(Error::Unauthorized)?; // NOTE: The "?" is important here !

    Ok(next.run(req).await)
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
        #[error("stream was interrupted or broken")]
        BrokenStream,
        #[error("file not found")]
        NotFound,
        #[error("Missing required parameter 'blob_id'")]
        MissingBlobId,
        #[error("{0}")]
        Unauthorized(String),
        #[error("failed to parse header values: {0}")]
        Headers(String),
        #[error("failed to build response: {0}")]
        ResponseFailed(#[from] axum::http::Error),
        #[error(transparent)]
        Io(#[from] std::io::Error),
    }

    impl IntoResponse for Error {
        fn into_response(self) -> Response {
            let status = match &self {
                Error::Io(_) | Error::ResponseFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::Unauthorized(_) => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            };
            let message = self.to_string();
            let s = Success::error(message);
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
    #[serde(skip_serializing_if = "Option::is_none")]
    blob_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_written: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    missing_chunks: Option<Vec<usize>>,
}

impl Success {
    pub fn error(message: impl AsRef<str>) -> Self {
        Success {
            success: false,
            message: message.as_ref().to_string(),
            blob_id: None,
            bytes_written: None,
            missing_chunks: None,
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

async fn read_blob(
    State(storage): State<FsController>,
    Path(blob_id): Path<Uuid>,
) -> Result<Response> {
    let (blob_path, _) = storage.blob_path(&blob_id);

    let f = tokio::fs::File::open(blob_path)
        .await
        .map_err(|_| Error::NotFound)?;

    // Stream file content into a response
    let stream = ReaderStream::new(f);
    let body = Body::from_stream(stream);

    let response = Response::builder()
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(body)?;

    Ok(response)
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

/// General entrypoint for the upload logic
async fn upload_data(
    State(storage): State<FsController>,
    Path(blob_id): Path<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Success>> {
    // 1. Determine file upload type from headers
    let upload_type = UploadType::from_headers(&headers)?;

    match upload_type {
        UploadType::Full => {
            let r = upload_full(storage, blob_id, body).await;
            if let Err(e) = &r {
                warn!(%blob_id, "{e}");
            }
            r
        }
        UploadType::Chunked {
            chunk_idx,
            chunk_total,
        } => {
            let r = upload_chunk(storage, blob_id, chunk_idx, chunk_total, body).await;
            if let Err(e) = &r {
                warn!(%blob_id, chunk_idx, chunk_total, "{e}");
            }
            r
        }
        UploadType::Merge { chunk_total } => {
            let r = merge_chunks(storage, blob_id, chunk_total).await;
            if let Err(e) = &r {
                warn!(%blob_id, chunk_total, "{e}");
            }
            r
        }
    }
}

async fn upload_chunk(
    storage: FsController,
    blob_id: Uuid,
    chunk_idx: usize,
    chunk_total: usize,
    body: Body,
) -> Result<Json<Success>> {
    let (chunk_path, chunk_tmp) = storage.chunk_path(&blob_id, chunk_idx, chunk_total)?;
    // Check, if there is a blob with that ID
    let (blob_path, _) = storage.blob_path(&blob_id);
    if blob_path.exists() {
        return Err(Error::Duplicate);
    }
    let bytes_written = stream_body_to_file(body, chunk_path, chunk_tmp).await?;
    let bytes = byte_size_str(bytes_written);
    debug!(%blob_id, %bytes, "uploaded chunk {chunk_idx}/{chunk_total}");

    let success = Success {
        success: true,
        message: format!("uploaded chunk {chunk_idx}/{chunk_total}"),
        blob_id: Some(blob_id),
        bytes_written: Some(bytes_written),
        missing_chunks: None,
    };

    Ok(Json(success))
}

async fn merge_chunks(
    storage: FsController,
    blob_id: Uuid,
    chunk_total: usize,
) -> Result<Json<Success>> {
    // 1. Check that all chunks are present
    if let Err(missing_chunks) = storage.check_chunks(&blob_id, chunk_total) {
        return Ok(Json(Success {
            success: false,
            message: format!("missing {} of {} chunks", missing_chunks.len(), chunk_total),
            blob_id: Some(blob_id),
            bytes_written: None,
            missing_chunks: Some(missing_chunks),
        }));
    }

    let bytes_written = storage.merge_chunks(&blob_id, chunk_total)?;
    let bytes = byte_size_str(bytes_written);
    debug!(%blob_id, %bytes, "merged chunks");
    let success = Success {
        success: true,
        message: format!("merged {} chunks", chunk_total),
        blob_id: Some(blob_id),
        bytes_written: Some(bytes_written),
        missing_chunks: None,
    };
    Ok(Json(success))
}

/// Helper function to perform the oneshot (full) upload
async fn upload_full(storage: FsController, blob_id: Uuid, body: Body) -> Result<Json<Success>> {
    let (blob_path, blob_tmp) = storage.blob_path(&blob_id);
    if blob_path.exists() {
        return Err(Error::Duplicate);
    }
    let bytes_written = stream_body_to_file(body, blob_path, blob_tmp).await?;
    let bytes = byte_size_str(bytes_written);
    debug!(%blob_id, %bytes, "uploaded blob");
    let success = Success {
        success: true,
        message: "uploaded blob".to_string(),
        blob_id: Some(blob_id),
        bytes_written: Some(bytes_written),
        missing_chunks: None,
    };
    Ok(Json(success))
}

/// Helper function that streams the content of a http-body into a file
///
/// First a temporary file is created at `tmp_path`, which the bytes will be streamed to.
/// After the stream has finished, the `tmp_path` is renamed into `target_path`.
///
/// This way we will not end up with broken files due to interrupted connections.
/// All files with the `.tmp` suffix can later be spotted and removed.
async fn stream_body_to_file(body: Body, target_path: PathBuf, tmp_path: PathBuf) -> Result<usize> {
    let f = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(f);
    let mut bytes_written = 0;
    let mut stream = body.into_data_stream();
    while let Some(result) = stream.next().await {
        match result {
            Ok(b) => {
                writer.write_all(&b)?;
                bytes_written += b.len();
            }
            Err(_) => {
                return Err(Error::BrokenStream);
            }
        }
    }
    writer.flush()?;
    std::fs::rename(&tmp_path, &target_path)?;
    Ok(bytes_written)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresignAction {
    Upload,
    Download,
}

#[derive(Serialize)]
pub struct PresignResponse {
    pub success: bool,
    pub action: PresignAction,
    pub blob_id: Uuid,
    pub url: String,
    pub method: String,
    pub expires_in: u64, // seconds
}

#[derive(Deserialize)]
pub struct PresignRequest {
    pub action: PresignAction,

    /// Optional: server can generate one if not provided (only valid for uploads)
    #[serde(default)]
    pub blob_id: Option<Uuid>,

    /// Optional: duration in seconds, server clamps to max allowed
    #[serde(default)]
    pub expires_in: Option<u64>,
}

async fn presign_url(
    State(auth): State<Arc<AuthState>>,
    Json(presign): Json<PresignRequest>,
) -> Result<Json<PresignResponse>> {
    let expires_in = presign.expires_in.unwrap_or(60 * 15); // 15 minutes default

    let (method, path, blob_id) = match presign.action {
        PresignAction::Upload => {
            let blob_id = presign.blob_id.unwrap_or_else(|| Uuid::now_v7());
            ("POST", format!("/upload/{blob_id}"), blob_id)
        }
        PresignAction::Download => {
            let blob_id = match presign.blob_id {
                Some(id) => id,
                None => return Err(Error::MissingBlobId),
            };
            ("GET", format!("/files/{blob_id}"), blob_id)
        }
    };

    let signed_url =
        generate_presigned_url(method, &auth.domain, &path, &auth.hmac_secret, expires_in);

    let res = PresignResponse {
        success: true,
        action: presign.action,
        blob_id,
        url: signed_url,
        method: method.to_string(),
        expires_in,
    };
    Ok(Json(res))
}
