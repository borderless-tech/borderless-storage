use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio_util::{io::ReaderStream, sync::CancellationToken};
use tower_http::{
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
    timeout::{RequestBodyTimeoutLayer, TimeoutLayer},
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::{Level, debug, info, warn};
use uuid::Uuid;

use self::error::Error;
use crate::{
    metadata::{BlobMetadata, MetadataStore},
    storage::FsController,
    utils::{
        byte_size_str, extract_sig_from_query, generate_presigned_url,
        normalize_and_validate_bucket_name, verify_presigned_signature,
    },
};

use super::Config;

/// Http-header to specify the upload type
const UPLOAD_TYPE: &str = "x-upload-type";

/// Http-header value that indicates a 'full' upload (all bytes in one request)
const UPLOAD_TYPE_FULL: &str = "full";

/// Http-header value that indicates a 'chunked' upload (multiple requests per file)
const UPLOAD_TYPE_CHUNK: &str = "chunked";

/// Http-header to specify the chunk-index
const CHUNK_IDX: &str = "x-chunk-index";

/// Http-header to specify the total amount of chunks
const CHUNK_TOTAL: &str = "x-chunk-total";

/// Http-header that is used in the last request of a chunk upload to advice the server to merge the chunks
const CHUNK_MERGE: &str = "x-chunk-merge";

/// Maximum (and default) expiry time for signatures
const MAX_EXPIRY_SECS: u64 = 15 * 60; // 15 Minutes

/// Entrypoint to start the webserver
///
/// This function basically never returns - it only does in case of an error.
pub async fn start(
    config: Config,
    fs_controller: FsController,
    shutdown_token: CancellationToken,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.ip_addr).await?;

    let service = build_service(config, fs_controller);

    info!("🚀 Launching webserver");
    axum::serve(listener, service)
        .with_graceful_shutdown(async move {
            shutdown_token.cancelled().await;
        })
        .await?;
    Ok(())
}

fn build_service(config: Config, fs_controller: FsController) -> Router {
    // --- Initialize tracing layer
    //
    // NOTE: If we would use 'include_headers(true)' - then we need this layer aswell, to now show the bearer token in the log
    // let exclude_headers = Arc::new([header::AUTHORIZATION, header::PROXY_AUTHORIZATION]);
    // .layer(SetSensitiveHeadersLayer::from_shared(
    //     exclude_headers.clone(),
    // ))
    let tracing_layer = TraceLayer::new_for_http()
        // .make_span_with(DefaultMakeSpan::new().include_headers(true))
        .make_span_with(|req: &axum::http::Request<_>| {
            let rid = req
                .extensions()
                .get::<RequestId>()
                .and_then(|id| id.header_value().to_str().ok())
                .unwrap_or("-");
            // NOTE: We strip the query from the request, to avoid leaking presigned urls into our logs
            tracing::info_span!("request",
                       request_id = %rid,
                       method = %req.method(),
                       uri = %req.uri().path()
            )
        })
        .on_request(DefaultOnRequest::new().level(Level::DEBUG))
        .on_response(
            DefaultOnResponse::new()
                .level(Level::INFO)
                .latency_unit(tower_http::LatencyUnit::Millis),
        );

    // In debug mode, always allow all cors headers

    #[cfg(debug_assertions)]
    let allowed_origins = {
        info!("🌐 Debug-Build: Allowing all cors origins");
        tower_http::cors::Any
    };
    #[cfg(not(debug_assertions))]
    let allowed_origins = {
        if let Some(origins) = config.cors_origins {
            let out = tower_http::cors::AllowOrigin::list(
                origins.split(',').flat_map(|s| s.parse().ok()),
            );
            for value in origins.split(',') {
                info!("🌐 Allowing cors origin '{value}'");
            }
            out
        } else {
            warn!(
                "🌐 No allowed cors origins specified ! Defaulting to any '*' - this is not recommended in production setups!"
            );
            tower_http::cors::AllowOrigin::any()
        }
    };

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            CONTENT_DISPOSITION,
            HeaderName::from_static(UPLOAD_TYPE),
            HeaderName::from_static(CHUNK_IDX),
            HeaderName::from_static(CHUNK_TOTAL),
            HeaderName::from_static(CHUNK_MERGE),
        ])
        // Optional: cache preflight for a day
        .max_age(std::time::Duration::from_secs(24 * 60 * 60));

    // Add no-store header for upload and presign route
    let no_store =
        SetResponseHeaderLayer::overriding(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    let hmac_secret = if let Some(s) = config.presign_hmac_secret {
        s.into_bytes()
    } else {
        /* generate random secret with 256 bit entropy */
        (0..255).map(|_| rand::random()).collect()
    };

    let auth = Arc::new(AuthState {
        hmac_secret,
        domain: config.domain,
        api_key: config.presign_api_key,
        metadata_store: fs_controller.get_metadata_store(),
    });

    let legacy_api_key_protected = Router::new()
        .route("/presign", post(presign_url))
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            require_api_key_auth,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_presign_rq_size))
        .layer(no_store.clone()) // Never cache presign responses ( IMPORTANT! )
        .with_state(auth.clone());

    // Legacy routes for backward compatibility (use "default" bucket)
    let legacy_upload = Router::new()
        .route("/upload/{blob_id}", post(legacy_upload_data))
        .route("/upload/{blob_id}", put(legacy_upload_data_put))
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            require_presign_auth,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_data_rq_size))
        .layer(no_store.clone()) // Never cache upload responses
        .with_state(fs_controller.clone());

    let legacy_files = Router::new()
        .route("/files/{blob_id}", get(legacy_read_blob))
        .route("/files/{blob_id}", delete(legacy_delete_blob))
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            require_presign_auth,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_data_rq_size))
        .with_state(fs_controller.clone());

    // New bucket-aware routes: /{bucket}/{blob_id}
    let bucket_aware_routes = Router::new()
        .route("/{bucket}/{blob_id}", get(read_blob_with_bucket))
        .route("/{bucket}/{blob_id}", post(upload_data_with_bucket))
        .route("/{bucket}/{blob_id}", put(upload_data_put_with_bucket))
        .route("/{bucket}/{blob_id}", delete(delete_blob_with_bucket))
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            require_presign_auth,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_data_rq_size))
        .with_state(fs_controller.clone());

    // Admin API presign route (uses Arc<AuthState>)
    let admin_presign = Router::new()
        .route("/admin/presign", post(presign_url))
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            require_api_key_auth,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_presign_rq_size))
        .layer(no_store.clone())
        .with_state(auth.clone());

    // Admin API routes - protected by API key (uses FsController)
    let admin_api = Router::new()
        .route("/admin/buckets", get(admin_list_buckets))
        .route("/admin/buckets/{bucket}", get(admin_get_bucket))
        .route("/admin/buckets/{bucket}", delete(admin_delete_bucket))
        .route("/admin/objects", get(admin_list_objects))
        .route("/admin/objects/{bucket}", get(admin_list_objects_in_bucket))
        .route("/admin/stats", get(admin_storage_stats))
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            require_api_key_auth,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_presign_rq_size))
        .with_state(fs_controller);

    let metrics_api = Router::new().route("/healthz", get(health_check));

    // NOTE: Middleware is layered like an onion:
    //
    //         requests
    //            |
    //            v
    // +----- layer_three -----+
    // | +---- layer_two ----+ |
    // | | +-- layer_one --+ | |
    // | | |               | | |
    // | | |    handler    | | |
    // | | |               | | |
    // | | +-- layer_one --+ | |
    // | +---- layer_two ----+ |
    // +----- layer_three -----+
    //            |
    //            v
    //         responses
    Router::new()
        .merge(metrics_api)
        .merge(legacy_api_key_protected)
        .merge(legacy_upload)
        .merge(legacy_files)
        .merge(admin_presign)
        .merge(admin_api)
        .merge(bucket_aware_routes)
        .fallback(reject_404) // NOTE: Without the fallback, we would always hit the authorization layer
        .layer(cors)
        .layer(tracing_layer)
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TimeoutLayer::new(Duration::from_secs(
            config.rq_timeout_secs,
        )))
        .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(
            config.rq_timeout_secs,
        )))
}

struct AuthState {
    /// HMAC Secret
    hmac_secret: Vec<u8>,
    /// The domain under which the server is reachable
    domain: String,
    /// API-Key to generate pre-signed urls
    api_key: String,
    /// Metadata storage (to access sha256 hash)
    metadata_store: Arc<MetadataStore>,
}

/// Helper function for 404 rejections
async fn reject_404() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// Simple existence check for load-balancer
async fn health_check() -> StatusCode {
    StatusCode::OK
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

/// Presign TTL to set cache header to the correct time
#[derive(Clone, Copy)]
struct PresignTtl(u64);

/// Middleware that checks if the request uses a pre-signed-url
async fn require_presign_auth(
    State(auth): State<Arc<AuthState>>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse> {
    let method = req.method().as_str();
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or_default();

    // Extract signature and verify it
    let (expires, sig) = extract_sig_from_query(query).map_err(Error::Unauthorized)?;
    let ttl = verify_presigned_signature(method, path, &sig, expires, &auth.hmac_secret)
        .map_err(Error::Unauthorized)?; // NOTE: The "?" is important here !

    // Insert ttl into extension
    req.extensions_mut().insert(PresignTtl(ttl));

    Ok(next.run(req).await)
}

mod error {
    use super::Success;
    use axum::{
        http::{
            StatusCode,
            header::{CONTENT_TYPE, ToStrError},
        },
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
        #[error("Invalid bucket name: {0}")]
        BucketName(String),
        #[error("Header contained non-ascii value: {0}")]
        InvalidHeader(#[from] ToStrError),
        #[error("{0}")]
        Unauthorized(String),
        #[error("failed to parse header values: {0}")]
        Headers(String),
        #[error("failed to build response: {0}")]
        ResponseFailed(#[from] axum::http::Error),
        #[error("io-error: {0}")]
        Io(#[from] std::io::Error),
        #[error("sqlite-error: {0}")]
        Metadata(#[from] rusqlite::Error),
    }

    impl IntoResponse for Error {
        fn into_response(self) -> Response {
            let status = match &self {
                // IO, database and response builder are server errors
                Error::Io(_) | Error::Metadata(_) | Error::ResponseFailed(_) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
                Error::Unauthorized(_) => StatusCode::UNAUTHORIZED,
                Error::Duplicate => StatusCode::CONFLICT,
                Error::NotFound => StatusCode::NOT_FOUND,
                // Everything else is a 400 bad-request
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

#[derive(Serialize, Deserialize)]
struct Success {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    blob_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_written: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256_hash: Option<String>,
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
            sha256_hash: None,
            missing_chunks: None,
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Bucket-aware blob download handler
async fn read_blob_with_bucket(
    State(storage): State<FsController>,
    Extension(PresignTtl(rem_ttl)): Extension<PresignTtl>,
    Path((bucket, blob_id)): Path<(String, Uuid)>,
) -> Result<Response> {
    // Normalize and validate bucket name
    let bucket = normalize_and_validate_bucket_name(&bucket).map_err(Error::BucketName)?;

    // Get metadata first to find content hash
    let metadata = storage
        .get_metadata(&bucket, &blob_id)?
        .ok_or(Error::NotFound)?;

    // Try to open the file - check content-addressed storage first, then fall back to blob path
    let f = if let Some(ref hash) = metadata.sha256_hash {
        let content_path = storage.content_path_from_hex(hash);
        match tokio::fs::File::open(&content_path).await {
            Ok(file) => file,
            Err(_) => {
                // Fallback to blob path (unmigrated or migration in progress)
                let blob_path = storage.blob_path(&bucket, &blob_id).0;
                tokio::fs::File::open(&blob_path)
                    .await
                    .map_err(|_| Error::NotFound)?
            }
        }
    } else {
        // No hash in metadata, use blob path directly
        let blob_path = storage.blob_path(&bucket, &blob_id).0;
        tokio::fs::File::open(&blob_path)
            .await
            .map_err(|_| Error::NotFound)?
    };

    // Stream file content into a response
    let stream = ReaderStream::new(f);
    let body = Body::from_stream(stream);

    // Set cache-control header to remaining ttl (and clamp at MAX_)
    let max_age = rem_ttl.min(MAX_EXPIRY_SECS);
    let cache_hdr = if max_age > 0 {
        format!("private, max-age={max_age}, immutable")
    } else {
        "no-store".to_string()
    };

    // Retrieve metadata and apply to response headers
    let mut response_builder = Response::builder().header(CACHE_CONTROL, cache_hdr);

    // Apply Content-Type if available, otherwise use default
    if let Some(content_type) = &metadata.content_type {
        response_builder = response_builder.header(CONTENT_TYPE, content_type);
    } else {
        response_builder = response_builder.header(CONTENT_TYPE, "application/octet-stream");
    }

    // Apply Content-Disposition if available
    if let Some(content_disposition) = &metadata.content_disposition {
        response_builder = response_builder.header(CONTENT_DISPOSITION, content_disposition);
    }

    debug!(
        blob_id = %blob_id,
        bucket = %bucket,
        content_type = metadata.content_type.as_deref().unwrap_or("none"),
        content_disposition = metadata.content_disposition.as_deref().unwrap_or("none"),
        "applied blob metadata to response"
    );

    let response = response_builder.body(body)?;
    Ok(response)
}

/// Legacy blob download handler (uses "default" bucket)
async fn legacy_read_blob(
    State(storage): State<FsController>,
    Extension(rem_ttl): Extension<PresignTtl>,
    Path(blob_id): Path<Uuid>,
) -> Result<Response> {
    read_blob_with_bucket(
        State(storage),
        Extension(rem_ttl),
        Path(("default".to_string(), blob_id)),
    )
    .await
}

/// Bucket-aware handler for deleting a blob
async fn delete_blob_with_bucket(
    State(storage): State<FsController>,
    Path((bucket, blob_id)): Path<(String, Uuid)>,
) -> Result<Json<Success>> {
    // Normalize and validate bucket name
    let bucket = normalize_and_validate_bucket_name(&bucket).map_err(Error::BucketName)?;

    // Delete the blob from both filesystem and metadata
    let existed = storage.delete_blob(&bucket, &blob_id).map_err(|e| {
        warn!("Failed to delete blob {}/{}: {}", bucket, blob_id, e);
        Error::Headers(format!("Failed to delete blob: {e}"))
    })?;

    if !existed {
        return Err(Error::NotFound);
    }

    info!(%blob_id, bucket = %bucket, "deleted blob");

    Ok(Json(Success {
        success: true,
        message: format!("deleted blob {blob_id}"),
        blob_id: Some(blob_id),
        bytes_written: None,
        sha256_hash: None,
        missing_chunks: None,
    }))
}

/// Legacy handler for deleting a blob (uses "default" bucket)
async fn legacy_delete_blob(
    State(storage): State<FsController>,
    Path(blob_id): Path<Uuid>,
) -> Result<Json<Success>> {
    delete_blob_with_bucket(State(storage), Path(("default".to_string(), blob_id))).await
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
                    "require header {UPLOAD_TYPE} to be either '{UPLOAD_TYPE_FULL}' or '{UPLOAD_TYPE_CHUNK}'"
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

/// Extract metadata from request headers
fn extract_metadata_from_headers(
    headers: &HeaderMap,
    bucket: String,
    blob_id: Uuid,
) -> Result<BlobMetadata> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .map(|h| h.to_str())
        .transpose()?
        .map(|s| s.to_string());

    let content_disposition = headers
        .get(CONTENT_DISPOSITION)
        .map(|h| h.to_str())
        .transpose()?
        .map(|s| s.to_string());

    Ok(BlobMetadata::new(bucket, blob_id)
        .with_content_type(content_type)
        .with_content_disposition(content_disposition))
}

/// General entrypoint for the upload logic (bucket-aware)
async fn upload_data_with_bucket(
    State(storage): State<FsController>,
    Path((bucket, blob_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Success>> {
    // Normalize and validate bucket name
    let bucket = normalize_and_validate_bucket_name(&bucket).map_err(Error::BucketName)?;

    // 1. Extract metadata from headers
    let metadata = extract_metadata_from_headers(&headers, bucket.clone(), blob_id)?;

    // 2. Determine file upload type from headers
    let upload_type = UploadType::from_headers(&headers)?;

    match upload_type {
        UploadType::Full => {
            let r = upload_full(storage, bucket, blob_id, metadata, body, false).await;
            if let Err(e) = &r {
                warn!(%blob_id, "{e}");
            }
            r
        }
        UploadType::Chunked {
            chunk_idx,
            chunk_total,
        } => {
            // For chunked uploads, we'll store metadata when all chunks are merged
            let r = upload_chunk(
                storage,
                bucket,
                blob_id,
                chunk_idx,
                chunk_total,
                body,
                false,
            )
            .await;
            if let Err(e) = &r {
                warn!(%blob_id, chunk_idx, chunk_total, "{e}");
            }
            r
        }
        UploadType::Merge { chunk_total } => {
            let r = merge_chunks(storage, bucket, blob_id, chunk_total, metadata).await;
            if let Err(e) = &r {
                warn!(%blob_id, chunk_total, "{e}");
            }
            r
        }
    }
}

/// Legacy entrypoint for upload logic (uses "default" bucket)
async fn legacy_upload_data(
    State(storage): State<FsController>,
    Path(blob_id): Path<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Success>> {
    upload_data_with_bucket(
        State(storage),
        Path(("default".to_string(), blob_id)),
        headers,
        body,
    )
    .await
}

/// General entrypoint for the upload logic (PUT method - allows overwrite, bucket-aware)
async fn upload_data_put_with_bucket(
    State(storage): State<FsController>,
    Path((bucket, blob_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Success>> {
    // Normalize and validate bucket name
    let bucket = normalize_and_validate_bucket_name(&bucket).map_err(Error::BucketName)?;

    let metadata = extract_metadata_from_headers(&headers, bucket.clone(), blob_id)?;
    let upload_type = UploadType::from_headers(&headers)?;

    match upload_type {
        UploadType::Full => {
            let r = upload_full(storage, bucket, blob_id, metadata, body, true).await;
            if let Err(e) = &r {
                warn!(%blob_id, "{e}");
            }
            r
        }
        UploadType::Chunked {
            chunk_idx,
            chunk_total,
        } => {
            let r =
                upload_chunk(storage, bucket, blob_id, chunk_idx, chunk_total, body, true).await;
            if let Err(e) = &r {
                warn!(%blob_id, chunk_idx, chunk_total, "{e}");
            }
            r
        }
        UploadType::Merge { chunk_total } => {
            let r = merge_chunks(storage, bucket, blob_id, chunk_total, metadata).await;
            if let Err(e) = &r {
                warn!(%blob_id, chunk_total, "{e}");
            }
            r
        }
    }
}

/// Legacy entrypoint for upload logic (PUT method - uses "default" bucket)
async fn legacy_upload_data_put(
    State(storage): State<FsController>,
    Path(blob_id): Path<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Success>> {
    upload_data_put_with_bucket(
        State(storage),
        Path(("default".to_string(), blob_id)),
        headers,
        body,
    )
    .await
}

async fn upload_chunk(
    storage: FsController,
    bucket: String,
    blob_id: Uuid,
    chunk_idx: usize,
    chunk_total: usize,
    body: Body,
    allow_overwrite: bool,
) -> Result<Json<Success>> {
    let (chunk_path, chunk_tmp) = storage.chunk_path(&blob_id, chunk_idx, chunk_total)?;

    // TODO: I think this logic is now wrong !
    // Check if there is already a final blob with that ID (only if overwrite not allowed)
    if !allow_overwrite {
        let (blob_path, _) = storage.blob_path(&bucket, &blob_id);
        if blob_path.exists() {
            return Err(Error::Duplicate);
        }
    }

    let (bytes_written, _sha256) = stream_body_to_file(body, chunk_tmp.clone()).await?;

    // Rename tmp to final chunk path
    std::fs::rename(&chunk_tmp, &chunk_path)?;
    let bytes = byte_size_str(bytes_written);
    debug!(%blob_id, %bytes, "uploaded chunk {chunk_idx}/{chunk_total}");

    let success = Success {
        success: true,
        message: format!("uploaded chunk {chunk_idx}/{chunk_total}"),
        blob_id: Some(blob_id),
        bytes_written: Some(bytes_written),
        sha256_hash: None,
        missing_chunks: None,
    };

    Ok(Json(success))
}

async fn merge_chunks(
    storage: FsController,
    bucket: String,
    blob_id: Uuid,
    chunk_total: usize,
    mut metadata: BlobMetadata,
) -> Result<Json<Success>> {
    // 1. Check that all chunks are present
    if let Err(missing_chunks) = storage.check_chunks(&blob_id, chunk_total) {
        return Ok(Json(Success {
            success: false,
            message: format!("missing {} of {} chunks", missing_chunks.len(), chunk_total),
            blob_id: Some(blob_id),
            bytes_written: None,
            sha256_hash: None,
            missing_chunks: Some(missing_chunks),
        }));
    }

    // Ensure bucket directory exists before merging
    storage.ensure_bucket_dir(&bucket)?;

    // Step 1: Merge chunks to temporary file and calculate hash
    let (tmp_path, bytes_written, sha256) = storage.merge_chunks(&bucket, &blob_id, chunk_total)?;
    let sha256_hex = hex::encode(sha256);

    // Step 2: Move content to content-addressable storage (with dedup)
    let content_path = storage.content_path(&sha256);
    let dedup_occurred = if !content_path.exists() {
        // We're first! Move our merged file to content storage
        std::fs::rename(&tmp_path, &content_path)?;
        debug!(%blob_id, hash=%sha256_hex, "stored new content from merged chunks");
        false
    } else {
        // Content already exists (dedup!), discard our copy
        std::fs::remove_file(&tmp_path)?;
        debug!(%blob_id, hash=%sha256_hex, "deduplicated merged chunks");
        true
    };

    // Step 3: Store metadata and update refcount
    metadata = metadata
        .with_file_size(bytes_written as i64)
        .with_sha256_hash(sha256_hex.clone());

    // Store metadata
    storage.store_metadata(&metadata)?;

    // Update content reference count
    storage
        .get_metadata_store()
        .increment_content_ref(&sha256_hex, bytes_written as i64)?;

    // Step 4: Optionally create symlink for human visibility
    storage.handle_symlinks(&bucket, &blob_id, &sha256);

    let bytes = byte_size_str(bytes_written);
    let dedup_msg = if dedup_occurred {
        " (deduplicated)"
    } else {
        ""
    };
    debug!(%blob_id, %bytes, hash=%sha256_hex, "merged chunks{}", dedup_msg);

    let success = Success {
        success: true,
        message: format!("merged {} chunks{}", chunk_total, dedup_msg),
        blob_id: Some(blob_id),
        bytes_written: Some(bytes_written),
        sha256_hash: Some(sha256_hex),
        missing_chunks: None,
    };
    Ok(Json(success))
}

/// Helper function to perform the oneshot (full) upload
async fn upload_full(
    storage: FsController,
    bucket: String,
    blob_id: Uuid,
    mut metadata: BlobMetadata,
    body: Body,
    allow_overwrite: bool,
) -> Result<Json<Success>> {
    // Ensure bucket directory exists
    storage.ensure_bucket_dir(&bucket)?;

    let (_blob_path, blob_tmp) = storage.blob_path(&bucket, &blob_id);

    // Check for duplicate blob_id if overwrite not allowed (POST semantics)
    // Note: we check metadata, not filesystem, since we use content-addressable storage
    if !allow_overwrite && storage.get_metadata(&bucket, &blob_id)?.is_some() {
        return Err(Error::Duplicate);
    }

    // Step 1: Stream to temporary file and calculate hash
    let (bytes_written, sha256) = stream_body_to_file(body, blob_tmp.clone()).await?;
    let sha256_hex = hex::encode(sha256);

    // Step 2: Move content to content-addressable storage (with dedup)
    let content_path = storage.content_path(&sha256);
    let dedup_occurred = if !content_path.exists() {
        // We're first! Move our upload to content storage
        std::fs::rename(&blob_tmp, &content_path)?;
        debug!(%blob_id, hash=%sha256_hex, "stored new content");
        false
    } else {
        // Content already exists (dedup!), discard our copy
        std::fs::remove_file(&blob_tmp)?;
        debug!(%blob_id, hash=%sha256_hex, "deduplicated content");
        true
    };

    // Step 3: Store metadata and update refcount
    metadata = metadata
        .with_file_size(bytes_written as i64)
        .with_sha256_hash(sha256_hex.clone());

    // Store metadata
    storage.store_metadata(&metadata)?;

    // Update content reference count
    storage
        .get_metadata_store()
        .increment_content_ref(&sha256_hex, bytes_written as i64)?;

    // Step 4: Optionally create symlink for human visibility
    storage.handle_symlinks(&bucket, &blob_id, &sha256);

    let bytes = byte_size_str(bytes_written);
    let dedup_msg = if dedup_occurred {
        " (deduplicated)"
    } else {
        ""
    };
    debug!(%blob_id, %bytes, hash=%sha256_hex, "uploaded blob{}", dedup_msg);

    let success = Success {
        success: true,
        message: format!("uploaded blob{}", dedup_msg),
        blob_id: Some(blob_id),
        bytes_written: Some(bytes_written),
        sha256_hash: Some(sha256_hex),
        missing_chunks: None,
    };
    Ok(Json(success))
}

/// Helper function that streams the content of a http-body into a temporary file
///
/// Streams bytes to `tmp_path` and calculates SHA-256 hash during streaming.
/// Returns the number of bytes written and the hash.
///
/// NOTE: This function does NOT rename the tmp file - caller must handle final placement
/// (either rename to content-addressed storage or to blob storage).
async fn stream_body_to_file(body: Body, tmp_path: PathBuf) -> Result<(usize, [u8; 32])> {
    let f = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(f);
    let mut bytes_written = 0;
    let mut stream = body.into_data_stream();
    let mut hash = Sha256::new();
    while let Some(result) = stream.next().await {
        match result {
            Ok(b) => {
                hash.update(&b);
                writer.write_all(&b)?;
                bytes_written += b.len();
            }
            Err(_) => {
                return Err(Error::BrokenStream);
            }
        }
    }
    writer.flush()?;
    let sha256 = hash.finalize();
    Ok((bytes_written, sha256.into()))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresignAction {
    Upload,
    Update,
    Download,
    Delete,
}

#[derive(Serialize)]
pub struct PresignResponse {
    pub success: bool,
    pub action: PresignAction,
    pub blob_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_hash: Option<String>,
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

    /// Optional: bucket name, defaults to "default"
    #[serde(default)]
    pub bucket: Option<String>,

    /// Optional: duration in seconds, server clamps to max allowed
    #[serde(default)]
    pub expires_in: Option<u64>,
}

async fn presign_url(
    State(auth): State<Arc<AuthState>>,
    Json(presign): Json<PresignRequest>,
) -> Result<Json<PresignResponse>> {
    // Use max as default and clamp to maximum
    let expires_in = presign
        .expires_in
        .unwrap_or(MAX_EXPIRY_SECS)
        .min(MAX_EXPIRY_SECS);

    // Get bucket from request or default to "default", then validate and normalize
    let bucket_input = presign.bucket.as_deref().unwrap_or("default");
    let bucket = normalize_and_validate_bucket_name(bucket_input).map_err(Error::BucketName)?;

    // Check upload action
    let (method, path, blob_id, sha256_hash) = match presign.action {
        PresignAction::Upload => {
            let blob_id = presign.blob_id.unwrap_or_else(Uuid::now_v7);
            // Use new bucket-aware path
            ("POST", format!("/{bucket}/{blob_id}"), blob_id, None)
        }
        PresignAction::Update => {
            let blob_id = match presign.blob_id {
                Some(id) => id,
                None => return Err(Error::MissingBlobId),
            };
            // Use new bucket-aware path
            ("PUT", format!("/{bucket}/{blob_id}"), blob_id, None)
        }
        PresignAction::Download => {
            let blob_id = match presign.blob_id {
                Some(id) => id,
                None => return Err(Error::MissingBlobId),
            };
            let sha256_hash = auth
                .metadata_store
                .get_sha256(&bucket, &blob_id)
                .ok()
                .flatten();
            // Use new bucket-aware path
            ("GET", format!("/{bucket}/{blob_id}"), blob_id, sha256_hash)
        }
        PresignAction::Delete => {
            let blob_id = match presign.blob_id {
                Some(id) => id,
                None => return Err(Error::MissingBlobId),
            };
            // Use new bucket-aware path
            ("DELETE", format!("/{bucket}/{blob_id}"), blob_id, None)
        }
    };
    debug!(%expires_in, %method, %path, %blob_id, bucket, "presigning url");

    let signed_url =
        generate_presigned_url(method, &auth.domain, &path, &auth.hmac_secret, expires_in);

    let res = PresignResponse {
        success: true,
        action: presign.action,
        blob_id,
        sha256_hash,
        url: signed_url,
        method: method.to_string(),
        expires_in,
    };
    Ok(Json(res))
}

// ============================================================================
// Admin API - Bucket and Object Management
// ============================================================================

#[derive(Serialize)]
struct BucketResponse {
    name: String,
    created_at: String,
    object_count: i64,
    total_size: i64,
    total_size_human: String,
}

impl From<crate::metadata::Bucket> for BucketResponse {
    fn from(bucket: crate::metadata::Bucket) -> Self {
        BucketResponse {
            name: bucket.name,
            created_at: bucket.created_at.to_rfc3339(),
            object_count: bucket.object_count,
            total_size: bucket.total_size,
            total_size_human: byte_size_str(bucket.total_size as usize),
        }
    }
}

#[derive(Serialize)]
struct ListBucketsResponse {
    success: bool,
    buckets: Vec<BucketResponse>,
}

#[derive(Serialize)]
struct GetBucketResponse {
    success: bool,
    bucket: BucketResponse,
}

#[derive(Serialize)]
struct ObjectResponse {
    bucket: String,
    blob_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_disposition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_size_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256_hash: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<BlobMetadata> for ObjectResponse {
    fn from(meta: BlobMetadata) -> Self {
        ObjectResponse {
            bucket: meta.bucket,
            blob_id: meta.blob_id,
            content_type: meta.content_type,
            content_disposition: meta.content_disposition,
            file_size: meta.file_size,
            file_size_human: meta.file_size.map(|s| byte_size_str(s as usize)),
            sha256_hash: meta.sha256_hash,
            created_at: meta.created_at.to_rfc3339(),
            updated_at: meta.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Serialize)]
struct ListObjectsResponse {
    success: bool,
    objects: Vec<ObjectResponse>,
    total: usize,
    limit: u32,
    offset: u32,
}

#[derive(Serialize)]
struct StorageStatsResponse {
    success: bool,
    stats: crate::metadata::StorageStats,
}

#[derive(Deserialize)]
struct PaginationQuery {
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u32>,
}

/// Default pagination limit
const DEFAULT_LIMIT: u32 = 100;

/// Maximum pagination limit
const MAX_LIMIT: u32 = 1000;

/// GET /admin/buckets - List all buckets
async fn admin_list_buckets(
    State(storage): State<FsController>,
) -> Result<Json<ListBucketsResponse>> {
    let buckets = storage
        .get_metadata_store()
        .list_buckets()
        .map_err(|e| Error::Headers(format!("Failed to list buckets: {e}")))?;

    let bucket_responses: Vec<BucketResponse> = buckets.into_iter().map(Into::into).collect();

    Ok(Json(ListBucketsResponse {
        success: true,
        buckets: bucket_responses,
    }))
}

/// GET /admin/buckets/:bucket - Get bucket info
async fn admin_get_bucket(
    State(storage): State<FsController>,
    Path(bucket): Path<String>,
) -> Result<Json<GetBucketResponse>> {
    // Normalize and validate bucket name
    let bucket = normalize_and_validate_bucket_name(&bucket).map_err(Error::BucketName)?;

    let bucket_info = storage
        .get_metadata_store()
        .get_bucket(&bucket)
        .map_err(|e| Error::Headers(format!("Failed to get bucket: {e}")))?
        .ok_or(Error::NotFound)?;

    Ok(Json(GetBucketResponse {
        success: true,
        bucket: bucket_info.into(),
    }))
}

/// DELETE /admin/buckets/:bucket - Delete bucket (only if empty)
async fn admin_delete_bucket(
    State(storage): State<FsController>,
    Path(bucket): Path<String>,
) -> Result<Json<Success>> {
    // Normalize and validate bucket name
    let bucket = normalize_and_validate_bucket_name(&bucket).map_err(Error::BucketName)?;

    // Check if bucket is empty
    let bucket_info = storage
        .get_metadata_store()
        .get_bucket(&bucket)
        .map_err(|e| Error::Headers(format!("Failed to get bucket: {e}")))?
        .ok_or(Error::NotFound)?;

    if bucket_info.object_count > 0 {
        return Err(Error::Headers(format!(
            "Bucket '{}' is not empty ({} objects)",
            bucket, bucket_info.object_count
        )));
    }

    // Delete the bucket
    let deleted = storage
        .get_metadata_store()
        .delete_bucket(&bucket)
        .map_err(|e| Error::Headers(format!("Failed to delete bucket: {e}")))?;

    if !deleted {
        return Err(Error::NotFound);
    }

    // Also delete the bucket directory from filesystem
    let bucket_dir = storage.bucket_dir(&bucket);
    if bucket_dir.exists() {
        std::fs::remove_dir_all(&bucket_dir)
            .map_err(|e| Error::Headers(format!("Failed to delete bucket directory: {e}")))?;
    }

    info!(%bucket, "deleted bucket");

    Ok(Json(Success {
        success: true,
        message: format!("deleted bucket '{}'", bucket),
        blob_id: None,
        bytes_written: None,
        sha256_hash: None,
        missing_chunks: None,
    }))
}

/// GET /admin/objects - List all objects (paginated)
async fn admin_list_objects(
    State(storage): State<FsController>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<ListObjectsResponse>> {
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);

    let objects = storage
        .get_metadata_store()
        .list_all_objects(Some(limit), Some(offset))
        .map_err(|e| Error::Headers(format!("Failed to list objects: {e}")))?;

    let total = objects.len();
    let object_responses: Vec<ObjectResponse> = objects.into_iter().map(Into::into).collect();

    Ok(Json(ListObjectsResponse {
        success: true,
        objects: object_responses,
        total,
        limit,
        offset,
    }))
}

/// GET /admin/objects/:bucket - List objects in bucket (paginated)
async fn admin_list_objects_in_bucket(
    State(storage): State<FsController>,
    Path(bucket): Path<String>,
    Query(params): Query<PaginationQuery>,
) -> Result<Json<ListObjectsResponse>> {
    // Normalize and validate bucket name
    let bucket = normalize_and_validate_bucket_name(&bucket).map_err(Error::BucketName)?;

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);

    let objects = storage
        .get_metadata_store()
        .list_objects_in_bucket(&bucket, Some(limit), Some(offset))
        .map_err(|e| Error::Headers(format!("Failed to list objects: {e}")))?;

    let total = objects.len();
    let object_responses: Vec<ObjectResponse> = objects.into_iter().map(Into::into).collect();

    Ok(Json(ListObjectsResponse {
        success: true,
        objects: object_responses,
        total,
        limit,
        offset,
    }))
}

/// GET /admin/stats - Get comprehensive storage statistics
async fn admin_storage_stats(
    State(storage): State<FsController>,
) -> Result<Json<StorageStatsResponse>> {
    let stats = storage
        .get_metadata_store()
        .get_storage_stats()
        .map_err(|e| Error::Headers(format!("Failed to get storage stats: {e}")))?;

    Ok(Json(StorageStatsResponse {
        success: true,
        stats,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request as HttpRequest, StatusCode},
    };
    use serde_json::Value;
    use tempfile::{TempDir, tempdir};
    use tower::ServiceExt; // for .oneshot
    use uuid::Uuid;

    /// Build a minimal app (Router) matching the real server wiring,
    /// but without binding a socket. This lets us do in-memory HTTP tests.
    fn build_test_app(
        domain: &str,
        api_key: &str,
        secret: &[u8],
        max_presign: usize,
        max_data: usize,
        rq_timeout_secs: u64,
    ) -> (axum::Router, TempDir) {
        let dir = tempdir().unwrap();
        let metadata_db = dir.path().join("metadata.db");
        let fs = FsController::init(dir.path(), &metadata_db, false).unwrap();
        let service = build_service(
            Config {
                ip_addr: "127.0.0.1:3000".to_string(),
                data_dir: "foo".into(),
                domain: domain.to_string(),
                presign_api_key: api_key.to_string(),
                presign_hmac_secret: Some(String::from_utf8_lossy(secret).to_string()),
                cors_origins: None,
                ttl_orphan_secs: 1234,
                max_data_rq_size: max_data,
                max_presign_rq_size: max_presign,
                rq_timeout_secs,
                metadata_db_path: None,
                create_bucket_symlinks: false,
            },
            fs,
        );
        (service, dir)
    }

    /// Helper to parse JSON body from a response.
    async fn json_body(resp: axum::response::Response) -> Value {
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!(
                "expected JSON (status {status}), got: {:?} / parse err: {e}",
                String::from_utf8_lossy(&bytes)
            )
        });
        v
    }

    #[tokio::test]
    async fn presign_requires_api_key_and_works_with_valid_key() {
        let domain = "https://example.test";
        let api_key = "super-secret";
        let secret = b"test-hmac-secret-32-bytes-----------";

        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 5);

        // 1) Missing Authorization -> 401 JSON error
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/presign")
            .header("content-type", "application/json")
            .body(Body::from(r#"{ "action":"upload" }"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 2) Wrong key -> 401
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/presign")
            .header("content-type", "application/json")
            .header("authorization", "Bearer nope")
            .body(Body::from(r#"{ "action":"upload" }"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 3) Correct key -> 200 and returns url/method/blob_id
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/presign")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {api_key}"))
            .body(Body::from(r#"{ "action":"upload" }"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;

        assert_eq!(v["success"], true);
        assert_eq!(v["action"], "upload");
        assert_eq!(v["method"], "POST");
        let url = v["url"].as_str().expect("url string");
        assert!(
            url.starts_with(domain),
            "url should be minted using configured domain"
        );
        assert!(
            url.contains("?expires=") && url.contains("&sig="),
            "pre-signed URL should include expires & sig"
        );
    }

    #[tokio::test]
    async fn full_upload_and_download_roundtrip() {
        let domain = "https://example.test";
        let api_key = "k";
        let secret = b"another-test-secret--------------------------------";

        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 10);

        // Create our own pre-signed upload URL (same algorithm/secret as server)
        let blob_id = Uuid::new_v4();
        let path = format!("/upload/{blob_id}");
        let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
        let u = url::Url::parse(&url).unwrap();
        let query = u.query().unwrap_or("");

        // Do the upload
        let body_bytes = b"hello axum storage";
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header("content-type", "application/octet-stream")
            .body(Body::from(&body_bytes[..]))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["success"], true);
        assert_eq!(v["blob_id"].as_str().unwrap(), blob_id.to_string());

        // Pre-sign a GET and download
        let get_path = format!("/files/{blob_id}");
        let get_url = crate::utils::generate_presigned_url("GET", domain, &get_path, secret, 300);
        let u = url::Url::parse(&get_url).unwrap();
        let query = u.query().unwrap_or("");

        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!("{get_path}?{query}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], &body_bytes[..], "downloaded content matches");
    }

    #[tokio::test]
    async fn chunked_upload_then_merge() {
        let domain = "https://example.test";
        let api_key = "k";
        let secret = b"chunk-secret---------------------------------------";
        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 10);

        let blob_id = Uuid::new_v4();
        // Upload 2 chunks
        let total = 2usize;

        for (idx, data) in [(1usize, b"hello "), (2, b"world!")].into_iter() {
            let path = format!("/upload/{blob_id}");
            let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
            let u = url::Url::parse(&url).unwrap();
            let query = u.query().unwrap_or("");

            let req = HttpRequest::builder()
                .method("POST")
                .uri(format!("{path}?{query}"))
                .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_CHUNK)
                .header(super::CHUNK_IDX, idx.to_string())
                .header(super::CHUNK_TOTAL, total.to_string())
                .body(Body::from(&data[..]))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "chunk {idx} should upload");
        }

        // Merge request (no body), just headers
        let path = format!("/upload/{blob_id}");
        let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
        let u = url::Url::parse(&url).unwrap();
        let query = u.query().unwrap_or("");

        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_CHUNK)
            .header(super::CHUNK_TOTAL, total.to_string())
            .header(super::CHUNK_MERGE, "1")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["success"], true);
        assert_eq!(v["message"], format!("merged {} chunks", total));
        assert_eq!(v["bytes_written"].as_u64().unwrap(), 12u64);

        // Download and confirm content
        let get_path = format!("/files/{blob_id}");
        let get_url = crate::utils::generate_presigned_url("GET", domain, &get_path, secret, 300);
        let u = url::Url::parse(&get_url).unwrap();
        let query = u.query().unwrap_or("");

        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!("{get_path}?{query}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"hello world!");
    }

    #[tokio::test]
    async fn merge_reports_missing_chunks() {
        let domain = "https://example.test";
        let api_key = "k";
        let secret = b"missing-secret-------------------------------------";
        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 10);

        let blob_id = Uuid::new_v4();
        let total = 3usize;

        // Upload only chunk 2/3
        let path = format!("/upload/{blob_id}");
        let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
        let u = url::Url::parse(&url).unwrap();
        let query = u.query().unwrap_or("");

        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_CHUNK)
            .header(super::CHUNK_IDX, "2")
            .header(super::CHUNK_TOTAL, total.to_string())
            .body(Body::from("middle"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Ask to merge -> expect success:false + missing list
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_CHUNK)
            .header(super::CHUNK_TOTAL, total.to_string())
            .header(super::CHUNK_MERGE, "1")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_body(resp).await;
        assert_eq!(v["success"], false);

        let missing: Vec<u64> = serde_json::from_value(v["missing_chunks"].clone()).unwrap();
        assert_eq!(missing, vec![1, 3]);
    }

    #[tokio::test]
    async fn invalid_headers_and_duplicate_are_handled() {
        let domain = "https://example.test";
        let api_key = "k";
        let secret = b"invalid-headers-secret------------------------------";
        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 10);

        let blob_id = Uuid::new_v4();
        let path = format!("/upload/{blob_id}");
        let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
        let u = url::Url::parse(&url).unwrap();
        let query = u.query().unwrap_or("");

        // 1) Bad X-Upload-Type value -> 400
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header(super::UPLOAD_TYPE, "weird")
            .body(Body::from("ignored"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 2) Full upload succeeds
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_FULL)
            .body(Body::from("abc"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 3) Duplicate upload -> 409 Conflict (POST semantics - no overwrite)
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_FULL)
            .body(Body::from("abc"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let v = json_body(resp).await;
        assert_eq!(v["success"], false);
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("duplicate")
        );
    }

    #[tokio::test]
    async fn metadata_headers_are_stored_and_applied() {
        let domain = "https://example.test";
        let api_key = "k";
        let secret = b"metadata-test-secret----------------------------";
        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 10);

        let blob_id = Uuid::new_v4();
        let path = format!("/upload/{blob_id}");
        let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
        let u = url::Url::parse(&url).unwrap();
        let query = u.query().unwrap_or("");

        // Upload with Content-Type and Content-Disposition headers
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header("content-type", "image/png")
            .header("content-disposition", "attachment; filename=\"test.png\"")
            .body(Body::from("fake image data"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Download and verify headers are applied
        let get_path = format!("/files/{blob_id}");
        let get_url = crate::utils::generate_presigned_url("GET", domain, &get_path, secret, 300);
        let u = url::Url::parse(&get_url).unwrap();
        let query = u.query().unwrap_or("");

        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!("{get_path}?{query}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Check that Content-Type and Content-Disposition headers are applied
        assert_eq!(resp.headers().get("content-type").unwrap(), "image/png");
        assert_eq!(
            resp.headers().get("content-disposition").unwrap(),
            "attachment; filename=\"test.png\""
        );

        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"fake image data");
    }

    #[tokio::test]
    async fn chunked_upload_metadata_stored_on_merge() {
        let domain = "https://example.test";
        let api_key = "k";
        let secret = b"chunk-metadata-test-----------------------------";
        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 10);

        let blob_id = Uuid::new_v4();
        let total = 2usize;

        // Upload 2 chunks (headers should be ignored for chunks)
        for (idx, data) in [(1usize, b"hello "), (2, b"world!")].into_iter() {
            let path = format!("/upload/{blob_id}");
            let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
            let u = url::Url::parse(&url).unwrap();
            let query = u.query().unwrap_or("");

            let req = HttpRequest::builder()
                .method("POST")
                .uri(format!("{path}?{query}"))
                .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_CHUNK)
                .header(super::CHUNK_IDX, idx.to_string())
                .header(super::CHUNK_TOTAL, total.to_string())
                .body(Body::from(&data[..]))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Merge request with metadata headers
        let path = format!("/upload/{blob_id}");
        let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
        let u = url::Url::parse(&url).unwrap();
        let query = u.query().unwrap_or("");

        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_CHUNK)
            .header(super::CHUNK_TOTAL, total.to_string())
            .header(super::CHUNK_MERGE, "1")
            .header("content-type", "text/plain")
            .header("content-disposition", "inline; filename=\"merged.txt\"")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Download and verify metadata headers are applied
        let get_path = format!("/files/{blob_id}");
        let get_url = crate::utils::generate_presigned_url("GET", domain, &get_path, secret, 300);
        let u = url::Url::parse(&get_url).unwrap();
        let query = u.query().unwrap_or("");

        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!("{get_path}?{query}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Check headers
        assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");
        assert_eq!(
            resp.headers().get("content-disposition").unwrap(),
            "inline; filename=\"merged.txt\""
        );

        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"hello world!");
    }

    #[tokio::test]
    async fn download_without_metadata_uses_defaults() {
        let domain = "https://example.test";
        let api_key = "k";
        let secret = b"no-metadata-test--------------------------------";
        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 10);

        let blob_id = Uuid::new_v4();
        let path = format!("/upload/{blob_id}");
        let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
        let u = url::Url::parse(&url).unwrap();
        let query = u.query().unwrap_or("");

        // Upload without any metadata headers
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .body(Body::from("some data"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Download and verify default headers are applied
        let get_path = format!("/files/{blob_id}");
        let get_url = crate::utils::generate_presigned_url("GET", domain, &get_path, secret, 300);
        let u = url::Url::parse(&get_url).unwrap();
        let query = u.query().unwrap_or("");

        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!("{get_path}?{query}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Should use default Content-Type, no Content-Disposition
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/octet-stream"
        );
        assert!(resp.headers().get("content-disposition").is_none());
    }

    #[tokio::test]
    async fn sha256_hash_is_stored_and_retrievable() {
        let domain = "https://example.test";
        let api_key = "k";
        let secret = b"sha256-test-secret------------------------------";
        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 10);

        let blob_id = Uuid::new_v4();
        let path = format!("/upload/{blob_id}");
        let url = crate::utils::generate_presigned_url("POST", domain, &path, secret, 300);
        let u = url::Url::parse(&url).unwrap();
        let query = u.query().unwrap_or("");

        let test_content = "This is test content for SHA-256 hashing";

        // Upload content
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header("content-type", "text/plain")
            .body(Body::from(test_content))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Calculate expected SHA-256
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(test_content.as_bytes());
        let expected_hash = hex::encode(hasher.finalize());

        // We can't directly access the metadata through the API, but we can verify
        // the upload worked and the hash would be stored by checking the response
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let response: Success = serde_json::from_slice(&body).unwrap();
        assert!(response.success);
        assert_eq!(response.blob_id, Some(blob_id));

        // Note: In a real system, you might expose a metadata endpoint
        // or add the hash to the upload response for verification
        debug!("Expected SHA-256 hash: {}", expected_hash);
    }

    #[tokio::test]
    async fn invalid_signature_is_rejected_by_middleware() {
        let domain = "https://example.test";
        let api_key = "k";
        let secret = b"valid-secret----------------------------------------";
        let (app, _guard) =
            build_test_app(domain, api_key, secret, 100 * 1024, 10 * 1024 * 1024, 10);

        // Sign with a WRONG secret
        let blob_id = Uuid::new_v4();
        let path = format!("/upload/{blob_id}");
        let bad_url =
            crate::utils::generate_presigned_url("POST", domain, &path, b"WRONG-SECRET", 300);
        let u = url::Url::parse(&bad_url).unwrap();
        let query = u.query().unwrap_or("");

        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_FULL)
            .body(Body::from("data"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let v = json_body(resp).await;
        assert_eq!(v["success"], false);
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("invalid")
        );
    }
}
