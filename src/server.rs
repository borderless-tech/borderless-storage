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
    extract::{Path, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
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
    storage::FsController,
    utils::{
        byte_size_str, extract_sig_from_query, generate_presigned_url, verify_presigned_signature,
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
            tracing::info_span!("request",
                       request_id = %rid,
                       method = %req.method(),
                       uri = %req.uri()
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
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
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
    });

    let api_key_protected = Router::new()
        .route("/presign", post(presign_url))
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            require_api_key_auth,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_presign_rq_size))
        .layer(no_store.clone()) // Never cache presign responses
        .with_state(auth.clone());

    let pre_sign_upload = Router::new()
        .route("/upload/{blob_id}", post(upload_data))
        .layer(middleware::from_fn_with_state(
            auth.clone(),
            require_presign_auth,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_data_rq_size))
        .layer(no_store.clone()) // Never cache responses with presigned-urls
        .with_state(fs_controller.clone());

    // NOTE: The download route sets the cache header directly in the response
    let pre_sign_download = Router::new()
        .route("/files/{blob_id}", get(read_blob))
        .layer(middleware::from_fn_with_state(auth, require_presign_auth))
        .layer(RequestBodyLimitLayer::new(config.max_data_rq_size))
        .with_state(fs_controller);

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
        .merge(api_key_protected)
        .merge(pre_sign_upload)
        .merge(pre_sign_download)
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
    Extension(PresignTtl(rem_ttl)): Extension<PresignTtl>,
    Path(blob_id): Path<Uuid>,
) -> Result<Response> {
    let (blob_path, _) = storage.blob_path(&blob_id);

    let f = tokio::fs::File::open(blob_path)
        .await
        .map_err(|_| Error::NotFound)?;

    // Stream file content into a response
    let stream = ReaderStream::new(f);
    let body = Body::from_stream(stream);

    // Set cache-control header to remainaing ttl (and clamp at MAX_)
    let max_age = rem_ttl.min(MAX_EXPIRY_SECS);
    let cache_hdr = if max_age > 0 {
        format!("private, max-age={max_age}, immutable")
    } else {
        "no-store".to_string()
    };

    let response = Response::builder()
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CACHE_CONTROL, cache_hdr)
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
    // Use max as default and clamp to maximum
    let expires_in = presign
        .expires_in
        .unwrap_or(MAX_EXPIRY_SECS)
        .min(MAX_EXPIRY_SECS);

    // Check upload action
    let (method, path, blob_id) = match presign.action {
        PresignAction::Upload => {
            let blob_id = presign.blob_id.unwrap_or_else(Uuid::now_v7);
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
    debug!(%expires_in, %method, %path, %blob_id, "presigning url");

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
        let fs = FsController::init(dir.path()).unwrap();
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

        // 3) Duplicate upload -> 400 Duplicate
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("{path}?{query}"))
            .header(super::UPLOAD_TYPE, super::UPLOAD_TYPE_FULL)
            .body(Body::from("abc"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
