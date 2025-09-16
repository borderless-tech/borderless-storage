use std::{net::SocketAddr, time::Instant};

use anyhow::Result;
use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use tokio::net::TcpListener;
use tracing::info;

/// Entrypoint to start the webserver
///
/// This function basically never returns - it only does in case of an error.
pub async fn start(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;

    let service = Router::new()
        .layer(middleware::from_fn(auth_middleware_dummy))
        .layer(middleware::from_fn(metrics));

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
