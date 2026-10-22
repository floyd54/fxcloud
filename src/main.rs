mod auth;
mod config;
mod db;
mod error;
mod files;
mod models;
mod sharing;
mod web;
mod webdav;

use std::sync::Arc;

use anyhow::Context;

use crate::config::Config;
use crate::db::Db;
use crate::web::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Structured logging to stdout.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fxcloud=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env().context("loading configuration")?;
    tracing::info!(?config, "starting fxcloud");

    let db = Db::open(&config.db_path()).context("opening database")?;
    tracing::info!(path = %config.db_path().display(), "database ready");

    // Periodically drop expired sessions in the background.
    {
        let db = db.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                ticker.tick().await;
                if let Err(e) = db.purge_expired_sessions().await {
                    tracing::warn!(error = %e, "session purge failed");
                }
            }
        });
    }

    let state = Arc::new(AppState::new(db, config.clone()));
    let app = web::build_router(state);

    let addr = format!("{}:{}", config.bind, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding to {addr}"))?;
    tracing::info!("listening on http://{addr}");

    axum::serve(listener, app).await.context("server error")?;
    Ok(())
}
