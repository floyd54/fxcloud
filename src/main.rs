mod auth;
mod config;
mod db;
mod error;
mod files;
mod models;
mod sharing;
mod web;
mod webauthn;
mod webdav;

use std::sync::Arc;

use anyhow::Context;

use crate::config::Config;
use crate::db::Db;
use crate::web::state::AppState;

/// Text of `fxcloud --help`: the flags plus the environment knobs, kept in
/// step with `Config::from_env` and the README's configuration table.
const HELP: &str = "\
fxcloud - a personal cloud in a single binary

usage: fxcloud [--version] [--help]

Without arguments fxcloud starts the HTTP server. Configuration comes from
environment variables:

  FXCLOUD_BIND             listen address (default 127.0.0.1)
  FXCLOUD_PORT             listen port (default 8080)
  FXCLOUD_DATA             data directory (default ./data)
  FXCLOUD_SESSION_TTL      session lifetime in seconds (default 2592000)
  FXCLOUD_SECURE_COOKIE    set Secure on cookies: 1/true/yes/on (behind HTTPS)
  FXCLOUD_MAX_UPLOAD_MB    max upload size in MiB (default 1024)
  FXCLOUD_TRASH_DAYS       days a trashed entry is kept (default 30)
  FXCLOUD_TRASH_SWEEP_SECS trash purge sweep interval in seconds (default 3600)
  FXCLOUD_ORIGIN           public origin for passkeys (e.g. https://cloud.example.com)
  RUST_LOG                 log filter (default fxcloud=info)
";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `--version` and `--help` answer before anything starts, so installers
    // can verify a fresh download without opening a port or the database.
    match std::env::args().nth(1).as_deref() {
        Some("--version") | Some("-V") => {
            println!("fxcloud v{}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--help") | Some("-h") => {
            print!("{HELP}");
            return Ok(());
        }
        Some(arg) => {
            eprintln!("fxcloud: unknown argument {arg:?} (try --help)");
            std::process::exit(2);
        }
        None => {}
    }

    // Structured logging to stdout.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fxcloud=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env().context("loading configuration")?;
    tracing::info!(?config, "starting fxcloud");

    // Passkeys bind to an exact origin: say up front which one this
    // deployment serves under, so a reverse-proxy surprise is one journal
    // read away instead of a mystery "Invalid request" in the browser.
    match &config.webauthn_origin {
        Some(origin) => tracing::info!(%origin, "passkey origin taken from FXCLOUD_ORIGIN"),
        None => tracing::info!(
            secure_cookie = config.secure_cookie,
            "passkey origin derived from the Host header - set FXCLOUD_ORIGIN when a \
             reverse proxy rewrites it"
        ),
    }

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
    // Move blobs from the legacy flat layout into <owner>/<year>/<h1>/<h2>.
    state.files.migrate_flat_blobs().await;

    // Trash purge: hard-delete trashed entries older than the retention
    // window - once at startup, then on the sweep interval.
    {
        let state = state.clone();
        let days = config.trash_days;
        let secs = config.trash_sweep_secs.max(1);
        tokio::spawn(async move {
            let mut first = true;
            loop {
                if !first {
                    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
                }
                first = false;
                match state.db.purge_expired_trash(days).await {
                    Ok(blobs) => state.files.delete_blobs(&blobs).await,
                    Err(e) => tracing::warn!(error = %e, "trash purge failed"),
                }
            }
        });
    }
    let app = web::build_router(state);

    let addr = format!("{}:{}", config.bind, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding to {addr}"))?;
    tracing::info!("listening on http://{addr}");

    axum::serve(listener, app).await.context("server error")?;
    Ok(())
}
