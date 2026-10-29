use std::path::PathBuf;

use anyhow::Context;

/// Runtime configuration for the fxcloud server.
///
/// All values can be overridden via environment variables so a single binary
/// can be pointed at different data locations without recompiling.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind the HTTP server to, e.g. `127.0.0.1` or `0.0.0.0`.
    pub bind: String,
    /// TCP port to listen on.
    pub port: u16,
    /// Directory where the database and file blobs are stored.
    pub data_dir: PathBuf,
    /// Lifetime of a login session in seconds (default: 7 days; slides
    /// while the session is in use).
    pub session_ttl: i64,
    /// Set the `Secure` attribute on session cookies. Enable this when serving
    /// over HTTPS (e.g. behind a TLS-terminating reverse proxy).
    pub secure_cookie: bool,
    /// Maximum request-body size for uploads, in bytes (multipart upload).
    /// Must exceed the largest single file; the multipart envelope adds a little
    /// overhead on top of the file itself.
    pub max_upload_bytes: usize,
    /// Days a trashed entry is kept before the background purge removes it
    /// together with its blob content (default: 30).
    pub trash_days: i64,
    /// Interval of the trash purge sweep in seconds (default: hourly). Kept
    /// configurable so tests can age entries out without waiting.
    pub trash_sweep_secs: u64,
    /// Public origin of this instance for WebAuthn (passkeys), e.g.
    /// `https://cloud.example.com`.
    ///
    /// WebAuthn binds credentials to an exact origin and to the origin's
    /// host without port (the rpId), so behind a reverse proxy that
    /// rewrites `Host` this is the one place to say what browsers actually
    /// see. Unset (the default), both are derived per request from
    /// `X-Forwarded-Proto` / `FXCLOUD_SECURE_COOKIE` and `Host`.
    pub webauthn_origin: Option<String>,
}

impl Config {
    /// Load configuration from the environment, falling back to sensible defaults.
    pub fn from_env() -> anyhow::Result<Self> {
        let bind = std::env::var("FXCLOUD_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = std::env::var("FXCLOUD_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);
        let data_dir = std::env::var("FXCLOUD_DATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        // Seven days, sliding: `sliding_renewal` moves the window
        // forward while a session is in use, and the settings page lists
        // and ends the others (Audit.md F4). The old default was 30
        // days, which kept a leaked cookie alive for weeks.
        let session_ttl = std::env::var("FXCLOUD_SESSION_TTL")
            .ok()
            .and_then(|t| t.parse().ok())
            .unwrap_or(60 * 60 * 24 * 7);
        let secure_cookie = std::env::var("FXCLOUD_SECURE_COOKIE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        let max_upload_mb: u64 = std::env::var("FXCLOUD_MAX_UPLOAD_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);
        let max_upload_bytes = (max_upload_mb.saturating_mul(1024 * 1024)) as usize;
        let trash_days = std::env::var("FXCLOUD_TRASH_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let trash_sweep_secs = std::env::var("FXCLOUD_TRASH_SWEEP_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);
        let webauthn_origin = std::env::var("FXCLOUD_ORIGIN")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let cfg = Self {
            bind,
            port,
            data_dir,
            session_ttl,
            secure_cookie,
            max_upload_bytes,
            trash_days,
            trash_sweep_secs,
            webauthn_origin,
        };
        cfg.ensure_dirs().context("creating data directories")?;
        Ok(cfg)
    }

    /// Absolute path to the SQLite database file.
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("fxcloud.db")
    }

    /// Directory holding file content blobs (laid out as
    /// `<owner>/<year>/<h1>/<h2>/<file-id>`, see the `files` module).
    pub fn blob_dir(&self) -> PathBuf {
        self.data_dir.join("blobs")
    }

    fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(self.blob_dir())?;
        Ok(())
    }
}
