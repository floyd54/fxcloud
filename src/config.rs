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
    /// Office integration (concepts/office.md): the engine's base URL as the
    /// *browser* sees it, `http(s)://host[:port][/prefix]`. Unset (the
    /// default) means the feature is off - no office routes, no CSP change,
    /// no UI (decision 3).
    pub office_url: Option<String>,
    /// `scheme://host[:port]` of `office_url`: the only part that may go
    /// into the CSP (`frame-src`, `form-action`); a path is never a CSP
    /// source.
    pub office_origin: Option<String>,
    /// HMAC key for the WOPI access tokens `/api/office/start` mints.
    /// Required together with `office_url`; it never leaves the process -
    /// the browser only ever sees single tokens.
    pub office_secret: Option<String>,
    /// URL the *engine container* uses to reach fxcloud (the WOPISrc base):
    /// `FXCLOUD_OFFICE_WOPI_BASE`, else `FXCLOUD_ORIGIN`, else the origin
    /// derived from the start request (concepts/office.md section 8 - the
    /// WOPI leg deliberately bypasses the reverse proxy).
    pub office_wopi_base: Option<String>,
    /// How the browser opens the editor: a form POST (the official WOPI
    /// host page - the OnlyOffice/Euro-Office flow) or a plain iframe GET
    /// (Collabora's flow). `FXCLOUD_OFFICE_EMBED`, default `form`.
    pub office_embed: OfficeEmbed,
}

/// The two embed flows of the office editor (concepts/office.md section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OfficeEmbed {
    /// `<form method="post">` with `access_token`/`access_token_ttl` into
    /// an iframe, target URL `.../hosting/wopi/<kind>/edit?wopisrc=...`.
    #[default]
    Form,
    /// Plain iframe `src` with the token in the query string,
    /// `.../cool.html?WOPISrc=...&access_token=...`.
    Iframe,
}

/// Split an office base URL into `(origin, base)`: the origin is what the
/// CSP may list (`scheme://host[:port]`), the base is what engine URLs are
/// appended to (it may carry a path prefix, e.g. Collabora's
/// `browser/<build>` segment). No query, fragment, userinfo or whitespace;
/// a trailing slash is dropped so callers can join with `/`.
fn office_base_parts(raw: &str) -> anyhow::Result<(String, String)> {
    let trimmed = raw.trim();
    let no_slash = trimmed.trim_end_matches('/');
    let (scheme, rest) = if let Some(rest) = no_slash.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = no_slash.strip_prefix("http://") {
        ("http", rest)
    } else {
        anyhow::bail!("missing http(s):// scheme");
    };
    if rest.is_empty() {
        anyhow::bail!("missing host");
    }
    if rest.contains('?')
        || rest.contains('#')
        || rest.contains('@')
        || rest.contains(char::is_whitespace)
    {
        anyhow::bail!("no query, fragment, userinfo or whitespace allowed");
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty()
        || !authority
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        anyhow::bail!("host must be a plain name, address and optional port");
    }
    Ok((
        format!("{scheme}://{authority}"),
        format!("{scheme}://{authority}{path}"),
    ))
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

        // Office integration (concepts/office.md): the knobs belong together -
        // a stray secret or base without FXCLOUD_OFFICE_URL is a config
        // mistake, and it fails loudly instead of silently staying off.
        let office_url = std::env::var("FXCLOUD_OFFICE_URL")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        for stray in [
            "FXCLOUD_OFFICE_SECRET",
            "FXCLOUD_OFFICE_WOPI_BASE",
            "FXCLOUD_OFFICE_EMBED",
        ] {
            if office_url.is_none()
                && std::env::var(stray)
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false)
            {
                anyhow::bail!(
                    "{stray} is set but FXCLOUD_OFFICE_URL is not - office editing stays off \
                     unless the engine's URL is configured"
                );
            }
        }
        let office_embed = match std::env::var("FXCLOUD_OFFICE_EMBED") {
            Err(_) => OfficeEmbed::Form,
            Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
                "" | "form" => OfficeEmbed::Form,
                "iframe" => OfficeEmbed::Iframe,
                other => anyhow::bail!(
                    "FXCLOUD_OFFICE_EMBED must be \"form\" or \"iframe\", got {other:?}"
                ),
            },
        };
        let (office_origin, office_url, office_secret, office_wopi_base) = match office_url {
            Some(raw) => {
                let (origin, base) = office_base_parts(&raw)
                    .context("FXCLOUD_OFFICE_URL must look like http(s)://host[:port][/prefix]")?;
                let secret = std::env::var("FXCLOUD_OFFICE_SECRET")
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .with_context(|| {
                        "FXCLOUD_OFFICE_SECRET is required with FXCLOUD_OFFICE_URL - \
                         generate one with: openssl rand -hex 32"
                    })?;
                let wopi_base = std::env::var("FXCLOUD_OFFICE_WOPI_BASE")
                    .ok()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .map(|raw| {
                        office_base_parts(&raw).map(|(_, base)| base).with_context(|| {
                            "FXCLOUD_OFFICE_WOPI_BASE must look like http(s)://host[:port][/path]"
                        })
                    })
                    .transpose()?;
                (Some(origin), Some(base), Some(secret), wopi_base)
            }
            None => (None, None, None, None),
        };

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
            office_url,
            office_origin,
            office_secret,
            office_wopi_base,
            office_embed,
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
