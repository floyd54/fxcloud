use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Unified application error.
///
/// Every fallible operation returns `Result<_, AppError>`, and because it
/// implements [`IntoResponse`] it can be returned straight from an axum handler.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: missing permission")]
    Forbidden,

    /// A permission check passed in a *specific* reason the caller can act
    /// on (e.g. "only the row's owner may change its key record"). Same
    /// status as `Forbidden`; the difference is that a user can tell which
    /// rule stopped them.
    #[error("forbidden: {0}")]
    ForbiddenDetail(String),

    #[error("account is not activated yet – ask an administrator to activate it")]
    InactiveAccount,

    /// An authentication endpoint is refusing attempts for now (F1): the
    /// account is in failed-attempt backoff, a per-source budget is spent,
    /// or too many WebAuthn challenges are in flight.
    ///
    /// 429 carries `Retry-After` in whole seconds; the same number rides in
    /// the body as `retry_after`, the way quota numbers do, so the UI can
    /// count along in the user's language instead of parsing the header.
    #[error("{reason}")]
    RateLimited {
        retry_after_secs: u64,
        reason: String,
    },

    /// The account's storage quota would be exceeded by `additional` bytes.
    ///
    /// 507 is the WebDAV status for "insufficient storage", so sync clients
    /// such as rclone and Cyberduck report it as a full quota rather than a
    /// generic failure.
    #[error("storage quota exceeded: {} of {} used", fmt_bytes(*used), fmt_bytes(*quota))]
    QuotaExceeded { used: i64, quota: i64 },

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("already exists: {0}")]
    Conflict(String),

    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("background task join error")]
    Join,
}

impl AppError {
    /// Stable machine-readable code for this error.
    ///
    /// It rides in the JSON response (`{"error": ..., "code": ...}`) so the
    /// UI can translate the failure (i18n.js `err.*`) instead of echoing the
    /// English text. Codes are API: renaming one breaks translation keys.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::Pool(_) | AppError::Db(_) | AppError::Internal(_) | AppError::Join => {
                "internal"
            }
            AppError::NotFound => "not_found",
            AppError::Unauthorized => "unauthorized",
            AppError::Forbidden | AppError::ForbiddenDetail(_) => "forbidden",
            AppError::InactiveAccount => "inactive_account",
            AppError::RateLimited { .. } => "rate_limited",
            AppError::BadRequest(_) => "bad_request",
            AppError::Conflict(_) => "conflict",
            AppError::QuotaExceeded { .. } => "quota_exceeded",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            AppError::Pool(_) | AppError::Db(_) | AppError::Internal(_) | AppError::Join => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden | AppError::ForbiddenDetail(_) | AppError::InactiveAccount => {
                StatusCode::FORBIDDEN
            }
            AppError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::QuotaExceeded { .. } => StatusCode::INSUFFICIENT_STORAGE,
        }
    }

    /// Message that may be shown to the client.
    ///
    /// 5xx details stay internal — same rule as the JSON body of a plain error
    /// response — which matters for batch operations that report one message
    /// per failed item.
    pub fn user_message(&self) -> String {
        match self.status() {
            StatusCode::INTERNAL_SERVER_ERROR => "internal error".to_string(),
            _ => self.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Never leak internal details for 5xx errors.
        let status = self.status();
        let code = self.code();
        // Quota numbers ride along raw so a UI can format them in its own
        // units and locale instead of parsing the English message.
        let quota_numbers = match &self {
            AppError::QuotaExceeded { used, quota } => Some((*used, *quota)),
            _ => None,
        };
        let message = match status {
            StatusCode::INTERNAL_SERVER_ERROR => {
                tracing::error!(error = %self, "internal server error");
                "internal server error".to_string()
            }
            _ => self.to_string(),
        };
        // The backoff window rides along too (F1): the `Retry-After`
        // header is the protocol's, the body field is the UI's, both in
        // whole seconds so the two can never disagree.
        let retry_after = match &self {
            AppError::RateLimited {
                retry_after_secs, ..
            } => Some(*retry_after_secs),
            _ => None,
        };
        // `code` is stable API - the frontend translates it via err.<code>.
        let mut body = json!({ "error": message, "code": code });
        if let Some((used, quota)) = quota_numbers {
            body["used"] = json!(used);
            body["quota"] = json!(quota);
        }
        if let Some(secs) = retry_after {
            body["retry_after"] = json!(secs);
        }
        let mut response = (status, Json(body)).into_response();
        if let Some(secs) = retry_after {
            let value = HeaderValue::from_str(&secs.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("1"));
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

/// Human-readable byte count for user-facing messages.
///
/// Binary units (1024-based), matching how the default quota of 1 GiB is
/// expressed — so "1.0 GB" always means exactly the quota a fresh account gets.
fn fmt_bytes(n: i64) -> String {
    const UNIT: f64 = 1024.0;
    let n = n.max(0) as f64;
    if n >= UNIT.powi(3) {
        format!("{:.1} GB", n / UNIT.powi(3))
    } else if n >= UNIT.powi(2) {
        format!("{:.1} MB", n / UNIT.powi(2))
    } else if n >= UNIT {
        format!("{:.0} KB", n / UNIT)
    } else {
        format!("{n:.0} B")
    }
}
