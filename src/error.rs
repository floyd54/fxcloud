use axum::http::StatusCode;
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

    #[error("account is not activated yet – ask an administrator to activate it")]
    InactiveAccount,

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
    fn status(&self) -> StatusCode {
        match self {
            AppError::Pool(_) | AppError::Db(_) | AppError::Internal(_) | AppError::Join => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden | AppError::InactiveAccount => StatusCode::FORBIDDEN,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
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
        let message = match status {
            StatusCode::INTERNAL_SERVER_ERROR => {
                tracing::error!(error = %self, "internal server error");
                "internal server error".to_string()
            }
            _ => self.to_string(),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
