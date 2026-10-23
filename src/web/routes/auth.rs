use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::auth::{hash_password, verify_password, AuthUser, SESSION_COOKIE};
use crate::error::AppError;
use crate::models::{LoginRequest, RegisterRequest, User};
use crate::web::state::SharedState;

/// Build the session cookie set on successful login/registration.
fn session_cookie(token: &str, max_age: i64, secure: bool) -> String {
    // HttpOnly + SameSite=Lax gives solid CSRF basics; `Secure` is appended when
    // serving over HTTPS (enabled via FXCLOUD_SECURE_COOKIE).
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}{secure_attr}"
    )
}

/// Build the cookie that clears the session on logout.
fn clear_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

/// POST /api/register – create a new user.
///
/// The account is created **inactive** (the very first one on a fresh instance
/// excepted) and gets no session: it must be activated in the database first,
/// which is reported back with `pending_activation`. Only an already-usable
/// account signs in directly.
pub async fn register(
    State(state): State<SharedState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Response, AppError> {
    let username = req.username.trim().to_lowercase();
    if username.is_empty() || username.len() < 3 {
        return Err(AppError::BadRequest(
            "username must be at least 3 characters".into(),
        ));
    }
    if req.password.len() < 8 {
        return Err(AppError::BadRequest(
            "password must be at least 8 characters".into(),
        ));
    }

    let display_name = req
        .display_name
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| req.username.trim().to_string());

    let hash = hash_password(&req.password)?;
    let user = state
        .db
        .create_user(username, hash, display_name)
        .await?;

    if !user.is_active {
        // No cookie: an inactive account cannot be used yet.
        return Ok(
            (StatusCode::ACCEPTED, Json(json!({ "user": user, "pending_activation": true })))
                .into_response(),
        );
    }

    let token = state.db.create_session(user.id, state.config.session_ttl).await?;
    let body = Json(json!({ "user": user }));
    Ok((
        [(header::SET_COOKIE, session_cookie(&token, state.config.session_ttl, state.config.secure_cookie))],
        body,
    )
        .into_response())
}

/// POST /api/login – verify credentials and open a session.
///
/// Correct credentials on a deactivated account are rejected with
/// [`AppError::InactiveAccount`] (403) instead of a generic 401, so the user
/// learns that the account is merely waiting to be activated.
pub async fn login(
    State(state): State<SharedState>,
    Json(req): Json<LoginRequest>,
) -> Result<Response, AppError> {
    let username = req.username.trim().to_lowercase();
    let found = state
        .db
        .find_user_by_username(username)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !verify_password(&req.password, &found.password_hash) {
        return Err(AppError::Unauthorized);
    }

    if !found.user.is_active {
        return Err(AppError::InactiveAccount);
    }

    let token = state
        .db
        .create_session(found.user.id, state.config.session_ttl)
        .await?;
    let body = Json(json!({ "user": found.user }));
    Ok((
        [(header::SET_COOKIE, session_cookie(&token, state.config.session_ttl, state.config.secure_cookie))],
        body,
    )
        .into_response())
}

/// POST /api/logout – invalidate the current session.
pub async fn logout(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Some(token) = crate::auth::token_from_cookie_header(
        headers.get(header::COOKIE).and_then(|v| v.to_str().ok()),
    ) {
        state.db.delete_session(token).await?;
    }
    Ok(([(header::SET_COOKIE, clear_cookie())], Json(json!({ "ok": true }))).into_response())
}

/// GET /api/me – return the currently logged-in user.
pub async fn me(user: AuthUser) -> Json<User> {
    Json(user.0)
}

/// Helper so handlers can return `204` with no body where needed.
#[allow(dead_code)]
pub fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}
