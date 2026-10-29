use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::net::SocketAddr;

use crate::auth::{
    hash_password, token_from_cookie_header, verify_password, AuthUser, SESSION_COOKIE,
};
use crate::error::AppError;
use crate::models::{
    ChangePasswordRequest, LoginRequest, RegisterRequest, UpdateMeRequest, User, UserOption,
};
use crate::web::state::SharedState;

/// Build the session cookie set on successful login (password or passkey)
/// and registration.
pub(super) fn session_cookie(token: &str, max_age: i64, secure: bool) -> String {
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
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
    // Spend the source budget before the hash: the hash is what the
    // budget exists for, and a taken name runs it all the same (F1).
    state.register_take(&addr.ip().to_string())?;

    let display_name = req
        .display_name
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| req.username.trim().to_string());

    let hash = hash_password(&req.password)?;
    let user = state.db.create_user(username, hash, display_name).await?;

    if !user.is_active {
        // No cookie: an inactive account cannot be used yet.
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({ "user": user, "pending_activation": true })),
        )
            .into_response());
    }

    let token = state
        .db
        .create_session(user.id, state.config.session_ttl)
        .await?;
    let body = Json(json!({ "user": user }));
    Ok((
        [(
            header::SET_COOKIE,
            session_cookie(&token, state.config.session_ttl, state.config.secure_cookie),
        )],
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Result<Response, AppError> {
    let username = req.username.trim().to_lowercase();
    let source = addr.ip().to_string();
    // Account backoff and the source's failed-attempt budget answer
    // before any work: a locked name never reaches the database or Argon2,
    // so waiting out a window also costs the server nothing (F1).
    state.login_gate(&username, &source)?;

    let Some(found) = state.db.find_user_by_username(username.clone()).await? else {
        state.login_failed(&username, &source);
        return Err(AppError::Unauthorized);
    };

    if !verify_password(&req.password, &found.password_hash) {
        state.login_failed(&username, &source);
        return Err(AppError::Unauthorized);
    }
    // The password was correct: the holder just proved they are the
    // holder, so the wrong ones before them are forgiven (F1).
    state.login_succeeded(&username);

    if !found.user.is_active {
        return Err(AppError::InactiveAccount);
    }

    let token = state
        .db
        .create_session(found.user.id, state.config.session_ttl)
        .await?;
    let body = Json(json!({ "user": found.user }));
    Ok((
        [(
            header::SET_COOKIE,
            session_cookie(&token, state.config.session_ttl, state.config.secure_cookie),
        )],
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
    Ok((
        [(header::SET_COOKIE, clear_cookie())],
        Json(json!({ "ok": true })),
    )
        .into_response())
}

/// GET /api/me – return the currently logged-in user, plus how many bytes of
/// the storage quota are used (the topbar shows `used_bytes of quota_bytes`).
pub async fn me(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let used_bytes = state.db.owner_usage(user.id()).await?;
    let mut me = serde_json::to_value(&user.0)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serializing user: {e}")))?;
    me["used_bytes"] = json!(used_bytes);
    Ok(Json(me))
}

/// PUT /api/me – save the settings from the user menu (display name, theme).
///
/// Only the fields present in the body are written, so the two halves of the
/// menu save independently. The theme value is validated server-side against
/// the two known themes; the display name is trimmed and cannot be empty -
/// an empty label would leave the topbar saying nothing at all.
pub async fn update_me(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<UpdateMeRequest>,
) -> Result<Json<User>, AppError> {
    let no_fields = req.display_name.is_none() && req.theme.is_none();
    let display_name = req.display_name.map(|d| d.trim().to_string());
    if let Some(name) = &display_name {
        if name.is_empty() {
            return Err(AppError::BadRequest("display name cannot be empty".into()));
        }
        if name.chars().count() > 100 {
            return Err(AppError::BadRequest(
                "display name too long (max 100 characters)".into(),
            ));
        }
    }
    if no_fields {
        return Err(AppError::BadRequest("nothing to update".into()));
    }
    let updated = state
        .db
        .update_settings(user.id(), display_name, req.theme)
        .await?;
    Ok(Json(updated))
}

/// PUT /api/me/password – change the signed-in user's password.
///
/// The current password is verified first (401 when it does not match) and
/// the new one gets the same length floor as registration. Every *other*
/// session of the account is dropped with the change (F3): a password
/// change is the incident response for a stolen credential, so the
/// sessions the old password minted cannot outlive it. The caller's own
/// session stays open - it authenticated this very request - so the menu
/// keeps being usable afterwards.
pub async fn change_password(
    State(state): State<SharedState>,
    user: AuthUser,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let found = state
        .db
        .find_user_by_username(user.0.username.clone())
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !verify_password(&req.current_password, &found.password_hash) {
        return Err(AppError::Unauthorized);
    }
    if req.new_password.len() < 8 {
        return Err(AppError::BadRequest(
            "new password must be at least 8 characters".into(),
        ));
    }
    let hash = hash_password(&req.new_password)?;
    // The session that made the change is kept alive by naming it; every
    // other session of this account goes with the old hash. The token is
    // read straight from the request's cookie header - `AuthUser` resolved
    // it already, but carries only the user, not the string it came from.
    let keep = token_from_cookie_header(
        headers.get(header::COOKIE).and_then(|v| v.to_str().ok()),
    );
    state.db.set_password(user.id(), hash, keep).await?;
    Ok(Json(json!({ "ok": true })))
}

/// GET /api/users – every account but the caller's own, so the share dialog
/// can offer the possible grantees as a dropdown instead of requiring the
/// username to be typed from memory.
///
/// Returns only what a grantee picker needs: `username`, `display_name` and
/// `is_active` (inactive accounts are still shareable — the share simply
/// becomes visible once the account is activated, see README).
pub async fn list_users(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<Vec<UserOption>>, AppError> {
    Ok(Json(state.db.list_share_targets(user.id()).await?))
}

/// Helper so handlers can return `204` with no body where needed.
#[allow(dead_code)]
pub fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}
