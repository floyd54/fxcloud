use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::auth::{
    hash_passphrase, hash_password, verify_passphrase, verify_password, AuthUser, SESSION_COOKIE,
};
use crate::error::AppError;
use crate::models::{
    ChangePasswordRequest, LoginRequest, RegisterRequest, RemovePassphraseRequest,
    SetPassphraseRequest, UpdateMeRequest, User, UserOption,
};
use crate::web::state::SharedState;

/// Floor for the optional sign-in passphrase.
///
/// Deliberately higher than the password's 8: this credential doubles as the
/// secret the account's key row is wrapped under (`kdf_params.secret =
/// "separate"`), so the server-side Argon2id hash of it is an offline
/// shortcut to the key material and its strength is what carries file
/// confidentiality (ENCRYPTION.md 5.7 addendum). A Diceware-style phrase
/// clears 16 characters without noticing.
const PASSPHRASE_MIN: usize = 16;

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

    // The passphrase is optional, but whatever is sent for it has to clear
    // the higher floor it exists for. An empty string counts as "sent" (and
    // fails), so a buggy client can never silently create an account that
    // looks like it chose a passphrase.
    let passphrase_hash = match &req.passphrase {
        Some(passphrase) => {
            if passphrase.len() < PASSPHRASE_MIN {
                return Err(AppError::BadRequest(
                    "passphrase must be at least 16 characters".into(),
                ));
            }
            Some(hash_passphrase(passphrase)?)
        }
        None => None,
    };

    let display_name = req
        .display_name
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| req.username.trim().to_string());

    let hash = hash_password(&req.password)?;
    let user = state
        .db
        .create_user(username, hash, display_name, passphrase_hash)
        .await?;

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
///
/// `mode` selects which credential `password` carries. `"password"` is the
/// default when the field is absent, which is what WebDAV, the API and every
/// client written before the passphrase existed sends - the password keeps
/// working unchanged. `"passphrase"` verifies against `passphrase_hash`
/// instead; both branches answer the same 401 for a wrong value, and a
/// passphrase-only account presenting its password (or the reverse) fails
/// identically, so neither response says which credential was tried.
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

    let verified = match req.mode.as_deref().unwrap_or("password") {
        "password" => verify_password(&req.password, &found.password_hash),
        "passphrase" => verify_passphrase(&req.password, found.passphrase_hash.as_deref()),
        _ => {
            return Err(AppError::BadRequest(
                "mode must be 'password' or 'passphrase'".into(),
            ))
        }
    };
    if !verified {
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
///
/// Also reports `has_passphrase`, a boolean: the settings dialog needs to
/// know whether the optional sign-in credential exists so it can offer to
/// set or remove it. Like both hashes, the underlying value stays inside
/// the auth layer - this is only the owner asking about their own account.
pub async fn me(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let used_bytes = state.db.owner_usage(user.id()).await?;
    let mut me = serde_json::to_value(&user.0)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serializing user: {e}")))?;
    me["used_bytes"] = json!(used_bytes);
    let has_passphrase = state
        .db
        .find_user_by_username(user.0.username.clone())
        .await?
        .map(|row| row.passphrase_hash.is_some())
        .unwrap_or(false);
    me["has_passphrase"] = json!(has_passphrase);
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
/// the new one gets the same length floor as registration. The session that
/// made the change stays open, so the menu can keep being used afterwards.
pub async fn change_password(
    State(state): State<SharedState>,
    user: AuthUser,
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
    state.db.set_password(user.id(), hash).await?;
    Ok(Json(json!({ "ok": true })))
}

/// PUT /api/me/passphrase - set or replace the optional sign-in passphrase.
///
/// The body's `current_password` is the proof, verified against
/// `password_hash`: the session alone only shows "someone is signed in", and
/// a hijacked tab must not be able to swap the credential the owner signs in
/// with (same reasoning as [`change_password`]). Only the current *password*
/// can prove it - the passphrase being set or replaced cannot vouch for
/// itself, and an old one is not required either, since ownership of the
/// account is what is being established.
///
/// This endpoint deliberately runs *before* the client rewraps the key row:
/// a mistyped proof then costs a single request and touches nothing, while
/// the reverse order could leave keys under a passphrase the server refuses
/// to accept at sign-in.
pub async fn set_passphrase(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<SetPassphraseRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if req.passphrase.len() < PASSPHRASE_MIN {
        return Err(AppError::BadRequest(
            "passphrase must be at least 16 characters".into(),
        ));
    }
    let found = state
        .db
        .find_user_by_username(user.0.username.clone())
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !verify_password(&req.current_password, &found.password_hash) {
        return Err(AppError::Unauthorized);
    }
    let hash = hash_passphrase(&req.passphrase)?;
    state.db.set_passphrase(user.id(), hash).await?;
    Ok(Json(json!({ "ok": true })))
}

/// DELETE /api/me/passphrase - give the optional sign-in credential up again.
///
/// Same password proof as [`set_passphrase`]; afterwards `mode:
/// "passphrase"` stops verifying while password sign-in and WebDAV are
/// untouched, and the client rewraps the key row back under the login
/// password in the same flow. Removing a passphrase that was never set is a
/// no-op, so a retried removal converges instead of erroring.
pub async fn remove_passphrase(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<RemovePassphraseRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let found = state
        .db
        .find_user_by_username(user.0.username.clone())
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !verify_password(&req.current_password, &found.password_hash) {
        return Err(AppError::Unauthorized);
    }
    state.db.clear_passphrase(user.id()).await?;
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
