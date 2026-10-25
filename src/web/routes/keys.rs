//! Key material endpoints (ENCRYPTION.md section 6).
//!
//! Four routes, all of them thin: the server stores and forwards wrapped
//! blobs, it never sees a key. `setup` is the only one that can *create* a
//! row, `rewrap` (`PUT /api/keys/me`) is the only one that can change it after
//! that, and both are reachable solely by the owner of the account.

use axum::extract::{Path, State};
use axum::Json;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{RewrapKeysRequest, SetupKeysRequest};
use crate::web::state::SharedState;

/// POST /api/keys/setup - publish an account's key material once.
///
/// Idempotent for an identical payload, 409 for a different one: see
/// [`crate::db::Db::save_user_keys`] for why overwriting is refused rather
/// than silently accepted.
pub async fn setup(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<SetupKeysRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.save_user_keys(user.id(), req).await?;
    let keys = state
        .db
        .get_own_keys(user.id())
        .await?
        .ok_or(AppError::Internal(anyhow::anyhow!(
            "keys vanished after setup"
        )))?;
    Ok(Json(serde_json::json!({ "keys": keys })))
}

/// GET /api/keys/me - the caller's own material, wrapped.
///
/// What a second tab needs to unlock without re-running setup, and what the
/// passphrase-change flow reads before it rewraps. Every field in the response
/// is ciphertext except the fingerprint.
pub async fn get_me(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let keys = state
        .db
        .get_own_keys(user.id())
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(serde_json::json!({ "keys": keys })))
}

/// PUT /api/keys/me - rewrap the ARK under a new passphrase KEK.
///
/// Only `wrapped_ark`, `kdf_salt` and `kdf_params` move; everything derived
/// from the ARK itself stays exactly where it was (ENCRYPTION.md 5.7).
pub async fn put_me(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<RewrapKeysRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.rewrap_keys(user.id(), req).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /api/keys/<username> - another account's public key and fingerprint.
///
/// 404 when the account exists but has not enabled encryption, so the share
/// dialog can tell "no key to exchange with" from "wrong username" without
/// learning anything it should not.
pub async fn get_public(
    State(state): State<SharedState>,
    user: AuthUser,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let _ = user; // any signed-in account may look up a public key
    let username = username.trim().to_lowercase();
    let info = state
        .db
        .get_public_key(username)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(serde_json::json!({ "key": info })))
}
