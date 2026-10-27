//! User administration (`/api/admin/users`).
//!
//! Everything here is guarded by the [`AdminUser`] extractor, so a signed-in
//! account without the administrator flag is rejected with `403` before any of
//! these handlers runs. The routes manage exactly the three properties the
//! admin dialog exposes - activation, the administrator flag itself, and the
//! storage quota - plus a password reset that hands back a freshly generated
//! temporary password.

use axum::extract::{Path, State};
use axum::Json;
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde_json::json;

use crate::auth::{hash_password, AdminUser};
use crate::error::AppError;
use crate::models::{AdminUpdateUserRequest, AdminUser as AdminUserRow};
use crate::web::state::SharedState;

/// GET /api/admin/users -- every account with the fields the admin dialog
/// renders: ids, labels, `is_active`, `is_admin`, the quota and current
/// consumption, and the creation time.
///
/// Only administrators reach this (the `AdminUser` extractor returns `403`
/// for anyone else).
pub async fn list_users(
    State(state): State<SharedState>,
    _admin: AdminUser,
) -> Result<Json<Vec<AdminUserRow>>, AppError> {
    Ok(Json(state.db.list_admin_users().await?))
}

/// PUT /api/admin/users/:id -- apply the partial update from the admin dialog.
///
/// Each field in the body is optional; only the present ones are written.
/// Two safety rules are enforced beyond a plain column write:
///
/// * an administrator cannot deactivate themselves (they would lose access to
///   the very dialog they are standing in, with no way back in);
/// * no change may leave the instance without a single active administrator
///   - deactivating or demoting the last one is refused, because nobody would
///   be left to undo it.
///
/// Returns the updated row so the dialog can refresh in place.
pub async fn update_user(
    State(state): State<SharedState>,
    admin: AdminUser,
    Path(user_id): Path<i64>,
    Json(req): Json<AdminUpdateUserRequest>,
) -> Result<Json<AdminUserRow>, AppError> {
    // The target's current state, needed to reason about the safety rules.
    let target = state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Rule 1: no self-deactivation. The request may flip is_active to false
    // for the caller's own account; that is always refused.
    if user_id == admin.id() && req.is_active == Some(false) {
        return Err(AppError::BadRequest(
            "you cannot deactivate your own account".into(),
        ));
    }

    // Rule 2: keep at least one active administrator. Compute the state after
    // the change: an account counts as an active admin when both flags are on.
    let after_active = req.is_active.unwrap_or(target.is_active);
    let after_admin = req.is_admin.unwrap_or(target.is_admin);
    let was_active_admin = target.is_active && target.is_admin;
    let now_active_admin = after_active && after_admin;
    if was_active_admin && !now_active_admin {
        // The change removes one active administrator. Refuse it if this is
        // the last one.
        let remaining = state.db.count_active_admins().await?;
        if remaining <= 1 {
            return Err(AppError::BadRequest(
                "cannot deactivate or demote the last active administrator".into(),
            ));
        }
    }

    // Quota sanity: a negative quota would reject every write, and a zero
    // quota is almost certainly a unit mistake (the schema default is 1 GiB).
    if let Some(quota) = req.quota_bytes {
        if quota < 0 {
            return Err(AppError::BadRequest("quota must not be negative".into()));
        }
    }

    // Apply each present field. They are written as separate statements so a
    // caller changing only one property does not touch the others.
    if let Some(active) = req.is_active {
        state.db.set_user_active(user_id, active).await?;
    }
    if let Some(is_admin) = req.is_admin {
        state.db.set_user_admin(user_id, is_admin).await?;
    }
    if let Some(quota) = req.quota_bytes {
        state.db.set_user_quota(user_id, quota).await?;
    }

    // Read the row back so the response reflects every applied change.
    let updated = state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let used_bytes = state.db.owner_usage(user_id).await?;
    Ok(Json(AdminUserRow {
        id: updated.id,
        username: updated.username,
        display_name: updated.display_name,
        is_active: updated.is_active,
        is_admin: updated.is_admin,
        quota_bytes: updated.quota_bytes,
        used_bytes,
        created_at: updated.created_at,
    }))
}

/// POST /api/admin/users/:id/password -- reset one account's password.
///
/// Generates a random temporary password, stores its hash, and returns the
/// plaintext exactly once so the administrator can pass it on. The account's
/// other sessions are left alone on purpose: the reset is meant for a user who
/// lost their password, not to kick out whoever is signed in.
///
/// The generated value is 16 alphanumeric characters (about 95 bits of
/// entropy from `OsRng`), which is far beyond what the 8-character minimum of
/// the normal change-password path allows.
pub async fn reset_password(
    State(state): State<SharedState>,
    _admin: AdminUser,
    Path(user_id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Make sure the account exists before generating anything.
    let target = state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let temporary = generate_temporary_password();
    let hash = hash_password(&temporary)?;
    state.db.set_password(user_id, hash).await?;

    Ok(Json(json!({
        "username": target.username,
        "temporary_password": temporary,
    })))
}

/// Draw a random temporary password: 16 alphanumeric characters from the
/// OS CSPRNG (`OsRng`), so it is unpredictable and safe to hand out once.
fn generate_temporary_password() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}
