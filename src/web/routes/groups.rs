//! Group membership and folder keys from the member's side
//! (concepts/groups.md sections 4-5): the caller's own groups, their stored
//! key envelopes, and - for managers - the pending list and the
//! distribution endpoint.
//!
//! The admin's side (creating groups, editing memberships) is
//! `src/web/routes/admin.rs`; everything here sits behind the plain
//! `AuthUser` and only ever reveals what the caller's membership entitles
//! them to: groups they belong to, envelopes for folders they may open, and
//! a pending list only a manager receives.

use axum::extract::{Path, State};
use axum::Json;
use serde_json::json;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{GroupKeyEnvelope, GroupKeyPutRequest, MyGroup, PendingGroupKey};
use crate::web::state::SharedState;

/// One envelope carries exactly one wrapped key record (ENCRYPTION.md 5.5)
/// - a folder key, never a subtree. The cap mirrors the share envelope's
/// (routes/shares.rs): the blob is opaque here by design, so a sane size is
/// the only thing the server can enforce, and a larger one is refused with
/// 400 rather than stored as a parking spot for data it is not meant to
/// understand.
const ENVELOPE_MAX_CHARS: usize = 8192;

/// Reject envelopes the server should not be carrying.
fn check_envelope(envelope: &str) -> Result<(), AppError> {
    if envelope.is_empty() {
        return Err(AppError::BadRequest(
            "empty key envelope - send the wrapped record".into(),
        ));
    }
    if envelope.len() > ENVELOPE_MAX_CHARS {
        return Err(AppError::BadRequest(format!(
            "key envelope is too large - one folder carries one wrapped key \
             record, up to {ENVELOPE_MAX_CHARS} characters"
        )));
    }
    Ok(())
}

/// GET /api/groups -- the caller's own groups with their roles: the root
/// badge, the "new group folder" picker, and the move dialog's group
/// entries. The quota figures ride along read-only (concepts/groups.md
/// section 8: the budget is operator-set, members see it but cannot write
/// it).
pub async fn list_my(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<Vec<MyGroup>>, AppError> {
    Ok(Json(state.db.list_my_groups(user.id()).await?))
}

/// GET /api/groups/keys -- the caller's stored key envelopes for their
/// groups' top-level folders (ENCRYPTION.md 5.5): one per folder they may
/// open, to feed the frontend's envelope cache beside the share ones.
pub async fn my_envelopes(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<Vec<GroupKeyEnvelope>>, AppError> {
    Ok(Json(state.db.group_key_envelopes(user.id()).await?))
}

/// GET /api/groups/{id}/keys/pending -- the manager's work list: every
/// (top-level folder, member) pair still missing a wrapped record, with a
/// flag saying whether the member has published a public key to wrap
/// against. Members get 403, non-members the 404 their listings give them
/// (the gate answers both, `db/group.rs`).
pub async fn keys_pending(
    State(state): State<SharedState>,
    user: AuthUser,
    Path(group_id): Path<i64>,
) -> Result<Json<Vec<PendingGroupKey>>, AppError> {
    Ok(Json(
        state.db.group_keys_pending(user.id(), group_id).await?,
    ))
}

/// POST /api/groups/{id}/keys -- distribute one wrapped key record to one
/// member (manager only; re-distributing overwrites).
///
/// The envelope is opaque here by design (5.5): the server holds no key and
/// cannot check that it opens, so it enforces the size cap and the chain of
/// gates - manager, folder of *this* group, recipient a member - and nothing
/// about the crypto (the same position `PUT /files/key` takes).
pub async fn distribute_key(
    State(state): State<SharedState>,
    user: AuthUser,
    Path(group_id): Path<i64>,
    Json(req): Json<GroupKeyPutRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_envelope(&req.envelope)?;
    state
        .db
        .put_group_key(user.id(), group_id, req.file_id, req.user_id, req.envelope)
        .await?;
    Ok(Json(json!({ "ok": true })))
}
