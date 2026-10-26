use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{BatchOutcome, BatchShareRequest, CreateShareRequest};
use crate::sharing::{perm_names, PERM_ALL};
use crate::web::state::SharedState;

/// Optional filter for the outgoing-shares listing.
#[derive(Deserialize, Default)]
pub struct OutgoingQuery {
    pub file_id: Option<i64>,
}

/// Size ceiling for one key envelope, in characters.
///
/// One envelope carries exactly one wrapped key record (5.5: a folder key or
/// a file key, never a whole subtree) - ECIES over a 32-byte value is a few
/// hundred characters of base64. The cap exists so a share row cannot become
/// an unbounded parking spot for data the server is not meant to understand;
/// a larger blob is refused with 400 rather than silently truncated, because
/// a truncated envelope would arrive at the grantee as an undecodable file.
const ENVELOPE_MAX_CHARS: usize = 8192;

/// Reject envelopes the server should not be carrying.
///
/// The blob is opaque here by design (5.5) - the server can neither read it
/// nor check that it opens - so the only thing it can enforce is a sane
/// size. Plaintext shares pass `None` and skip this entirely.
fn check_envelope(envelope: &Option<String>) -> Result<(), AppError> {
    match envelope {
        None => Ok(()),
        Some(env) if env.is_empty() => Err(AppError::BadRequest(
            "empty key envelope - send the wrapped record or no field at all".into(),
        )),
        Some(env) if env.len() > ENVELOPE_MAX_CHARS => Err(AppError::BadRequest(format!(
            "key envelope is too large - one share carries one wrapped key record, \
             up to {ENVELOPE_MAX_CHARS} characters"
        ))),
        Some(_) => Ok(()),
    }
}

/// POST /api/shares – share a file/folder with another user.
pub async fn create(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<CreateShareRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_envelope(&req.envelope)?;
    let perms = req.permissions.unwrap_or(PERM_ALL);
    let share = state
        .db
        .create_share(user.id(), req.file_id, req.username, perms, req.envelope)
        .await?;
    Ok(Json(json!({
        "share": {
            "id": share.id,
            "file_id": share.source_id,
            "source_name": share.source_name,
            "is_dir": share.is_dir,
            "username": share.grantee_username,
            "permissions": share.permissions,
            "permission_names": perm_names(share.permissions),
            "created_at": share.created_at,
        }
    })))
}

/// POST /api/shares/batch – share several items with the same user at once.
///
/// Independent per item, like the other batch operations: an item that is
/// already shared with that user (or that the caller may not share) is
/// reported in `failed`, the rest of the selection still goes through.
pub async fn create_batch(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<BatchShareRequest>,
) -> Result<Json<BatchOutcome>, AppError> {
    if req.items.is_empty() {
        return Err(AppError::BadRequest("nothing is selected".into()));
    }
    // Checked before the loop so one oversized blob cannot leave a
    // half-shared selection behind: the items either all carry sane
    // envelopes or the request never reaches a single one of them.
    for item in &req.items {
        check_envelope(&item.envelope)?;
    }
    let perms = req.permissions.unwrap_or(PERM_ALL);
    let mut out = BatchOutcome::default();

    for item in req.items {
        let file_id = item.file_id;
        match state
            .db
            .create_share(user.id(), file_id, req.username.clone(), perms, item.envelope)
            .await
        {
            Ok(_) => out.success(file_id),
            Err(e) => {
                let name = state
                    .db
                    .entry_for_read(user.id(), file_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|entry| entry.name);
                out.failure(file_id, name, e.user_message());
            }
        }
    }
    Ok(Json(out))
}

/// DELETE /api/shares/:id – revoke a share (owner or grantee).
pub async fn revoke(
    State(state): State<SharedState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.revoke_share(user.id(), id).await?;
    Ok(Json(json!({ "ok": true })))
}

/// GET /api/shares/outgoing[?file_id=N] – shares I created, optionally for one item.
pub async fn outgoing(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<OutgoingQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let shares = state.db.list_outgoing(user.id()).await?;
    Ok(Json(json!({
        "shares": shares.iter().filter(|s| q.file_id.is_none_or(|f| s.source_id == f)).map(|s| json!({
            "id": s.id,
            "file_id": s.source_id,
            "source_name": s.source_name,
            "is_dir": s.is_dir,
            "username": s.grantee_username,
            "permissions": s.permissions,
            "permission_names": perm_names(s.permissions),
            "created_at": s.created_at,
        })).collect::<Vec<_>>(),
    })))
}

/// GET /api/shares/incoming – shares given to me (mounted in my root).
pub async fn incoming(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let shares = state.db.list_incoming(user.id()).await?;
    Ok(Json(json!({
        "shares": shares.iter().map(|s| json!({
            "id": s.id,
            "file_id": s.source_id,
            "name": s.display_name,
            "source_name": s.source_name,
            "is_dir": s.is_dir,
            "size": s.size,
            "owner": s.owner_username,
            "permissions": s.permissions,
            "permission_names": perm_names(s.permissions),
            "can_share": crate::sharing::grants(s.permissions, crate::sharing::PERM_SHARE),
            "created_at": s.created_at,
            // Sealed to my public key by the sharer's browser; only my
            // private key opens it (5.5). NULL for plaintext shares.
            "envelope": s.envelope,
        })).collect::<Vec<_>>(),
    })))
}
