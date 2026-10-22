use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::CreateShareRequest;
use crate::sharing::{perm_names, PERM_ALL};
use crate::web::state::SharedState;

/// Optional filter for the outgoing-shares listing.
#[derive(Deserialize, Default)]
pub struct OutgoingQuery {
    pub file_id: Option<i64>,
}

/// POST /api/shares – share a file/folder with another user.
pub async fn create(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<CreateShareRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let perms = req.permissions.unwrap_or(PERM_ALL);
    let share = state
        .db
        .create_share(user.id(), req.file_id, req.username, perms)
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
        })).collect::<Vec<_>>(),
    })))
}
