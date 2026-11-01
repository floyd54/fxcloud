use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::AuthUser;
use crate::db::link::DEFAULT_EXPIRY_DAYS;
use crate::error::AppError;
use crate::models::{CreatePublicLinkRequest, PublicLink};
use crate::sharing::{grants, perm_names, PERM_CREATE, PERM_DELETE, PERM_READ, PERM_UPDATE};
use crate::web::state::SharedState;

/// Optional filter for the public-links overview.
#[derive(Deserialize, Default)]
pub struct LinksQuery {
    pub file_id: Option<i64>,
}

/// The three preset masks the UI may send (concepts/public_links.md section
/// 4). The server refuses anything else, so a caller cannot smuggle in an
/// arbitrary mask - least of all `PERM_SHARE`, which the database layer
/// rejects on top of this.
const PRESET_MASKS: [i64; 3] = [
    PERM_READ,                                           // read:  1
    PERM_CREATE,                                         // add:   4
    PERM_READ | PERM_CREATE | PERM_UPDATE | PERM_DELETE, // full: 15
];

fn check_preset(perms: i64) -> Result<i64, AppError> {
    if PRESET_MASKS.contains(&perms) {
        Ok(perms)
    } else {
        Err(AppError::BadRequest(
            "permissions must be one of the presets: read (1), add (4) or full (15)".into(),
        ))
    }
}

/// One link's JSON shape, without any token - the overview can never re-echo
/// a working one, only the record that exists in the table.
fn link_json(l: &PublicLink) -> serde_json::Value {
    json!({
        "id": l.id,
        "file_id": l.source_id,
        "source_name": l.source_name,
        "is_dir": l.is_dir,
        "permissions": l.permissions,
        "permission_names": perm_names(l.permissions),
        "can_read": grants(l.permissions, PERM_READ),
        "can_create": grants(l.permissions, PERM_CREATE),
        "label": l.label,
        "expiry_mode": l.expiry_mode,
        "expires_in_days": l.expires_in_days,
        "expires_at": l.expires_at,
        "last_access_at": l.last_access_at,
        "download_count": l.download_count,
        "created_at": l.created_at,
    })
}

/// POST /api/links - mint a public link on a personal entry.
///
/// Returns the record plus the raw token and its visitor URL. This is the
/// **only** response that ever carries the token: the server stores just its
/// sha256, so a later overview or a database dump yields nothing usable.
pub async fn create(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<CreatePublicLinkRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let perms = check_preset(req.permissions)?;
    let (link, token) = state
        .db
        .create_public_link(
            user.id(),
            req.file_id,
            perms,
            req.expiry_mode,
            req.expires_in_days,
            req.label,
        )
        .await?;
    Ok(Json(json!({
        "link": link_json(&link),
        // Shown once, in this response, then only its hash survives.
        "token": token,
        "url": format!("/s/{token}"),
    })))
}

/// GET /api/links[?file_id=N] - the caller's public links, newest first.
pub async fn list(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<LinksQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let links = state.db.list_public_links(user.id()).await?;
    Ok(Json(json!({
        "links": links
            .iter()
            .filter(|l| q.file_id.is_none_or(|f| l.source_id == f))
            .map(link_json)
            .collect::<Vec<_>>(),
        "default_expiry_days": DEFAULT_EXPIRY_DAYS,
    })))
}

/// DELETE /api/links/:id - revoke a link (owner only), effective next request.
pub async fn revoke(
    State(state): State<SharedState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.db.revoke_public_link(user.id(), id).await?;
    Ok(Json(json!({ "ok": true })))
}
