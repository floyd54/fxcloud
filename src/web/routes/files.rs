use axum::extract::{Multipart, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{CreateFolderRequest, RenameRequest, TransferRequest};
use crate::web::state::SharedState;

#[derive(Deserialize)]
pub struct ListQuery {
    pub parent: Option<i64>,
}

#[derive(Deserialize)]
pub struct IdQuery {
    pub id: i64,
}

/// GET /api/files?parent=<id> – list a folder's contents (root when omitted).
pub async fn list(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let entries = state.db.list_children(user.id(), q.parent).await?;
    Ok(Json(json!({ "entries": entries })))
}

/// GET /api/files/breadcrumb?id=<id> – breadcrumb trail to the given folder.
pub async fn breadcrumb(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<IdQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let trail = state.db.breadcrumbs(user.id(), q.id).await?;
    Ok(Json(json!({ "breadcrumbs": trail })))
}

/// GET /api/files/info?id=<id> – one entry's metadata including the viewer's
/// permission mask (full set for own entries, the share's for shared ones).
pub async fn info(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<IdQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let entry = state
        .db
        .entry_for_read(user.id(), q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(json!({ "entry": entry })))
}

/// POST /api/files/folder – create a new folder.
pub async fn create_folder(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<CreateFolderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let entry = state
        .db
        .create_dir(user.id(), req.parent_id, req.name)
        .await?;
    Ok(Json(json!({ "entry": entry })))
}

/// POST /api/files/rename – rename an existing entry.
pub async fn rename(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<RenameRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let entry = state.db.rename_entry(user.id(), req.id, req.name).await?;
    Ok(Json(json!({ "entry": entry })))
}

/// POST /api/files/delete – delete an entry (recursive for folders).
pub async fn delete(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = req
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::BadRequest("missing 'id'".into()))?;
    let blob_ids = state.db.delete_entry(user.id(), id).await?;
    state.files.delete_blobs(&blob_ids).await;
    Ok(Json(json!({ "ok": true })))
}

/// POST /api/files/move – move an entry into another folder (keeps its name).
///
/// Enforced by the DB layer: UPDATE on the source, CREATE at the destination,
/// and no moving items across owners.
pub async fn move_entry(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<TransferRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let entry = state
        .db
        .entry_for_read(user.id(), req.id)
        .await?
        .ok_or(AppError::NotFound)?;
    let moved = state
        .db
        .move_entry(user.id(), req.id, req.dest_parent, entry.name)
        .await?;
    Ok(Json(json!({ "entry": moved })))
}

/// POST /api/files/copy – copy an entry (subtree incl. content) elsewhere.
///
/// Requires READ on the source and CREATE at the destination; the copy lands
/// in the destination owner's tree.
pub async fn copy_entry(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<TransferRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let entry = state
        .db
        .entry_for_read(user.id(), req.id)
        .await?
        .ok_or(AppError::NotFound)?;
    let dst_name = entry.name.clone();
    let copied =
        crate::webdav::copy_recursive(&state, user.id(), &entry, req.dest_parent, dst_name)
            .await?;
    Ok(Json(json!({ "entry": copied })))
}

/// POST /api/files/upload – multipart upload of one file into `parent`.
pub async fn upload(
    State(state): State<SharedState>,
    user: AuthUser,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut parent_id: Option<i64> = None;
    let mut filename: Option<String> = None;
    let mut data: Option<Vec<u8>> = None;
    let mut mime: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("invalid multipart: {e}")))?
    {
        match field.name().unwrap_or("") {
            "parent" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("bad parent: {e}")))?;
                parent_id = text.trim().parse().ok();
            }
            "file" => {
                filename = field.file_name().map(|s| s.to_string());
                mime = field
                    .content_type()
                    .map(|s| s.to_string());
                data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("bad file data: {e}")))?
                        .to_vec(),
                );
            }
            _ => {}
        }
    }

    let filename = filename.ok_or_else(|| AppError::BadRequest("missing file".into()))?;
    let data = data.ok_or_else(|| AppError::BadRequest("missing file data".into()))?;
    let size = data.len() as i64;

    // Create metadata first to obtain a file id, then persist the blob.
    let entry = state
        .db
        .create_file(user.id(), parent_id, filename, size, mime)
        .await?;
    if let Err(e) = state.files.write_blob(entry.id, data).await {
        // Roll back the orphaned metadata row.
        let _ = state.db.delete_entry(user.id(), entry.id).await;
        return Err(e);
    }

    Ok(Json(json!({ "entry": entry })))
}

/// GET /api/files/download?id=<id> – stream a file's content.
pub async fn download(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<IdQuery>,
) -> Result<Response, AppError> {
    let (entry, data) = state.files.read_blob(user.id(), q.id).await?;

    let content_type = entry
        .mime
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    // RFC 5987 encoding so non-ASCII filenames survive the header.
    let encoded_name = encode_rfc5987(&entry.name);
    let disposition = format!("attachment; filename*=UTF-8''{encoded_name}");

    let headers = [
        (header::CONTENT_TYPE, content_type.parse::<header::HeaderValue>().unwrap()),
        (
            header::CONTENT_DISPOSITION,
            disposition.parse::<header::HeaderValue>().unwrap(),
        ),
        (
            header::CONTENT_LENGTH,
            data.len().to_string().parse::<header::HeaderValue>().unwrap(),
        ),
    ];

    Ok((StatusCode::OK, headers, data).into_response())
}

/// Percent-encode a string for use in an RFC 5987 `filename*` parameter.
fn encode_rfc5987(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
