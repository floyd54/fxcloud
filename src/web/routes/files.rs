use std::collections::HashSet;
use std::io::{Read, Write};

use axum::body::Bytes;
use axum::extract::{Multipart, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::files::FileService;
use crate::models::{
    BatchIdsRequest, BatchOutcome, BatchTransferRequest, BlobRef, CreateFileRequest,
    CreateFolderRequest, FileEntry, RenameRequest, TransferRequest, ZipRequest,
};
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

/// POST /api/files/file – create a new, initially empty file (the web UI's
/// "New file" button; content follows via PUT /api/files/content).
///
/// Name rules, the CREATE permission on the parent and the duplicate check
/// are the ones folder creation already uses.
pub async fn create_file(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<CreateFileRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let entry = state
        .db
        .create_file(user.id(), req.parent_id, req.name, 0, None)
        .await?;
    // An empty blob on disk, so download and preview work right away.
    if let Err(e) = state.files.write_blob(&entry, Vec::new()).await {
        let _ = state.db.hard_delete_entry(user.id(), entry.id).await;
        return Err(e);
    }
    Ok(Json(json!({ "entry": entry })))
}

/// POST /api/files/folder/ensure – get-or-create a folder by name.
///
/// Folder uploads call this once per directory level, so re-uploading a tree
/// reuses the folders that already exist instead of failing with 409.
pub async fn ensure_folder(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<CreateFolderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let entry = state
        .db
        .ensure_dir(user.id(), req.parent_id, req.name)
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
    state.db.trash_entry(user.id(), id).await?;
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
    if let Err(e) = state.files.write_blob(&entry, data).await {
        // Roll back the orphaned metadata row.
        let _ = state.db.hard_delete_entry(user.id(), entry.id).await;
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
        (
            header::X_CONTENT_TYPE_OPTIONS,
            "nosniff".parse::<header::HeaderValue>().unwrap(),
        ),
    ];

    Ok((StatusCode::OK, headers, data).into_response())
}

/// Content types the browser renders natively, keyed by file extension.
///
/// This table decides the `Content-Type` of `/api/files/preview` and is
/// mirrored in `previewKind()` in `frontend/assets/app.js`, which decides
/// whether a click opens the lightbox instead of downloading. The server is
/// the authority on what actually gets served.
fn extension_type(name: &str) -> Option<&'static str> {
    let ext = name.rsplit('.').next()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "png" | "apng" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "svg" => "image/svg+xml",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "ogv" => "video/ogg",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "flac" => "audio/flac",
        "pdf" => "application/pdf",
        "html" | "htm" => "text/html; charset=utf-8",
        // Notes, data, configuration and source files — plain text all the
        // way, so the browser shows their contents directly.
        "txt" | "text" | "md" | "markdown" | "csv" | "tsv" | "log" | "json" | "xml" | "yml"
        | "yaml" | "toml" | "ini" | "cfg" | "conf" | "env" | "sql" | "rst" | "tex" | "diff"
        | "patch" | "rs" | "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "py" | "rb" | "go"
        | "java" | "c" | "h" | "cc" | "cpp" | "hpp" | "cs" | "php" | "sh" | "bash" | "zsh"
        | "pl" | "lua" | "swift" | "kt" | "kts" | "scala" | "r" | "vue" | "svelte" | "css"
        | "scss" | "sass" | "less" | "makefile" => "text/plain; charset=utf-8",
        _ => return None,
    })
}

/// The `Content-Type` an inline preview is served with: the extension wins,
/// otherwise a stored MIME type the browser understands (an upload that
/// arrived as `application/octet-stream` still previews when its stored type
/// is a real one). `None` means "not previewable in the browser".
fn preview_content_type(entry: &FileEntry) -> Option<String> {
    if let Some(t) = extension_type(&entry.name) {
        return Some(t.to_string());
    }
    let mime = entry.mime.as_deref()?;
    let browser_kind = mime.starts_with("text/")
        || mime.starts_with("image/")
        || mime.starts_with("video/")
        || mime.starts_with("audio/")
        || mime == "application/pdf";
    browser_kind.then(|| mime.to_string())
}

/// What to do with a request's `Range` header.
enum ByteRange {
    /// No header (or one we deliberately ignore): send the whole body.
    Full,
    /// A satisfiable single range, both ends inclusive.
    Slice(usize, usize),
    /// Valid syntax, but outside the file: answer `416`.
    Unsatisfiable,
}

/// Parse the range forms media players actually send for seeking
/// (`bytes=0-`, `bytes=100-`, `bytes=-500`). Multi-range and malformed
/// headers fall back to the full body, which RFC 9110 explicitly allows.
fn parse_byte_range(value: &str, len: usize) -> ByteRange {
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        return ByteRange::Full; // any other unit: ignore
    };
    if spec.contains(',') {
        return ByteRange::Full; // multipart ranges are not worth it here
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return ByteRange::Full;
    };
    let (start_s, end_s) = (start_s.trim(), end_s.trim());
    if start_s.is_empty() {
        // "bytes=-500": the last 500 bytes.
        return match end_s.parse::<usize>() {
            Ok(0) => ByteRange::Unsatisfiable,
            Ok(_) if len == 0 => ByteRange::Unsatisfiable,
            Ok(n) => ByteRange::Slice(len.saturating_sub(n), len - 1),
            Err(_) => ByteRange::Full,
        };
    }
    let Ok(start) = start_s.parse::<usize>() else {
        return ByteRange::Full;
    };
    if start >= len {
        return ByteRange::Unsatisfiable;
    }
    match end_s.parse::<usize>() {
        // An open end ("bytes=100-") runs to the last byte.
        Err(_) if end_s.is_empty() => ByteRange::Slice(start, len - 1),
        Ok(end) if end >= start => ByteRange::Slice(start, end.min(len - 1)),
        // last < first is invalid syntax: ignore the header entirely.
        _ => ByteRange::Full,
    }
}

/// GET /api/files/preview?id=<id> – serve content the browser can render by
/// itself, inline instead of as a download (the web UI's lightbox).
///
/// Byte ranges are honoured (206 / 416) because media players seek, and
/// every response carries `nosniff` plus an empty `sandbox`: HTML or SVG
/// hosted on this origin renders without scripts, so a page someone shared
/// in can never act on the viewer's session.
pub async fn preview(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<IdQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (entry, data) = state.files.read_blob(user.id(), q.id).await?;
    let content_type = preview_content_type(&entry).ok_or_else(|| {
        AppError::BadRequest(
            "this file type cannot be displayed in the browser - use Download".into(),
        )
    })?;
    let len = data.len();
    let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(value) => parse_byte_range(value, len),
        None => ByteRange::Full,
    };

    // RFC 5987 encoding so non-ASCII filenames survive the header.
    let encoded_name = encode_rfc5987(&entry.name);
    let disposition = format!("inline; filename*=UTF-8''{encoded_name}");

    let (status, body, content_range) = match range {
        ByteRange::Unsatisfiable => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            Vec::new(),
            Some(format!("bytes */{len}")),
        ),
        ByteRange::Slice(start, end) => (
            StatusCode::PARTIAL_CONTENT,
            data[start..=end].to_vec(),
            Some(format!("bytes {start}-{end}/{len}")),
        ),
        ByteRange::Full => (StatusCode::OK, data, None),
    };

    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, &content_type)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        // Empty sandbox: renders without scripts (see the doc comment).
        .header("Content-Security-Policy", "sandbox");
    if let Some(content_range) = content_range {
        builder = builder.header(header::CONTENT_RANGE, content_range);
    }
    builder = builder.header(header::CONTENT_LENGTH, body.len().to_string());
    let resp = builder
        .body(axum::body::Body::from(body))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("building preview response: {e}")))?;
    Ok(resp.into_response())
}

/// PUT /api/files/content?id=<id> – overwrite a file's content with the raw
/// request body (the web editor's save path).
///
/// Permission (PERM_UPDATE), tree-owner resolution and the quota gate all
/// come from `update_file_meta`, the same path WebDAV PUT takes, so the
/// editor and sync clients cannot diverge.
pub async fn save_content(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<IdQuery>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    let entry = state
        .db
        .entry_for_read(user.id(), q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    if entry.is_dir {
        return Err(AppError::BadRequest("cannot edit a folder".into()));
    }
    let mime = mime_guess::from_path(&entry.name)
        .first()
        .map(|m| m.to_string());
    // The blob path is id-derived, so replacing the content in place swaps
    // the blob underneath; meta first, because it holds the quota gate.
    state
        .db
        .update_file_meta(user.id(), entry.id, body.len() as i64, mime)
        .await?;
    state.files.write_blob(&entry, body.to_vec()).await?;
    // Fresh row for the response: size and modified_at just changed.
    let entry = state
        .db
        .entry_for_read(user.id(), q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(json!({ "entry": entry })))
}

// ---------------------------------------------------------------------------
// Batch operations (multi-selection)
// ---------------------------------------------------------------------------

/// POST /api/files/batch/delete – delete several entries in one request.
///
/// Items are processed independently: an entry the caller may not delete is
/// reported in `failed`, while the rest of the selection still goes through.
pub async fn batch_delete(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<BatchIdsRequest>,
) -> Result<Json<BatchOutcome>, AppError> {
    if req.ids.is_empty() {
        return Err(AppError::BadRequest("nothing is selected".into()));
    }
    let mut out = BatchOutcome::default();

    for id in req.ids {
        match state.db.trash_entry(user.id(), id).await {
            Ok(()) => out.success(id),
            Err(e) => {
                let name = entry_name(&state, user.id(), id).await;
                out.failure(id, name, e.user_message());
            }
        }
    }

    Ok(Json(out))
}

/// GET /api/files/trash – the caller's trash: trashed roots, newest first,
/// each with the deletion time and the purge deadline.
pub async fn trash_list(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut entries = state.db.trash_list(user.id()).await?;
    let days = state.config.trash_days;
    for entry in &mut entries {
        if let Some(deleted) = entry.deleted_at {
            entry.purge_at = Some(deleted + chrono::Duration::days(days));
        }
    }
    Ok(Json(json!({ "entries": entries })))
}

/// POST /api/files/trash/restore {id} – bring a trashed entry back to where
/// it was; a name taken in the meantime gets a " (restored)" suffix.
pub async fn trash_restore(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = req
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::BadRequest("missing 'id'".into()))?;
    let entry = state.db.restore_trash(user.id(), id).await?;
    Ok(Json(json!({ "ok": true, "entry": entry })))
}

/// POST /api/files/trash/purge {id} – delete one trashed entry for good.
pub async fn trash_purge(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = req
        .get("id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::BadRequest("missing 'id'".into()))?;
    let blobs = state.db.purge_trash_item(user.id(), id).await?;
    state.files.delete_blobs(&blobs).await;
    Ok(Json(json!({ "ok": true })))
}

/// POST /api/files/trash/empty – delete the caller's whole trash now.
pub async fn trash_empty(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let blobs = state.db.empty_trash(user.id()).await?;
    state.files.delete_blobs(&blobs).await;
    Ok(Json(json!({ "ok": true })))
}

/// POST /api/files/batch/move – move several entries into one folder.
///
/// Same rules as the single-item move (permissions, owner crossing, cycle and
/// name-collision guards), applied per item.
pub async fn batch_move(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<BatchTransferRequest>,
) -> Result<Json<BatchOutcome>, AppError> {
    if req.ids.is_empty() {
        return Err(AppError::BadRequest("nothing is selected".into()));
    }
    let mut out = BatchOutcome::default();

    for id in req.ids {
        let result = async {
            let entry = state
                .db
                .entry_for_read(user.id(), id)
                .await?
                .ok_or(AppError::NotFound)?;
            state
                .db
                .move_entry(user.id(), id, req.dest_parent, entry.name)
                .await?;
            Ok::<(), AppError>(())
        }
        .await;

        match result {
            Ok(()) => out.success(id),
            Err(e) => {
                let name = entry_name(&state, user.id(), id).await;
                out.failure(id, name, e.user_message());
            }
        }
    }
    Ok(Json(out))
}

/// POST /api/files/batch/copy – copy several entries (subtrees incl. content)
/// into one folder.
pub async fn batch_copy(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<BatchTransferRequest>,
) -> Result<Json<BatchOutcome>, AppError> {
    if req.ids.is_empty() {
        return Err(AppError::BadRequest("nothing is selected".into()));
    }
    let mut out = BatchOutcome::default();

    for id in req.ids {
        let result = async {
            let entry = state
                .db
                .entry_for_read(user.id(), id)
                .await?
                .ok_or(AppError::NotFound)?;
            let name = entry.name.clone();
            crate::webdav::copy_recursive(&state, user.id(), &entry, req.dest_parent, name).await?;
            Ok::<(), AppError>(())
        }
        .await;

        match result {
            Ok(()) => out.success(id),
            Err(e) => {
                let name = entry_name(&state, user.id(), id).await;
                out.failure(id, name, e.user_message());
            }
        }
    }
    Ok(Json(out))
}

/// Look an entry's name up for a failure report (best effort — the entry may
/// already be gone by then).
async fn entry_name(state: &SharedState, user_id: i64, id: i64) -> Option<String> {
    state
        .db
        .entry_for_read(user_id, id)
        .await
        .ok()
        .flatten()
        .map(|entry| entry.name)
}

// ---------------------------------------------------------------------------
// ZIP download of a selection
// ---------------------------------------------------------------------------

/// Largest uncompressed selection a single ZIP download may contain.
///
/// The archive is assembled in memory before it is streamed, so the cap keeps
/// a huge "select all" from taking the process down; the error message tells
/// the user to download in several runs.
const MAX_ZIP_BYTES: i64 = 1024 * 1024 * 1024; // 1 GiB

#[derive(Deserialize)]
pub struct ZipQuery {
    pub token: String,
}

/// POST /api/files/zip – prepare a ZIP download, returning `{token}`.
///
/// The browser then opens `GET /api/files/zip?token=…`, which builds the
/// archive. Two steps keep the URL short no matter how many items are
/// selected (proxies cap request lines around 8 KB).
pub async fn prepare_zip(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<ZipRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if req.ids.is_empty() {
        return Err(AppError::BadRequest("nothing is selected".into()));
    }

    // Walk the selection once to size it: folders count with everything
    // inside them, and unreadable/deleted items fail early with a clear error.
    let mut total: i64 = 0;
    for id in &req.ids {
        for (_, entry) in state.db.readable_subtree(user.id(), *id).await? {
            if !entry.is_dir {
                total += entry.size;
            }
        }
        if total > MAX_ZIP_BYTES {
            return Err(AppError::BadRequest(format!(
                "the selection is too large for a single download ({}) — download fewer items at a time",
                human_size(total)
            )));
        }
    }

    let token = state.new_zip_job(user.id(), req.ids);
    Ok(Json(json!({ "token": token })))
}

/// GET /api/files/zip?token=… – build the archive and stream it as an
/// attachment.
pub async fn zip_download(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<ZipQuery>,
) -> Result<Response, AppError> {
    // Single-use token: unknown, expired or prepared by someone else — plain
    // text, because this request comes from a browser navigation.
    let Some(job) = state.take_zip_job(&q.token, user.id()) else {
        return Ok(text_error(
            StatusCode::GONE,
            "This download link has expired or was already used.\nSelect the items again to start a new download.",
        ));
    };

    // Re-read the selection: items may have been deleted or unshared since
    // the token was created. Those are skipped (and noted in the archive);
    // only a real database error aborts.
    let mut trees = Vec::with_capacity(job.ids.len());
    for id in job.ids {
        match state.db.readable_subtree(user.id(), id).await {
            Ok(tree) => trees.push(tree),
            Err(AppError::NotFound) => {}
            Err(e) => return Err(e),
        }
    }
    if trees.is_empty() {
        return Ok(text_error(
            StatusCode::NOT_FOUND,
            "Nothing to download: the selected items are gone or no longer readable.",
        ));
    }

    let filename = zip_filename(&trees);
    let builder_state = state.clone();
    let data = tokio::task::spawn_blocking(move || build_zip(&builder_state, trees))
        .await
        .map_err(|_| AppError::Join)??;

    // RFC 5987 encoding so non-ASCII names survive the header.
    let encoded_name = encode_rfc5987(&filename);
    let disposition = format!("attachment; filename*=UTF-8''{encoded_name}");
    let headers = [
        (
            header::CONTENT_TYPE,
            "application/zip".parse::<header::HeaderValue>().unwrap(),
        ),
        (
            header::CONTENT_DISPOSITION,
            disposition.parse::<header::HeaderValue>().unwrap(),
        ),
        (
            header::CONTENT_LENGTH,
            data.len()
                .to_string()
                .parse::<header::HeaderValue>()
                .unwrap(),
        ),
    ];
    Ok((StatusCode::OK, headers, data).into_response())
}

/// Download name: the single item's own name, or a generic count for more.
fn zip_filename(trees: &[Vec<(String, FileEntry)>]) -> String {
    if trees.len() == 1 {
        let name = trees[0]
            .first()
            .map(|(path, _)| path.as_str())
            .unwrap_or("download");
        format!("{name}.zip")
    } else {
        format!("{} items.zip", trees.len())
    }
}

/// Assemble the archive.
///
/// Runs on the blocking pool: the zip crate writes synchronously and blobs are
/// read off disk in 64 KiB chunks, so only the compressed output is held in
/// memory (bounded by [`MAX_ZIP_BYTES`]). Content that disappeared mid-download
/// is skipped and listed in `fxcloud-skipped.txt` inside the archive instead
/// of failing the whole selection.
fn build_zip(
    state: &SharedState,
    trees: Vec<Vec<(String, FileEntry)>>,
) -> Result<Vec<u8>, AppError> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut used: HashSet<String> = HashSet::new();
    let mut skipped: Vec<String> = Vec::new();

    for tree in trees {
        // Two selected items may carry the same path (the API takes ids from
        // anywhere, not just one folder), so the *root* of each tree gets the
        // " (2)" suffix — its descendants follow it and stay together.
        let root_path = match tree.first() {
            Some((path, _)) => path.clone(),
            None => continue,
        };
        let root = unique_path(&mut used, &root_path);
        let prefix = format!("{root_path}/");

        for (path, entry) in tree {
            let path = if path == root_path {
                root.clone()
            } else if let Some(rest) = path.strip_prefix(&prefix) {
                format!("{root}/{rest}")
            } else {
                path
            };
            // Carry the item's real modification time into the archive.
            let opts = match entry.modified_at.naive_utc().try_into() {
                Ok(time) => opts.last_modified_time(time),
                Err(_) => opts,
            };

            if entry.is_dir {
                writer
                    .add_directory(format!("{path}/"), opts)
                    .map_err(zip_error)?;
                continue;
            }

            writer.start_file(&path, opts).map_err(zip_error)?;
            if let Err(e) = copy_blob(&state.files, &entry, &mut writer) {
                if e.kind() == std::io::ErrorKind::NotFound {
                    skipped.push(format!("{path} (content missing)"));
                } else {
                    return Err(AppError::Internal(anyhow::anyhow!(
                        "reading content of '{path}': {e}"
                    )));
                }
            }
        }
    }

    if !skipped.is_empty() {
        tracing::warn!(
            count = skipped.len(),
            "zip download: entries without content"
        );
        writer
            .start_file("fxcloud-skipped.txt", opts)
            .map_err(zip_error)?;
        let note = format!(
            "The following entries could not be included:\n{}\n",
            skipped.join("\n")
        );
        writer
            .write_all(note.as_bytes())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("writing zip note: {e}")))?;
    }

    let cursor = writer.finish().map_err(zip_error)?;
    Ok(cursor.into_inner())
}

/// Stream one blob into the archive without loading it whole.
fn copy_blob(
    files: &FileService,
    entry: &FileEntry,
    writer: &mut impl std::io::Write,
) -> std::io::Result<()> {
    let path = files.blob_path(BlobRef::from(entry));
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        // Fall back to the flat layout for blobs the startup migration left
        // behind (see the `files` module docs).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::File::open(files.legacy_blob_path(entry.id))?
        }
        Err(e) => return Err(e),
    };
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
    }
    Ok(())
}

/// Keep an archive's top-level name unique: two selected items can be named the
/// same ("report.txt" in different folders) and a zip may not contain a path
/// twice. The second occurrence becomes "report (2).txt".
fn unique_path(used: &mut HashSet<String>, path: &str) -> String {
    if used.insert(path.to_string()) {
        return path.to_string();
    }
    let (dir, file) = match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    };
    let (stem, ext) = match file.rfind('.') {
        Some(i) if i > 0 => (&file[..i], &file[i..]),
        _ => (file, ""),
    };
    for n in 2..10_000 {
        let candidate = format!("{dir}{stem} ({n}){ext}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    path.to_string()
}

fn zip_error(e: zip::result::ZipError) -> AppError {
    AppError::Internal(anyhow::anyhow!("building zip: {e}"))
}

/// Human-readable size for user-facing messages (the UI has its own formatter).
fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Plain-text body for downloads the browser opened as a top-level request.
fn text_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        message.to_string(),
    )
        .into_response()
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
