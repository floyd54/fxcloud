use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::PathBuf;

use axum::body::{Body, Bytes};
use axum::extract::{Multipart, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::files::FileService;
use crate::models::{
    BatchIdsRequest, BatchOutcome, BatchTransferRequest, BlobRef, CreateFileRequest,
    CreateFolderRequest, FileEntry, RenameRequest, SetKeyRequest, TransferRequest, ZipRequest,
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
        // An empty file is always created plaintext: only a client-side
        // encrypt-on-save (a later phase) can put ciphertext behind a row it
        // also knows the wrapped key for.
        .create_file(user.id(), req.parent_id, req.name, 0, None, 0, None)
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
/// and no moving items across owners. An encrypted row arrives with its key
/// record already re-wrapped for its destination (ENCRYPTION.md 5.4), which
/// is why this route takes the caller-trusted door of `move_entry_rebound`
/// rather than the key-domain guard WebDAV runs.
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
        .move_entry_rebound(user.id(), req.id, req.dest_parent, entry.name)
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
///
/// The file part streams into a temp file (S1): memory stays flat however
/// large the upload is, the per-file limit is enforced while counting, and
/// the bytes reach the blob layout through a single rename once the row
/// exists.
pub async fn upload(
    State(state): State<SharedState>,
    user: AuthUser,
    multipart: Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut temp: Option<PathBuf> = None;
    let outcome = upload_parts(&state, user.id(), multipart, &mut temp).await;
    if outcome.is_err() {
        // Whatever sits in the temp file never became a blob: drop it.
        if let Some(path) = temp.take() {
            let _ = tokio::fs::remove_file(path).await;
        }
    }
    outcome
}

/// The body of [`upload`]. The temp file is handed in so the caller can
/// clean it up on every failing path with one rule, wherever the failure
/// happens.
async fn upload_parts(
    state: &SharedState,
    user_id: i64,
    mut multipart: Multipart,
    temp: &mut Option<PathBuf>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut parent_id: Option<i64> = None;
    let mut filename: Option<String> = None;
    let mut mime: Option<String> = None;
    // Client-side encryption, sent as two plain multipart fields: a version
    // (0 = plaintext, 1 = FXE1) and the entry's key wrapped with the parent
    // folder's key, base64. The server stores both without looking inside -
    // it cannot read either of them (ENCRYPTION.md 5.3/5.4).
    let mut enc_version: i64 = 0;
    let mut enc_key: Option<Vec<u8>> = None;
    // The sniffable head of the file, kept by the streaming write below: the
    // MIME decision (magic numbers, then the text heuristic) is made on it.
    let mut sample: Vec<u8> = Vec::new();
    let mut size: i64 = 0;

    while let Some(mut field) = multipart
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
            "enc_version" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("bad enc_version: {e}")))?;
                enc_version = text
                    .trim()
                    .parse()
                    .map_err(|_| AppError::BadRequest("bad enc_version".into()))?;
                if enc_version != 0 && enc_version != 1 {
                    return Err(AppError::BadRequest("unsupported enc_version".into()));
                }
            }
            "enc_key" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::BadRequest(format!("bad enc_key: {e}")))?;
                let text = text.trim();
                if !text.is_empty() {
                    enc_key =
                        Some(BASE64.decode(text).map_err(|_| {
                            AppError::BadRequest("enc_key is not valid base64".into())
                        })?);
                }
            }
            "file" => {
                filename = field.file_name().map(|s| s.to_string());
                mime = field
                    .content_type()
                    .map(|s| s.to_string());
                // A second file part would leave the first one's temp file
                // without an owner; only the last one wins, as before.
                if let Some(previous) = temp.take() {
                    let _ = tokio::fs::remove_file(previous).await;
                }
                let (path, written, head) = stream_field_to_temp(state, &mut field).await?;
                *temp = Some(path);
                size = written;
                sample = head;
            }
            _ => {}
        }
    }

    let filename = filename.ok_or_else(|| AppError::BadRequest("missing file".into()))?;
    let temp = temp
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("missing file data".into()))?;

    // Encrypted content needs its wrapped key, and must not claim a
    // content type the server will later serve as if it were the truth: the
    // bytes on disk are ciphertext (ENCRYPTION.md section 7).
    if enc_version > 0 {
        if enc_key.is_none() {
            return Err(AppError::BadRequest(
                "encrypted upload is missing enc_key".into(),
            ));
        }
        mime = None;
    } else if enc_key.is_some() {
        return Err(AppError::BadRequest(
            "enc_key given for a plaintext upload".into(),
        ));
    } else {
        // The client's Content-Type is a hint, not the truth: a browser
        // sends `application/octet-stream` (or nothing) for a file without
        // an extension, which is exactly the case where the stored type has
        // to decide later whether the row opens in the editor. The bytes
        // decide here - magic numbers first, then a text heuristic - both
        // on the sniffed head of the file (`sample`), and the client's word
        // only survives as the fallback for binary the sniffer does not
        // know (`resolve_mime`).
        mime = crate::files::resolve_mime(mime.as_deref(), &sample);
    }

    // Create metadata first to obtain a file id, then move the temp file
    // into the blob layout - the rename is what publishes the content.
    let entry = state
        .db
        .create_file(
            user_id,
            parent_id,
            filename,
            size,
            mime,
            enc_version,
            enc_key,
        )
        .await?;
    if let Err(e) = state.files.commit_blob(&entry, temp).await {
        // Roll back the orphaned metadata row.
        let _ = state.db.hard_delete_entry(user_id, entry.id).await;
        return Err(e);
    }

    Ok(Json(json!({ "entry": entry })))
}

/// Stream one multipart file field into a fresh temp file: the chunk loop is
/// the whole memory story of an upload (a 4 GiB body costs 64 KiB), the byte
/// count doubles as the per-file size limit, and the leading bytes are kept
/// for the MIME sniff. Every failure removes the temp file before returning.
async fn stream_field_to_temp(
    state: &SharedState,
    field: &mut axum::extract::multipart::Field<'_>,
) -> Result<(PathBuf, i64, Vec<u8>), AppError> {
    let path = state.files.temp_path();
    let mut file = tokio::fs::File::create(&path)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("creating temp upload {path:?}: {e}")))?;
    let mut sample = Vec::new();
    let mut size: i64 = 0;
    let pumped = async {
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|_| {
                // The body-limit layer refuses a body between the counted
                // cap and its framing headroom by erroring the stream - the
                // frame that crossed the line is dropped, not delivered, so
                // this error *is* the over-limit answer, not a parse
                // failure. A broken upload lands here too; the old buffered
                // path answered 413 for both, and every other write path in
                // this file still does.
                AppError::PayloadTooLarge(format!(
                    "file exceeds the upload limit of {} or was interrupted mid-stream",
                    human_size(state.config.max_upload_bytes as i64)
                ))
            })?
        {
            size += chunk.len() as i64;
            if size > state.config.max_upload_bytes as i64 {
                return Err(AppError::PayloadTooLarge(format!(
                    "file exceeds the upload limit of {}",
                    human_size(state.config.max_upload_bytes as i64)
                )));
            }
            // Only the head is kept: `resolve_mime` decides on it.
            let room = crate::files::SNIFF_WINDOW - sample.len();
            if room > 0 {
                let take = room.min(chunk.len());
                sample.extend_from_slice(&chunk[..take]);
            }
            file.write_all(&chunk).await.map_err(|e| {
                AppError::Internal(anyhow::anyhow!("writing temp upload {path:?}: {e}"))
            })?;
        }
        file.flush().await.map_err(|e| {
            AppError::Internal(anyhow::anyhow!("flushing temp upload {path:?}: {e}"))
        })?;
        Ok::<(), AppError>(())
    }
    .await;
    drop(file);
    if let Err(e) = pumped {
        let _ = tokio::fs::remove_file(&path).await;
        return Err(e);
    }
    Ok((path, size, sample))
}

/// GET /api/files/download?id=<id> – stream a file's content.
///
/// Byte ranges are honoured (206 / 416, `Accept-Ranges`) with the same
/// arithmetic the preview uses, so a player or `curl -r` seeks without the
/// whole file crossing the wire - and the body is read in 64 KiB chunks
/// either way (S1, `concepts/streaming.md`).
pub async fn download(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<IdQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (entry, file, len) = state.files.open_blob(user.id(), q.id).await?;

    // Encrypted rows never advertise a content type: the bytes on disk are an
    // FXE1 container, so `image/png` here would be a lie the browser acts on
    // (ENCRYPTION.md section 7 - the server's authoritative answer for
    // encrypted content is octet-stream, always).
    let content_type = if entry.enc_version > 0 {
        "application/octet-stream".to_string()
    } else {
        entry
            .mime
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string())
    };
    // RFC 5987 encoding so non-ASCII filenames survive the header.
    let encoded_name = encode_rfc5987(&entry.name);
    let disposition = format!("attachment; filename*=UTF-8''{encoded_name}");

    let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(value) => parse_byte_range(value, len as usize),
        None => ByteRange::Full,
    };
    let ranged = ranged_body(file, len as usize, range).await?;

    let mut builder = Response::builder()
        .status(ranged.status)
        .header(header::CONTENT_TYPE, &content_type)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CONTENT_LENGTH, ranged.content_len.to_string());
    if let Some(content_range) = ranged.content_range {
        builder = builder.header(header::CONTENT_RANGE, content_range);
    }
    let resp = builder
        .body(ranged.body)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("building download response: {e}")))?;
    Ok(resp.into_response())
}

/// Query of the version routes: one entry plus one row of its history.
#[derive(Deserialize)]
pub struct VersionQuery {
    pub id: i64,
    pub vid: i64,
}

/// GET /api/files/versions?id=<id> - the kept previous versions of one file,
/// newest first (READ, the same gate as a download: a share's reader sees the
/// history too, they hold the file key either way - concepts/versioning.md
/// decision 2).
pub async fn versions_list(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<IdQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let versions = state.db.list_versions(user.id(), q.id).await?;
    Ok(Json(json!({ "versions": versions })))
}

/// GET /api/files/version/download?id=&vid= - stream one kept version with
/// the same byte-range answers as the entry download (one helper for both, so
/// they cannot drift), and the encrypted/plaintext type rule of a save from
/// *its* time: `enc_version` of the version row, not of today's entry.
pub async fn version_download(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<VersionQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let entry = state
        .db
        .entry_for_read(user.id(), q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    if entry.is_dir {
        return Err(AppError::BadRequest("cannot download a folder".into()));
    }
    let version = state.db.version_for_read(user.id(), q.id, q.vid).await?;
    let path = state.files.version_path(q.id, &version.blob_key);
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| AppError::NotFound)?;
    let len = file
        .metadata()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("version metadata {path:?}: {e}")))?
        .len();

    let content_type = if version.enc_version > 0 {
        "application/octet-stream".to_string()
    } else {
        entry
            .mime
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_string())
    };
    let encoded_name = encode_rfc5987(&entry.name);
    let disposition = format!("attachment; filename*=UTF-8''{encoded_name}");

    let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(value) => parse_byte_range(value, len as usize),
        None => ByteRange::Full,
    };
    let ranged = ranged_body(file, len as usize, range).await?;

    let mut builder = Response::builder()
        .status(ranged.status)
        .header(header::CONTENT_TYPE, &content_type)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CONTENT_LENGTH, ranged.content_len.to_string());
    if let Some(content_range) = ranged.content_range {
        builder = builder.header(header::CONTENT_RANGE, content_range);
    }
    let resp = builder
        .body(ranged.body)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("building version download: {e}")))?;
    Ok(resp.into_response())
}

/// POST /api/files/version/restore?id=&vid= - exchange restore: the chosen
/// version becomes the entry's content and the outgoing content becomes the
/// newest version (UPDATE grant; the exchange itself is
/// `FileService::restore_version`).
pub async fn version_restore(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<VersionQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.files.restore_version(user.id(), q.id, q.vid).await?;
    // Fresh row for the response: size, enc_version and modified_at changed.
    let entry = state
        .db
        .entry_for_read(user.id(), q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(json!({ "entry": entry })))
}

/// DELETE /api/files/version?id=&vid= - drop one version row and the bytes
/// behind it (UPDATE; deleting a version deletes the bytes - delete means
/// delete, concepts/versioning.md section 8).
pub async fn version_delete(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<VersionQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let blob = state.db.delete_version(user.id(), q.id, q.vid).await?;
    state.files.delete_blobs(&[blob]).await;
    Ok(Json(json!({ "ok": true })))
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

/// An answered body with its range arithmetic resolved.
struct RangedBody {
    status: StatusCode,
    body: Body,
    content_range: Option<String>,
    content_len: u64,
}

/// Turn a parsed range into a streamed answer: seek + take for a slice, the
/// whole handle otherwise, `416` (with `bytes */len`) for a range outside the
/// file. Download and preview both go through it, so the two cannot drift
/// apart (S1, `concepts/streaming.md`).
async fn ranged_body(
    mut file: tokio::fs::File,
    len: usize,
    range: ByteRange,
) -> Result<RangedBody, AppError> {
    let (status, slice, content_range) = match range {
        ByteRange::Unsatisfiable => (
            StatusCode::RANGE_NOT_SATISFIABLE,
            None,
            Some(format!("bytes */{len}")),
        ),
        ByteRange::Slice(start, end) => (
            StatusCode::PARTIAL_CONTENT,
            Some((start as u64, (end - start + 1) as u64)),
            Some(format!("bytes {start}-{end}/{len}")),
        ),
        ByteRange::Full => (StatusCode::OK, None, None),
    };
    let (body, content_len) = match slice {
        // A 416 carries no body; its length is zero by definition.
        None if status == StatusCode::RANGE_NOT_SATISFIABLE => (Body::empty(), 0),
        None => (file_stream(file), len as u64),
        Some((offset, length)) => {
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("seeking blob: {e}")))?;
            (file_stream(file.take(length)), length)
        }
    };
    Ok(RangedBody {
        status,
        body,
        content_range,
        content_len,
    })
}

/// A response body that reads in 64 KiB chunks instead of buffering: a
/// 4 GiB download costs the same memory as a 4 KiB one, and a client that
/// hangs up mid-transfer just has its reader dropped. Used by the JSON
/// download, the preview and the WebDAV `GET`.
pub(crate) fn file_stream<R>(reader: R) -> Body
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    Body::from_stream(FileChunks {
        reader,
        buf: vec![0u8; 64 * 1024],
        done: false,
    })
}

/// The reads behind [`file_stream`].
///
/// A hand-rolled `Stream` instead of `futures_util::stream::unfold`:
/// hyper polls a body once more after its end (keep-alive bookkeeping), and
/// unfold answers that re-poll with a panic since futures-util 0.3.34 -
/// killing the connection right after its own last byte, which the client
/// sees as a truncated download. This one remembers that it is finished and
/// stays finished, so the extra poll costs a comparison.
struct FileChunks<R> {
    reader: R,
    buf: Vec<u8>,
    done: bool,
}

impl<R: tokio::io::AsyncRead + Unpin> futures_util::Stream for FileChunks<R> {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return std::task::Poll::Ready(None);
        }
        let filled = {
            let mut read_buf = tokio::io::ReadBuf::new(&mut this.buf);
            match std::pin::Pin::new(&mut this.reader).poll_read(cx, &mut read_buf) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => {
                    this.done = true;
                    return std::task::Poll::Ready(Some(Err(e)));
                }
                std::task::Poll::Ready(Ok(())) => read_buf.filled().len(),
            }
        };
        if filled == 0 {
            this.done = true;
            return std::task::Poll::Ready(None);
        }
        std::task::Poll::Ready(Some(Ok(Bytes::copy_from_slice(&this.buf[..filled]))))
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
    let (entry, file, len) = state.files.open_blob(user.id(), q.id).await?;
    // Encrypted rows are not previewable server-side: there is no plaintext
    // to serve, and answering `image/png` for ciphertext would hand the
    // browser bytes it cannot render. Inline preview of encrypted content is a
    // client-side decrypt-and-blob flow (phase 2); until then the UI offers
    // Download, which decrypts in the browser.
    if entry.enc_version > 0 {
        return Err(AppError::BadRequest(
            "this file is encrypted - download it to decrypt it in the browser".into(),
        ));
    }
    let content_type = preview_content_type(&entry).ok_or_else(|| {
        AppError::BadRequest(
            "this file type cannot be displayed in the browser - use Download".into(),
        )
    })?;
    let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(value) => parse_byte_range(value, len as usize),
        None => ByteRange::Full,
    };

    // RFC 5987 encoding so non-ASCII filenames survive the header.
    let encoded_name = encode_rfc5987(&entry.name);
    let disposition = format!("inline; filename*=UTF-8''{encoded_name}");

    // Streamed like the download, with the same range arithmetic (S1).
    let ranged = ranged_body(file, len as usize, range).await?;

    let mut builder = Response::builder()
        .status(ranged.status)
        .header(header::CONTENT_TYPE, &content_type)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        // Empty sandbox: renders without scripts (see the doc comment).
        .header("Content-Security-Policy", "sandbox")
        .header(header::CONTENT_LENGTH, ranged.content_len.to_string());
    if let Some(content_range) = ranged.content_range {
        builder = builder.header(header::CONTENT_RANGE, content_range);
    }
    let resp = builder
        .body(ranged.body)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("building preview response: {e}")))?;
    Ok(resp.into_response())
}

/// Query for `PUT /api/files/content`: the row plus the optional encryption
/// mode the caller wants to write it in.
///
/// `enc` is absent for the ordinary editor save, where the row's mode is left
/// exactly as it is. `enc=1` with `key` is the *only* way a plaintext row ever
/// becomes encrypted through this endpoint - the server never sniffs a
/// plaintext row, because arbitrary user files may legitimately begin with the
/// four magic bytes. On a row that is already encrypted the content is our own
/// format, so the magic check there is exact (ENCRYPTION.md 5.3).
#[derive(Deserialize)]
pub struct ContentQuery {
    pub id: i64,
    pub enc: Option<u8>,
    pub key: Option<String>,
}

/// PUT /api/files/content?id=<id> – overwrite a file's content with the raw
/// request body (the web editor's save path, and the second half of an
/// encrypted upload).
///
/// Permission (PERM_UPDATE), tree-owner resolution and the quota gate all
/// come from `update_file_meta`, the same path WebDAV PUT takes, so the
/// editor and sync clients cannot diverge.
///
/// The body streams into a temp file (S1) and lands in the blob layout by a
/// single rename - memory stays flat however large the save is.
pub async fn save_content(
    State(state): State<SharedState>,
    user: AuthUser,
    Query(q): Query<ContentQuery>,
    request: Request,
) -> Result<Json<serde_json::Value>, AppError> {
    let entry = state
        .db
        .entry_for_read(user.id(), q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    if entry.is_dir {
        return Err(AppError::BadRequest("cannot edit a folder".into()));
    }

    // The body streams into a temp file (S1): the FXE1 magic is read off the
    // head, the count doubles as the size limit, and nothing the checks below
    // reject is ever kept in memory.
    let (temp, sample, size) = stream_body_to_temp(
        &state,
        request.into_body(),
        state.config.max_upload_bytes as u64,
    )
    .await?;

    let outcome = save_streamed(&state, user.id(), &q, entry, temp.clone(), &sample, size).await;
    if outcome.is_err() {
        // The temp file only ever disappears by being renamed into place.
        let _ = tokio::fs::remove_file(&temp).await;
    }
    outcome
}

/// The byte-dependent half of [`save_content`]: the enc/`key` matrix, the
/// type decision, and the meta + blob commit under the row's write lock.
/// `temp` is consumed by the rename that publishes the content.
async fn save_streamed(
    state: &SharedState,
    user_id: i64,
    q: &ContentQuery,
    entry: FileEntry,
    temp: PathBuf,
    sample: &[u8],
    size: i64,
) -> Result<Json<serde_json::Value>, AppError> {
    let enc_version = q.enc.unwrap_or(entry.enc_version as u8);
    let transition = match (q.enc, &q.key) {
        (None, None) => {
            // Plain save: leave the mode alone.
            if entry.enc_version > 0 && !sample.starts_with(crate::files::FXE1_MAGIC) {
                return Err(AppError::Conflict(
                    "this file is encrypted; saving plaintext would destroy it - \
                     encrypt the content first (client-side save arrives with the \
                     editor round-trip)"
                        .into(),
                ));
            }
            None
        }
        (None, Some(_)) => {
            return Err(AppError::BadRequest("key requires enc=1".into()));
        }
        (Some(1), Some(key)) => {
            if !sample.starts_with(crate::files::FXE1_MAGIC) {
                return Err(AppError::Conflict(
                    "enc=1 declares encrypted content but the body is not an FXE1 \
                     container"
                        .into(),
                ));
            }
            let key = BASE64
                .decode(key.trim())
                .map_err(|_| AppError::BadRequest("key is not valid base64".into()))?;
            if key.is_empty() {
                return Err(AppError::BadRequest("key is empty".into()));
            }
            // A share's UPDATE grantee re-saves with the very record they
            // were handed: the file key does not change on overwrite
            // (DECISION 5), so the wrapper goes back verbatim and the owner
            // keeps being able to unwrap it. Only the row's owner may *swap*
            // that record - the server holds no key and cannot check the
            // wrapping, and a foreign one would leave the owner holding a
            // record nobody in their own tree can open (5.5).
            let same_record = entry.enc_key.as_ref().is_some_and(|current| {
                BASE64.decode(current.trim()).is_ok_and(|c| c == key)
            });
            if entry.owner_id != user_id && !same_record {
                return Err(AppError::ForbiddenDetail(
                    "only the row's owner may change its key record".into(),
                ));
            }
            Some((1i64, key))
        }
        (Some(1), None) => {
            return Err(AppError::BadRequest("enc=1 requires key".into()));
        }
        (Some(0), Some(_)) => {
            return Err(AppError::BadRequest("enc=0 cannot carry a key".into()));
        }
        (Some(0), None) => {
            if entry.enc_version > 0 {
                // The server holds no plaintext, so it can never produce a
                // plaintext body for this row.
                return Err(AppError::Conflict(
                    "an encrypted file cannot be turned back into plaintext here - \
                     download it, decrypt it client-side and upload it again"
                        .into(),
                ));
            }
            None
        }
        (Some(_), _) => {
            return Err(AppError::BadRequest("unsupported enc_version".into()));
        }
    };

    // For an encrypted row keep `mime` NULL: the stored type must not describe
    // bytes the server has never seen in plaintext. For a plaintext save the
    // bytes decide (`resolve_mime`), on the sniffed head of the body: the
    // editor's save is a write path like any other, and a file without an
    // extension would otherwise lose the sniffed `text/plain` on its first
    // save and drop out of the editor menu.
    let mime = if enc_version > 0 {
        None
    } else {
        crate::files::resolve_mime(
            mime_guess::from_path(&entry.name)
                .first()
                .map(|m| m.to_string())
                .as_deref(),
            sample,
        )
    };
    // The blob path is id-derived, so replacing the content in place swaps
    // the blob underneath; meta first, because it holds the quota gate. Both
    // halves run under the row's write lock: two saves of this row landing at
    // once must not interleave, or the row ends up with one save's `enc_key`
    // next to another save's bytes (see `FileService::begin_replace`). The
    // commit itself is the temp file's rename, so the pair stays atomic and
    // no byte is copied twice.
    {
        let _write = state.files.begin_replace(entry.id).await;
        let pins_old = entry.size > 0;
        state
            .db
            .update_file_meta(user_id, entry.id, size, mime, transition, pins_old)
            .await?;
        // History (concepts/versioning.md): the outgoing bytes get their
        // version name while they are still the entry's content - link,
        // then row - and the rename below then publishes the new content
        // over a name nothing else points at yet. Nothing is copied either
        // way; with the row already checked, this order also keeps the
        // quota gate's arithmetic (growth = incoming size) exact.
        state.files.pin_content_as_version(user_id, &entry).await?;
        state.files.commit_blob(&entry, &temp).await?;
    }
    // Fresh row for the response: size and modified_at just changed.
    let entry = state
        .db
        .entry_for_read(user_id, q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(json!({ "entry": entry })))
}

/// Stream a request body into a fresh temp file, counting bytes: the limit
/// is a number, not a buffer (S1). Returns the temp path, the sniffable head
/// and the size. On any failure - over the limit, a broken stream, disk
/// trouble - the temp file is removed before the error is returned.
pub(crate) async fn stream_body_to_temp(
    state: &SharedState,
    body: axum::body::Body,
    cap: u64,
) -> Result<(PathBuf, Vec<u8>, i64), AppError> {
    let path = state.files.temp_path();
    let mut file = tokio::fs::File::create(&path)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("creating temp body {path:?}: {e}")))?;
    let mut sample = Vec::new();
    let mut size: i64 = 0;
    let mut stream = body.into_data_stream();
    let pumped = async {
        while let Some(chunk) = stream.next().await {
            // The body-limit layer refuses over-cap reads with a stream
            // error; that answers as 413 here, the way the old buffered
            // paths answered it.
            let chunk = chunk.map_err(|_| {
                AppError::PayloadTooLarge(format!(
                    "body exceeds the limit of {} or was interrupted mid-stream",
                    human_size(cap as i64)
                ))
            })?;
            size += chunk.len() as i64;
            if size as u64 > cap {
                return Err(AppError::PayloadTooLarge(format!(
                    "body exceeds the limit of {}",
                    human_size(cap as i64)
                )));
            }
            // Only the head is kept: `resolve_mime` and the FXE1 magic
            // decide on it.
            let room = crate::files::SNIFF_WINDOW - sample.len();
            if room > 0 {
                let take = room.min(chunk.len());
                sample.extend_from_slice(&chunk[..take]);
            }
            file.write_all(&chunk).await.map_err(|e| {
                AppError::Internal(anyhow::anyhow!("writing temp body {path:?}: {e}"))
            })?;
        }
        file.flush().await.map_err(|e| {
            AppError::Internal(anyhow::anyhow!("flushing temp body {path:?}: {e}"))
        })?;
        Ok::<(), AppError>(())
    }
    .await;
    drop(file);
    if let Err(e) = pumped {
        let _ = tokio::fs::remove_file(&path).await;
        return Err(e);
    }
    Ok((path, sample, size))
}

/// PUT /api/files/key – store a row's key record, leaving its bytes alone.
///
/// Two callers change a record and nothing else (5.5): a folder gaining its
/// key on the first encrypted write below it, and the re-binding a move or
/// the share-time migration performs on a row that already has one. Going
/// through `/files/content` for that would mean re-uploading ciphertext just
/// to swap a 32-byte wrapper, so it gets its own door - gated on PERM_UPDATE,
/// the same mask the content write asks for (crypto mirrors the API
/// permission), and a plaintext file has no record to replace. Replacing a
/// record that already exists is the owner's move alone (`Db::set_enc_key`
/// draws the same line `save_content` draws on its key field): the wrapper
/// is opaque to the server, so a grantee's replacement of a keyed row's
/// record is indistinguishable from the sabotage it usually is.
pub async fn put_key(
    State(state): State<SharedState>,
    user: AuthUser,
    Json(req): Json<SetKeyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let key = BASE64
        .decode(req.key.trim())
        .map_err(|_| AppError::BadRequest("key is not valid base64".into()))?;
    let entry = state.db.set_enc_key(user.id(), req.id, key).await?;
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
                out.failure(id, name, e);
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
/// name-collision guards), applied per item - including the caller-trusted
/// door for encrypted rows (ENCRYPTION.md 5.4): app.js re-binds each keyed
/// row to the destination before this request and rolls the record back for
/// every item the server did not move.
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
                .move_entry_rebound(user.id(), id, req.dest_parent, entry.name)
                .await?;
            Ok::<(), AppError>(())
        }
        .await;

        match result {
            Ok(()) => out.success(id),
            Err(e) => {
                let name = entry_name(&state, user.id(), id).await;
                out.failure(id, name, e);
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
                out.failure(id, name, e);
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
            // The server ZIP writes plaintext members. Packing ciphertext
            // under a `.png` name would hand back a file nothing can open, so
            // the archive refuses the selection instead of quietly degrading:
            // zipping encrypted content is a client-side job (DECISION 8).
            if entry.enc_version > 0 {
                return Err(AppError::BadRequest(format!(
                    "\"{}\" is encrypted - download encrypted items one by one, \
                     or unselect them to zip the rest",
                    entry.name
                )));
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

    // The archive is assembled on the blocking pool into a temp file (S1):
    // `ZipWriter` must be able to seek - it patches its headers and lays down
    // a central directory - so it cannot write into a pipe; a temp file
    // gives it a seekable sink while memory stays flat: a 1 GiB selection
    // costs kilobytes of RAM instead of a gigabyte, plus one temporary file
    // on disk. The name ends in `.part`, so a crash mid-build is swept at
    // the next startup, and a failed build removes it right here.
    let temp = state.files.temp_path();
    let build_path = temp.clone();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::create(&build_path).map_err(|e| {
            AppError::Internal(anyhow::anyhow!("creating temp zip {build_path:?}: {e}"))
        })?;
        let result = build_zip(&builder_state, trees, &mut file);
        drop(file);
        if result.is_err() {
            let _ = std::fs::remove_file(&build_path);
        }
        result
    })
    .await
    .map_err(|_| AppError::Join)??;

    // Reopen the finished archive and unlink it immediately: the open handle
    // keeps the inode alive, so the download runs from an unnamed file and a
    // client that hangs up mid-transfer leaves nothing on disk.
    let file = match tokio::fs::File::open(&temp).await {
        Ok(file) => file,
        Err(e) => {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(AppError::Internal(anyhow::anyhow!(
                "reopening temp zip {temp:?}: {e}"
            )));
        }
    };
    let _ = tokio::fs::remove_file(&temp).await;
    let len = file
        .metadata()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("stat temp zip {temp:?}: {e}")))?
        .len();

    // RFC 5987 encoding so non-ASCII names survive the header. The size is
    // known - the file exists - so the response carries a Content-Length and
    // streams out in 64 KiB chunks like every other content path.
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
            len.to_string().parse::<header::HeaderValue>().unwrap(),
        ),
        (
            header::X_CONTENT_TYPE_OPTIONS,
            "nosniff".parse::<header::HeaderValue>().unwrap(),
        ),
    ];
    Ok((StatusCode::OK, headers, file_stream(file)).into_response())
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
/// Runs on the blocking pool: the zip crate writes synchronously, blobs are
/// read off disk in 64 KiB chunks, and the finished bytes go to `writer` - a
/// temp file (`ZipWriter` needs `Seek` for its headers and central
/// directory), so not even the selection's size is ever held in memory (S1).
/// Content that disappeared mid-download is skipped and listed in
/// `fxcloud-skipped.txt` inside the archive instead of failing the whole
/// selection.
fn build_zip(
    state: &SharedState,
    trees: Vec<Vec<(String, FileEntry)>>,
    writer: &mut (impl std::io::Write + std::io::Seek),
) -> Result<(), AppError> {
    let mut writer = zip::ZipWriter::new(writer);
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

    writer.finish().map_err(zip_error)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::encode_rfc5987;

    /// Inverse of [`encode_rfc5987`], used to prove the encoding round-trips
    /// rather than to compare it against another encoder that could share the
    /// same mistake.
    fn decode(input: &str) -> Vec<u8> {
        let raw = input.as_bytes();
        let mut out = Vec::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%' && i + 2 < raw.len() {
                let hex = std::str::from_utf8(&raw[i + 1..i + 3]).expect("hex digits");
                out.push(u8::from_str_radix(hex, 16).expect("valid hex escape"));
                i += 3;
            } else {
                out.push(raw[i]);
                i += 1;
            }
        }
        out
    }

    #[test]
    fn unreserved_characters_stay_as_they_are() {
        assert_eq!(encode_rfc5987("abcXYZ019-._~"), "abcXYZ019-._~");
        assert_eq!(encode_rfc5987(""), "");
    }

    #[test]
    fn everything_else_is_percent_encoded() {
        // Space must not survive as a literal or become '+', which a browser
        // would read as a space in some contexts and as '+' in others.
        assert_eq!(encode_rfc5987("two words.txt"), "two%20words.txt");
        assert_eq!(encode_rfc5987("a+b"), "a%2Bb");
        assert_eq!(encode_rfc5987("a&b=c"), "a%26b%3Dc");
        // An already-encoded name must be re-encoded, not silently accepted.
        assert_eq!(encode_rfc5987("100%"), "100%25");
        assert_eq!(encode_rfc5987("#anchor"), "%23anchor");
        assert_eq!(encode_rfc5987("\u{00fc}"), "%C3%BC");
    }

    #[test]
    fn non_ascii_is_encoded_one_utf8_byte_at_a_time() {
        assert_eq!(encode_rfc5987("\u{00e9}"), "%C3%A9");
        assert_eq!(encode_rfc5987("\u{65e5}\u{672c}"), "%E6%97%A5%E6%9C%AC");
        assert_eq!(encode_rfc5987("\u{1f512}"), "%F0%9F%94%92");
    }

    #[test]
    fn the_encoding_round_trips_to_the_original_bytes() {
        for original in [
            "plain.txt",
            "two words.tar.gz",
            "\u{dc}n\u{ef}c\u{f6}d\u{e9} (1) [final].txt",
            "100% \u{65e5}\u{672c}\u{8a9e}/v2 + &.csv",
        ] {
            assert_eq!(
                decode(&encode_rfc5987(original)),
                original.as_bytes(),
                "{original}"
            );
        }
    }
}
