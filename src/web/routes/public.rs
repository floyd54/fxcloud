use std::net::SocketAddr;
use std::path::PathBuf;

use axum::extract::{ConnectInfo, Multipart, Path, Query, State};
use axum::http::{header, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::db::link::{hash_link_token, LinkState};
use crate::error::AppError;
use crate::models::PublicLink;
use crate::sharing::{grants, perm_names, PERM_CREATE, PERM_DELETE, PERM_READ};
use crate::web::state::SharedState;

use super::files::{file_stream, stream_field_to_temp};

/// One entry id, as the visitor names it.
#[derive(Deserialize)]
pub struct IdQuery {
    pub id: i64,
}

/// The embedded visitor page (concepts/public_links.md section 7).
///
/// Served straight from the binary with `include_str!` rather than a second
/// `RustEmbed` folder, so `ui.rs` and the app's own asset pipeline stay
/// untouched. The token in the path is *not* validated here: the page is a
/// static shell whose script resolves the link through `/api/public/…/meta`,
/// which is where the miss/hit budgets and the 404/410 answers live. Serving
/// the same HTML for a garbage token reveals nothing - it carries no secrets
/// and the very next request is the one that tells the truth.
pub async fn visitor_page(Path(_token): Path<String>) -> Result<Response, AppError> {
    let html = include_str!("../../../frontend/visitor.html");
    let mut response = Html(html).into_response();
    visitor_headers(&mut response);
    Ok(response)
}

/// Headers every visitor response carries (section 7).
///
/// * `no-referrer` - a stranger's visit must not leak the link URL to
///   whatever the page might reference.
/// * `no-store` - the link content is not the browser's to cache on a shared
///   machine.
/// * `noindex` - search engines are told to drop the URL; a bearer token in
///   a path is exactly the kind of thing that must not be crawled.
///
/// The baseline middleware already added `nosniff`/`CSP`/`X-Frame-Options`;
/// these only add what the visitor surface specifically needs, and the
/// middleware's `or_insert` leaves anything set here alone.
fn visitor_headers(response: &mut Response) {
    let h = response.headers_mut();
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-robots-tag", HeaderValue::from_static("noindex"));
}

/// Resolve a visitor's token into its live link, applying both budgets
/// (section 8.3).
///
/// The miss gate runs **before** the lookup so a spent guessing budget never
/// reaches the database; a failed resolution is then counted against the
/// source. A live link passes through the hit gate, which charges before any
/// expensive work happens - so even a bearer token that leaked cannot drive
/// unbounded reads.
async fn resolve_visitor(
    state: &SharedState,
    source: &str,
    token: &str,
) -> Result<PublicLink, AppError> {
    state.public_miss_gate(source)?;
    let hash = hash_link_token(token);
    match state.db.resolve_public_link(hash).await? {
        LinkState::Active(link) => {
            state.public_hit_gate(source)?;
            Ok(link)
        }
        LinkState::Expired => {
            state.public_missed(source);
            Err(AppError::Gone)
        }
        LinkState::Unknown => {
            state.public_missed(source);
            Err(AppError::NotFound)
        }
    }
}

/// GET /api/public/:token/meta - what the visitor may do, and what with it.
///
/// Served to any preset: even an add-only visitor (no READ) needs the folder
/// name to know where they are dropping a file. No listing, no bytes.
pub async fn meta(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    let source = addr.ip().to_string();
    let link = resolve_visitor(&state, &source, &token).await?;
    // Any successful visit keeps a rolling link alive (section 3).
    state.db.touch_public_link(link.id, false).await?;

    let response = Json(json!({
        "id": link.source_id,
        "name": link.source_name,
        "is_dir": link.is_dir,
        "permissions": link.permissions,
        "permission_names": perm_names(link.permissions),
        "can_read": grants(link.permissions, PERM_READ),
        "can_create": grants(link.permissions, PERM_CREATE),
        "can_delete": grants(link.permissions, PERM_DELETE),
        "label": link.label,
        "expiry_mode": link.expiry_mode,
        "expires_at": link.expires_at,
    }));
    let mut resp = response.into_response();
    visitor_headers(&mut resp);
    Ok(resp)
}

/// GET /api/public/:token/list[?id=N] - one folder's plaintext children.
///
/// `id` defaults to the link's source. Encrypted children are filtered out
/// of the query itself (section 5): their names never leave the server. A
/// visitor without READ (the `add` preset) gets 403 - they can upload but
/// not look around.
pub async fn list(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Query(q): Query<IdQuery>,
) -> Result<Response, AppError> {
    let source = addr.ip().to_string();
    let link = resolve_visitor(&state, &source, &token).await?;
    if !grants(link.permissions, PERM_READ) {
        return Err(AppError::Forbidden);
    }
    // The requested folder must sit inside the link's subtree.
    let parent = state
        .db
        .public_entry_in_subtree(link.source_id, q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !parent.is_dir {
        return Err(AppError::BadRequest("not a folder".into()));
    }
    let entries = state
        .db
        .public_list_children(link.owner_id, parent.id)
        .await?;
    state.db.touch_public_link(link.id, false).await?;

    let response = Json(json!({
        "id": parent.id,
        "name": parent.name,
        "entries": entries.iter().map(|e| json!({
            "id": e.id,
            "name": e.name,
            "is_dir": e.is_dir,
            "size": e.size,
            "mime": e.mime,
            "modified_at": e.modified_at,
        })).collect::<Vec<_>>(),
    }));
    let mut resp = response.into_response();
    visitor_headers(&mut resp);
    Ok(resp)
}

/// GET /api/public/:token/download?id= - stream one plaintext file.
///
/// Attachment-only, whole-file (no byte ranges on the public surface, a v1
/// simplification: the visitor's browser downloads it in one pass). The
/// bytes are opened as the **owner**, who always may read their own file;
/// the containment walk already proved the id belongs to the link, and the
/// plaintext filter proved it is not ciphertext a stranger should see.
pub async fn download(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Query(q): Query<IdQuery>,
) -> Result<Response, AppError> {
    let source = addr.ip().to_string();
    let link = resolve_visitor(&state, &source, &token).await?;
    if !grants(link.permissions, PERM_READ) {
        return Err(AppError::Forbidden);
    }
    // Containment first: never open a blob outside the linked subtree.
    let entry = state
        .db
        .public_entry_in_subtree(link.source_id, q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    if entry.is_dir {
        return Err(AppError::BadRequest("cannot download a folder".into()));
    }
    if entry.enc_version > 0 {
        // Encrypted children are invisible; a guessed id must not leak them.
        return Err(AppError::NotFound);
    }

    let (entry, file, _len) = state.files.open_blob(link.owner_id, q.id).await?;
    // A successful open is the 2xx: count it and slide a rolling link.
    state.db.touch_public_link(link.id, true).await?;

    let encoded_name = encode_rfc5987(&entry.name);
    let disposition = format!("attachment; filename*=UTF-8''{encoded_name}");
    let content_type = entry
        .mime
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let mut response = Response::new(file_stream(file));
    {
        let h = response.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            content_type
                .parse()
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        );
        h.insert(
            header::CONTENT_DISPOSITION,
            disposition
                .parse()
                .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
        );
        h.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
    }
    visitor_headers(&mut response);
    Ok(response)
}

/// POST /api/public/:token/upload - multipart drop into the link's folder.
///
/// Plaintext-only (v1): the visitor's bytes land as an ordinary file in the
/// owner's tree, so the owner sees them like any other upload. The parent
/// defaults to the link's source folder; a deeper folder is allowed only
/// when it sits inside the subtree *and* the visitor holds READ (the `add`
/// preset cannot navigate, so it cannot redirect its own uploads either).
pub async fn upload(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let source = addr.ip().to_string();
    let link = resolve_visitor(&state, &source, &token).await?;
    if !grants(link.permissions, PERM_CREATE) {
        return Err(AppError::Forbidden);
    }
    // Writes get their own, slower budget (100/hour) on top of the hit line.
    state.public_upload_gate(&source)?;

    let mut parent_id: Option<i64> = None;
    let mut filename: Option<String> = None;
    let mut mime: Option<String> = None;
    let mut temp: Option<PathBuf> = None;
    let mut sample: Vec<u8> = Vec::new();
    let mut size: i64 = 0;

    let outcome: Result<(), AppError> = async {
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
                "file" => {
                    filename = field.file_name().map(|s| s.to_string());
                    mime = field.content_type().map(|s| s.to_string());
                    if let Some(previous) = temp.take() {
                        let _ = tokio::fs::remove_file(previous).await;
                    }
                    let (path, written, head) = stream_field_to_temp(&state, &mut field).await?;
                    temp = Some(path);
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

        // The parent must be a folder inside the link's subtree. `add`-only
        // visitors (no READ) are pinned to the source folder itself.
        let parent = parent_id.unwrap_or(link.source_id);
        let parent_entry = state
            .db
            .public_entry_in_subtree(link.source_id, parent)
            .await?
            .ok_or(AppError::NotFound)?;
        if !parent_entry.is_dir {
            return Err(AppError::BadRequest("uploads go into a folder".into()));
        }
        if parent != link.source_id && !grants(link.permissions, PERM_READ) {
            return Err(AppError::Forbidden);
        }

        let mime = crate::files::resolve_mime(mime.as_deref(), &sample);
        let entry = state
            .db
            .create_file(
                link.owner_id,
                Some(parent),
                None,
                filename,
                size,
                mime,
                0,
                None,
            )
            .await?;
        if let Err(e) = state.files.commit_blob(&entry, temp).await {
            // Roll back the orphaned metadata row.
            let _ = state.db.hard_delete_entry(link.owner_id, entry.id).await;
            return Err(e);
        }
        Ok(())
    }
    .await;

    if let Some(path) = temp.take() {
        // On success `commit_blob` renamed it away; on failure it is garbage.
        let _ = tokio::fs::remove_file(path).await;
    }
    outcome?;

    state.db.touch_public_link(link.id, false).await?;
    let response = Json(json!({ "ok": true }));
    let mut resp = response.into_response();
    visitor_headers(&mut resp);
    Ok(resp)
}

/// DELETE /api/public/:token/entry?id= - move one entry to the **owner's**
/// trash (section 7).
///
/// The visitor never destroys anything: the row is marked trashed in the
/// owner's tree, restorable from their trash exactly like their own delete.
/// The shared root itself is protected - a stranger with a `full` link may
/// clear out files, but not trash the very folder the link points at (which
/// would also break the link for everyone else).
pub async fn delete_entry(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Query(q): Query<IdQuery>,
) -> Result<Response, AppError> {
    let source = addr.ip().to_string();
    let link = resolve_visitor(&state, &source, &token).await?;
    if !grants(link.permissions, PERM_DELETE) {
        return Err(AppError::Forbidden);
    }
    let entry = state
        .db
        .public_entry_in_subtree(link.source_id, q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    if entry.id == link.source_id {
        return Err(AppError::BadRequest(
            "the shared folder itself cannot be removed".into(),
        ));
    }
    // `trash_entry` resolves the principal as the owner, so this lands in
    // *their* trash - the visitor's delete is the owner's restoreable one.
    state.db.trash_entry(link.owner_id, entry.id).await?;
    state.db.touch_public_link(link.id, false).await?;

    let response = Json(json!({ "ok": true }));
    let mut resp = response.into_response();
    visitor_headers(&mut resp);
    Ok(resp)
}

/// RFC 5987 encoding for the `filename*` parameter, so a non-ASCII name
/// survives the header. A local copy of the same pure function in
/// `files.rs` (kept here to leave that never-rustfmt file untouched); the
/// test suite round-trips it to prove the two agree by behaviour, not by
/// sharing a body that could drift.
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

    /// The inverse of the encoder, proving a round-trip rather than comparing
    /// against another encoder that could share the same mistake.
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
    fn rfc5987_round_trips_non_ascii_names() {
        let name = "Grüße_ünïcødé.txt";
        let enc = encode_rfc5987(name);
        assert!(
            enc.is_ascii(),
            "the encoded form must be pure ASCII for the header: {enc}"
        );
        assert_eq!(decode(&enc), name.as_bytes());
    }

    #[test]
    fn rfc5987_leaves_unreserved_bytes_alone() {
        assert_eq!(encode_rfc5987("aZ09-._~"), "aZ09-._~");
        // Space and slash must be escaped, never literal in the header.
        assert_eq!(encode_rfc5987(" "), "%20");
        assert_eq!(encode_rfc5987("/"), "%2F");
    }
}
