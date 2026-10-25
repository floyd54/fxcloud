//! WebDAV endpoint so real sync clients (Nextcloud desktop, rclone, Cyberduck,
//! Windows "Map network drive") can mount a user's fxcloud files.
//!
//! Mounted at `/dav/` and authenticated via HTTP Basic auth. The path after
//! `/dav/` is relative to the authenticated user's home.

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};

use crate::auth::authenticate_basic;
use crate::db::session::generate_token;
use crate::error::AppError;
use crate::models::FileEntry;
use crate::web::state::SharedState;

/// Endpoint prefix stripped from incoming request paths.
const DAV_PREFIX: &str = "/dav";

/// Maximum body accepted for a WebDAV `PUT` (4 GiB).
const MAX_PUT_BYTES: usize = 4 * 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Route every WebDAV request here. Dispatches on the HTTP method.
pub async fn dispatch(State(state): State<SharedState>, req: Request) -> Response {
    let user = match authenticate_basic(&state, req.headers()).await {
        Ok(u) => u,
        // Credentials are right but the account is switched off: answer 403
        // instead of 401 so clients don't keep re-prompting for a password.
        Err(AppError::InactiveAccount) => return inactive_account(),
        Err(_) => return unauthorized(),
    };
    let owner_id = user.id;
    let method = req.method().as_str().to_owned();
    let segments = parse_segments(req.uri().path());

    match method.as_str() {
        "OPTIONS" => options(),
        "PROPFIND" => propfind(&state, owner_id, &segments, req.headers()).await,
        "GET" => serve_file(&state, owner_id, &segments, false).await,
        "HEAD" => serve_file(&state, owner_id, &segments, true).await,
        "PUT" => put_file(&state, owner_id, &segments, req).await,
        "DELETE" => delete_resource(&state, owner_id, &segments).await,
        "MKCOL" => mkcol(&state, owner_id, &segments).await,
        "MOVE" => move_resource(&state, owner_id, &segments, req.headers()).await,
        "COPY" => copy_resource(&state, owner_id, &segments, req.headers()).await,
        "LOCK" => lock(),
        "UNLOCK" => StatusCode::NO_CONTENT.into_response(),
        _ => method_not_allowed(),
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Strip the `/dav` prefix and split the remaining path into decoded segments.
fn parse_segments(path: &str) -> Vec<String> {
    path.strip_prefix(DAV_PREFIX)
        .unwrap_or(path)
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| percent_decode_str(s).decode_utf8_lossy().into_owned())
        .collect()
}

fn encode_segment(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Build the absolute DAV href for a path (collections get a trailing slash).
fn build_href(segments: &[String], is_dir: bool) -> String {
    let mut href = String::from(DAV_PREFIX);
    if segments.is_empty() {
        href.push('/');
    } else {
        for seg in segments {
            href.push('/');
            href.push_str(&encode_segment(seg));
        }
        if is_dir {
            href.push('/');
        }
    }
    href
}

/// A resolved request target: either the user's virtual root or a real entry.
///
/// Entries carry the viewer's permission mask, so every operation can check
/// its required bit before acting.
enum Target {
    Root,
    Entry(FileEntry),
}

impl Target {
    fn permissions(&self) -> i64 {
        match self {
            Target::Root => crate::sharing::PERM_ALL, // the root is always yours
            Target::Entry(e) => e.permissions,
        }
    }
}

/// Enforce that a target grants `required` (permission bitmask).
fn require(target: &Target, required: i64) -> Result<(), Response> {
    if crate::sharing::grants(target.permissions(), required) {
        Ok(())
    } else {
        Err(forbidden())
    }
}

async fn resolve(
    state: &SharedState,
    owner_id: i64,
    segments: &[String],
) -> Result<Target, Response> {
    if segments.is_empty() {
        return Ok(Target::Root);
    }
    match state.db.resolve_path(owner_id, segments.to_vec()).await {
        Ok(Some(e)) => Ok(Target::Entry(e)),
        Ok(None) => Err(not_found()),
        Err(e) => Err(e.into_response()),
    }
}

/// A resolved *parent* directory for a create/move/copy operation: the virtual
/// root (no id) or a collection entry carrying the viewer's permissions.
struct ParentTarget {
    id: Option<i64>,
    permissions: i64,
}

/// Resolve a *parent* directory path for a create/move/copy operation.
///
/// Unlike [`resolve`], a missing intermediate returns `409 Conflict` (per
/// RFC 4918) instead of `404`, as does a path that is not a directory.
async fn resolve_parent(
    state: &SharedState,
    owner_id: i64,
    segments: &[String],
) -> Result<ParentTarget, Response> {
    if segments.is_empty() {
        // The virtual root belongs to the requester.
        return Ok(ParentTarget { id: None, permissions: crate::sharing::PERM_ALL });
    }
    match state.db.resolve_path(owner_id, segments.to_vec()).await {
        Ok(Some(e)) => {
            if e.is_dir {
                Ok(ParentTarget { id: Some(e.id), permissions: e.permissions })
            } else {
                Err(conflict())
            }
        }
        Ok(None) => Err(conflict()),
        Err(e) => Err(e.into_response()),
    }
}

// ---------------------------------------------------------------------------
// PROPFIND
// ---------------------------------------------------------------------------

enum Depth {
    Zero,
    One,
    Infinity,
}

fn parse_depth(headers: &HeaderMap) -> Depth {
    match headers.get("Depth").and_then(|v| v.to_str().ok()) {
        Some("0") => Depth::Zero,
        Some("1") => Depth::One,
        _ => Depth::Infinity, // RFC 4918 default
    }
}

async fn propfind(
    state: &SharedState,
    owner_id: i64,
    segments: &[String],
    headers: &HeaderMap,
) -> Response {
    let target = match resolve(state, owner_id, segments).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) = require(&target, crate::sharing::PERM_READ) {
        return r;
    }
    let depth = parse_depth(headers);

    let mut resources: Vec<Resource> = Vec::new();
    let (list_parent, base_segments): (Option<i64>, Vec<String>) = match &target {
        Target::Root => {
            resources.push(Resource::root());
            (None, segments.to_vec())
        }
        Target::Entry(e) => {
            resources.push(Resource::from_entry(segments, e));
            (Some(e.id), segments.to_vec())
        }
    };

    match depth {
        Depth::Zero => {}
        Depth::One => {
            match state.db.list_children(owner_id, list_parent).await {
                Ok(children) => {
                    for c in children {
                        let mut cs = base_segments.clone();
                        cs.push(c.name.clone());
                        resources.push(Resource::from_entry(&cs, &c));
                    }
                }
                Err(e) => return e.into_response(),
            }
        }
        Depth::Infinity => {
            // Iterative BFS over every descendant.
            let mut queue: Vec<(Vec<String>, Option<i64>)> = vec![(base_segments, list_parent)];
            while let Some((path, parent)) = queue.pop() {
                match state.db.list_children(owner_id, parent).await {
                    Ok(children) => {
                        for c in children {
                            let mut cs = path.clone();
                            cs.push(c.name.clone());
                            let (is_dir, cid) = (c.is_dir, c.id);
                            resources.push(Resource::from_entry(&cs, &c));
                            if is_dir {
                                queue.push((cs, Some(cid)));
                            }
                        }
                    }
                    Err(e) => return e.into_response(),
                }
            }
        }
    }

    multistatus(multistatus_xml(&resources))
}

// ---------------------------------------------------------------------------
// GET / HEAD
// ---------------------------------------------------------------------------

async fn serve_file(
    state: &SharedState,
    owner_id: i64,
    segments: &[String],
    head_only: bool,
) -> Response {
    let target = match resolve(state, owner_id, segments).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let entry = match target {
        Target::Root => return method_not_allowed(),
        Target::Entry(e) => e,
    };
    if entry.is_dir {
        return method_not_allowed();
    }
    if !crate::sharing::grants(entry.permissions, crate::sharing::PERM_READ) {
        return forbidden();
    }

    match state.files.read_blob(owner_id, entry.id).await {
        Ok((e, data)) => {
            // Encrypted rows are exposed as opaque ciphertext: same branch the
            // JSON download takes, so a dumb client sees one consistent,
            // self-describing content type instead of a guessed one.
            let content_type = if e.enc_version > 0 {
                "application/octet-stream".to_string()
            } else {
                e.mime
                    .clone()
                    .unwrap_or_else(|| "application/octet-stream".to_string())
            };
            let etag = format!("\"{}-{}-{}\"", e.id, e.size, e.modified_at.timestamp());
            let builder = Response::builder()
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, data.len())
                .header(header::ETAG, etag)
                .header(header::LAST_MODIFIED, http_date(&e.modified_at));
            let result = if head_only {
                builder.body(Body::empty())
            } else {
                builder.body(Body::from(data))
            };
            result.unwrap_or_else(|_| internal())
        }
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT
// ---------------------------------------------------------------------------

fn overwrite_allowed(headers: &HeaderMap) -> bool {
    // RFC 4918: default is "T"; only an explicit "F" blocks overwrite.
    !matches!(
        headers.get("Overwrite").and_then(|v| v.to_str().ok()),
        Some(v) if v.eq_ignore_ascii_case("F")
    )
}

async fn put_file(
    state: &SharedState,
    owner_id: i64,
    segments: &[String],
    req: Request,
) -> Response {
    if segments.is_empty() {
        return method_not_allowed(); // cannot PUT the root
    }
    let name = segments.last().unwrap().clone();
    let parent_segments = &segments[..segments.len() - 1];

    // Parent must be a directory (root is allowed); a missing one is 409.
    let parent = match resolve_parent(state, owner_id, parent_segments).await {
        Ok(p) => p,
        Err(r) => return r,
    };

    let overwrite = overwrite_allowed(req.headers());
    let body = match to_bytes(req.into_body(), MAX_PUT_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large").into_response()
        }
    };
    let size = body.len() as i64;
    let mime = mime_guess::from_path(&name).first().map(|m| m.to_string());

    let existing = match state.db.resolve_path(owner_id, segments.to_vec()).await {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    match existing {
        Some(old) if old.is_dir => method_not_allowed(),
        Some(old) => {
            // Overwrite in place (the blob path is derived from the id, so it
            // is replaced).
            if !overwrite {
                return precondition();
            }
            if !crate::sharing::grants(old.permissions, crate::sharing::PERM_UPDATE) {
                return forbidden();
            }
            // A row the client encrypted carries a wrapped key the server
            // cannot read, so it only ever accepts a body it can *recognise*
            // as another FXE1 container - a desktop client's plaintext would
            // otherwise overwrite ciphertext the server cannot produce again.
            // Validating that magic first is what keeps DAV from silently
            // destroying encrypted files (ENCRYPTION.md 5.4, DECISION 9:
            // never blind). The row's `enc_key` is untouched, so the writer
            // must be whoever holds the file key - same contract the editor
            // save path takes (DECISION 5: no rotation on overwrite).
            if old.enc_version > 0 && !body.starts_with(crate::files::FXE1_MAGIC) {
                return (
                    StatusCode::CONFLICT,
                    "Encrypted file: this row only accepts an FXE1 container. A \
                     desktop client cannot produce one - write through the web \
                     client, or use the fxcloud sync agent.",
                )
                    .into_response();
            }
            // No magic sniffing on plaintext rows: their content is arbitrary
            // user data, and four bytes of it are none of the server's
            // business. `enc_version` stays 0 here either way.
            // Both halves under the row's write lock: a DAV overwrite racing
            // a browser save must not interleave the two halves (see
            // `FileService::begin_replace`).
            {
                let _write = state.files.begin_replace(old.id).await;
                if let Err(e) = state
                    .db
                    .update_file_meta(owner_id, old.id, size, mime, None)
                    .await
                {
                    return e.into_response();
                }
                if let Err(e) = state.files.write_blob(&old, body.to_vec()).await {
                    return e.into_response();
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        None => {
            // New file: the parent must grant CREATE (always true for own root).
            if !crate::sharing::grants(parent.permissions, crate::sharing::PERM_CREATE) {
                return forbidden();
            }
            // A *create* is not an overwrite, so nothing can be destroyed and
            // nothing is sniffed: `enc_version` stays 0, exactly as it would
            // for any other file whose first four bytes happen to spell
            // "FXE1". DAV has no channel for a key record, so it can only ever
            // create plaintext rows.
            match state
                .db
                .create_file(owner_id, parent.id, name, size, mime, 0, None)
                .await
            {
                Ok(entry) => {
                    if let Err(e) = state.files.write_blob(&entry, body.to_vec()).await {
                        // Failed upload rollback: the row never existed for the
                        // user, so drop it for good instead of trashing it.
                        let _ = state.db.hard_delete_entry(owner_id, entry.id).await;
                        return e.into_response();
                    }
                    (
                        StatusCode::CREATED,
                        [(header::LOCATION, build_href(segments, false))],
                    )
                        .into_response()
                }
                Err(e) => e.into_response(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------

async fn delete_resource(state: &SharedState, owner_id: i64, segments: &[String]) -> Response {
    if segments.is_empty() {
        return forbidden();
    }
    let target = match resolve(state, owner_id, segments).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Err(r) = require(&target, crate::sharing::PERM_DELETE) {
        return r;
    }
    let entry = match target {
        Target::Root => return forbidden(),
        Target::Entry(e) => e,
    };
    match state.db.trash_entry(owner_id, entry.id).await {
        // The entry (and, for folders, its subtree) moves to the trash:
        // rows and content stay until the purge or a restore.
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// MKCOL
// ---------------------------------------------------------------------------

async fn mkcol(state: &SharedState, owner_id: i64, segments: &[String]) -> Response {
    if segments.is_empty() {
        return method_not_allowed();
    }
    let name = segments.last().unwrap().clone();
    let parent_segments = &segments[..segments.len() - 1];

    // Missing/invalid parent -> 409 Conflict (RFC 4918).
    let parent = match resolve_parent(state, owner_id, parent_segments).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    // New collection: the parent must grant CREATE.
    if !crate::sharing::grants(parent.permissions, crate::sharing::PERM_CREATE) {
        return forbidden();
    }

    // 405 if the collection already exists.
    if let Ok(Some(_)) = state.db.resolve_path(owner_id, segments.to_vec()).await {
        return method_not_allowed();
    }

    match state.db.create_dir(owner_id, parent.id, name).await {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// MOVE
// ---------------------------------------------------------------------------

/// Parse the `Destination` header into DAV path segments.
fn destination_segments(headers: &HeaderMap) -> Option<Vec<String>> {
    let dest = headers.get("Destination").and_then(|v| v.to_str().ok())?;
    let path = if let Some(idx) = dest.find("://") {
        // Absolute URL: scheme://host[:port]/path
        let rest = &dest[idx + 3..];
        match rest.find('/') {
            Some(slash) => &rest[slash..],
            None => "/",
        }
    } else {
        dest // already an absolute path
    };
    Some(parse_segments(path))
}

async fn move_resource(
    state: &SharedState,
    owner_id: i64,
    segments: &[String],
    headers: &HeaderMap,
) -> Response {
    if segments.is_empty() {
        return forbidden();
    }
    let src_entry = match resolve(state, owner_id, segments).await {
        Ok(Target::Root) => return forbidden(),
        Ok(Target::Entry(e)) => e,
        Err(r) => return r,
    };
    if !crate::sharing::grants(src_entry.permissions, crate::sharing::PERM_UPDATE) {
        return forbidden();
    }

    let dest = match destination_segments(headers) {
        Some(s) if !s.is_empty() => s,
        Some(_) => return forbidden(), // destination is root
        None => return (StatusCode::BAD_REQUEST, "Missing Destination").into_response(),
    };
    if dest.as_slice() == segments {
        return forbidden();
    }

    let dest_name = dest.last().unwrap().clone();
    let dest_parent = match resolve_parent(state, owner_id, &dest[..dest.len() - 1]).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !crate::sharing::grants(dest_parent.permissions, crate::sharing::PERM_CREATE) {
        return forbidden();
    }

    let existing = match state.db.resolve_path(owner_id, dest.clone()).await {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };
    let overwrote = existing.is_some();
    if let Some(old) = existing {
        if !overwrite_allowed(headers) {
            return precondition();
        }
        // Overwriting moves the old target to the trash instead of dropping
        // it: nothing disappears for good outside the trash flow.
        match state.db.trash_entry(owner_id, old.id).await {
            Ok(()) => {}
            Err(e) => return e.into_response(),
        }
    }

    match state
        .db
        .move_entry(owner_id, src_entry.id, dest_parent.id, dest_name)
        .await
    {
        Ok(_) => {
            if overwrote {
                StatusCode::NO_CONTENT.into_response()
            } else {
                StatusCode::CREATED.into_response()
            }
        }
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// COPY
// ---------------------------------------------------------------------------

/// Copy `src` (file or whole subtree, including blob content) under
/// `dst_parent` as `dst_name`. Shared with the WebDAV `COPY` handler and the
/// web API so both go through the same permission-aware create path.
///
/// The destination owner's quota is checked once for the whole subtree before
/// anything is written (`507` otherwise), so a full quota never leaves a
/// partial copy behind.
pub(crate) async fn copy_recursive(
    state: &SharedState,
    owner_id: i64,
    src: &FileEntry,
    dst_parent: Option<i64>,
    dst_name: String,
) -> Result<FileEntry, AppError> {
    let total = state.db.subtree_size(src.id).await?;
    // Refuse before anything is written: a partial copy of an encrypted
    // subtree would be a row the user can see and never open again.
    let keyed = state.db.subtree_keyed_names(src.id).await?;
    if let Some(first) = keyed.first() {
        let what = if keyed.len() == 1 {
            format!("\"{first}\"")
        } else {
            format!("{} encrypted items", keyed.len())
        };
        return Err(AppError::Conflict(format!(
            "{what} cannot be copied yet - a copy gets a new row id and would \
             need its key record re-wrapped under the destination key first; \
             download and upload it instead"
        )));
    }
    state.db.check_quota(owner_id, total).await?;
    copy_node(state, owner_id, src, dst_parent, dst_name).await
}

/// Create one node of a copy and recurse into its children (see
/// [`copy_recursive`], which gates the whole subtree up front).
async fn copy_node(
    state: &SharedState,
    owner_id: i64,
    src: &FileEntry,
    dst_parent: Option<i64>,
    dst_name: String,
) -> Result<FileEntry, AppError> {
    if src.is_dir {
        let new_dir = state.db.create_dir(owner_id, dst_parent, dst_name).await?;
        let children = state.db.list_children(owner_id, Some(src.id)).await?;
        for child in children {
            // Box::pin to allow this async fn to recurse.
            Box::pin(copy_node(
                state,
                owner_id,
                &child,
                Some(new_dir.id),
                child.name.clone(),
            ))
            .await?;
        }
        Ok(new_dir)
    } else {
        let new_file = state
            .db
            // `copy_recursive` already refused any subtree carrying a key
            // record, so what reaches here is plaintext by construction.
            .create_file(
                owner_id,
                dst_parent,
                dst_name,
                src.size,
                src.mime.clone(),
                0,
                None,
            )
            .await?;
        let (_e, data) = state.files.read_blob(owner_id, src.id).await?;
        state.files.write_blob(&new_file, data).await?;
        Ok(new_file)
    }
}

async fn copy_resource(
    state: &SharedState,
    owner_id: i64,
    segments: &[String],
    headers: &HeaderMap,
) -> Response {
    if segments.is_empty() {
        return forbidden();
    }
    let src_entry = match resolve(state, owner_id, segments).await {
        Ok(Target::Root) => return forbidden(),
        Ok(Target::Entry(e)) => e,
        Err(r) => return r,
    };
    // Copying out of a share only needs READ on the source.
    if !crate::sharing::grants(src_entry.permissions, crate::sharing::PERM_READ) {
        return forbidden();
    }

    let dest = match destination_segments(headers) {
        Some(s) if !s.is_empty() => s,
        Some(_) => return forbidden(),
        None => return (StatusCode::BAD_REQUEST, "Missing Destination").into_response(),
    };

    let dest_name = dest.last().unwrap().clone();
    let dest_parent = match resolve_parent(state, owner_id, &dest[..dest.len() - 1]).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !crate::sharing::grants(dest_parent.permissions, crate::sharing::PERM_CREATE) {
        return forbidden();
    }

    if let Ok(Some(_)) = state.db.resolve_path(owner_id, dest.clone()).await {
        if !overwrite_allowed(headers) {
            return precondition();
        }
        // Delete the existing destination before copying over it.
        let old = match state.db.resolve_path(owner_id, dest.clone()).await {
            Ok(Some(o)) => o,
            _ => return internal(),
        };
        // Overwriting moves the old target to the trash instead of dropping
        // it: nothing disappears for good outside the trash flow.
        match state.db.trash_entry(owner_id, old.id).await {
            Ok(()) => {}
            Err(e) => return e.into_response(),
        }
    }

    match copy_recursive(state, owner_id, &src_entry, dest_parent.id, dest_name).await {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// LOCK (permissive no-op so Office/Windows clients stay happy)
// ---------------------------------------------------------------------------

fn lock() -> Response {
    let token = format!("opaquelocktoken:{}", generate_token());
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>\
         <D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope>\
         <D:depth>infinity</D:depth><D:timeout>Second-3600</D:timeout>\
         <D:locktoken><D:href>{token}</D:href></D:locktoken>\
         </D:activelock></D:lockdiscovery></D:prop>"
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header("Lock-Token", format!("<{token}>"))
        .body(Body::from(body))
        .unwrap_or_else(|_| internal())
}

// ---------------------------------------------------------------------------
// OPTIONS
// ---------------------------------------------------------------------------

fn options() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("DAV", "1, 2")
        .header(
            "Allow",
            "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, MOVE, COPY, LOCK, UNLOCK",
        )
        .header("MS-Author-Via", "DAV")
        .body(Body::empty())
        .unwrap_or_else(|_| internal())
}

// ---------------------------------------------------------------------------
// XML rendering
// ---------------------------------------------------------------------------

struct Resource {
    href: String,
    name: String,
    is_dir: bool,
    size: i64,
    mime: Option<String>,
    created: DateTime<Utc>,
    modified: DateTime<Utc>,
    etag: String,
}

impl Resource {
    fn from_entry(segments: &[String], e: &FileEntry) -> Self {
        Self {
            href: build_href(segments, e.is_dir),
            name: e.name.clone(),
            is_dir: e.is_dir,
            size: e.size,
            mime: e.mime.clone(),
            created: e.created_at,
            modified: e.modified_at,
            etag: format!("\"{}-{}-{}\"", e.id, e.size, e.modified_at.timestamp()),
        }
    }

    fn root() -> Self {
        let now = Utc::now();
        Self {
            href: build_href(&[], true),
            name: "Home".to_string(),
            is_dir: true,
            size: 0,
            mime: None,
            created: now,
            modified: now,
            etag: format!("\"root-{}\"", now.timestamp()),
        }
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn http_date(dt: &DateTime<Utc>) -> String {
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn multistatus_xml(resources: &[Resource]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n",
    );
    for r in resources {
        xml.push_str("<D:response><D:href>");
        xml.push_str(&escape_xml(&r.href));
        xml.push_str("</D:href><D:propstat><D:prop>");
        xml.push_str(&format!(
            "<D:displayname>{}</D:displayname>",
            escape_xml(&r.name)
        ));
        if r.is_dir {
            xml.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
        } else {
            xml.push_str("<D:resourcetype/>");
            xml.push_str(&format!(
                "<D:getcontentlength>{}</D:getcontentlength>",
                r.size
            ));
            if let Some(m) = &r.mime {
                xml.push_str(&format!(
                    "<D:getcontenttype>{}</D:getcontenttype>",
                    escape_xml(m)
                ));
            }
        }
        xml.push_str(&format!("<D:getetag>{}</D:getetag>", escape_xml(&r.etag)));
        xml.push_str(&format!(
            "<D:getlastmodified>{}</D:getlastmodified>",
            http_date(&r.modified)
        ));
        xml.push_str(&format!(
            "<D:creationdate>{}</D:creationdate>",
            r.created.to_rfc3339()
        ));
        xml.push_str("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n");
    }
    xml.push_str("</D:multistatus>");
    xml
}

// ---------------------------------------------------------------------------
// Small response helpers
// ---------------------------------------------------------------------------

fn internal() -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}
fn method_not_allowed() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed").into_response()
}
fn conflict() -> Response {
    (StatusCode::CONFLICT, "Conflict").into_response()
}
fn precondition() -> Response {
    (StatusCode::PRECONDITION_FAILED, "Precondition Failed").into_response()
}
fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"fxcloud\", charset=\"UTF-8\"")],
        "Unauthorized",
    )
        .into_response()
}
fn inactive_account() -> Response {
    (
        StatusCode::FORBIDDEN,
        "Account not activated. Ask an administrator to activate it.",
    )
        .into_response()
}
fn multistatus(xml: String) -> Response {
    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml,
    )
        .into_response()
}
