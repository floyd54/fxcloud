//! Office integration (concepts/office.md): the WOPI host.
//!
//! Three doors, two audiences. `POST /api/office/start` mints an editor
//! session for a signed-in user; the `/wopi/files/{id}` family answers the
//! *engine container's* server-side calls, where the bearer token is the
//! only credential (the engine has no cookie). Nothing here exists unless
//! `FXCLOUD_OFFICE_URL` is configured - the router does not register these
//! paths at all then (decision 3).

use axum::extract::{Path, Query, Request, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;

use crate::auth::AuthUser;
use crate::config::OfficeEmbed;
use crate::error::AppError;
use crate::models::{FileEntry, User};
use crate::web::routes::files::{
    ranged_body, save_streamed, stream_body_to_temp, ByteRange, ContentQuery,
};
use crate::web::state::SharedState;

/// Lifetime of one office session token. The WOPI host-page documentation
/// recommends an `access_token_ttl` of ten hours, and a long editing session
/// is the normal case, not an exception.
const OFFICE_TTL_MS: i64 = 10 * 60 * 60 * 1000;

/// Domain separator: a token proves nothing anywhere but in the WOPI routes,
/// even if the same secret ever served another purpose.
const TOKEN_DOMAIN: &[u8] = b"fxcloud-wopi-v1:";

/// What one minted token stands for (concepts/office.md section 5).
///
/// Deliberately tiny: the file it may touch, the user it acts as, when the
/// session opened (the identity of the version-pin rule, decision 12) and
/// when it dies. The HMAC below covers the encoded payload; the secret
/// itself never leaves the server.
#[derive(Debug, Serialize, Deserialize)]
struct OfficeClaims {
    /// file id
    f: i64,
    /// acting user id
    u: i64,
    /// opened-at, unix ms - the office session's identity
    o: i64,
    /// expiry, unix ms
    x: i64,
}

/// The start request: `{"id": <fileId>}` as the JSON body (the overlay and
/// the suite send it that way; a query parameter would put a file id in
/// every proxy log).
#[derive(Deserialize)]
pub struct OfficeStartQuery {
    pub id: i64,
}

/// Query of every WOPI route: the engines append the access token to the
/// request URL (measured for GET and POST alike in the spike).
#[derive(Deserialize)]
pub struct WopiTokenQuery {
    pub access_token: Option<String>,
}

/// The raw HMAC-SHA256 construction, exactly what the RFC 4231 vector
/// pins: [`hmac_sig`] adds the domain separator on top of this.
fn hmac_raw(secret: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sig(secret: &[u8], payload: &str) -> Vec<u8> {
    // Domain separator: a token proves nothing anywhere but in the WOPI
    // routes, even if the same secret ever served another purpose.
    let mut msg = TOKEN_DOMAIN.to_vec();
    msg.extend_from_slice(payload.as_bytes());
    hmac_raw(secret, &msg)
}

/// Constant-time byte equality: a token forgery must not be readable from
/// timing differences in the comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn mint_token(secret: &str, file_id: i64, user_id: i64, now_ms: i64) -> (String, i64) {
    let claims = OfficeClaims {
        f: file_id,
        u: user_id,
        o: now_ms,
        x: now_ms + OFFICE_TTL_MS,
    };
    let payload = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&claims).expect("claims serialize"));
    let sig = URL_SAFE_NO_PAD.encode(hmac_sig(secret.as_bytes(), &payload));
    (format!("{payload}.{sig}"), claims.x)
}

/// Verify a token for `file_id`. Every failure is the *same* `404`: unknown,
/// tampered, expired or bound to another file never tell the caller that the
/// id exists somewhere (concepts/office.md section 5).
fn verify_token(secret: &str, token: &str, file_id: i64) -> Result<OfficeClaims, AppError> {
    let not_found = || AppError::NotFound;
    let (payload, sig) = token.split_once('.').ok_or_else(not_found)?;
    let expected = hmac_sig(secret.as_bytes(), payload);
    let given = URL_SAFE_NO_PAD.decode(sig).map_err(|_| not_found())?;
    if !ct_eq(&expected, &given) {
        return Err(not_found());
    }
    let raw = URL_SAFE_NO_PAD.decode(payload).map_err(|_| not_found())?;
    let claims: OfficeClaims = serde_json::from_slice(&raw).map_err(|_| not_found())?;
    if claims.f != file_id || Utc::now().timestamp_millis() > claims.x {
        return Err(not_found());
    }
    Ok(claims)
}

/// Which engine section handles a file, by extension: the OnlyOffice-family
/// host page lives under `/hosting/wopi/<kind>/edit`, and its discovery lists
/// the same `word`/`cell`/`slide` segments. Unknown types never reach here
/// from the UI; the API refuses them so a hand-built session cannot smuggle
/// one in.
fn doc_kind(name: &str) -> Option<&'static str> {
    let ext = name.rsplit('.').next()?.to_ascii_lowercase();
    match ext.as_str() {
        "doc" | "docx" | "odt" | "rtf" | "ott" => Some("word"),
        "xls" | "xlsx" | "ods" | "ots" | "csv" => Some("cell"),
        "ppt" | "pptx" | "odp" | "otp" => Some("slide"),
        _ => None,
    }
}

/// The URL the *engine container* uses to reach fxcloud (the WOPISrc base):
/// the explicit knob first, then `FXCLOUD_ORIGIN`, then the origin derived
/// from the start request - the same derivation passkeys use. The proxy
/// section of concepts/office.md section 8 explains why this leg normally
/// bypasses the reverse proxy and why the knob exists for the cases it
/// cannot.
async fn wopi_base(
    state: &SharedState,
    headers: &axum::http::HeaderMap,
) -> Result<String, AppError> {
    if let Some(base) = &state.config.office_wopi_base {
        return Ok(base.clone());
    }
    if let Some(origin) = &state.config.webauthn_origin {
        return Ok(origin.clone());
    }
    crate::webauthn::origin_and_rp(headers, &state.config)
        .ok()
        .map(|(origin, _)| origin)
        .ok_or_else(|| {
            AppError::BadRequest(
                "cannot derive the WOPI base URL - set FXCLOUD_OFFICE_WOPI_BASE or FXCLOUD_ORIGIN"
                    .into(),
            )
        })
}

/// `Version`: changes exactly when the content does (millis of
/// `modified_at`). `LastModifiedTime`: the ISO-8601 form WOPI asks for.
/// Both must stay byte-stable between real writes - an ever-fresh value
/// makes the engine believe the file changed underneath it and *discard
/// local edits* (observed in the spike, concepts/office.md section 11).
fn version_string(t: &DateTime<Utc>) -> String {
    t.timestamp_millis().to_string()
}

fn iso_utc(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Token -> the acting user and the entry, with the *live* state checked on
/// every call (concepts/office.md section 5): signature and expiry first,
/// then the account still active, the entry still readable and not a folder,
/// and the caller still holding UPDATE. Deactivating an account or revoking
/// a share therefore cuts an open editor off on its next request - the same
/// instant semantics sessions and WebDAV already have. v1 has no viewer mode
/// (decision 11), so UPDATE is required for every WOPI call, read included.
async fn authenticate(
    state: &SharedState,
    token: &str,
    file_id: i64,
) -> Result<(OfficeClaims, User, FileEntry), AppError> {
    let secret = state
        .config
        .office_secret
        .as_deref()
        .ok_or(AppError::NotFound)?;
    let claims = verify_token(secret, token, file_id)?;
    let user = state
        .db
        .find_user_by_id(claims.u)
        .await?
        .ok_or(AppError::NotFound)?;
    if !user.is_active {
        return Err(AppError::NotFound);
    }
    let entry = state
        .db
        .entry_for_read(user.id, file_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if entry.is_dir {
        return Err(AppError::NotFound);
    }
    state.db.require_update(user.id, file_id).await?;
    Ok((claims, user, entry))
}

/// POST /api/office/start `{"id": <fileId>}` - mint the office session.
///
/// Gates, in order: a live session (`AuthUser`), the entry exists and is
/// readable, it is a file (400), it is plaintext (409 - the engine only
/// ever sees plaintext, concepts/office.md section 7), and the caller holds
/// UPDATE (403; no viewer mode in v1, decision 11).
///
/// The response is everything the overlay needs to render: the target URL
/// for the configured embed flow, the token as a form field or query
/// parameter, its expiry in ms, and which flow it is. The HMAC secret never
/// leaves the process.
pub async fn start(
    State(state): State<SharedState>,
    user: AuthUser,
    headers: axum::http::HeaderMap,
    Json(q): Json<OfficeStartQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (Some(secret), Some(office_url)) = (
        state.config.office_secret.as_deref(),
        state.config.office_url.as_deref(),
    ) else {
        // Not registered when the feature is off; this arm only exists so a
        // future refactor cannot resurrect the route half-configured.
        return Err(AppError::NotFound);
    };
    let entry = state
        .db
        .entry_for_read(user.id(), q.id)
        .await?
        .ok_or(AppError::NotFound)?;
    if entry.is_dir {
        return Err(AppError::BadRequest("folders have no office editor".into()));
    }
    if entry.enc_version > 0 {
        return Err(AppError::Conflict(
            "this file is encrypted; the office editor works on plaintext - \
             open it in the built-in editor instead"
                .into(),
        ));
    }
    state.db.require_update(user.id(), entry.id).await?;
    let kind = doc_kind(&entry.name)
        .ok_or_else(|| AppError::BadRequest("this file type has no office editor".into()))?;
    let base = wopi_base(&state, &headers).await?;
    let now_ms = Utc::now().timestamp_millis();
    let (token, exp_ms) = mint_token(secret, entry.id, user.id(), now_ms);
    let wopisrc = format!("{base}/wopi/files/{}", entry.id);
    let wopisrc = utf8_percent_encode(&wopisrc, NON_ALPHANUMERIC).to_string();
    let (url, mode) = match state.config.office_embed {
        // The official WOPI host page: a form POST carrying the token in
        // its body into the iframe (measured against Euro-Office 9.3.7,
        // concepts/office.md section 11). `wopisrc` stays in the query.
        OfficeEmbed::Form => (
            format!("{office_url}/hosting/wopi/{kind}/edit?wopisrc={wopisrc}"),
            "form",
        ),
        // Collabora's flow: one GET on `cool.html` with everything in the
        // query string (measured against CODE 26.04, section 11).
        OfficeEmbed::Iframe => (
            format!(
                "{office_url}/cool.html?WOPISrc={wopisrc}&access_token={token}&access_token_ttl={exp_ms}"
            ),
            "iframe",
        ),
    };
    Ok(Json(json!({
        "url": url,
        "access_token": token,
        "access_token_ttl": exp_ms,
        "mode": mode,
    })))
}

/// GET /wopi/files/{id} - CheckFileInfo: what the file is, what this
/// session may do with it (v1: write everything - decision 11), and when it
/// last changed.
pub async fn checkfileinfo(
    State(state): State<SharedState>,
    Path(file_id): Path<i64>,
    Query(q): Query<WopiTokenQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = q.access_token.ok_or(AppError::NotFound)?;
    let (claims, user, entry) = authenticate(&state, &token, file_id).await?;
    Ok(Json(json!({
        "BaseFileName": entry.name,
        "FileName": entry.name,
        "Size": entry.size,
        "Version": version_string(&entry.modified_at),
        "LastModifiedTime": iso_utc(&entry.modified_at),
        "UserId": user.id.to_string(),
        "UserFriendlyName": user.display_name,
        "ReadOnly": false,
        "UserCanWrite": true,
        "SupportsUpdate": true,
        "SupportsLocks": false,
        "IsAnonymousUser": false,
        "MimeType": entry.mime.clone().unwrap_or_else(|| "application/octet-stream".into()),
        "access_token_ttl": claims.x,
    })))
}

/// GET /wopi/files/{id}/content and /contents - GetFile.
///
/// The trailing `contents` spelling is Collabora's; the MS spec says
/// `content`. The spike measured both (one engine per spelling), so the
/// host answers both - the alternative was a 404 loop per engine family
/// (concepts/office.md section 5 and 11).
pub async fn getfile(
    State(state): State<SharedState>,
    Path(file_id): Path<i64>,
    Query(q): Query<WopiTokenQuery>,
) -> Result<Response, AppError> {
    let token = q.access_token.ok_or(AppError::NotFound)?;
    let (claims, _user, _entry) = authenticate(&state, &token, file_id).await?;
    let (entry, file, len) = state.files.open_blob(claims.u, file_id).await?;
    let ranged = ranged_body(file, len as usize, ByteRange::Full).await?;
    let response = Response::builder()
        .status(ranged.status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, ranged.content_len.to_string())
        .header("X-WOPI-ItemVersion", version_string(&entry.modified_at))
        .body(ranged.body)
        .map_err(|e| {
            AppError::Internal(anyhow::anyhow!("building the WOPI GetFile response: {e}"))
        })?;
    Ok(response.into_response())
}

/// POST/PUT /wopi/files/{id} and .../contents - PutFile, the engine's save.
///
/// The body streams into the temp pipeline like every other write (S1,
/// concepts/streaming.md), then the *same* `save_streamed` runs the quota
/// gate (507), the MIME decision and the row commit - an office save cannot
/// diverge from an editor or WebDAV save (concepts/office.md section 5).
///
/// The pin follows decision 12: the outgoing content becomes a version row
/// unless *this session* wrote it, so autosaves inside one session do not
/// shred the history while pre-session state and foreign writes (WebDAV,
/// built-in editor) are always kept.
pub async fn putfile(
    State(state): State<SharedState>,
    Path(file_id): Path<i64>,
    Query(q): Query<WopiTokenQuery>,
    request: Request,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = q.access_token.ok_or(AppError::NotFound)?;
    let (claims, _user, entry) = authenticate(&state, &token, file_id).await?;
    if entry.enc_version > 0 {
        return Err(AppError::Conflict(
            "this file is encrypted; the office editor writes plaintext - \
             open it in the built-in editor instead"
                .into(),
        ));
    }
    // The body counts its way to disk; a rejection removes the temp file
    // before the error is returned (the save_content contract).
    let (temp, sample, size) = stream_body_to_temp(
        &state,
        request.into_body(),
        state.config.max_upload_bytes as u64,
    )
    .await?;
    let q = ContentQuery {
        id: file_id,
        enc: None,
        key: None,
    };
    let pin_old =
        entry.size > 0 && state.office_pin_needed(file_id, claims.o, entry.modified_at);
    let outcome =
        save_streamed(&state, claims.u, &q, entry, temp.clone(), &sample, size, pin_old).await;
    if let Err(e) = outcome {
        // The temp file only ever disappears by being renamed into place.
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(e);
    }
    let fresh = state
        .db
        .entry_for_read(claims.u, file_id)
        .await?
        .ok_or(AppError::NotFound)?;
    // Record what *we* just wrote (the DB's own timestamp, not the wall
    // clock), so the next save of this session can skip the pin.
    state.office_record_write(file_id, claims.o, fresh.modified_at);
    Ok(Json(json!({
        "LastModifiedTime": iso_utc(&fresh.modified_at),
        "Version": version_string(&fresh.modified_at),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-0123456789";

    /// A minted token round-trips for its own file and nobody else's: the
    /// whole contract in one assertion, because every WOPI refusal shares
    /// the same 404 and a broken binding would be invisible in the suite.
    #[test]
    fn token_binds_file_and_survives_roundtrip() {
        let now = Utc::now().timestamp_millis();
        let (token, exp) = mint_token(SECRET, 7, 42, now);
        assert_eq!(exp, now + OFFICE_TTL_MS);
        let claims = verify_token(SECRET, &token, 7).expect("valid token verifies");
        assert_eq!((claims.f, claims.u, claims.o), (7, 42, now));
        assert!(verify_token(SECRET, &token, 8).is_err(), "wrong file must404");
    }

    /// Tampering with either half kills the token: flipping a payload byte
    /// breaks the signature, flipping a signature byte breaks the compare.
    /// Minted with the real clock, so a *stale* token cannot make these
    /// assertions pass by expiry alone.
    #[test]
    fn token_tampering_is_refused() {
        let (token, _) = mint_token(SECRET, 1, 1, Utc::now().timestamp_millis());
        let (payload, sig) = token.split_once('.').unwrap();
        let flipped_payload = format!("{}{}", &payload[1..], &payload[..1]);
        assert!(verify_token(SECRET, &format!("{flipped_payload}.{sig}"), 1).is_err());
        let flipped_sig = format!("{}{}", &sig[1..], &sig[..1]);
        assert!(verify_token(SECRET, &format!("{payload}.{flipped_sig}"), 1).is_err());
        assert!(verify_token("other-secret", &token, 1).is_err(), "wrong key");
        assert!(verify_token(SECRET, "not-a-token", 1).is_err(), "garbage");
    }

    /// Expiry is checked against the clock, not the token's own word.
    #[test]
    fn expired_tokens_are_refused() {
        let long_past = Utc::now().timestamp_millis() - OFFICE_TTL_MS - 1;
        let (token, _) = mint_token(SECRET, 1, 1, long_past);
        assert!(verify_token(SECRET, &token, 1).is_err(), "expired token");
    }

    /// The document-kind map covers both families and refuses everything
    /// else, so a hand-built session cannot smuggle an unknown type in.
    #[test]
    fn doc_kind_maps_office_extensions() {
        assert_eq!(doc_kind("a.docx"), Some("word"));
        assert_eq!(doc_kind("B.ODT"), Some("word"));
        assert_eq!(doc_kind("m.xlsx"), Some("cell"));
        assert_eq!(doc_kind("s.pptx"), Some("slide"));
        assert_eq!(doc_kind("notes.md"), None);
        assert_eq!(doc_kind("noextension"), None);
    }

    /// The HMAC is the real construction (RFC 4231 test vector 1), not a
    /// hand-rolled hash that would drift from every other implementation.
    /// [`hmac_sig`] is this primitive plus the domain separator, which the
    /// round-trip tests cover.
    #[test]
    fn hmac_matches_rfc4231_vector() {
        let sig = hmac_raw(b"key", b"The quick brown fox jumps over the lazy dog");
        let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }
}
