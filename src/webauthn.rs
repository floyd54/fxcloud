//! WebAuthn (passkey) ceremony verification.
//!
//! Everything in here is pure: parse bytes, check them against the
//! challenge, origin and rpId the server issued, and return what to store.
//! Ceremony state lives in [`crate::web::state`], HTTP plumbing in
//! [`crate::web::routes::passkeys`] - this module only decides whether a
//! ceremony output is *valid*.
//!
//! Scope of this first version:
//!
//! * ES256 on P-256 only (COSE alg -7) - the one algorithm every
//!   authenticator in service supports.
//! * Attestation formats `none` and `packed` *without* `x5c`. We request
//!   `attestation: "none"`, so a certificate chain back to a vendor CA is
//!   out of scope; `packed` self-attestation (the new credential signing
//!   for itself) uses the same ECDSA verify as an assertion.
//! * Username-first sign-in: the options carry an explicit
//!   `allowCredentials` list, discoverable-credential-only flows are not
//!   part of the endpoints.

use axum::http::header::{HOST, ORIGIN};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::Value as Cbor;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::error::AppError;
use crate::models::{LoginCredentialJson, RegisterCredentialJson};

/// COSE algorithm id of ES256 - the only one offered in `pubKeyCredParams`
/// and the only one accepted in a credential key or attestation statement.
pub const COSE_ALG_ES256: i128 = -7;

/// Authenticator data flag: the user is present (touched the device).
const FLAG_UP: u8 = 0x01;
/// Authenticator data flag: the user was verified (PIN, biometrics, or the
/// passkey's own gesture).
const FLAG_UV: u8 = 0x04;
/// Authenticator data flag: attested credential data follows the header.
const FLAG_AT: u8 = 0x40;

/// `clientDataJSON.type` strings of the two ceremonies.
const CLIENT_REGISTER: &str = "webauthn.create";
const CLIENT_LOGIN: &str = "webauthn.get";

// ---------------------------------------------------------------------------
// base64url and randomness
// ---------------------------------------------------------------------------

/// Encode bytes the way WebAuthn transports them: base64url, unpadded
/// (the form browsers re-encode into `clientData.challenge` and friends).
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a base64url field the client sent. `what` names the field so a
/// malformed payload points at the exact spot that is broken.
pub fn b64url_decode(input: &str, what: &str) -> Result<Vec<u8>, AppError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| AppError::BadRequest(format!("{what} is not valid base64url")))
}

/// `len` cryptographically random bytes.
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// A fresh ceremony challenge: 32 random bytes, base64url. This exact
/// string goes into the options and must come back verbatim in
/// `clientData.challenge`.
pub fn new_challenge() -> String {
    b64url(&random_bytes(32))
}

// ---------------------------------------------------------------------------
// Origin and rpId
// ---------------------------------------------------------------------------

/// The `(origin, rp_id)` pair this request is served under.
///
/// WebAuthn binds credentials to an exact origin *and* to a registrable
/// domain (the rpId, which is the origin's host without any port), so both
/// must be derived the same way in the options and in every verification:
///
/// * `FXCLOUD_ORIGIN` (config) wins when set - the one knob for a reverse
///   proxy that rewrites `Host`.
/// * Otherwise the scheme comes from `X-Forwarded-Proto` or, failing that,
///   from `FXCLOUD_SECURE_COOKIE`, and the authority from `Host`.
///
/// When the browser sends an `Origin` header (always the case on the JSON
/// POSTs of a ceremony) it must equal the derived origin. A mismatch means
/// deployment config disagrees with what browsers actually see, which would
/// fail verification anyway - better a clear 400 with a pointer to
/// `FXCLOUD_ORIGIN` before a single challenge is spent. Every refusal here
/// is journaled at WARN with the headers in play: a wrong `FXCLOUD_ORIGIN`
/// is otherwise invisible (the browser shows a generic "Invalid request"
/// and the journal said nothing), so `journalctl -u fxcloud` is the first
/// place to look when passkeys stop working.
pub fn origin_and_rp(headers: &HeaderMap, config: &Config) -> Result<(String, String), AppError> {
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            tracing::warn!(
                forwarded_proto = ?headers.get("x-forwarded-proto"),
                "passkey request refused: no Host header to derive the origin from"
            );
            AppError::BadRequest("missing Host header".into())
        })?
        .to_string();

    let raw = match &config.webauthn_origin {
        Some(configured) => configured.clone(),
        None => {
            let scheme = headers
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|s| s == "http" || s == "https")
                .unwrap_or_else(|| {
                    if config.secure_cookie {
                        "https".to_string()
                    } else {
                        "http".to_string()
                    }
                });
            format!("{scheme}://{host}")
        }
    };
    let (origin, rp_id) = match split_origin(&raw) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(
                origin = %raw,
                fxcloud_origin_set = config.webauthn_origin.is_some(),
                "passkey request refused: the origin is not http(s)://host[:port]"
            );
            return Err(err);
        }
    };

    if let Some(sent) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
        if sent != origin {
            tracing::warn!(
                browser_origin = %sent,
                derived_origin = %origin,
                host = %host,
                forwarded_proto = ?headers.get("x-forwarded-proto"),
                secure_cookie = config.secure_cookie,
                fxcloud_origin_set = config.webauthn_origin.is_some(),
                "passkey request refused: the browser's Origin does not match this \
                 deployment - set FXCLOUD_ORIGIN to the URL users open it under \
                 (and FXCLOUD_SECURE_COOKIE=1 behind HTTPS)"
            );
            return Err(AppError::BadRequest(
                "Origin does not match this server's address - set FXCLOUD_ORIGIN to the URL \
                 users open it under"
                    .into(),
            ));
        }
    }
    Ok((origin, rp_id))
}

/// Normalize `scheme://host[:port][/anything]` into the canonical origin
/// plus the rpId (host without port, per the WebAuthn rpId rules).
fn split_origin(origin: &str) -> Result<(String, String), AppError> {
    let malformed = || AppError::BadRequest("origin must look like http(s)://host[:port]".into());
    let (scheme, rest) = origin.split_once("://").ok_or_else(malformed)?;
    if scheme != "http" && scheme != "https" {
        return Err(malformed());
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(malformed());
    }
    let rp_id = host_without_port(authority);
    if rp_id.is_empty() {
        return Err(malformed());
    }
    Ok((format!("{scheme}://{authority}"), rp_id))
}

/// Host without its port: `example.com:8080` -> `example.com`. An IPv6
/// literal keeps its brackets, dropping only `:port` behind them
/// (`[::1]:8080` -> `[::1]`). The rpId is the origin's *domain*, never its
/// port - matching what the browser itself derives.
fn host_without_port(authority: &str) -> String {
    if let Some(end) = authority.find(']') {
        // Bracketed IPv6 authority: keep through the closing bracket.
        if end + 1 <= authority.len() {
            return authority[..=end].to_string();
        }
    }
    match authority.rsplit_once(':') {
        Some((head, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            head.to_string()
        }
        _ => authority.to_string(),
    }
}

// ---------------------------------------------------------------------------
// clientDataJSON
// ---------------------------------------------------------------------------

/// Parsed `clientDataJSON` plus its raw bytes - the signature covers
/// exactly those bytes, so the hash is taken from here.
pub struct ClientData {
    pub typ: String,
    pub challenge: String,
    pub origin: String,
    pub cross_origin: bool,
    pub raw: Vec<u8>,
}

/// Decode the base64url field into JSON. Structure only: the semantic
/// checks run in the verify functions, because the caller first needs the
/// *challenge* out of it to find the ceremony this response belongs to.
pub fn read_client_data(json_b64: &str, what: &str) -> Result<ClientData, AppError> {
    let raw = b64url_decode(json_b64, what)?;
    let value: Json = serde_json::from_slice(&raw)
        .map_err(|_| AppError::BadRequest(format!("{what} is not valid JSON")))?;
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or_else(|| AppError::BadRequest(format!("{what} is missing '{name}'")))
    };
    Ok(ClientData {
        typ: field("type")?,
        challenge: field("challenge")?,
        origin: field("origin")?,
        cross_origin: value
            .get("crossOrigin")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        raw,
    })
}

/// The checks both ceremonies repeat: the right ceremony's type string, the
/// echoed challenge (a mismatch is a replay or a stale tab), our origin,
/// and no cross-origin iframe. Unknown extra fields are ignored - the
/// browser adds them as the spec evolves.
fn check_client_data(
    data: &ClientData,
    want_type: &str,
    want_challenge: &str,
    want_origin: &str,
) -> Result<(), AppError> {
    if data.typ != want_type {
        return Err(AppError::BadRequest(format!(
            "clientData.type must be '{want_type}'"
        )));
    }
    if data.challenge != want_challenge {
        return Err(AppError::BadRequest(
            "challenge does not match (stale or replayed ceremony)".into(),
        ));
    }
    if data.origin != want_origin {
        return Err(AppError::BadRequest(
            "clientData.origin does not match this server".into(),
        ));
    }
    if data.cross_origin {
        return Err(AppError::BadRequest(
            "cross-origin ceremonies are not supported".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// authenticatorData
// ---------------------------------------------------------------------------

/// The parts of `authenticatorData` this server reads.
struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    counter: u32,
    attested: Option<AttestedCredential<'a>>,
}

/// Present only when [`FLAG_AT`] is set.
struct AttestedCredential<'a> {
    credential_id: &'a [u8],
    cose_key: &'a [u8],
}

/// Layout: `rpIdHash(32) || flags(1) || counter(4, big-endian)`, then with
/// `FLAG_AT`: `aaguid(16) || idLen(2, big-endian) || id || COSE key`.
fn parse_auth_data(bytes: &[u8]) -> Result<AuthData<'_>, AppError> {
    if bytes.len() < 37 {
        return Err(AppError::BadRequest(
            "authenticator data is too short".into(),
        ));
    }
    let flags = bytes[32];
    let counter = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

    let mut attested = None;
    if flags & FLAG_AT != 0 {
        if bytes.len() < 55 {
            return Err(AppError::BadRequest(
                "attested credential data is too short".into(),
            ));
        }
        let id_len = u16::from_be_bytes([bytes[53], bytes[54]]) as usize;
        let id_start = 55;
        let id_end = id_start + id_len;
        if id_len == 0 {
            return Err(AppError::BadRequest("credential id is empty".into()));
        }
        if bytes.len() < id_end {
            return Err(AppError::BadRequest(
                "credential id runs past the authenticator data".into(),
            ));
        }
        attested = Some(AttestedCredential {
            credential_id: &bytes[id_start..id_end],
            cose_key: &bytes[id_end..],
        });
    }
    Ok(AuthData {
        rp_id_hash: &bytes[0..32],
        flags,
        counter,
        attested,
    })
}

/// The two flags every ceremony here requires: someone touched the device
/// and the authenticator confirmed the user. The options ask for
/// `userVerification: "required"`, so a missing UV means the client
/// ignored the request.
fn check_user_flags(flags: u8) -> Result<(), AppError> {
    if flags & FLAG_UP == 0 {
        return Err(AppError::BadRequest(
            "authenticator did not confirm user presence".into(),
        ));
    }
    if flags & FLAG_UV == 0 {
        return Err(AppError::BadRequest(
            "user verification (PIN or biometrics) is required".into(),
        ));
    }
    Ok(())
}

/// rpIdHash of `authData` must equal SHA-256 of the rpId we serve under;
/// anything else is a credential minted for a different domain.
fn check_rp_id(auth: &AuthData<'_>, rp_id: &str) -> Result<(), AppError> {
    let expected = Sha256::digest(rp_id.as_bytes());
    if auth.rp_id_hash != expected.as_slice() {
        return Err(AppError::BadRequest(
            "rpId hash mismatch (credential belongs to another origin)".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// COSE_Key
// ---------------------------------------------------------------------------

/// Integer or `None` for a CBOR value that should be an integer.
fn cbor_int(v: &Cbor) -> Option<i128> {
    match v {
        Cbor::Integer(n) => Some(i128::from(*n)),
        _ => None,
    }
}

/// Byte string or `None`.
fn cbor_bytes(v: &Cbor) -> Option<&[u8]> {
    match v {
        Cbor::Bytes(b) => Some(b),
        _ => None,
    }
}

/// Extract the credential's public key from its COSE_Key (CBOR): EC2
/// (`1: 2`), P-256 (`-1: 1`), ES256 (`3: -7`), x and y 32 bytes each.
/// Anything else falls outside this server's v1 scope (-7 only).
fn cose_verifying_key(cose: &[u8]) -> Result<VerifyingKey, AppError> {
    let value: Cbor = ciborium::de::from_reader(cose)
        .map_err(|_| AppError::BadRequest("credential public key is not valid CBOR".into()))?;
    let Cbor::Map(entries) = value else {
        return Err(AppError::BadRequest(
            "credential public key is not a CBOR map".into(),
        ));
    };

    // `Some(Some(v))`: key present with an integer value; `Some(None)`: key
    // present but of the wrong CBOR type; `None`: key missing.
    let lookup = |key: i128| {
        entries
            .iter()
            .find_map(|(k, v)| (cbor_int(k) == Some(key)).then(|| cbor_int(v)))
    };
    // x/y arrive as byte strings, so they need their own probe.
    let lookup_bytes = |key: i128| {
        entries
            .iter()
            .find(|(k, _)| cbor_int(k) == Some(key))
            .and_then(|(_, v)| cbor_bytes(v))
    };

    if lookup(1) != Some(Some(2)) {
        return Err(AppError::BadRequest(
            "unsupported credential key type (need EC2)".into(),
        ));
    }
    if lookup(3) != Some(Some(COSE_ALG_ES256)) {
        return Err(AppError::BadRequest(
            "unsupported credential algorithm (need ES256)".into(),
        ));
    }
    if lookup(-1) != Some(Some(1)) {
        return Err(AppError::BadRequest(
            "unsupported curve (need P-256)".into(),
        ));
    }
    let x = lookup_bytes(-2).unwrap_or_default();
    let y = lookup_bytes(-3).unwrap_or_default();
    if x.len() != 32 || y.len() != 32 {
        return Err(AppError::BadRequest(
            "credential public key coordinates are not 32 bytes".into(),
        ));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04); // uncompressed point
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| {
        AppError::BadRequest("credential public key is not a valid P-256 point".into())
    })
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

/// The transports a browser may report; anything else is dropped rather
/// than stored, so the settings list only ever shows real values.
const KNOWN_TRANSPORTS: [&str; 5] = ["usb", "nfc", "ble", "internal", "hybrid"];

fn sanitize_transports(list: Option<Vec<String>>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in list.into_iter().flatten() {
        let t = t.trim().to_ascii_lowercase();
        if KNOWN_TRANSPORTS.contains(&t.as_str()) && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Registration (attestation)
// ---------------------------------------------------------------------------

/// What a verified registration ceremony produced - the row to store.
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub transports: Vec<String>,
}

/// Verify a registration response end to end: clientData against the
/// stored challenge and our origin, attestation structure, rpId hash and
/// user flags, then the credential key itself (and, for `packed`, its
/// self-attestation signature). Returns the credential material to store.
pub fn verify_registration(
    rp_id: &str,
    origin: &str,
    challenge: &str,
    credential: &RegisterCredentialJson,
) -> Result<Registration, AppError> {
    let client = read_client_data(&credential.response.client_data_json, "clientDataJSON")?;
    check_client_data(&client, CLIENT_REGISTER, challenge, origin)?;

    let attestation = b64url_decode(&credential.response.attestation_object, "attestationObject")?;
    let (fmt, att_stmt, auth_data) = parse_attestation(&attestation)?;

    let auth = parse_auth_data(&auth_data)?;
    check_rp_id(&auth, rp_id)?;
    check_user_flags(auth.flags)?;
    let attested = auth.attested.ok_or_else(|| {
        AppError::BadRequest("no attested credential data in authenticator data".into())
    })?;
    // The credential's handle in the JSON envelope must be the very id the
    // attested data carries - a mismatch means the client pasted
    // inconsistent parts together.
    if credential.id != b64url(attested.credential_id) {
        return Err(AppError::BadRequest(
            "credential id does not match the attested credential".into(),
        ));
    }
    let public_key = cose_verifying_key(attested.cose_key)?;

    let client_hash = Sha256::digest(&client.raw);
    match fmt.as_str() {
        // We requested attestation: "none" - there is no statement to
        // check, the credential key itself is verified below by being
        // parseable and by every future assertion.
        "none" => {}
        // `packed` without x5c: the fresh credential signed its own
        // attestation - the same ECDSA verify as an assertion, with the
        // key that was just created.
        "packed" => verify_packed_self(&att_stmt, &auth_data, client_hash.as_slice(), &public_key)?,
        other => {
            return Err(AppError::BadRequest(format!(
                "unsupported attestation format '{other}' (need 'none' or self-signed 'packed')"
            )));
        }
    }

    Ok(Registration {
        credential_id: attested.credential_id.to_vec(),
        public_key: attested.cose_key.to_vec(),
        sign_count: auth.counter,
        transports: sanitize_transports(credential.response.transports.clone()),
    })
}

/// Split `attestationObject` (CBOR) into its three members: `fmt`,
/// `attStmt`, `authData`.
fn parse_attestation(raw: &[u8]) -> Result<(String, Cbor, Vec<u8>), AppError> {
    let value: Cbor = ciborium::de::from_reader(raw)
        .map_err(|_| AppError::BadRequest("attestationObject is not valid CBOR".into()))?;
    let Cbor::Map(entries) = value else {
        return Err(AppError::BadRequest(
            "attestationObject is not a CBOR map".into(),
        ));
    };
    let mut fmt = None;
    let mut att_stmt = None;
    let mut auth_data = None;
    for (k, v) in entries {
        if let Cbor::Text(name) = k {
            match name.as_str() {
                "fmt" => {
                    if let Cbor::Text(f) = v {
                        fmt = Some(f);
                    }
                }
                "attStmt" => att_stmt = Some(v),
                "authData" => {
                    if let Cbor::Bytes(b) = v {
                        auth_data = Some(b);
                    }
                }
                _ => {}
            }
        }
    }
    let missing = || AppError::BadRequest("attestationObject is missing a member".into());
    Ok((
        fmt.ok_or_else(missing)?,
        att_stmt.ok_or_else(missing)?,
        auth_data.ok_or_else(missing)?,
    ))
}

/// `packed` self-attestation: no certificate chain (an `x5c` present is
/// rejected - we asked for attestation: "none" and validating vendor chains
/// is out of scope), so the check is one ECDSA verify over
/// `authData || SHA256(clientDataJSON)` with the new credential's key.
fn verify_packed_self(
    att_stmt: &Cbor,
    auth_data: &[u8],
    client_hash: &[u8],
    key: &VerifyingKey,
) -> Result<(), AppError> {
    let Cbor::Map(entries) = att_stmt else {
        return Err(AppError::BadRequest(
            "packed attestation statement is not a CBOR map".into(),
        ));
    };
    let mut alg = None;
    let mut sig = None;
    for (k, v) in entries.iter() {
        if let Cbor::Text(name) = k {
            match name.as_str() {
                "alg" => alg = cbor_int(v),
                "sig" => sig = cbor_bytes(v).map(<[u8]>::to_vec),
                "x5c" => {
                    return Err(AppError::BadRequest(
                        "attestation certificates are not accepted; the authenticator should \
                         honor attestation: none"
                            .into(),
                    ));
                }
                _ => {}
            }
        }
    }
    if alg != Some(COSE_ALG_ES256) {
        return Err(AppError::BadRequest(
            "packed attestation algorithm must be ES256".into(),
        ));
    }
    let sig = sig.ok_or_else(|| {
        AppError::BadRequest("packed attestation statement has no signature".into())
    })?;
    let sig = Signature::from_der(&sig).map_err(|_| {
        AppError::BadRequest("packed attestation signature is not valid DER".into())
    })?;
    let mut message = auth_data.to_vec();
    message.extend_from_slice(client_hash);
    key.verify(&message, &sig)
        .map_err(|_| AppError::BadRequest("packed self-attestation did not verify".into()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Assertion (login)
// ---------------------------------------------------------------------------

/// What a verified assertion proved: the new counter value to store.
pub struct Assertion {
    pub sign_count: u32,
}

/// Verify a login assertion end to end: clientData against the stored
/// challenge and our origin, rpId hash and user flags, the optional
/// `userHandle` pin, the ECDSA signature over
/// `authenticatorData || SHA256(clientDataJSON)`, and finally the signature
/// counter (clone detection). `stored_*` come from the credential row.
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion(
    rp_id: &str,
    origin: &str,
    challenge: &str,
    user_id: i64,
    credential: &LoginCredentialJson,
    stored_public_key: &[u8],
    stored_count: i64,
) -> Result<Assertion, AppError> {
    let client = read_client_data(&credential.response.client_data_json, "clientDataJSON")?;
    check_client_data(&client, CLIENT_LOGIN, challenge, origin)?;

    let auth_data = b64url_decode(&credential.response.authenticator_data, "authenticatorData")?;
    let auth = parse_auth_data(&auth_data)?;
    check_rp_id(&auth, rp_id)?;
    check_user_flags(auth.flags)?;
    // Captured before `auth_data` is consumed by the signature message.
    let new_count = auth.counter;

    // userHandle, when the client sends one, must be the id we issued at
    // registration: it pins the assertion to the account even if a foreign
    // credential id were pasted into the request.
    if let Some(handle) = &credential.response.user_handle {
        let raw = b64url_decode(handle, "userHandle")?;
        if raw != user_id.to_le_bytes() {
            return Err(AppError::Unauthorized);
        }
    }

    // The signature covers authenticatorData || SHA256(clientDataJSON);
    // `verify` hashes that message internally with SHA-256. The stored blob
    // is the COSE_Key as attested, so the same parse as registration runs
    // here - a failure is server-side corruption, not a client error.
    let key = cose_verifying_key(stored_public_key).map_err(|_| {
        AppError::Internal(anyhow::anyhow!(
            "stored passkey public key is not a usable COSE key"
        ))
    })?;
    let sig_raw = b64url_decode(&credential.response.signature, "signature")?;
    let sig = Signature::from_der(&sig_raw).map_err(|_| AppError::Unauthorized)?;
    let client_hash = Sha256::digest(&client.raw);
    let mut message = auth_data;
    message.extend_from_slice(client_hash.as_slice());
    key.verify(&message, &sig)
        .map_err(|_| AppError::Unauthorized)?;

    // Clone detection: a nonzero counter must strictly advance. Authenticators
    // that never count (platform passkeys commonly stay at 0) are exempt -
    // that is the spec's rule, not a shortcut.
    if stored_count > 0 && new_count > 0 && i64::from(new_count) <= stored_count {
        return Err(AppError::BadRequest(
            "passkey counter went backwards (possible clone; re-register the device if this \
             persists)"
                .into(),
        ));
    }
    Ok(Assertion {
        sign_count: new_count,
    })
}
