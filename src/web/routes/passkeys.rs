//! Passkey routes: the four WebAuthn ceremony endpoints plus the device
//! list the settings dialog manages.
//!
//! Ceremony endpoints are named `.../start` (issue a bound, single-use
//! challenge) and `.../finish` (redeem it); the login pair is public, the
//! register pair and the `/me/passkeys` device management require a
//! session. Cookie and session handling is shared with the password flow
//! in [`super::auth`].

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use super::auth::session_cookie;
use crate::auth::AuthUser;
use crate::error::AppError;
use crate::models::{
    PasskeyInfo, PasskeyLoginFinishRequest, PasskeyLoginStartRequest, PasskeyRegisterFinishRequest,
    RenamePasskeyRequest,
};
use crate::web::state::{CeremonyKind, SharedState};
use crate::webauthn;

/// Milliseconds echoed as the ceremony `timeout`; matches the challenge TTL
/// enforced server-side in [`SharedState::new_ceremony`].
const CEREMONY_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// Default device name when registration finishes without a label.
const DEFAULT_LABEL: &str = "Passkey";

/// Label ceiling, same 100 characters display names get in `update_me`.
const MAX_LABEL_CHARS: usize = 100;

/// Trimmed, non-empty, bounded - the one rule both label inputs follow.
fn check_label(raw: &str) -> Result<String, AppError> {
    let label = raw.trim().to_string();
    if label.is_empty() {
        return Err(AppError::BadRequest("label cannot be empty".into()));
    }
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(AppError::BadRequest(format!(
            "label too long (max {MAX_LABEL_CHARS} characters)"
        )));
    }
    Ok(label)
}

/// POST /api/passkeys/register/start - begin adding a device (settings).
///
/// The challenge is bound to the calling session and single-use, and
/// `excludeCredentials` tells the authenticator not to mint a second
/// credential for a device this account already registered.
pub async fn register_start(
    State(state): State<SharedState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Result<Json<Value>, AppError> {
    // The origin check inside runs before any challenge exists, so a
    // misconfigured deployment fails here instead of at finish.
    let (_origin, rp_id) = webauthn::origin_and_rp(&headers, &state.config)?;
    let existing = state.db.passkey_credential_ids(user.id()).await?;
    let challenge = state.new_ceremony(CeremonyKind::Register, Some(user.id()));

    let exclude = existing
        .iter()
        .map(|id| json!({ "type": "public-key", "id": webauthn::b64url(id) }))
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "challenge": challenge,
        "rp": { "id": rp_id, "name": "fxcloud" },
        "user": {
            "id": webauthn::b64url(&user.id().to_le_bytes()),
            "name": user.0.username,
            "displayName": user.0.display_name,
        },
        "pubKeyCredParams": [{ "type": "public-key", "alg": webauthn::COSE_ALG_ES256 }],
        "timeout": CEREMONY_TIMEOUT_MS,
        "excludeCredentials": exclude,
        "authenticatorSelection": { "userVerification": "required" },
        "attestation": "none",
    })))
}

/// POST /api/passkeys/register/finish - redeem the registration challenge
/// and store the attested credential. Returns the new row (`201`).
pub async fn register_finish(
    State(state): State<SharedState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(req): Json<PasskeyRegisterFinishRequest>,
) -> Result<(StatusCode, Json<PasskeyInfo>), AppError> {
    // Derive first: a deployment that cannot build an origin must not burn
    // a challenge on the way to an error.
    let (origin, rp_id) = webauthn::origin_and_rp(&headers, &state.config)?;
    // Read the challenge out of clientData to find this response's
    // ceremony; the full semantic comparison runs inside verify against
    // the stored copy.
    let client =
        webauthn::read_client_data(&req.credential.response.client_data_json, "clientDataJSON")?;
    let Some(ceremony) = state.take_ceremony(&client.challenge, CeremonyKind::Register) else {
        tracing::warn!(
            user = %user.0.username,
            "registration refused: challenge unknown or older than the ceremony timeout"
        );
        return Err(AppError::Unauthorized);
    };
    if ceremony.user_id != Some(user.id()) {
        // The session changed underneath the ceremony - restart it.
        tracing::warn!(
            user = %user.0.username,
            "registration refused: the session changed underneath the ceremony"
        );
        return Err(AppError::Unauthorized);
    }

    let result =
        webauthn::verify_registration(&rp_id, &origin, &ceremony.challenge, &req.credential)
            .map_err(|err| {
                tracing::warn!(
                    user = %user.0.username,
                    %origin,
                    %rp_id,
                    %err,
                    "registration refused by verification"
                );
                err
            })?;
    let label = check_label(req.label.as_deref().unwrap_or(DEFAULT_LABEL))?;

    let info = state
        .db
        .insert_passkey(
            user.id(),
            result.credential_id,
            result.public_key,
            i64::from(result.sign_count),
            result.transports,
            label,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(info)))
}

/// POST /api/passkeys/login/start - challenge for the named account.
///
/// The response has identical shape for an unknown name, an account
/// without passkeys and a real one: the latter two both get a single
/// random, unusable `allowCredentials` entry instead of an empty list, so
/// the endpoint cannot be used to enumerate accounts or to learn whether a
/// name has devices registered.
pub async fn login_start(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<PasskeyLoginStartRequest>,
) -> Result<Json<Value>, AppError> {
    // Fails fast on a deployment whose origin cannot be derived - before
    // any challenge exists. `origin` itself is only consumed at finish.
    let (_origin, rp_id) = webauthn::origin_and_rp(&headers, &state.config)?;
    let username = req.username.trim().to_lowercase();
    let found = state.db.find_user_by_username(username).await?;
    let ids = match &found {
        Some(f) => state.db.passkey_credential_ids(f.user.id).await?,
        None => Vec::new(),
    };
    let allow: Vec<Value> = if ids.is_empty() {
        vec![json!({
            "type": "public-key",
            "id": webauthn::b64url(&webauthn::random_bytes(32)),
        })]
    } else {
        ids.iter()
            .map(|id| json!({ "type": "public-key", "id": webauthn::b64url(id) }))
            .collect()
    };

    let challenge = state.new_ceremony(CeremonyKind::Login, found.as_ref().map(|f| f.user.id));
    Ok(Json(json!({
        "challenge": challenge,
        "rpId": rp_id,
        "timeout": CEREMONY_TIMEOUT_MS,
        "allowCredentials": allow,
        "userVerification": "required",
    })))
}

/// POST /api/passkeys/login/finish - verify the assertion and open a
/// session. Mirrors the password login's ordering exactly: the credential
/// is checked first, then the account state (an inactive account gets 403
/// only with a valid credential), then the session cookie is minted.
pub async fn login_finish(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<PasskeyLoginFinishRequest>,
) -> Result<Response, AppError> {
    let (origin, rp_id) = webauthn::origin_and_rp(&headers, &state.config)?;
    let client =
        webauthn::read_client_data(&req.credential.response.client_data_json, "clientDataJSON")?;
    let Some(ceremony) = state.take_ceremony(&client.challenge, CeremonyKind::Login) else {
        tracing::warn!("sign-in refused: challenge unknown or older than the ceremony timeout");
        return Err(AppError::Unauthorized);
    };
    let Some(user_id) = ceremony.user_id else {
        // The challenge was issued for a name nobody has.
        tracing::warn!("sign-in refused: the challenge was issued for an unknown account");
        return Err(AppError::Unauthorized);
    };

    let credential_id = webauthn::b64url_decode(&req.credential.id, "credential id")?;
    let Some(record) = state
        .db
        .find_passkey_by_credential_id(credential_id)
        .await?
    else {
        tracing::warn!(
            user_id,
            "sign-in refused: no credential with this id is registered"
        );
        return Err(AppError::Unauthorized);
    };
    if record.user_id != user_id {
        // A credential of another account pasted into this ceremony - do
        // not switch users silently.
        tracing::warn!(
            ceremony_user = user_id,
            credential_user = record.user_id,
            "sign-in refused: the credential belongs to another account"
        );
        return Err(AppError::Unauthorized);
    }

    let assertion = webauthn::verify_assertion(
        &rp_id,
        &origin,
        &ceremony.challenge,
        user_id,
        &req.credential,
        &record.public_key,
        record.sign_count,
    )
    .map_err(|err| {
        tracing::warn!(user_id, %origin, %rp_id, %err, "sign-in refused by verification");
        err
    })?;
    state
        .db
        .touch_passkey(record.id, i64::from(assertion.sign_count))
        .await?;

    let user = state
        .db
        .find_user_by_id(user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !user.is_active {
        tracing::warn!(
            user = %user.username,
            "sign-in refused: the account is not activated yet"
        );
        return Err(AppError::InactiveAccount);
    }
    let token = state
        .db
        .create_session(user.id, state.config.session_ttl)
        .await?;
    let body = Json(json!({ "user": user }));
    Ok((
        [(
            header::SET_COOKIE,
            session_cookie(&token, state.config.session_ttl, state.config.secure_cookie),
        )],
        body,
    )
        .into_response())
}

/// GET /api/me/passkeys - every device of the signed-in account.
pub async fn list(
    State(state): State<SharedState>,
    user: AuthUser,
) -> Result<Json<Vec<PasskeyInfo>>, AppError> {
    Ok(Json(state.db.list_passkeys(user.id()).await?))
}

/// PATCH /api/me/passkeys/:id - rename one device.
pub async fn rename(
    State(state): State<SharedState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Json(req): Json<RenamePasskeyRequest>,
) -> Result<Json<PasskeyInfo>, AppError> {
    let label = check_label(&req.label)?;
    Ok(Json(state.db.rename_passkey(user.id(), id, label).await?))
}

/// DELETE /api/me/passkeys/:id - unregister one device.
///
/// Removing the last passkey is allowed: the password keeps working, and
/// cutting off a lost device should never be blocked by a policy question.
pub async fn remove(
    State(state): State<SharedState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    state.db.delete_passkey(user.id(), id).await?;
    Ok(Json(json!({ "ok": true })))
}
