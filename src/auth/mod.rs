use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::error::AppError;
use crate::models::User;
use crate::web::state::SharedState;

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "fxcloud_session";

/// Hash a plaintext password using Argon2id.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("password hashing failed: {e}")))
}

/// Verify a plaintext password against an encoded Argon2 hash.
pub fn verify_password(password: &str, encoded: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Extract the raw session token from the `Cookie` header, if present.
pub fn token_from_cookie_header(header: Option<&str>) -> Option<String> {
    let header = header?;
    for pair in header.split(';') {
        let mut kv = pair.trim().splitn(2, '=');
        let key = kv.next()?.trim();
        let value = kv.next()?.trim();
        if key == SESSION_COOKIE {
            return Some(value.to_string());
        }
    }
    None
}

/// Authenticated user attached to a request by [`AuthUser`].
pub struct AuthUser(pub User);

impl AuthUser {
    pub fn id(&self) -> i64 {
        self.0.id
    }
}

/// Axum extractor that resolves the session cookie into a logged-in user.
///
/// Rejects the request with `401 Unauthorized` when the cookie is missing,
/// invalid, or expired, and also when the account has been deactivated in the
/// meantime — deactivating a user cuts off access right away, open sessions
/// included.
impl FromRequestParts<SharedState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let token = token_from_cookie_header(
            parts.headers.get(axum::http::header::COOKIE).and_then(|v| v.to_str().ok()),
        )
        .ok_or(AppError::Unauthorized)?;

        let user_id = state
            .db
            .session_user_id(token)
            .await?
            .ok_or(AppError::Unauthorized)?;

        let user = state
            .db
            .find_user_by_id(user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;

        if !user.is_active {
            return Err(AppError::Unauthorized);
        }

        Ok(AuthUser(user))
    }
}

/// Authenticate a request via HTTP Basic auth (used by WebDAV clients).
///
/// Returns the logged-in user on success; `Err(AppError::Unauthorized)` on any
/// missing/malformed/invalid credential and `Err(AppError::InactiveAccount)`
/// when the credentials are correct but the account is switched off. The
/// caller is responsible for adding a `WWW-Authenticate: Basic` header to the
/// 401 response.
pub async fn authenticate_basic(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<User, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
        .ok_or(AppError::Unauthorized)?;

    let decoded = BASE64
        .decode(encoded.trim())
        .map_err(|_| AppError::Unauthorized)?;
    let creds = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
    let (username, password) = creds.split_once(':').ok_or(AppError::Unauthorized)?;

    let found = state
        .db
        .find_user_by_username(username.trim().to_lowercase())
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !verify_password(password, &found.password_hash) {
        return Err(AppError::Unauthorized);
    }
    if !found.user.is_active {
        return Err(AppError::InactiveAccount);
    }
    Ok(found.user)
}
