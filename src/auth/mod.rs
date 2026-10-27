use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::error::AppError;
use crate::models::User;
use crate::web::state::SharedState;

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "fxcloud_session";

/// Argon2id parameters for **new** login hashes, and the floor the client-side
/// storage KDF has to clear at setup.
///
/// DECISION 3 (ENCRYPTION.md 5.7) reuses the login password as the default
/// storage secret, which turns the database's login hash into an offline
/// shortcut to the encryption key. Raising the login cost is therefore a
/// *condition* of that decision, not an optimisation: the login hash must be
/// at least as expensive as the client KDF we would otherwise demand.
///
/// 64 MiB with three passes is roughly five times the crate's default
/// (~180 ms per hash+verify here), and the same numbers are enforced as the
/// floor on `kdf_params` when key material is uploaded
/// ([`crate::db::Db::save_user_keys`]) so a weak client cannot quietly lower
/// the bar. Hashes already stored keep their embedded parameters - verification
/// reads them from the hash - so no existing account needs migrating.
pub const LOGIN_KDF_M_KIB: u32 = 65536;
pub const LOGIN_KDF_T: u32 = 3;
pub const LOGIN_KDF_P: u32 = 1;

/// Floor for `kdf_params` in `POST /api/keys/setup`: Argon2id at or above the
/// login cost. Returned verbatim in the rejection so a client that picked the
/// wrong numbers can show the user what the server expects.
pub const KDF_FLOOR_MESSAGE: &str =
    "kdf_params must be argon2id with m >= 65536 KiB, t >= 3, p >= 1 (see /api/keys/setup)";

/// The login hasher: explicit parameters instead of [`Argon2::default`], whose
/// 19 MiB / t=2 is OWASP's *minimum* rather than DECISION 3's requirement.
fn login_hasher() -> Result<Argon2<'static>, AppError> {
    let params = Params::new(LOGIN_KDF_M_KIB, LOGIN_KDF_T, LOGIN_KDF_P, Some(32))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("argon2 params rejected: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash a plaintext password using Argon2id at [`LOGIN_KDF_*`] cost.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    login_hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("password hashing failed: {e}")))
}

/// Verify a plaintext password against an encoded Argon2 hash.
///
/// The parameters come from the stored hash, not from [`login_hasher`], so
/// accounts created before the DECISION 3 raise keep verifying at their own
/// (lower) cost until their password is next changed.
pub fn verify_password(password: &str, encoded: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ---------------------------------------------------------------------------
// Basic-auth verification cache
// ---------------------------------------------------------------------------

/// How long a cached Basic-auth verdict stays valid.
///
/// Long enough that a desktop sync client re-authenticates about once a
/// minute instead of once per request, short enough that a revoked password
/// stops working within a bounded window (and a *changed* one stops working
/// immediately - see the hash comparison below).
const BASIC_CACHE_TTL: Duration = Duration::from_secs(60);

/// Upper bound on cached entries, so a flood of distinct credentials cannot
/// grow the map without limit. Reaching it evicts everything rather than the
/// oldest item: the cost is one Argon2id run per client, which is the state we
/// started in anyway.
const BASIC_CACHE_MAX: usize = 4096;

/// One cached verdict: the stored hash it was checked against, and when.
struct BasicCacheEntry {
    password_hash: String,
    at: Instant,
}

static BASIC_CACHE: LazyLock<Mutex<HashMap<u64, BasicCacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Cheap, non-cryptographic fingerprint of a credential.
///
/// Only ever used as a cache key for verdicts that *already verified once*,
/// never as an authenticator: a hit still has to match the stored password
/// hash, and reaching a hit at all requires knowing a password that passed
/// verification for this exact username. It keeps the presented password out
/// of the map, which is the whole reason for not storing the pair directly.
fn basic_cache_key(username: &str, password: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    username.hash(&mut hasher);
    password.hash(&mut hasher);
    hasher.finish()
}

/// Look for a recent successful verification of `username` + `password`
/// against `password_hash`.
fn basic_cache_get(key: u64, password_hash: &str) -> bool {
    let mut cache = BASIC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    match cache.get(&key) {
        Some(entry)
            if entry.at.elapsed() < BASIC_CACHE_TTL && entry.password_hash == password_hash =>
        {
            true
        }
        // Expired, or the account's hash changed (password reset, rehash on
        // login): drop it so the next request pays the real cost once more.
        Some(_) => {
            cache.remove(&key);
            false
        }
        None => false,
    }
}

/// Record a successful verification.
fn basic_cache_put(key: u64, password_hash: &str) {
    let mut cache = BASIC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= BASIC_CACHE_MAX {
        cache.clear();
    }
    cache.insert(
        key,
        BasicCacheEntry {
            password_hash: password_hash.to_string(),
            at: Instant::now(),
        },
    );
}

/// Extract the raw session token from the `Cookie` header, if present.
pub fn token_from_cookie_header(header: Option<&str>) -> Option<String> {
    let header = header?;
    for pair in header.split(';') {
        let mut kv = pair.trim().splitn(2, '=');
        // A token with no `=` (`Cookie: secure; fxcloud_session=…`) is not a
        // name/value pair at all. Skipping that pair keeps the scan going:
        // bailing out here would silently drop the session of every client
        // that sends a valueless cookie before ours.
        let (Some(key), Some(value)) = (kv.next(), kv.next()) else {
            continue;
        };
        if key.trim() == SESSION_COOKIE {
            return Some(value.trim().to_string());
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

/// Administrator variant of [`AuthUser`], used by the user-administration
/// routes under `/api/admin`.
///
/// Resolves the session exactly like `AuthUser` (same 401 on a missing,
/// invalid or expired cookie, same rejection for a deactivated account) and
/// additionally requires `is_admin`. A signed-in account without the flag is
/// rejected with `403 Forbidden` -- authenticated, but not permitted.
pub struct AdminUser(pub User);

impl AdminUser {
    pub fn id(&self) -> i64 {
        self.0.id
    }
}

impl FromRequestParts<SharedState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // Reuse the normal auth resolution, then gate on the admin flag.
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;
        if !user.is_admin {
            return Err(AppError::Forbidden);
        }
        Ok(AdminUser(user))
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

    // WebDAV resends these credentials on every single request, so paying the
    // full DECISION 3 Argon2id cost (~120 ms) for each PROPFIND would make
    // desktop sync visibly sluggish. A recent, still-valid verdict short-
    // circuits that; everything else falls through to a real verification.
    let cache_key = basic_cache_key(username.trim(), password);
    if !basic_cache_get(cache_key, &found.password_hash) {
        if !verify_password(password, &found.password_hash) {
            return Err(AppError::Unauthorized);
        }
        basic_cache_put(cache_key, &found.password_hash);
    }
    if !found.user.is_active {
        return Err(AppError::InactiveAccount);
    }
    Ok(found.user)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(value: &str) -> String {
        format!("{SESSION_COOKIE}={value}")
    }

    #[test]
    fn no_header_means_no_session() {
        assert_eq!(token_from_cookie_header(None), None);
        assert_eq!(token_from_cookie_header(Some("")), None);
        assert_eq!(token_from_cookie_header(Some("other=1")), None);
        assert_eq!(token_from_cookie_header(Some(";")), None);
    }

    #[test]
    fn finds_our_cookie_among_the_others() {
        let mixed = format!("a=1; {} ; b=2", session("deadbeef"));
        assert_eq!(
            token_from_cookie_header(Some(&mixed)).as_deref(),
            Some("deadbeef")
        );
        assert_eq!(
            token_from_cookie_header(Some(&session("solo"))).as_deref(),
            Some("solo")
        );
    }

    #[test]
    fn a_valueless_token_before_ours_does_not_hide_it() {
        // Regression: the scan used to abort at the first token without `=`,
        // so `Cookie: secure; fxcloud_session=…` logged the user straight out.
        assert_eq!(
            token_from_cookie_header(Some(&format!("secure; {}", session("abc")))).as_deref(),
            Some("abc")
        );
        assert_eq!(
            token_from_cookie_header(Some(&format!("; {}", session("abc")))).as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn whitespace_around_the_pair_is_tolerated() {
        let spaced = format!("  a=1 ;  {}  ", session(" tok "));
        assert_eq!(
            token_from_cookie_header(Some(&spaced)).as_deref(),
            Some("tok")
        );
    }

    #[test]
    fn lookalike_names_are_not_ours() {
        assert_eq!(token_from_cookie_header(Some("x_fxcloud_session=1")), None);
        assert_eq!(
            token_from_cookie_header(Some(&format!("pre{SESSION_COOKIE}=1"))),
            None
        );
        assert_eq!(
            token_from_cookie_header(Some(&format!("{SESSION_COOKIE}x=1"))),
            None
        );
    }

    #[test]
    fn the_login_hash_uses_the_documented_cost() {
        // Guarded from both sides: fxcrypto.js holds the same numbers, and
        // db/keys.rs enforces them on every key setup and rewrap.
        assert_eq!(LOGIN_KDF_M_KIB, 65536);
        assert_eq!(LOGIN_KDF_T, 3);
        assert_eq!(LOGIN_KDF_P, 1);
        assert!(KDF_FLOOR_MESSAGE.contains("65536"));
    }
}
