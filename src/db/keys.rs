//! Storage for per-account client-side encryption key material.
//!
//! Everything in this module is *write-through opaque*: blobs arrive already
//! wrapped by the client, are stored as bytes, and leave unchanged. There is
//! no operation here that can tell a valid key record from random bytes, and
//! none needs one - the whole point of ENCRYPTION.md 5.2 is that the server is
//! not part of the trust path.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use crate::auth::{KDF_FLOOR_MESSAGE, LOGIN_KDF_M_KIB, LOGIN_KDF_P, LOGIN_KDF_T};
use crate::error::AppError;
use crate::models::{PublicKeyInfo, RewrapKeysRequest, SetupKeysRequest, UserKeys};

use super::Db;

/// Enforce the KDF parameter floor on a client's `kdf_params`.
///
/// DECISION 3 makes the login password the default storage secret, so the
/// *client* Argon2id run is what stands between a database dump and the files.
/// Accepting whatever numbers the client claims would let a careless or
/// malicious frontend store the account root key behind a 1 KiB hash; setup
/// therefore rejects anything weaker than the login hash itself. The stored
/// value doubles as the record: once it is on the row, weak parameters are
/// detectable by inspection rather than by trust.
fn enforce_kdf_floor(value: &serde_json::Value) -> Result<(), AppError> {
    let obj = value
        .as_object()
        .ok_or_else(|| AppError::BadRequest("kdf_params must be a JSON object".into()))?;

    let kdf = obj.get("kdf").and_then(|v| v.as_str()).unwrap_or_default();
    if !kdf.eq_ignore_ascii_case("argon2id") {
        return Err(AppError::BadRequest(KDF_FLOOR_MESSAGE.into()));
    }

    let num = |key: &str| -> Option<u64> {
        obj.get(key)
            .and_then(|v| v.as_u64())
            .or_else(|| obj.get(key).and_then(|v| v.as_f64()).map(|f| f as u64))
    };
    let (Some(m), Some(t), Some(p)) = (num("m"), num("t"), num("p")) else {
        return Err(AppError::BadRequest(KDF_FLOOR_MESSAGE.into()));
    };

    if m < u64::from(LOGIN_KDF_M_KIB) || t < u64::from(LOGIN_KDF_T) || p < u64::from(LOGIN_KDF_P) {
        return Err(AppError::BadRequest(format!(
            "kdf_params too weak: m={m} t={t} p={p}; {KDF_FLOOR_MESSAGE}"
        )));
    }
    Ok(())
}

/// Decode a base64 request field, rejecting empty input with a message that
/// names the field (the client always knows which one it got wrong).
fn blob(field: &str, value: &str) -> Result<Vec<u8>, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("{field} is empty")));
    }
    BASE64
        .decode(value)
        .map_err(|_| AppError::BadRequest(format!("{field} is not valid base64")))
}

fn row_to_keys(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserKeys> {
    let created_at: String = row.get("created_at")?;
    let updated_at: String = row.get("updated_at")?;
    let kdf_params: String = row.get("kdf_params")?;
    let params_value = serde_json::from_str(&kdf_params).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(UserKeys {
        user_id: row.get("user_id")?,
        public_key: BASE64.encode(row.get::<_, Vec<u8>>("public_key")?),
        private_key_wrapped: BASE64.encode(row.get::<_, Vec<u8>>("private_key_wrapped")?),
        wrapped_ark: BASE64.encode(row.get::<_, Vec<u8>>("wrapped_ark")?),
        wrapped_root_key: BASE64.encode(row.get::<_, Vec<u8>>("wrapped_root_key")?),
        wrapped_ark_recovery: BASE64.encode(row.get::<_, Vec<u8>>("wrapped_ark_recovery")?),
        kdf_salt: BASE64.encode(row.get::<_, Vec<u8>>("kdf_salt")?),
        kdf_params: params_value,
        fingerprint: row.get("fingerprint")?,
        created_at: super::user::parse_ts(&created_at, 7)?,
        updated_at: super::user::parse_ts(&updated_at, 8)?,
    })
}

const KEY_COLS: &str = "user_id, public_key, private_key_wrapped, wrapped_ark, wrapped_root_key, \
     wrapped_ark_recovery, kdf_salt, kdf_params, fingerprint, created_at, updated_at";

impl Db {
    /// Store an account's key material at encryption setup.
    ///
    /// Idempotent in the way a network call has to be: re-posting the *same*
    /// material succeeds, so a client that lost the response can simply retry.
    /// A *different* payload for an account that is already set up is a 409 -
    /// overwriting it would strand every file key already wrapped under the
    /// old root folder key, and no server-side operation can detect that.
    pub async fn save_user_keys(
        &self,
        user_id: i64,
        req: SetupKeysRequest,
    ) -> Result<(), AppError> {
        // Validate before touching the database so a half-decoded payload
        // cannot leave a row behind that only the first half of.
        let public_key = blob("public_key", &req.public_key)?;
        let private_key_wrapped = blob("private_key_wrapped", &req.private_key_wrapped)?;
        let wrapped_ark = blob("wrapped_ark", &req.wrapped_ark)?;
        let wrapped_root_key = blob("wrapped_root_key", &req.wrapped_root_key)?;
        let wrapped_ark_recovery = blob("wrapped_ark_recovery", &req.wrapped_ark_recovery)?;
        let kdf_salt = blob("kdf_salt", &req.kdf_salt)?;
        if req.fingerprint.trim().is_empty() {
            return Err(AppError::BadRequest("fingerprint is empty".into()));
        }
        enforce_kdf_floor(&req.kdf_params)?;
        let fingerprint = req.fingerprint.trim().to_string();
        let kdf_params = serde_json::to_string(&req.kdf_params)
            .map_err(|e| AppError::BadRequest(format!("bad kdf_params: {e}")))?;

        self.run(move |conn| {
            let existing: Option<(Vec<u8>, String)> = conn
                .query_row(
                    "SELECT public_key, fingerprint FROM user_keys WHERE user_id = ?1",
                    params![user_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;

            if let Some((old_public, old_fingerprint)) = existing {
                if old_public == public_key && old_fingerprint == fingerprint {
                    return Ok(());
                }
                return Err(AppError::Conflict(
                    "encryption is already set up for this account".into(),
                ));
            }

            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO user_keys (user_id, public_key, private_key_wrapped, wrapped_ark,
                                        wrapped_root_key, wrapped_ark_recovery, kdf_salt,
                                        kdf_params, fingerprint, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
                params![
                    user_id,
                    public_key,
                    private_key_wrapped,
                    wrapped_ark,
                    wrapped_root_key,
                    wrapped_ark_recovery,
                    kdf_salt,
                    kdf_params,
                    fingerprint,
                    now
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// The account's own key material, or `None` while it is not set up yet.
    pub async fn get_own_keys(&self, user_id: i64) -> Result<Option<UserKeys>, AppError> {
        self.run(move |conn| {
            let found = conn
                .query_row(
                    &format!("SELECT {KEY_COLS} FROM user_keys WHERE user_id = ?1"),
                    params![user_id],
                    row_to_keys,
                )
                .optional()?;
            Ok(found)
        })
        .await
    }

    /// Rewrap the ARK under a new passphrase-derived KEK (ENCRYPTION.md 5.7).
    ///
    /// This is the whole cost of a passphrase change: one 32-byte value.
    /// `private_key_wrapped` and `wrapped_root_key` are deliberately not
    /// touched, because they hang off the ARK rather than off the KEK.
    pub async fn rewrap_keys(&self, user_id: i64, req: RewrapKeysRequest) -> Result<(), AppError> {
        let wrapped_ark = blob("wrapped_ark", &req.wrapped_ark)?;
        let kdf_salt = blob("kdf_salt", &req.kdf_salt)?;
        // A rewrap may not become the moment the floor is dropped: the new
        // parameters have to clear it just like the ones at setup.
        enforce_kdf_floor(&req.kdf_params)?;
        let kdf_params = serde_json::to_string(&req.kdf_params)
            .map_err(|e| AppError::BadRequest(format!("bad kdf_params: {e}")))?;

        self.run(move |conn| {
            let changed = conn.execute(
                "UPDATE user_keys
                    SET wrapped_ark = ?2, kdf_salt = ?3, kdf_params = ?4,
                        updated_at = ?5
                  WHERE user_id = ?1",
                params![
                    user_id,
                    wrapped_ark,
                    kdf_salt,
                    kdf_params,
                    Utc::now().to_rfc3339()
                ],
            )?;
            if changed == 0 {
                return Err(AppError::Conflict(
                    "encryption is not set up for this account".into(),
                ));
            }
            Ok(())
        })
        .await
    }

    /// Another account's published public key and fingerprint.
    ///
    /// The only piece of key material the server ever shows to a third party,
    /// and even that is useless without the out-of-band fingerprint check of
    /// ENCRYPTION.md 5.6.
    pub async fn get_public_key(
        &self,
        username: String,
    ) -> Result<Option<PublicKeyInfo>, AppError> {
        self.run(move |conn| {
            let found = conn
                .query_row(
                    "SELECT u.username, k.public_key, k.fingerprint
                       FROM user_keys k JOIN users u ON u.id = k.user_id
                      WHERE u.username = ?1",
                    params![username],
                    |r| {
                        Ok(PublicKeyInfo {
                            username: r.get(0)?,
                            public_key: BASE64.encode(r.get::<_, Vec<u8>>(1)?),
                            fingerprint: r.get(2)?,
                        })
                    },
                )
                .optional()?;
            Ok(found)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn params(m: u64, t: u64, p: u64) -> Value {
        json!({"kdf": "argon2id", "m": m, "t": t, "p": p})
    }

    #[test]
    fn the_floor_exactly_is_accepted_and_stronger_is_too() {
        assert!(enforce_kdf_floor(&params(
            LOGIN_KDF_M_KIB.into(),
            LOGIN_KDF_T.into(),
            LOGIN_KDF_P.into()
        ))
        .is_ok());
        assert!(enforce_kdf_floor(&params(131072, 4, 2)).is_ok());
    }

    #[test]
    fn every_number_below_the_floor_is_refused() {
        let too_weak = [(65535, 3, 1), (65536, 2, 1), (65536, 3, 0)];
        for (m, t, p) in too_weak {
            let claimed = params(m, t, p);
            assert!(
                enforce_kdf_floor(&claimed).is_err(),
                "accepted m={m} t={t} p={p}"
            );
        }
    }

    #[test]
    fn another_hash_function_is_refused_even_with_enough_memory() {
        for kdf in ["argon2i", "argon2d", "scrypt", ""] {
            let claimed = json!({"kdf": kdf, "m": 65536, "t": 3, "p": 1});
            assert!(enforce_kdf_floor(&claimed).is_err(), "accepted kdf={kdf:?}");
        }
    }

    #[test]
    fn shapes_that_are_not_a_parameter_object_are_refused() {
        assert!(enforce_kdf_floor(&json!("65536")).is_err());
        assert!(enforce_kdf_floor(&json!(null)).is_err());
        assert!(enforce_kdf_floor(&json!([])).is_err());
        // A missing number is an absent claim, not a defaulted one.
        assert!(enforce_kdf_floor(&json!({"kdf": "argon2id", "m": 65536, "t": 3})).is_err());
        // Nor is a number wearing the wrong JSON type.
        assert!(
            enforce_kdf_floor(&json!({"kdf": "argon2id", "m": "65536", "t": 3, "p": 1})).is_err()
        );
    }

    #[test]
    fn a_float_from_a_javascript_client_is_still_a_number() {
        // JavaScript hands integers back as JSON numbers; a client that did
        // the arithmetic in floating point must not be refused over a decimal
        // point. This is the fallback path of `num`.
        assert!(
            enforce_kdf_floor(&json!({"kdf": "argon2id", "m": 65536.0, "t": 3.0, "p": 1.0}))
                .is_ok()
        );
    }

    #[test]
    fn the_rejection_names_the_numbers_it_did_not_like() {
        let err = enforce_kdf_floor(&params(1024, 1, 1)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("m=1024"), "got: {msg}");
        assert!(msg.contains("t=1"), "got: {msg}");
        assert!(msg.contains(KDF_FLOOR_MESSAGE), "got: {msg}");
    }

    #[test]
    fn the_floor_is_the_same_cost_as_the_login_hash() {
        // fxcrypto.js carries these three numbers as KDF_FLOOR. If one side
        // moves without the other, a passphrase could open key material that
        // the server's own login hash would have refused as too weak.
        assert_eq!(LOGIN_KDF_M_KIB, 65536);
        assert_eq!(LOGIN_KDF_T, 3);
        assert_eq!(LOGIN_KDF_P, 1);
    }
}
