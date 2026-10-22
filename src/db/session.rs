use chrono::{Duration, Utc};
use rusqlite::{params, OptionalExtension};

use crate::error::AppError;

use super::Db;

impl Db {
    /// Create a new session for `user_id` that expires after `ttl_secs`.
    /// Returns the opaque session token (stored as a cookie on the client).
    pub async fn create_session(&self, user_id: i64, ttl_secs: i64) -> Result<String, AppError> {
        self.run(move |conn| {
            let token = super::session::generate_token();
            let now = Utc::now();
            let expires = now + Duration::seconds(ttl_secs);
            conn.execute(
                "INSERT INTO sessions (id, user_id, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    token,
                    user_id,
                    now.to_rfc3339(),
                    expires.to_rfc3339()
                ],
            )?;
            Ok(token)
        })
        .await
    }

    /// Resolve a session token to its user id, ignoring expired sessions.
    pub async fn session_user_id(&self, token: String) -> Result<Option<i64>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT user_id, expires_at FROM sessions WHERE id = ?1",
            )?;
            let found = stmt
                .query_row(params![token], |row| {
                    let user_id: i64 = row.get(0)?;
                    let expires_at: String = row.get(1)?;
                    Ok((user_id, expires_at))
                })
                .optional()?;

            match found {
                Some((user_id, expires_at)) => {
                    let expired = chrono::DateTime::parse_from_rfc3339(&expires_at)
                        .map(|exp| Utc::now() > exp.with_timezone(&Utc))
                        .unwrap_or(true);
                    if expired {
                        Ok(None)
                    } else {
                        Ok(Some(user_id))
                    }
                }
                None => Ok(None),
            }
        })
        .await
    }

    /// Delete a session (logout).
    pub async fn delete_session(&self, token: String) -> Result<(), AppError> {
        self.run(move |conn| {
            conn.execute("DELETE FROM sessions WHERE id = ?1", params![token])?;
            Ok(())
        })
        .await
    }

    /// Remove all expired sessions (housekeeping).
    pub async fn purge_expired_sessions(&self) -> Result<(), AppError> {
        self.run(move |conn| {
            let now = Utc::now().to_rfc3339();
            conn.execute("DELETE FROM sessions WHERE expires_at < ?1", params![now])?;
            Ok(())
        })
        .await
    }
}

/// Generate a cryptographically random, URL-safe session token.
pub fn generate_token() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
