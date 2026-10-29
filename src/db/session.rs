use chrono::{Duration, Utc};
use rusqlite::{params, OptionalExtension};

use crate::error::AppError;

use super::Db;

impl Db {
    /// Create a new session for `user_id` that expires after `ttl_secs`.
    /// Returns the opaque session token (stored as a cookie on the client).
    /// `user_agent` is the device line the settings listing shows.
    pub async fn create_session(
        &self,
        user_id: i64,
        ttl_secs: i64,
        user_agent: String,
    ) -> Result<String, AppError> {
        self.run(move |conn| {
            let token = super::session::generate_token();
            let now = Utc::now();
            let expires = now + Duration::seconds(ttl_secs);
            conn.execute(
                "INSERT INTO sessions (id, user_id, created_at, expires_at, sid, last_seen_at, user_agent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?3, ?6)",
                params![
                    token,
                    user_id,
                    now.to_rfc3339(),
                    expires.to_rfc3339(),
                    generate_sid(),
                    user_agent
                ],
            )?;
            Ok(token)
        })
        .await
    }

    /// The public handle of a live session token; `None` when the token
    /// is unknown or its window has run out. The "keep this one" lookup
    /// behind `DELETE /api/me/sessions` and the `current` flag in the
    /// listing both name a session through the caller's own cookie.
    pub async fn session_sid(&self, token: String) -> Result<Option<String>, AppError> {
        self.run(move |conn| {
            let mut stmt =
                conn.prepare("SELECT sid FROM sessions WHERE id = ?1 AND expires_at >= ?2")?;
            let sid = stmt
                .query_row(params![token, Utc::now().to_rfc3339()], |row| row.get(0))
                .optional()?;
            Ok(sid)
        })
        .await
    }

    /// Slide a session's window forward if it was not renewed lately.
    ///
    /// One statement whose `WHERE` skips every session used within the
    /// renewal window, so sliding renewal costs the hot path nothing and
    /// writes at most once per window per session - a quarter of the
    /// lifetime, capped at a day: frequent enough for a truthful "last
    /// used" column, rare enough to stay a rounding error in the journal.
    /// Returns whether the row actually moved.
    pub async fn session_touch(&self, token: String, ttl_secs: i64) -> Result<bool, AppError> {
        self.run(move |conn| {
            let now = Utc::now();
            let expires = (now + Duration::seconds(ttl_secs)).to_rfc3339();
            let window = Duration::seconds((ttl_secs / 4).min(86_400));
            let changed = conn.execute(
                "UPDATE sessions SET last_seen_at = ?1, expires_at = ?2
                 WHERE id = ?3 AND last_seen_at < ?4",
                params![
                    now.to_rfc3339(),
                    expires,
                    token,
                    (now - window).to_rfc3339()
                ],
            )?;
            Ok(changed > 0)
        })
        .await
    }

    /// One row of the session list: what the UI may show, never the token.
    pub async fn list_sessions(&self, user_id: i64) -> Result<Vec<SessionInfo>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT sid, created_at, last_seen_at, expires_at, user_agent FROM sessions
                 WHERE user_id = ?1 AND expires_at >= ?2
                 ORDER BY created_at",
            )?;
            let rows = stmt.query_map(params![user_id, Utc::now().to_rfc3339()], |row| {
                Ok(SessionInfo {
                    sid: row.get(0)?,
                    created_at: row.get(1)?,
                    last_seen_at: row.get(2)?,
                    expires_at: row.get(3)?,
                    user_agent: row.get(4)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// End one of the user's own sessions by its public handle. Returns
    /// whether a row died; another user's sid matches nothing, so the
    /// answer cannot be used to probe for sessions elsewhere.
    pub async fn delete_session_by_sid(&self, user_id: i64, sid: String) -> Result<bool, AppError> {
        self.run(move |conn| {
            let changed = conn.execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND sid = ?2",
                params![user_id, sid],
            )?;
            Ok(changed > 0)
        })
        .await
    }

    /// End every session of `user_id` except the one holding `keep_sid`:
    /// the "sign out everywhere else" incident button (Audit.md F4).
    pub async fn delete_other_sessions(
        &self,
        user_id: i64,
        keep_sid: String,
    ) -> Result<u64, AppError> {
        self.run(move |conn| {
            let changed = conn.execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND sid != ?2",
                params![user_id, keep_sid],
            )?;
            Ok(changed as u64)
        })
        .await
    }

    /// Resolve a session token to its user id, ignoring expired sessions.
    pub async fn session_user_id(&self, token: String) -> Result<Option<i64>, AppError> {
        self.run(move |conn| {
            let mut stmt =
                conn.prepare("SELECT user_id, expires_at FROM sessions WHERE id = ?1")?;
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

/// Generate a session's public handle: 16 random bytes, hex.
///
/// Not a secret - every query using it is scoped to the caller's own
/// sessions - but random all the same, so a listing never hands out a
/// guessable label.
pub fn generate_sid() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One row of `GET /api/me/sessions`: the public handle plus the three
/// timestamps and the device line the UI shows. The secret token is
/// never part of it.
pub struct SessionInfo {
    pub sid: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
    pub user_agent: String,
}

/// A session's device line: the User-Agent as the client sent it, capped
/// so a hostile or broken client cannot grow the column without bound.
pub fn cap_user_agent(raw: Option<&str>) -> String {
    raw.map(|s| s.chars().take(200).collect())
        .unwrap_or_default()
}
