use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::AppError;
use crate::models::{User, UserOption};

use super::Db;

/// Parse an RFC3339 timestamp column into a `DateTime<Utc>`, mapping failures
/// into a proper rusqlite conversion error.
pub(super) fn parse_ts(s: &str, idx: usize) -> rusqlite::Result<DateTime<Utc>> {
    s.parse().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Row shape used internally to carry the password hash alongside the user.
pub struct UserWithHash {
    pub user: User,
    pub password_hash: String,
}

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let created_at: String = row.get("created_at")?;
    Ok(User {
        id: row.get("id")?,
        username: row.get("username")?,
        display_name: row.get("display_name")?,
        is_active: row.get("is_active")?,
        created_at: parse_ts(&created_at, 0)?,
        quota_bytes: row.get("quota_bytes")?,
    })
}

impl Db {
    /// Look up a user by username, including their stored password hash.
    pub async fn find_user_by_username(
        &self,
        username: String,
    ) -> Result<Option<UserWithHash>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, username, display_name, is_active, created_at, quota_bytes, password_hash
                 FROM users WHERE username = ?1",
            )?;
            let found = stmt
                .query_row(params![username], |row| {
                    Ok(UserWithHash {
                        user: row_to_user(row)?,
                        password_hash: row.get("password_hash")?,
                    })
                })
                .optional()?;
            Ok(found)
        })
        .await
    }

    /// Fetch a single user by id.
    pub async fn find_user_by_id(&self, id: i64) -> Result<Option<User>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, username, display_name, is_active, created_at, quota_bytes FROM users WHERE id = ?1",
            )?;
            let found = stmt.query_row(params![id], row_to_user).optional()?;
            Ok(found)
        })
        .await
    }

    /// Every account except `exclude_id`, for the share dialog's dropdown:
    /// username and display name for the label, plus `is_active` so accounts
    /// that cannot sign in yet can be marked as such.
    pub async fn list_share_targets(&self, exclude_id: i64) -> Result<Vec<UserOption>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT username, display_name, is_active FROM users
                  WHERE id != ?1 ORDER BY username",
            )?;
            let rows = stmt
                .query_map(params![exclude_id], |row| {
                    Ok(UserOption {
                        username: row.get(0)?,
                        display_name: row.get(1)?,
                        is_active: row.get(2)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Insert a new user and return the created record.
    ///
    /// The account starts out **inactive** — unless it is the very first one
    /// on a fresh instance (see [`insert_user`]) — and has to be activated
    /// before its owner can sign in.
    pub async fn create_user(
        &self,
        username: String,
        password_hash: String,
        display_name: String,
    ) -> Result<User, AppError> {
        self.run(move |conn| {
            insert_user(conn, &username, &password_hash, &display_name)
        })
        .await
    }
}

/// Synchronous helper so other modules (e.g. first-run setup) can create users.
///
/// New accounts are inserted with `is_active = 0`: they can be used only after
/// an administrator flips them on directly in the database
/// (`UPDATE users SET is_active = 1 WHERE username = '…';`) — there is no user
/// administration UI yet. The single exception is bootstrap: when the instance
/// has no users at all, the account being created is the operator's own first
/// login, so it is activated right away.
///
/// The storage quota is *not* passed in: the schema default (1 GiB, migration
/// `004_user_quota`) decides what a new account gets, and it is read back
/// after the insert so there is exactly one source of truth for it.
pub fn insert_user(
    conn: &mut Connection,
    username: &str,
    password_hash: &str,
    display_name: &str,
) -> Result<User, AppError> {
    let now = Utc::now().to_rfc3339();
    let is_active: bool =
        conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))? == 0;
    conn.execute(
        "INSERT INTO users (username, password_hash, display_name, created_at, is_active)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![username, password_hash, display_name, now, is_active],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            AppError::Conflict(format!("username '{username}' is already taken"))
        }
        other => other.into(),
    })?;

    let id = conn.last_insert_rowid();
    let quota_bytes: i64 = conn.query_row(
        "SELECT quota_bytes FROM users WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )?;
    Ok(User {
        id,
        username: username.to_string(),
        display_name: display_name.to_string(),
        is_active,
        created_at: now.parse().map_err(|_| AppError::Internal(anyhow::anyhow!("bad timestamp")))?,
        quota_bytes,
    })
}
