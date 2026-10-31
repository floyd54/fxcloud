use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::AppError;
use crate::models::{AdminUser, User, UserOption};

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
        theme: row.get("theme")?,
        // Guarded by migration 010_user_admin, so an older database that
        // somehow skipped it fails loudly here rather than silently denying.
        is_admin: row.get("is_admin")?,
        version_keep_n: row.get("version_keep_n")?,
        version_keep_days: row.get("version_keep_days")?,
    })
}

/// The full column list that [`row_to_user`] reads, kept in one place so a
/// new column is added in a single edit. `password_hash` is deliberately
/// absent: the sign-in path selects it separately and it never leaves the
/// auth layer.
const USER_COLUMNS: &str = "id, username, display_name, is_active, created_at, quota_bytes, \
                            theme, is_admin, version_keep_n, version_keep_days";

impl Db {
    /// Look up a user by username, including their stored password hash.
    pub async fn find_user_by_username(
        &self,
        username: String,
    ) -> Result<Option<UserWithHash>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {USER_COLUMNS}, password_hash FROM users WHERE username = ?1",
            ))?;
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
            let mut stmt =
                conn.prepare(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1",))?;
            let found = stmt.query_row(params![id], row_to_user).optional()?;
            Ok(found)
        })
        .await
    }

    /// Save the user's own settings from the user menu: display name, UI
    /// theme and the version-retention bounds. Only fields the caller passes
    /// as `Some` are written, so each section of the dialog saves on its own
    /// without resending the others. The theme value is validated against the
    /// two known themes here rather than trusted from the request body, and
    /// the retention bounds must be non-negative (0 disables a bound).
    pub async fn update_settings(
        &self,
        id: i64,
        display_name: Option<String>,
        theme: Option<String>,
        version_keep_n: Option<i64>,
        version_keep_days: Option<i64>,
    ) -> Result<User, AppError> {
        if let Some(theme) = &theme {
            if theme != "light" && theme != "dark" {
                return Err(AppError::BadRequest(
                    "theme must be 'light' or 'dark'".into(),
                ));
            }
        }
        for (value, name) in [
            (&version_keep_n, "version_keep_n"),
            (&version_keep_days, "version_keep_days"),
        ] {
            if value.is_some_and(|v| v < 0) {
                return Err(AppError::BadRequest(format!(
                    "{name} must be 0 or greater (0 disables the bound)"
                )));
            }
        }
        self.run(move |conn| {
            if let Some(name) = display_name {
                conn.execute(
                    "UPDATE users SET display_name = ?2 WHERE id = ?1",
                    params![id, name],
                )?;
            }
            if let Some(theme) = theme {
                conn.execute(
                    "UPDATE users SET theme = ?2 WHERE id = ?1",
                    params![id, theme],
                )?;
            }
            if let Some(keep) = version_keep_n {
                conn.execute(
                    "UPDATE users SET version_keep_n = ?2 WHERE id = ?1",
                    params![id, keep],
                )?;
            }
            if let Some(days) = version_keep_days {
                conn.execute(
                    "UPDATE users SET version_keep_days = ?2 WHERE id = ?1",
                    params![id, days],
                )?;
            }
            let mut stmt =
                conn.prepare(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1",))?;
            stmt.query_row(params![id], row_to_user)
                .optional()?
                .ok_or_else(|| AppError::NotFound)
        })
        .await
    }

    /// Replace the password hash after the caller proved they know the old
    /// one (self-service) or an administrator reset a reported account, and
    /// cut every other session of that account with it (F3, Audit.md).
    ///
    /// A password change is the incident response for a stolen credential,
    /// so the sessions the old password minted cannot outlive it: an
    /// attacker holding a cookie would otherwise keep the account for the
    /// rest of the session TTL no matter how fast the victim reacted. The
    /// caller's own session is passed through as `keep_session` and stays
    /// open - it authenticated this very request - so the menu that made
    /// the change keeps working. The admin reset passes `None`: a reset
    /// exists precisely because an account may be compromised, and every
    /// session on it has to go.
    pub async fn set_password(
        &self,
        id: i64,
        password_hash: String,
        keep_session: Option<String>,
    ) -> Result<(), AppError> {
        self.run(move |conn| {
            conn.execute(
                "UPDATE users SET password_hash = ?2 WHERE id = ?1",
                params![id, password_hash],
            )?;
            match keep_session {
                Some(token) => conn.execute(
                    "DELETE FROM sessions WHERE user_id = ?1 AND id != ?2",
                    params![id, token],
                )?,
                None => conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![id])?,
            };
            Ok(())
        })
        .await
    }

    /// Every account for the user-administration table, with the fields the
    /// admin dialog renders plus each account's storage consumption so the
    /// quota column can be shown against what is actually used.
    ///
    /// Only reachable behind the `AdminUser` extractor (`src/web/middleware.rs`);
    /// this is the one place that serializes ids and quotas to a caller other
    /// than the owner.
    pub async fn list_admin_users(&self) -> Result<Vec<AdminUser>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {USER_COLUMNS},
                        (SELECT COALESCE(SUM(size), 0) FROM files
                          WHERE owner_id = users.id AND owner_group_id IS NULL
                            AND deleted_at IS NULL)
                      + (SELECT COALESCE(SUM(v.size), 0) FROM file_versions v
                         JOIN files f ON f.id = v.file_id
                          WHERE f.owner_id = users.id AND f.owner_group_id IS NULL
                            AND f.deleted_at IS NULL)
                                                               AS used_bytes
                   FROM users ORDER BY username",
            ))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(AdminUser {
                        id: row.get("id")?,
                        username: row.get("username")?,
                        display_name: row.get("display_name")?,
                        is_active: row.get("is_active")?,
                        is_admin: row.get("is_admin")?,
                        quota_bytes: row.get("quota_bytes")?,
                        used_bytes: row.get("used_bytes")?,
                        created_at: {
                            let s: String = row.get("created_at")?;
                            parse_ts(&s, 0)?
                        },
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Flip the `is_active` flag for one account (the "activate"/"deactivate"
    /// action in the admin dialog). Sign-in checks this flag, so deactivating
    /// cuts off new sign-ins; sessions already open keep working until they
    /// expire -- see the sign-in path for the exact semantics.
    pub async fn set_user_active(&self, id: i64, active: bool) -> Result<(), AppError> {
        self.run(move |conn| {
            conn.execute(
                "UPDATE users SET is_active = ?2 WHERE id = ?1",
                params![id, active],
            )?;
            Ok(())
        })
        .await
    }

    /// Grant or revoke the administrator flag for one account. The caller in
    /// `src/web/routes/admin.rs` refuses the operation when it would leave the
    /// instance with no active administrator, so this helper does not second-
    /// guess the decision.
    pub async fn set_user_admin(&self, id: i64, admin: bool) -> Result<(), AppError> {
        self.run(move |conn| {
            conn.execute(
                "UPDATE users SET is_admin = ?2 WHERE id = ?1",
                params![id, admin],
            )?;
            Ok(())
        })
        .await
    }

    /// Set the storage quota (bytes) for one account. Content beyond it is
    /// rejected with `507 Insufficient Storage`.
    pub async fn set_user_quota(&self, id: i64, quota_bytes: i64) -> Result<(), AppError> {
        self.run(move |conn| {
            conn.execute(
                "UPDATE users SET quota_bytes = ?2 WHERE id = ?1",
                params![id, quota_bytes],
            )?;
            Ok(())
        })
        .await
    }

    /// How many accounts are both active and administrators. The admin routes
    /// use this to refuse demoting or deactivating the last administrator,
    /// which would leave the instance unmanageable.
    pub async fn count_active_admins(&self) -> Result<i64, AppError> {
        self.run(move |conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM users WHERE is_active = 1 AND is_admin = 1",
                [],
                |r| r.get(0),
            )?;
            Ok(n)
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
        self.run(move |conn| insert_user(conn, &username, &password_hash, &display_name))
            .await
    }
}

/// Synchronous helper so other modules (e.g. first-run setup) can create users.
///
/// New accounts are inserted with `is_active = 0`: they can be used only after
/// an administrator enables them in the user-administration dialog (or, before
/// that UI existed, directly in the database). The single exception is
/// bootstrap: when the instance has no users at all, the account being created
/// is the operator's own first login, so it is activated right away **and**
/// given `is_admin = 1`. That first account is the administrator who then
/// manages every account created afterwards. On an existing database the same
/// promotion is performed once by migration `010_user_admin`.
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
    // Bootstrap: the very first account (COUNT(*) == 0) is both active and an
    // administrator. Every later account starts inactive and non-admin.
    let is_first: bool =
        conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))? == 0;
    let is_active = is_first;
    let is_admin = is_first;
    conn.execute(
        "INSERT INTO users (username, password_hash, display_name, created_at, is_active, is_admin)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            username,
            password_hash,
            display_name,
            now,
            is_active,
            is_admin
        ],
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
    let (quota_bytes, theme, version_keep_n, version_keep_days): (i64, String, i64, i64) = conn
        .query_row(
            "SELECT quota_bytes, theme, version_keep_n, version_keep_days
              FROM users WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    Ok(User {
        id,
        username: username.to_string(),
        display_name: display_name.to_string(),
        is_active,
        created_at: now
            .parse()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("bad timestamp")))?,
        quota_bytes,
        theme,
        is_admin,
        version_keep_n,
        version_keep_days,
    })
}
