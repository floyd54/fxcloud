use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use crate::error::AppError;
use crate::models::PasskeyInfo;

use super::Db;

/// A stored passkey as the ceremony code needs it: everything public key
/// verification and clone detection read. The credential id is the lookup
/// key itself, the label is display-only - neither rides along here.
#[derive(Debug, Clone)]
pub struct PasskeyRecord {
    pub id: i64,
    pub user_id: i64,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
}

/// Columns of [`PasskeyRecord`], in struct order.
const RECORD_COLUMNS: &str = "id, user_id, public_key, sign_count";

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<PasskeyRecord> {
    Ok(PasskeyRecord {
        id: row.get("id")?,
        user_id: row.get("user_id")?,
        public_key: row.get("public_key")?,
        sign_count: row.get("sign_count")?,
    })
}

/// Comma list from the column -> the array the settings dialog renders.
fn split_transports(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

impl Db {
    /// Store a freshly attested credential and return the row as the
    /// settings dialog displays it.
    ///
    /// A duplicate `credential_id` (the same authenticator registered twice)
    /// surfaces as 409 instead of a raw constraint error.
    pub async fn insert_passkey(
        &self,
        user_id: i64,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        sign_count: i64,
        transports: Vec<String>,
        label: String,
    ) -> Result<PasskeyInfo, AppError> {
        self.run(move |conn| {
            let now = Utc::now().to_rfc3339();
            let transport_list = transports.join(",");
            conn.execute(
                "INSERT INTO webauthn_credentials
                     (user_id, credential_id, public_key, sign_count,
                      transports, label, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    user_id,
                    credential_id,
                    public_key,
                    sign_count,
                    transport_list,
                    label,
                    now
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    AppError::Conflict("this passkey is already registered".into())
                }
                other => other.into(),
            })?;
            let id = conn.last_insert_rowid();
            let (created_at, last_used_at): (String, Option<String>) = conn.query_row(
                "SELECT created_at, last_used_at FROM webauthn_credentials WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok(PasskeyInfo {
                id,
                label,
                created_at: super::user::parse_ts(&created_at, 0)?,
                last_used_at: last_used_at
                    .as_deref()
                    .map(|s| super::user::parse_ts(s, 0))
                    .transpose()?,
                transports: split_transports(&transport_list),
            })
        })
        .await
    }

    /// Every passkey of one account, newest registration first (the settings
    /// list).
    pub async fn list_passkeys(&self, user_id: i64) -> Result<Vec<PasskeyInfo>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT id, label, created_at, last_used_at, transports
                   FROM webauthn_credentials
                  WHERE user_id = ?1
                  ORDER BY created_at DESC, id DESC",
            )?;
            let rows = stmt
                .query_map(params![user_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut out = Vec::with_capacity(rows.len());
            for (id, label, created_at, last_used_at, transports) in rows {
                out.push(PasskeyInfo {
                    id,
                    label,
                    created_at: super::user::parse_ts(&created_at, 0)?,
                    last_used_at: last_used_at
                        .as_deref()
                        .map(|s| super::user::parse_ts(s, 0))
                        .transpose()?,
                    transports: split_transports(&transports),
                });
            }
            Ok(out)
        })
        .await
    }

    /// The raw credential ids of one account. Feeds the registration
    /// `excludeCredentials` list and the login `allowCredentials` list.
    pub async fn passkey_credential_ids(&self, user_id: i64) -> Result<Vec<Vec<u8>>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT credential_id FROM webauthn_credentials
                  WHERE user_id = ?1 ORDER BY id",
            )?;
            let rows = stmt.query_map(params![user_id], |row| row.get::<_, Vec<u8>>(0))?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
    }

    /// Look a credential up by its id - the single lookup every assertion
    /// performs. `None` means the credential is unknown to this instance.
    pub async fn find_passkey_by_credential_id(
        &self,
        credential_id: Vec<u8>,
    ) -> Result<Option<PasskeyRecord>, AppError> {
        self.run(move |conn| {
            let sql = format!(
                "SELECT {RECORD_COLUMNS} FROM webauthn_credentials WHERE credential_id = ?1"
            );
            let record = conn
                .query_row(&sql, params![credential_id], row_to_record)
                .optional()?;
            Ok(record)
        })
        .await
    }

    /// Rename one device. Scoped to the owner: a foreign or unknown id is
    /// `404` so the endpoint cannot confirm whether an id exists elsewhere.
    pub async fn rename_passkey(
        &self,
        user_id: i64,
        id: i64,
        label: String,
    ) -> Result<PasskeyInfo, AppError> {
        self.run(move |conn| {
            let changed = conn.execute(
                "UPDATE webauthn_credentials SET label = ?1
                  WHERE id = ?2 AND user_id = ?3",
                params![label, id, user_id],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            let (created_at, last_used_at, transports): (String, Option<String>, String) = conn
                .query_row(
                    "SELECT created_at, last_used_at, transports
                       FROM webauthn_credentials WHERE id = ?1",
                    params![id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
            Ok(PasskeyInfo {
                id,
                label,
                created_at: super::user::parse_ts(&created_at, 0)?,
                last_used_at: last_used_at
                    .as_deref()
                    .map(|s| super::user::parse_ts(s, 0))
                    .transpose()?,
                transports: split_transports(&transports),
            })
        })
        .await
    }

    /// Unregister one device, owner-scoped like [`Self::rename_passkey`].
    pub async fn delete_passkey(&self, user_id: i64, id: i64) -> Result<(), AppError> {
        self.run(move |conn| {
            let changed = conn.execute(
                "DELETE FROM webauthn_credentials WHERE id = ?1 AND user_id = ?2",
                params![id, user_id],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            Ok(())
        })
        .await
    }

    /// Record a successful sign-in: advance the clone-detection counter and
    /// stamp `last_used_at` for the settings list.
    pub async fn touch_passkey(&self, id: i64, sign_count: i64) -> Result<(), AppError> {
        self.run(move |conn| {
            conn.execute(
                "UPDATE webauthn_credentials
                    SET sign_count = ?1, last_used_at = ?2
                  WHERE id = ?3",
                params![sign_count, Utc::now().to_rfc3339(), id],
            )?;
            Ok(())
        })
        .await
    }
}
