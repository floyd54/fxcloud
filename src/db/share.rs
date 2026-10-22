use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::AppError;
use crate::models::{IncomingShare, OutgoingShare};
use crate::sharing::{normalize, ShareAccess};

use super::user::parse_ts;
use super::Db;

impl Db {
    /// Share `source_id` (owned by `owner_id`) with `grantee_username`.
    ///
    /// The share is surfaced in the grantee's root under a display name derived
    /// from the source name, uniquified against that user's root.
    pub async fn create_share(
        &self,
        owner_id: i64,
        source_id: i64,
        grantee_username: String,
        permissions: i64,
    ) -> Result<OutgoingShare, AppError> {
        let perms = normalize(permissions);
        self.run(move |conn| {
            // Source must exist and belong to the owner.
            let (source_name, is_dir): (String, bool) = conn
                .query_row(
                    "SELECT name, is_dir != 0 FROM files WHERE id = ?1 AND owner_id = ?2",
                    params![source_id, owner_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(AppError::NotFound)?;

            // Resolve grantee.
            let grantee_id: i64 = conn
                .query_row(
                    "SELECT id FROM users WHERE username = ?1 COLLATE NOCASE",
                    params![grantee_username.trim()],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or_else(|| AppError::BadRequest("no such user".into()))?;

            if grantee_id == owner_id {
                return Err(AppError::BadRequest("cannot share with yourself".into()));
            }

            // One share per (source, grantee).
            let dup: Option<i64> = conn
                .query_row(
                    "SELECT id FROM shares WHERE source_id = ?1 AND grantee_id = ?2",
                    params![source_id, grantee_id],
                    |r| r.get(0),
                )
                .optional()?;
            if dup.is_some() {
                return Err(AppError::Conflict("already shared with this user".into()));
            }

            let owner_username: String = conn.query_row(
                "SELECT username FROM users WHERE id = ?1",
                params![owner_id],
                |r| r.get(0),
            )?;
            let display_name = uniquify_root_name(conn, grantee_id, &source_name, &owner_username)?;

            let now = Utc::now();
            conn.execute(
                "INSERT INTO shares (source_id, owner_id, grantee_id, display_name, permissions, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![source_id, owner_id, grantee_id, display_name, perms, now.to_rfc3339()],
            )
            .map_err(|e| map_share_constraint(e))?;

            Ok(OutgoingShare {
                id: conn.last_insert_rowid(),
                source_id,
                source_name,
                is_dir,
                grantee_username: grantee_username.trim().to_string(),
                permissions: perms,
                created_at: now,
            })
        })
        .await
    }

    /// Revoke a share. Allowed for either the owner or the grantee.
    pub async fn revoke_share(&self, requester_id: i64, share_id: i64) -> Result<(), AppError> {
        self.run(move |conn| {
            let changed = conn.execute(
                "DELETE FROM shares WHERE id = ?1 AND (owner_id = ?2 OR grantee_id = ?2)",
                params![share_id, requester_id],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            Ok(())
        })
        .await
    }

    /// Shares I created (items I shared out), with grantee context.
    pub async fn list_outgoing(&self, owner_id: i64) -> Result<Vec<OutgoingShare>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT s.id, s.source_id, f.name, f.is_dir != 0, u.username, s.permissions, s.created_at
                 FROM shares s
                 JOIN files f ON f.id = s.source_id
                 JOIN users  u ON u.id = s.grantee_id
                 WHERE s.owner_id = ?1
                 ORDER BY s.created_at DESC",
            )?;
            let rows = stmt
                .query_map(params![owner_id], |r| {
                    Ok(OutgoingShare {
                        id: r.get(0)?,
                        source_id: r.get(1)?,
                        source_name: r.get(2)?,
                        is_dir: r.get(3)?,
                        grantee_username: r.get(4)?,
                        permissions: r.get(5)?,
                        created_at: parse_ts(&r.get::<_, String>(6)?, 6)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }

    /// Shares given to me, with owner context. These mount in my root.
    pub async fn list_incoming(&self, grantee_id: i64) -> Result<Vec<IncomingShare>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT s.id, s.source_id, f.name, s.display_name, f.is_dir != 0, f.size,
                        u.username, s.permissions, s.created_at
                 FROM shares s
                 JOIN files f ON f.id = s.source_id
                 JOIN users  u ON u.id = s.owner_id
                 WHERE s.grantee_id = ?1
                 ORDER BY s.created_at DESC",
            )?;
            let rows = stmt
                .query_map(params![grantee_id], |r| {
                    Ok(IncomingShare {
                        id: r.get(0)?,
                        source_id: r.get(1)?,
                        source_name: r.get(2)?,
                        display_name: r.get(3)?,
                        is_dir: r.get(4)?,
                        size: r.get(5)?,
                        owner_username: r.get(6)?,
                        permissions: r.get(7)?,
                        created_at: parse_ts(&r.get::<_, String>(8)?, 8)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }

    /// The share that mounts `display_name` in this user's root, if any.
    pub async fn access_by_display_name(
        &self,
        grantee_id: i64,
        display_name: String,
    ) -> Result<Option<ShareAccess>, AppError> {
        self.run(move |conn| share_by_display_name(conn, grantee_id, &display_name))
        .await
    }

    /// Authorize access to `entry_id` for `requester_id`.
    ///
    /// Returns `true` if the requester owns the entry, or a share on the entry
    /// (or one of its ancestors) grants `required`. Walks up the owner's tree
    /// so children of a shared folder are covered by the folder's share.
    pub async fn authorize_entry(
        &self,
        requester_id: i64,
        entry_id: i64,
        required: i64,
    ) -> Result<bool, AppError> {
        self.run(move |conn| {
            let owner_id: Option<i64> = conn
                .query_row(
                    "SELECT owner_id FROM files WHERE id = ?1",
                    params![entry_id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(entry_owner) = owner_id else {
                return Ok(false); // no such entry
            };
            if entry_owner == requester_id {
                return Ok(true); // owners can do anything to their own items
            }
            // Find the nearest shared ancestor (or the entry itself).
            match covering_share(conn, requester_id, entry_id)? {
                Some(access) => Ok(access.can(required)),
                None => Ok(false),
            }
        })
        .await
    }
}

/// The share (if any) that governs `entry_id` for `grantee_id`: either a share
/// on the entry itself or on the nearest shared ancestor. This is what makes
/// children of a shared folder accessible through the folder's share.
pub(super) fn covering_share(
    conn: &Connection,
    grantee_id: i64,
    entry_id: i64,
) -> Result<Option<ShareAccess>, AppError> {
    let mut cur = Some(entry_id);
    while let Some(id) = cur {
        if let Some(access) = share_on(conn, grantee_id, id)? {
            return Ok(Some(access));
        }
        let parent: Option<i64> = conn
            .query_row(
                "SELECT parent_id FROM files WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        cur = parent;
    }
    Ok(None)
}

/// Is `name` already used as a share mount in `grantee_id`'s root?
pub(super) fn share_name_taken(
    conn: &Connection,
    grantee_id: i64,
    name: &str,
) -> Result<bool, AppError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT id FROM shares WHERE grantee_id = ?1 AND display_name = ?2",
            params![grantee_id, name],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn row_to_access(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShareAccess> {
    Ok(ShareAccess {
        share_id: row.get(0)?,
        source_id: row.get(1)?,
        owner_id: row.get(2)?,
        grantee_id: row.get(3)?,
        permissions: row.get(4)?,
    })
}

fn share_on(conn: &Connection, grantee_id: i64, source_id: i64) -> Result<Option<ShareAccess>, AppError> {
    let found = conn
        .query_row(
            "SELECT id, source_id, owner_id, grantee_id, permissions
             FROM shares WHERE grantee_id = ?1 AND source_id = ?2",
            params![grantee_id, source_id],
            row_to_access,
        )
        .optional()?;
    Ok(found)
}

/// The share (if any) mounted at `display_name` in this user's root.
pub(super) fn share_by_display_name(
    conn: &Connection,
    grantee_id: i64,
    display_name: &str,
) -> Result<Option<ShareAccess>, AppError> {
    let found = conn
        .query_row(
            "SELECT id, source_id, owner_id, grantee_id, permissions
             FROM shares WHERE grantee_id = ?1 AND display_name = ?2",
            params![grantee_id, display_name],
            row_to_access,
        )
        .optional()?;
    Ok(found)
}

/// Is `name` already used in `grantee`'s root (by a file or another share)?
fn root_name_taken(conn: &Connection, grantee_id: i64, name: &str) -> Result<bool, AppError> {
    let in_files: Option<i64> = conn
        .query_row(
            "SELECT id FROM files WHERE owner_id = ?1 AND parent_id IS NULL AND name = ?2",
            params![grantee_id, name],
            |r| r.get(0),
        )
        .optional()?;
    if in_files.is_some() {
        return Ok(true);
    }
    let in_shares: Option<i64> = conn
        .query_row(
            "SELECT id FROM shares WHERE grantee_id = ?1 AND display_name = ?2",
            params![grantee_id, name],
            |r| r.get(0),
        )
        .optional()?;
    Ok(in_shares.is_some())
}

/// Pick a display name for `base` that is free in `grantee`'s root, falling
/// back to `<base> (<owner>)` and then numbered suffixes on collision.
fn uniquify_root_name(
    conn: &Connection,
    grantee_id: i64,
    base: &str,
    owner_username: &str,
) -> Result<String, AppError> {
    if !root_name_taken(conn, grantee_id, base)? {
        return Ok(base.to_string());
    }
    let suffixed = format!("{base} ({owner_username})");
    if !root_name_taken(conn, grantee_id, &suffixed)? {
        return Ok(suffixed);
    }
    for n in 2..1000 {
        let candidate = format!("{suffixed} {n}");
        if !root_name_taken(conn, grantee_id, &candidate)? {
            return Ok(candidate);
        }
    }
    Err(AppError::Conflict("too many shares named this in your root".into()))
}

fn map_share_constraint(e: rusqlite::Error) -> AppError {
    match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            AppError::Conflict("already shared".into())
        }
        other => other.into(),
    }
}
