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
        envelope: Option<String>,
    ) -> Result<OutgoingShare, AppError> {
        let perms = normalize(permissions);
        self.run(move |conn| {
            // Source must exist, be a personal row, and belong to the owner.
            let (source_name, is_dir, row_owner, source_group): (
                String,
                bool,
                i64,
                Option<i64>,
            ) = conn
                .query_row(
                    "SELECT name, is_dir != 0, owner_id, owner_group_id
                       FROM files WHERE id = ?1",
                    params![source_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?
                .ok_or(AppError::NotFound)?;
            if let Some(group_id) = source_group {
                // Group files take no incoming shares, and v1 draws no
                // re-share *out of* a group folder to individuals
                // (concepts/groups.md section 4): members learn why (403),
                // for non-members the row is not there (404) - the same
                // answer their listings give them.
                let member: Option<i64> = conn
                    .query_row(
                        "SELECT role FROM group_members
                          WHERE group_id = ?1 AND user_id = ?2",
                        params![group_id, owner_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                return Err(match member {
                    Some(_) => AppError::ForbiddenDetail(
                        "group folders cannot be shared with individuals - their \
                         members receive access through the group"
                            .into(),
                    ),
                    None => AppError::NotFound,
                });
            }
            if row_owner != owner_id {
                return Err(AppError::NotFound);
            }

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
                "INSERT INTO shares (source_id, owner_id, grantee_id, display_name, permissions, created_at, envelope)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    source_id,
                    owner_id,
                    grantee_id,
                    display_name,
                    perms,
                    now.to_rfc3339(),
                    envelope
                ],
            )
            .map_err(map_share_constraint)?;

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

    /// Replace the envelope on a share row I created (5.6 re-key).
    ///
    /// Only the row's owner may re-seal: the envelope is addressed to a
    /// grantee by the person who shared, and `list_outgoing` shows exactly
    /// these rows. Zero rows changed answers 404 - a foreign id and a
    /// revoked id are the same silence, as in [`Db::revoke_share`].
    pub async fn update_share_envelope(
        &self,
        owner_id: i64,
        share_id: i64,
        envelope: String,
    ) -> Result<(), AppError> {
        self.run(move |conn| {
            let changed = conn.execute(
                "UPDATE shares SET envelope = ?1 WHERE id = ?2 AND owner_id = ?3",
                params![envelope, share_id, owner_id],
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
                        u.username, s.permissions, s.created_at, s.envelope
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
                        envelope: r.get(9)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
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
    let mut hops = 0;
    while let Some(id) = cur {
        // The depth cap turns a corrupt parent cycle into "no share" -
        // the same guard under_trash uses, in its own currency: a walk
        // that never finds a share must end, not spin (Audit.md F6).
        hops += 1;
        if hops > 64 {
            return Ok(None);
        }
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

fn share_on(
    conn: &Connection,
    grantee_id: i64,
    source_id: i64,
) -> Result<Option<ShareAccess>, AppError> {
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
    Err(AppError::Conflict(
        "too many shares named this in your root".into(),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A throwaway database with the real migrations applied - file-backed
    /// for the same reason as the file tests: `Db` pools eight connections
    /// and every `:memory:` connection would get its own private database.
    struct Scratch {
        db: Db,
        dir: PathBuf,
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn scratch() -> Scratch {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("fxcloud-share-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let db = Db::open(&dir.join("fxcloud.db")).expect("migrations must apply to an empty db");
        Scratch { db, dir }
    }

    fn user(conn: &Connection, name: &str) -> i64 {
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, created_at, quota_bytes)
             VALUES (?1, 'hash', ?1, '2026-01-01T00:00:00Z', 1000000)",
            params![name],
        )
        .expect("insert user");
        conn.query_row(
            "SELECT id FROM users WHERE username = ?1",
            params![name],
            |r| r.get(0),
        )
        .expect("user id")
    }

    fn add_file(conn: &Connection, owner: i64, name: &str) -> i64 {
        conn.execute(
            "INSERT INTO files (owner_id, name, is_dir, size, created_at, modified_at)
             VALUES (?1, ?2, 1, 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            params![owner, name],
        )
        .expect("insert file");
        conn.last_insert_rowid()
    }

    fn envelope_of(s: &Scratch, id: i64) -> Option<String> {
        let conn = s.db.pool.get().unwrap();
        conn.query_row(
            "SELECT envelope FROM shares WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()
        .expect("query")
    }

    #[tokio::test]
    async fn only_the_owner_reseals_and_the_row_stays_addressable() {
        let s = scratch();
        let (owner, grantee, file) = {
            let conn = s.db.pool.get().unwrap();
            let o = user(&conn, "owner");
            let g = user(&conn, "grantee");
            let f = add_file(&conn, o, "proj");
            (o, g, f)
        };
        let share =
            s.db.create_share(
                owner,
                file,
                "grantee".into(),
                crate::sharing::PERM_ALL,
                Some("env-old".into()),
            )
            .await
            .expect("share created");
        assert_eq!(envelope_of(&s, share.id).as_deref(), Some("env-old"));

        // The owner re-seals after a re-key (5.6).
        s.db.update_share_envelope(owner, share.id, "env-new".into())
            .await
            .expect("owner may re-seal");
        assert_eq!(envelope_of(&s, share.id).as_deref(), Some("env-new"));

        // The grantee rewrites nothing: a foreign row and a missing id
        // are the same silence, and the row itself stays untouched.
        let err =
            s.db.update_share_envelope(grantee, share.id, "env-x".into())
                .await
                .expect_err("grantee refused");
        assert!(matches!(err, AppError::NotFound));
        assert_eq!(
            envelope_of(&s, share.id).as_deref(),
            Some("env-new"),
            "row untouched by the refused call"
        );
        let err =
            s.db.update_share_envelope(owner, 999_999, "env-x".into())
                .await
                .expect_err("missing id");
        assert!(matches!(err, AppError::NotFound));

        // A revoked row cannot be re-sealed either.
        s.db.revoke_share(owner, share.id).await.expect("revoke");
        let err =
            s.db.update_share_envelope(owner, share.id, "env-x".into())
                .await
                .expect_err("revoked row");
        assert!(matches!(err, AppError::NotFound));
    }
}
