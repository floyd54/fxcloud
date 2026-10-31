//! Group management: the admin CRUD over groups and memberships, the member
//! view of their own groups, and the E2EE key distribution for group folders
//! (concepts/groups.md sections 3-5).
//!
//! Every permission decision on group *files* - who may read, write, trash,
//! restore - happens in `super::file` through the membership role; this
//! module manages the groups themselves. Roles come from `crate::sharing`.

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::AppError;
use crate::models::{GroupInfo, GroupKeyEnvelope, GroupMember, MyGroup, PendingGroupKey};
use crate::sharing::{ROLE_MANAGER, ROLE_MEMBER};

use super::file::group_role;
use super::Db;

/// A role value the tables may legally hold. Both bits are masks through
/// `role_perms`; anything else is a number no route ever wrote.
fn check_role(role: i64) -> Result<(), AppError> {
    if role == ROLE_MEMBER || role == ROLE_MANAGER {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "role must be 0 (member) or 1 (manager)".into(),
        ))
    }
}

/// Constraint violations on the group tables mean one thing each: a name the
/// unique index already carries, or a membership that already exists.
fn map_group_constraint(e: rusqlite::Error, what: &str) -> AppError {
    match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            AppError::Conflict(format!("{what} already exists"))
        }
        other => other.into(),
    }
}

/// The group's consumption under the exact rule `ensure_quota` bills with
/// (db/file.rs): the group's own live-plus-trashed file rows and their
/// version history - trash keeps counting until it is purged.
const GROUP_USAGE: &str = "COALESCE((SELECT SUM(f.size) FROM files f
                                WHERE f.owner_group_id = g.id AND f.is_dir = 0), 0)
                          + COALESCE((SELECT SUM(v.size) FROM file_versions v
                               JOIN files f ON f.id = v.file_id
                                WHERE f.owner_group_id = g.id AND f.is_dir = 0), 0)";

/// One group's memberships, member labels first.
fn member_list(conn: &Connection, group_id: i64) -> Result<Vec<GroupMember>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT m.user_id, u.username, u.display_name, m.role, m.added_at
           FROM group_members m JOIN users u ON u.id = m.user_id
          WHERE m.group_id = ?1
          ORDER BY u.username COLLATE NOCASE",
    )?;
    let rows = stmt.query_map(params![group_id], |r| {
        let added_at: String = r.get(4)?;
        Ok(GroupMember {
            user_id: r.get(0)?,
            username: r.get(1)?,
            display_name: r.get(2)?,
            role: r.get(3)?,
            added_at: super::user::parse_ts(&added_at, 4)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// One group with its members, or `None` when it does not exist: the
/// read-back every group mutation answers with.
fn group_info(conn: &Connection, group_id: i64) -> Result<Option<GroupInfo>, AppError> {
    let row = conn
        .query_row(
            &format!(
                "SELECT g.id, g.name, g.quota_bytes, g.created_by, g.created_at,
                        {GROUP_USAGE} AS used_bytes
                   FROM groups g WHERE g.id = ?1"
            ),
            params![group_id],
            |r| {
                let created_at: String = r.get(4)?;
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    created_at,
                    r.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((id, name, quota_bytes, created_by, created_at, used_bytes)) = row else {
        return Ok(None);
    };
    let created_by_name = match created_by {
        Some(uid) => conn
            .query_row(
                "SELECT username FROM users WHERE id = ?1",
                params![uid],
                |r| r.get(0),
            )
            .optional()?,
        None => None,
    };
    Ok(Some(GroupInfo {
        id,
        name,
        quota_bytes,
        used_bytes,
        created_by,
        created_by_name,
        created_at: super::user::parse_ts(&created_at, 4)?,
        members: member_list(conn, group_id)?,
    }))
}

impl Db {
    /// Every group with members and consumption - the admin dialog's table.
    pub async fn list_groups(&self) -> Result<Vec<GroupInfo>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT g.id FROM groups g ORDER BY g.name COLLATE NOCASE"
            ))?;
            let ids: Vec<i64> = stmt
                .query_map([], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            ids.into_iter()
                .map(|id| group_info(conn, id).map(|g| g.expect("id came from a query")))
                .collect()
        })
        .await
    }

    /// Create a group and put its creator in as the first manager.
    ///
    /// Whoever creates a group staffs it: the creator is a manager of it
    /// (implementation note in concepts/groups.md), so a fresh group is
    /// never left without anybody who may add members or hand out folder
    /// keys.
    pub async fn create_group(
        &self,
        created_by: i64,
        name: String,
        quota_bytes: i64,
    ) -> Result<GroupInfo, AppError> {
        if quota_bytes < 0 {
            return Err(AppError::BadRequest("quota must not be negative".into()));
        }
        self.run(move |conn| {
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO groups (name, quota_bytes, created_by, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![name, quota_bytes, created_by, now],
            )
            .map_err(|e| map_group_constraint(e, &format!("a group named '{name}'")))?;
            let id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO group_members (group_id, user_id, role, added_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, created_by, ROLE_MANAGER, now],
            )
            .map_err(|e| map_group_constraint(e, "the membership"))?;
            group_info(conn, id)?.ok_or(AppError::NotFound)
        })
        .await
    }

    /// Apply the partial group update: each present field is written on its
    /// own, so a rename does not touch the quota and vice versa.
    pub async fn update_group(
        &self,
        group_id: i64,
        name: Option<String>,
        quota_bytes: Option<i64>,
    ) -> Result<GroupInfo, AppError> {
        if let Some(quota) = quota_bytes {
            if quota < 0 {
                return Err(AppError::BadRequest("quota must not be negative".into()));
            }
        }
        self.run(move |conn| {
            if name.is_some() {
                conn.execute(
                    "UPDATE groups SET name = ?1 WHERE id = ?2",
                    params![name, group_id],
                )
                .map_err(|e| {
                    map_group_constraint(
                        e,
                        &format!("a group named '{}'", name.unwrap_or_default()),
                    )
                })?;
            }
            if let Some(quota) = quota_bytes {
                conn.execute(
                    "UPDATE groups SET quota_bytes = ?1 WHERE id = ?2",
                    params![quota, group_id],
                )?;
            }
            group_info(conn, group_id)?.ok_or(AppError::NotFound)
        })
        .await
    }

    /// Delete a group that has been emptied: no members, no file rows
    /// attributed to it (live or trashed). Removing everything first keeps
    /// every deletion an explicit, reviewable step - a group with content
    /// refused here is a group whose folders somebody still has to delete.
    pub async fn delete_group(&self, group_id: i64) -> Result<(), AppError> {
        self.run(move |conn| {
            let members: i64 = conn.query_row(
                "SELECT COUNT(*) FROM group_members WHERE group_id = ?1",
                params![group_id],
                |r| r.get(0),
            )?;
            if members > 0 {
                return Err(AppError::Conflict(
                    "remove all members before deleting the group".into(),
                ));
            }
            let rows: i64 = conn.query_row(
                "SELECT COUNT(*) FROM files WHERE owner_group_id = ?1",
                params![group_id],
                |r| r.get(0),
            )?;
            if rows > 0 {
                return Err(AppError::Conflict(
                    "delete the group's folders first - its files are still attributed to it"
                        .into(),
                ));
            }
            let changed = conn.execute("DELETE FROM groups WHERE id = ?1", params![group_id])?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            Ok(())
        })
        .await
    }

    /// Add a member (by username) with a role, returning the new list.
    pub async fn add_group_member(
        &self,
        group_id: i64,
        username: String,
        role: i64,
    ) -> Result<Vec<GroupMember>, AppError> {
        check_role(role)?;
        self.run(move |conn| {
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM groups WHERE id = ?1",
                params![group_id],
                |r| r.get(0),
            )?;
            if exists == 0 {
                return Err(AppError::NotFound);
            }
            let user_id: Option<i64> = conn
                .query_row(
                    "SELECT id FROM users WHERE username = ?1 COLLATE NOCASE",
                    params![username],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(user_id) = user_id else {
                return Err(AppError::NotFound);
            };
            conn.execute(
                "INSERT INTO group_members (group_id, user_id, role, added_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![group_id, user_id, role, Utc::now().to_rfc3339()],
            )
            .map_err(|e| map_group_constraint(e, "the membership"))?;
            member_list(conn, group_id)
        })
        .await
    }

    /// Change one member's role, returning the new list.
    pub async fn set_group_member_role(
        &self,
        group_id: i64,
        user_id: i64,
        role: i64,
    ) -> Result<Vec<GroupMember>, AppError> {
        check_role(role)?;
        self.run(move |conn| {
            let changed = conn.execute(
                "UPDATE group_members SET role = ?1 WHERE group_id = ?2 AND user_id = ?3",
                params![role, group_id, user_id],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            member_list(conn, group_id)
        })
        .await
    }

    /// Remove a member, returning the new list.
    ///
    /// Their key envelopes for this group's folders go with the membership:
    /// an ex-member keeps nothing that would still open a folder of a group
    /// they can no longer see (the bytes were never theirs to keep - access
    /// follows membership, concepts/groups.md section 4). The rows they
    /// created stay attributed to the group; `owner_id` is audit, not
    /// access.
    pub async fn remove_group_member(
        &self,
        group_id: i64,
        user_id: i64,
    ) -> Result<Vec<GroupMember>, AppError> {
        self.run(move |conn| {
            let changed = conn.execute(
                "DELETE FROM group_members WHERE group_id = ?1 AND user_id = ?2",
                params![group_id, user_id],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            conn.execute(
                "DELETE FROM group_keys WHERE user_id = ?1
                  AND file_id IN (SELECT id FROM files WHERE owner_group_id = ?2)",
                params![user_id, group_id],
            )?;
            member_list(conn, group_id)
        })
        .await
    }

    /// The caller's own groups with their roles: the root badge, the
    /// "new group folder" picker, and the move dialog's group entries.
    pub async fn list_my_groups(&self, user_id: i64) -> Result<Vec<MyGroup>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT g.id, g.name, m.role, g.quota_bytes, {GROUP_USAGE} AS used_bytes
                   FROM groups g
                   JOIN group_members m ON m.group_id = g.id
                  WHERE m.user_id = ?1
                  ORDER BY g.name COLLATE NOCASE"
            ))?;
            let rows = stmt.query_map(params![user_id], |r| {
                Ok(MyGroup {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    role: r.get(2)?,
                    quota_bytes: r.get(3)?,
                    used_bytes: r.get(4)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// The caller's stored key envelopes for group top-level folders
    /// (`GET /api/groups/keys`): one per folder they may open, to feed the
    /// frontend's envelope cache beside the share ones.
    pub async fn group_key_envelopes(
        &self,
        user_id: i64,
    ) -> Result<Vec<GroupKeyEnvelope>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT gk.file_id, f.owner_group_id, g.name, gk.envelope, gk.created_at
                   FROM group_keys gk
                   JOIN files f ON f.id = gk.file_id
                   JOIN groups g ON g.id = f.owner_group_id
                  WHERE gk.user_id = ?1 AND f.parent_id IS NULL
                    AND f.deleted_at IS NULL
                  ORDER BY g.name COLLATE NOCASE, f.name COLLATE NOCASE",
            )?;
            let rows = stmt.query_map(params![user_id], |r| {
                let created_at: String = r.get(4)?;
                Ok(GroupKeyEnvelope {
                    file_id: r.get(0)?,
                    group_id: r.get(1)?,
                    group_name: r.get(2)?,
                    envelope: r.get(3)?,
                    created_at: super::user::parse_ts(&created_at, 4)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// Every (top-level folder, member) pair still missing a key record
    /// (`GET /api/groups/{id}/keys/pending`): the manager's work list for
    /// the distribution UI. Only a manager sees it - a member gets 403, a
    /// non-member the 404 their listings give them.
    pub async fn group_keys_pending(
        &self,
        user_id: i64,
        group_id: i64,
    ) -> Result<Vec<PendingGroupKey>, AppError> {
        self.run(move |conn| {
            let role = group_role(conn, user_id, group_id)?.ok_or(AppError::NotFound)?;
            if role != ROLE_MANAGER {
                return Err(AppError::ForbiddenDetail(
                    "only a group manager may see or distribute folder keys".into(),
                ));
            }
            let mut stmt = conn.prepare(
                "SELECT f.id, f.name, m.user_id, u.username, u.display_name,
                        EXISTS(SELECT 1 FROM user_keys uk WHERE uk.user_id = m.user_id)
                   FROM files f
                   JOIN group_members m ON m.group_id = f.owner_group_id
                   JOIN users u ON u.id = m.user_id
                  WHERE f.owner_group_id = ?1 AND f.parent_id IS NULL
                    AND f.deleted_at IS NULL
                    AND NOT EXISTS (SELECT 1 FROM group_keys gk
                                     WHERE gk.file_id = f.id AND gk.user_id = m.user_id)
                  ORDER BY f.name COLLATE NOCASE, u.username COLLATE NOCASE",
            )?;
            let rows = stmt.query_map(params![group_id], |r| {
                Ok(PendingGroupKey {
                    file_id: r.get(0)?,
                    folder_name: r.get(1)?,
                    user_id: r.get(2)?,
                    username: r.get(3)?,
                    display_name: r.get(4)?,
                    has_public_key: r.get(5)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// Store one member's wrapped key record for one top-level folder
    /// (upsert - re-distributing overwrites the old envelope), checking the
    /// whole chain in one statement block: the caller is the group's
    /// manager, the folder is this group's live top-level row, and the
    /// recipient is a member of it.
    pub async fn put_group_key(
        &self,
        manager_id: i64,
        group_id: i64,
        file_id: i64,
        user_id: i64,
        envelope: String,
    ) -> Result<(), AppError> {
        self.run(move |conn| {
            let role = group_role(conn, manager_id, group_id)?.ok_or(AppError::NotFound)?;
            if role != ROLE_MANAGER {
                return Err(AppError::ForbiddenDetail(
                    "only a group manager may see or distribute folder keys".into(),
                ));
            }
            let folder = conn
                .query_row(
                    "SELECT 1 FROM files
                      WHERE id = ?1 AND owner_group_id = ?2 AND parent_id IS NULL
                        AND deleted_at IS NULL",
                    params![file_id, group_id],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?;
            if folder.is_none() {
                return Err(AppError::NotFound);
            }
            let member = conn
                .query_row(
                    "SELECT 1 FROM group_members WHERE group_id = ?1 AND user_id = ?2",
                    params![group_id, user_id],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?;
            if member.is_none() {
                return Err(AppError::BadRequest(
                    "the recipient is not a member of this group".into(),
                ));
            }
            conn.execute(
                "INSERT INTO group_keys (file_id, user_id, envelope, created_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(file_id, user_id)
                 DO UPDATE SET envelope = ?3, created_at = ?4",
                params![file_id, user_id, envelope, Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A throwaway database with the real migrations applied (file-backed:
    /// the pool's eight connections would each get their own private
    /// database from `:memory:`).
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
        let dir = std::env::temp_dir().join(format!("fxcloud-group-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let db = Db::open(&dir.join("fxcloud.db")).expect("migrations must apply to an empty db");
        Scratch { db, dir }
    }

    fn user(s: &Scratch, name: &str) -> i64 {
        let conn = s.db.pool.get().unwrap();
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, created_at)
             VALUES (?1, 'hash', ?1, '2026-01-01T00:00:00Z')",
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

    #[tokio::test]
    async fn the_creator_becomes_the_groups_first_manager() {
        let s = scratch();
        let alice = user(&s, "alice");

        let group =
            s.db.create_group(alice, "Finance".into(), 1024)
                .await
                .unwrap();
        assert_eq!(group.name, "Finance");
        assert_eq!(group.created_by, Some(alice));
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0].user_id, alice);
        assert_eq!(group.members[0].role, ROLE_MANAGER);
        assert_eq!(
            s.db.group_role_of(alice, group.id).await.unwrap(),
            Some(ROLE_MANAGER)
        );

        // A second creator cannot take the name: unique, case-insensitive.
        let bob = user(&s, "bob");
        assert!(matches!(
            s.db.create_group(bob, "finance".into(), 1).await,
            Err(AppError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn members_come_and_go_with_roles_and_keys() {
        let s = scratch();
        let alice = user(&s, "alice");
        let bob = user(&s, "bob");
        let group = s.db.create_group(alice, "Ops".into(), 1024).await.unwrap();

        let members =
            s.db.add_group_member(group.id, "bob".into(), ROLE_MEMBER)
                .await
                .unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[1].role, ROLE_MEMBER);
        assert_eq!(
            s.db.group_role_of(bob, group.id).await.unwrap(),
            Some(ROLE_MEMBER)
        );

        // One membership per member: adding again is a conflict, a role
        // outside the table's range is refused outright.
        assert!(matches!(
            s.db.add_group_member(group.id, "bob".into(), ROLE_MEMBER)
                .await,
            Err(AppError::Conflict(_))
        ));
        assert!(matches!(
            s.db.add_group_member(group.id, "bob".into(), 7).await,
            Err(AppError::BadRequest(_))
        ));

        let members =
            s.db.set_group_member_role(group.id, bob, ROLE_MANAGER)
                .await
                .unwrap();
        assert_eq!(members[1].role, ROLE_MANAGER);

        // The member view only shows their own groups, with the role the
        // file checks derive permissions from.
        let mine = s.db.list_my_groups(bob).await.unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].role, ROLE_MANAGER);

        let members = s.db.remove_group_member(group.id, bob).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(s.db.group_role_of(bob, group.id).await.unwrap(), None);
        assert!(matches!(
            s.db.remove_group_member(group.id, bob).await,
            Err(AppError::NotFound)
        ));

        // Only an emptied group may be deleted.
        assert!(matches!(
            s.db.delete_group(group.id).await,
            Err(AppError::Conflict(_))
        ));
        s.db.remove_group_member(group.id, alice).await.unwrap();
        s.db.delete_group(group.id).await.unwrap();
        assert!(
            s.db.list_groups().await.unwrap().is_empty(),
            "the deleted group is gone from the admin list"
        );
    }

    #[tokio::test]
    async fn envelopes_and_pending_follow_the_memberships() {
        let s = scratch();
        let alice = user(&s, "alice");
        let bob = user(&s, "bob");
        let group = s.db.create_group(alice, "Eng".into(), 1024).await.unwrap();
        s.db.add_group_member(group.id, "bob".into(), ROLE_MEMBER)
            .await
            .unwrap();

        // The top-level folder: the bootstrap the JSON create route takes.
        let folder =
            s.db.create_dir(alice, None, Some(group.id), "specs".into())
                .await
                .unwrap();
        assert_eq!(folder.owner_group_id, Some(group.id));
        assert_eq!(folder.owner_id, alice);

        // Before any wrap: one pending pair per member.
        let pending = s.db.group_keys_pending(alice, group.id).await.unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().all(|p| p.file_id == folder.id));
        assert!(pending.iter().all(|p| !p.has_public_key));

        // One wrap clears that pair, the other stays pending.
        s.db.put_group_key(alice, group.id, folder.id, alice, "envelope-a".into())
            .await
            .unwrap();
        let pending = s.db.group_keys_pending(alice, group.id).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].user_id, bob);

        // Re-distributing overwrites instead of duplicating.
        s.db.put_group_key(alice, group.id, folder.id, alice, "envelope-a2".into())
            .await
            .unwrap();
        let mine = s.db.group_key_envelopes(alice).await.unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].envelope, "envelope-a2");
        assert_eq!(mine[0].group_id, group.id);
        assert_eq!(mine[0].group_name, "Eng");
        assert!(s.db.group_key_envelopes(bob).await.unwrap().is_empty());

        // Removing the member takes their envelopes with the membership.
        s.db.put_group_key(alice, group.id, folder.id, bob, "envelope-b".into())
            .await
            .unwrap();
        assert_eq!(s.db.group_key_envelopes(bob).await.unwrap().len(), 1);
        s.db.remove_group_member(group.id, bob).await.unwrap();
        assert!(s.db.group_key_envelopes(bob).await.unwrap().is_empty());
    }
}
