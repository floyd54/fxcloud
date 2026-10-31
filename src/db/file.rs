use std::collections::HashMap;

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::error::AppError;
use crate::models::{BlobOwner, BlobRef, Breadcrumb, FileEntry, FileVersion, TreeOwner};
use crate::sharing::{role_perms, PERM_ALL};

use super::share::{covering_share, share_name_taken};
use super::user::parse_ts;
use super::Db;

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileEntry> {
    let created_at: String = row.get("created_at")?;
    let modified_at: String = row.get("modified_at")?;
    let deleted_at: Option<String> = row.get("deleted_at")?;
    Ok(FileEntry {
        id: row.get("id")?,
        owner_id: row.get("owner_id")?,
        owner_group_id: row.get("owner_group_id")?,
        // Filled by listings that alias the join in (`g.name AS
        // group_name`); queries without the join leave it empty (the lookup
        // of a missing column is an error, which reads as "absent" here).
        group_name: row.get::<_, Option<String>>("group_name").unwrap_or(None),
        parent_id: row.get("parent_id")?,
        name: row.get("name")?,
        is_dir: row.get::<_, i64>("is_dir")? != 0,
        size: row.get("size")?,
        mime: row.get("mime")?,
        created_at: parse_ts(&created_at, 7)?,
        modified_at: parse_ts(&modified_at, 8)?,
        permissions: PERM_ALL,
        owner_name: None,
        subtree_bytes: None,
        enc_version: row.get("enc_version")?,
        // Blobs only ever leave as base64: the JSON API and the WebDAV layer
        // both speak that, and serde would otherwise emit an array of bytes.
        enc_key: row
            .get::<_, Option<Vec<u8>>>("enc_key")?
            .map(|b| BASE64.encode(b)),
        deleted_at: deleted_at.as_deref().map(|s| parse_ts(s, 9)).transpose()?,
        purge_at: None,
    })
}

/// Build a [`BlobRef`] from row values: the attribution decides the
/// namespace - personal rows keep their user id forever, group rows go
/// under `g<group_id>` (concepts/groups.md section 3).
fn blob_ref(
    id: i64,
    owner_id: i64,
    owner_group_id: Option<i64>,
    created_at: &str,
) -> rusqlite::Result<BlobRef> {
    Ok(BlobRef::Entry {
        file_id: id,
        owner: match owner_group_id {
            Some(group_id) => BlobOwner::Group(group_id),
            None => BlobOwner::User(owner_id),
        },
        created_at: parse_ts(created_at, 2)?,
    })
}

/// The acting user's role in `group_id`, or `None` when they are not a
/// member - the one fact every group permission check starts from.
pub(super) fn group_role(conn: &Connection, user_id: i64, group_id: i64) -> rusqlite::Result<Option<i64>> {
    let role: Option<i64> = conn
        .query_row(
            "SELECT role FROM group_members WHERE group_id = ?1 AND user_id = ?2",
            params![group_id, user_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(role)
}

/// The `(owner_id, owner_group_id)` pair a new row under `principal` is
/// created with: a personal tree records the tree owner (the sharer, as
/// always), a group folder records the *creator* for the audit while the
/// group pays (concepts/groups.md section 3).
fn insert_owner(principal: TreeOwner, creator: i64) -> (i64, Option<i64>) {
    match principal {
        TreeOwner::User(owner) => (owner, None),
        TreeOwner::Group(group_id) => (creator, Some(group_id)),
    }
}

/// Bindings for [`PRINCIPAL_GUARD`], in its placeholder order: the acting
/// user's id for a personal tree (and no group), or the group id (and no
/// user). A personal write never lands on a group row and vice versa, even
/// when the requester created the group row themselves.
fn principal_params(principal: TreeOwner) -> (Option<i64>, Option<i64>) {
    match principal {
        TreeOwner::User(user_id) => (Some(user_id), None),
        TreeOwner::Group(group_id) => (None, Some(group_id)),
    }
}

/// Build a version's [`BlobRef`] from `(file_id, blob_created_at)` row
/// values: the version key is already the complete path component.
fn version_blob_ref(file_id: i64, blob_key: &str) -> BlobRef {
    BlobRef::Version {
        file_id,
        version_key: blob_key.to_string(),
    }
}

/// Whether `additional` more bytes still fit into `principal`'s quota.
///
/// Every path that adds content funnels through here — `create_file` and
/// `update_file_meta` run this in the same statement block as their write, so
/// content only ever appears when it fits. Bulk copies pre-check the whole
/// subtree via [`Db::check_quota`] before they start.
///
/// Kept versions count (concepts/versioning.md decision 4): the sum is the
/// principal's own rows plus the history of those rows, so a save that pins
/// the outgoing bytes cannot slip past the gate by keeping them. A user's
/// sum covers only their personal rows - group folders bill the group, never
/// the member who happened to write into them (concepts/groups.md section 4).
fn ensure_quota(conn: &Connection, principal: TreeOwner, additional: i64) -> Result<(), AppError> {
    if additional <= 0 {
        return Ok(());
    }
    let (quota, used): (i64, i64) = match principal {
        TreeOwner::User(owner_id) => conn.query_row(
            "SELECT u.quota_bytes,
                    COALESCE((SELECT SUM(f.size) FROM files f
                               WHERE f.owner_id = u.id AND f.owner_group_id IS NULL
                                 AND f.is_dir = 0), 0)
                  + COALESCE((SELECT SUM(v.size) FROM file_versions v
                              JOIN files f ON f.id = v.file_id
                               WHERE f.owner_id = u.id AND f.owner_group_id IS NULL
                                 AND f.is_dir = 0), 0)
               FROM users u WHERE u.id = ?1",
            params![owner_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?,
        TreeOwner::Group(group_id) => conn.query_row(
            "SELECT g.quota_bytes,
                    COALESCE((SELECT SUM(f.size) FROM files f
                               WHERE f.owner_group_id = ?1 AND f.is_dir = 0), 0)
                  + COALESCE((SELECT SUM(v.size) FROM file_versions v
                              JOIN files f ON f.id = v.file_id
                               WHERE f.owner_group_id = ?1 AND f.is_dir = 0), 0)
               FROM groups g WHERE g.id = ?1",
            params![group_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?,
    };
    if used + additional > quota {
        return Err(AppError::QuotaExceeded { used, quota });
    }
    Ok(())
}

const ENTRY_COLS: &str = "id, owner_id, owner_group_id, parent_id, name, is_dir, size, mime, \
                         created_at, modified_at, deleted_at, enc_version, enc_key";

/// Enforce the count bound on one file's history: keep the newest `keep`
/// versions, collect and delete the rest. `keep <= 0` disables the bound
/// (concepts/versioning.md decision 1), so a user who turned it off never
/// loses history here.
fn prune_versions(conn: &Connection, file_id: i64, keep: i64) -> Result<Vec<BlobRef>, AppError> {
    if keep <= 0 {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT id, file_id, blob_created_at FROM file_versions
          WHERE file_id = ?1
            AND id NOT IN (SELECT id FROM file_versions WHERE file_id = ?1
                            ORDER BY created_at DESC, id DESC LIMIT ?2)",
    )?;
    let expired = stmt
        .query_map(params![file_id, keep], |r| {
            Ok(version_blob_ref(r.get(1)?, &r.get::<_, String>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    conn.execute(
        "DELETE FROM file_versions
          WHERE file_id = ?1
            AND id NOT IN (SELECT id FROM file_versions WHERE file_id = ?1
                            ORDER BY created_at DESC, id DESC LIMIT ?2)",
        params![file_id, keep],
    )?;
    Ok(expired)
}

/// One file's version rows, newest first - the shared read of the listing
/// and the single-version lookup (permission checks happen in the callers).
fn read_versions(conn: &Connection, file_id: i64) -> Result<Vec<FileVersion>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT id, size, enc_version, created_at, blob_created_at FROM file_versions
          WHERE file_id = ?1
          ORDER BY created_at DESC, id DESC",
    )?;
    let rows = stmt
        .query_map(params![file_id], |r| {
            let created_at: String = r.get(3)?;
            Ok(FileVersion {
                id: r.get(0)?,
                size: r.get(1)?,
                enc_version: r.get(2)?,
                created_at: parse_ts(&created_at, 5)?,
                blob_key: r.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Entries that are trash roots: marked themselves, with a live (or absent)
/// parent. Children of a trashed folder are part of that folder's restore
/// unit, not separate trash items.
const TRASH_ROOTS: &str = "deleted_at IS NOT NULL
       AND (parent_id IS NULL
            OR parent_id IN (SELECT id FROM files WHERE deleted_at IS NULL))";

/// The row interlock for a write whose permission check resolved a
/// [`TreeOwner`]: the row must sit under that same principal - a personal
/// tree touches only its own un-attributed rows, a group only its own.
/// Binds two trailing params in this order (see [`principal_params`]).
const PRINCIPAL_GUARD: &str = "((owner_id = ? AND owner_group_id IS NULL)
            OR (owner_group_id = ?))";

/// A validated move whose rows have not been touched yet (see
/// [`Db::prepare_move`]). The caller relocates the blob when
/// [`MovePlan::relocation`] returns one - link the new path, apply, then
/// drop the old name - so a crash at any instant leaves the content
/// reachable under some path (the crash discipline, Audit.md F).
#[derive(Debug)]
pub struct MovePlan {
    id: i64,
    new_parent: Option<i64>,
    new_name: String,
    src: TreeOwner,
    dest: TreeOwner,
    relocation: Option<(BlobRef, BlobRef)>,
}

impl MovePlan {
    /// Old path first, destination path second - only when the attribution
    /// (and with it the blob namespace) changes with the move.
    pub fn relocation(&self) -> Option<(&BlobRef, &BlobRef)> {
        self.relocation.as_ref().map(|(old, new)| (old, new))
    }
}

impl Db {
    /// List the direct children of `parent_id` as seen by `user_id`
    /// (root when `None`), folders-first then alphabetically.
    ///
    /// Root merges the user's own entries with their groups' top-level
    /// folders (badged) and incoming share mounts; a foreign parent folder
    /// is listed when a covering share grants READ, a group folder whenever
    /// the requester is a member with READ.
    pub async fn list_children(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
    ) -> Result<Vec<FileEntry>, AppError> {
        self.run(move |conn| {
            let mut entries = match parent_id {
                None => {
                    let mut entries = own_children(conn, user_id, None)?;
                    entries.extend(group_roots(conn, user_id)?);
                    entries.extend(incoming_mounts(conn, user_id)?);
                    sort_entries(&mut entries);
                    entries
                }
                Some(pid) => {
                    let parent = get_entry_by_id(conn, pid)?;
                    if !parent.is_dir {
                        return Err(AppError::BadRequest("parent is not a folder".into()));
                    }
                    if let Some(group_id) = parent.owner_group_id {
                        // The membership role decides, creator or not
                        // (concepts/groups.md section 4).
                        let role = group_role(conn, user_id, group_id)?
                            .ok_or(AppError::NotFound)?;
                        let perms = role_perms(role);
                        if !crate::sharing::grants(perms, crate::sharing::PERM_READ) {
                            return Err(AppError::NotFound);
                        }
                        let mut entries = group_children(conn, group_id, Some(pid))?;
                        let group_name = group_name(conn, group_id)?;
                        let owners = creator_names(conn, group_id, Some(pid))?;
                        for e in &mut entries {
                            e.permissions = perms;
                            e.owner_name = owners.get(&e.owner_id).cloned();
                            e.group_name = Some(group_name.clone());
                        }
                        entries
                    } else if parent.owner_id == user_id {
                        own_children(conn, user_id, Some(pid))?
                    } else {
                        // Foreign folder: only a covering share may open it.
                        let access =
                            covering_share(conn, user_id, pid)?.ok_or(AppError::NotFound)?;
                        if !access.can(crate::sharing::PERM_READ) {
                            return Err(AppError::Forbidden);
                        }
                        let mut entries = own_children(conn, parent.owner_id, Some(pid))?;
                        let owner_name = username_by_id(conn, parent.owner_id)?;
                        for e in &mut entries {
                            e.permissions = access.permissions;
                            e.owner_name = Some(owner_name.clone());
                        }
                        entries
                    }
                }
            };
            fill_subtree_sizes(conn, &mut entries)?;
            Ok(entries)
        })
        .await
    }

    /// Fetch a single entry, verifying it belongs to `owner_id`.
    pub async fn get_entry(&self, owner_id: i64, id: i64) -> Result<Option<FileEntry>, AppError> {
        self.run(move |conn| {
            let mut stmt =
                conn.prepare(&format!("SELECT {ENTRY_COLS} FROM files WHERE id = ?1 AND owner_id = ?2"))?;
            let found = stmt.query_row(params![id, owner_id], row_to_entry).optional()?;
            Ok(found)
        })
        .await
    }

    /// Create a directory under `parent_id` (root when `None`).
    ///
    /// A foreign parent is allowed when a covering share grants CREATE; the
    /// new entry then joins the *owner's* tree, exactly like Nextcloud. A
    /// group folder joins the group's tree with the creator in `owner_id`;
    /// `group` bootstraps a group's top-level folder at the root.
    pub async fn create_dir(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
        group: Option<i64>,
        name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;
            let principal = create_target(conn, user_id, parent_id, group, &name)?;
            let (owner, owner_group_id) = insert_owner(principal, user_id);
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO files (owner_id, owner_group_id, parent_id, name, is_dir, size,
                                    mime, created_at, modified_at)
                 VALUES (?1, ?2, ?3, ?4, 1, 0, NULL, ?5, ?5)",
                params![owner, owner_group_id, parent_id, name, now],
            )
            .map_err(|e| map_constraint(e, &name))?;
            let id = conn.last_insert_rowid();
            let entry = get_entry_by_id(conn, id)?;
            Ok(entry)
        })
        .await
    }

    /// Insert a file entry (metadata only). The caller writes the blob separately.
    ///
    /// Shares the parent rules of [`Db::create_dir`], including the root
    /// bootstrap through `group`.
    pub async fn create_file(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
        group: Option<i64>,
        name: String,
        size: i64,
        mime: Option<String>,
        enc_version: i64,
        enc_key: Option<Vec<u8>>,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;
            let principal = create_target(conn, user_id, parent_id, group, &name)?;
            // Quota gate sits before the INSERT: content is never tracked that
            // the principal has no space for (shared uploads count against
            // the sharer, group uploads against the group, because that tree
            // stores the bytes).
            ensure_quota(conn, principal, size)?;
            let (owner, owner_group_id) = insert_owner(principal, user_id);
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO files (owner_id, owner_group_id, parent_id, name, is_dir, size,
                                    mime, created_at, modified_at, enc_version, enc_key)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?7, ?8, ?9)",
                params![
                    owner,
                    owner_group_id,
                    parent_id,
                    name,
                    size,
                    mime,
                    now,
                    enc_version,
                    enc_key
                ],
            )
            .map_err(|e| map_constraint(e, &name))?;
            let id = conn.last_insert_rowid();
            let entry = get_entry_by_id(conn, id)?;
            Ok(entry)
        })
        .await
    }

    /// Get-or-create a directory by name (idempotent; used by folder uploads).
    ///
    /// Returns the existing folder when one is already there; otherwise creates
    /// it. A foreign parent needs a covering share with CREATE (read-only
    /// shares can only return an existing folder, never create one), a group
    /// folder needs the role's CREATE; `group` bootstraps at the root.
    pub async fn ensure_dir(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
        group: Option<i64>,
        name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;

            // Whose tree are we operating in, and may we create there?
            let (principal, can_create) = match parent_id {
                None => match group {
                    Some(group_id) => {
                        let role =
                            group_role(conn, user_id, group_id)?.ok_or(AppError::NotFound)?;
                        let perms = role_perms(role);
                        (
                            TreeOwner::Group(group_id),
                            crate::sharing::grants(perms, crate::sharing::PERM_CREATE),
                        )
                    }
                    None => (TreeOwner::User(user_id), true),
                },
                Some(pid) => {
                    let parent = get_entry_by_id(conn, pid)?;
                    if !parent.is_dir {
                        return Err(AppError::BadRequest("parent is not a folder".into()));
                    }
                    if let Some(group_id) = parent.owner_group_id {
                        // Non-members 404 (the folder does not exist for
                        // them), members carry their role's mask.
                        let role =
                            group_role(conn, user_id, group_id)?.ok_or(AppError::NotFound)?;
                        let perms = role_perms(role);
                        (
                            TreeOwner::Group(group_id),
                            crate::sharing::grants(perms, crate::sharing::PERM_CREATE),
                        )
                    } else if parent.owner_id == user_id {
                        (TreeOwner::User(user_id), true)
                    } else {
                        let access =
                            covering_share(conn, user_id, pid)?.ok_or(AppError::NotFound)?;
                        if !access.can(crate::sharing::PERM_READ) {
                            return Err(AppError::NotFound);
                        }
                        (
                            TreeOwner::User(parent.owner_id),
                            access.can(crate::sharing::PERM_CREATE),
                        )
                    }
                }
            };

            // Already there? That's our answer (as long as it's a folder).
            if let Some(existing) = find_child(conn, principal, parent_id, &name)? {
                if existing.is_dir {
                    return Ok(existing);
                }
                return Err(AppError::Conflict(format!(
                    "'{name}' already exists and is not a folder"
                )));
            }

            if !can_create {
                return Err(AppError::Forbidden);
            }
            if parent_id.is_none() && share_name_taken(conn, user_id, &name)? {
                return Err(AppError::Conflict(format!("'{name}' already exists here")));
            }

            let (owner, owner_group_id) = insert_owner(principal, user_id);
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO files (owner_id, owner_group_id, parent_id, name, is_dir, size,
                                    mime, created_at, modified_at)
                 VALUES (?1, ?2, ?3, ?4, 1, 0, NULL, ?5, ?5)",
                params![owner, owner_group_id, parent_id, name, now],
            )
            .map_err(|e| map_constraint(e, &name))?;
            get_entry_by_id(conn, conn.last_insert_rowid())
        })
        .await
    }

    /// Rename an entry (or update a file's metadata after an overwrite).
    ///
    /// Foreign entries require the covering share to grant UPDATE; group
    /// entries the membership role's UPDATE.
    pub async fn rename_entry(
        &self,
        user_id: i64,
        id: i64,
        name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;
            let principal = update_target(conn, user_id, id, crate::sharing::PERM_UPDATE)?;
            let (user, group) = principal_params(principal);
            let changed = conn.execute(
                &format!(
                    "UPDATE files SET name = ?1, modified_at = ?2
                     WHERE id = ?3 AND {PRINCIPAL_GUARD}"
                ),
                params![name, Utc::now().to_rfc3339(), id, user, group],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            let entry = get_entry_by_id(conn, id)?;
            Ok(entry)
        })
        .await
    }

    /// Move an entry to the trash: only the entry itself is marked with a
    /// deletion time - its subtree rows and blob content stay untouched, so
    /// a restore is a single UPDATE and nothing moves on disk.
    ///
    /// Foreign entries require the covering share to grant DELETE, group
    /// entries the role's DELETE; the mark lands in the *tree's* trash, so
    /// the owner (or every member, for a group row) sees and restores it.
    pub async fn trash_entry(&self, user_id: i64, id: i64) -> Result<(), AppError> {
        self.run(move |conn| {
            let principal = update_target(conn, user_id, id, crate::sharing::PERM_DELETE)?;
            let (user, group) = principal_params(principal);
            conn.execute(
                &format!(
                    "UPDATE files SET deleted_at = ?1
                     WHERE id = ?2 AND {PRINCIPAL_GUARD} AND deleted_at IS NULL"
                ),
                params![Utc::now().to_rfc3339(), id, user, group],
            )?;
            Ok(())
        })
        .await
    }

    /// Hard-delete an entry's row subtree and return the blobs to unlink.
    ///
    /// This is the *real* deletion, used by the trash purge and by rollback
    /// paths (a failed upload). Owner-scoped only: a share cannot lead here -
    /// a grantee's delete marks the owner's entry as trashed instead.
    pub async fn hard_delete_entry(&self, user_id: i64, id: i64) -> Result<Vec<BlobRef>, AppError> {
        self.run(move |conn| {
            let owner: Option<i64> = conn
                .query_row(
                    "SELECT owner_id FROM files WHERE id = ?1",
                    params![id],
                    |r| r.get(0),
                )
                .optional()?;
            match owner {
                Some(o) if o == user_id => hard_delete(conn, id),
                _ => Err(AppError::NotFound),
            }
        })
        .await
    }

    /// The caller's trash: trashed roots, newest first. One row per restore
    /// unit - children of a trashed folder come back with their parent.
    /// Group rows are in every member's view, badged with their group
    /// (concepts/groups.md section 4).
    pub async fn trash_list(&self, user_id: i64) -> Result<Vec<FileEntry>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {ENTRY_COLS} FROM files
                 WHERE {TRASH_ROOTS}
                   AND ((owner_id = ?1 AND owner_group_id IS NULL)
                        OR owner_group_id IN (SELECT group_id FROM group_members
                                               WHERE user_id = ?1))
                 ORDER BY deleted_at DESC, name COLLATE NOCASE ASC"
            ))?;
            let mut entries = stmt
                .query_map(params![user_id], row_to_entry)?
                .collect::<Result<Vec<_>, _>>()?;
            for e in &mut entries {
                if let Some(group_id) = e.owner_group_id {
                    e.group_name = Some(group_name(conn, group_id)?);
                    e.owner_name = Some(username_by_id(conn, e.owner_id)?);
                }
            }
            // Trashed folders still occupy the disk, so their subtree size
            // belongs in the listing just like for live folders.
            fill_subtree_sizes(conn, &mut entries)?;
            Ok(entries)
        })
        .await
    }

    /// Bring a trashed entry back to where it was; the whole subtree returns
    /// with it. A live sibling that took the name in the meantime gets a
    /// " (restored)" suffix, so the restore always succeeds visibly.
    ///
    /// Personal rows restore through their owner (as always), group rows
    /// through any member's DELETE bit - the trash view shows them to every
    /// member, so every member may put them back (concepts/groups.md
    /// section 4).
    pub async fn restore_trash(&self, user_id: i64, id: i64) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            let entry = get_entry_by_id(conn, id)?;
            if entry.deleted_at.is_none() {
                return Err(AppError::NotFound);
            }
            let principal = match entry.owner_group_id {
                Some(group_id) => {
                    let role =
                        group_role(conn, user_id, group_id)?.ok_or(AppError::NotFound)?;
                    if !crate::sharing::grants(role_perms(role), crate::sharing::PERM_DELETE) {
                        return Err(AppError::NotFound);
                    }
                    TreeOwner::Group(group_id)
                }
                None => {
                    if entry.owner_id != user_id {
                        return Err(AppError::NotFound);
                    }
                    TreeOwner::User(user_id)
                }
            };
            match entry.parent_id {
                // A root-level item goes straight back to the root.
                None => {
                    conn.execute(
                        "UPDATE files SET deleted_at = NULL WHERE id = ?1",
                        params![id],
                    )?;
                }
                Some(pid) => {
                    match get_entry_by_id(conn, pid) {
                        // Not a trash root of its own: restore the parent first.
                        Ok(parent) if parent.deleted_at.is_some() => {
                            return Err(AppError::Conflict(
                                "the original folder is in the trash - restore it first".into(),
                            ));
                        }
                        Ok(_) => {}
                        // Parent row gone (a purge takes the subtree along, so
                        // this cannot normally happen): restore to the root.
                        Err(AppError::NotFound) => {
                            conn.execute(
                                "UPDATE files SET deleted_at = NULL, parent_id = NULL
                                 WHERE id = ?1",
                                params![id],
                            )?;
                            return get_entry_by_id(conn, id);
                        }
                        Err(e) => return Err(e),
                    }
                    let mut name = entry.name.clone();
                    let mut nth = 0;
                    while find_child(conn, principal, Some(pid), &name)?.is_some() {
                        nth += 1;
                        name = match nth {
                            1 => format!("{} (restored)", entry.name),
                            n => format!("{} (restored {n})", entry.name),
                        };
                    }
                    conn.execute(
                        "UPDATE files SET deleted_at = NULL, name = ?1 WHERE id = ?2",
                        params![name, id],
                    )?;
                }
            }
            get_entry_by_id(conn, id)
        })
        .await
    }

    /// Hard-delete every trashed root older than `older_than_days` (rows via
    /// the foreign-key cascade, blobs returned for the caller to unlink).
    /// Runs on the background sweep: at startup and then on the interval.
    pub async fn purge_expired_trash(
        &self,
        older_than_days: i64,
    ) -> Result<Vec<BlobRef>, AppError> {
        let cutoff = (Utc::now() - chrono::Duration::days(older_than_days)).to_rfc3339();
        self.run(move |conn| purge_roots(conn, None, Some(cutoff)))
            .await
    }

    /// Hard-delete the user's whole trash right now ("Empty trash").
    pub async fn empty_trash(&self, user_id: i64) -> Result<Vec<BlobRef>, AppError> {
        self.run(move |conn| purge_roots(conn, Some(user_id), None))
            .await
    }

    /// Hard-delete a single trashed root in the caller's trash ("Delete
    /// permanently"): their personal rows, or a group row any member may
    /// purge with the role's DELETE bit (concepts/groups.md section 4).
    pub async fn purge_trash_item(&self, user_id: i64, id: i64) -> Result<Vec<BlobRef>, AppError> {
        self.run(move |conn| {
            let entry = get_entry_by_id(conn, id)?;
            if entry.deleted_at.is_none() {
                return Err(AppError::NotFound);
            }
            match entry.owner_group_id {
                Some(group_id) => {
                    let role =
                        group_role(conn, user_id, group_id)?.ok_or(AppError::NotFound)?;
                    if !crate::sharing::grants(role_perms(role), crate::sharing::PERM_DELETE) {
                        return Err(AppError::NotFound);
                    }
                }
                None => {
                    if entry.owner_id != user_id {
                        return Err(AppError::NotFound);
                    }
                }
            }
            // Only trash roots are units of their own; a child of a trashed
            // folder goes with its parent.
            let parent_is_trashed = match entry.parent_id {
                None => false,
                Some(pid) => matches!(get_entry_by_id(conn, pid), Ok(p) if p.deleted_at.is_some()),
            };
            if parent_is_trashed {
                return Err(AppError::NotFound);
            }
            hard_delete(conn, id)
        })
        .await
    }

    /// Owner, attribution and creation time of every file row — one query
    /// feeding the startup blob migration, instead of one lookup per blob.
    pub async fn blob_origins(&self) -> Result<HashMap<i64, BlobRef>, AppError> {
        self.run(move |conn| {
            let mut stmt =
                conn.prepare("SELECT id, owner_id, owner_group_id, created_at FROM files")?;
            let mut rows = stmt.query_map([], |r| {
                let id: i64 = r.get(0)?;
                let owner_id: i64 = r.get(1)?;
                let owner_group_id: Option<i64> = r.get(2)?;
                let created_at: String = r.get(3)?;
                Ok((id, blob_ref(id, owner_id, owner_group_id, &created_at)?))
            })?;
            let mut out = HashMap::new();
            while let Some(row) = rows.next() {
                let (id, blob) = row?;
                out.insert(id, blob);
            }
            Ok(out)
        })
        .await
    }

    /// Build the breadcrumb trail from the root down to (and including) `id`.
    ///
    /// For entries reached through a share the trail is cut at the mount point
    /// (the owner's own root above the shared item is not visible), and the
    /// mount crumb shows the share's display name. A trail that starts at a
    /// group's top-level folder stays whole - that folder *is* the viewer's
    /// root when they are a member, and there is nothing to show above it.
    pub async fn breadcrumbs(&self, user_id: i64, id: i64) -> Result<Vec<Breadcrumb>, AppError> {
        self.run(move |conn| {
            let mut trail: Vec<Breadcrumb> = Vec::new();
            let mut current = Some(id);
            let mut top_owner: Option<i64> = None;
            let mut top_group: Option<i64> = None;
            let mut hops = 0;
            while let Some(cid) = current {
                // The depth cap turns a corrupt parent cycle into a clean
                // 404 - the same guard under_trash and covering_share
                // carry (Audit.md F6); a trail deeper than 64 is
                // unreachable anyway.
                hops += 1;
                if hops > 64 {
                    return Err(AppError::NotFound);
                }
                let (name, parent, owner, group, enc_key): (
                    String,
                    Option<i64>,
                    i64,
                    Option<i64>,
                    Option<Vec<u8>>,
                ) = conn.query_row(
                    "SELECT name, parent_id, owner_id, owner_group_id, enc_key
                       FROM files WHERE id = ?1",
                    params![cid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )?;
                top_owner = Some(owner);
                top_group = group;
                trail.push(Breadcrumb {
                    id: Some(cid),
                    name,
                    enc_key: enc_key.map(|b| BASE64.encode(b)),
                });
                current = parent;
            }
            trail.reverse();
            if let Some(group_id) = top_group {
                // Membership is the gate for a group trail - a removed
                // member gets the same 404 their entries give them.
                let role = group_role(conn, user_id, group_id)?.ok_or(AppError::NotFound)?;
                if !crate::sharing::grants(role_perms(role), crate::sharing::PERM_READ) {
                    return Err(AppError::NotFound);
                }
            } else if top_owner != Some(user_id) {
                // Reached via a share: cut at the mount and rename that crumb.
                let access = covering_share(conn, user_id, id)?.ok_or(AppError::NotFound)?;
                let display: String = conn.query_row(
                    "SELECT display_name FROM shares WHERE id = ?1",
                    params![access.share_id],
                    |r| r.get(0),
                )?;
                if let Some(pos) = trail.iter().position(|b| b.id == Some(access.source_id)) {
                    let mut visible = trail.split_off(pos);
                    visible[0].name = display;
                    trail = visible;
                }
            }
            // Prepend the implicit root.
            trail.insert(
                0,
                Breadcrumb {
                    id: None,
                    name: "Home".to_string(),
                    // The synthetic root has no row and therefore no key
                    // record: a read starts from the session's root key.
                    enc_key: None,
                },
            );
            Ok(trail)
        })
        .await
    }

    /// Walk `segments` down from the user's root and return the entry there.
    ///
    /// Own entries win on every level. A first segment that matches an incoming
    /// share's display name crosses into the *owner's* subtree; the resolved
    /// entry is stamped with the share's permissions and the owner's name.
    ///
    /// Callers must only pass a **non-empty** path; an empty path (the virtual
    /// root) is handled by the caller. Returns `Ok(None)` if any component is
    /// missing.
    pub async fn resolve_path(
        &self,
        user_id: i64,
        segments: Vec<String>,
    ) -> Result<Option<FileEntry>, AppError> {
        self.run(move |conn| {
            let mut principal = TreeOwner::User(user_id);
            let mut parent: Option<i64> = None;
            let mut perms = PERM_ALL;
            let mut owner_name: Option<String> = None;
            let mut crossed = false;
            for seg in segments {
                let found = match find_child(conn, principal, parent, &seg)? {
                    Some(e) => e,
                    None => {
                        // Root-level fallbacks: one of my groups' top-level
                        // folders first (membership-checked, with the role's
                        // mask), then an incoming share mount.
                        if parent.is_none() && !crossed {
                            if let Some((e, role)) = group_root_by_name(conn, user_id, &seg)? {
                                perms = role_perms(role);
                                owner_name = Some(username_by_id(conn, e.owner_id)?);
                                e
                            } else {
                                let Some(access) =
                                    super::share::share_by_display_name(conn, user_id, &seg)?
                                else {
                                    return Ok(None);
                                };
                                if !access.can(crate::sharing::PERM_READ) {
                                    return Ok(None);
                                }
                                let Ok(src) = get_entry_by_id(conn, access.source_id) else {
                                    return Ok(None);
                                };
                                perms = access.permissions;
                                owner_name = Some(username_by_id(conn, access.owner_id)?);
                                crossed = true;
                                src
                            }
                        } else {
                            return Ok(None);
                        }
                    }
                };
                // Attribution picks the tree the next segment resolves in:
                // group rows stay in their group's tree, everything else in
                // the row owner's.
                principal = match found.owner_group_id {
                    Some(group_id) => TreeOwner::Group(group_id),
                    None => TreeOwner::User(found.owner_id),
                };
                parent = Some(found.id);
            }
            let Some(id) = parent else { return Ok(None); };
            let Ok(mut entry) = get_entry_by_id(conn, id) else {
                return Ok(None);
            };
            entry.permissions = perms;
            entry.owner_name = match entry.owner_group_id {
                // The creator of the row itself, not of the top folder.
                Some(_) => Some(username_by_id(conn, entry.owner_id)?),
                None => owner_name,
            };
            Ok(Some(entry))
        })
        .await
    }

    /// Validate a move without touching a row: UPDATE on the source, CREATE
    /// at the destination, both trees' rules (a user's own tree or a group
    /// they belong to - never another user's tree, never another group,
    /// concepts/groups.md section 4), the cycle and name guards, and -
    /// when the attribution changes - the destination quota over the whole
    /// subtree plus the refusal to smuggle active shares into a group.
    ///
    /// The `guard_key_domains` flag is the key-blind door: WebDAV MOVE
    /// passes `true` and holds no keys (DECISION 9 - treat encrypted rows
    /// as opaque), so a keyed row may only travel between parents that
    /// already carry the same key record. The JSON routes arrive with the
    /// record already re-wrapped for the destination (ENCRYPTION.md 5.4)
    /// and pass `false`.
    ///
    /// The blob relocation when [`MovePlan::relocation`] returns one is the
    /// caller's job - link first, apply via [`Db::apply_move`], then drop
    /// the old name ([`crate::files::FileService::move_entry`] sequences
    /// it that way).
    pub async fn prepare_move(
        &self,
        user_id: i64,
        id: i64,
        new_parent: Option<i64>,
        new_name: String,
        guard_key_domains: bool,
    ) -> Result<MovePlan, AppError> {
        self.run(move |conn| {
            validate_name(&new_name)?;
            let src = update_target(conn, user_id, id, crate::sharing::PERM_UPDATE)?;
            let dest = create_target(conn, user_id, new_parent, None, &new_name)?;
            match (src, dest) {
                (TreeOwner::User(a), TreeOwner::User(b)) if a != b => {
                    return Err(AppError::BadRequest(if new_parent.is_none() {
                        "cannot move a shared item into your own root"
                    } else {
                        "cannot move an item across owners"
                    }
                    .into()));
                }
                (TreeOwner::User(a), TreeOwner::Group(_)) if a != user_id => {
                    return Err(AppError::BadRequest(
                        "cannot move a shared item into a group folder".into(),
                    ));
                }
                (TreeOwner::Group(a), TreeOwner::Group(b)) if a != b => {
                    return Err(AppError::BadRequest(
                        "cannot move an item between groups".into(),
                    ));
                }
                _ => {}
            }
            // A key record is wrapped under the *source* parent's key, so for
            // a caller that holds no keys a move is a pure metadata operation
            // only while both parents carry the same key record
            // (ENCRYPTION.md 5.4). The JSON routes arrive with the record
            // already re-wrapped for the destination and skip this; WebDAV,
            // which cannot re-wrap, is exactly what it is here for.
            let (keyed, src_parent): (Option<Vec<u8>>, Option<i64>) = conn.query_row(
                "SELECT enc_key, parent_id FROM files WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if guard_key_domains && keyed.is_some() {
                let key_of = |parent: Option<i64>| -> rusqlite::Result<Option<Vec<u8>>> {
                    match parent {
                        None => Ok(None),
                        Some(p) => Ok(conn
                            .query_row("SELECT enc_key FROM files WHERE id = ?1", params![p], |r| {
                                r.get(0)
                            })
                            .optional()?
                            .flatten()),
                    }
                };
                if key_of(src_parent)? != key_of(new_parent)? {
                    return Err(AppError::Conflict(
                        "moving this item between folders with different keys needs \
                         its key record re-wrapped first, which the client must do \
                         (ENCRYPTION.md 5.4)"
                            .into(),
                    ));
                }
            }
            // Cycle guard: new parent must not be the entry itself or a descendant.
            let mut cur = new_parent;
            while let Some(c) = cur {
                if c == id {
                    return Err(AppError::BadRequest(
                        "cannot move a folder into itself".into(),
                    ));
                }
                let parent_of: Option<Option<i64>> = conn
                    .query_row(
                        "SELECT parent_id FROM files WHERE id = ?1",
                        params![c],
                        |r| r.get(0),
                    )
                    .optional()?;
                cur = parent_of.flatten();
            }

            // An attribution change moves bytes between budgets and between
            // blob namespaces - both decided here, applied by the caller.
            let relocation = if src != dest {
                if let (TreeOwner::User(_), TreeOwner::Group(_)) = (src, dest) {
                    // A shared subtree keeps its shares (they would outlive
                    // the move and expose a group row - concepts/groups.md
                    // section 4: group files take no incoming shares).
                    let shared: i64 = conn.query_row(
                        "WITH RECURSIVE subtree(id) AS (
                             SELECT id FROM files WHERE id = ?1
                             UNION ALL
                             SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
                         )
                         SELECT COUNT(*) FROM shares
                          WHERE source_id IN (SELECT id FROM subtree)",
                        params![id],
                        |r| r.get(0),
                    )?;
                    if shared > 0 {
                        return Err(AppError::Conflict(
                            "this item is shared - revoke its shares before moving \
                             it into a group folder"
                                .into(),
                        ));
                    }
                }
                // The destination gains the subtree's rows and their version
                // history - exactly what its sums will count from then on.
                let delta: i64 = conn.query_row(
                    "WITH RECURSIVE subtree(id) AS (
                         SELECT id FROM files WHERE id = ?1
                         UNION ALL
                         SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
                     )
                     SELECT COALESCE((SELECT SUM(size) FROM files
                                       WHERE is_dir = 0
                                         AND id IN (SELECT id FROM subtree)), 0)
                          + COALESCE((SELECT SUM(v.size) FROM file_versions v
                                       WHERE v.file_id IN (SELECT id FROM subtree)), 0)",
                    params![id],
                    |r| r.get(0),
                )?;
                ensure_quota(conn, dest, delta)?;
                let src_entry = get_entry_by_id(conn, id)?;
                let old = BlobRef::from(&src_entry);
                let owner = match dest {
                    TreeOwner::Group(group_id) => BlobOwner::Group(group_id),
                    TreeOwner::User(owner_id) => BlobOwner::User(owner_id),
                };
                let new = BlobRef::Entry {
                    file_id: id,
                    owner,
                    created_at: src_entry.created_at,
                };
                Some((old, new))
            } else {
                None
            };

            Ok(MovePlan {
                id,
                new_parent,
                new_name,
                src,
                dest,
                relocation,
            })
        })
        .await
    }

    /// Apply a [`MovePlan`]: one statement re-parents the root row and, on
    /// an attribution change, re-attributes the whole subtree - materialized
    /// attribution must never be half a move behind (concepts/groups.md
    /// section 3). Interlocked on the source principal the permission check
    /// resolved.
    pub async fn apply_move(&self, plan: MovePlan) -> Result<FileEntry, AppError> {
        let MovePlan {
            id,
            new_parent,
            new_name,
            src,
            dest,
            relocation,
        } = plan;
        self.run(move |conn| {
            let now = Utc::now().to_rfc3339();
            let changed = if relocation.is_some() {
                // Crossing: destination attribution for every row of the
                // subtree (creators stay put when entering a group, rows
                // join the destination user's tree when leaving one), root
                // row parent/name in the same statement.
                let (dest_user, dest_group) = principal_params(dest);
                let (src_user, src_group) = principal_params(src);
                conn.execute(
                    &format!(
                        "WITH RECURSIVE subtree(id) AS (
                             SELECT id FROM files WHERE id = ?1
                             UNION ALL
                             SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
                         )
                         UPDATE files SET
                             parent_id = CASE WHEN id = ?1 THEN ?2 ELSE parent_id END,
                             name = CASE WHEN id = ?1 THEN ?3 ELSE name END,
                             modified_at = CASE WHEN id = ?1 THEN ?4 ELSE modified_at END,
                             owner_group_id = ?5,
                             owner_id = COALESCE(?6, owner_id)
                          WHERE id IN (SELECT id FROM subtree)
                            AND (id != ?1 OR {PRINCIPAL_GUARD})"
                    ),
                    params![id, new_parent, new_name, now, dest_group, dest_user, src_user, src_group],
                )
                .map_err(|e| map_constraint(e, &new_name))?
            } else {
                let (user, group) = principal_params(src);
                conn.execute(
                    &format!(
                        "UPDATE files SET parent_id = ?1, name = ?2, modified_at = ?3
                         WHERE id = ?4 AND {PRINCIPAL_GUARD}"
                    ),
                    params![new_parent, new_name, now, id, user, group],
                )
                .map_err(|e| map_constraint(e, &new_name))?
            };
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            get_entry_by_id(conn, id)
        })
        .await
    }

    /// Update a file's size/mime/timestamp in place (used by WebDAV PUT overwrite).
    ///
    /// Foreign entries require UPDATE via the covering share.
    ///
    /// `pins_old` marks a replacement that keeps the outgoing bytes on disk
    /// as a version: their size then *stays* in the total (the row loses it,
    /// the history gains it), so the growth the quota has to accommodate is
    /// the incoming size alone. Without a pin the delta is the usual
    /// `size - old_size` — shrinking passes with a negative number.
    pub async fn update_file_meta(
        &self,
        user_id: i64,
        id: i64,
        size: i64,
        mime: Option<String>,
        // `(enc_version, enc_key)` when this write also changes the row's
        // encryption mode; `None` to leave both columns alone (the usual
        // case: content replaced, mode unchanged).
        enc: Option<(i64, Vec<u8>)>,
        pins_old: bool,
    ) -> Result<(), AppError> {
        self.run(move |conn| {
            let principal = update_target(conn, user_id, id, crate::sharing::PERM_UPDATE)?;
            let (user, group) = principal_params(principal);
            // Overwriting replaces content in place: only the *growth* has
            // to fit into the quota.
            let old_size: Option<i64> = conn
                .query_row(
                    &format!(
                        "SELECT size FROM files
                          WHERE id = ?1 AND is_dir = 0 AND {PRINCIPAL_GUARD}"
                    ),
                    params![id, user, group],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(old_size) = old_size {
                let delta = if pins_old { size } else { size - old_size };
                ensure_quota(conn, principal, delta)?;
            }
            let now = Utc::now().to_rfc3339();
            // Mode change and content change belong in one statement: a row
            // that reports `enc_version = 0` while holding ciphertext (or the
            // other way round) is exactly the half-applied state every other
            // branch in this codebase is written to avoid.
            let changed = match enc {
                Some((version, key)) => conn.execute(
                    &format!(
                        "UPDATE files SET size = ?1, mime = ?2, modified_at = ?3,
                                          enc_version = ?4, enc_key = ?5
                          WHERE id = ?6 AND is_dir = 0 AND {PRINCIPAL_GUARD}"
                    ),
                    params![size, mime, now, version, key, id, user, group],
                )?,
                None => conn.execute(
                    &format!(
                        "UPDATE files SET size = ?1, mime = ?2, modified_at = ?3
                          WHERE id = ?4 AND is_dir = 0 AND {PRINCIPAL_GUARD}"
                    ),
                    params![size, mime, now, id, user, group],
                )?,
            };
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            Ok(())
        })
        .await
    }

    /// Bytes of content owned by `owner_id` — what counts against their quota
    /// and what `GET /api/me` reports as `used_bytes`. Version history of
    /// the owner's files counts alongside the live rows (decision 4); group
    /// folders are excluded because they bill the group, not the member who
    /// wrote into them (concepts/groups.md section 4).
    pub async fn owner_usage(&self, owner_id: i64) -> Result<i64, AppError> {
        self.run(move |conn| {
            let used: i64 = conn.query_row(
                "SELECT COALESCE((SELECT SUM(size) FROM files
                                  WHERE owner_id = ?1 AND owner_group_id IS NULL
                                    AND is_dir = 0), 0)
                       + COALESCE((SELECT SUM(v.size) FROM file_versions v
                                   JOIN files f ON f.id = v.file_id
                                    WHERE f.owner_id = ?1 AND f.owner_group_id IS NULL
                                      AND f.is_dir = 0), 0)",
                params![owner_id],
                |r| r.get(0),
            )?;
            Ok(used)
        })
        .await
    }

    /// Up-front quota gate for bulk writes: fails with
    /// [`AppError::QuotaExceeded`] when `additional` more bytes would not fit
    /// into the principal of `parent_id`'s tree (the destination's group,
    /// the folder owner's, or the requester's own root). Called before
    /// copying a subtree so a full quota never leaves a partial copy behind.
    pub async fn check_quota(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
        additional: i64,
    ) -> Result<(), AppError> {
        self.run(move |conn| {
            let principal = target_principal(conn, user_id, parent_id)?;
            ensure_quota(conn, principal, additional)
        })
        .await
    }

    /// Assert the UPDATE grant on a row without changing anything.
    ///
    /// The restore path needs this *before* its first filesystem operation:
    /// the exchange starts with a hardlink, and a permission check that only
    /// arrived later (in the metadata statement) would have run after bytes
    /// were already named. Saving takes the same grant up front through
    /// [`Db::update_file_meta`].
    pub async fn require_update(&self, user_id: i64, file_id: i64) -> Result<(), AppError> {
        self.run(move |conn| {
            update_target(conn, user_id, file_id, crate::sharing::PERM_UPDATE)?;
            Ok(())
        })
        .await
    }

    /// Pin a replaced blob as a version row and enforce the acting user's
    /// count bound (`version_keep_n`, 0 = keep everything) on that file.
    /// Callers hold the UPDATE grant; the blob must already carry its
    /// version name (link before row - a crash costs an orphan file, never
    /// a row pointing at nothing).
    ///
    /// Returns the rows retention removed: their bytes have to go from disk
    /// as well, which is the caller's unlink via `delete_blobs`.
    pub async fn insert_version(
        &self,
        acting_user: i64,
        file_id: i64,
        size: i64,
        enc_version: i64,
        blob_key: String,
    ) -> Result<Vec<BlobRef>, AppError> {
        self.run(move |conn| {
            // Fixed-width fraction (9 digits): the listing and retention
            // order by this string, and RFC3339's default 0/3/6/9-digit
            // widths do not compare chronologically within one second -
            // `.987...` would sort above a later `.123...`.
            let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, false);
            conn.execute(
                "INSERT INTO file_versions (file_id, size, enc_version, author_id,
                                            blob_created_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![file_id, size, enc_version, acting_user, blob_key, now],
            )?;
            let keep: i64 = conn.query_row(
                "SELECT version_keep_n FROM users WHERE id = ?1",
                params![acting_user],
                |r| r.get(0),
            )?;
            prune_versions(conn, file_id, keep)
        })
        .await
    }

    /// History of one file, newest first (READ, same gate as a download).
    pub async fn list_versions(
        &self,
        user_id: i64,
        file_id: i64,
    ) -> Result<Vec<FileVersion>, AppError> {
        if self.entry_for_read(user_id, file_id).await?.is_none() {
            return Err(AppError::NotFound);
        }
        self.run(move |conn| read_versions(conn, file_id)).await
    }

    /// One version's metadata, READ-checked through the same gate as the
    /// listing - the starting point of a version download or a restore.
    pub async fn version_for_read(
        &self,
        user_id: i64,
        file_id: i64,
        vid: i64,
    ) -> Result<FileVersion, AppError> {
        if self.entry_for_read(user_id, file_id).await?.is_none() {
            return Err(AppError::NotFound);
        }
        self.run(move |conn| {
            let rows = read_versions(conn, file_id)?;
            rows.into_iter()
                .find(|v| v.id == vid)
                .ok_or(AppError::NotFound)
        })
        .await
    }

    /// The database half of an exchange restore: point the entry's row at
    /// the restored bytes (size, `enc_version`, `modified_at`) and drop the
    /// version row they came from - the entry now holds that inode, so the
    /// row must not. UPDATE grant, checked here even though the filesystem
    /// half checked it first; the two run under the row's write lock.
    ///
    /// `enc_key` is deliberately untouched: the file key lives across all
    /// versions of an entry (ENCRYPTION.md DECISION 5), a restore only
    /// changes which bytes sit at the entry - and with them `enc_version`,
    /// which describes those bytes.
    pub async fn finish_restore(
        &self,
        acting_user: i64,
        file_id: i64,
        vid: i64,
    ) -> Result<(), AppError> {
        self.run(move |conn| {
            update_target(conn, acting_user, file_id, crate::sharing::PERM_UPDATE)?;
            let (size, enc_version): (i64, i64) = conn
                .query_row(
                    "SELECT size, enc_version FROM file_versions
                      WHERE id = ?1 AND file_id = ?2",
                    params![vid, file_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(AppError::NotFound)?;
            let now = Utc::now().to_rfc3339();
            let changed = conn.execute(
                "UPDATE files SET size = ?1, enc_version = ?2, modified_at = ?3
                  WHERE id = ?4 AND is_dir = 0",
                params![size, enc_version, now, file_id],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            conn.execute("DELETE FROM file_versions WHERE id = ?1", params![vid])?;
            Ok(())
        })
        .await
    }

    /// Drop one version row (UPDATE grant) and return its blob to unlink.
    /// Delete means delete: the bytes go with the row.
    pub async fn delete_version(
        &self,
        acting_user: i64,
        file_id: i64,
        vid: i64,
    ) -> Result<BlobRef, AppError> {
        self.run(move |conn| {
            update_target(conn, acting_user, file_id, crate::sharing::PERM_UPDATE)?;
            let row: Option<(i64, String)> = conn
                .query_row(
                    "SELECT file_id, blob_created_at FROM file_versions
                      WHERE id = ?1 AND file_id = ?2",
                    params![vid, file_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (row_file, key) = row.ok_or(AppError::NotFound)?;
            conn.execute("DELETE FROM file_versions WHERE id = ?1", params![vid])?;
            Ok(version_blob_ref(row_file, &key))
        })
        .await
    }

    /// The age half of retention (concepts/versioning.md section 5): drop
    /// every version older than its author's `version_keep_days` (0 = off;
    /// no author left, so the file's owner decides). Runs in the trash sweep
    /// loop, on the same cadence. Returns the rows it removed.
    pub async fn sweep_versions(&self) -> Result<Vec<BlobRef>, AppError> {
        self.run(move |conn| {
            // The cutoff differs per user, so SQLite formats it per row: an
            // RFC3339-shaped UTC string, comparable with the stored
            // `created_at` the same way every other timestamp here is.
            let mut stmt = conn.prepare(
                "SELECT v.id, v.file_id, v.blob_created_at FROM file_versions v
                   JOIN files f ON f.id = v.file_id
                   JOIN users u ON u.id = COALESCE(v.author_id, f.owner_id)
                  WHERE u.version_keep_days > 0
                    AND v.created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now',
                                                '-' || u.version_keep_days || ' days')",
            )?;
            let expired = stmt
                .query_map([], |r| {
                    let id: i64 = r.get(0)?;
                    let file_id: i64 = r.get(1)?;
                    let key: String = r.get(2)?;
                    Ok((id, version_blob_ref(file_id, &key)))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            if expired.is_empty() {
                return Ok(Vec::new());
            }
            let mut pruned = Vec::with_capacity(expired.len());
            for (id, blob) in expired {
                let changed =
                    conn.execute("DELETE FROM file_versions WHERE id = ?1", params![id])?;
                if changed > 0 {
                    pruned.push(blob);
                }
            }
            Ok(pruned)
        })
        .await
    }

    /// Total bytes of the non-directory entries at and below `id`.
    pub async fn subtree_size(&self, id: i64) -> Result<i64, AppError> {
        self.run(move |conn| {
            let total: i64 = conn.query_row(
                "WITH RECURSIVE subtree(id) AS (
                     SELECT id FROM files WHERE id = ?1
                     UNION ALL
                     SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
                 )
                 SELECT COALESCE(SUM(size), 0) FROM files
                  WHERE is_dir = 0 AND id IN (SELECT id FROM subtree)",
                params![id],
                |r| r.get(0),
            )?;
            Ok(total)
        })
        .await
    }

    /// Names of every *file* at or below `id` that carries a key record.
    ///
    /// A copy mints new row ids, and a key record's AAD binds it to the id it
    /// was wrapped for (ENCRYPTION.md 5.4), so a copied record could never be
    /// opened: the result would look perfectly healthy and never decrypt. The
    /// client therefore refuses loudly instead of handing back a row that
    /// silently fails to open; `PUT /api/files/key` is the re-wrap API such a
    /// copy will build on once copy is taught to re-bind.
    ///
    /// Folders are excluded on purpose. Their records are wrapped with their
    /// *parent's* key and re-created for a copy (a fresh folder is keyed
    /// lazily on the first encrypted write below it), so a keyed folder of
    /// plaintext files must keep copying exactly like an unkeyed one.
    pub async fn subtree_keyed_names(&self, id: i64) -> Result<Vec<String>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "WITH RECURSIVE subtree(id) AS (
                     SELECT id FROM files WHERE id = ?1
                     UNION ALL
                     SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
                 )
                 SELECT name FROM files
                  WHERE id IN (SELECT id FROM subtree) AND enc_key IS NOT NULL
                    AND is_dir = 0
                  ORDER BY name COLLATE NOCASE ASC",
            )?;
            let names = stmt
                .query_map(params![id], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(names)
        })
        .await
    }

    /// Store a row's key record, replacing whatever it held (ENCRYPTION.md
    /// 5.5), without touching the row's bytes.
    ///
    /// Permission is PERM_UPDATE, the same mask the content write asks for -
    /// but an UPDATE grantee may only *give* a row its record, never take a
    /// record it already has away. Setting a record where none exists is the
    /// first encrypted write below a folder: nothing is keyed under the old
    /// record yet, so there is nothing for a swapped-in key to orphan. A
    /// record that exists may only change by the row's owner's hand, exactly
    /// like the content write's key field (see `save_content`): the server
    /// cannot see through a wrapper - it holds no key - so it cannot tell the
    /// owner's re-binding after a move from a grantee handing it a wrapper
    /// only the grantee can open. On a group row the F5 rule reads "owner"
    /// as "manager" (concepts/groups.md section 5) - the creator being a
    /// member grants nothing extra. A plaintext file has no record to set
    /// and is refused.
    pub async fn set_enc_key(
        &self,
        user_id: i64,
        id: i64,
        key: Vec<u8>,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            if key.is_empty() {
                return Err(AppError::BadRequest("key is empty".into()));
            }
            let principal = update_target(conn, user_id, id, crate::sharing::PERM_UPDATE)?;
            let (user, group) = principal_params(principal);
            let (is_dir, enc_version, has_record): (bool, i64, bool) = conn
                .query_row(
                    &format!(
                        "SELECT is_dir != 0, enc_version, enc_key IS NOT NULL
                           FROM files WHERE id = ?1 AND {PRINCIPAL_GUARD}"
                    ),
                    params![id, user, group],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?
                .ok_or(AppError::NotFound)?;
            if !is_dir && enc_version == 0 {
                return Err(AppError::BadRequest("this file is not encrypted".into()));
            }
            // F5 (Audit.md): swapping a keyed row's record is how a share
            // UPDATE-grantee would hand themselves the row for good - the
            // owner's chain stops opening it and every write below a folder
            // record is wrapped for the grantee's key from then on. Same
            // line `save_content` draws, same words; on group rows the
            // "owner" is the manager role.
            let may_swap = match principal {
                TreeOwner::User(owner) => user_id == owner,
                TreeOwner::Group(group_id) => matches!(
                    group_role(conn, user_id, group_id)?,
                    Some(role) if role == crate::sharing::ROLE_MANAGER
                ),
            };
            if has_record && !may_swap {
                return Err(AppError::ForbiddenDetail(
                    match principal {
                        TreeOwner::User(_) => "only the row's owner may change its key record",
                        TreeOwner::Group(_) => {
                            "only a group manager may change this folder's key record"
                        }
                    }
                    .into(),
                ));
            }
            conn.execute(
                &format!(
                    "UPDATE files SET enc_key = ?1 WHERE id = ?2 AND {PRINCIPAL_GUARD}"
                ),
                params![key, id, user, group],
            )?;
            get_entry_by_id(conn, id)
        })
        .await
    }

    /// Fetch an entry the user may *read*: their own, or one covered by a
    /// share granting READ. Stamps the share's permissions onto the entry.
    pub async fn entry_for_read(
        &self,
        user_id: i64,
        id: i64,
    ) -> Result<Option<FileEntry>, AppError> {
        self.run(move |conn| readable_entry(conn, user_id, id))
            .await
    }

    /// The acting user's role in `group_id`, or `None` when they are not a
    /// member: the F5 rule's "owner" stand-in on group rows and the gate on
    /// the key-distribution routes (concepts/groups.md section 5).
    pub async fn group_role_of(
        &self,
        user_id: i64,
        group_id: i64,
    ) -> Result<Option<i64>, AppError> {
        self.run(move |conn| Ok(group_role(conn, user_id, group_id)?))
            .await
    }

    /// One entry plus every descendant the user may read, as `(path, entry)`
    /// pairs where `path` is relative to the entry itself (`Sub/file.txt`).
    ///
    /// This is the read side of a multi-selection download: one round trip per
    /// selected item, permission-checked at the top (children inherit access
    /// through the covering share or through the owner's own tree). The root
    /// comes first, folders and files are depth-first afterwards.
    pub async fn readable_subtree(
        &self,
        user_id: i64,
        id: i64,
    ) -> Result<Vec<(String, FileEntry)>, AppError> {
        self.run(move |conn| {
            let root = readable_entry(conn, user_id, id)?.ok_or(AppError::NotFound)?;

            // Everything below the root, whatever the owner (a folder shared
            // with me contains the owner's files; mine contain what I created
            // inside shares).
            let mut stmt = conn.prepare(&format!(
                "WITH RECURSIVE subtree(id) AS (
                     SELECT id FROM files WHERE id = ?1
                     UNION ALL
                     SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
                 )
                 SELECT {ENTRY_COLS} FROM files
                 WHERE id != ?1 AND id IN (SELECT id FROM subtree)"
            ))?;
            let descendants = stmt
                .query_map(params![id], row_to_entry)?
                .collect::<Result<Vec<_>, _>>()?;

            // Group children by parent, then walk down to build the paths.
            let mut children: HashMap<i64, Vec<FileEntry>> = HashMap::new();
            for entry in descendants {
                if let Some(parent) = entry.parent_id {
                    children.entry(parent).or_default().push(entry);
                }
            }

            let mut out = Vec::new();
            let mut stack: Vec<(String, FileEntry)> = vec![(String::new(), root)];
            while let Some((prefix, entry)) = stack.pop() {
                let path = if prefix.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{prefix}/{}", entry.name)
                };
                if entry.is_dir {
                    // Reversed push keeps the natural (folders first, by name)
                    // order of the listing as they are popped.
                    if let Some(kids) = children.remove(&entry.id) {
                        for kid in kids.into_iter().rev() {
                            stack.push((path.clone(), kid));
                        }
                    }
                }
                out.push((path, entry));
            }
            Ok(out)
        })
        .await
    }
}

fn get_entry_by_id(conn: &Connection, id: i64) -> Result<FileEntry, AppError> {
    let mut stmt =
        conn.prepare(&format!("SELECT {ENTRY_COLS} FROM files WHERE id = ?1"))?;
    let entry = stmt.query_row(params![id], row_to_entry).optional()?;
    entry.ok_or(AppError::NotFound)
}

/// The same lookup as [`Db::entry_for_read`], for use inside another
/// connection closure (one round trip shared by permission checks and subtree
/// walks). `Ok(None)` means "no read access".
fn readable_entry(conn: &Connection, user_id: i64, id: i64) -> Result<Option<FileEntry>, AppError> {
    let entry = match get_entry_by_id(conn, id) {
        Ok(e) => e,
        Err(AppError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };
    if under_trash(conn, &entry)? {
        return Ok(None);
    }
    // Group attribution decides before ownership: a member removed from the
    // group loses the rows they created too, and every member's mask is
    // their role's (concepts/groups.md section 4).
    if let Some(group_id) = entry.owner_group_id {
        let Some(role) = group_role(conn, user_id, group_id)? else {
            return Ok(None);
        };
        let perms = role_perms(role);
        if !crate::sharing::grants(perms, crate::sharing::PERM_READ) {
            return Ok(None);
        }
        let mut entry = entry;
        entry.permissions = perms;
        entry.owner_name = Some(username_by_id(conn, entry.owner_id)?);
        return Ok(Some(entry));
    }
    if entry.owner_id == user_id {
        return Ok(Some(entry));
    }
    let Some(access) = covering_share(conn, user_id, id)? else {
        return Ok(None);
    };
    if !access.can(crate::sharing::PERM_READ) {
        return Ok(None);
    }
    let mut entry = entry;
    entry.permissions = access.permissions;
    entry.owner_name = Some(username_by_id(conn, entry.owner_id)?);
    Ok(Some(entry))
}

/// Which storage principal a create lands in: the requester's own tree, the
/// group of a group folder (the role must grant CREATE), or the folder
/// owner's tree when a covering share grants CREATE. Also guards a root
/// create against shadowing an incoming share's display name.
///
/// `group` bootstraps a group's top-level folder at the root: it names the
/// group the requester is a member of. Deeper levels take attribution from
/// their parent, so the parameter applies to root creates only.
fn create_target(
    conn: &Connection,
    user_id: i64,
    parent_id: Option<i64>,
    group: Option<i64>,
    name: &str,
) -> Result<TreeOwner, AppError> {
    let Some(pid) = parent_id else {
        if share_name_taken(conn, user_id, name)? {
            return Err(AppError::Conflict(format!("'{name}' already exists here")));
        }
        if let Some(group_id) = group {
            let role = group_role(conn, user_id, group_id)?.ok_or(AppError::NotFound)?;
            if !crate::sharing::grants(role_perms(role), crate::sharing::PERM_CREATE) {
                return Err(AppError::Forbidden);
            }
            return Ok(TreeOwner::Group(group_id));
        }
        return Ok(TreeOwner::User(user_id));
    };
    if group.is_some() {
        return Err(AppError::BadRequest(
            "a group target applies only to root-level creates".into(),
        ));
    }
    target_principal(conn, user_id, Some(pid))
}

/// The storage principal a write under `parent_id` bills to, applying the
/// parent's gates first: group membership and its CREATE bit (a non-member
/// gets NotFound, the same answer removal gives everywhere else), ownership,
/// then the covering share's CREATE. `None` is the requester's own root.
fn target_principal(
    conn: &Connection,
    user_id: i64,
    parent_id: Option<i64>,
) -> Result<TreeOwner, AppError> {
    let Some(pid) = parent_id else {
        return Ok(TreeOwner::User(user_id));
    };
    let parent = get_entry_by_id(conn, pid)?;
    if !parent.is_dir {
        return Err(AppError::BadRequest("parent is not a folder".into()));
    }
    if under_trash(conn, &parent)? {
        return Err(AppError::NotFound);
    }
    if let Some(group_id) = parent.owner_group_id {
        let role = group_role(conn, user_id, group_id)?.ok_or(AppError::NotFound)?;
        if !crate::sharing::grants(role_perms(role), crate::sharing::PERM_CREATE) {
            return Err(AppError::Forbidden);
        }
        return Ok(TreeOwner::Group(group_id));
    }
    if parent.owner_id == user_id {
        return Ok(TreeOwner::User(user_id));
    }
    let access = covering_share(conn, user_id, pid)?.ok_or(AppError::NotFound)?;
    if !access.can(crate::sharing::PERM_CREATE) {
        return Err(AppError::Forbidden);
    }
    Ok(TreeOwner::User(parent.owner_id))
}

/// Which storage principal an update/delete operates on: a group row resolves
/// through the membership role *first* (a removed member loses even the rows
/// they created - concepts/groups.md section 4), own rows pass
/// unconditionally, foreign entries require the covering share to grant
/// `required`.
fn update_target(
    conn: &Connection,
    user_id: i64,
    id: i64,
    required: i64,
) -> Result<TreeOwner, AppError> {
    let entry = get_entry_by_id(conn, id)?;
    if under_trash(conn, &entry)? {
        return Err(AppError::NotFound);
    }
    if let Some(group_id) = entry.owner_group_id {
        let role = group_role(conn, user_id, group_id)?.ok_or(AppError::NotFound)?;
        if !crate::sharing::grants(role_perms(role), required) {
            return Err(AppError::Forbidden);
        }
        return Ok(TreeOwner::Group(group_id));
    }
    if entry.owner_id == user_id {
        return Ok(TreeOwner::User(user_id));
    }
    let access = covering_share(conn, user_id, id)?.ok_or(AppError::NotFound)?;
    if !access.can(required) {
        return Err(AppError::Forbidden);
    }
    Ok(TreeOwner::User(entry.owner_id))
}

/// Whether an entry is trashed or sits inside a trashed folder. Such rows
/// are invisible to every normal operation (listing, read, write, delete).
fn under_trash(conn: &Connection, entry: &FileEntry) -> Result<bool, AppError> {
    if entry.deleted_at.is_some() {
        return Ok(true);
    }
    let mut cur = entry.parent_id;
    let mut hops = 0;
    while let Some(pid) = cur {
        // The depth cap turns a corrupt parent cycle into a clean 404.
        hops += 1;
        if hops > 64 {
            return Err(AppError::NotFound);
        }
        match get_entry_by_id(conn, pid) {
            Ok(parent) => {
                if parent.deleted_at.is_some() {
                    return Ok(true);
                }
                cur = parent.parent_id;
            }
            // A missing ancestor leaves the entry unreachable; callers 404.
            Err(AppError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

/// Find a direct child of `parent` inside `principal`'s tree by name: a
/// personal tree filters on its rows (they carry that owner and no group),
/// a group tree on its attribution (rows carry their creators, so `owner_id`
/// is no discriminator there).
fn find_child(
    conn: &Connection,
    principal: TreeOwner,
    parent: Option<i64>,
    name: &str,
) -> Result<Option<FileEntry>, AppError> {
    let (user, group) = principal_params(principal);
    let entry = conn
        .query_row(
            &format!(
                "SELECT {ENTRY_COLS} FROM files
                 WHERE parent_id IS ?1 AND name = ?2
                   AND {PRINCIPAL_GUARD}
                   AND deleted_at IS NULL"
            ),
            params![parent, name, user, group],
            row_to_entry,
        )
        .optional()?;
    Ok(entry)
}

/// A user's own children of a folder (or of the root when `None`).
fn own_children(
    conn: &Connection,
    owner_id: i64,
    parent_id: Option<i64>,
) -> Result<Vec<FileEntry>, AppError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {ENTRY_COLS} FROM files
         WHERE owner_id = ?1 AND owner_group_id IS NULL AND parent_id IS ?2
           AND deleted_at IS NULL
         ORDER BY is_dir DESC, name COLLATE NOCASE ASC"
    ))?;
    let entries = stmt
        .query_map(params![owner_id, parent_id], row_to_entry)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

/// A group folder's children: attribution, not the creator, groups them, so
/// every member lists every row of the folder they may open.
fn group_children(
    conn: &Connection,
    group_id: i64,
    parent_id: Option<i64>,
) -> Result<Vec<FileEntry>, AppError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {ENTRY_COLS} FROM files
         WHERE owner_group_id = ?1 AND parent_id IS ?2 AND deleted_at IS NULL
         ORDER BY is_dir DESC, name COLLATE NOCASE ASC"
    ))?;
    let entries = stmt
        .query_map(params![group_id, parent_id], row_to_entry)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

/// The user's root group entries: every top-level folder of every group
/// they belong to, with group name and creator filled for the badge.
fn group_roots(conn: &Connection, user_id: i64) -> Result<Vec<FileEntry>, AppError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {ENTRY_COLS} FROM files
         WHERE parent_id IS NULL AND deleted_at IS NULL
           AND owner_group_id IN
               (SELECT group_id FROM group_members WHERE user_id = ?1)
         ORDER BY is_dir DESC, name COLLATE NOCASE ASC"
    ))?;
    let mut entries = stmt
        .query_map(params![user_id], row_to_entry)?
        .collect::<Result<Vec<_>, _>>()?;
    for e in &mut entries {
        if let Some(group_id) = e.owner_group_id {
            e.group_name = Some(group_name(conn, group_id)?);
            e.owner_name = Some(username_by_id(conn, e.owner_id)?);
        }
    }
    Ok(entries)
}

/// A group's top-level folder by root name for `user_id`, with their role:
/// the WebDAV path walk's way into a group tree (the JSON listing merges
/// the same rows through [`group_roots`]). `None` when no group the user
/// belongs to owns that name - visibility follows membership.
fn group_root_by_name(
    conn: &Connection,
    user_id: i64,
    name: &str,
) -> Result<Option<(FileEntry, i64)>, AppError> {
    let hit = conn
        .query_row(
            &format!(
                "SELECT {ENTRY_COLS}, m.role FROM files
                 JOIN group_members m ON m.group_id = files.owner_group_id
                 WHERE m.user_id = ?1 AND files.parent_id IS NULL
                   AND files.name = ?2 AND files.deleted_at IS NULL
                 LIMIT 1"
            ),
            params![user_id, name],
            |r| {
                let entry = row_to_entry(r)?;
                let role: i64 = r.get("role")?;
                Ok((entry, role))
            },
        )
        .optional()?;
    Ok(hit)
}

/// A group's display name - the root badge and every grouped listing say
/// which group the row belongs to.
fn group_name(conn: &Connection, group_id: i64) -> Result<String, AppError> {
    let name: String = conn.query_row(
        "SELECT name FROM groups WHERE id = ?1",
        params![group_id],
        |r| r.get(0),
    )?;
    Ok(name)
}

/// Creator usernames for a group folder's direct children in one query -
/// `owner_id` differs per row in a group tree, so unlike a share listing
/// there is no single owner to ask for once.
fn creator_names(
    conn: &Connection,
    group_id: i64,
    parent_id: Option<i64>,
) -> Result<HashMap<i64, String>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT f.id, u.username FROM files f
         JOIN users u ON u.id = f.owner_id
         WHERE f.owner_group_id = ?1 AND f.parent_id IS ?2 AND f.deleted_at IS NULL",
    )?;
    let rows = stmt.query_map(params![group_id, parent_id], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
    })?;
    Ok(rows.collect::<Result<HashMap<_, _>, _>>()?)
}

/// Entries that appear in a user's root because someone shared them: one
/// virtual mount per incoming share, named by the share's display name.
fn incoming_mounts(conn: &Connection, user_id: i64) -> Result<Vec<FileEntry>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT f.id, f.owner_id, f.parent_id, s.display_name, f.is_dir, f.size, f.mime,
                f.created_at, f.modified_at, u.username, s.permissions,
                f.enc_version, f.enc_key
         FROM shares s
         JOIN files f ON f.id = s.source_id
         JOIN users  u ON u.id = s.owner_id
         WHERE s.grantee_id = ?1 AND f.deleted_at IS NULL",
    )?;
    let rows = stmt
        .query_map(params![user_id], |r| {
            let created: String = r.get(7)?;
            let modified: String = r.get(8)?;
            Ok(FileEntry {
                id: r.get(0)?,
                owner_id: r.get(1)?,
                // A share is strictly user-to-user: a group-owned source is
                // refused at creation and cannot ride in through a move, so
                // mount rows are never group rows (concepts/groups.md 4).
                owner_group_id: None,
                group_name: None,
                parent_id: r.get(2)?,
                name: r.get(3)?,
                is_dir: r.get::<_, i64>(4)? != 0,
                size: r.get(5)?,
                mime: r.get(6)?,
                created_at: parse_ts(&created, 7)?,
                modified_at: parse_ts(&modified, 8)?,
                permissions: r.get(10)?,
                owner_name: Some(r.get(9)?),
                subtree_bytes: None,
                enc_version: r.get(11)?,
                enc_key: r.get::<_, Option<Vec<u8>>>(12)?.map(|b| BASE64.encode(b)),
                deleted_at: None,
                purge_at: None,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn sort_entries(entries: &mut [FileEntry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

fn username_by_id(conn: &Connection, id: i64) -> Result<String, AppError> {
    let name: String = conn.query_row(
        "SELECT username FROM users WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )?;
    Ok(name)
}

/// Set `subtree_bytes` on the directory rows of a listing.
///
/// One recursive CTE sums every listed folder's whole subtree in a single
/// pass (the `UNION` also makes a stray parent cycle terminate), so folder
/// sizes cost one indexed query per page instead of one walk per row.
fn fill_subtree_sizes(conn: &Connection, entries: &mut [FileEntry]) -> Result<(), AppError> {
    let dirs: Vec<i64> = entries.iter().filter(|e| e.is_dir).map(|e| e.id).collect();
    if dirs.is_empty() {
        return Ok(());
    }
    let placeholders = vec!["?"; dirs.len()].join(",");
    let sql = format!(
        "WITH RECURSIVE tree(root, id) AS (
             SELECT id, id FROM files WHERE id IN ({placeholders})
             UNION
             SELECT t.root, c.id FROM files c JOIN tree t ON c.parent_id = t.id
         )
         SELECT t.root, COALESCE(SUM(f.size), 0)
         FROM tree t JOIN files f ON f.parent_id = t.id AND f.is_dir = 0
         GROUP BY t.root"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(dirs.iter()))?;
    let mut sizes: HashMap<i64, i64> = HashMap::new();
    while let Some(row) = rows.next()? {
        sizes.insert(row.get(0)?, row.get(1)?);
    }
    for entry in entries.iter_mut() {
        if entry.is_dir {
            entry.subtree_bytes = Some(sizes.get(&entry.id).copied().unwrap_or(0));
        }
    }
    Ok(())
}

/// Collect a subtree's blobs and delete its root row (children follow via
/// the foreign-key cascade). The shared engine behind the trash purge and
/// rollback paths; unlike the user-facing trash flow this removes rows and
/// content for good.
fn hard_delete(conn: &Connection, id: i64) -> Result<Vec<BlobRef>, AppError> {
    let mut stmt = conn.prepare(
        "WITH RECURSIVE subtree(id) AS (
             SELECT id FROM files WHERE id = ?1
             UNION ALL
             SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
         )
         SELECT id, owner_id, owner_group_id, created_at FROM files
          WHERE is_dir = 0 AND id IN (SELECT id FROM subtree)",
    )?;
    let mut blobs = stmt
        .query_map(params![id], |r| {
            let id: i64 = r.get(0)?;
            let owner_id: i64 = r.get(1)?;
            let owner_group_id: Option<i64> = r.get(2)?;
            let created_at: String = r.get(3)?;
            blob_ref(id, owner_id, owner_group_id, &created_at)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    // Version rows follow the foreign-key cascade, the blobs they point at do
    // not: capture them while the rows still exist, like the file blobs.
    let mut vstmt = conn.prepare(
        "WITH RECURSIVE subtree(id) AS (
             SELECT id FROM files WHERE id = ?1
             UNION ALL
             SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
         )
         SELECT file_id, blob_created_at FROM file_versions
          WHERE file_id IN (SELECT id FROM subtree)",
    )?;
    let vblobs = vstmt
        .query_map(params![id], |r| {
            Ok(version_blob_ref(r.get(0)?, &r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    blobs.extend(vblobs);
    conn.execute("DELETE FROM files WHERE id = ?1", params![id])?;
    Ok(blobs)
}

/// Shared engine of `purge_expired_trash` / `empty_trash`: hard-delete every
/// matching trash root and collect the blobs to unlink. `owner = None` is
/// the age-based sweep over everyone; a user scope is their own trash -
/// personal rows plus the group rows every member may purge with the role's
/// DELETE bit (concepts/groups.md section 4).
fn purge_roots(
    conn: &Connection,
    owner: Option<i64>,
    before: Option<String>,
) -> Result<Vec<BlobRef>, AppError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT id FROM files
         WHERE {TRASH_ROOTS}
           AND (?1 IS NULL
                OR (owner_id = ?1 AND owner_group_id IS NULL)
                OR owner_group_id IN (SELECT group_id FROM group_members
                                       WHERE user_id = ?1))
           AND (?2 IS NULL OR deleted_at < ?2)"
    ))?;
    let roots = stmt
        .query_map(params![owner, before], |r| r.get(0))?
        .collect::<Result<Vec<i64>, _>>()?;
    let mut blobs = Vec::new();
    for id in roots {
        blobs.extend(hard_delete(conn, id)?);
    }
    Ok(blobs)
}

fn validate_name(name: &str) -> Result<(), AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("name must not be empty".into()));
    }
    if trimmed == "." || trimmed == ".." || trimmed.contains('/') || trimmed.contains('\\') {
        return Err(AppError::BadRequest("name contains invalid characters".into()));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest(
            "name contains control characters".into(),
        ));
    }
    Ok(())
}

fn map_constraint(e: rusqlite::Error, name: &str) -> AppError {
    match e {
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
            AppError::Conflict(format!("'{name}' already exists here"))
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

    /// A throwaway database with the real migrations applied.
    ///
    /// File-backed rather than `:memory:` on purpose: `Db` pools eight
    /// connections and SQLite hands every `:memory:` connection its own
    /// private database, so seven of them would come up empty.
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
        let dir = std::env::temp_dir().join(format!("fxcloud-unit-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let db = Db::open(&dir.join("fxcloud.db")).expect("migrations must apply to an empty db");
        Scratch { db, dir }
    }

    fn user_with_quota(conn: &Connection, quota: i64) -> i64 {
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, created_at, quota_bytes)
             VALUES ('u', 'hash', 'u', '2026-01-01T00:00:00Z', ?1)",
            params![quota],
        )
        .expect("insert user");
        conn.query_row("SELECT id FROM users WHERE username = 'u'", [], |r| {
            r.get(0)
        })
        .expect("user id")
    }

    fn add_file(conn: &Connection, owner: i64, name: &str, size: i64, is_dir: bool) -> i64 {
        conn.execute(
            "INSERT INTO files (owner_id, name, is_dir, size, created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            params![owner, name, is_dir, size],
        )
        .expect("insert file");
        conn.last_insert_rowid()
    }

    /// A user with quota `quota` and one file of `size` bytes: the starting
    /// point of every version test (owner, file_id).
    fn seed_file(s: &Scratch, name: &str, size: i64, quota: i64) -> (i64, i64) {
        let conn = s.db.pool.get().unwrap();
        let owner = user_with_quota(&conn, quota);
        let file_id = add_file(&conn, owner, name, size, false);
        drop(conn);
        (owner, file_id)
    }

    #[test]
    fn the_quota_holds_at_the_exact_byte() {
        let s = scratch();
        let conn = s.db.pool.get().unwrap();
        let owner = user_with_quota(&conn, 100);

        assert!(
            ensure_quota(&conn, TreeOwner::User(owner), 100).is_ok(),
            "exactly the quota fits"
        );
        assert!(
            ensure_quota(&conn, TreeOwner::User(owner), 101).is_err(),
            "one byte over does not"
        );

        add_file(&conn, owner, "a", 60, false);
        assert!(ensure_quota(&conn, TreeOwner::User(owner), 40).is_ok(), "60 + 40 == 100");
        assert!(ensure_quota(&conn, TreeOwner::User(owner), 41).is_err(), "60 + 41 > 100");
    }

    #[test]
    fn trash_keeps_billing_until_it_is_purged() {
        // Deleting frees no disk until the sweep runs, so the bytes stay on
        // the owner's account - otherwise a full quota would be one click away.
        let s = scratch();
        let conn = s.db.pool.get().unwrap();
        let owner = user_with_quota(&conn, 100);
        add_file(&conn, owner, "keep", 50, false);
        add_file(&conn, owner, "gone", 40, false);
        conn.execute(
            "UPDATE files SET deleted_at = '2026-01-01T00:00:00Z' WHERE name = 'gone'",
            [],
        )
        .expect("trash");

        assert!(ensure_quota(&conn, TreeOwner::User(owner), 10).is_ok(), "90 + 10 == 100");
        assert!(ensure_quota(&conn, TreeOwner::User(owner), 11).is_err());
    }

    #[test]
    fn folders_are_never_billed() {
        let s = scratch();
        let conn = s.db.pool.get().unwrap();
        let owner = user_with_quota(&conn, 100);
        add_file(&conn, owner, "d", 0, true);
        // No writer gives a folder a size today; assert the filter anyway, so
        // the invariant is pinned rather than implied by the data.
        conn.execute("UPDATE files SET size = 999 WHERE is_dir = 1", [])
            .expect("size");
        assert!(
            ensure_quota(&conn, TreeOwner::User(owner), 100).is_ok(),
            "folder bytes must not count"
        );
    }

    #[test]
    fn a_zero_or_negative_write_never_fails() {
        // Downloads, renames and metadata updates also go through this gate;
        // a full quota must not be able to block reading what is already there.
        let s = scratch();
        let conn = s.db.pool.get().unwrap();
        let owner = user_with_quota(&conn, 100);
        add_file(&conn, owner, "full", 500, false);

        assert!(ensure_quota(&conn, TreeOwner::User(owner), 0).is_ok());
        assert!(ensure_quota(&conn, TreeOwner::User(owner), -5).is_ok());
    }

    #[test]
    fn the_refusal_reports_both_numbers() {
        let s = scratch();
        let conn = s.db.pool.get().unwrap();
        let owner = user_with_quota(&conn, 100);
        add_file(&conn, owner, "a", 90, false);

        match ensure_quota(&conn, TreeOwner::User(owner), 20) {
            Err(AppError::QuotaExceeded { used, quota }) => {
                assert_eq!(used, 90);
                assert_eq!(quota, 100);
            }
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
    }

    #[test]
    fn names_that_could_escape_or_corrupt_a_listing_are_refused() {
        for rejected in [
            "",
            "   ",
            ".",
            "..",
            "a/b",
            "a\\b",
            "/abs",
            "line\nbreak",
            "nul\u{0}byte",
        ] {
            assert!(validate_name(rejected).is_err(), "accepted {rejected:?}");
        }
    }

    #[test]
    fn ordinary_names_are_accepted() {
        for accepted in [
            "a.txt",
            "Ümlaute.txt",
            "two words.tar.gz",
            "  padded  ",
            "a-b_c.1",
        ] {
            assert!(validate_name(accepted).is_ok(), "refused {accepted:?}");
        }
    }

    #[test]
    fn listings_are_folders_first_then_case_insensitive() {
        let now = Utc::now();
        let entry = |name: &str, is_dir: bool| FileEntry {
            id: 0,
            owner_id: 1,
            owner_group_id: None,
            group_name: None,
            parent_id: None,
            name: name.to_string(),
            is_dir,
            size: 0,
            mime: None,
            created_at: now,
            modified_at: now,
            permissions: 0,
            owner_name: None,
            subtree_bytes: None,
            deleted_at: None,
            purge_at: None,
            enc_version: 0,
            enc_key: None,
        };

        let mut entries = vec![
            entry("b.txt", false),
            entry("Zeta", true),
            entry("alpha", false),
            entry("Docs", true),
        ];
        sort_entries(&mut entries);

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Docs", "Zeta", "alpha", "b.txt"]);
    }

    // ---- version history (concepts/versioning.md) ----

    #[tokio::test]
    async fn count_retention_keeps_the_newest_versions_and_returns_the_pruned() {
        let s = scratch();
        let (owner, file_id) = seed_file(&s, "doc.txt", 10, 1_000_000);
        s.db.update_settings(owner, None, None, Some(2), None)
            .await
            .expect("set count bound");

        let mut pruned = 0;
        for n in 0..4i64 {
            let out =
                s.db.insert_version(owner, file_id, 5 + n, 0, format!("key{n}"))
                    .await
                    .expect("insert version");
            pruned += out.len();
        }
        let rows =
            s.db.list_versions(owner, file_id)
                .await
                .expect("list versions");
        assert_eq!(rows.len(), 2, "the bound keeps the newest two");
        assert_eq!(rows[0].size, 8, "newest first");
        assert_eq!(rows[1].size, 7);
        assert_eq!(pruned, 2, "every pruned row comes back as a blob to unlink");
    }

    #[tokio::test]
    async fn count_retention_zero_keeps_the_whole_history() {
        let s = scratch();
        let (owner, file_id) = seed_file(&s, "doc.txt", 10, 1_000_000);
        s.db.update_settings(owner, None, None, Some(0), None)
            .await
            .expect("disable the count bound");

        for n in 0..3i64 {
            let out =
                s.db.insert_version(owner, file_id, n, 0, format!("key{n}"))
                    .await
                    .expect("insert version");
            assert!(out.is_empty(), "nothing is pruned with the bound off");
        }
        let rows =
            s.db.list_versions(owner, file_id)
                .await
                .expect("list versions");
        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn age_sweep_drops_only_rows_past_the_author_bound() {
        let s = scratch();
        let (owner, file_id) = seed_file(&s, "old.txt", 10, 1_000_000);
        let out =
            s.db.insert_version(owner, file_id, 5, 0, "oldkey".into())
                .await
                .expect("insert version");
        assert!(out.is_empty());

        // Backdate the row beyond any plausible bound.
        {
            let conn = s.db.pool.get().unwrap();
            conn.execute(
                "UPDATE file_versions SET created_at = '2000-01-01T00:00:00+00:00'",
                [],
            )
            .expect("backdate");
        }

        // Bound off: the sweep touches nothing.
        s.db.update_settings(owner, None, None, None, Some(0))
            .await
            .expect("disable the age bound");
        let refs = s.db.sweep_versions().await.expect("sweep");
        assert!(refs.is_empty(), "0 days means no age bound");

        // Bound on: a row from 2000 is older than a day, and comes back as
        // the blob to unlink.
        s.db.update_settings(owner, None, None, None, Some(1))
            .await
            .expect("set the age bound");
        let refs = s.db.sweep_versions().await.expect("sweep");
        assert_eq!(refs.len(), 1, "the expired row is returned");
        assert_eq!(s.db.list_versions(owner, file_id).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn quota_sums_live_rows_and_their_version_history() {
        let s = scratch();
        let (owner, file_id) = seed_file(&s, "big.txt", 60, 1000);
        assert_eq!(s.db.owner_usage(owner).await.unwrap(), 60);

        s.db.insert_version(owner, file_id, 40, 0, "history".into())
            .await
            .expect("insert version");
        assert_eq!(
            s.db.owner_usage(owner).await.unwrap(),
            100,
            "history counts toward used_bytes"
        );

        assert!(
            s.db.check_quota(owner, None, 900).await.is_ok(),
            "100 + 900 fits 1000"
        );
        assert!(
            matches!(
                s.db.check_quota(owner, None, 901).await,
                Err(AppError::QuotaExceeded { .. })
            ),
            "the version bytes are part of the gate"
        );
    }

    #[tokio::test]
    async fn finish_restore_swaps_the_row_to_the_chosen_version() {
        let s = scratch();
        let (owner, file_id) = seed_file(&s, "doc.txt", 10, 1_000_000);
        s.db.insert_version(owner, file_id, 7, 0, "v7".into())
            .await
            .expect("insert version");
        let rows = s.db.list_versions(owner, file_id).await.unwrap();
        assert_eq!(rows.len(), 1);
        let vid = rows[0].id;

        s.db.finish_restore(owner, file_id, vid)
            .await
            .expect("restore");
        let entry =
            s.db.entry_for_read(owner, file_id)
                .await
                .unwrap()
                .expect("entry");
        assert_eq!(entry.size, 7, "the row now describes the restored bytes");
        assert!(s.db.list_versions(owner, file_id).await.unwrap().is_empty());

        // A second restore of the same row cannot happen: it is gone.
        assert!(matches!(
            s.db.finish_restore(owner, file_id, vid).await,
            Err(AppError::NotFound)
        ));
    }
}
