use std::collections::HashMap;

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::AppError;
use crate::models::{BlobRef, Breadcrumb, FileEntry};
use crate::sharing::PERM_ALL;

use super::share::{covering_share, share_name_taken};
use super::user::parse_ts;
use super::Db;

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileEntry> {
    let created_at: String = row.get("created_at")?;
    let modified_at: String = row.get("modified_at")?;
    Ok(FileEntry {
        id: row.get("id")?,
        owner_id: row.get("owner_id")?,
        parent_id: row.get("parent_id")?,
        name: row.get("name")?,
        is_dir: row.get::<_, i64>("is_dir")? != 0,
        size: row.get("size")?,
        mime: row.get("mime")?,
        created_at: parse_ts(&created_at, 7)?,
        modified_at: parse_ts(&modified_at, 8)?,
        permissions: PERM_ALL,
        owner_name: None,
    })
}

/// Build a [`BlobRef`] from `(id, owner_id, created_at)` row values.
fn blob_ref(id: i64, owner_id: i64, created_at: &str) -> rusqlite::Result<BlobRef> {
    Ok(BlobRef {
        file_id: id,
        owner_id,
        created_at: parse_ts(created_at, 2)?,
    })
}

/// Whether `additional` more bytes still fit into `owner_id`'s quota.
///
/// Every path that adds content funnels through here — `create_file` and
/// `update_file_meta` run this in the same statement block as their write, so
/// content only ever appears when it fits. Bulk copies pre-check the whole
/// subtree via [`Db::check_quota`] before they start.
fn ensure_quota(conn: &Connection, owner_id: i64, additional: i64) -> Result<(), AppError> {
    if additional <= 0 {
        return Ok(());
    }
    let (quota, used): (i64, i64) = conn.query_row(
        "SELECT u.quota_bytes,
                COALESCE((SELECT SUM(f.size) FROM files f
                           WHERE f.owner_id = u.id AND f.is_dir = 0), 0)
           FROM users u WHERE u.id = ?1",
        params![owner_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if used + additional > quota {
        return Err(AppError::QuotaExceeded { used, quota });
    }
    Ok(())
}

const ENTRY_COLS: &str =
    "id, owner_id, parent_id, name, is_dir, size, mime, created_at, modified_at";

impl Db {
    /// List the direct children of `parent_id` as seen by `user_id`
    /// (root when `None`), folders-first then alphabetically.
    ///
    /// Root merges the user's own entries with incoming share mounts; a foreign
    /// parent folder is listed when a covering share grants READ.
    pub async fn list_children(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
    ) -> Result<Vec<FileEntry>, AppError> {
        self.run(move |conn| match parent_id {
            None => {
                let mut entries = own_children(conn, user_id, None)?;
                entries.extend(incoming_mounts(conn, user_id)?);
                sort_entries(&mut entries);
                Ok(entries)
            }
            Some(pid) => {
                let parent = get_entry_by_id(conn, pid)?;
                if !parent.is_dir {
                    return Err(AppError::BadRequest("parent is not a folder".into()));
                }
                if parent.owner_id == user_id {
                    own_children(conn, user_id, Some(pid))
                } else {
                    // Foreign folder: only a covering share may open it.
                    let access = covering_share(conn, user_id, pid)?.ok_or(AppError::NotFound)?;
                    if !access.can(crate::sharing::PERM_READ) {
                        return Err(AppError::Forbidden);
                    }
                    let mut entries = own_children(conn, parent.owner_id, Some(pid))?;
                    let owner_name = username_by_id(conn, parent.owner_id)?;
                    for e in &mut entries {
                        e.permissions = access.permissions;
                        e.owner_name = Some(owner_name.clone());
                    }
                    Ok(entries)
                }
            }
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
    /// A foreign parent is allowed when a covering share grants CREATE; the new
    /// entry then joins the *owner's* tree, exactly like Nextcloud.
    pub async fn create_dir(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
        name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;
            let tree_owner = create_target(conn, user_id, parent_id, &name)?;
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO files (owner_id, parent_id, name, is_dir, size, mime, created_at, modified_at)
                 VALUES (?1, ?2, ?3, 1, 0, NULL, ?4, ?4)",
                params![tree_owner, parent_id, name, now],
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
    /// Shares the parent rules of [`Db::create_dir`].
    pub async fn create_file(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
        name: String,
        size: i64,
        mime: Option<String>,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;
            let tree_owner = create_target(conn, user_id, parent_id, &name)?;
            // Quota gate sits before the INSERT: content is never tracked that
            // the owner has no space for (shared uploads count against the
            // sharer, because the tree owner stores the bytes).
            ensure_quota(conn, tree_owner, size)?;
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO files (owner_id, parent_id, name, is_dir, size, mime, created_at, modified_at)
                 VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?6)",
                params![tree_owner, parent_id, name, size, mime, now],
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
    /// shares can only return an existing folder, never create one).
    pub async fn ensure_dir(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
        name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;

            // Whose tree are we operating in, and may we create there?
            let (tree_owner, can_create) = match parent_id {
                None => (user_id, true),
                Some(pid) => {
                    let parent = get_entry_by_id(conn, pid)?;
                    if !parent.is_dir {
                        return Err(AppError::BadRequest("parent is not a folder".into()));
                    }
                    if parent.owner_id == user_id {
                        (user_id, true)
                    } else {
                        let access =
                            covering_share(conn, user_id, pid)?.ok_or(AppError::NotFound)?;
                        if !access.can(crate::sharing::PERM_READ) {
                            return Err(AppError::NotFound);
                        }
                        (parent.owner_id, access.can(crate::sharing::PERM_CREATE))
                    }
                }
            };

            // Already there? That's our answer (as long as it's a folder).
            if let Some(existing) = find_child(conn, tree_owner, parent_id, &name)? {
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

            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO files (owner_id, parent_id, name, is_dir, size, mime, created_at, modified_at)
                 VALUES (?1, ?2, ?3, 1, 0, NULL, ?4, ?4)",
                params![tree_owner, parent_id, name, now],
            )
            .map_err(|e| map_constraint(e, &name))?;
            get_entry_by_id(conn, conn.last_insert_rowid())
        })
        .await
    }

    /// Rename an entry (or update a file's metadata after an overwrite).
    ///
    /// Foreign entries require the covering share to grant UPDATE.
    pub async fn rename_entry(
        &self,
        user_id: i64,
        id: i64,
        name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;
            let tree_owner = update_target(conn, user_id, id, crate::sharing::PERM_UPDATE)?;
            let changed = conn.execute(
                "UPDATE files SET name = ?1, modified_at = ?2
                 WHERE id = ?3 AND owner_id = ?4",
                params![name, Utc::now().to_rfc3339(), id, tree_owner],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            let entry = get_entry_by_id(conn, id)?;
            Ok(entry)
        })
        .await
    }

    /// Delete an entry and, for directories, all descendants (cascade).
    /// Returns the [`BlobRef`]s of any deleted non-directory blobs for
    /// cleanup, captured while the rows still exist.
    ///
    /// Foreign entries require the covering share to grant DELETE.
    pub async fn delete_entry(&self, user_id: i64, id: i64) -> Result<Vec<BlobRef>, AppError> {
        self.run(move |conn| {
            let tree_owner = update_target(conn, user_id, id, crate::sharing::PERM_DELETE)?;

            // Collect the blobs in the subtree before cascade removes the rows.
            let mut stmt = conn.prepare(
                "WITH RECURSIVE subtree(id) AS (
                     SELECT id FROM files WHERE id = ?1
                     UNION ALL
                     SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
                 )
                 SELECT id, owner_id, created_at FROM files
                  WHERE is_dir = 0 AND id IN (SELECT id FROM subtree)",
            )?;
            let blobs = stmt
                .query_map(params![id], |r| {
                    let id: i64 = r.get(0)?;
                    let owner_id: i64 = r.get(1)?;
                    let created_at: String = r.get(2)?;
                    blob_ref(id, owner_id, &created_at)
                })?
                .collect::<Result<Vec<_>, _>>()?;

            conn.execute(
                "DELETE FROM files WHERE id = ?1 AND owner_id = ?2",
                params![id, tree_owner],
            )?;
            Ok(blobs)
        })
        .await
    }

    /// Owner and creation time of every file row — one query feeding the
    /// startup blob migration, instead of one lookup per blob.
    pub async fn blob_origins(&self) -> Result<HashMap<i64, BlobRef>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare("SELECT id, owner_id, created_at FROM files")?;
            let mut rows = stmt.query_map([], |r| {
                let id: i64 = r.get(0)?;
                let owner_id: i64 = r.get(1)?;
                let created_at: String = r.get(2)?;
                Ok((id, blob_ref(id, owner_id, &created_at)?))
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
    /// mount crumb shows the share's display name.
    pub async fn breadcrumbs(&self, user_id: i64, id: i64) -> Result<Vec<Breadcrumb>, AppError> {
        self.run(move |conn| {
            let mut trail: Vec<Breadcrumb> = Vec::new();
            let mut current = Some(id);
            let mut top_owner: Option<i64> = None;
            while let Some(cid) = current {
                let (name, parent, owner): (String, Option<i64>, i64) = conn.query_row(
                    "SELECT name, parent_id, owner_id FROM files WHERE id = ?1",
                    params![cid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                top_owner = Some(owner);
                trail.push(Breadcrumb { id: Some(cid), name });
                current = parent;
            }
            trail.reverse();
            if top_owner != Some(user_id) {
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
            trail.insert(0, Breadcrumb { id: None, name: "Home".to_string() });
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
            let mut owner = user_id;
            let mut parent: Option<i64> = None;
            let mut perms = PERM_ALL;
            let mut owner_name: Option<String> = None;
            let mut crossed = false;
            for seg in segments {
                match find_child(conn, owner, parent, &seg)? {
                    Some(e) => parent = Some(e.id),
                    None => {
                        // Root-level fallback: an incoming share mount?
                        if parent.is_none() && !crossed {
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
                            owner = access.owner_id;
                            perms = access.permissions;
                            owner_name = Some(username_by_id(conn, access.owner_id)?);
                            crossed = true;
                            parent = Some(src.id);
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }
            let Some(id) = parent else { return Ok(None); };
            let Ok(mut entry) = get_entry_by_id(conn, id) else {
                return Ok(None);
            };
            entry.permissions = perms;
            entry.owner_name = owner_name;
            Ok(Some(entry))
        })
        .await
    }

    /// Move an entry to a new parent and name (blobs keep their id).
    ///
    /// Foreign entries require UPDATE on the source and CREATE at the
    /// destination; moving an item across owners is refused (use COPY).
    pub async fn move_entry(
        &self,
        user_id: i64,
        id: i64,
        new_parent: Option<i64>,
        new_name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&new_name)?;
            let src_owner = update_target(conn, user_id, id, crate::sharing::PERM_UPDATE)?;
            if new_parent.is_none() && src_owner != user_id {
                return Err(AppError::BadRequest(
                    "cannot move a shared item into your own root".into(),
                ));
            }
            let dest_owner = create_target(conn, user_id, new_parent, &new_name)?;
            if dest_owner != src_owner {
                return Err(AppError::BadRequest(
                    "cannot move an item across owners".into(),
                ));
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

            conn.execute(
                "UPDATE files SET parent_id = ?1, name = ?2, modified_at = ?3
                 WHERE id = ?4 AND owner_id = ?5",
                params![new_parent, new_name, Utc::now().to_rfc3339(), id, src_owner],
            )
            .map_err(|e| map_constraint(e, &new_name))?;
            get_entry_by_id(conn, id)
        })
        .await
    }

    /// Update a file's size/mime/timestamp in place (used by WebDAV PUT overwrite).
    ///
    /// Foreign entries require UPDATE via the covering share.
    pub async fn update_file_meta(
        &self,
        user_id: i64,
        id: i64,
        size: i64,
        mime: Option<String>,
    ) -> Result<(), AppError> {
        self.run(move |conn| {
            let tree_owner = update_target(conn, user_id, id, crate::sharing::PERM_UPDATE)?;
            // Overwriting replaces content in place: only the *growth* has to
            // fit into the quota (shrinking passes with a negative delta).
            let old_size: Option<i64> = conn
                .query_row(
                    "SELECT size FROM files WHERE id = ?1 AND owner_id = ?2 AND is_dir = 0",
                    params![id, tree_owner],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(old_size) = old_size {
                ensure_quota(conn, tree_owner, size - old_size)?;
            }
            let changed = conn.execute(
                "UPDATE files SET size = ?1, mime = ?2, modified_at = ?3
                 WHERE id = ?4 AND owner_id = ?5 AND is_dir = 0",
                params![size, mime, Utc::now().to_rfc3339(), id, tree_owner],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            Ok(())
        })
        .await
    }

    /// Bytes of content owned by `owner_id` — what counts against the quota
    /// and what `GET /api/me` reports as `used_bytes`.
    pub async fn owner_usage(&self, owner_id: i64) -> Result<i64, AppError> {
        self.run(move |conn| {
            let used: i64 = conn.query_row(
                "SELECT COALESCE(SUM(size), 0) FROM files WHERE owner_id = ?1 AND is_dir = 0",
                params![owner_id],
                |r| r.get(0),
            )?;
            Ok(used)
        })
        .await
    }

    /// Up-front quota gate for bulk writes: fails with
    /// [`AppError::QuotaExceeded`] when `additional` more bytes would not fit
    /// into `owner_id`'s quota. Called before copying a subtree so a full
    /// quota never leaves a partial copy behind.
    pub async fn check_quota(&self, owner_id: i64, additional: i64) -> Result<(), AppError> {
        self.run(move |conn| ensure_quota(conn, owner_id, additional))
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

/// Which user's tree a create operation lands in: the requester's own tree, or
/// the folder owner's tree when a covering share grants CREATE. Also guards a
/// root create against shadowing an incoming share's display name.
fn create_target(
    conn: &Connection,
    user_id: i64,
    parent_id: Option<i64>,
    name: &str,
) -> Result<i64, AppError> {
    let Some(pid) = parent_id else {
        if share_name_taken(conn, user_id, name)? {
            return Err(AppError::Conflict(format!("'{name}' already exists here")));
        }
        return Ok(user_id);
    };
    let parent = get_entry_by_id(conn, pid)?;
    if !parent.is_dir {
        return Err(AppError::BadRequest("parent is not a folder".into()));
    }
    if parent.owner_id == user_id {
        return Ok(user_id);
    }
    let access = covering_share(conn, user_id, pid)?.ok_or(AppError::NotFound)?;
    if !access.can(crate::sharing::PERM_CREATE) {
        return Err(AppError::Forbidden);
    }
    Ok(parent.owner_id)
}

/// Which user's tree an update/delete operates in. Owners pass unconditionally;
/// foreign entries require the covering share to grant `required`.
fn update_target(
    conn: &Connection,
    user_id: i64,
    id: i64,
    required: i64,
) -> Result<i64, AppError> {
    let entry = get_entry_by_id(conn, id)?;
    if entry.owner_id == user_id {
        return Ok(user_id);
    }
    let access = covering_share(conn, user_id, id)?.ok_or(AppError::NotFound)?;
    if !access.can(required) {
        return Err(AppError::Forbidden);
    }
    Ok(entry.owner_id)
}

/// Find a direct child of `parent` in `owner`'s tree by name.
fn find_child(
    conn: &Connection,
    owner_id: i64,
    parent: Option<i64>,
    name: &str,
) -> Result<Option<FileEntry>, AppError> {
    let entry = conn
        .query_row(
            &format!(
                "SELECT {ENTRY_COLS} FROM files
                 WHERE owner_id = ?1 AND parent_id IS ?2 AND name = ?3"
            ),
            params![owner_id, parent, name],
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
         WHERE owner_id = ?1 AND parent_id IS ?2
         ORDER BY is_dir DESC, name COLLATE NOCASE ASC"
    ))?;
    let entries = stmt
        .query_map(params![owner_id, parent_id], row_to_entry)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

/// Entries that appear in a user's root because someone shared them: one
/// virtual mount per incoming share, named by the share's display name.
fn incoming_mounts(conn: &Connection, user_id: i64) -> Result<Vec<FileEntry>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT f.id, f.owner_id, f.parent_id, s.display_name, f.is_dir, f.size, f.mime,
                f.created_at, f.modified_at, u.username, s.permissions
         FROM shares s
         JOIN files f ON f.id = s.source_id
         JOIN users  u ON u.id = s.owner_id
         WHERE s.grantee_id = ?1",
    )?;
    let rows = stmt
        .query_map(params![user_id], |r| {
            let created: String = r.get(7)?;
            let modified: String = r.get(8)?;
            Ok(FileEntry {
                id: r.get(0)?,
                owner_id: r.get(1)?,
                parent_id: r.get(2)?,
                name: r.get(3)?,
                is_dir: r.get::<_, i64>(4)? != 0,
                size: r.get(5)?,
                mime: r.get(6)?,
                created_at: parse_ts(&created, 7)?,
                modified_at: parse_ts(&modified, 8)?,
                permissions: r.get(10)?,
                owner_name: Some(r.get(9)?),
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

fn validate_name(name: &str) -> Result<(), AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("name must not be empty".into()));
    }
    if trimmed == "." || trimmed == ".." || trimmed.contains('/') || trimmed.contains('\\') {
        return Err(AppError::BadRequest("name contains invalid characters".into()));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest("name contains control characters".into()));
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
