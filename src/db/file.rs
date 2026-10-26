use std::collections::HashMap;

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::error::AppError;
use crate::models::{BlobRef, Breadcrumb, FileEntry};
use crate::sharing::PERM_ALL;

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

const ENTRY_COLS: &str = "id, owner_id, parent_id, name, is_dir, size, mime, created_at, \
                         modified_at, deleted_at, enc_version, enc_key";

/// Entries that are trash roots: marked themselves, with a live (or absent)
/// parent. Children of a trashed folder are part of that folder's restore
/// unit, not separate trash items.
const TRASH_ROOTS: &str = "deleted_at IS NOT NULL
       AND (parent_id IS NULL
            OR parent_id IN (SELECT id FROM files WHERE deleted_at IS NULL))";

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
        self.run(move |conn| {
            let mut entries = match parent_id {
                None => {
                    let mut entries = own_children(conn, user_id, None)?;
                    entries.extend(incoming_mounts(conn, user_id)?);
                    sort_entries(&mut entries);
                    entries
                }
                Some(pid) => {
                    let parent = get_entry_by_id(conn, pid)?;
                    if !parent.is_dir {
                        return Err(AppError::BadRequest("parent is not a folder".into()));
                    }
                    if parent.owner_id == user_id {
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
        enc_version: i64,
        enc_key: Option<Vec<u8>>,
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
                "INSERT INTO files (owner_id, parent_id, name, is_dir, size, mime, created_at,
                                    modified_at, enc_version, enc_key)
                 VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?6, ?7, ?8)",
                params![
                    tree_owner,
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

    /// Move an entry to the trash: only the entry itself is marked with a
    /// deletion time - its subtree rows and blob content stay untouched, so
    /// a restore is a single UPDATE and nothing moves on disk.
    ///
    /// Foreign entries require the covering share to grant DELETE; the mark
    /// lands in the *owner's* tree, so the owner sees and restores it.
    pub async fn trash_entry(&self, user_id: i64, id: i64) -> Result<(), AppError> {
        self.run(move |conn| {
            let tree_owner = update_target(conn, user_id, id, crate::sharing::PERM_DELETE)?;
            conn.execute(
                "UPDATE files SET deleted_at = ?1
                 WHERE id = ?2 AND owner_id = ?3 AND deleted_at IS NULL",
                params![Utc::now().to_rfc3339(), id, tree_owner],
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
    pub async fn trash_list(&self, user_id: i64) -> Result<Vec<FileEntry>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {ENTRY_COLS} FROM files
                 WHERE owner_id = ?1 AND {TRASH_ROOTS}
                 ORDER BY deleted_at DESC, name COLLATE NOCASE ASC"
            ))?;
            let mut entries = stmt
                .query_map(params![user_id], row_to_entry)?
                .collect::<Result<Vec<_>, _>>()?;
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
    pub async fn restore_trash(&self, user_id: i64, id: i64) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            let entry = get_entry_by_id(conn, id)?;
            if entry.owner_id != user_id || entry.deleted_at.is_none() {
                return Err(AppError::NotFound);
            }
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
                    while find_child(conn, user_id, Some(pid), &name)?.is_some() {
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

    /// Hard-delete a single trashed root of this user ("Delete permanently").
    pub async fn purge_trash_item(&self, user_id: i64, id: i64) -> Result<Vec<BlobRef>, AppError> {
        self.run(move |conn| {
            let entry = get_entry_by_id(conn, id)?;
            if entry.owner_id != user_id || entry.deleted_at.is_none() {
                return Err(AppError::NotFound);
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
                let (name, parent, owner, enc_key): (String, Option<i64>, i64, Option<Vec<u8>>) =
                    conn.query_row(
                        "SELECT name, parent_id, owner_id, enc_key FROM files WHERE id = ?1",
                        params![cid],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )?;
                top_owner = Some(owner);
                trail.push(Breadcrumb {
                    id: Some(cid),
                    name,
                    enc_key: enc_key.map(|b| BASE64.encode(b)),
                });
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
    /// Move a row within one owner's tree (UPDATE on the source, CREATE at
    /// the destination, never across owners).
    ///
    /// This is the key-blind door: WebDAV MOVE takes it and holds no keys
    /// (DECISION 9 - treat encrypted rows as opaque), so a keyed row may
    /// only travel between parents that already carry the same key record.
    /// Anything else would produce a row whose record no longer opens, and
    /// the move refuses rather than doing that silently.
    pub async fn move_entry(
        &self,
        user_id: i64,
        id: i64,
        new_parent: Option<i64>,
        new_name: String,
    ) -> Result<FileEntry, AppError> {
        self.move_entry_inner(user_id, id, new_parent, new_name, true)
            .await
    }

    /// The JSON move: the caller re-wrapped the row's key record for its
    /// destination *before* asking (ENCRYPTION.md 5.4 - app.js re-binds,
    /// moves, and puts the record back if the move is refused), so only the
    /// metadata travels now.
    ///
    /// The server cannot read keys and so cannot verify that wrap. This is
    /// the position `PUT /files/key` already takes for the same caller:
    /// PERM_UPDATE is the check, the crypto stays the client's. Keeping the
    /// key-domain guard here would refuse exactly the moves the client
    /// prepared - in a keyed tree every folder carries its own record, so
    /// every destination differs from every source (5.4).
    pub async fn move_entry_rebound(
        &self,
        user_id: i64,
        id: i64,
        new_parent: Option<i64>,
        new_name: String,
    ) -> Result<FileEntry, AppError> {
        self.move_entry_inner(user_id, id, new_parent, new_name, false)
            .await
    }

    async fn move_entry_inner(
        &self,
        user_id: i64,
        id: i64,
        new_parent: Option<i64>,
        new_name: String,
        guard_key_domains: bool,
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
        // `(enc_version, enc_key)` when this write also changes the row's
        // encryption mode; `None` to leave both columns alone (the usual
        // case: content replaced, mode unchanged).
        enc: Option<(i64, Vec<u8>)>,
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
            let now = Utc::now().to_rfc3339();
            // Mode change and content change belong in one statement: a row
            // that reports `enc_version = 0` while holding ciphertext (or the
            // other way round) is exactly the half-applied state every other
            // branch in this codebase is written to avoid.
            let changed = match enc {
                Some((version, key)) => conn.execute(
                    "UPDATE files SET size = ?1, mime = ?2, modified_at = ?3,
                                     enc_version = ?4, enc_key = ?5
                     WHERE id = ?6 AND owner_id = ?7 AND is_dir = 0",
                    params![size, mime, now, version, key, id, tree_owner],
                )?,
                None => conn.execute(
                    "UPDATE files SET size = ?1, mime = ?2, modified_at = ?3
                     WHERE id = ?4 AND owner_id = ?5 AND is_dir = 0",
                    params![size, mime, now, id, tree_owner],
                )?,
            };
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
    /// Permission is PERM_UPDATE, the same mask the content write asks for:
    /// the owner re-binding a record after a move or during the share-time
    /// migration, and a share's UPDATE grantee re-binding one they hold the
    /// raw key for (the crypto mirrors the API permission, it does not
    /// replace it). The server cannot check the wrapping - it holds no key -
    /// but a caller with UPDATE can already overwrite the bytes, so this
    /// hands out no new capability. A plaintext file has no record to
    /// replace and is refused; a folder may gain one at any time, because
    /// folders start unkeyed and are keyed on the first encrypted write
    /// below them.
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
            let tree_owner = update_target(conn, user_id, id, crate::sharing::PERM_UPDATE)?;
            let (is_dir, enc_version): (bool, i64) = conn
                .query_row(
                    "SELECT is_dir != 0, enc_version FROM files WHERE id = ?1 AND owner_id = ?2",
                    params![id, tree_owner],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(AppError::NotFound)?;
            if !is_dir && enc_version == 0 {
                return Err(AppError::BadRequest("this file is not encrypted".into()));
            }
            conn.execute(
                "UPDATE files SET enc_key = ?1 WHERE id = ?2 AND owner_id = ?3",
                params![key, id, tree_owner],
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
    if under_trash(conn, &parent)? {
        return Err(AppError::NotFound);
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
    if under_trash(conn, &entry)? {
        return Err(AppError::NotFound);
    }
    if entry.owner_id == user_id {
        return Ok(user_id);
    }
    let access = covering_share(conn, user_id, id)?.ok_or(AppError::NotFound)?;
    if !access.can(required) {
        return Err(AppError::Forbidden);
    }
    Ok(entry.owner_id)
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
                 WHERE owner_id = ?1 AND parent_id IS ?2 AND name = ?3
                   AND deleted_at IS NULL"
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
         WHERE owner_id = ?1 AND parent_id IS ?2 AND deleted_at IS NULL
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
    conn.execute("DELETE FROM files WHERE id = ?1", params![id])?;
    Ok(blobs)
}

/// Shared engine of `purge_expired_trash` / `empty_trash`: hard-delete every
/// matching trash root and collect the blobs to unlink.
fn purge_roots(
    conn: &Connection,
    owner: Option<i64>,
    before: Option<String>,
) -> Result<Vec<BlobRef>, AppError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT id FROM files
         WHERE {TRASH_ROOTS}
           AND (?1 IS NULL OR owner_id = ?1)
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

    fn add_file(conn: &Connection, owner: i64, name: &str, size: i64, is_dir: bool) {
        conn.execute(
            "INSERT INTO files (owner_id, name, is_dir, size, created_at, modified_at)
             VALUES (?1, ?2, ?3, ?4, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            params![owner, name, is_dir, size],
        )
        .expect("insert file");
    }

    #[test]
    fn the_quota_holds_at_the_exact_byte() {
        let s = scratch();
        let conn = s.db.pool.get().unwrap();
        let owner = user_with_quota(&conn, 100);

        assert!(
            ensure_quota(&conn, owner, 100).is_ok(),
            "exactly the quota fits"
        );
        assert!(
            ensure_quota(&conn, owner, 101).is_err(),
            "one byte over does not"
        );

        add_file(&conn, owner, "a", 60, false);
        assert!(ensure_quota(&conn, owner, 40).is_ok(), "60 + 40 == 100");
        assert!(ensure_quota(&conn, owner, 41).is_err(), "60 + 41 > 100");
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

        assert!(ensure_quota(&conn, owner, 10).is_ok(), "90 + 10 == 100");
        assert!(ensure_quota(&conn, owner, 11).is_err());
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
            ensure_quota(&conn, owner, 100).is_ok(),
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

        assert!(ensure_quota(&conn, owner, 0).is_ok());
        assert!(ensure_quota(&conn, owner, -5).is_ok());
    }

    #[test]
    fn the_refusal_reports_both_numbers() {
        let s = scratch();
        let conn = s.db.pool.get().unwrap();
        let owner = user_with_quota(&conn, 100);
        add_file(&conn, owner, "a", 90, false);

        match ensure_quota(&conn, owner, 20) {
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
}
