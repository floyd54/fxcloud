use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::AppError;
use crate::models::{Breadcrumb, FileEntry};

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
    })
}

const ENTRY_COLS: &str =
    "id, owner_id, parent_id, name, is_dir, size, mime, created_at, modified_at";

impl Db {
    /// List the direct children of `parent_id` (or the owner's root when `None`),
    /// sorted folders-first then alphabetically.
    pub async fn list_children(
        &self,
        owner_id: i64,
        parent_id: Option<i64>,
    ) -> Result<Vec<FileEntry>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {ENTRY_COLS} FROM files
                 WHERE owner_id = ?1 AND parent_id IS ?2
                 ORDER BY is_dir DESC, name COLLATE NOCASE ASC"
            ))?;
            let entries = stmt
                .query_map(params![owner_id, parent_id], row_to_entry)?
                .collect::<Result<Vec<_>, _>>()?;
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
    pub async fn create_dir(
        &self,
        owner_id: i64,
        parent_id: Option<i64>,
        name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;
            if parent_id.is_some() {
                ensure_dir_exists(conn, owner_id, parent_id)?;
            }
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO files (owner_id, parent_id, name, is_dir, size, mime, created_at, modified_at)
                 VALUES (?1, ?2, ?3, 1, 0, NULL, ?4, ?4)",
                params![owner_id, parent_id, name, now],
            )
            .map_err(|e| map_constraint(e, &name))?;
            let id = conn.last_insert_rowid();
            let entry = get_entry_by_id(conn, id)?;
            Ok(entry)
        })
        .await
    }

    /// Insert a file entry (metadata only). The caller writes the blob separately.
    pub async fn create_file(
        &self,
        owner_id: i64,
        parent_id: Option<i64>,
        name: String,
        size: i64,
        mime: Option<String>,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;
            if parent_id.is_some() {
                ensure_dir_exists(conn, owner_id, parent_id)?;
            }
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO files (owner_id, parent_id, name, is_dir, size, mime, created_at, modified_at)
                 VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?6)",
                params![owner_id, parent_id, name, size, mime, now],
            )
            .map_err(|e| map_constraint(e, &name))?;
            let id = conn.last_insert_rowid();
            let entry = get_entry_by_id(conn, id)?;
            Ok(entry)
        })
        .await
    }

    /// Rename an entry (or update a file's metadata after an overwrite).
    pub async fn rename_entry(
        &self,
        owner_id: i64,
        id: i64,
        name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&name)?;
            let changed = conn.execute(
                "UPDATE files SET name = ?1, modified_at = ?2
                 WHERE id = ?3 AND owner_id = ?4",
                params![name, Utc::now().to_rfc3339(), id, owner_id],
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
    /// Returns the file ids of any deleted non-directory blobs for cleanup.
    pub async fn delete_entry(&self, owner_id: i64, id: i64) -> Result<Vec<i64>, AppError> {
        self.run(move |conn| {
            // Guard against deleting the root (which has no row anyway) or foreign entries.
            let exists: Option<i64> = conn
                .query_row(
                    "SELECT id FROM files WHERE id = ?1 AND owner_id = ?2",
                    params![id, owner_id],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(AppError::NotFound);
            }

            // Collect file (non-dir) ids in the subtree before cascade removes them.
            let mut stmt = conn.prepare(
                "WITH RECURSIVE subtree(id) AS (
                     SELECT id FROM files WHERE id = ?1
                     UNION ALL
                     SELECT f.id FROM files f JOIN subtree s ON f.parent_id = s.id
                 )
                 SELECT id FROM subtree WHERE id IN (SELECT id FROM files WHERE is_dir = 0)",
            )?;
            let blob_ids = stmt
                .query_map(params![id], |r| r.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?;

            conn.execute(
                "DELETE FROM files WHERE id = ?1 AND owner_id = ?2",
                params![id, owner_id],
            )?;
            Ok(blob_ids)
        })
        .await
    }

    /// Build the breadcrumb trail from the root down to (and including) `id`.
    pub async fn breadcrumbs(&self, owner_id: i64, id: i64) -> Result<Vec<Breadcrumb>, AppError> {
        self.run(move |conn| {
            let mut trail = Vec::new();
            let mut current = Some(id);
            while let Some(cid) = current {
                let (name, parent): (String, Option<i64>) = conn.query_row(
                    "SELECT name, parent_id FROM files WHERE id = ?1 AND owner_id = ?2",
                    params![cid, owner_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                trail.push(Breadcrumb { id: Some(cid), name });
                current = parent;
            }
            trail.reverse();
            // Prepend the implicit root.
            trail.insert(0, Breadcrumb { id: None, name: "Home".to_string() });
            Ok(trail)
        })
        .await
    }

    /// Walk `segments` down from the owner's root and return the entry there.
    ///
    /// Callers must only pass a **non-empty** path; an empty path (the virtual
    /// root) is handled by the caller. Returns `Ok(None)` if any component is
    /// missing.
    pub async fn resolve_path(
        &self,
        owner_id: i64,
        segments: Vec<String>,
    ) -> Result<Option<FileEntry>, AppError> {
        self.run(move |conn| {
            let mut parent: Option<i64> = None;
            let mut last: Option<i64> = None;
            for seg in segments {
                let entry: Option<FileEntry> = {
                    let mut stmt = conn.prepare(&format!(
                        "SELECT {ENTRY_COLS} FROM files
                         WHERE owner_id = ?1 AND parent_id IS ?2 AND name = ?3"
                    ))?;
                    stmt.query_row(params![owner_id, parent, seg], row_to_entry)
                        .optional()?
                };
                match entry {
                    Some(e) => {
                        parent = Some(e.id);
                        last = Some(e.id);
                    }
                    None => return Ok(None),
                }
            }
            match last {
                Some(id) => Ok(get_entry_by_id(conn, id).ok()),
                None => Ok(None),
            }
        })
        .await
    }

    /// Move an entry to a new parent and name (same owner; blobs keep their id).
    pub async fn move_entry(
        &self,
        owner_id: i64,
        id: i64,
        new_parent: Option<i64>,
        new_name: String,
    ) -> Result<FileEntry, AppError> {
        self.run(move |conn| {
            validate_name(&new_name)?;
            if new_parent.is_some() {
                ensure_dir_exists(conn, owner_id, new_parent)?;
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
                params![new_parent, new_name, Utc::now().to_rfc3339(), id, owner_id],
            )
            .map_err(|e| map_constraint(e, &new_name))?;
            get_entry_by_id(conn, id)
        })
        .await
    }

    /// Update a file's size/mime/timestamp in place (used by WebDAV PUT overwrite).
    pub async fn update_file_meta(
        &self,
        owner_id: i64,
        id: i64,
        size: i64,
        mime: Option<String>,
    ) -> Result<(), AppError> {
        self.run(move |conn| {
            let changed = conn.execute(
                "UPDATE files SET size = ?1, mime = ?2, modified_at = ?3
                 WHERE id = ?4 AND owner_id = ?5 AND is_dir = 0",
                params![size, mime, Utc::now().to_rfc3339(), id, owner_id],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            Ok(())
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

fn ensure_dir_exists(conn: &Connection, owner_id: i64, parent_id: Option<i64>) -> Result<(), AppError> {
    let is_dir: Option<i64> = match parent_id {
        Some(pid) => conn
            .query_row(
                "SELECT is_dir FROM files WHERE id = ?1 AND owner_id = ?2",
                params![pid, owner_id],
                |r| r.get(0),
            )
            .optional()?,
        None => Some(1), // implicit root
    };
    match is_dir {
        Some(v) if v != 0 => Ok(()),
        Some(_) => Err(AppError::BadRequest("parent is not a folder".into())),
        None => Err(AppError::NotFound),
    }
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
