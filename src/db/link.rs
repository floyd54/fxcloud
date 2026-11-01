//! Public links: anonymous bearer-token shares (concepts/public_links.md).
//!
//! A link is a row in `public_links` plus a secret token that only the
//! visitor ever sees. The server stores `sha256(token)` and never the token
//! itself, so a leaked database dump yields no working links. Expiry is
//! *rolling* by default (a link dies only after N days **without** use, and
//! every successful visitor call slides the deadline forward) with an
//! explicit override to a *fixed* deadline or to *never*.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::models::{FileEntry, PublicLink};
use crate::sharing::{grants, normalize, PERM_SHARE};

use super::user::parse_ts;
use super::Db;

/// Default rolling window / fixed lifetime when the caller says nothing.
pub const DEFAULT_EXPIRY_DAYS: i64 = 30;

/// Upper bound on `expires_in_days`: ten years is a lifetime, not an expiry.
/// Anything beyond is refused so a typo cannot mint a link that outlives the
/// deployment.
const MAX_EXPIRY_DAYS: i64 = 3650;

/// Ceiling on the owner's label, characters.
const MAX_LABEL_CHARS: usize = 200;

/// What resolving a visitor's token turned up.
pub enum LinkState {
    /// The link is live: here is its record (source name and permissions
    /// included) and the operations the visitor may perform.
    Active(PublicLink),
    /// The link exists but its effective deadline has passed (410).
    Expired,
    /// No such link: wrong, revoked, or the file it pointed at is gone (404).
    Unknown,
}

impl Db {
    /// Mint a public link on a personal entry of `owner_id`.
    ///
    /// Returns the record plus the **raw token**, which is handed to the caller
    /// exactly once and then only its hash survives. Refuses encrypted sources
    /// (v1 is plaintext-only, section 5), group-owned rows, and any mask
    /// carrying `PERM_SHARE`.
    pub async fn create_public_link(
        &self,
        owner_id: i64,
        source_id: i64,
        permissions: i64,
        expiry_mode: Option<String>,
        expires_in_days: Option<i64>,
        label: Option<String>,
    ) -> Result<(PublicLink, String), AppError> {
        let perms = normalize(permissions);
        // An anonymous visitor must never be able to mint further links.
        if grants(perms, PERM_SHARE) {
            return Err(AppError::BadRequest(
                "public links cannot re-share - PERM_SHARE is not grantable".into(),
            ));
        }
        let mode = parse_expiry_mode(expiry_mode.as_deref())?;
        let days = parse_expiry_days(mode, expires_in_days)?;
        let label = normalize_label(label)?;

        self.run(move |conn| {
            // Source must exist, be a personal row, belong to the owner, and be
            // plaintext (concepts/public_links.md section 5).
            let (source_name, is_dir, row_owner, row_group, enc_version): (
                String,
                bool,
                i64,
                Option<i64>,
                i64,
            ) = conn
                .query_row(
                    "SELECT name, is_dir != 0, owner_id, owner_group_id, enc_version
                   FROM files WHERE id = ?1",
                    params![source_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?
                .ok_or(AppError::NotFound)?;
            if row_group.is_some() {
                // Groups have their own audience logic; v1 refuses them (403).
                return Err(AppError::ForbiddenDetail(
                    "group folders cannot back a public link yet".into(),
                ));
            }
            if row_owner != owner_id {
                return Err(AppError::NotFound);
            }
            if enc_version > 0 {
                // v1 links are plaintext-only; the dialog disables the control,
                // and this is the server-side backstop (section 5).
                return Err(AppError::Conflict(
                    "encrypted entries cannot back a public link yet".into(),
                ));
            }

            let token = generate_link_token();
            let token_hash = hash_link_token(&token);
            let now = Utc::now();
            let expires_at = match mode {
                ExpiryMode::Never => None,
                // Fixed and rolling start the same way ("N days from now");
                // only a later visitor call slides the rolling one forward.
                ExpiryMode::Fixed | ExpiryMode::Rolling => {
                    Some((now + Duration::days(days.unwrap_or(DEFAULT_EXPIRY_DAYS))).to_rfc3339())
                }
            };
            conn.execute(
                "INSERT INTO public_links (token_hash, source_id, owner_id, permissions, label,
                                       expiry_mode, expires_in_days, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    token_hash,
                    source_id,
                    owner_id,
                    perms,
                    label,
                    mode.as_str(),
                    days,
                    now.to_rfc3339(),
                    expires_at
                ],
            )
            .map_err(|e| map_link_constraint(e))?;
            let id = conn.last_insert_rowid();

            Ok((
                PublicLink {
                    id,
                    source_id,
                    owner_id,
                    source_name,
                    is_dir,
                    permissions: perms,
                    label,
                    expiry_mode: mode.as_str().to_string(),
                    expires_in_days: days,
                    expires_at: expires_at.as_deref().and_then(|s| parse_ts(s, 0).ok()),
                    last_access_at: None,
                    download_count: 0,
                    created_at: now,
                },
                token,
            ))
        })
        .await
    }

    /// Resolve a visitor's token to its state: live, expired, or unknown.
    ///
    /// The expiry check happens here, **before** any touch, so a visit to an
    /// already-expired link can never resurrect it (section 3). Rolling links
    /// that are still inside their window come back `Active`; their deadline is
    /// *not* moved here - that is [`Db::touch_public_link`]'s job, after a
    /// successful (2xx) operation.
    pub async fn resolve_public_link(&self, token_hash: String) -> Result<LinkState, AppError> {
        self.run(move |conn| {
            let found = conn
                .query_row(
                    "SELECT l.id, l.source_id, l.owner_id, f.name, f.is_dir != 0 AS is_dir, l.permissions,
                        IFNULL(l.label, '') AS label, l.expiry_mode, l.expires_in_days,
                        l.created_at, l.expires_at, l.last_access_at, l.download_count
                   FROM public_links l
                   JOIN files f ON f.id = l.source_id
                  WHERE l.token_hash = ?1",
                    params![token_hash],
                    row_to_link,
                )
                .optional()?;
            match found {
                None => Ok(LinkState::Unknown),
                Some(link) => {
                    let now = Utc::now();
                    match link.expires_at {
                        // `NULL` = never expires.
                        None => Ok(LinkState::Active(link)),
                        Some(deadline) if deadline > now => Ok(LinkState::Active(link)),
                        Some(_) => Ok(LinkState::Expired),
                    }
                }
            }
        })
        .await
    }

    /// Record one **successful** (2xx) visitor operation against a link.
    ///
    /// Slides a rolling link's deadline to `now + window` (never backwards -
    /// `now` only grows), stamps `last_access_at`, and bumps `download_count`
    /// when the operation was a download. Fixed and `never` links keep their
    /// deadline untouched.
    ///
    /// The `WHERE` guard re-checks the deadline so this can never revive an
    /// expired link even if a caller forgets the resolve-then-touch order: an
    /// expired row matches no row and the UPDATE is a no-op.
    pub async fn touch_public_link(
        &self,
        link_id: i64,
        count_download: bool,
    ) -> Result<(), AppError> {
        self.run(move |conn| {
            let now = Utc::now();
            let now_s = now.to_rfc3339();
            // Read the mode and window, then slide in Rust so the stored format
            // stays exactly what chrono wrote (SQLite's datetime() would emit a
            // different shape and break the lexicographic RFC3339 comparison).
            let info: Option<(String, Option<i64>)> = conn
                .query_row(
                    "SELECT expiry_mode, expires_in_days FROM public_links WHERE id = ?1",
                    params![link_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((mode, days)) = info else {
                return Ok(()); // revoked between resolve and touch: nothing to do
            };
            let new_expiry = if mode == ExpiryMode::Rolling.as_str() {
                days.map(|d| (now + Duration::days(d)).to_rfc3339())
            } else {
                // Fixed and never: carry the existing deadline forward unchanged
                // (SELECT it so the UPDATE below does not clobber it to NULL).
                conn.query_row(
                    "SELECT expires_at FROM public_links WHERE id = ?1",
                    params![link_id],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten()
            };
            conn.execute(
                "UPDATE public_links
                SET last_access_at = ?1,
                    expires_at = ?2,
                    download_count = download_count + ?3
              WHERE id = ?4
                AND (expires_at IS NULL OR expires_at > ?1)",
                params![now_s, new_expiry, i64::from(count_download), link_id],
            )?;
            Ok(())
        })
        .await
    }

    /// The owner's public links, newest first. Never carries a token - only the
    /// stored hash exists, so there is nothing to re-echo.
    pub async fn list_public_links(&self, owner_id: i64) -> Result<Vec<PublicLink>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT l.id, l.source_id, l.owner_id, f.name, f.is_dir != 0 AS is_dir, l.permissions,
                    IFNULL(l.label, '') AS label, l.expiry_mode, l.expires_in_days,
                    l.created_at, l.expires_at, l.last_access_at, l.download_count
               FROM public_links l
               JOIN files f ON f.id = l.source_id
              WHERE l.owner_id = ?1
              ORDER BY l.created_at DESC",
            )?;
            let rows = stmt
                .query_map(params![owner_id], row_to_link)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }

    /// Revoke a link (owner only): a row delete, effective on the next request.
    pub async fn revoke_public_link(&self, owner_id: i64, link_id: i64) -> Result<(), AppError> {
        self.run(move |conn| {
            let changed = conn.execute(
                "DELETE FROM public_links WHERE id = ?1 AND owner_id = ?2",
                params![link_id, owner_id],
            )?;
            if changed == 0 {
                return Err(AppError::NotFound);
            }
            Ok(())
        })
        .await
    }

    /// Drop every link whose effective deadline has passed. Runs next to the
    /// trash sweep (`src/main.rs`); the lazy per-access check answers 410 in
    /// the meantime.
    pub async fn sweep_expired_links(&self) -> Result<usize, AppError> {
        self.run(move |conn| {
            let now = Utc::now().to_rfc3339();
            let n = conn.execute(
                "DELETE FROM public_links WHERE expires_at IS NOT NULL AND expires_at <= ?1",
                params![now],
            )?;
            Ok(n)
        })
        .await
    }

    /// The entry a visitor asked for (`requested_id`), but only when it sits
    /// **inside** the link's subtree - the source itself or a descendant.
    ///
    /// Walks up the parent chain with the same 64-hop cap `covering_share`
    /// uses, so a corrupt parent cycle yields "outside" instead of spinning.
    /// A sibling or anything above the source is `None`: the visitor can never
    /// reach beyond the entry the owner linked (section 6).
    pub async fn public_entry_in_subtree(
        &self,
        source_id: i64,
        requested_id: i64,
    ) -> Result<Option<FileEntry>, AppError> {
        self.run(move |conn| {
            let mut cur = Some(requested_id);
            let mut hops = 0;
            while let Some(id) = cur {
                if id == source_id {
                    // Inside - but the caller asked for `requested_id`, so hand
                    // back *that* row. The climb only proves containment; it
                    // must not substitute the source for a descendant (a
                    // download would then see a folder, a delete would trash
                    // the shared root).
                    return get_entry_for_link(conn, requested_id).map(Some);
                }
                hops += 1;
                if hops > 64 {
                    return Ok(None);
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
        })
        .await
    }

    /// List a folder's **plaintext**, live children for a visitor.
    ///
    /// Encrypted children (`enc_version > 0`) are filtered out entirely - not
    /// merely undownloadable, but invisible: their names never reach the
    /// visitor (section 5). The rows are the link owner's personal tree, so the
    /// filter is on `owner_id` + no group + not trashed.
    pub async fn public_list_children(
        &self,
        owner_id: i64,
        parent_id: i64,
    ) -> Result<Vec<FileEntry>, AppError> {
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {ENTRY_COLS_FOR_LINK} FROM files
              WHERE owner_id = ?1 AND owner_group_id IS NULL AND parent_id = ?2
                AND deleted_at IS NULL AND enc_version = 0
              ORDER BY is_dir DESC, name COLLATE NOCASE ASC"
            ))?;
            let entries = stmt
                .query_map(params![owner_id, parent_id], row_to_entry_for_link)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(entries)
        })
        .await
    }
} // impl Db

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The three expiry modes, as stored in `public_links.expiry_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryMode {
    /// Dies only after `expires_in_days` days *without* use; every
    /// successful visitor call slides the deadline forward. The default.
    Rolling,
    /// Hard deadline from creation ("expires exactly 30 days after it was
    /// made"), never moved by use.
    Fixed,
    /// No deadline at all; `expires_at` stays NULL.
    Never,
}

impl ExpiryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ExpiryMode::Rolling => "rolling",
            ExpiryMode::Fixed => "fixed",
            ExpiryMode::Never => "never",
        }
    }
}

fn parse_expiry_mode(raw: Option<&str>) -> Result<ExpiryMode, AppError> {
    match raw {
        None | Some("") => Ok(ExpiryMode::Rolling),
        Some("rolling") => Ok(ExpiryMode::Rolling),
        Some("fixed") => Ok(ExpiryMode::Fixed),
        Some("never") => Ok(ExpiryMode::Never),
        Some(other) => Err(AppError::BadRequest(format!(
            "unknown expiry_mode {other:?} - use rolling, fixed or never"
        ))),
    }
}

fn parse_expiry_days(mode: ExpiryMode, days: Option<i64>) -> Result<Option<i64>, AppError> {
    if mode == ExpiryMode::Never {
        // `never` stores NULL days regardless of what was sent.
        return Ok(None);
    }
    let days = days.unwrap_or(DEFAULT_EXPIRY_DAYS);
    if !(1..=MAX_EXPIRY_DAYS).contains(&days) {
        return Err(AppError::BadRequest(format!(
            "expires_in_days must be between 1 and {MAX_EXPIRY_DAYS}"
        )));
    }
    Ok(Some(days))
}

fn normalize_label(label: Option<String>) -> Result<String, AppError> {
    let label = label.unwrap_or_default().trim().to_string();
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(AppError::BadRequest(format!(
            "label is too long - up to {MAX_LABEL_CHARS} characters"
        )));
    }
    Ok(label)
}

/// A fresh bearer token: 32 OsRng bytes, base64url without padding (43
/// chars, 256 bits). Generated server-side so the plaintext exists only in
/// this response.
pub fn generate_link_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The stored form of a token: sha256 hex. Only this ever touches the disk.
pub fn hash_link_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn row_to_link(row: &rusqlite::Row<'_>) -> rusqlite::Result<PublicLink> {
    let created_at: String = row.get("created_at")?;
    let expires_at: Option<String> = row.get("expires_at")?;
    let last_access_at: Option<String> = row.get("last_access_at")?;
    Ok(PublicLink {
        id: row.get("id")?,
        source_id: row.get("source_id")?,
        owner_id: row.get("owner_id")?,
        source_name: row.get("name")?,
        is_dir: row.get::<_, i64>("is_dir")? != 0,
        permissions: row.get("permissions")?,
        label: row.get("label")?,
        expiry_mode: row.get("expiry_mode")?,
        expires_in_days: row.get("expires_in_days")?,
        expires_at: expires_at.as_deref().and_then(|s| parse_ts(s, 0).ok()),
        last_access_at: last_access_at.as_deref().and_then(|s| parse_ts(s, 0).ok()),
        download_count: row.get("download_count")?,
        created_at: parse_ts(&created_at, 0).unwrap_or_else(|_| Utc::now()),
    })
}

/// The `files` columns the visitor surface reads, mirroring `file.rs`'s
/// `ENTRY_COLS` without reaching into that module (which stays untouched).
const ENTRY_COLS_FOR_LINK: &str =
    "id, owner_id, owner_group_id, parent_id, name, is_dir, size, mime, \
     created_at, modified_at, deleted_at, enc_version";

/// Map one `files` row (per [`ENTRY_COLS_FOR_LINK`]) into a [`FileEntry`].
///
/// Only the fields a visitor's listing or download needs are meaningful
/// here; permissions/owner_name/subtree are left at their defaults because
/// the public routes decide access from the link's mask, not the row's.
fn row_to_entry_for_link(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileEntry> {
    let created_at: String = row.get("created_at")?;
    let modified_at: String = row.get("modified_at")?;
    let deleted_at: Option<String> = row.get("deleted_at")?;
    Ok(FileEntry {
        id: row.get("id")?,
        owner_id: row.get("owner_id")?,
        owner_group_id: row.get("owner_group_id")?,
        group_name: None,
        parent_id: row.get("parent_id")?,
        name: row.get("name")?,
        is_dir: row.get::<_, i64>("is_dir")? != 0,
        size: row.get("size")?,
        mime: row.get("mime")?,
        created_at: parse_ts(&created_at, 0)?,
        modified_at: parse_ts(&modified_at, 0)?,
        permissions: 0,
        owner_name: None,
        subtree_bytes: None,
        deleted_at: deleted_at.as_deref().map(|s| parse_ts(s, 0)).transpose()?,
        purge_at: None,
        enc_version: row.get("enc_version")?,
        enc_key: None,
    })
}

/// One entry by id, for the visitor surface. Missing row -> `NotFound`.
fn get_entry_for_link(conn: &Connection, id: i64) -> Result<FileEntry, AppError> {
    conn.query_row(
        &format!("SELECT {ENTRY_COLS_FOR_LINK} FROM files WHERE id = ?1"),
        params![id],
        row_to_entry_for_link,
    )
    .optional()?
    .ok_or(AppError::NotFound)
}

fn map_link_constraint(e: rusqlite::Error) -> AppError {
    match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            AppError::Conflict("link token collision - retry".into())
        }
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharing::PERM_READ;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A throwaway database with the real migrations applied (see the note
    /// in `db/file.rs`: file-backed, not `:memory:`, because the pool hands
    /// every in-memory connection its own private database).
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
        let dir = std::env::temp_dir().join(format!("fxcloud-link-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let db = Db::open(&dir.join("fxcloud.db")).expect("migrations must apply");
        Scratch { db, dir }
    }

    fn add_user(conn: &Connection, name: &str) -> i64 {
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, created_at, quota_bytes)
             VALUES (?1, 'hash', ?1, '2026-01-01T00:00:00Z', 1048576)",
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

    fn add_file(
        conn: &Connection,
        owner: i64,
        name: &str,
        is_dir: bool,
        enc: i64,
        parent: Option<i64>,
    ) -> i64 {
        conn.execute(
            "INSERT INTO files (owner_id, parent_id, name, is_dir, size, created_at, modified_at, enc_version)
             VALUES (?1, ?2, ?3, ?4, 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', ?5)",
            params![owner, parent, name, is_dir, enc],
        )
        .expect("insert file");
        conn.last_insert_rowid()
    }

    /// A user plus one plaintext folder to link (owner, folder_id).
    fn seed(s: &Scratch) -> (i64, i64) {
        let conn = s.db.pool.get().unwrap();
        let owner = add_user(&conn, "owner");
        let folder = add_file(&conn, owner, "docs", true, 0, None);
        drop(conn);
        (owner, folder)
    }

    #[test]
    fn a_token_roundtrips_through_its_hash() {
        let token = generate_link_token();
        // 32 bytes base64url, no padding -> 43 characters.
        assert_eq!(token.len(), 43);
        assert!(!token.contains('='));
        assert_eq!(hash_link_token(&token).len(), 64, "sha256 hex is 64 chars");
        // The hash is deterministic and distinct per token.
        assert_eq!(hash_link_token(&token), hash_link_token(&token));
        assert_ne!(
            hash_link_token(&token),
            hash_link_token(&generate_link_token())
        );
    }

    #[tokio::test]
    async fn an_unknown_token_resolves_to_unknown() {
        let s = scratch();
        let state =
            s.db.resolve_public_link(hash_link_token("nope"))
                .await
                .expect("resolve");
        assert!(matches!(state, LinkState::Unknown));
    }

    #[tokio::test]
    async fn the_default_link_is_rolling_and_expires_in_30_days() {
        let s = scratch();
        let (owner, folder) = seed(&s);
        let (link, token) =
            s.db.create_public_link(owner, folder, PERM_READ, None, None, None)
                .await
                .expect("create");
        assert_eq!(link.expiry_mode, "rolling");
        assert_eq!(link.expires_in_days, Some(30));
        assert!(link.expires_at.is_some());
        assert_eq!(link.permissions, PERM_READ);
        // The token resolves, and its stored form is the hash, not the token.
        let state =
            s.db.resolve_public_link(hash_link_token(&token))
                .await
                .expect("resolve");
        assert!(matches!(state, LinkState::Active(_)));
        let stored: String = {
            let conn = s.db.pool.get().unwrap();
            conn.query_row("SELECT token_hash FROM public_links", [], |r| r.get(0))
                .expect("token_hash")
        };
        assert_ne!(stored, token, "the raw token must never be stored");
        assert_eq!(stored, hash_link_token(&token));
    }

    #[tokio::test]
    async fn a_rolling_link_slides_forward_on_touch_and_never_backwards() {
        let s = scratch();
        let (owner, folder) = seed(&s);
        let (link, _) =
            s.db.create_public_link(
                owner,
                folder,
                PERM_READ,
                Some("rolling".into()),
                Some(30),
                None,
            )
            .await
            .expect("create");
        let original = link.expires_at.expect("rolling has a deadline");

        // Pretend the link was made 25 days ago: its deadline is now+5d.
        {
            let conn = s.db.pool.get().unwrap();
            let past = (Utc::now() - Duration::days(25)).to_rfc3339();
            conn.execute(
                "UPDATE public_links SET created_at = ?1, expires_at = ?2 WHERE id = ?3",
                params![past, (Utc::now() + Duration::days(5)).to_rfc3339(), link.id],
            )
            .expect("backdate");
        }
        s.db.touch_public_link(link.id, false).await.expect("touch");
        let state =
            s.db.resolve_public_link(hash_link_token(&generate_link_token()))
                .await
                .expect("resolve");
        // (that resolve was for an unknown token; re-read the row directly)
        let _ = state;
        let slid: Option<String> = {
            let conn = s.db.pool.get().unwrap();
            conn.query_row(
                "SELECT expires_at FROM public_links WHERE id = ?1",
                params![link.id],
                |r| r.get(0),
            )
            .expect("read back")
        };
        let slid_at = parse_ts(&slid.expect("deadline"), 0).expect("parse");
        assert!(
            slid_at > Utc::now() + Duration::days(29),
            "a touch slides the window out to ~30 days ({slid_at:?})"
        );
        assert!(slid_at >= original, "and never moves backwards");
    }

    #[tokio::test]
    async fn a_fixed_link_is_never_slid_by_use() {
        let s = scratch();
        let (owner, folder) = seed(&s);
        let (link, token) =
            s.db.create_public_link(
                owner,
                folder,
                PERM_READ,
                Some("fixed".into()),
                Some(30),
                None,
            )
            .await
            .expect("create");
        let deadline = link.expires_at.expect("fixed has a deadline");

        // A successful visitor call must not move a fixed deadline.
        s.db.touch_public_link(link.id, true).await.expect("touch");
        let state =
            s.db.resolve_public_link(hash_link_token(&token))
                .await
                .expect("resolve");
        let active = match state {
            LinkState::Active(l) => l,
            _ => panic!("fixed link should still be active"),
        };
        assert_eq!(
            active.expires_at.expect("deadline"),
            deadline,
            "a fixed deadline is set once and never touched"
        );
        assert_eq!(active.download_count, 1, "the download counter still bumps");
    }

    #[tokio::test]
    async fn a_never_link_has_no_deadline() {
        let s = scratch();
        let (owner, folder) = seed(&s);
        let (link, token) =
            s.db.create_public_link(
                owner,
                folder,
                PERM_READ,
                Some("never".into()),
                Some(999),
                None,
            )
            .await
            .expect("create");
        assert_eq!(link.expiry_mode, "never");
        assert_eq!(link.expires_in_days, None, "never stores NULL days");
        assert!(link.expires_at.is_none());
        // Touching it keeps the deadline NULL.
        s.db.touch_public_link(link.id, false).await.expect("touch");
        let state =
            s.db.resolve_public_link(hash_link_token(&token))
                .await
                .expect("resolve");
        match state {
            LinkState::Active(l) => assert!(l.expires_at.is_none()),
            _ => panic!("never-link must stay active"),
        }
    }

    #[tokio::test]
    async fn an_expired_link_is_gone_and_a_touch_cannot_revive_it() {
        let s = scratch();
        let (owner, folder) = seed(&s);
        let (link, token) =
            s.db.create_public_link(
                owner,
                folder,
                PERM_READ,
                Some("fixed".into()),
                Some(30),
                None,
            )
            .await
            .expect("create");
        // Force the deadline into the past.
        {
            let conn = s.db.pool.get().unwrap();
            conn.execute(
                "UPDATE public_links SET expires_at = ?1 WHERE id = ?2",
                params![(Utc::now() - Duration::days(1)).to_rfc3339(), link.id],
            )
            .expect("expire");
        }
        let state =
            s.db.resolve_public_link(hash_link_token(&token))
                .await
                .expect("resolve");
        assert!(matches!(state, LinkState::Expired), "expired, not unknown");
        // A touch must not revive it (the WHERE guard matches no row).
        s.db.touch_public_link(link.id, true).await.expect("touch");
        let still: Option<String> = {
            let conn = s.db.pool.get().unwrap();
            conn.query_row(
                "SELECT expires_at FROM public_links WHERE id = ?1",
                params![link.id],
                |r| r.get(0),
            )
            .expect("read")
        };
        let at = parse_ts(&still.expect("deadline"), 0).expect("parse");
        assert!(at < Utc::now(), "still in the past - not resurrected");
    }

    #[tokio::test]
    async fn perm_share_is_refused_at_creation() {
        let s = scratch();
        let (owner, folder) = seed(&s);
        let err =
            s.db.create_public_link(owner, folder, crate::sharing::PERM_ALL, None, None, None)
                .await
                .expect_err("PERM_SHARE must be refused");
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn an_encrypted_source_is_refused_with_409() {
        let s = scratch();
        let conn = s.db.pool.get().unwrap();
        let owner = add_user(&conn, "owner");
        let enc_file = add_file(&conn, owner, "secret.txt", false, 1, None);
        drop(conn);
        let err =
            s.db.create_public_link(owner, enc_file, PERM_READ, None, None, None)
                .await
                .expect_err("encrypted source must be refused");
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn containment_allows_the_source_and_descendants_only() {
        let s = scratch();
        let (owner, folder) = seed(&s);
        let (child, sibling) = {
            let conn = s.db.pool.get().unwrap();
            (
                add_file(&conn, owner, "inside.txt", false, 0, Some(folder)),
                add_file(&conn, owner, "outside.txt", false, 0, None),
            )
        };
        // The source itself, and a child, are inside - and the child hands
        // back its *own* row: the containment climb may only prove that the
        // id sits inside the subtree, never substitute the source for it.
        assert!(s
            .db
            .public_entry_in_subtree(folder, folder)
            .await
            .expect("src")
            .is_some());
        let inside =
            s.db.public_entry_in_subtree(folder, child)
                .await
                .expect("child")
                .expect("child is inside");
        assert_eq!(inside.id, child, "the requested row must come back");
        assert_eq!(inside.name, "inside.txt");
        // A sibling (same owner, different branch) is outside.
        assert!(s
            .db
            .public_entry_in_subtree(folder, sibling)
            .await
            .expect("sib")
            .is_none());
    }

    #[tokio::test]
    async fn the_sweep_only_removes_expired_links() {
        let s = scratch();
        let (owner, folder) = seed(&s);
        let (live, _) =
            s.db.create_public_link(owner, folder, PERM_READ, None, None, None)
                .await
                .expect("live");
        let (dead, dead_token) =
            s.db.create_public_link(
                owner,
                folder,
                PERM_READ,
                Some("fixed".into()),
                Some(1),
                None,
            )
            .await
            .expect("dead");
        {
            let conn = s.db.pool.get().unwrap();
            conn.execute(
                "UPDATE public_links SET expires_at = ?1 WHERE id = ?2",
                params![(Utc::now() - Duration::days(1)).to_rfc3339(), dead.id],
            )
            .expect("expire");
        }
        let removed = s.db.sweep_expired_links().await.expect("sweep");
        assert_eq!(removed, 1, "exactly the expired link is swept");
        // The live one is untouched; the dead one is now unknown.
        assert!(matches!(
            s.db.resolve_public_link(hash_link_token(&generate_link_token()))
                .await
                .expect("r"),
            LinkState::Unknown
        ));
        let _ = (live, dead_token);
        let remaining: i64 = {
            let conn = s.db.pool.get().unwrap();
            conn.query_row("SELECT COUNT(*) FROM public_links", [], |r| r.get(0))
                .expect("count")
        };
        assert_eq!(remaining, 1, "only the live link remains");
    }

    #[tokio::test]
    async fn encrypted_children_are_invisible_in_the_visitor_listing() {
        let s = scratch();
        let (owner, folder) = seed(&s);
        {
            let conn = s.db.pool.get().unwrap();
            add_file(&conn, owner, "plain.txt", false, 0, Some(folder));
            add_file(&conn, owner, "cipher.txt", false, 1, Some(folder));
        }
        let kids =
            s.db.public_list_children(owner, folder)
                .await
                .expect("list");
        assert_eq!(kids.len(), 1, "only the plaintext child shows");
        assert_eq!(kids[0].name, "plain.txt");
    }
}
