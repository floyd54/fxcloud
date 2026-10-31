use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;

use crate::config::Config;
use crate::db::Db;
use crate::error::AppError;
use crate::models::{BlobRef, FileEntry};

/// Leading bytes of client-side encrypted content (ENCRYPTION.md 5.3).
///
/// The server never parses beyond this: the magic exists so a write path can
/// tell "the caller handed me a ciphertext container" from "the caller handed
/// me plaintext" *before* it overwrites a row, which is what keeps WebDAV from
/// silently destroying encrypted files with a plaintext `PUT`.
pub const FXE1_MAGIC: &[u8] = b"FXE1";

/// How many leading bytes the text heuristic looks at.
const TEXT_SNIFF_WINDOW: usize = 8192;

/// How many leading bytes the write paths keep for [`resolve_mime`].
///
/// Magic numbers all sit in the head of a file (the farthest out is the ISO
/// image signature at 32 KiB), and the text heuristic windows further down
/// to [`TEXT_SNIFF_WINDOW`] on its own - so a streamed upload hands this
/// prefix instead of its whole body, and sniffing a 4 GiB PUT decides on
/// 64 KiB of it (S1, `concepts/streaming.md`).
pub const SNIFF_WINDOW: usize = 64 * 1024;

/// Pick the `mime` to store for a plaintext row: the *content* decides
/// (magic numbers first, then a text heuristic - `declared` plays no role in
/// either), and the client's declaration is only the fallback for binary the
/// sniffer does not know. `None` means "binary the sniffer does not know" -
/// the caller keeps whatever the client declared (or NULL).
///
/// This is what lets a file *without an extension* open as text: the
/// browser's `Content-Type` for such an upload is `application/octet-stream`
/// or empty, which is no help at all, while the bytes themselves usually
/// settle the question. Encrypted uploads never reach this - their bytes are
/// an FXE1 container the server cannot read (ENCRYPTION.md 7), so their
/// `mime` stays NULL.
///
/// `declared` is what the client or the file name claims (browser
/// `Content-Type`, `mime_guess` on the name). A more specific declared text
/// type (`text/markdown`, `application/json`) is kept over the generic
/// `text/plain` the heuristic would offer, so a `.md` file keeps its type;
/// `application/octet-stream` - the placeholder every extensionless upload
/// carries - is treated as "no declaration" rather than as an answer.
pub fn resolve_mime(declared: Option<&str>, data: &[u8]) -> Option<String> {
    // Magic numbers are content, not naming: they win outright.
    if let Some(kind) = infer::get(data) {
        return Some(kind.mime_type().to_string());
    }
    if looks_like_text(data) {
        return Some(match declared {
            Some(d) if is_specific_text(d) => d.to_string(),
            _ => "text/plain".to_string(),
        });
    }
    // Unknown binary: keep a real declaration, drop the placeholder.
    declared
        .filter(|d| !d.is_empty() && *d != "application/octet-stream")
        .map(str::to_string)
}

/// A declared type worth keeping over the generic `text/plain`.
fn is_specific_text(declared: &str) -> bool {
    (declared.starts_with("text/") && declared != "text/plain")
        || matches!(
            declared,
            "application/json"
                | "application/xml"
                | "application/yaml"
                | "application/x-yaml"
                | "application/toml"
                | "application/x-sh"
                | "application/javascript"
        )
        || declared.ends_with("+json")
        || declared.ends_with("+xml")
}

/// The text heuristic behind [`resolve_mime`]: one scan over the first
/// [`TEXT_SNIFF_WINDOW`] bytes decides. Text in any single-byte encoding
/// (ASCII, UTF-8, Latin-1, cp1252) contains nothing but the whitespace
/// controls (tab, LF, CR, FF) - so German umlauts in either encoding stay
/// text - while compressed, encrypted and executable data is full of the
/// remaining C0 controls, the NUL byte of UTF-16 included. UTF-16 text
/// therefore stays untyped: the editor reads UTF-8, so calling it text
/// would only promise a decode the browser cannot keep.
fn looks_like_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(TEXT_SNIFF_WINDOW)];
    !sample
        .iter()
        .any(|&b| (b < 0x20 && !matches!(b, 0x09 | 0x0A | 0x0C | 0x0D)) || b == 0x7f)
}

/// High-level file operations combining DB metadata with on-disk blobs.
///
/// Blob layout: `<blob_dir>/<owner-id>/<year>/<h1>/<h2>/<file-id>` — the
/// owner's tree and the year the file was created in come first (handy for
/// per-user and per-year backups), then two hex levels derived from the id
/// (`h1` covers 65 536 ids, `h2` covers 256). Both name levels are bounded
/// at 256 entries each, and a leaf holds 256 blobs per generation of
/// 2^24 = 16 777 216 ids: one owner-year carries up to 16.7 M files before
/// any leaf sees a 257th blob, and past that a leaf only gains another 256
/// per further 16.7 M ids handed out - the tree never gets deeper. The leaf
/// keeps the plain decimal id as its file name, which is unique by
/// construction and immune to path-traversal, and the whole path stays
/// recomputable from a row without extra state.
///
/// Blobs written before this layout existed live flat in `<blob_dir>/<id>`.
/// [`FileService::migrate_flat_blobs`] moves them into place at startup; reads
/// and deletes additionally fall back to the flat path, so a blob whose move
/// failed never goes missing.
pub struct FileService {
    db: Db,
    blob_dir: PathBuf,
    /// Staging area for incoming bodies - the same filesystem as the blobs,
    /// so committing one is a rename (see [`FileService::commit_blob`]).
    temp_dir: PathBuf,
    /// One write lock per row that is being (or was recently) rewritten; see
    /// [`FileService::begin_replace`].
    replaces: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
}

/// Rows remembered for write serialization at once (see
/// [`FileService::begin_replace`]); above this, slots nobody holds are dropped.
const REPLACE_LOCKS_MAX: usize = 4096;

/// Counters of one migration run (see [`FileService::migrate_flat_blobs`]).
#[derive(Default)]
struct MoveStats {
    moved: usize,
    orphans: usize,
    failed: usize,
    leftover: usize,
}

impl MoveStats {
    /// Whether the run had nothing to say at all.
    fn is_empty(&self) -> bool {
        self.moved + self.orphans + self.failed + self.leftover == 0
    }
}

impl FileService {
    pub fn new(db: Db, config: &Config) -> Self {
        Self {
            db,
            blob_dir: config.blob_dir(),
            temp_dir: config.data_dir.join("tmp"),
            replaces: Mutex::new(HashMap::new()),
        }
    }

    /// Hold a row's write lock across both halves of a content replacement.
    ///
    /// Replacing content is two operations: the metadata statement (size,
    /// mime, `modified_at`, and for an encrypted save `enc_version`/`enc_key`)
    /// and then the blob write. Nothing pairs them, so two saves of the *same*
    /// row overlapping in time can interleave - the later save's `enc_key`
    /// lands first and the earlier save's ciphertext lands last - and the row
    /// is left holding one file key next to another save's bytes.
    ///
    /// That state looks entirely healthy from the outside: the stored key
    /// still unwraps (it is bound to this row's id, and the passphrase is
    /// right), so the failure only surfaces the next time the file is opened,
    /// as `decryption failed for chunk 0`. Holding this guard around the
    /// statement *and* the blob write makes the pair atomic per row, while
    /// writes to different rows stay independent.
    pub async fn begin_replace(&self, file_id: i64) -> tokio::sync::OwnedMutexGuard<()> {
        let slot = {
            let mut map = self.replaces.lock().unwrap_or_else(|p| p.into_inner());
            // Keep the map from growing with every row ever written: a slot
            // whose only reference is the map's own is idle. The clone below
            // happens under this same lock, so a slot about to be handed out
            // is never seen as idle.
            if map.len() > REPLACE_LOCKS_MAX {
                map.retain(|_, slot| Arc::strong_count(slot) > 1);
            }
            map.entry(file_id)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        slot.lock_owned().await
    }

    /// On-disk location of a file's content (see the module docs for the
    /// layout). Public so the ZIP builder can stream blobs without loading
    /// whole files into memory first.
    pub fn blob_path(&self, blob: BlobRef) -> PathBuf {
        self.blob_dir.join(Self::blob_rel_path(&blob))
    }

    /// Pre-layout location of a blob, `<blob_dir>/<file-id>`. Still consulted
    /// when reading and deleting, in case the startup migration could not move
    /// a blob (see the module docs).
    pub fn legacy_blob_path(&self, file_id: i64) -> PathBuf {
        self.blob_dir.join(file_id.to_string())
    }

    /// Where a blob lives, relative to the blob dir.
    fn blob_rel_path(blob: &BlobRef) -> PathBuf {
        match blob {
            BlobRef::Entry {
                file_id,
                owner,
                created_at,
            } => {
                let (h1, h2) = Self::id_levels(*file_id);
                PathBuf::new()
                    .join(owner.dir_segment())
                    .join(created_at.format("%Y").to_string())
                    .join(h1)
                    .join(h2)
                    .join(file_id.to_string())
            }
            // One directory per file, one name per attempt: the key already
            // is time + random bytes, so no level split is needed here and
            // the path reads straight off the row (concepts/versioning.md
            // section 3).
            BlobRef::Version {
                file_id,
                version_key,
            } => PathBuf::new()
                .join("_versions")
                .join(file_id.to_string())
                .join(version_key),
        }
    }

    /// Same split for blobs whose database row is gone: `_orphans/<h1>/<h2>`,
    /// so unreachable leftovers stay out of the way but keep their id visible.
    fn orphan_rel_path(file_id: i64) -> PathBuf {
        let (h1, h2) = Self::id_levels(file_id);
        PathBuf::new()
            .join("_orphans")
            .join(h1)
            .join(h2)
            .join(file_id.to_string())
    }

    /// The two id levels: one `h1` dir per 65 536 ids, one `h2` dir (and thus
    /// one leaf holding 256 files per 2^24-id generation) per 256 ids.
    fn id_levels(file_id: i64) -> (String, String) {
        let id = file_id as u64;
        (
            format!("{:02x}", (id >> 16) & 0xff),
            format!("{:02x}", (id >> 8) & 0xff),
        )
    }

    /// Store file content for a freshly created file entry, creating the
    /// directory levels on demand.
    pub async fn write_blob(&self, entry: &FileEntry, data: Vec<u8>) -> Result<(), AppError> {
        let path = self.blob_path(BlobRef::from(entry));
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AppError::Internal(anyhow::anyhow!("creating blob dir {parent:?}: {e}"))
            })?;
        }
        tokio::fs::write(&path, data)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("writing blob {path:?}: {e}")))?;
        Ok(())
    }

    /// A fresh temp path for an incoming body (see [`FileService::commit_blob`]).
    ///
    /// The name carries the process id and random bytes, so a leftover can
    /// always be attributed to one server run and swept at startup.
    pub fn temp_path(&self) -> PathBuf {
        use rand::Rng;
        let nonce: u64 = rand::thread_rng().gen();
        self.temp_dir
            .join(format!("{}-{nonce:016x}.part", std::process::id()))
    }

    /// Open a file's content for a user who owns it or holds a READ share:
    /// the permission check first, then the handle, plus the size as the
    /// filesystem reports it - the authority for what a download actually
    /// sends, and the number every range answer is computed from.
    pub async fn open_blob(
        &self,
        user_id: i64,
        file_id: i64,
    ) -> Result<(FileEntry, tokio::fs::File, u64), AppError> {
        let entry = self
            .db
            .entry_for_read(user_id, file_id)
            .await?
            .ok_or(AppError::NotFound)?;
        if entry.is_dir {
            return Err(AppError::BadRequest("cannot download a folder".into()));
        }
        let path = self.blob_path(BlobRef::from(&entry));
        let file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            // Fall back to the flat layout for blobs the startup migration
            // left behind (see the module docs).
            Err(_) => tokio::fs::File::open(self.legacy_blob_path(file_id))
                .await
                .map_err(|_| AppError::NotFound)?,
        };
        let len = file
            .metadata()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("blob metadata {path:?}: {e}")))?
            .len();
        Ok((entry, file, len))
    }

    /// Move a fully written temp file into place as a file entry's blob.
    ///
    /// Both live under the data directory, so the commit is a rename:
    /// atomic, no second copy of the bytes, and constant memory however
    /// large the file is. On error the caller discards the temp file.
    pub async fn commit_blob(&self, entry: &FileEntry, temp: &Path) -> Result<(), AppError> {
        let path = self.blob_path(BlobRef::from(entry));
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AppError::Internal(anyhow::anyhow!("creating blob dir {parent:?}: {e}"))
            })?;
        }
        tokio::fs::rename(temp, &path)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("committing blob {path:?}: {e}")))
    }

    /// On-disk location of one kept version's bytes: `_versions/<file_id>/`
    /// under the blob dir (see [`BlobRef::Version`]).
    pub fn version_path(&self, file_id: i64, key: &str) -> PathBuf {
        self.blob_path(BlobRef::Version {
            file_id,
            version_key: key.to_string(),
        })
    }

    /// A fresh on-disk key for a version blob: microseconds + random bytes.
    ///
    /// The concept orders the link *before* its row (a crash then costs an
    /// orphan file, never a row pointing at nothing), so the name has to be
    /// unique by construction - time alone is too close together for two
    /// saves under the same lock, and a lookup cannot exist yet.
    pub fn fresh_version_key() -> String {
        use rand::Rng;
        let nonce: u64 = rand::thread_rng().gen();
        format!("{}-{:016x}", Utc::now().timestamp_micros(), nonce)
    }

    /// Give an entry's outgoing content its version name: a hardlink, so the
    /// same inode lives on under a second name and the rename that publishes
    /// the new content cannot make the old bytes disappear. Metadata-only -
    /// no copy, constant memory for any file size.
    ///
    /// Runs under the row's write lock, before the version row exists (see
    /// [`FileService::fresh_version_key`]).
    ///
    /// `Ok(false)` means there was nothing to pin: the blob is not on disk
    /// either (a row whose bytes are already gone), and a version row
    /// pointing at a link that was never made must not be written - the save
    /// continues without a history step.
    pub async fn pin_version(&self, entry: &FileEntry, key: &str) -> Result<bool, AppError> {
        let src = self.blob_path(BlobRef::from(entry));
        let dst = self.version_path(entry.id, key);
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AppError::Internal(anyhow::anyhow!("creating version dir {parent:?}: {e}"))
            })?;
        }
        match tokio::fs::hard_link(&src, &dst).await {
            Ok(()) => Ok(true),
            // Fall back to the flat layout, like every other read of an entry
            // blob does (see the module docs).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match tokio::fs::hard_link(self.legacy_blob_path(entry.id), &dst).await {
                    Ok(()) => Ok(true),
                    Err(le) if le.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(e) => Err(AppError::Internal(anyhow::anyhow!(
                        "pinning version of file {}: {e}",
                        entry.id
                    ))),
                }
            }
            Err(e) => Err(AppError::Internal(anyhow::anyhow!(
                "pinning version of file {}: {e}",
                entry.id
            ))),
        }
    }

    /// The history step of a content replacement, in the concept's order
    /// (concepts/versioning.md section 4): name the outgoing blob, then
    /// write its row - retention runs inside the insert - then unlink what
    /// retention dropped. Held under the caller's row write lock, with the
    /// UPDATE grant already checked.
    ///
    /// `Ok(false)` means the entry had no outgoing bytes (an empty file's
    /// first fill, for instance): nothing to pin, no row written.
    pub async fn pin_content_as_version(
        &self,
        acting_user: i64,
        entry: &FileEntry,
    ) -> Result<bool, AppError> {
        if entry.size <= 0 {
            return Ok(false);
        }
        let key = Self::fresh_version_key();
        if !self.pin_version(entry, &key).await? {
            return Ok(false);
        }
        let pruned = self
            .db
            .insert_version(acting_user, entry.id, entry.size, entry.enc_version, key)
            .await?;
        self.delete_blobs(&pruned).await;
        Ok(true)
    }

    /// Copy a readable file's bytes to another entry's blob (WebDAV `COPY`
    /// and the API's copy route): the same permission check as every read,
    /// then a filesystem-level copy - 64 KiB on the kernel's side, never the
    /// whole file in memory.
    pub async fn copy_blob(
        &self,
        user_id: i64,
        src_id: i64,
        dst: &FileEntry,
    ) -> Result<(), AppError> {
        let src_entry = self
            .db
            .entry_for_read(user_id, src_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let src = self.blob_path(BlobRef::from(&src_entry));
        let dst_path = self.blob_path(BlobRef::from(dst));
        if let Some(parent) = dst_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AppError::Internal(anyhow::anyhow!("creating blob dir {parent:?}: {e}"))
            })?;
        }
        match tokio::fs::copy(&src, &dst_path).await {
            Ok(_) => Ok(()),
            // Fall back to the flat layout for blobs the startup migration
            // left behind (see the module docs).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tokio::fs::copy(self.legacy_blob_path(src_id), &dst_path)
                    .await
                    .map(|_| ())
                    .map_err(|_| AppError::NotFound)
            }
            Err(e) => Err(AppError::Internal(anyhow::anyhow!(
                "copying blob {src:?} -> {dst_path:?}: {e}"
            ))),
        }
    }

    /// Hard-link a blob to its relocation target: the link a move between
    /// principals lays down *before* the row updates - link, row, unlink,
    /// the same order the version exchange uses, so a crash at any instant
    /// leaves the content reachable under some path.
    pub async fn link_blob(&self, from: &BlobRef, to: &BlobRef) -> Result<(), AppError> {
        let src = self.blob_path(from.clone());
        let dst = self.blob_path(to.clone());
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AppError::Internal(anyhow::anyhow!("creating blob dir {parent:?}: {e}"))
            })?;
        }
        match tokio::fs::hard_link(&src, &dst).await {
            Ok(()) => Ok(()),
            // Flat layout fallback for blobs the startup migration could
            // not move yet (see the module docs).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let BlobRef::Entry { file_id, .. } = from {
                    tokio::fs::hard_link(self.legacy_blob_path(*file_id), &dst)
                        .await
                        .map(|_| ())
                        .map_err(|e| {
                            AppError::Internal(anyhow::anyhow!(
                                "relocating flat blob {file_id} -> {dst:?}: {e}"
                            ))
                        })
                } else {
                    Err(AppError::Internal(anyhow::anyhow!(
                        "relocating blob {src:?} -> {dst:?}: {e}"
                    )))
                }
            }
            Err(e) => Err(AppError::Internal(anyhow::anyhow!(
                "relocating blob {src:?} -> {dst:?}: {e}"
            ))),
        }
    }

    /// Move an entry to another parent and name - and, when the attribution
    /// changes with it, between blob namespaces. Sequences the crash-safe
    /// order around [`Db::prepare_move`] / [`Db::apply_move`]: plan
    /// (permissions, cycle, destination quota, group boundaries), link the
    /// new blob path, apply the rows, drop the old name. The final unlink is
    /// best effort - a lingering hardlink keeps the content readable and
    /// only leaks an extra name for one inode.
    ///
    /// `guard_key_domains` selects the key-blind door (WebDAV `true`, the
    /// JSON routes `false` - see [`Db::prepare_move`]).
    pub async fn move_entry(
        &self,
        user_id: i64,
        id: i64,
        new_parent: Option<i64>,
        new_name: String,
        guard_key_domains: bool,
    ) -> Result<FileEntry, AppError> {
        let plan = self
            .db
            .prepare_move(user_id, id, new_parent, new_name, guard_key_domains)
            .await?;
        let relocation = plan
            .relocation()
            .map(|(old, new)| (old.clone(), new.clone()));
        if let Some((old, new)) = &relocation {
            self.link_blob(old, new).await?;
        }
        let moved = match self.db.apply_move(plan).await {
            Ok(entry) => entry,
            Err(e) => {
                // The rows never moved: take the fresh link away again
                // (best effort - a leftover link keeps content readable).
                if let Some((_, new)) = &relocation {
                    self.delete_blobs(&[new.clone()]).await;
                }
                return Err(e);
            }
        };
        if let Some((old, _)) = relocation {
            self.delete_blobs(&[old]).await;
        }
        Ok(moved)
    }

    /// Exchange a version in (concepts/versioning.md section 4): the chosen
    /// version's bytes become the entry's content, the outgoing content
    /// becomes a new version. Every step is a hardlink or a rename, so
    /// neither direction copies a byte and the swap stays flat in memory for
    /// any file size - the same trade the replace flow takes (section 4).
    ///
    /// Order: the UPDATE grant first, before any filesystem work (permissions
    /// are not something to discover halfway through an exchange), then the
    /// outgoing content is named - link, then row - then the chosen bytes are
    /// renamed onto the entry, then the rows catch up. A crash at any point
    /// leaves an orphan file or a briefly duplicated readable row, never an
    /// unreadable entry. Retention runs with the outgoing row's insert.
    pub async fn restore_version(
        &self,
        acting_user: i64,
        file_id: i64,
        vid: i64,
    ) -> Result<(), AppError> {
        self.db.require_update(acting_user, file_id).await?;
        let _lock = self.begin_replace(file_id).await;
        let entry = self
            .db
            .entry_for_read(acting_user, file_id)
            .await?
            .ok_or(AppError::NotFound)?;
        if entry.is_dir {
            return Err(AppError::BadRequest("cannot restore a folder".into()));
        }
        let chosen = self.db.version_for_read(acting_user, file_id, vid).await?;

        // 1 + 2: the outgoing content becomes the newest version. An entry
        // with no outgoing bytes (still empty) restores without one - there
        // was nothing to keep.
        self.pin_content_as_version(acting_user, &entry).await?;
        // 3: the chosen inode takes the entry's name - linked to a temp name
        // first, so a failure here never leaves the entry half-renamed.
        let src = self.version_path(file_id, &chosen.blob_key);
        let temp = self.temp_path();
        if let Err(e) = tokio::fs::hard_link(&src, &temp).await {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(AppError::Internal(anyhow::anyhow!(
                "linking version {vid} of file {file_id}: {e}"
            )));
        }
        let entry_path = self.blob_path(BlobRef::from(&entry));
        if let Err(e) = tokio::fs::rename(&temp, &entry_path).await {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(AppError::Internal(anyhow::anyhow!(
                "publishing restored version {vid}: {e}"
            )));
        }
        // 4: the row follows its bytes (size, enc_version, modified_at; the
        // chosen row is dropped - the entry holds its inode now), then the
        // redundant version name goes. Only the name can disappear: unlink
        // after the row, so a crash in between leaves an orphan file rather
        // than a row pointing at nothing.
        self.db.finish_restore(acting_user, file_id, vid).await?;
        let _ = tokio::fs::remove_file(&src).await;
        Ok(())
    }

    /// Remove temp files interrupted uploads left behind: a restart kills
    /// every in-flight request, so anything still sitting in the temp
    /// directory is garbage with no owner. Called at startup next to the
    /// flat-blob migration (`main.rs`).
    pub async fn sweep_temps(&self) {
        if let Err(e) = tokio::fs::create_dir_all(&self.temp_dir).await {
            tracing::warn!(
                error = %e,
                dir = %self.temp_dir.display(),
                "cannot create upload temp dir"
            );
            return;
        }
        let mut entries = match tokio::fs::read_dir(&self.temp_dir).await {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    dir = %self.temp_dir.display(),
                    "cannot scan upload temp dir"
                );
                return;
            }
        };
        let mut swept = 0usize;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let is_temp = path.is_file() && path.extension().is_some_and(|ext| ext == "part");
            if !is_temp {
                continue;
            }
            match tokio::fs::remove_file(&path).await {
                Ok(()) => swept += 1,
                Err(e) => tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "cannot remove stale temp file"
                ),
            }
        }
        if swept > 0 {
            tracing::info!(count = swept, "stale upload temp files removed");
        }
    }

    /// Delete blobs for removed file entries (best-effort: also tries the flat
    /// layout a blob may not have been migrated out of yet).
    ///
    /// Version blobs have no flat layout and no second chance: they only ever
    /// lived in `_versions/`, so they get their path and nothing else.
    pub async fn delete_blobs(&self, blobs: &[BlobRef]) {
        for blob in blobs {
            let _ = tokio::fs::remove_file(self.blob_path(blob.clone())).await;
            if let BlobRef::Entry { file_id, .. } = blob {
                let _ = tokio::fs::remove_file(self.legacy_blob_path(*file_id)).await;
            }
        }
    }

    /// Move blobs out of the legacy flat layout into the owner/year/id
    /// structure (see the module docs).
    ///
    /// Idempotent: only files sitting directly in the blob root are considered,
    /// so a second run finds nothing to do. Nothing is ever deleted — a blob
    /// whose database row is gone ends up in `_orphans/` and is logged.
    pub async fn migrate_flat_blobs(&self) {
        let origins = match self.db.blob_origins().await {
            Ok(origins) => origins,
            Err(e) => {
                tracing::error!(error = %e, "blob migration: cannot read file metadata");
                return;
            }
        };
        let blob_dir = self.blob_dir.clone();
        let run = tokio::task::spawn_blocking(move || Self::move_flat_blobs(&blob_dir, &origins));
        match run.await {
            Ok(stats) if stats.is_empty() => {}
            Ok(stats) => {
                if stats.moved > 0 || stats.failed > 0 {
                    tracing::info!(
                        moved = stats.moved,
                        orphans = stats.orphans,
                        failed = stats.failed,
                        "legacy flat blobs moved to <owner>/<year>/<h1>/<h2>"
                    );
                }
                if stats.orphans > 0 {
                    tracing::warn!(
                        count = stats.orphans,
                        "blobs without a database row moved to _orphans/"
                    );
                }
                if stats.failed > 0 {
                    tracing::warn!(
                        count = stats.failed,
                        "blobs could not be moved; reads fall back to the flat path"
                    );
                }
                if stats.leftover > 0 {
                    tracing::warn!(
                        count = stats.leftover,
                        "non-id files in the blob root left in place"
                    );
                }
            }
            Err(e) => tracing::error!(error = %e, "blob migration task failed"),
        }
    }

    /// One synchronous migration pass over the blob root (runs on the blocking
    /// pool, see [`FileService::migrate_flat_blobs`]).
    fn move_flat_blobs(blob_dir: &Path, origins: &HashMap<i64, BlobRef>) -> MoveStats {
        let mut stats = MoveStats::default();
        let entries = match std::fs::read_dir(blob_dir) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(error = %e, path = %blob_dir.display(), "cannot scan blob root");
                return stats;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Owner and `_orphans` directories, or blobs that are already
            // migrated, are left alone.
            if !path.is_file() {
                continue;
            }
            let Some(id) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.parse::<i64>().ok())
            else {
                stats.leftover += 1;
                continue;
            };
            let (rel, orphans) = match origins.get(&id) {
                Some(blob) => (Self::blob_rel_path(blob), false),
                None => (Self::orphan_rel_path(id), true),
            };
            let dst = blob_dir.join(rel);
            if let Some(parent) = dst.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    tracing::warn!(error = %e, dir = %parent.display(), "cannot create blob dir");
                    stats.failed += 1;
                    continue;
                }
            }
            match std::fs::rename(&path, &dst) {
                Ok(()) if orphans => stats.orphans += 1,
                Ok(()) => stats.moved += 1,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        from = %path.display(),
                        to = %dst.display(),
                        "cannot move legacy blob"
                    );
                    stats.failed += 1;
                }
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::{is_specific_text, looks_like_text, resolve_mime};

    /// A real 1x1 PNG: the signature alone is what the magic table matches.
    const PNG: &[u8] =
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89";

    #[test]
    fn magic_bytes_win_over_the_client_word() {
        // Content is not naming: a renamed upload keeps the type its bytes say.
        assert_eq!(resolve_mime(None, PNG).as_deref(), Some("image/png"));
        assert_eq!(
            resolve_mime(Some("application/octet-stream"), PNG).as_deref(),
            Some("image/png")
        );
        assert_eq!(
            resolve_mime(Some("text/plain"), PNG).as_deref(),
            Some("image/png")
        );
    }

    #[test]
    fn utf8_text_is_text_plain() {
        // German text with umlauts: high bytes, still text.
        let note = b"Gr\xc3\xbc\xc3\x9fe\nZeile zwei, mit Umlauten: \xc3\xa4\xc3\xb6\xc3\xbc\n";
        assert_eq!(resolve_mime(None, note).as_deref(), Some("text/plain"));
    }

    #[test]
    fn legacy_single_byte_text_is_still_text() {
        // Latin-1/cp1252: not valid UTF-8, but no controls beyond whitespace.
        let old = b"Gr\xfc\xdfe\nalte Notiz mit Umlauten: \xe4\xf6\xfc\n";
        assert!(looks_like_text(old));
        assert_eq!(resolve_mime(None, old).as_deref(), Some("text/plain"));
    }

    #[test]
    fn nul_bytes_end_the_text_guess() {
        let mut binary = b"some prefix".to_vec();
        binary.push(0);
        binary.extend_from_slice(b"\x01\x02\x03");
        assert!(!looks_like_text(&binary));
        assert_eq!(resolve_mime(None, &binary), None);
    }

    #[test]
    fn unknown_binary_keeps_a_real_declaration_only() {
        let binary = b"\x01\x02\x03\x04\x05\x06\x07";
        assert_eq!(
            resolve_mime(Some("application/x-custom"), binary).as_deref(),
            Some("application/x-custom")
        );
        // The octet-stream placeholder every extensionless upload carries is
        // not an answer, and neither is an empty string.
        assert_eq!(resolve_mime(Some("application/octet-stream"), binary), None);
        assert_eq!(resolve_mime(Some(""), binary), None);
        assert_eq!(resolve_mime(None, binary), None);
    }

    #[test]
    fn a_specific_declared_text_type_survives() {
        // text/markdown says more than the heuristic's text/plain.
        assert_eq!(
            resolve_mime(Some("text/markdown"), "# titel\n".as_bytes()).as_deref(),
            Some("text/markdown")
        );
        assert_eq!(
            resolve_mime(Some("application/json"), b"{\"a\":1}\n").as_deref(),
            Some("application/json")
        );
        // The flat text/plain and the octet-stream placeholder do not.
        assert_eq!(
            resolve_mime(Some("text/plain"), "# titel\n".as_bytes()).as_deref(),
            Some("text/plain")
        );
        assert_eq!(
            resolve_mime(Some("application/octet-stream"), "# titel\n".as_bytes()).as_deref(),
            Some("text/plain")
        );
    }

    #[test]
    fn is_specific_text_draws_the_line_where_it_says() {
        assert!(is_specific_text("text/markdown"));
        assert!(is_specific_text("text/csv"));
        assert!(is_specific_text("application/json"));
        assert!(is_specific_text("application/ld+json"));
        assert!(is_specific_text("image/svg+xml"));
        assert!(!is_specific_text("text/plain"));
        assert!(!is_specific_text("application/octet-stream"));
        assert!(!is_specific_text("image/png"));
    }

    #[test]
    fn an_empty_file_is_an_empty_note() {
        // Nothing to contradict the guess: an empty upload opens as text.
        assert_eq!(resolve_mime(None, b"").as_deref(), Some("text/plain"));
    }

    #[test]
    fn utf16_stays_untyped() {
        // UTF-16 text is full of NUL bytes: the editor reads UTF-8, so the
        // server must not promise a decode the browser cannot keep.
        let utf16: &[u8] = b"H\0e\0l\0l\0o\0";
        assert!(!looks_like_text(utf16));
        assert_eq!(resolve_mime(None, utf16), None);
    }
}
