use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
/// (`h1` covers 65 536 ids, `h2` covers 256) so no leaf directory ever holds
/// more than 256 blobs and no directory grows without bound. The leaf keeps
/// the plain decimal id as its file name, which is unique by construction and
/// immune to path-traversal, and the whole path stays recomputable from a row
/// without extra state.
///
/// Blobs written before this layout existed live flat in `<blob_dir>/<id>`.
/// [`FileService::migrate_flat_blobs`] moves them into place at startup; reads
/// and deletes additionally fall back to the flat path, so a blob whose move
/// failed never goes missing.
pub struct FileService {
    db: Db,
    blob_dir: PathBuf,
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
        self.blob_dir.join(Self::blob_rel_path(blob))
    }

    /// Pre-layout location of a blob, `<blob_dir>/<file-id>`. Still consulted
    /// when reading and deleting, in case the startup migration could not move
    /// a blob (see the module docs).
    pub fn legacy_blob_path(&self, file_id: i64) -> PathBuf {
        self.blob_dir.join(file_id.to_string())
    }

    /// Where a blob lives, relative to the blob dir.
    fn blob_rel_path(blob: BlobRef) -> PathBuf {
        let (h1, h2) = Self::id_levels(blob.file_id);
        PathBuf::new()
            .join(blob.owner_id.to_string())
            .join(blob.created_at.format("%Y").to_string())
            .join(h1)
            .join(h2)
            .join(blob.file_id.to_string())
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
    /// one leaf holding at most 256 files) per 256 ids.
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

    /// Read a file's content for a user who owns it or holds a READ share.
    pub async fn read_blob(
        &self,
        user_id: i64,
        file_id: i64,
    ) -> Result<(FileEntry, Vec<u8>), AppError> {
        let entry = self
            .db
            .entry_for_read(user_id, file_id)
            .await?
            .ok_or(AppError::NotFound)?;
        if entry.is_dir {
            return Err(AppError::BadRequest("cannot download a folder".into()));
        }
        let path = self.blob_path(BlobRef::from(&entry));
        let data = match tokio::fs::read(&path).await {
            Ok(data) => data,
            // Fall back to the flat layout for blobs the startup migration
            // left behind (see the module docs).
            Err(_) => tokio::fs::read(self.legacy_blob_path(file_id))
                .await
                .map_err(|_| AppError::NotFound)?,
        };
        Ok((entry, data))
    }

    /// Delete blobs for removed file entries (best-effort: also tries the flat
    /// layout a blob may not have been migrated out of yet).
    pub async fn delete_blobs(&self, blobs: &[BlobRef]) {
        for blob in blobs {
            let _ = tokio::fs::remove_file(self.blob_path(*blob)).await;
            let _ = tokio::fs::remove_file(self.legacy_blob_path(blob.file_id)).await;
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
                Some(blob) => (Self::blob_rel_path(*blob), false),
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
