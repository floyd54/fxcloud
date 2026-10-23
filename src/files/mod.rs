use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::db::Db;
use crate::error::AppError;
use crate::models::{BlobRef, FileEntry};

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
}

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
        }
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
