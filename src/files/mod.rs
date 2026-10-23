use std::path::PathBuf;

use crate::config::Config;
use crate::db::Db;
use crate::error::AppError;
use crate::models::FileEntry;

/// High-level file operations combining DB metadata with on-disk blobs.
///
/// Blob layout: each file's content is stored at `<blob_dir>/<file_id>`, keyed
/// by the database row id. This keeps naming trivially unique and immune to
/// path-traversal, since ids are integers we control.
pub struct FileService {
    db: Db,
    blob_dir: PathBuf,
}

impl FileService {
    pub fn new(db: Db, config: &Config) -> Self {
        Self {
            db,
            blob_dir: config.blob_dir(),
        }
    }

    /// On-disk location of a file's content (see the module docs for why the
    /// id is used as the name). Public so the ZIP builder can stream blobs
    /// without loading whole files into memory first.
    pub fn blob_path(&self, file_id: i64) -> PathBuf {
        self.blob_dir.join(file_id.to_string())
    }

    /// Store file content for a freshly created file entry.
    pub async fn write_blob(&self, file_id: i64, data: Vec<u8>) -> Result<(), AppError> {
        let path = self.blob_path(file_id);
        tokio::fs::write(&path, data)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("writing blob {path:?}: {e}")))?;
        Ok(())
    }

    /// Read a file's content for a user who owns it or holds a READ share.
    pub async fn read_blob(&self, user_id: i64, file_id: i64) -> Result<(FileEntry, Vec<u8>), AppError> {
        let entry = self
            .db
            .entry_for_read(user_id, file_id)
            .await?
            .ok_or(AppError::NotFound)?;
        if entry.is_dir {
            return Err(AppError::BadRequest("cannot download a folder".into()));
        }
        let path = self.blob_path(file_id);
        let data = tokio::fs::read(&path)
            .await
            .map_err(|_| AppError::NotFound)?;
        Ok((entry, data))
    }

    /// Delete blobs for removed file entries (best-effort).
    pub async fn delete_blobs(&self, file_ids: &[i64]) {
        for id in file_ids {
            let path = self.blob_path(*id);
            let _ = tokio::fs::remove_file(&path).await;
        }
    }
}
