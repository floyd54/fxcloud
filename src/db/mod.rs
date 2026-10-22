pub mod file;
pub mod session;
pub mod user;

use std::path::Path;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

use crate::error::AppError;

pub type DbPool = Pool<SqliteConnectionManager>;

/// A thin, async-friendly wrapper around an SQLite connection pool.
///
/// SQLite calls are blocking, so every operation is transparently moved onto
/// the blocking thread pool via [`tokio::task::spawn_blocking`]. Handlers can
/// therefore `await` database methods directly without stalling the runtime.
#[derive(Clone)]
pub struct Db {
    pool: DbPool,
}

impl Db {
    /// Open (and migrate) the database at `path`, returning a pooled handle.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let manager = SqliteConnectionManager::file(path).with_init(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = NORMAL;",
            )
        });
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| anyhow::anyhow!("failed to build db pool: {e}"))?;

        let db = Self { pool };
        db.migrate()?;
        Ok(db)
    }

    /// Run a blocking closure with a pooled connection, off the async runtime.
    async fn run<T, F>(&self, f: F) -> Result<T, AppError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, AppError> + Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            f(&mut conn)
        })
        .await
        .map_err(|_| AppError::Join)?
    }

    /// Apply any pending schema migrations.
    fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.pool.get()?;
        conn.execute_batch(include_str!("../../migrations/001_init.sql"))
            .map_err(|e| anyhow::anyhow!("migration failed: {e}"))?;
        Ok(())
    }
}
