pub mod file;
pub mod keys;
pub mod passkey;
pub mod session;
pub mod share;
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

    /// Apply any pending schema migrations, in order.
    ///
    /// Migrations are re-run on every startup, so each one must be idempotent
    /// (`IF NOT EXISTS` / guarded DDL). A statement that cannot be written
    /// idempotently in SQLite — `ALTER TABLE ADD COLUMN` has no `IF NOT
    /// EXISTS` — therefore ships a guard query: when it returns a non-zero
    /// count the migration has already been applied and is skipped.
    fn migrate(&self) -> anyhow::Result<()> {
        const MIGRATIONS: &[(&str, &str, Option<&str>)] = &[
            (
                "001_init",
                include_str!("../../migrations/001_init.sql"),
                None,
            ),
            (
                "002_shares",
                include_str!("../../migrations/002_shares.sql"),
                None,
            ),
            (
                "003_user_active",
                include_str!("../../migrations/003_user_active.sql"),
                // Skip once `users.is_active` exists.
                Some(
                    "SELECT COUNT(*) FROM pragma_table_info('users')
                     WHERE name = 'is_active'",
                ),
            ),
            (
                "004_user_quota",
                include_str!("../../migrations/004_user_quota.sql"),
                // Skip once `users.quota_bytes` exists.
                Some(
                    "SELECT COUNT(*) FROM pragma_table_info('users')
                     WHERE name = 'quota_bytes'",
                ),
            ),
            (
                "005_trash",
                include_str!("../../migrations/005_trash.sql"),
                // Skip once `files.deleted_at` exists.
                Some(
                    "SELECT COUNT(*) FROM pragma_table_info('files')
                     WHERE name = 'deleted_at'",
                ),
            ),
            (
                "006_keys",
                include_str!("../../migrations/006_keys.sql"),
                // Skip once `files.enc_version` exists.
                Some(
                    "SELECT COUNT(*) FROM pragma_table_info('files')
                     WHERE name = 'enc_version'",
                ),
            ),
            (
                "007_enc_key",
                include_str!("../../migrations/007_enc_key.sql"),
                // Skip once `files.enc_key` exists.
                Some(
                    "SELECT COUNT(*) FROM pragma_table_info('files')
                     WHERE name = 'enc_key'",
                ),
            ),
            (
                "008_share_envelopes",
                include_str!("../../migrations/008_share_envelopes.sql"),
                // Skip once `shares.envelope` exists.
                Some(
                    "SELECT COUNT(*) FROM pragma_table_info('shares')
                     WHERE name = 'envelope'",
                ),
            ),
            (
                "009_user_theme",
                include_str!("../../migrations/009_user_theme.sql"),
                // Skip once `users.theme` exists.
                Some(
                    "SELECT COUNT(*) FROM pragma_table_info('users')
                     WHERE name = 'theme'",
                ),
            ),
            (
                "010_user_admin",
                include_str!("../../migrations/010_user_admin.sql"),
                // Skip once `users.is_admin` exists.
                Some(
                    "SELECT COUNT(*) FROM pragma_table_info('users')
                     WHERE name = 'is_admin'",
                ),
            ),
            // 011 stays open: that number belonged to the withdrawn
            // passphrase-login round (reverted in f9aa1d9). The table below
            // needs no guard - `CREATE TABLE/INDEX IF NOT EXISTS` is
            // idempotent on every startup.
            (
                "012_webauthn_credentials",
                include_str!("../../migrations/012_webauthn_credentials.sql"),
                None,
            ),
            (
                "013_sessions_meta",
                include_str!("../../migrations/013_sessions_meta.sql"),
                // Skip once `sessions.sid` exists.
                Some(
                    "SELECT COUNT(*) FROM pragma_table_info('sessions')
                     WHERE name = 'sid'",
                ),
            ),
        ];
        let conn = self.pool.get()?;
        for (name, sql, guard) in MIGRATIONS {
            if let Some(guard) = guard {
                let applied: i64 = conn.query_row(guard, [], |r| r.get(0))?;
                if applied > 0 {
                    continue;
                }
            }
            conn.execute_batch(sql)
                .map_err(|e| anyhow::anyhow!("migration {name} failed: {e}"))?;
        }
        Ok(())
    }
}
