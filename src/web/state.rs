use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};

use crate::config::Config;
use crate::db::Db;
use crate::files::FileService;

/// How long a prepared ZIP download may take before its token expires.
const ZIP_JOB_TTL_MINUTES: i64 = 5;

/// A prepared ZIP download: who asked for which ids, and until when.
///
/// Tokens are handed out by `POST /api/files/zip` and redeemed once by
/// `GET /api/files/zip?token=…`. Keeping them in memory (instead of in the
/// URL) means the download URL stays short no matter how many items are
/// selected, and a token is useless to anyone but the session that created it.
pub struct ZipJob {
    pub user_id: i64,
    pub ids: Vec<i64>,
    pub expires_at: DateTime<Utc>,
}

/// Shared application state available to every handler.
pub struct AppState {
    pub db: Db,
    pub files: FileService,
    pub config: Config,
    /// Short-lived, single-use ZIP download tokens (see [`ZipJob`]).
    zip_jobs: Mutex<HashMap<String, ZipJob>>,
}

impl AppState {
    pub fn new(db: Db, config: Config) -> Self {
        let files = FileService::new(db.clone(), &config);
        Self {
            db,
            files,
            config,
            zip_jobs: Mutex::new(HashMap::new()),
        }
    }

    /// Register a ZIP download and return its single-use token.
    ///
    /// Expired jobs are dropped on every call, so the map only ever holds the
    /// few tokens of the last five minutes.
    pub fn new_zip_job(&self, user_id: i64, ids: Vec<i64>) -> String {
        use crate::db::session::generate_token;

        let mut jobs = self.zip_jobs.lock().unwrap_or_else(|p| p.into_inner());
        let now = Utc::now();
        jobs.retain(|_, job| job.expires_at > now);

        let token = generate_token();
        jobs.insert(
            token.clone(),
            ZipJob {
                user_id,
                ids,
                expires_at: now + Duration::minutes(ZIP_JOB_TTL_MINUTES),
            },
        );
        token
    }

    /// Consume a ZIP job.
    ///
    /// Returns `None` when the token is unknown, expired, or was prepared by a
    /// different user — the job is always removed, even on a failed attempt.
    pub fn take_zip_job(&self, token: &str, user_id: i64) -> Option<ZipJob> {
        let mut jobs = self.zip_jobs.lock().unwrap_or_else(|p| p.into_inner());
        let job = jobs.remove(token)?;
        (job.user_id == user_id && job.expires_at > Utc::now()).then_some(job)
    }
}

pub type SharedState = Arc<AppState>;
