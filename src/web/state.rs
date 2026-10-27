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

/// How long a WebAuthn challenge stays redeemable. Matches the `timeout`
/// sent with the ceremony options.
const CEREMONY_TTL_MINUTES: i64 = 5;

/// What a pending WebAuthn ceremony may be redeemed for. The kind is
/// re-checked at redemption, so a registration challenge cannot open a
/// session and a login challenge cannot register a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyKind {
    Register,
    Login,
}

/// One pending WebAuthn ceremony: the issued challenge plus what it was
/// issued for.
///
/// Keyed by challenge and single-use - redemption removes the entry, and
/// expired entries are dropped on the next insert, exactly like
/// [`ZipJob`]. Kept in memory only: a restart clearing half-finished
/// ceremonies just means the user opens the dialog again.
pub struct Ceremony {
    /// Copy of the map key so verification can compare against the stored
    /// challenge without threading the key through separately.
    pub challenge: String,
    /// Register: the session's user. Login: the targeted account - `None`
    /// when no account of that name exists (the response must look
    /// identical either way).
    pub user_id: Option<i64>,
    pub kind: CeremonyKind,
    pub expires_at: DateTime<Utc>,
}

/// Shared application state available to every handler.
pub struct AppState {
    pub db: Db,
    pub files: FileService,
    pub config: Config,
    /// Short-lived, single-use ZIP download tokens (see [`ZipJob`]).
    zip_jobs: Mutex<HashMap<String, ZipJob>>,
    /// Pending WebAuthn challenges (see [`Ceremony`]), keyed by challenge.
    ceremonies: Mutex<HashMap<String, Ceremony>>,
}

impl AppState {
    pub fn new(db: Db, config: Config) -> Self {
        let files = FileService::new(db.clone(), &config);
        Self {
            db,
            files,
            config,
            zip_jobs: Mutex::new(HashMap::new()),
            ceremonies: Mutex::new(HashMap::new()),
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

    /// Issue a fresh WebAuthn challenge bound to `kind` and `user_id`.
    ///
    /// Housekeeping mirrors [`Self::new_zip_job`]: expired ceremonies are
    /// dropped on every call, so the map only ever holds the last five
    /// minutes' worth.
    pub fn new_ceremony(&self, kind: CeremonyKind, user_id: Option<i64>) -> String {
        let mut map = self.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
        let now = Utc::now();
        map.retain(|_, c| c.expires_at > now);

        let challenge = crate::webauthn::new_challenge();
        map.insert(
            challenge.clone(),
            Ceremony {
                challenge: challenge.clone(),
                user_id,
                kind,
                expires_at: now + Duration::minutes(CEREMONY_TTL_MINUTES),
            },
        );
        challenge
    }

    /// Redeem a challenge for `kind`: always removed, returned only when it
    /// exists, is of that kind and has not expired - single-use even for a
    /// wrong kind or an expired attempt, like [`Self::take_zip_job`].
    pub fn take_ceremony(&self, challenge: &str, kind: CeremonyKind) -> Option<Ceremony> {
        let mut map = self.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
        let found = map.remove(challenge)?;
        (found.kind == kind && found.expires_at > Utc::now()).then_some(found)
    }
}

pub type SharedState = Arc<AppState>;
