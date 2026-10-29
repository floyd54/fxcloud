use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};

use crate::config::Config;
use crate::db::Db;
use crate::error::AppError;
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

// ---- authentication attempt accounting (Audit.md F1) ----

/// Consecutive failed sign-ins an account may record before backoff starts.
const AUTH_LOCK_AFTER: u32 = 5;

/// First backoff window in seconds; every further failure doubles it until
/// [`AUTH_LOCK_MAX_SECS`] takes over.
const AUTH_LOCK_BASE_SECS: i64 = 10;
const AUTH_LOCK_MAX_SECS: i64 = 300;

/// How long an account's failure count is remembered after its lock has
/// lapsed - the memory that makes the *next* lock longer than the last.
const AUTH_LOCK_MEMORY_SECS: i64 = 3600;

/// Failed password sign-ins one source address may spend per window, and
/// the window itself. The key is the socket peer: a reverse proxy
/// collapses every client into one address, so this budget is set where a
/// busy morning never reaches it and only a flood does - the per-account
/// backoff stays the precise instrument behind a proxy. `X-Forwarded-For`
/// is never trusted: a bare install would be one spoofed header away from
/// a limiter that both misses the attacker and can be aimed at others.
const LOGIN_FAIL_BUDGET: u32 = 30;
const LOGIN_FAIL_WINDOW_SECS: i64 = 60;

/// Registration attempts per source address per window. Every attempt
/// hashes a password whether or not the name is free, so this door spends
/// its budget up front - and a personal cloud registers a handful of
/// accounts in its whole life, never ten in ten minutes.
const REGISTER_BUDGET: u32 = 10;
const REGISTER_WINDOW_SECS: i64 = 600;

/// Pending WebAuthn challenges before the start endpoints answer 429
/// instead of growing the map. Generous for any real household, a hard
/// line for ceremony spam: the map was pruned but never capped (F1).
const MAX_CEREMONIES: usize = 256;

/// Account failure entries and per-source windows held at once. Every use
/// prunes what its window has dropped, so the caps are only a line
/// against a flood of invented names or addresses between prunes; the
/// oldest entry falls out first.
const MAX_AUTH_ACCOUNTS: usize = 4096;
const MAX_AUTH_SOURCES: usize = 4096;

/// One account's failed sign-in bookkeeping (F1): counts failures into a
/// backoff window, then remembers the count after the window lapses so
/// the next lock is longer than the last. Keyed by the name itself, an
/// invented one exactly like a real one - which is what keeps a refusal
/// from telling an attacker who has an account.
struct AccountLock {
    failures: u32,
    last_failure: DateTime<Utc>,
    locked_until: Option<DateTime<Utc>>,
}

/// One source address's spend inside its current window (F1). The window
/// starts with the first spend and never slides, so a steady trickle is
/// bounded at the budget's own rate.
struct SourceSpend {
    window_start: DateTime<Utc>,
    spent: u32,
}

/// In-memory attempt accounting for the authentication endpoints (F1).
///
/// Memory only, pruned on every use - a restart forgives counters the way
/// it forgives ceremonies, and both are bounded by the caps above rather
/// than by hoping traffic stays small.
struct AuthLimiter {
    accounts: HashMap<String, AccountLock>,
    login_fails: HashMap<String, SourceSpend>,
    registers: HashMap<String, SourceSpend>,
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
    /// Failed sign-ins, per-source spends and challenge caps (F1).
    auth: Mutex<AuthLimiter>,
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
            auth: Mutex::new(AuthLimiter {
                accounts: HashMap::new(),
                login_fails: HashMap::new(),
                registers: HashMap::new(),
            }),
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
    /// minutes' worth - and when that is *still* full, the challenge the
    /// caller asked for is refused with 429 rather than letting ceremony
    /// spam grow the map without bound (F1). Slots free as challenges are
    /// redeemed or expire; five seconds is the retry hint, not a promise.
    pub fn new_ceremony(
        &self,
        kind: CeremonyKind,
        user_id: Option<i64>,
    ) -> Result<String, AppError> {
        let mut map = self.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
        let now = Utc::now();
        map.retain(|_, c| c.expires_at > now);
        if map.len() >= MAX_CEREMONIES {
            return Err(rate_limited(
                "too many WebAuthn challenges in flight, retry shortly".into(),
                5,
            ));
        }

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
        Ok(challenge)
    }

    /// Redeem a challenge for `kind`: always removed, returned only when it
    /// exists, is of that kind and has not expired - single-use even for a
    /// wrong kind or an expired attempt, like [`Self::take_zip_job`].
    pub fn take_ceremony(&self, challenge: &str, kind: CeremonyKind) -> Option<Ceremony> {
        let mut map = self.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
        let found = map.remove(challenge)?;
        (found.kind == kind && found.expires_at > Utc::now()).then_some(found)
    }

    /// The account half of the sign-in gate (F1), for endpoints that are
    /// not source-budgeted: the WebAuthn challenge door refuses on the
    /// same backoff as the password door, keyed by the name itself so
    /// unknown and real names refuse identically.
    pub fn account_gate(&self, username: &str) -> Result<(), AppError> {
        let now = Utc::now();
        let mut auth = self.auth.lock().unwrap_or_else(|p| p.into_inner());
        prune_auth(&mut auth, now);
        check_account_backoff(&auth, username, now)
    }

    /// Gate a password sign-in before any work happens (F1).
    ///
    /// The account's backoff answers first - checking it costs nothing, so
    /// a locked account never reaches the database or Argon2, and even the
    /// right password waits out the window the wrong ones started. Then
    /// the source address's failed-attempt budget, which bounds the
    /// aggregate hashing one address can trigger.
    pub fn login_gate(&self, username: &str, source: &str) -> Result<(), AppError> {
        let now = Utc::now();
        let mut auth = self.auth.lock().unwrap_or_else(|p| p.into_inner());
        prune_auth(&mut auth, now);

        check_account_backoff(&auth, username, now)?;
        if let Some(spend) = auth.login_fails.get(source) {
            // Pruning dropped every lapsed window, so this one is live.
            if spend.spent >= LOGIN_FAIL_BUDGET {
                let secs = remaining_secs(spend.window_start + login_window(), now);
                return Err(rate_limited(
                    format!("too many failed sign-in attempts from this address, retry in {secs} seconds"),
                    secs,
                ));
            }
        }
        Ok(())
    }

    /// Count a failed sign-in against both keys (F1): the account's
    /// backoff - which starts or extends its window once the failures add
    /// up - and the source address's spend, which 429s the *next* failure
    /// after the budget is gone.
    pub fn login_failed(&self, username: &str, source: &str) {
        let now = Utc::now();
        let mut auth = self.auth.lock().unwrap_or_else(|p| p.into_inner());
        prune_auth(&mut auth, now);

        let lock = auth
            .accounts
            .entry(username.to_string())
            .or_insert_with(|| AccountLock {
                failures: 0,
                last_failure: now,
                locked_until: None,
            });
        lock.failures = lock.failures.saturating_add(1);
        lock.last_failure = now;
        if lock.failures >= AUTH_LOCK_AFTER {
            let step = u32::from(lock.failures - AUTH_LOCK_AFTER).min(24);
            let window = AUTH_LOCK_BASE_SECS.saturating_mul(1_i64 << step);
            lock.locked_until = Some(now + Duration::seconds(window.min(AUTH_LOCK_MAX_SECS)));
        }
        if auth.accounts.len() > MAX_AUTH_ACCOUNTS {
            let oldest = auth
                .accounts
                .iter()
                .min_by_key(|(_, l)| l.last_failure)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                auth.accounts.remove(&key);
            }
        }

        let spend = auth
            .login_fails
            .entry(source.to_string())
            .or_insert_with(|| SourceSpend {
                window_start: now,
                spent: 0,
            });
        spend.spent = spend.spent.saturating_add(1);
        if auth.login_fails.len() > MAX_AUTH_SOURCES {
            let oldest = auth
                .login_fails
                .iter()
                .min_by_key(|(_, s)| s.window_start)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                auth.login_fails.remove(&key);
            }
        }
    }

    /// A sign-in that proved the password clears the account's record (F1):
    /// the holder just demonstrated they are the holder, so the wrong
    /// ones before them are forgiven.
    pub fn login_succeeded(&self, username: &str) {
        let mut auth = self.auth.lock().unwrap_or_else(|p| p.into_inner());
        auth.accounts.remove(username);
    }

    /// Spend one registration attempt from the source budget (F1).
    ///
    /// Counted *before* the password is hashed: the expensive half is the
    /// reason the budget exists, and a taken name still pays for it.
    pub fn register_take(&self, source: &str) -> Result<(), AppError> {
        let now = Utc::now();
        let mut auth = self.auth.lock().unwrap_or_else(|p| p.into_inner());
        prune_auth(&mut auth, now);

        let spend = auth
            .registers
            .entry(source.to_string())
            .or_insert_with(|| SourceSpend {
                window_start: now,
                spent: 0,
            });
        if spend.spent >= REGISTER_BUDGET {
            let secs = remaining_secs(spend.window_start + register_window(), now);
            return Err(rate_limited(
                format!("too many accounts registered from this address lately, retry in {secs} seconds"),
                secs,
            ));
        }
        spend.spent = spend.spent.saturating_add(1);
        if auth.registers.len() > MAX_AUTH_SOURCES {
            let oldest = auth
                .registers
                .iter()
                .min_by_key(|(_, s)| s.window_start)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                auth.registers.remove(&key);
            }
        }
        Ok(())
    }
}

pub type SharedState = Arc<AppState>;

/// The account half of the gate, against an already-pruned limiter (F1):
/// an invented name carries the same backoff as a real one, so the
/// refusal pattern never tells an attacker who has an account.
fn check_account_backoff(
    auth: &AuthLimiter,
    username: &str,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let Some(lock) = auth.accounts.get(username) else {
        return Ok(());
    };
    let Some(until) = lock.locked_until else {
        return Ok(());
    };
    if until > now {
        let secs = remaining_secs(until, now);
        return Err(rate_limited(
            format!("too many failed sign-in attempts for this account, retry in {secs} seconds"),
            secs,
        ));
    }
    Ok(())
}

/// The login-failure window as a duration (F1).
fn login_window() -> Duration {
    Duration::seconds(LOGIN_FAIL_WINDOW_SECS)
}

/// The registration window as a duration (F1).
fn register_window() -> Duration {
    Duration::seconds(REGISTER_WINDOW_SECS)
}

/// Drop every authentication counter whose window or memory has lapsed
/// (F1) - called on every use, the way `new_ceremony` prunes, so the maps
/// only ever hold what is currently in flight.
fn prune_auth(auth: &mut AuthLimiter, now: DateTime<Utc>) {
    auth.login_fails
        .retain(|_, s| now - s.window_start < login_window());
    auth.registers
        .retain(|_, s| now - s.window_start < register_window());
    let memory = Duration::seconds(AUTH_LOCK_MEMORY_SECS);
    auth.accounts
        .retain(|_, l| l.locked_until.is_some_and(|u| u > now) || now - l.last_failure < memory);
}

/// Seconds (rounded up, never zero) until `until` - the number every 429
/// states in both the `Retry-After` header and the body (F1).
fn remaining_secs(until: DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    (until - now).num_seconds().max(1) as u64
}

/// The one shape every authentication 429 takes (F1).
fn rate_limited(reason: String, retry_after_secs: u64) -> AppError {
    AppError::RateLimited {
        retry_after_secs: retry_after_secs.max(1),
        reason,
    }
}
