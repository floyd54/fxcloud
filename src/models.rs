use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A registered fxcloud user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    /// Accounts are created inactive and must be enabled before their owner
    /// can sign in. Deactivating a user cuts off access immediately,
    /// including sessions that are already open. Administrators flip this in
    /// the user-administration dialog (or directly in the database).
    #[serde(default)]
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    /// Storage quota in bytes. Content beyond it is rejected with
    /// `507 Insufficient Storage`. The schema default (1 GiB, see migration
    /// `004_user_quota`) applies to every account; administrators raise or
    /// lower it per account in the user-administration dialog.
    pub quota_bytes: i64,
    /// UI theme chosen in the user menu: "light" or "dark". The web app reads
    /// it from `GET /api/me` and applies it as `data-theme` on `<html>`; the
    /// server only stores and validates it (migration `009_user_theme`).
    #[serde(default = "default_theme")]
    pub theme: String,
    /// Administrator flag (migration `010_user_admin`). Only these accounts
    /// get the "user administration" menu entry and may call the
    /// `/api/admin/users` endpoints; every other request is rejected with
    /// 403 by the `AdminUser` extractor. The very first account is created
    /// with the flag on, and the migration promotes the oldest already-active
    /// account on upgrades.
    #[serde(default)]
    pub is_admin: bool,
    /// Version-history bounds per file (migrations `015`/`016`, section 5 of
    /// `concepts/versioning.md`): keep at most `version_keep_n` versions
    /// (0 = no count bound) and none older than `version_keep_days` (0 = no
    /// age bound). Defaults 20 / 180; both are edited in the settings
    /// dialog's versioning section.
    #[serde(default = "default_version_keep_n")]
    pub version_keep_n: i64,
    #[serde(default = "default_version_keep_days")]
    pub version_keep_days: i64,
}

fn default_theme() -> String {
    "light".to_string()
}

fn default_version_keep_n() -> i64 {
    20
}

fn default_version_keep_days() -> i64 {
    180
}

/// One row of `GET /api/users` — the accounts the share dialog offers as
/// dropdown entries. Deliberately minimal: no ids, no quotas (those stay
/// private to their owner), just what is needed to pick a grantee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOption {
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub is_active: bool,
}

/// One row of `GET /api/admin/users` -- the user-administration table.
///
/// Carries everything the admin dialog needs per account: the numeric `id`
/// (for the `PUT`/`POST` subroutes), the labels, and the three administrated
/// properties `is_active`, `is_admin` and `quota_bytes`, plus `used_bytes`
/// so the dialog can show consumption against the quota. Unlike
/// [`UserOption`] this exposes ids and quotas, so it is only ever serialized
/// behind the `AdminUser` extractor (`src/web/middleware.rs`), never to
/// ordinary accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default)]
    pub is_admin: bool,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub created_at: DateTime<Utc>,
}

/// A file-system entry (file or directory) owned by a user.
///
/// Entries form a tree via `parent_id`; a `NULL` parent means the user's root.
/// When an entry is presented to a user who only sees it through a share, the
/// `permissions` field carries that share's mask (instead of the owner's full
/// set) and `owner_name` names the real owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub id: i64,
    pub owner_id: i64,
    pub parent_id: Option<i64>,
    pub name: String,
    pub is_dir: bool,
    pub size: i64,
    pub mime: Option<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    /// Permission mask the *viewer* has on this entry.
    #[serde(default)]
    pub permissions: i64,
    /// Real owner's username, set when the viewer sees it via a share.
    #[serde(default)]
    pub owner_name: Option<String>,
    /// Total bytes of everything inside this folder (recursive sum). Only
    /// directory rows of listing responses carry it — see `list_children`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtree_bytes: Option<i64>,
    /// When the entry was moved to the trash. Only the trashed root row
    /// carries it (its subtree stays intact); trash listings expose it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
    /// When the background purge will remove the entry for good. Set on
    /// trash listings only, derived from the retention window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purge_at: Option<DateTime<Utc>>,
    /// Content encryption format: `0` = plaintext (the default for every
    /// pre-existing row), `1` = the "FXE1" container of ENCRYPTION.md 5.3.
    /// Read paths branch on this instead of sniffing bytes, and the UI
    /// badges the row.
    #[serde(default)]
    pub enc_version: i64,
    /// The entry's key wrapped with its parent folder's key (ENCRYPTION.md
    /// 5.4), base64-encoded. `None` for plaintext entries.
    ///
    /// Server-opaque: useless without the parent key, which only the client
    /// can unwrap. It is returned exactly where the existing read logic
    /// already authorizes the caller, because that is who may unwrap it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_key: Option<String>,
}

/// One account's encryption key material (ENCRYPTION.md section 6).
///
/// Blobs travel base64-encoded: the server stores and forwards them, it can
/// neither read nor produce them. `kdf_params` is the client-side Argon2id
/// configuration as JSON, kept opaque here - only the client ever parses it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKeys {
    pub user_id: i64,
    /// Raw public key with its suite id prefix; published to other users.
    pub public_key: String,
    /// Private key wrapped under the ARK - owner only.
    pub private_key_wrapped: String,
    /// Account root key wrapped under the passphrase-derived KEK.
    pub wrapped_ark: String,
    /// Root folder key wrapped under the ARK (ENCRYPTION.md 5.4).
    pub wrapped_root_key: String,
    /// ARK wrapped under the recovery key. Mandatory, not optional: under
    /// DECISION 3 the login password and the storage secret are one event,
    /// so this is the only path left if that secret is forgotten.
    pub wrapped_ark_recovery: String,
    /// Salt for the client-side Argon2id run.
    pub kdf_salt: String,
    /// Argon2id m/t/p and suite ids, as sent at setup.
    pub kdf_params: serde_json::Value,
    /// Display fingerprint for out-of-band comparison (ENCRYPTION.md 5.6).
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// POST /api/keys/setup payload - everything the server needs to store a
/// fresh key material row. All blobs base64.
#[derive(Debug, Deserialize)]
pub struct SetupKeysRequest {
    pub public_key: String,
    pub private_key_wrapped: String,
    pub wrapped_ark: String,
    pub wrapped_root_key: String,
    pub wrapped_ark_recovery: String,
    pub kdf_salt: String,
    pub kdf_params: serde_json::Value,
    pub fingerprint: String,
}

/// PUT /api/keys/me payload - rewraps the ARK after a passphrase change.
///
/// Only the KEK-wrapped values move: `private_key_wrapped` and
/// `wrapped_root_key` stay untouched because they hang off the ARK, which is
/// exactly why the hierarchy has a KEK -> ARK indirection in the first place.
#[derive(Debug, Deserialize)]
pub struct RewrapKeysRequest {
    pub wrapped_ark: String,
    pub kdf_salt: String,
    pub kdf_params: serde_json::Value,
}

/// One entry of `GET /api/keys/<username>` - the public half only.
#[derive(Debug, Serialize)]
pub struct PublicKeyInfo {
    pub username: String,
    pub public_key: String,
    pub fingerprint: String,
}

/// Where a file's content blob lives on disk.
///
/// The blob path is derived from these values (see the `files` module docs
/// for the layout), so a blob can be located without a database row - which
/// is exactly what deletions need: the rows are gone by the time the content
/// is removed, therefore they are captured before.
#[derive(Debug, Clone, PartialEq)]
pub enum BlobRef {
    /// A file entry's content: `<owner>/<year>/<h1>/<h2>/<file_id>` under
    /// the blob dir (the flat pre-layout only ever applies here, which is
    /// why the legacy fallback is this variant's alone).
    Entry {
        file_id: i64,
        owner_id: i64,
        created_at: DateTime<Utc>,
    },
    /// A kept version's content: `_versions/<file_id>/<version_key>`, where
    /// the key is the row's `blob_created_at` value - time plus random
    /// bytes, unique per attempt so the link can exist before its row.
    Version { file_id: i64, version_key: String },
}

impl From<&FileEntry> for BlobRef {
    fn from(entry: &FileEntry) -> Self {
        Self::Entry {
            file_id: entry.id,
            owner_id: entry.owner_id,
            created_at: entry.created_at,
        }
    }
}

/// One row of `file_versions`: the metadata half of a kept previous version.
///
/// The bytes live in their own path space (see [`BlobRef::Version`]);
/// `blob_key` is what locates them and never leaves the server, while
/// `created_at` - when the content this version preserves was replaced - is
/// what the listing shows and retention counts from.
#[derive(Debug, Clone, Serialize)]
pub struct FileVersion {
    pub id: i64,
    pub size: i64,
    pub enc_version: i64,
    pub created_at: DateTime<Utc>,
    /// The version blob's on-disk key (`BlobRef::Version`).
    #[serde(skip)]
    pub blob_key: String,
}

/// One step in a breadcrumb trail used by the file explorer UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breadcrumb {
    pub id: Option<i64>,
    pub name: String,
    /// The crumb's key record, wrapped with *its* parent's key (5.4).
    ///
    /// The breadcrumb is the trail a read walks to turn stored `enc_key`
    /// values into a usable key (5.2: every child key is wrapped with its
    /// parent's), so one request brings the whole chain - the trail ends at
    /// the entry itself, with its own record last.
    #[serde(default)]
    pub enc_key: Option<String>,
}

/// Payload for creating a new folder.
#[derive(Debug, Deserialize)]
pub struct CreateFolderRequest {
    pub parent_id: Option<i64>,
    pub name: String,
}

/// Payload for creating a new (initially empty) file.
#[derive(Debug, Deserialize)]
pub struct CreateFileRequest {
    pub parent_id: Option<i64>,
    pub name: String,
}

/// Payload for renaming an entry.
#[derive(Debug, Deserialize)]
pub struct RenameRequest {
    pub id: i64,
    pub name: String,
}

/// Registration payload.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Login payload.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Settings saved from the user menu (`PUT /api/me`).
///
/// The optional fields are saved independently - the name form, the theme
/// picker and the version-retention section each send their own values
/// without resending the others.
#[derive(Debug, Default, Deserialize)]
pub struct UpdateMeRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub theme: Option<String>,
    /// How many versions to keep per file (`version_keep_n`, 0 = unbound).
    #[serde(default)]
    pub version_keep_n: Option<i64>,
    /// Age bound for versions in days (`version_keep_days`, 0 = unbound).
    #[serde(default)]
    pub version_keep_days: Option<i64>,
}

/// Password change from the user menu (`PUT /api/me/password`).
///
/// The current password has to be sent along: the session cookie only proves
/// "someone signed in", not "the same person still knows the password", and a
/// hijacked tab should not be able to lock the owner out of their own account.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Partial update of one account from the user-administration dialog
/// (`PUT /api/admin/users/:id`).
///
/// Every field is optional so the dialog can change one property at a time
/// without resending the others. The server validates the *combination*:
/// it refuses a change that would deactivate or demote the last active
/// administrator, and refuses an administrator deactivating themselves
/// (see `src/web/routes/admin.rs`).
#[derive(Debug, Default, Deserialize)]
pub struct AdminUpdateUserRequest {
    /// Activate or deactivate the account (`is_active`).
    #[serde(default)]
    pub is_active: Option<bool>,
    /// Grant or revoke the administrator flag (`is_admin`).
    #[serde(default)]
    pub is_admin: Option<bool>,
    /// Set the storage quota in bytes.
    #[serde(default)]
    pub quota_bytes: Option<i64>,
}

/// A share row (a grant from an owner to a grantee).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub id: i64,
    pub source_id: i64,
    pub owner_id: i64,
    pub grantee_id: i64,
    pub display_name: String,
    pub permissions: i64,
    pub created_at: DateTime<Utc>,
}

/// One of my outgoing shares (item I shared with someone), with context.
#[derive(Debug, Serialize)]
pub struct OutgoingShare {
    pub id: i64,
    pub source_id: i64,
    pub source_name: String,
    pub is_dir: bool,
    pub grantee_username: String,
    pub permissions: i64,
    pub created_at: DateTime<Utc>,
}

/// One incoming share (item someone shared with me), with context.
#[derive(Debug, Serialize)]
pub struct IncomingShare {
    pub id: i64,
    pub source_id: i64,
    pub source_name: String,
    pub display_name: String,
    pub is_dir: bool,
    pub size: i64,
    pub owner_username: String,
    pub permissions: i64,
    pub created_at: DateTime<Utc>,
    /// The source's key record, sealed to *my* public key (5.5). NULL for
    /// plaintext shares. Only a share I hold carries one for me, and only
    /// my private key opens it.
    #[serde(default)]
    pub envelope: Option<String>,
}

/// Payload to create a share.
#[derive(Debug, Deserialize)]
pub struct CreateShareRequest {
    pub file_id: i64,
    pub username: String,
    /// Optional permission mask; defaults to all permissions.
    #[serde(default)]
    pub permissions: Option<i64>,
    /// ECIES envelope carrying this source's key record for the grantee
    /// (5.5). Opaque here; only the grantee's browser can open it. Absent
    /// for plaintext sources, which need no exchange.
    #[serde(default)]
    pub envelope: Option<String>,
}

/// Payload to move or copy an entry into another folder.
///
/// `dest_parent: null` means the requester's own root. The entry keeps its
/// name at the destination (the server rejects collisions with 409).
#[derive(Debug, Deserialize)]
pub struct TransferRequest {
    pub id: i64,
    #[serde(default)]
    pub dest_parent: Option<i64>,
}

/// Payload for `PUT /api/files/key` - store a row's key record without
/// touching its bytes (5.5: a folder gaining its key, the re-binding after
/// a move, the share-time migration of a legacy record).
#[derive(Debug, Deserialize)]
pub struct SetKeyRequest {
    pub id: i64,
    /// Base64 of the wrapped record, exactly as every other endpoint
    /// carries it. Empty and undecodable values are refused.
    pub key: String,
}

// ---------------------------------------------------------------------------
// Batch operations (multi-selection in the file list)
// ---------------------------------------------------------------------------

/// Payload for a batch operation on a list of entries (e.g. delete).
#[derive(Debug, Deserialize)]
pub struct BatchIdsRequest {
    pub ids: Vec<i64>,
}

/// Payload to move or copy several entries into the same destination folder.
#[derive(Debug, Deserialize)]
pub struct BatchTransferRequest {
    pub ids: Vec<i64>,
    #[serde(default)]
    pub dest_parent: Option<i64>,
}

/// Payload to share several entries with one user in a single step.
#[derive(Debug, Deserialize)]
pub struct BatchShareRequest {
    /// One item per source: each row's key record is wrapped for the same
    /// grantee but under its own id, so the envelope cannot be shared
    /// between them - a flat id list would have nowhere to carry it (5.5).
    pub items: Vec<ShareItem>,
    pub username: String,
    /// Optional permission mask; defaults to all permissions.
    #[serde(default)]
    pub permissions: Option<i64>,
}

/// One source in a batch share, with the envelope for that source.
#[derive(Debug, Deserialize)]
pub struct ShareItem {
    pub file_id: i64,
    /// See `CreateShareRequest::envelope`.
    #[serde(default)]
    pub envelope: Option<String>,
}

/// Payload to prepare a ZIP download of a selection.
#[derive(Debug, Deserialize)]
pub struct ZipRequest {
    pub ids: Vec<i64>,
}

/// One entry a batch operation could not process.
#[derive(Debug, Serialize)]
pub struct BatchFailure {
    pub id: i64,
    /// Entry name when it could still be looked up, `None` otherwise.
    pub name: Option<String>,
    pub error: String,
    /// Stable error code, same vocabulary as the `code` field of a plain
    /// error response, so the UI can translate per-item failures.
    pub code: String,
}

/// Result of a batch operation: what went through, and what didn't.
///
/// Batch items are independent on purpose — one forbidden or colliding entry
/// must not roll back the rest of the selection.
#[derive(Debug, Default, Serialize)]
pub struct BatchOutcome {
    pub ok: Vec<i64>,
    pub failed: Vec<BatchFailure>,
}

impl BatchOutcome {
    /// Record a successful item.
    pub fn success(&mut self, id: i64) {
        self.ok.push(id);
    }

    /// Record a failed item, keeping the entry's name for the error message.
    ///
    /// The caller passes the [`crate::error::AppError`] itself: the client
    /// gets the redacted `user_message` plus the stable `code`, so internal
    /// 5xx details still never reach it while the UI can translate the
    /// failure (i18n.js `err.*`).
    pub fn failure(&mut self, id: i64, name: Option<String>, error: crate::error::AppError) {
        self.failed.push(BatchFailure {
            id,
            name,
            error: error.user_message(),
            code: error.code().to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// Passkeys (WebAuthn)
// ---------------------------------------------------------------------------

/// One registered passkey of the account (`GET /api/me/passkeys`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyInfo {
    pub id: i64,
    /// Device name shown in the settings list; renameable.
    pub label: String,
    pub created_at: DateTime<Utc>,
    /// Last successful sign-in with this device; `null` until then.
    #[serde(default)]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Transport hints the browser reported at registration (usb, nfc, ...).
    #[serde(default)]
    pub transports: Vec<String>,
}

/// Payload of `POST /api/passkeys/login/start`.
#[derive(Debug, Deserialize)]
pub struct PasskeyLoginStartRequest {
    pub username: String,
}

/// Credential produced by `navigator.credentials.create()` during
/// registration, as the browser's `toJSON()` serializes it: base64url
/// strings in place of the raw byte fields.
#[derive(Debug, Deserialize)]
pub struct RegisterCredentialJson {
    /// Informational here: the server takes the authoritative credential id
    /// from the attested authenticator data and checks it against this.
    pub id: String,
    pub response: AttestationResponseJson,
}

/// The `AuthenticatorAttestationResponse` object.
#[derive(Debug, Deserialize)]
pub struct AttestationResponseJson {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    /// Optional transport hints; some authenticators omit them.
    #[serde(rename = "transports", default)]
    pub transports: Option<Vec<String>>,
}

/// Payload of `POST /api/passkeys/register/finish`.
#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    /// Device label for the settings list; defaults server-side.
    #[serde(default)]
    pub label: Option<String>,
    pub credential: RegisterCredentialJson,
}

/// Credential produced by `navigator.credentials.get()` during sign-in.
#[derive(Debug, Deserialize)]
pub struct LoginCredentialJson {
    /// Base64url credential id - the lookup key of the whole assertion.
    pub id: String,
    pub response: AssertionResponseJson,
}

/// The `AuthenticatorAssertionResponse` object.
#[derive(Debug, Deserialize)]
pub struct AssertionResponseJson {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    /// The registration's user id, echoed by authenticators that remember
    /// it; `null` when the username-first client does not send it.
    #[serde(rename = "userHandle", default)]
    pub user_handle: Option<String>,
}

/// Payload of `POST /api/passkeys/login/finish`.
#[derive(Debug, Deserialize)]
pub struct PasskeyLoginFinishRequest {
    pub credential: LoginCredentialJson,
}

/// Payload of `PATCH /api/me/passkeys/:id` (rename one device).
#[derive(Debug, Deserialize)]
pub struct RenamePasskeyRequest {
    pub label: String,
}
