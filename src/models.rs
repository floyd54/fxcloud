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
}

fn default_theme() -> String {
    "light".to_string()
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
/// The blob path is derived from these three values (see the `files` module
/// docs for the layout), so a blob can be located without a database row —
/// which is exactly what deletions need: the rows are gone by the time the
/// content is removed, therefore they are captured before.
#[derive(Debug, Clone, Copy)]
pub struct BlobRef {
    pub file_id: i64,
    pub owner_id: i64,
    pub created_at: DateTime<Utc>,
}

impl From<&FileEntry> for BlobRef {
    fn from(entry: &FileEntry) -> Self {
        Self {
            file_id: entry.id,
            owner_id: entry.owner_id,
            created_at: entry.created_at,
        }
    }
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
    /// Optional sign-in passphrase, 16 characters minimum (README:
    /// "passphrase login"). Absent or null for every client that does not
    /// send one - the password stays mandatory either way, since WebDAV
    /// clients only ever send that one.
    #[serde(default)]
    pub passphrase: Option<String>,
}

/// Login payload.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    /// The credential being presented, whichever `mode` says it is.
    pub password: String,
    /// Which credential `password` carries: absent or `"password"` (the
    /// default, what WebDAV and every pre-existing client sends), or
    /// `"passphrase"` for a sign-in with the optional passphrase.
    #[serde(default)]
    pub mode: Option<String>,
}

/// Settings saved from the user menu (`PUT /api/me`).
///
/// Both fields are optional so each half of the menu - the name form and the
/// theme picker - saves on its own without resending the other's value.
#[derive(Debug, Default, Deserialize)]
pub struct UpdateMeRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub theme: Option<String>,
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

/// Set or replace the optional sign-in passphrase (`PUT /api/me/passphrase`).
///
/// Proof and secret are separate on purpose: `current_password` is verified
/// against `password_hash` before anything is written (a hijacked session
/// must not be able to lock the owner out by swapping the passphrase), and
/// the server stores only an Argon2id hash of `passphrase` - it never
/// becomes a key itself, the key row stays wrapped client-side.
#[derive(Debug, Deserialize)]
pub struct SetPassphraseRequest {
    pub current_password: String,
    /// 16 characters minimum, checked by the handler, never trimmed:
    /// a passphrase is a secret exactly as typed.
    pub passphrase: String,
}

/// Remove the optional sign-in passphrase (`DELETE /api/me/passphrase`).
///
/// Password and key row are rewrapped by the client afterwards, so this
/// endpoint only gives up the *credential*: with it gone, `mode:
/// "passphrase"` stops verifying while password sign-in and WebDAV are
/// untouched.
#[derive(Debug, Deserialize)]
pub struct RemovePassphraseRequest {
    pub current_password: String,
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
    /// The caller passes [`crate::error::AppError::user_message`] so internal
    /// 5xx details never reach the client.
    pub fn failure(&mut self, id: i64, name: Option<String>, error: String) {
        self.failed.push(BatchFailure { id, name, error });
    }
}
