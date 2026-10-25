use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A registered fxcloud user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    /// Accounts are created inactive and must be enabled (directly in the
    /// database until a user-administration UI exists) before their owner can
    /// sign in. Deactivating a user cuts off access immediately, including
    /// sessions that are already open.
    #[serde(default)]
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    /// Storage quota in bytes. Content beyond it is rejected with
    /// `507 Insufficient Storage`. The schema default (1 GiB, see migration
    /// `004_user_quota`) applies to every account; raise or lower it with
    /// `UPDATE users SET quota_bytes = …` until an admin UI exists.
    pub quota_bytes: i64,
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
}

/// Payload to create a share.
#[derive(Debug, Deserialize)]
pub struct CreateShareRequest {
    pub file_id: i64,
    pub username: String,
    /// Optional permission mask; defaults to all permissions.
    #[serde(default)]
    pub permissions: Option<i64>,
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
    pub file_ids: Vec<i64>,
    pub username: String,
    /// Optional permission mask; defaults to all permissions.
    #[serde(default)]
    pub permissions: Option<i64>,
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
