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
