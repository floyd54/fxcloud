use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A registered fxcloud user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
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
