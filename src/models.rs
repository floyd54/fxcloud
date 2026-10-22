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
