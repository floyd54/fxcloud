//! Sharing model: permission bitmasks and the share-access value type.
//!
//! Nextcloud-style permissions are a bitmask so a grantee can be given exactly
//! the rights the owner intends. The database stores the mask as an integer.

use serde::{Deserialize, Serialize};

/// View/read the item (download file, list folder).
pub const PERM_READ: i64 = 1;
/// Change the content of a file (overwrite / `PUT`).
pub const PERM_UPDATE: i64 = 2;
/// Create new items inside a folder (`MKCOL` / new upload).
pub const PERM_CREATE: i64 = 4;
/// Delete the item (or children of a folder).
pub const PERM_DELETE: i64 = 8;
/// Re-share the item to someone else.
pub const PERM_SHARE: i64 = 16;

/// Every possible permission.
pub const PERM_ALL: i64 = PERM_READ | PERM_UPDATE | PERM_CREATE | PERM_DELETE | PERM_SHARE;

/// True if `perms` includes `required`.
pub fn grants(perms: i64, required: i64) -> bool {
    perms & required == required
}

/// Validate that a requested mask only uses known bits.
pub fn normalize(mask: i64) -> i64 {
    mask & PERM_ALL
}

/// A resolved grant: the share row that authorizes access to an entry the
/// requester does not own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareAccess {
    pub share_id: i64,
    pub source_id: i64,
    pub owner_id: i64,
    pub grantee_id: i64,
    pub permissions: i64,
}

impl ShareAccess {
    pub fn can(&self, required: i64) -> bool {
        grants(self.permissions, required)
    }
}

/// Human-readable permission names (for API/debug output).
pub fn perm_names(mask: i64) -> Vec<&'static str> {
    let mut names = Vec::new();
    if grants(mask, PERM_READ) {
        names.push("read");
    }
    if grants(mask, PERM_UPDATE) {
        names.push("update");
    }
    if grants(mask, PERM_CREATE) {
        names.push("create");
    }
    if grants(mask, PERM_DELETE) {
        names.push("delete");
    }
    if grants(mask, PERM_SHARE) {
        names.push("share");
    }
    names
}
