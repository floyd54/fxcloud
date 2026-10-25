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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_only_share_cannot_write() {
        assert!(grants(PERM_READ, PERM_READ));
        assert!(!grants(PERM_READ, PERM_UPDATE));
        assert!(!grants(PERM_READ, PERM_CREATE));
        assert!(!grants(PERM_READ, PERM_DELETE));
        assert!(!grants(PERM_READ, PERM_SHARE));
    }

    #[test]
    fn all_permissions_cover_every_bit() {
        assert_eq!(
            PERM_ALL,
            PERM_READ | PERM_UPDATE | PERM_CREATE | PERM_DELETE | PERM_SHARE
        );
        for req in [PERM_READ, PERM_UPDATE, PERM_CREATE, PERM_DELETE, PERM_SHARE] {
            assert!(grants(PERM_ALL, req), "PERM_ALL must grant {req}");
        }
    }

    #[test]
    fn a_combined_requirement_needs_every_bit_of_it() {
        let read_write = PERM_READ | PERM_UPDATE;
        assert!(grants(read_write, read_write));
        assert!(!grants(PERM_READ, read_write));
        assert!(!grants(PERM_UPDATE, read_write));
        assert!(grants(PERM_ALL, read_write));
    }

    #[test]
    fn an_empty_mask_grants_nothing() {
        assert!(!grants(0, PERM_READ));
        assert!(!grants(0, PERM_UPDATE | PERM_DELETE));
        // `required == 0` is vacuously satisfied, but no caller asks for it;
        // recording it keeps the mask arithmetic honest rather than special.
        assert!(grants(0, 0));
    }

    #[test]
    fn normalize_drops_bits_that_are_not_permissions() {
        assert_eq!(normalize(PERM_ALL | 0b1000_0000), PERM_ALL);
        assert_eq!(normalize(PERM_READ | PERM_DELETE), PERM_READ | PERM_DELETE);
        // A negative mask has every bit set, including bits that do not exist.
        assert_eq!(normalize(-1), PERM_ALL);
        assert_eq!(normalize(0), 0);
    }

    #[test]
    fn perm_names_lists_exactly_what_is_granted() {
        assert_eq!(perm_names(0), Vec::<&str>::new());
        assert_eq!(perm_names(PERM_READ), vec!["read"]);
        assert_eq!(
            perm_names(PERM_DELETE | PERM_SHARE),
            vec!["delete", "share"]
        );
        assert_eq!(perm_names(PERM_ALL).len(), 5);
    }

    #[test]
    fn a_resolved_grant_delegates_to_its_mask() {
        let read_only = ShareAccess {
            share_id: 1,
            source_id: 2,
            owner_id: 3,
            grantee_id: 4,
            permissions: PERM_READ,
        };
        assert!(read_only.can(PERM_READ));
        assert!(!read_only.can(PERM_UPDATE));
        assert!(!read_only.can(PERM_SHARE));
    }
}
