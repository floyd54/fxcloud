# Concept: quotas

Status: **implemented** (migration `004_user_quota`; group quotas
arrived with the group folders, migration `017`).

## 1. Goal

Nobody's storage grows without limit. Every account carries a
`quota_bytes` column (default 1 GiB, set per account by an
administrator), and every write path checks it *next to the write
itself*, so a full quota never leaves a partial file, copy or upload
behind.

## 2. What counts

- The summed `size` of the entries the account **owns**: files you
  uploaded, copies you made, content others shared *to you* counts
  against the original owner, not the grantee.
- Kept versions count too (`file_versions` rows are summed with the
  live sizes), and **trashed content keeps counting** - the disk really
  holds it until the purge removes it.
- Group storage is a separate budget: writes into a group folder count
  against the *group's* `quota_bytes`, never against a member's
  personal quota (see [groups.md](groups.md)).

## 3. Enforcement

- Checked in the database layer beside the write: creating a file,
  overwriting one (only the growth counts) and copying a subtree
  (checked up front for the whole tree). Uploads, editor saves, WebDAV
  `PUT`s and move/copy-in all run through the same gate.
- Exceeding the quota yields `507 Insufficient Storage` with a
  readable message - the web UI and WebDAV both surface it, and the
  topbar shows current usage against the quota.
- Lowering a quota below current usage is allowed: files stay, growth
  stops.

## 4. Where it lives

- Code: `src/db/file.rs` (`ensure_quota`, the `TreeOwner` split
  between user and group), `src/db/user.rs` (`set_user_quota`).
- Model: [ARCHITECTURE.md](../ARCHITECTURE.md) - quotas (and folder
  sizes for the read-only `subtree_bytes` display).
- Admin surface: `PUT /api/admin/users/:id`, `PUT /api/admin/groups/:id`
  (API.md).
- User side: [USERGUIDE.md](../USERGUIDE.md) sections 8 and 9.
- Tests: `tests/suite.sh` section "storage quota".
