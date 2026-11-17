# Names at rest (phase 6 S3)

Metadata encryption, scoped honestly: the strings in the `name` column
are wrapped client-side, so the server stores blobs where it used to
read words. This lifts one corner of NG1 - it does **not** claim full
metadata privacy: sizes, timestamps, tree structure, MIME types,
usernames and the approximate length of a name stay visible (see
Residuals).

The design follows the house rules: the server stays key-blind, mixed
trees are a normal tested state, the browser does the crypto with the
primitives the golden vectors already pin, and every subsystem that
needs plaintext gets an explicit, documented answer instead of a silent
break.

## Decisions

| #  | Question | Decision |
|----|----------|----------|
| N1 | Granularity | per-folder opt-in flag `name_enc`, inherited by descendants through the breadcrumb exactly like `enc_zone` (section 10); a copy does not carry it. Unflagged paths are untouched - WebDAV, office and the duplicate check keep working there. Mixed trees are the normal state, as everywhere else. |
| N2 | Which key wraps a name | the **parent folder's key** (top level: the root key). A name is just another value in the parent-wraps-child hierarchy, and every grantee who may legitimately see a name already holds that key through their envelope. No new key material, no new envelope field, no third key to manage. |
| N3 | Blob format | `wrap(parentKey, utf8(name), childKeyAad(childId))` - the same AES-256-GCM wrap and the same AAD as a key record. A name is a wrapped value like any other. Stored base64 in `files.name`. |
| N4 | `display_name` (share mounts) | built by the **client** at share time as `wrap(nodeKey, utf8(name), shareEnvelopeAad(source, grantee))`: the mount label in the grantee's root must open with the key the share's envelope already carries - the parent key never leaves the owner, and the node's own key is exactly what the grantee receives. Plaintext rows keep the server-side derivation unchanged. |
| N5 | Duplicate names | the server cannot compare what it cannot read: under the flag the server-side duplicate check is skipped and the **client** compares decrypted siblings before creating. A lost race can leave two rows with one name; the listing shows it and the user renames one - the same outcome the server would have produced, one race wider. |
| N6 | Move | the name travels with the row's record: the existing client-side re-bind walk (`rewrapForParent`) re-wraps the name under the destination parent's key in the same pass. |
| N7 | Copy | already refused for keyed rows (`copy_recursive` refuses keyed descendants) - names inherit that refusal, nothing new to build. |
| N8 | Trash and restore | the server still sorts by the stored blob (a meaningless order) - the client re-sorts after decrypting. The restore suffix logic ("name (2)") is skipped under the flag: it needs plaintext to invent a variant. A genuine collision surfaces in the listing and is renamed by hand. |
| N9 | WebDAV | PROPFIND serves the stored blob as the name (opaque, still a legal filename), and a rename over WebDAV is refused with 403 on flagged rows - only the app can re-wrap. Reads, writes, id-based moves and deletes are unchanged. |
| N10 | Office | CheckFileInfo gets a synthetic name built from the plaintext MIME (`enc-<id>.<ext>`): the engine needs an extension to pick an editor (`doc_kind`), it does not need the user's title. |
| N11 | Public links | minting a link on a flagged row is refused - an anonymous visitor has no key and would be shown a blob. |
| N12 | Re-key synergy | the folder re-key (5.6) re-wraps child names in the same step that re-wraps child records: rotating a folder key also rotates what its children are called. The file-key rotation (DECISION 5) does not touch names - a file's name lives under its parent key. |
| N13 | Flag transitions | flagging a folder runs a client-side walk that wraps every existing name below it (the encrypt-migration pattern, names only - cheap); unflagging unwraps them again. The invariant is client-maintained: flagged parent => every name below is wrapped, all of them under keys the holder of the chain already has. |

## Residuals (what stays visible, deliberately)

- sizes, subtree sizes, quota accounting - the server enforces quota
- timestamps (created, modified, deleted) and the tree structure
  (parent ids, row ids, child counts)
- MIME type: client-supplied at upload; this is also what keeps the
  office engine working (N10)
- usernames, share relations, permission masks
- the approximate length of a name (the blob grows ~1.37x +40 bytes)
- access patterns: which row changed, and when

This is "names at rest", not NG1. Full metadata privacy stays a
non-goal (section 8).

## Touch points

Server:

- `files.name_enc` column, exposed next to `enc_zone` in the listing,
  breadcrumb crumbs and `info` (the client must know what to decrypt,
  the server must know which branches to skip)
- duplicate checks skipped under the flag (the three `already exists`
  sites), restore suffix skipped
- WebDAV rename refused on flagged rows; public-link mint refused
- office: `BaseFileName` and `doc_kind` from the MIME column for
  flagged rows
- `POST /api/shares` accepts an optional client-built `display_name`
  (size-checked like an envelope, otherwise opaque); plaintext rows
  keep today's server-side derivation

Client (fxenc / app):

- listing and breadcrumbs decrypt names with the chain keys the walk
  already unwraps
- create and rename wrap before the call; the pre-create sibling
  compare runs on decrypted names (N5)
- move extends `rewrapForParent` to re-wrap names (N6)
- the share dialog builds `display_name` (N4); outgoing lists decrypt
  `source_name` for the share rows and the revoke prompt
- trash re-sorts after decrypting
- flag/unflag run the name walk (N13)
- every new string in de/en/tlh; tests follow the fixture discipline -
  the wrap itself is already vector-pinned, the new pins are the
  flag's branching (skip/refuse/decrypt paths) in the suite

## Rollout

Flag a folder when the names in it should stop being readable by the
server; the walk rewrites them in one pass and everything below stays
consistent from that moment. Unflag to hand a subtree back to WebDAV
and office in full fidelity. The rest of the account is never touched,
and nothing about content keys, envelopes or revocation changes - this
feature adds one wrapped value per row and refuses five things by name.
