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
| N1 | Granularity | per-folder opt-in flag, exactly like `enc_zone` (section 10): the client toggles it with `PUT /api/files/nameenc {id, flag}`, which sets `files.names_enc` on the folder ("my children's names are blobs") and cascades `files.name_enc` ("my own name is a blob") to every row below - two columns, two meanings, because office, links, WebDAV and the share-label guard must answer from a single row while creates and moves inherit from the parent's flag. The flag is inherited by descendants through the breadcrumb; a copy does not carry it. Unflagged paths are untouched - WebDAV, office and the duplicate check keep working there. Mixed trees are the normal state, as everywhere else. |
| N2 | Which key wraps a name | the **parent folder's key** (top level: the root key). A name is just another value in the parent-wraps-child hierarchy, and every grantee who may legitimately see a name already holds that key through their envelope. No new key material, no new envelope field, no third key to manage. |
| N3 | Blob format | `wrap(parentKey, utf8(name), childKeyAad(childId))` - the same AES-256-GCM wrap and the same AAD as a key record. A name is a wrapped value like any other. Stored **URL-safe** base64 in `files.name` (RFC 4648 section 5: the name validator refuses `/`, which the standard alphabet contains). |
| N4 | `display_name` (share mounts) | built by the **client** at share time as `wrap(nodeKey, utf8(name), shareEnvelopeAad(source, grantee))`: the mount label in the grantee's root must open with the key the share's envelope already carries - the parent key never leaves the owner, and the node's own key is exactly what the grantee receives. Plaintext rows keep the server-side derivation unchanged. A flagged row whose **content** is not encrypted has no node key to wrap under: sharing it is refused outright (server-side BadRequest, client-side alert) rather than leaking the name as a label. |
| N5 | Duplicate names | the server cannot compare what it cannot read: under the flag the server-side duplicate check is skipped and the **client** compares decrypted siblings before creating. A lost race can leave two rows with one name; the listing shows it and the user renames one - the same outcome the server would have produced, one race wider. (The server needs no branch for the skip: ciphertext never equals ciphertext, so its check simply never fires under the flag - and the UNIQUE sibling index never collides either.) |
| N6 | Move | the name travels with the row's record: the existing client-side re-bind walk (`rewrapForParent`) re-wraps the name under the destination parent's key in the same pass. |
| N7 | Copy | already refused for keyed rows (`copy_recursive` refuses keyed descendants); extended the same way for names: a source subtree carrying wrapped names and a destination folder that demands wrapping are both refused whole - a copy re-wraps nothing, and the visitor-shaped alternative (plaintext landing under the flag, or blobs landing outside it) would strand rows. |
| N8 | Trash and restore | the server still sorts by the stored blob (a meaningless order) - the client re-sorts after decrypting. The restore suffix logic ("name (2)") is skipped under the flag: it needs plaintext to invent a variant - and, like the duplicate check, it never fires on its own, because it compares ciphertext. A genuine collision surfaces in the listing and is renamed by hand. |
| N9 | WebDAV | PROPFIND serves the stored blob as the name (opaque, still a legal filename), and **any MOVE** - a rename in place or a move to another folder - is refused with 403 when the source row or the destination folder carries the flag: only the app can re-wrap. Reads, writes and deletes are unchanged. |
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

- `files.names_enc` (the folder flag) and `files.name_enc` (the row's
  own state), exposed next to `enc_zone` in the listing, breadcrumb
  crumbs and `info` - the client needs both (decrypt this name? / may I
  wrap a new one here?), the server needs the row state for its
  branches and the flag for inheritance
- `PUT /api/files/nameenc {id, flag}` flips the flag and cascades the
  row marks (the client wraps first, then flips - and unwraps before
  lowering it, so no reader ever meets a mark without the blob)
- duplicate checks and the restore suffix need no branch: ciphertext
  never equals ciphertext, so they simply never fire under the flag
- WebDAV MOVE refused on flagged rows (source or destination);
  public-link mint refused on flagged rows; visitor upload refused into
  flagged folders
- office: `BaseFileName` and `doc_kind` from the MIME column for
  flagged rows (`engine_label`)
- `POST /api/shares` accepts an optional client-built `display_name`
  (size-checked like an envelope, stored verbatim, refused on
  plaintext rows); plaintext rows keep today's server-side derivation

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
