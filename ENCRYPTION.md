# ENCRYPTION.md - Concept for client-side per-file encryption

Status: **decisions made (section 13), implementation started with phase 1.**
This document is the reference we come back to while implementing. It
describes a design for user-side, per-file encryption in fxcloud that does
not break sharing between users, which requires a key exchange.

Nothing here is committed to API.md / ARCHITECTURE.md yet. Sections marked
`DECISION` name a decision; where one was made, the consequences that bind
the implementation are written out next to it (see in particular
DECISION 3 in 5.7 and DECISION 9 in 7).

---

## 1. Goals and non-goals

Goals:

- **G1 - Content confidentiality against the server.** File bytes are
  encrypted in the browser before upload and decrypted only in the
  browser. The server stores and serves ciphertext it cannot read.
- **G2 - Per-file keys.** Every file has its own random key, so leaking one
  key never exposes other files, and keys can be shared, rotated and
  revoked per file.
- **G3 - Sharing keeps working.** Sharing a file or folder with another
  fxcloud user stays a one-click operation, implemented as a key exchange:
  the owner wraps the relevant key(s) to the grantee's public key.
- **G4 - The server stays dumb about content, smart about permissions.**
  Quota, trash, shares, permission masks, rate limits and all other server
  logic keep working on opaque ciphertext.
- **G5 - Opt-in and mixed mode.** Encryption is enabled per user (or per
  file, see DECISION 2). Existing plaintext files keep working untouched.

Non-goals (v1):

- **NG1 - Full metadata privacy.** Names, sizes, folder structure, times,
  share relations and usernames stay visible to the server (section 8).
- **NG2 - Protection against a malicious server serving backdoored
  JavaScript.** See threat model, section 2.
- **NG3 - Anonymous access / public links.** Shares are user-to-user only,
  as today.
- **NG4 - Deniability, forward secrecy, post-quantum.** Not in v1; the
  format is versioned so these can be added later (section 5.3).

---

## 2. Threat model

What we defend against:

| Adversary | Defended? | How |
| --- | --- | --- |
| Stolen disk / DB dump / leaked backup | yes | only ciphertext + wrapped keys at rest |
| Honest-but-curious admin reading files | yes | server never holds plaintext or keys |
| Another tenant / SQL-injection attacker reading rows | yes | same as above |
| Attacker with a leaked session cookie | partial | they see ciphertext; without the passphrase they cannot decrypt. They can still delete/modify (availability, integrity of the ciphertext) |
| Traffic analysis (metadata) | no | NG1 |
| Server deleting or withholding data | no | availability was never in scope |
| Server serving modified JS that exfiltrates keys | **no** | the browser trusts the origin it loads the app from. Mitigations exist (reproducible builds, signed releases, external integrity check of the app bundle) but are out of scope for v1 - see DECISION 6 |
| Compromised client device (keylogger, stolen unlocked session) | no | standard client-side crypto limitation |
| Server reading data *before* migration to encryption | no | plaintext files stay plaintext until migrated (section 10) |

Honest summary: this design protects **data at rest and in transit against
everyone except the fxcloud server itself while it serves the app**. It
turns a server compromise from "attacker reads every file" into "attacker
reads ciphertext and metadata, and must additionally serve modified client
code to get plaintext".

---

## 3. Constraints imposed by the current fxcloud design

Facts taken from the code, all of which shape this concept:

1. **The server reads file content in several places** (see section 7):
   preview with `Range` support and `nosniff`/`sandbox` headers, the
   text editor's `PUT /api/files/content`, server-side ZIP assembly, and
   WebDAV `GET`/`PUT`.
2. **The server is authoritative for `Content-Type`** and enforces the
   HTML/SVG sandbox on responses. For encrypted files the server cannot
   know the real type, so its authoritative answer becomes
   `application/octet-stream` (section 7).
3. **Sharing is a row in `shares (source_id, owner_id, grantee_id, ...)`**
   where `source_id` may be a file *or a folder*, with a permission mask
   (READ/UPDATE/CREATE/DELETE/SHARE). The grantee sees the source in their
   root. This maps perfectly to one key envelope per share row (5.5).
4. **Login is password-based Argon2 on the server.** The encryption key
   must never be derivable from anything the server stores (section 5.1).
5. **Blobs are content-addressed by file id and moved nowhere on rename,
   move, trash, restore.** A file's key therefore needs no relocation when
   metadata changes - only when content is replaced.
6. **No server-side search, no thumbnails, no server-side content index
   exists.** Nothing in the current feature set requires server-side
   plaintext besides the ones listed in section 7. (A future full-text
   search would not work on encrypted data - noted for the roadmap.)
7. **Browser platform: Web Crypto API.** AES-GCM, HKDF, ECDH, PBKDF2 and
   (in current browsers) X25519 are available natively. Argon2id is not -
   it needs a WASM build. Uploads today are already fully buffered in
   memory server-side, so chunked client-side encryption does not make the
   memory profile worse.

---

## 4. Design in one paragraph

Every user has a keypair. The private key is stored on the server, wrapped
with a key derived from a secret the server never sees; the public key is
stored in the clear. Every file gets a random file key; its content is
encrypted with that key (AES-256-GCM, chunked). Every file key and folder
key is wrapped to its parent folder's key, forming a per-subtree key
hierarchy that ends at the owner's root. Sharing a file or folder means:
the owner (or an authorized re-sharer) wraps the source's key to the
grantee's public key and stores that single envelope next to the share
row. The grantee unwraps it with their private key and can then unwrap the
whole shared subtree. The server keeps enforcing every permission it
enforces today, on bytes it cannot read.

---

## 5. Cryptographic design

### 5.1 Primitives and where they run

| Purpose | Algorithm | Runs in |
| --- | --- | --- |
| Login password check | Argon2id (unchanged) | server (never used for keys) |
| Passphrase -> KEK | Argon2id, per-user salt, OWASP-class params | browser, WASM |
| Content encryption | AES-256-GCM, chunked | browser, WebCrypto |
| Symmetric key wrap (parent -> child) | AES-256-GCM, key-as-key | browser, WebCrypto |
| Key exchange (owner -> grantee) | ECIES: ephemeral ECDH + HKDF-SHA-256 + AES-256-GCM | browser, WebCrypto |
| Key derivation / subkeys | HKDF-SHA-256 with labeled `info` strings | browser, WebCrypto |

`DECISION 1 - ECDSA curve: X25519 or P-256?`
X25519 is modern, fast and simple; browser support is good but not yet
universal across the versions a self-hosted instance may encounter.
P-256 ECDH works everywhere WebCrypto exists. Recommendation: **suite
field in every envelope (section 5.3), ship X25519 first, keep P-256 as a
documented fallback suite** - the format must not hardcode one curve.

Why the login password must not directly encrypt anything: the server
stores an Argon2 hash of it. Anyone with the DB can then offline-brute the
password *and* derive the same key material. So either the encryption
secret is separate, or it goes through a client-side derivation with its
own salt and much higher cost such that the server-side hash adds no
useful shortcut. Both options are listed in DECISION 3.

### 5.2 Key hierarchy

```
storage passphrase (secret; server never sees it)
        |  Argon2id(salt, params)          [params stored server-side, opaque]
        v
      KEK  (256 bit)
        |  AES-GCM unwrap
        v
   Account Root Key - ARK  (random 256 bit, generated once at setup)
        |  wraps: private key, root folder key
        +---------------------> private key  (published: public key, fingerprint)
        |
        v
   root folder key (random, per user)
        |  wraps keys of entries in the root
        +--> folder key of folder A --+--> folder keys / file keys below
        +--> file key of doc.pdf       |
        +--> ...                       |
                                       v
                          each child key is wrapped with its parent's key

   share envelope (only for external users):
   ECIES(recipient_public_key, source key record)  ->  stored in shares.envelope
```

Rationale for each level:

- **KEK -> ARK indirection:** changing the storage passphrase rewraps one
  32-byte value (ARK), not every file key. It also gives us a single
  future root for device keys, recovery keys or metadata encryption
  without touching the file format.
- **ARK wraps the private key:** the private key is generated client-side
  at setup and uploaded only in wrapped form.
- **Parent-wraps-child symmetric hierarchy:** this is what makes *folder*
  sharing cheap (5.5) and makes "add a file to an already shared folder"
  cost exactly one wrap, with no knowledge of who the grantees are.
- **Random key per file:** satisfies G2; a new content version reuses the
  file key only when the writer already holds it (the legitimate case:
  the text editor saving), otherwise rotation is trivial.

`DECISION 2 - Opt-in granularity: whole-account, per-folder, or per-file?`
Whole-account (an "encrypted account" set up at registration) is simplest
to reason about and makes mixed-mode UI (badges, broken WebDAV) rare.
Per-file opt-in gives users a migration path and keeps some folders usable
with WebDAV/desktop sync clients. Recommendation: **store the flag per
file (`files.enc_version`), expose it in the UI as a per-folder "Encrypt
everything here" toggle plus an account-level switch.** The data model
supports both; only the UX defaults differ.

### 5.3 File content format (versioned)

Encrypted blob layout. The header is exactly **18 bytes** - there is
nothing else in it, and the header itself is what each chunk authenticates:

```
offset  size  field            value
------  ----  ---------------  -----------------------------------
     0     4  magic            "FXE1"
     4     1  format version   1
     5     1  suite            cipher id (1 = AES-256-GCM)
     6     4  chunk size       u32 big-endian, e.g. 4194304 (4 MiB)
    10     8  nonce base       per-file random
------  ----  ---------------  -----------------------------------
```

Followed by the chunk payloads:

```
+----------------------------------------------------------+
| chunk 0: ciphertext || 16-byte GCM tag                    |
| chunk 1: ciphertext || 16-byte GCM tag                    |
| ...                                                      |
+----------------------------------------------------------+
```

- **Chunk nonce** = `nonce_base || chunk_index` (8 bytes, then a u32
  big-endian index). Because the file key is unique per file, nonces never
  repeat under one key, and the layout allows random access later
  (seek/Range mapped to chunk ranges, section 7).
- **Chunk count** = `ceil(body_len / (chunk_size + 16))`, so an empty file
  is the header alone with zero chunks. The reader rejects a `chunk_size`
  below 1 byte or above 64 MiB, and rejects a truncated trailing chunk -
  a short last chunk is exactly what silent truncation looks like.
- **AAD per chunk** = `header || file_id || chunk_index`. This binds the
  ciphertext to its row: an attacker with DB write access cannot move one
  file's bytes onto another file's id, truncate silently, or reorder
  chunks - every such manipulation fails the GCM tag.
- **Versioned and self-describing** so suites can change later (e.g. a
  post-quantum envelope) without a migration flag day. Old files keep
  decrypting via their recorded suite.
- Chunk size default 4 MiB: large enough that tag overhead is negligible
  (16 B per chunk), small enough for future partial reads.

Why chunked at all, if v1 reads whole files? Because it locks in the
format now rather than migrating every blob later, and it is what makes
`Range`-style preview (7) possible at all.

### 5.4 Key records and folder hierarchy

Each encrypted entry (file or folder) carries one server-stored,
server-opaque **key record**:

- `files.enc_key` (BLOB, nullable) = the entry's key wrapped with the
  *parent folder's key*, e.g. `AES-GCM(parent_key, child_key,
  AAD = child_id || version)`.
- Top-level entries are wrapped with the user's root folder key; the root
  folder key itself is wrapped by ARK and lives in the new `user_keys`
  table (section 6).
- **Folder keys are filled in lazily (phase 3, shipped):** phase 1 wrapped
  every record straight against the root folder key, and rows from that era
  keep opening - the client walks the trail of records and falls back to the
  root key where the trail stops early, and only the account holding that
  root key has such a fallback to hit; a grantee never held it. Now a folder
  gains its own record on the first encrypted write below it, or when a
  share migrates its subtree (5.5), both through `PUT /api/files/key`
  (PERM_UPDATE, the mask the content write already asks for). Nothing
  creates a folder record up front: a folder nobody has written an
  encrypted file into carries none. A folder is marked by that record
  alone - it holds no content, so `enc_version` stays 0 on it, and 1 only
  ever names a file in the FXE1 format.

Every wrap in the design is one AES-GCM call producing
`nonce(12) || ciphertext || tag(16)` with a fresh random 12-byte nonce, so
re-wrapping the same value twice never yields the same bytes. What differs
between wraps is only the AAD - and the AAD is what stops a value produced
for one slot from opening in another:

| AAD (or HKDF `info`)  | wrap                                          |
| --------------------- | --------------------------------------------- |
| `child_id \|\| version` | a child key under its parent's key          |
| `fx1:ark:v1`          | ARK under the passphrase KEK (AES-GCM AAD)    |
| `fx1:ark-recovery:v1` | ARK under the recovery KEK (AES-GCM AAD)      |
| `fx1:privkey:v1`      | private key under ARK (AES-GCM AAD)           |
| `fx1:rootkey:v1`      | root folder key under ARK (AES-GCM AAD)       |
| `fx1:recovery-kek:v1` | HKDF-SHA-256 `info` when deriving the recovery KEK from the 256-bit recovery key |

The label list is deliberately short and fixed: a wrap whose AAD does not
match byte for byte fails the tag, so an added or renamed label is a
visible, deliberate break rather than a silent mis-binding.

Consequences (all as shipped):

- Renaming, trashing, restoring: **no key operation at all** - keys travel
  with the row, the row itself never moves (constraint 5), and the AAD is
  `child_id || version`, not the name and not the parent. **Moving** is the
  exception once folders carry keys: the record is wrapped for the folder
  the row stands in, so the client **re-binds first and moves second**
  - one `PUT /api/files/key` with the same raw key re-wrapped under the
  destination folder's key, so every envelope sealed to that key stays
  valid - and a move the server refuses (name collision, missing
  permission) rolls the record back to where it came from. The JSON move
  trusts that re-bind, because the server cannot read keys: PERM_UPDATE is
  the check it can make, exactly the position `PUT /api/files/key` takes
  for the same caller. WebDAV MOVE holds no keys at all, so it keeps the
  other half of the rule: a keyed row may travel only between parents that
  carry the same record, and otherwise the move answers 409 rather than
  producing a row whose record no longer opens (DECISION 9 - never blind).
- Copying a file creates a new row with a new id, so its record cannot come
  along with it: **a keyed file still refuses the copy with a 409** that
  names the fix (download and re-upload instead), and the gate looks at the
  subtree's *files* - a folder that carries a record while everything under
  it is plaintext copies fine, because every row of a copy arrives unkeyed,
  like every copy. Wrapping a fresh key under the destination folder key -
  the version that makes copy useful again - is not part of phase 3 and
  stays the documented follow-up.
- Replacing content (upload over existing file, editor save): if the
  writer already holds the file key, content is re-encrypted under it and
  `enc_key` does not change; other grantee envelopes stay valid. Shipped
  exactly so: `writeText` passes the row's own record back verbatim
  (DECISION 5), and a grantee re-saving does the same - see 5.5.

`DECISION 5 - Does content replacement rotate the file key?`
Rotating on every overwrite is safer against a leaked old key but forces
re-wrapping every grantee envelope on every save. Recommendation: **no
rotation on overwrite (the legitimate writer already holds the key),
explicit "rotate key" action available in the UI later.**

### 5.5 Sharing as key exchange

Share creation today: `POST /api/shares {file_id, username, permissions}`
resolves the grantee and inserts a row. With encryption the flow becomes
(shipped):

```
owner browser                         server                    grantee
-------------                         ------                    ------
unlock (holds source key record,
        has grantee public key)  -->
                    GET /api/keys/<username>  ----------------->  returns public_key,
                                                                  fingerprint
key the subtree (one folder key,
  every row below re-wrapped to it)
wrap: env = ECIES(grantee_pub, source_key_record)
                    POST /api/shares {file_id, username,
                                       permissions, envelope}
                                      inserts share row +
                                      stores envelope in
                                      shares.envelope      -->
                                                                grantee unlocks,
                                                                GET /api/shares/incoming,
                                                                eciesOpen(env, own
                                                                private key) -> source
                                                                key record, then one
                                                                unwrap per level down
```

Key points:

- **One envelope per share row**, not per file: the request is
  `{file_id, username, permissions, envelope?}` for one item and
  `{items: [{file_id, envelope?}, ...], username, permissions}` for a
  batch, so a multi-selection seals each record against its own row id and
  two rows never share a blob. The envelope is a base64 string the server
  never opens: empty is refused, so is anything longer than 8192
  characters, and both checks run before the first share of a batch is
  inserted - one oversized blob cannot leave half a selection shared
  without it.
- **Envelope format** (so two independent implementations agree):
  `suite || ephPub || iv(12) || ct`. The sender generates an *ephemeral*
  pair in the recipient's suite, ECDHs, and derives the AES-256-GCM key
  with HKDF-SHA-256 over labels `fx1:share-kek:v1` (KEK) and `fx1:share:v1`
  (wrap). The leading suite byte doubles as the ephemeral public key's own
  prefix, so sender and recipient negotiate nothing out of band and a
  P-256 account is sealed to on its own curve (DECISION 1).
- **The AAD binds an envelope to one share:** `u64be(source_id) ||
  utf8(grantee) || version`. A stored envelope cannot be replayed against
  a second share of the same row, and a grantee cannot hand a colleague
  *their* envelope as if it had been sealed for the colleague - re-sharing
  means re-wrapping the record they hold (see below).
- **A folder share keys the subtree first** (shipped as `keySubtree`):
  the client walks the folder once, gives every unkeyed row and folder a
  record under its parent's key - rows from the flat era of 5.4 included -
  and seals exactly one envelope, the folder key. The grantee's walk then
  starts at that key instead of at a root key they never held: one unwrap
  per breadcrumb level, the file's own record last. Every later encrypted
  write under that folder wraps to the same folder key, so **adding files
  to an already shared folder is free**: no re-share step, and no grantee
  list is consulted client-side.
- **A grantee re-saves the record they were handed, never another one.**
  The file key does not change on overwrite (DECISION 5), so the editor's
  save puts the same record back verbatim and the owner keeps being able to
  unwrap it. Swapping it is refused by name - `403 only the row's owner may
  change its key record` - because the server holds no key and cannot check
  a replacement: a foreign record would leave the owner holding something
  nobody in their own tree can open. `PUT /api/files/key` is the other door
  to that record, gated on the same PERM_UPDATE mask the content write asks
  for - the crypto mirrors the API permission, it does not replace it.
- **No grantee key, no envelope.** `GET /api/keys/<username>` answers 404
  for an account that never set encryption up; the dialog then says so and
  offers the plaintext share, which still works and costs nothing. Sealing
  needs this tab's keys, and a selection holding encrypted rows or folders
  asks for the unlock first - a folder may hide encrypted rows no listing
  has shown, so a folder share counts as keyed work too.
- **Re-sharing** (PERM_SHARE bit) works naturally: a grantee who holds a
  source key can wrap it to a third user. The *server still enforces*
  PERM_SHARE on the API, and the envelope is only created for authorized
  callers - crypto permission mirrors API permission instead of replacing
  it.
- **Batch shares** (`/api/shares/batch`) and per-row share UI fetch the
  grantee public key once per share; keys are cacheable (section 6, `GET
  /api/keys/<username>`), and a changed public key is caught before it is
  used (see key substitution below).

Server-side enforcement that must stay strict: a grantee's `enc_key`
values and share envelopes are only ever returned to rows the existing
share logic already authorizes. The crypto is a second lock, not the only
one - revoking a share must remove API access even if the grantee saved a
copy of the unwrapped key earlier (see 5.6 for the forward-looking part).

**Key substitution attack:** a malicious server could hand out its own
public key for a grantee, and the owner would happily encrypt to it.
Mitigations, in order of cost: (a) display a **key fingerprint** per user
in the share dialog so users can compare out of band, (b) trust on first
use with a visible "key changed" warning, (c) later: signed key
announcements. v1 ships (a) + (b); documented as accepted residual risk in
the meantime (DECISION 6).

Shipped as: the fingerprint appears the moment a grantee is picked, not at
confirm - it is there to be compared *while choosing*. First use is
remembered; a later fingerprint that differs is spelled out before
anything is sealed ("key changed: <now> (was <before>)") with the reason
it matters and the advice to compare out of band, and confirming or
declining it is the user's call. What is remembered lives in
`localStorage["fxcloud.peerfp"]`, one username-to-fingerprint map: **the
single exception to the "nothing in localStorage" rule of 11**, and it is
public data by construction - a hash of a published key opens nothing, and
no key material ever goes there.

Fingerprint definition, so two independent implementations agree byte for
byte: take the *published* key blob - one suite byte followed by the raw
public key - SHA-256 it, keep the first 16 bytes, and render them as 32
lowercase hex digits grouped as four blocks of eight, e.g.
`a1b2c3d4 e5f60718 293a4b5c 6d7e8f90`. 16 bytes is 128 bits of collision
resistance, comfortably beyond what a human comparing two strings out of
band can be talked past.

### 5.6 Revocation

Deleting a share row (today's `DELETE /api/shares/{id}`) stops API access
immediately. Cryptographically the grantee may have kept the unwrapped
key, so they can still read copies they already downloaded - unavoidable
and stated as such (revocation is about *future* access).

For genuinely future-proof revocation of a shared folder the owner can
**re-key**: generate a new folder key, re-wrap all children under it (one
client-side subtree walk), and re-wrap to every *remaining* grantee. The
old folder key held by the revoked grantee then opens nothing new.
Design: keep this as an explicit action ("Re-key folder" / automatic
after revoke), not automatic on every revoke - it costs O(subtree) wraps
and one round trip per remaining grantee (DECISION 4).

### 5.7 Passphrase, unlock, recovery, password change

- **Setup (once per account):** generate ARK, keypair, root folder key;
  derive KEK from the storage passphrase; upload `wrapped_ark`,
  `public_key`, wrapped private key, KDF salt + params, fingerprint.
- **Unlock:** happens on demand inside the tab - when the badge is
  clicked, or when an upload, download or bulk action needs the key. The
  setup/unlock/recovery dialog is the only prompt; there is no unlock step
  bolted onto login, so a user who never touches an encrypted file never
  sees it.
  **The one exception is the sign-in handoff.** When the row is wrapped
  under the login password (the DECISION 3 default), `login.js` parks that
  password in `sessionStorage` for the length of the redirect into the
  app, and the app page takes it and deletes it in the same tick - so the
  tab that just signed in unlocks without being asked for a string it was
  given a moment ago. What makes that safe: the row records which secret
  it is wrapped under (`kdf_params.secret`, written at setup and at
  recovery, and `login` is claimed only after the server agreed the string
  is the login password), so a `separate` row is never parked for; the
  value is read and removed together, so a reload during the derivation
  finds nothing; it expires after 60 s, because a value that old is a
  restored tab rather than a sign-in; and a wrong or tampered one is
  declined with the pane as the fallback. Unlocked keys live **in memory
  only** for the tab's lifetime; "Turn off for this tab" clears them, and
  so does a reload; no key material in `localStorage`/`sessionStorage`.
  Consequence: a second tab, or the same tab after a reload, starts
  **Unencrypted** - new writes are plaintext and the badge says so - and
  opening one of the account's encrypted files asks for the passphrase
  again (DECISION 7 discusses the UX tradeoff, DECISION 11 the writing
  rule that follows from it).
- **Passkeys are not part of this.** A WebAuthn sign-in (API.md,
  *Passkeys*) carries no password at all, so there is nothing to park for
  the redirect: the handoff above stays password-only, and the pane asks
  for the storage passphrase when a row needs it - the fallback it always
  was. The passkey authenticates the *session*; its private half never
  leaves the device and it unlocks nothing in this hierarchy.
- **Passphrase change:** derive new KEK, rewrap ARK, upload. O(1), no file
  re-encryption, no share re-wrapping.
- **Recovery:** if the passphrase is lost, the data is unrecoverable by
  design. A **recovery key** is generated at setup: a random 256-bit
  value, shown once as a downloadable file / printable code, which wraps
  ARK as an additional envelope the server stores. The server cannot use
  it (it stores only the wrapped copy); anyone holding the recovery file
  can. **Mandatory under DECISION 3**, because reusing the login password
  correlates the "forgot password" and "lost the data" failure modes into
  one event: setup must not complete until the recovery key is downloaded
  or the user explicitly confirms they accept losing everything.
- **Account deactivation / admin actions** stay server-side and untouched;
  they cut API access but can never yield plaintext.

`DECISION 3 - Storage passphrase: separate secret, or the login password?`
**DECIDED: reuse the login password as the default.** (Section 13, row 3.)

The two options were:
- Separate passphrase: strictly stronger (the DB's Argon2 hash reveals
  nothing usable), standard practice in restic/borg-style tools, but it
  is one more secret the user must not lose, and one more unlock prompt.
- Reuse the login password: one secret, one prompt; the server-side
  Argon2 hash becomes an offline attack surface for the encryption key
  too, so the client KDF must be strong enough to matter (Argon2id, high
  params) and password strength becomes load-bearing for file
  confidentiality.

Both derive through the same client-side Argon2id with a per-account
salt; only the input secret differs. The setup UI keeps the choice, with
"reuse login password" pre-selected and a "choose a separate passphrase"
alternative one click away - so the decision is the *default*, not a
straitjacket.

The three consequences that come with this default, which the
implementation must honor (each is a hard requirement, not a nice-to-have):

1. **The server-side login hash becomes the weak link for content
   confidentiality.** An attacker holding a DB dump only has to crack the
   *login* Argon2 hash - the client-side Argon2id cost no longer helps,
   because the server hash is a shortcut to the same input. Therefore
   raising the **login** KDF parameters is a condition of this decision:
   the login hash must be at least as expensive as we would demand of the
   client KDF (OWASP-class Argon2id with a per-user salt, memory cost in
   the 64 MiB range where the hardware allows it, and a parameter floor
   recorded in `kdf_params` so weaker hashes are detectable). This is
   checked in the implementation checklist for phase 1.
2. **Changing the password must rewrap ARK in the same flow.** After a
   login-password change the old KEK no longer opens the stored ARK, so
   the change endpoint's client side derives the new KEK and issues
   `PUT /api/keys/me` with the rewrapped ARK *in the same user action*.
   If either half fails, the UI must not report success - a half-changed
   password with a stale ARK wrap is a data-loss state. The rewrap needs
   the ARK in memory, i.e. the user must be unlocked while changing the
   password; the flow therefore requires unlock first and says so up
   front. Status: `PUT /api/keys/me` exists, applies the same KDF floor as
   setup, and has a round-trip test (the old passphrase stops opening the
   account, the new one opens what the server stored, and the root key is
   byte-identical afterwards). The *login password change* endpoint itself
   does not exist yet, so the two halves cannot currently drift apart -
   when it is added they have to ship in the same change.
3. **Correlated failure: one forgotten secret loses both the account and
   the data.** With a separate passphrase the two failure modes were
   independent. This default therefore makes the **recovery key**
   (5.7) mandatory in setup rather than optional: setup cannot complete
   without either downloading the recovery key or explicitly confirming
   "I understand that losing my password loses all my files".

`DECISION 7 - Unlock persistence.` In-memory only (recommended for v1:
a stolen laptop with an unlocked tab is the threat, and re-prompting per
tab is honest) vs. wrapping ARK with a device key stored in IndexedDB for
"stay unlocked for 30 days". Device keys are explicitly future work; the
ARK-wrapping design already accommodates them without format changes.

---

## 6. Server-side data model changes (draft)

New table `user_keys` (one row per user):

```
user_id            INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE
public_key         BLOB NOT NULL          -- raw public key + suite id prefix
private_key_wrapped BLOB NOT NULL         -- private key wrapped under ARK
wrapped_ark        BLOB NOT NULL          -- ARK wrapped under the passphrase KEK
wrapped_root_key   BLOB NOT NULL          -- root folder key wrapped under ARK (5.4)
wrapped_ark_recovery BLOB NOT NULL        -- ARK wrapped under the recovery KEK
kdf_salt           BLOB NOT NULL
kdf_params         TEXT NOT NULL          -- JSON: argon2 m/t/p, kdf suite id
fingerprint        TEXT NOT NULL          -- display + out-of-band compare
created_at, updated_at TEXT NOT NULL
```

`wrapped_ark_recovery` is **required, not optional**: under DECISION 3
(reuse-login-password default) the passphrase and the login secret are one
and the same event, so the recovery envelope is the only remaining path to
the data if it is forgotten. Setup rejects a payload without it; the
download of the recovery key itself is a client-side step (5.7).

Changed columns:

- `files.enc_version INTEGER NOT NULL DEFAULT 0` - 0 = plaintext,
  1 = "FXE1" format; lets every read path branch explicitly and lets the
  UI badge rows.
- `files.enc_key BLOB NULL` - the parent-wrapped file/folder key (5.4).

Changed column on the share table (shipped, migration
`008_share_envelopes.sql`):

```
shares.envelope  TEXT NULL    -- opaque base64 ECIES blob (5.5), <= 8192 chars
```

One column on `shares` rather than a table of its own: an envelope has
exactly one share's lifetime and is read by exactly the query that reads
shares (`GET /api/shares/incoming` hands it to the grantee), so a join
would buy nothing. The value stays opaque - the route checks only that it
is present-when-given and short enough, and never looks inside.

New endpoint:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/keys/setup` | upload key material at encryption setup (idempotent, owner only) |
| `GET /api/keys/me` | own public + wrapped material (for a second tab / future device flow) |
| `GET /api/keys/<username>` | public key + fingerprint for key exchange; 404 if not encrypted-enabled |
| `PUT /api/keys/me` | rewrap ARK (passphrase change) / rotate keypair later |
| `PUT /api/files/key` | store an entry's key record (a folder gaining its chain key, the re-bind a move or share performs); PERM_UPDATE, base64, a plaintext file answers 400 - folders are allowed, files need `enc_version = 1` |

Everything else - uploads, downloads, trash, quota, WebDAV - keeps its
existing API shape with two deliberate changes: `POST /api/shares/batch`
now takes `items: [{file_id, envelope?}]` instead of a bare id list (an
envelope belongs to one row, and a body that still says `file_ids` fails
to deserialize rather than silently sharing without one), and
`PUT /api/files/key` is new (table above). Otherwise only the
*interpretation* of the bytes changes on the client (section 7).
`PUT /api/files/content` gains two optional query
parameters, `enc` and `key`, with a fixed accepted matrix: `enc=1`
requires a non-empty base64 `key`, a `key` requires `enc=1`, and `enc=0`
may not carry one. `enc=1` on a plaintext row is what promotes it (the
two-phase upload in section 7); `enc=0` on an encrypted row is refused,
because the server holds no plaintext to put back. The body rule follows
from the same place: an `enc=1` write must begin with `FXE1`, and no other
write path ever looks at the first four bytes. One more rule guards the
key record behind that write (5.5): a caller who is not the row's owner may
pass the row's own record through unchanged, but not swap it - anything
else is `403 only the row's owner may change its key record`.

---

## 7. Impact on existing features

| Feature (code location) | Problem under encryption | Approach for v1 |
| --- | --- | --- |
| Upload `POST /api/files/upload` (plaintext path) | n/a - not used while the badge reads "Encrypted" | unchanged; the client calls it only while the badge reads "Unencrypted" (no key record yet, or keys not loaded in this tab), decided before anything is created and said out loud in the header - never behind an "Encrypted" badge (DECISION 11) |
| Encrypted upload (new two-phase path) | the multipart endpoint has nowhere to bind a key, because the client does not know the row's id until after the row exists | **(1)** `POST /api/files/file {parent_id, name}` reserves the row and returns its id - a duplicate name fails here, before a byte is read or encrypted; **(2)** the client encrypts against that id and `PUT /api/files/content?id=<id>&enc=1&key=<base64>` fills it. The wrapped key lands on a row that `create_file` always mints under the *uploader*, so the wrapper is this account's root key even when the destination folder belongs to someone else - no destination check is needed. Cancelling before step 1 creates nothing; a failure during step 2 deletes the half-made row and purges it from trash, so no 0-byte or half-filled row survives |
| Download `GET /api/files/download` | returns ciphertext | client fetches, decrypts in memory, saves via Blob URL |
| Preview `GET /api/files/preview` with `Range`, `nosniff`, `sandbox` | server cannot render or slice plaintext it does not have | **client-side preview: shipped.** The tab pulls the container from the download endpoint (the one route that serves ciphertext), the worker decrypts it, and the frame renders the plaintext from a Blob URL - images, video and audio in their own elements, PDF in the browser's own viewer, HTML in a frame that carries `sandbox=""` itself, because a Blob URL never reaches the server's `sandbox` header. While the bytes are still in flight the lightbox says "Decrypting preview..." rather than showing a half-built frame, and the "new tab" link is hidden: the URL only lives in this tab. The MIME type is chosen for the renderer (`mimeForPreview`), while a saved file keeps the harder octet-stream answer for HTML/SVG, so a download can never run on double-click. Server side unchanged: the preview endpoint still answers **400** for an `enc_version > 0` row rather than `image/png` for ciphertext, and encrypted files are never served inline. Still open: byte-range seeking inside a large video (decrypt the needed chunk ranges client-side) - today the whole file is decrypted into memory first, which bounds how big a video can usefully be previewed |
| Text editor `PUT /api/files/content` | reads and writes plaintext | **text editor round-trip: shipped.** The client decrypts on open - through the download endpoint, because `/api/files/preview` refuses ciphertext - encrypts on save and PUTs `enc=1&key=`; the server treats it as an opaque content update (same quota/mtime logic), and its 409 still guards the bare plaintext save. A file created while encryption is on is written as an empty container straight away, so a new row is never plaintext even briefly (`newFile()`), and a save keeps the row's file key, so envelopes sealed to it stay valid (DECISION 5). Key and bytes are written under a per-row lock, so two saves landing at the same moment cannot interleave into one save's `enc_key` beside another save's ciphertext: that state unwraps happily - the key is still bound to this row and the passphrase is right - and only fails the next time the file is opened, as `decryption failed for chunk 0` |
| Server-side ZIP `POST/GET /api/files/zip` | cannot zip plaintext it lacks | **client-side ZIP** for encrypted selections (JSZip-style, worker-based); keep server ZIP for plaintext files. DECISION 8 |
| WebDAV `GET`/`PUT`/`PROPFIND` | desktop clients do not encrypt | DECIDED (9): goal stays *flawless WebDAV*, delivered in two steps. Interim (v1): encrypted files are exposed **read-only as ciphertext** (visible, not hidden - the user sees the file exists) and `PUT` onto an `enc_version > 0` row is **rejected after validating the `FXE1` magic** - the server can do that without decrypting. Not blind-reject: a desktop client writing plaintext over a ciphertext row would otherwise destroy the file. The error body names the fix (web UI or sync agent). COPY refuses a subtree that contains a keyed file (a copy gets a new row id), and MOVE refuses a keyed row whose destination carries a different key record - WebDAV holds no keys to re-wrap with, so refusing beats a row that will not open again, while the web UI re-binds first (5.4). Target: `fxcloud sync` agent (see phases) makes DAV transparent again |
| `Content-Type` authority + HTML/SVG sandbox | server cannot know the real type | server's authoritative answer for `enc_version > 0` is `application/octet-stream; nosniff`, attachment disposition, `sandbox` on the response - always. Real types only ever materialize client-side |
| MIME sniffing and magic bytes (`extension_type`, `mime_guess`) | sniffing ciphertext yields nonsense, but a rule that rejects bytes because they *look* like something is just as much a trap for legitimate files | the `FXE1` magic check runs **only against rows with `enc_version > 0`**. Plaintext rows are never sniffed and no create path (web or WebDAV) is sniffed, so a genuine file that happens to begin `FXE1` is stored as-is; and an encrypted row can only ever be filled with bytes that really do begin `FXE1`. Net effect: an encrypted row accepts only an `FXE1` body (anything else 409), a plaintext row accepts any body whatever it starts with, and promotion to `enc_version = 1` happens only through an explicit `enc=1` + `key` write |
| Client-side rendering of decrypted HTML/SVG | **new risk:** Blob URLs inherit the page origin | decrypted HTML/SVG must render in an `<iframe sandbox>` **without** `allow-same-origin`, plus a restrictive CSP - replicating exactly what the server-side sandbox does for plaintext (see the `preview` handler comments in `src/web/routes/files.rs`). This must be a review item in implementation, not an afterthought |
| Quota, trash, restore, purge, move, rename | none - all metadata-level | untouched; trash keeps counting against quota exactly as now |
| Share list, permission masks, batch shares | none server-side; the envelope step runs client-side and lands in `shares.envelope` | **shipped** (phase 3): one envelope per item, sealed before the request, opaque to the server - section 5.5 |
| Full-text search (future) | would need plaintext | explicitly deferred; a client-side index is a later idea |

---

## 8. What the server still sees (accepted leakage, v1)

- user names, display names, quota, activation state
- full folder structure: names, sizes, mime *hint* for plaintext files,
  modified/deleted times, parent relations
- ciphertext sizes (leaking approximate plaintext size: within one chunk)
- that a file is encrypted (`enc_version`), and its opaque wrapped key
  record (`enc_key`) - both meaningless without the passphrase, and handed
  out only to the viewers the existing share logic already authorizes
- who shares what with whom, permissions, timestamps - plus the opaque key
  envelope sealed to the grantee, which opens with nothing the server ever
  sees (5.5)
- login times, IPs, request patterns

Encrypting names and structure (a "hidden vault" mode) is possible in a
later phase: names move into the encrypted payload, listings become
client-side filtered, WebDAV/breadcrumb/sort all move client-side. It
roughly doubles the UI work, so it stays out of v1 (NG1).

---

## 9. UX flows (what the user experiences)

1. **Enable encryption** (once): the header badge reads "Encrypt uploads"
   and opens the setup dialog - choose a storage passphrase (reusing the
   login password is the recommended default, since the server now applies
   the same KDF cost to both), then confirm. Argon2id runs in a worker for
   a few hundred ms; only afterwards does the one-time recovery key appear,
   with a download button, and the dialog cannot be dismissed until it is
   acknowledged: *losing both passphrase and recovery key means losing
   every encrypted file*.
2. **Unlock / the badge:** the badge answers exactly one question - *are
   new writes encrypted in this tab?* - and reads "Encrypt uploads"
   before setup, "Unencrypted" when the keys exist but are not loaded
   (files and uploads are stored as-is), and "Encrypted" once they are in
   memory. A tab that just signed in with the login password opens the
   folder as "Encrypted" without a prompt: sign-in carries that password
   across the page load and the app takes it once (5.7). Otherwise the
   badge reads "Unencrypted", and clicking it opens a passphrase field -
   which is also the only way an encrypted row can be opened, since those
   bytes cannot be read any other way. Each encrypted row carries a small
   lock badge, and features that need a key (preview, edit, WebDAV writes
   onto an encrypted row) explain why rather than failing silently. Every
   reload and every new tab starts Unencrypted by design.
3. **Upload:** indistinguishable from today; the encryption step happens
   in a Web Worker while a progress bar shows encrypt-then-upload. The
   batch follows the badge rather than a prompt, and the decision is taken
   *before* anything is created: an "Encrypted" tab encrypts, an
   "Unencrypted" tab uploads as-is and the progress line says so. Two
   properties follow, and both are the point of the rule: plaintext is
   never written behind an "Encrypted" badge, and no passphrase is ever
   demanded for a write the badge already describes (DECISION 11).
   Small caveat: the server buffers uploads in memory today (constraint
   7), so very large files are already limited before encryption is
   considered - unchanged by this concept.
4. **Download:** transparently decrypted client-side and saved under the
   original name. **Edit** works the same way for text files: opening
   decrypts, saving re-encrypts, and a file created while encryption is on
   is stored as an empty container at once - so "everything new is
   encrypted" holds without any conversion step. **Preview** works on an
   encrypted row now too: the tab pulls the container, the worker decrypts
   it, and the frame renders the plaintext from a Blob URL - images, video
   and audio in their own elements, PDF in the browser's own viewer, HTML
   in a `sandbox`ed frame - while the "new tab" link stays hidden, because
   that URL only lives in this tab (5.3).
5. **Share** *(phase 3, shipped)*: the dialog lists accounts as before and
   adds three things. The grantee's **key fingerprint** appears the moment
   they are picked - four blocks of eight hex digits, meant to be read out
   loud and compared before anything is handed over; the first fingerprint
   is remembered, and a later one that changed is shown as exactly that
   ("key changed: ... (was ...)") with a confirm/decline in front of it.
   Sealing an envelope needs this tab's keys, so a selection holding
   encrypted rows or folders asks for the passphrase first (a folder may
   hold encrypted rows no listing has shown). Each selected row is then
   sealed to the grantee's published key - one envelope per row, batched
   into one request - and an account without encryption of its own gets
   that said out loud instead: the plaintext share still works, anything
   encrypted would stay unreadable for them. On the grantee's side nothing
   extra is asked: unlock as usual, and the mounts open - the envelope for
   the top row, one unwrap per folder level below it, the file's own record
   last. Moving an encrypted file follows the same rule as opening one:
   without keys the move waits for the unlock prompt, because its record
   has to be re-wrapped for the destination before the row travels (5.4).
6. **Locked out?** Every new tab starts Unencrypted; the passphrase turns
   encryption back on for that tab, and the recovery key is accepted
   instead of the passphrase - it opens the same account root key and
   rewraps the outer shell under a new passphrase in one flow.

---

## 10. Migration of existing plaintext data

- v1 does **not** re-encrypt anything automatically. Existing files keep
  `enc_version = 0` and behave exactly as today.
- A user can run **"Encrypt existing files"**: a client-side batch job
  (download -> encrypt -> upload -> replace row) that walks the tree,
  shows progress, is resumable, and pauses on quota pressure (ciphertext
  adds a few bytes per chunk, so peak usage grows slightly).
- Per-folder toggle means users can encrypt a subtree first and keep the
  rest compatible with WebDAV while evaluating.
- Rollout safety: every read path branches on `enc_version`, so mixed
  trees are a normal, tested state - not an edge case.

---

## 11. Engineering notes

- The two genuinely slow operations - the Argon2id run (64 MiB x 3) and
  whole-file chunk encryption - run in a **Web Worker** (`fxworker.js`) so
  the UI does not block. Everything short (key generation, wrapping a
  32-byte value, fingerprints) stays on the calling thread: moving those
  would mean shipping key material across a thread boundary for no gain.
  The worker's op names and argument lists are exactly `fxcrypto.js`'s, so
  an engine without a usable Worker falls back to the identical call on the
  page instead of failing.
- Keys live in **memory only** - one object in the page that holds the
  opened ARK, root key and private key. Nothing goes to localStorage,
  sessionStorage, cookies or a cached response body, with **one documented
  exception: `localStorage["fxcloud.peerfp"]`** (5.5, DECISION 6), a map of
  username to *public* key fingerprint for trust-on-first-use - a hash of a
  published key, useful to nobody who steals it, and never key material.
  The single value that
  does cross a page load is the login password itself, parked by
  `login.js` for the length of the redirect into the app and deleted by
  `fxenc.js` on its first read (5.7): the string the user has just typed,
  never the row's key material, and never for a row marked
  `secret: separate`. The worker keeps no state between messages: it is
  given bytes, it returns bytes, it forgets them. "Turn off" therefore
  just drops the references, and because the handoff is consumed once, a
  reload lands back on Unencrypted - each tab proves the passphrase
  itself before it encrypts anything again.
- WASM dependency for Argon2id is the only new third-party crypto
  dependency; everything else is WebCrypto (audited by the browser
  vendor). No hand-rolled primitives.
- The server never links against a crypto library beyond what login
  already uses (argon2 for passwords). It gains BLOB columns and copy
  logic - envelope rows are copied when a share is copied, dropped by
  `ON DELETE CASCADE` when a share or file dies (trash -> purge already
  cascades).
- Testing: the suite now runs **475 checks**. The additions cover the key
  endpoints (server-side KDF floor, idempotent setup, 409 when a second
  differing payload arrives, rewrap round trip, what
  `GET /api/keys/<username>` does and does not expose), the encrypted
  write matrix (`enc`/`key` combinations, FXE1 body rule, preview and ZIP
  refusal), the copy refusal, WebDAV's opaque view of an encrypted row,
  and one real encrypt -> upload -> download -> decrypt trip driven through
  the HTTP API by the very `fxcrypto.js` the browser loads. The key
  exchange of 5.5 has its own set: `PUT /api/files/key` answering the
  owner, a read-only grantee (403) and a plaintext file (400), a breadcrumb
  that carries the record of each keyed level from an id-less Home crumb
  onward, an envelope arriving in the grantee's inbox byte for byte while a
  share sent without one stays without it, the 8 KiB envelope cap checked
  before the first share of a batch, the retired `file_ids` body refused,
  a grantee's save passing their own record through while a different one
  is refused by name, a prepared JSON move of an encrypted row crossing key
  domains against WebDAV's 409 on the same travel, and a keyed folder of
  plaintext files copying into an unkeyed copy. A second
  harness runs `fxenc.js` itself - the file that picks every argument and
  every request body - behind a fake DOM and a cookie-carrying fetch, and
  drives the real browser path end to end: unlock through the pane,
  `encryptUpload` -> `download` byte for byte, `writeText` -> `readText`
  with the file key kept across saves (DECISION 5), a reopen that goes
  through a *fresh listing* instead of the object the save handed back,
  overlapping saves of one row, a new file encrypted before anything can
  read it, an upload into a folder that keys that folder and chains the
  file under it, an ECIES envelope opened by the recipient alone while the
  wrong recipient, the wrong row and the wrong grantee are each refused,
  the sealed folder key walked down to the file's actual bytes by a peer
  key that never saw the owner's root key, an encrypted row moved both
  ways through a re-bind-before-move trip that still decrypts after it,
  and a preview (5.3) that pulls each of an image, a PDF and an HTML file
  and gets back the same bytes typed for the renderer, while the download
  of that same HTML name stays octet-stream. Two further checks hold the badge to its word from both ends: `fxenc.js`
  has to render "Unencrypted" for a tab whose keys are not loaded and
  "Encrypted" once they are, and `app.js` may no longer gate a write on
  `enabled()` at all (DECISION 11).
  It runs twice - once with `Worker` undefined, the documented
  main-thread fallback, and once with a Worker whose message handler is
  the real `fxworker.js` source, cloned on both hops the way a browser
  serialises them: that is the path a browser tab always takes, and
  nothing else in the suite could see it. That module is what both of
  this release's frontend bugs hid in: a
  scrambled `encryptBytes(plain, id, fileKey)` died with "expected a
  256-bit file key" on every upload while the suite stayed green, because
  the suite reached encryption through `fxtool.js`, which calls the same
  primitives in the right order. The crypto
  itself has its own round-trip harness (DECISION 10: 31 checks over the
  same WebCrypto code paths), every frontend source file gets a parse
  check so a syntax error cannot sit unnoticed until someone unlocks, and
  every frontend call site is checked against the signature it calls - an
  argument dropped on the way parses perfectly and surfaces only as a 400
  in a user's browser, which is how the encryption setup answered 400 for
  every user of the previous release. The save path is pinned the same
  way, for the same reason - nothing on the wire shows it: a save refreshes
  the folder before it checks whether that file is still open in the
  editor. The other order skips the refresh whenever the lightbox closes
  during the round trip, and every row then keeps the previous wrapped key
  - which still unwraps, so the next open fails much further down, as
  `decryption failed for chunk 0`. The setup dialog's wiring is pinned
  as well: the pre-selected default of section 5.7, the alternative beside
  it, and the `/api/login` re-check it runs from inside an existing
  session. The sign-in handoff is covered from both ends: the harness
  parks a secret and asserts that the tab opens without the pane, that a
  wrong, stale or `separate`-marked row declines it and clears the spot in
  every case, and that the pane still unlocks afterwards; two pins hold the
  `login.js` side, because neither of its failure modes throws - the
  secret has to be parked before the redirect, and never for a row whose
  passphrase is a separate one. The share dialog and the encrypted move are
  pinned the same way, for the same reason: the dialog has to seal one
  envelope per item into the `items` body (the retired `file_ids` field
  answers 422 server-side now), show the fingerprint while the grantee is
  being picked and keep its TOFU record in the one documented localStorage
  place; and `transferConfirm` has to re-bind each keyed row *before* the
  move request - afterwards the record would name a folder the row is not
  under yet, which surfaces much later as a file that will not open rather
  than as an error now.

---

## 12. Phases

| Phase | Scope | Rough size |
| --- | --- | --- |
| 0 | This concept reviewed and DECISIONs answered | **done** - see section 13 |
| 1 | Key setup, unlock, encrypt-on-upload, decrypt-on-download; **login KDF params raised (condition of DECISION 3)**; recovery key mandatory at setup; UI limited to the header badge plus the setup / unlock / recovery dialog - no preview, no client-side ZIP | **released since v0.0.9** |
| 2 | Text editor round-trip (**shipped**: decrypt on open, encrypt on save, and a file created while encryption is on stored encrypted from its first second), client-side preview for images/video/audio/PDF/HTML (**shipped**: the tab decrypts and renders from a Blob URL, section 7), client-side ZIP - still one download per row rather than one archive (the server's ZIP refuses ciphertext, so an encrypted selection decrypts each row in the tab and saves it; a real in-browser ZIP writer stays open) | makes daily use possible |
| 3 | Sharing: key exchange, envelopes, fingerprints, revoke | **done** - shipped in this release: folder-key hierarchy filled in lazily (5.4), share-time subtree migration and one envelope per share row (5.5), fingerprint shown while picking + TOFU with a changed-key warning (DECISION 6), owner-only swap of a key record, re-bind-before-move. Folder re-key on revoke stays phase 6 (DECISION 4) | G3 satisfied |
| 4 | Migration tool ("Encrypt existing files"), per-folder encrypt toggle, recovery-key UX refinements | G5 satisfied |
| 5 | **`fxcloud sync` agent** - local daemon doing encrypt/decrypt between Finder/Explorer and the unchanged DAV API; this is what makes WebDAV *flawless* (DECISION 9), so it is a committed deliverable, not "later, independent" | largest single item; own milestone |
| 6 | Folder re-key, key rotation action, (optional) metadata encryption | later, independent |

Phase 5 moved from "later, independent" to a committed phase because
DECISION 9 sets flawless WebDAV as a requirement, and no browser-side
design can meet it: Finder/Explorer mount an HTTP endpoint, so the
encryption has to happen in a local component. The interim that shipped
with phase 1 - encrypted rows stay visible over WebDAV as ciphertext, and
`PUT` is checked against the `FXE1` magic instead of being blindly
accepted or blindly rejected - is the bridge, not the destination.

Each phase ships independently; nothing before phase 3 changes the
security story beyond "content at rest is protected".

---

## 13. Decisions (summary)

| # | Question | Recommendation | Decision |
| --- | --- | --- | --- |
| 1 | X25519 vs P-256 | X25519 first, suite field in format, P-256 as fallback suite | implement as recommended |
| 2 | Encryption granularity | flag per file, UX per folder + account switch | implement as recommended |
| 3 | Storage passphrase vs login password | separate passphrase; optional "reuse login password" checkbox | **reuse login password as default** (choice kept in setup UI). Conditions binding: (a) raise server login KDF params, (b) password change rewraps ARK in the same flow, (c) recovery key mandatory at setup - details in 5.7 |
| 4 | Re-key on revoke | explicit/optional action, not automatic | implement as recommended |
| 5 | Key rotation on overwrite | no; explicit rotate action later | implement as recommended |
| 6 | Malicious-server / key-substitution | fingerprints + TOFU now; signed keys later; reproducible builds out of scope | implement as recommended |
| 7 | Unlock persistence | memory-only per tab in v1; device keys later | implement as recommended - plus the sign-in handoff of 5.7: for a `secret: login` row the login password is parked for the length of one redirect, taken once and cleared on read, so the tab that just signed in is not asked again. Nothing else is ever written, a `separate` row is never parked for, and a reload puts the badge back to Unencrypted |
| 8 | ZIP | client-side for encrypted, server-side stays for plaintext | implement as recommended |
| 9 | WebDAV | hide/deny-write encrypted files in v1; sync agent later | **must work flawlessly.** Split: interim = encrypted files visible read-only as ciphertext + `PUT` rejected after `FXE1` magic check (never blind); target = `fxcloud sync` agent, promoted to committed phase 5. Detail in 7 + 12 |
| 10 | Test strategy for client crypto | WebCrypto round-trip harness in CI + API visibility tests | implement as recommended |
| 11 | Write rule while the keys are not loaded | first cut: a locked tab stops new writes and asks to unlock (9, flow 3) | **revised after v0.0.12 - follow the badge.** The two write paths (`newFile`, `uploadTree`) gate on `unlocked()`, not `enabled()`: an "Unencrypted" tab writes plaintext under a badge that says so, an "Encrypted" tab encrypts. Opening an encrypted row still prompts, because those bytes cannot be read any other way. See 9, flows 2-3 |
| 12 | Shape of phase-3 sharing: one envelope per *file*, or the folder hierarchy the concept already describes? | concept as written (5.2 + 5.5): parent-wraps-child folder keys, one envelope per share row | **implement the concept as written.** Folder keys appear lazily (first encrypted write below a folder, or the subtree walk a share performs), one envelope per share row carries the folder key, and the server stays key-blind: PERM_UPDATE is the whole check on `PUT /api/files/key` and on the JSON move, while WebDAV keeps the key-domain refusal because it holds no keys at all. A move re-binds before it travels (and rolls back if refused); a save never rotates the key (DECISION 5); a grantee may pass their own record back but not swap it. Legacy flat rows keep opening through the root-key fallback, which no grantee ever has. Detail in 5.4 + 5.5 |

---

## 14. References

- NIST SP 800-38D - GCM (chunk nonce and AAD practice)
- RFC 9180 - HPKE (the pattern ECIES in 5.5 follows, simplified)
- RFC 5869 - HKDF
- OWASP Password Storage Cheat Sheet (Argon2id parameters for the KEK)
- Nextcloud E2EE and Tresorit/Mega design write-ups (prior art for
  envelope-per-share and folder key hierarchies)
- Web Crypto API - AES-GCM, HKDF, ECDH, X25519 availability
