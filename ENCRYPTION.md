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
   ECIES(recipient_public_key, source key record)  ->  stored next to the share row
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
- **Phase 1 has no folder keys yet** (no folder carries an `enc_key`), so
  in practice every key record is wrapped directly with the root folder
  key. The hierarchy above is what phase 3 fills in; the wrap call, the
  AAD and the stored column are already the final shape.

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

Consequences (all desired):

- Renaming, trashing, restoring, moving: **no key operation at all** -
  keys travel with the row, and the row never moves (constraint 5); the
  AAD is `child_id || version`, not the name and not the parent. Today no
  folder carries a key, so every destination is in the same key domain and
  `db::move_entry` simply allows it. Once folders have keys (phase 3) a
  move across domains refuses rather than mis-wrapping: one client-side
  re-wrap is required, and the row turns away with a 409 until it happens.
- Copying a file creates a new row with a new id, so the key record cannot
  come along with it: phase 1 refuses the copy with a 409 and the user
  downloads and re-uploads instead. Phase 3 wraps a fresh key copy (or
  reuses the key - DECISION 5) under the destination folder key, which is
  the version that makes copy useful again.
- Replacing content (upload over existing file, editor save): if the
  writer already holds the file key, content is re-encrypted under it and
  `enc_key` does not change; other grantee envelopes stay valid.

`DECISION 5 - Does content replacement rotate the file key?`
Rotating on every overwrite is safer against a leaked old key but forces
re-wrapping every grantee envelope on every save. Recommendation: **no
rotation on overwrite (the legitimate writer already holds the key),
explicit "rotate key" action available in the UI later.**

### 5.5 Sharing as key exchange

Share creation today: `POST /api/shares {source_id, username, permissions}`
resolves the grantee and inserts a row. With encryption the flow becomes:

```
owner browser                         server                    grantee
-------------                         ------                    ------
unlock (holds source key record,
        has grantee public key)  -->
                    GET /api/keys/<username>  ----------------->  returns public_key,
                                                                  fingerprint
wrap: env = ECIES(grantee_pub, source_key_record)
                    POST /api/shares {source_id, username, perms, env}
                                      inserts share row +
                                      stores env in file_keys  -->
                                                                grantee unlocks,
                                                                GET own share envelopes,
                                                                unwraps env with private
                                                                key -> source key record,
                                                                then unwraps subtree
```

Key points:

- **One envelope per share row**, not per file. For a folder share the
  envelope carries the folder key; the grantee walks down the hierarchy
  because every child key is wrapped with its parent's key and every row
  (including `enc_key`) is readable by anyone holding share READ.
- **Adding files to a shared folder is free:** the uploader wraps the new
  file key with the folder key it already holds. Existing grantees gain
  access through their existing folder-key envelope. No re-share step, no
  grantee list consulted client-side.
- **Re-sharing** (PERM_SHARE bit) works naturally: a grantee who holds a
  source key can wrap it to a third user. The *server still enforces*
  PERM_SHARE on the API, and the envelope's existence is only created for
  authorized callers - crypto permission mirrors API permission instead of
  replacing it.
- **Batch shares** (`/api/shares/batch`) and per-row share UI need the
  grantee public key fetched once per share; keys are cacheable
  (section 6, `GET /api/keys/<username>`), but a changed public key must
  invalidate the cache (see key substitution below).

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
  sees it. Unlocked keys live **in memory only** for the tab's lifetime;
  "Lock now" clears them, and so does a reload; no key material in
  `localStorage`/`sessionStorage`. Consequence: a fresh tab requires
  re-entering the passphrase (DECISION 7 discusses the UX tradeoff).
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

New table `share_envelopes` (one row per share):

```
share_id    INTEGER PRIMARY KEY REFERENCES shares(id) ON DELETE CASCADE
suite       INTEGER NOT NULL
envelope    BLOB NOT NULL                 -- ephemeral pub || nonce || wrapped key record
created_at  TEXT NOT NULL
```

(Could alternatively be a column on `shares`; separate table keeps the
existing share queries untouched - `ON DELETE CASCADE` mirrors share
lifetime exactly.)

New endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/keys/setup` | upload key material at encryption setup (idempotent, owner only) |
| `GET /api/keys/me` | own public + wrapped material (for a second tab / future device flow) |
| `GET /api/keys/<username>` | public key + fingerprint for key exchange; 404 if not encrypted-enabled |
| `PUT /api/keys/me` | rewrap ARK (passphrase change) / rotate keypair later |

Everything else - uploads, downloads, trash, shares, quota, WebDAV - keeps
its existing API shape; only the *interpretation* of the bytes changes on
the client (section 7). `PUT /api/files/content` gains two optional query
parameters, `enc` and `key`, with a fixed accepted matrix: `enc=1`
requires a non-empty base64 `key`, a `key` requires `enc=1`, and `enc=0`
may not carry one. `enc=1` on a plaintext row is what promotes it (the
two-phase upload in section 7); `enc=0` on an encrypted row is refused,
because the server holds no plaintext to put back. The body rule follows
from the same place: an `enc=1` write must begin with `FXE1`, and no other
write path ever looks at the first four bytes.

---

## 7. Impact on existing features

| Feature (code location) | Problem under encryption | Approach for v1 |
| --- | --- | --- |
| Upload `POST /api/files/upload` (plaintext path) | n/a - this path is not used once encryption is on | unchanged; it is reachable only while the account has no key record, because once keys exist an upload is never silently downgraded to plaintext |
| Encrypted upload (new two-phase path) | the multipart endpoint has nowhere to bind a key, because the client does not know the row's id until after the row exists | **(1)** `POST /api/files/file {parent_id, name}` reserves the row and returns its id - a duplicate name fails here, before a byte is read or encrypted; **(2)** the client encrypts against that id and `PUT /api/files/content?id=<id>&enc=1&key=<base64>` fills it. The wrapped key lands on a row that `create_file` always mints under the *uploader*, so the wrapper is this account's root key even when the destination folder belongs to someone else - no destination check is needed. Cancelling before step 1 creates nothing; a failure during step 2 deletes the half-made row and purges it from trash, so no 0-byte or half-filled row survives |
| Download `GET /api/files/download` | returns ciphertext | client fetches, decrypts in memory, saves via Blob URL |
| Preview `GET /api/files/preview` with `Range`, `nosniff`, `sandbox` | server cannot render or slice plaintext it does not have | **client-side preview:** download, decrypt, render from a Blob; for video/audio, decrypt chunk ranges client-side later. Until that lands (phase 2) the server answers **400** for an `enc_version > 0` row rather than `image/png` for ciphertext, and the UI disables the row click on such rows so no `<img>`/`<iframe>` is ever handed undecodable bytes. Encrypted files are never served inline |
| Text editor `PUT /api/files/content` | reads and writes plaintext | **phase 2, not in this release:** client decrypts on open, encrypts on save, PUTs ciphertext; the server treats it as an opaque content update (same quota/mtime logic). Until then an encrypted row has no editor at all - the UI hides Edit/Preview on it, and a bare save returns 409 rather than silently replacing ciphertext with plaintext |
| Server-side ZIP `POST/GET /api/files/zip` | cannot zip plaintext it lacks | **client-side ZIP** for encrypted selections (JSZip-style, worker-based); keep server ZIP for plaintext files. DECISION 8 |
| WebDAV `GET`/`PUT`/`PROPFIND` | desktop clients do not encrypt | DECIDED (9): goal stays *flawless WebDAV*, delivered in two steps. Interim (v1): encrypted files are exposed **read-only as ciphertext** (visible, not hidden - the user sees the file exists) and `PUT` onto an `enc_version > 0` row is **rejected after validating the `FXE1` magic** - the server can do that without decrypting. Not blind-reject: a desktop client writing plaintext over a ciphertext row would otherwise destroy the file. The error body names the fix (web UI or sync agent). Target: `fxcloud sync` agent (see phases) makes DAV transparent again |
| `Content-Type` authority + HTML/SVG sandbox | server cannot know the real type | server's authoritative answer for `enc_version > 0` is `application/octet-stream; nosniff`, attachment disposition, `sandbox` on the response - always. Real types only ever materialize client-side |
| MIME sniffing and magic bytes (`extension_type`, `mime_guess`) | sniffing ciphertext yields nonsense, but a rule that rejects bytes because they *look* like something is just as much a trap for legitimate files | the `FXE1` magic check runs **only against rows with `enc_version > 0`**. Plaintext rows are never sniffed and no create path (web or WebDAV) is sniffed, so a genuine file that happens to begin `FXE1` is stored as-is; and an encrypted row can only ever be filled with bytes that really do begin `FXE1`. Net effect: an encrypted row accepts only an `FXE1` body (anything else 409), a plaintext row accepts any body whatever it starts with, and promotion to `enc_version = 1` happens only through an explicit `enc=1` + `key` write |
| Client-side rendering of decrypted HTML/SVG | **new risk:** Blob URLs inherit the page origin | decrypted HTML/SVG must render in an `<iframe sandbox>` **without** `allow-same-origin`, plus a restrictive CSP - replicating exactly what the server-side sandbox does for plaintext (see the `preview` handler comments in `src/web/routes/files.rs`). This must be a review item in implementation, not an afterthought |
| Quota, trash, restore, purge, move, rename | none - all metadata-level | untouched; trash keeps counting against quota exactly as now |
| Share list, permission masks, batch shares | none server-side; add envelope step client-side | section 5.5 |
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
- who shares what with whom, permissions, timestamps
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
2. **Unlock:** the badge reads "Locked"; clicking it opens a passphrase
   field. After unlock, no visible difference - except each encrypted row
   carries a small lock badge, and locked features (WebDAV writes,
   preview, edit) explain why rather than failing silently. Every new tab
   starts locked again by design.
3. **Upload:** indistinguishable from today; the encryption step happens
   in a Web Worker while a progress bar shows encrypt-then-upload. If the
   account has keys but the tab is locked, the batch stops and asks to
   unlock *before* anything is created - it never quietly writes plaintext.
   Small caveat: the server buffers uploads in memory today (constraint
   7), so very large files are already limited before encryption is
   considered - unchanged by this concept.
4. **Download:** transparently decrypted client-side and saved under the
   original name. **Preview and edit** decrypt the same way but arrive in
   phase 2; until then those menu entries are hidden on encrypted rows.
5. **Share** *(phase 3)*: the share dialog additionally shows the
   grantee's key fingerprint; on first share a "key changed?" warning
   appears if a cached public key differs.
6. **Locked out?** Unlock prompt on every new tab, recovery key accepted
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
  sessionStorage, cookies or a cached response body. The worker keeps no
  state between messages: it is given bytes, it returns bytes, it forgets
  them. "Lock" therefore just drops the references (and a reload lands back
  in the locked state, which is the intended behaviour: each tab proves the
  passphrase itself).
- WASM dependency for Argon2id is the only new third-party crypto
  dependency; everything else is WebCrypto (audited by the browser
  vendor). No hand-rolled primitives.
- The server never links against a crypto library beyond what login
  already uses (argon2 for passwords). It gains BLOB columns and copy
  logic - envelope rows are copied when a share is copied, dropped by
  `ON DELETE CASCADE` when a share or file dies (trash -> purge already
  cascades).
- Testing: the suite now runs **183 checks**. The additions cover the key
  endpoints (server-side KDF floor, idempotent setup, 409 when a second
  differing payload arrives, rewrap round trip, what
  `GET /api/keys/<username>` does and does not expose), the encrypted
  write matrix (`enc`/`key` combinations, FXE1 body rule, preview and ZIP
  refusal), the copy refusal, WebDAV's opaque view of an encrypted row,
  and one real encrypt -> upload -> download -> decrypt trip driven through
  the HTTP API by the very `fxcrypto.js` the browser loads. The crypto
  itself has its own round-trip harness (DECISION 10: 31 checks over the
  same WebCrypto code paths), and every frontend source file gets a parse
  check so a syntax error cannot sit unnoticed until someone unlocks.

---

## 12. Phases

| Phase | Scope | Rough size |
| --- | --- | --- |
| 0 | This concept reviewed and DECISIONs answered | **done** - see section 13 |
| 1 | Key setup, unlock, encrypt-on-upload, decrypt-on-download; **login KDF params raised (condition of DECISION 3)**; recovery key mandatory at setup; UI limited to the header badge plus the setup / unlock / recovery dialog - no preview, no editor, no client-side ZIP | **implemented, not yet released** |
| 2 | Client-side preview, text editor round-trip, client-side ZIP | makes daily use possible |
| 3 | Sharing: key exchange, envelopes, fingerprints, revoke | G3 satisfied |
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
| 7 | Unlock persistence | memory-only per tab in v1; device keys later | implement as recommended |
| 8 | ZIP | client-side for encrypted, server-side stays for plaintext | implement as recommended |
| 9 | WebDAV | hide/deny-write encrypted files in v1; sync agent later | **must work flawlessly.** Split: interim = encrypted files visible read-only as ciphertext + `PUT` rejected after `FXE1` magic check (never blind); target = `fxcloud sync` agent, promoted to committed phase 5. Detail in 7 + 12 |
| 10 | Test strategy for client crypto | WebCrypto round-trip harness in CI + API visibility tests | implement as recommended |

---

## 14. References

- NIST SP 800-38D - GCM (chunk nonce and AAD practice)
- RFC 9180 - HPKE (the pattern ECIES in 5.5 follows, simplified)
- RFC 5869 - HKDF
- OWASP Password Storage Cheat Sheet (Argon2id parameters for the KEK)
- Nextcloud E2EE and Tresorit/Mega design write-ups (prior art for
  envelope-per-share and folder key hierarchies)
- Web Crypto API - AES-GCM, HKDF, ECDH, X25519 availability
