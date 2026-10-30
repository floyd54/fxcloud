# Concept: streaming large files (decided)

Status: decided 2026-10-30. Implementation order: **1 of 3** - first,
because it is a small mechanical foundation (no visible feature) that
the versioning work builds on and that everything else benefits from.

## 1. Goal

Constant server memory on every content path regardless of file size,
byte ranges on the download route (video seeking without a full
transfer), a robust WebDAV up to its 4 GiB limit, and - in S2 - a
browser that no longer holds large encrypted files in the JS heap.

## 2. What it builds on: the measured bottlenecks

| Path | Today | Problem |
| --- | --- | --- |
| Upload (multipart) | `field.bytes().to_vec()` | RAM = file size (cap 1 GiB) |
| Editor save | `body: Bytes` | RAM = file size |
| WebDAV PUT | `to_bytes(4 GiB)` + `.to_vec()` | up to ~8 GiB peak (double copy) |
| Download / preview / DAV GET | `read_blob` -> `Vec<u8>` | RAM = file size; ranges slice from memory, only on preview |
| Client (E2EE upload) | `file.arrayBuffer()` | JS heap = file size + ciphertext |
| ZIP builder | **streams already** | the pattern to reuse (`blob_path` is public for it) |

Range parsing (`parse_byte_range`, 206/416 semantics) already exists and
is tested - it is just wired to a buffer instead of a file.

## 3. S1 - server pipes (this work-line)

**Temp pipeline** (one helper, all write paths):

- `data_dir/tmp/<uuid>.part` - same filesystem as the blobs, so the
  commit is a `rename` (atomic, no copies, constant memory).
- Count while writing; a per-file count above `max_upload_bytes`
  aborts with **413** and removes the temp file. The existing
  `DefaultBodyLimit` stays as the outer request guard.
- MIME sniffing from a **prefix sample** (first 8 KiB): magic numbers
  and the FXE1 check only need the head; the text heuristic reads the
  sample instead of the whole buffer (documented behavior change: type
  detection is decided on the head of the file).
- Error paths: temp removed, metadata row rolled back - the pairing
  rules of `begin_replace` are unchanged.
- Startup sweep removes stale `*.part` files (the precedent is the
  flat-blobs migration; no upload survives a restart).

**Write paths become one shape:**

1. `POST /api/files/upload` - chunk loop over the file field instead of
   `bytes()`; metadata fields stay `text()`; field order irrelevant
   (temp path exists as soon as the file field starts).
2. `PUT /api/files/content` (editor) - consume the body as a stream;
   FXE1 magic and the `enc`/`key` matrix are checked on the prefix /
   after the fact on sizes, never on a fully buffered body.
3. WebDAV `PUT` - stream instead of `to_bytes` + `.to_vec()`;
   `MAX_PUT_BYTES` becomes a counted cap (413), not a buffer size.

**Read paths stream:**

- New `open_blob(user_id, file_id)` -> `(FileEntry, File, len)` next to
  `read_blob`, with the same permission check, `is_dir` refusal, blob
  path + legacy fallback (open instead of read).
- `GET /api/files/download`: streaming body, `Content-Length` from file
  metadata, **`Accept-Ranges: bytes`** and full `Range` handling
  (206/416 + `Content-Range`) - decision 10: same behavior as preview.
- `GET /api/files/preview`: same shared range helper, body streamed
  instead of sliced from a buffer; the encrypted-row branches stay
  byte-for-byte as they are.
- WebDAV `GET`: streaming body.
- `copy_recursive`: filesystem-level copy where it currently reads and
  rewrites (verified during implementation).
- ZIP: untouched (already streams).

No API shape changes: same routes, same headers, same status codes -
only the memory profile and the new range support on download.

## 4. S2 - client E2EE chunking (separate work-line, later)

- FXE1 is chunked AES-GCM already, so encrypt via
  `file.slice(offset, offset + CHUNK)` - a **disk-backed view, not a
  heap copy** - and collect ciphertext chunks into `new Blob(parts)`
  (disk-backed as well); the browser streams that Blob to FormData from
  disk. Heap drops from O(file) to O(chunk).
- Download decrypt mirrors it: `res.body.getReader()` chunkwise into
  Blob parts.
- **Format stability:** same nonce/chunk order as today - files
  encrypted by the old code stay readable, old code reads new files.
- Honest limit: browsers cannot stream a multipart request body
  themselves; FormData + Blob is the way, and the server receives it
  streamingly after S1.

## 5. S3 - out of scope (noted, not planned)

Resumable uploads (upload IDs / PATCH), WebDAV versioning extensions,
CDN-oriented range caching. The `fxcloud sync` agent (ENCRYPTION phase
5) owns large-file sync anyway.

## 6. Security

- Temp under `data_dir` (owner-only directory, same FS as blobs) - no
  foreign temp domain; startup sweep so abandoned bytes do not linger.
- Hard caps preserved and enforced while counting (413), sniffing only
  ever parses a bounded prefix, Range parser untouched (416, no
  multi-range), crypto untouched.
- No new endpoints, no schema change - only the way bytes travel.

## 7. Test strategy

Source pins: no `field.bytes()` on content, no `to_bytes`/`.to_vec()`
in WebDAV, temp sweep present. Functional: `curl -r` -> 206 with correct
`Content-Range` on download **and** preview; 416 outside the file; an
~16 MiB upload + ranged download roundtrip (the suite runs its own
instance); temp cleanup after a failed upload; existing ZIP and DAV
pins stay green; counts bump in README/ENCRYPTION/Audit.

## 8. Size: **S1 = M**, **S2 = M** (separately releasable)

## 9. Decisions (summary)

| # | Question | Decision |
| --- | --- | --- |
| 9 | Order | **streaming S1 first**, then versioning, then groups (no double work on the same code paths) |
| 10 | Ranges | yes, on `/download` too - unified with preview |
| - | Temp location | `data_dir/tmp`, swept at startup, commit by rename |
| - | MIME sniffing | bounded prefix sample (first 8 KiB) on streamed uploads |
