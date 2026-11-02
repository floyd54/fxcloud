# Concept: preview and the built-in editor

Status: **implemented** (baseline lightbox; the sandboxed preview, the
content sniffer, the Markdown preview and the unsaved-changes dialog
followed in later releases, the last one in v0.1.4).

## 1. Goal

Clicking a file shows it *inside* the app - no download round trip for
a look - and text files can be edited where they are shown. Nothing
that renders may touch the session cookie, so HTML and SVG previews are
sandboxed server-side and the Markdown preview escapes everything up
front.

## 2. The lightbox

- Images, video, audio, PDF, HTML and text open in a lightbox; text
  files open in the editor instead. Gallery arrows step through the
  listing; closing with unsaved changes asks first (section 4).
- `GET /api/files/preview?id=` serves the content inline with
  `Content-Type` from an extension allowlist, always `nosniff` and -
  for HTML/SVG - `CSP: sandbox`, so a rendered page cannot reach the
  app origin's cookies. **Byte ranges** (206/416) are supported on
  preview *and* download, which is what makes media seeking work
  without transferring the whole file ([streaming.md](streaming.md)).
- The stored type comes from the **bytes** of an uploaded file (magic
  numbers first, then a text heuristic over the first 64 KiB; the
  heuristic re-windows to 8 KiB), so a note without an extension still
  opens in the editor - and the stored type survives WebDAV writes and
  editor saves rather than being re-guessed each time.

## 3. Encrypted files

The tab decrypts an encrypted row into a Blob URL before previewing,
so images, video, audio, PDF and HTML preview with encryption on, and
an encrypted text file edits exactly like a plaintext one. The
plaintext never reaches the server; WebDAV clients see ciphertext and
cannot write it back (ENCRYPTION.md).

## 4. The editor

- `PUT /api/files/content?id=` overwrites the file with a raw text
  body; it is quota-checked like any other write (507 when full).
  Encrypted rows add `&enc=1&key=<base64 file key>` and must carry an
  `FXE1` body (ENCRYPTION.md 5.4).
- The Markdown preview escapes everything and filters link targets, so
  a note cannot run script.
- **Unsaved changes:** closing the editor with a modified buffer - or
  stepping to another file with the gallery arrows - asks first, with
  **Save** as the focused default (Enter), **Discard** and **Cancel**.
  If the save fails the lightbox stays open and the status line carries
  the error, so the text is never closed over.
- New text files are created directly in the UI and open in the editor
  ready to type.

## 5. Where it lives

- Code: `src/web/routes/files.rs` (preview, content, sniffing),
  `frontend/assets/app.js` (lightbox, editor, gallery arrows).
- Safety model: [ARCHITECTURE.md](../ARCHITECTURE.md) - frontend &
  preview safety.
- Memory and ranges: [streaming.md](streaming.md).
- API: [API.md](../API.md) - `/api/files/preview`, `/api/files/content`.
- User side: [USERGUIDE.md](../USERGUIDE.md) section 4.
- Tests: `tests/suite.sh` sections "inline preview (lightbox)",
  "content sniffing: the bytes decide the stored type", "text editor",
  "editor: unsaved-changes dialog", "create new text files",
  "gallery arrows (lightbox navigation)".
