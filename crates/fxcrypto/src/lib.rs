//! fxcloud client-side crypto core - slice1: the FXE1 container format.
//!
//! One Rust implementation of the container the browser's `fxcrypto.js`
//! writes and reads (ENCRYPTION.md section 5.3), so native apps (phase 7)
//! never grow a second one. Parity is enforced by golden vectors shared
//! with the JS implementation: `tests/fixtures/fx1-vectors.json` is
//! verified by BOTH sides in CI - `frontend/tests/gen-fx1-vectors.js
//! --check` (JS) and `tests/golden.rs` (here), plus self-roundtrips over
//! every chunk boundary.
//!
//! This crate is a **client** library. The fxcloud server must never
//! depend on it - the server stays key-blind (magic check only), and the
//! suite fails if this crate ever appears in the server's `[dependencies]`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

/// Container magic: `FXE1` (fxcrypto.js `MAGIC`).
pub const MAGIC: [u8; 4] = *b"FXE1";
/// Container version byte (fxcrypto.js `ENC_VERSION`).
pub const ENC_VERSION: u8 = 1;
/// The only cipher suite in the container header (fxcrypto.js
/// `SUITE_AES256_GCM`).
pub const SUITE_AES256_GCM: u8 = 1;
/// `magic(4) || version(1) || suite(1) || chunk_size(4) || nonce_base(8)`
pub const HEADER_LEN: usize = 18;
/// Offset of the 8-byte per-file nonce base inside the header.
pub const NONCE_BASE_OFF: usize = 10;
/// Plaintext bytes per chunk - the value the JS encoder hardcodes; the
/// reader takes the (validly bounded) value from each container's header.
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// AES-GCM tag bytes per chunk.
pub const TAG_LEN: usize = 16;
/// File key length in bytes (256-bit).
pub const KEY_LEN: usize = 32;

/// Everything `read_header` rejects before a key is even tried. Messages
/// are byte-compatible with fxcrypto.js `readHeader` (the shared golden
/// vectors pin both against the same substrings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u8),
    UnsupportedSuite(u8),
    ImplausibleChunkSize(u32),
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::TooShort => write!(f, "file is too short to be an FXE1 container"),
            FormatError::BadMagic => write!(f, "not an FXE1 container (bad magic)"),
            FormatError::UnsupportedVersion(v) => {
                write!(f, "unsupported fxcloud container version {v}")
            }
            FormatError::UnsupportedSuite(s) => write!(f, "unsupported cipher suite {s}"),
            FormatError::ImplausibleChunkSize(c) => {
                write!(f, "implausible chunk size in container header: {c}")
            }
        }
    }
}

impl std::error::Error for FormatError {}

/// Read and validate the 18-byte header; returns `(header, chunk_size)`
/// exactly like fxcrypto.js `readHeader` - same bounds, same errors.
pub fn read_header(blob: &[u8]) -> Result<(&[u8], u32), FormatError> {
    if blob.len() < HEADER_LEN {
        return Err(FormatError::TooShort);
    }
    if blob[0..4] != MAGIC {
        return Err(FormatError::BadMagic);
    }
    if blob[4] != ENC_VERSION {
        return Err(FormatError::UnsupportedVersion(blob[4]));
    }
    if blob[5] != SUITE_AES256_GCM {
        return Err(FormatError::UnsupportedSuite(blob[5]));
    }
    let chunk_size = u32::from_be_bytes([blob[6], blob[7], blob[8], blob[9]]);
    if !(1..=64 * 1024 * 1024).contains(&chunk_size) {
        return Err(FormatError::ImplausibleChunkSize(chunk_size));
    }
    Ok((&blob[..HEADER_LEN], chunk_size))
}

/// Every failure `encrypt_bytes`/`decrypt_bytes` can report. The Display
/// strings mirror the JS errors so the shared vectors can pin *which*
/// failure happened, not just that one happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Header-level rejection (see [`FormatError`]).
    Format(FormatError),
    /// The key is not32 bytes long.
    KeyLength,
    /// The AEAD primitive refused (never happens for AES-256-GCM with
    /// legal sizes; kept so encrypt has a fallible surface).
    Aead,
    /// The body's final segment is at most one tag - our encoder never
    /// emits that (fxcrypto.js: "malformed FXE1 container").
    MalformedTail,
    /// Chunk *i* failed authentication: wrong key, tampering, or a row
    /// move. Message byte-compatible with fxcrypto.js.
    Chunk(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Format(e) => write!(f, "{e}"),
            Error::KeyLength => write!(f, "expected a256-bit file key"),
            Error::Aead => write!(f, "aead failure"),
            Error::MalformedTail => write!(f, "malformed FXE1 container (truncated final chunk)"),
            Error::Chunk(i) => write!(
                f,
                "decryption failed for chunk {i} - wrong key, a tampered file, or a file moved to another row"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<FormatError> for Error {
    fn from(e: FormatError) -> Self {
        Error::Format(e)
    }
}

/// `header || u64be(file_id) || u32be(chunk_index)` (5.3).
fn chunk_aad(header: &[u8], file_id: u64, index: u32) -> [u8; HEADER_LEN + 12] {
    let mut aad = [0u8; HEADER_LEN + 12];
    aad[..HEADER_LEN].copy_from_slice(header);
    aad[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&file_id.to_be_bytes());
    aad[HEADER_LEN + 8..].copy_from_slice(&index.to_be_bytes());
    aad
}

/// The 12-byte chunk nonce: `nonce_base || u32be(index)` (5.3).
fn chunk_nonce(header: &[u8], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&header[NONCE_BASE_OFF..HEADER_LEN]);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

/// Encrypt `plain` into an FXE1 container bound to row `file_id`, using
/// the reference chunk size (4 MiB) - the byte-level twin of fxcrypto.js
/// `encryptBytes` (fresh random nonce base per call, so outputs are NOT
/// reproducible; the golden vectors therefore pin the *read* side).
pub fn encrypt_bytes(file_id: u64, key: &[u8], plain: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_bytes_with_chunk_size(file_id, key, plain, CHUNK_SIZE as u32)
}

/// Like [`encrypt_bytes`], but with an explicit chunk size (1 ..=64 MiB,
/// the reader's bounds). Smaller chunk sizes are what make boundary tests
/// cheap - the format does not care, the header carries the value.
pub fn encrypt_bytes_with_chunk_size(
    file_id: u64,
    key: &[u8],
    plain: &[u8],
    chunk_size: u32,
) -> Result<Vec<u8>, Error> {
    // JS order: the key length check comes first in encryptBytes.
    if key.len() != KEY_LEN {
        return Err(Error::KeyLength);
    }
    if !(1..=64 * 1024 * 1024).contains(&chunk_size) {
        return Err(Error::Format(FormatError::ImplausibleChunkSize(chunk_size)));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::KeyLength)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.push(ENC_VERSION);
    header.push(SUITE_AES256_GCM);
    header.extend_from_slice(&chunk_size.to_be_bytes());
    let mut nonce_base = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce_base);
    header.extend_from_slice(&nonce_base);

    let stride = chunk_size as usize;
    let count = if plain.is_empty() {
        0
    } else {
        plain.len().div_ceil(stride)
    };
    if count == 0 {
        return Ok(header); // empty plaintext: header only, like the JS encoder
    }

    let mut out = Vec::with_capacity(HEADER_LEN + plain.len() + count * TAG_LEN);
    out.extend_from_slice(&header);
    for i in 0..count {
        let start = i * stride;
        let chunk = &plain[start..(start + stride).min(plain.len())];
        let aad = chunk_aad(&header, file_id, i as u32);
        let nonce = chunk_nonce(&header, i as u32);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Aead)?;
        out.extend_from_slice(&ct);
    }
    Ok(out)
}

/// Reverse of [`encrypt_bytes`]: validates header, then every chunk's
/// GCM tag with the row-bound AAD. Throws semantics mirror JS - any
/// tampering, wrong key or moved row surfaces as [`Error::Chunk`].
pub fn decrypt_bytes(file_id: u64, key: &[u8], blob: &[u8]) -> Result<Vec<u8>, Error> {
    let (header, chunk_size) = read_header(blob)?;
    let body_len = blob.len() - HEADER_LEN;
    if body_len == 0 {
        return Ok(Vec::new());
    }

    let stride = chunk_size as usize + TAG_LEN;
    let count = body_len.div_ceil(stride);
    let last_len = body_len - (count - 1) * stride;
    if last_len <= TAG_LEN {
        // Same branch as fxcrypto.js: our encoder never emits an empty
        // trailing chunk, so a tail of at most one tag is not ours.
        return Err(Error::MalformedTail);
    }
    // JS order: the key is validated after the shape checks (importAes).
    if key.len() != KEY_LEN {
        return Err(Error::KeyLength);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::KeyLength)?;

    let mut out = Vec::with_capacity(body_len - count * TAG_LEN);
    let mut off = HEADER_LEN;
    for i in 0..count {
        let ct_len = if i == count - 1 { last_len } else { stride };
        let aad = chunk_aad(header, file_id, i as u32);
        let nonce = chunk_nonce(header, i as u32);
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &blob[off..off + ct_len],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Chunk(i))?;
        out.extend_from_slice(&pt);
        off += ct_len;
    }
    Ok(out)
}
