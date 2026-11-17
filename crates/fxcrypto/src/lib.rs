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
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::elliptic_curve::Generate;
use p256::pkcs8::EncodePrivateKey;

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
    /// Argon2id rejected its parameters (or the salt was too short).
    Kdf,
    /// HKDF refused the requested output length (never: callers stay far
    /// below `255 * hash_len`, this exists instead of a panic).
    Hkdf,
    /// A wrapped blob shorter than nonce + tag - the exact check
    /// fxcrypto.js `unwrap` performs first.
    WrappedTooShort,
    /// Unwrapping failed: wrong KEK/key, tampered bytes, or an AAD
    /// mismatch (row move, wrong grantee, wrong purpose). One message on
    /// purpose - telling the three apart would help a prober (5.4/5.5).
    Unwrap,
    /// `public_key` is missing its suite byte.
    PublicBlob,
    /// A published blob or envelope names a suite neither implementation
    /// knows (`fxcrypto.js`: "unknown key suite N").
    UnknownSuite(u8),
    /// Sealing to a recipient whose published blob carries no point.
    RecipientKeyShort,
    /// A stored private key that parses as neither X25519 nor P-256 PKCS#8.
    /// (The JS twin fails the WebCrypto import here with a browser-defined
    /// message, so this one is deliberately not vector-pinned.)
    Pkcs8,
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
            Error::Kdf => write!(f, "argon2id key derivation failed (check the kdf parameters)"),
            Error::Hkdf => write!(f, "hkdf expansion rejected the output length"),
            Error::WrappedTooShort => {
                write!(f, "wrapped value is too short to be a key record")
            }
            Error::Unwrap => write!(
                f,
                "could not unwrap this key - wrong passphrase, or the data was altered"
            ),
            Error::PublicBlob => write!(f, "public key is too short"),
            Error::UnknownSuite(s) => write!(f, "unknown key suite {s}"),
            Error::RecipientKeyShort => write!(f, "recipient public key is too short"),
            Error::Pkcs8 => write!(f, "private key could not be imported"),
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
    rand::fill(&mut nonce_base);
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

// ---- KDF and key derivation (mirror fxcrypto.js184) ----------------------

/// Argon2id floor: exactly what the *server* uses for new login hashes
/// (KDF_FLOOR in fxcrypto.js, LOGIN_KDF_* in src/auth/mod.rs) - DECISION 3's
/// "login hash >= client KDF" holds as an equality.
pub const KDF_M_KIB: u32 = 65536;
pub const KDF_T: u32 = 3;
pub const KDF_P: u32 = 1;
/// Account-wrap salt length (fxcrypto.js `SALT_LEN`).
pub const SALT_LEN: usize = 16;
/// AES-GCM nonce length: wrap blobs and chunk nonces alike (fxcrypto.js
/// `NONCE_LEN`).
pub const NONCE_LEN: usize = 12;
/// Version byte folded into every key record's AAD (ENCRYPTION.md 5.4).
pub const KEY_RECORD_VERSION: u8 = 1;
/// Published-key suite bytes (ENCRYPTION.md 5.5): the leading byte of
/// `public_key` names the curve, so a reader dispatches instead of guessing.
pub const SUITE_X25519: u8 = 1;
pub const SUITE_P256: u8 = 2;

/// Domain separation for the account-level wraps (5.4): a blob written as
/// "wrap the root key" cannot be replayed as "wrap the private key".
pub const AAD_ARK: &[u8] = b"fx1:ark:v1";
pub const AAD_ARK_RECOVERY: &[u8] = b"fx1:ark-recovery:v1";
pub const AAD_PRIVKEY: &[u8] = b"fx1:privkey:v1";
pub const AAD_ROOTKEY: &[u8] = b"fx1:rootkey:v1";
pub const AAD_RECOVERY_KEK: &[u8] = b"fx1:recovery-kek:v1";
pub const AAD_RECOVERY_VIEW: &[u8] = b"fx1:recovery-view:v1";
pub const AAD_DEVICE_ARK: &[u8] = b"fx1:device-ark:v1";

/// Stored `kdf_params` (`0`/missing = floor, the `|| FLOOR` semantics of
/// fxcrypto.js `deriveKek`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m: KDF_M_KIB,
            t: KDF_T,
            p: KDF_P,
        }
    }
}

impl KdfParams {
    /// JS semantics: absent (or zeroed) fields fall back to the floor.
    pub fn with_defaults(m: u32, t: u32, p: u32) -> Self {
        KdfParams {
            m: if m == 0 { KDF_M_KIB } else { m },
            t: if t == 0 { KDF_T } else { t },
            p: if p == 0 { KDF_P } else { p },
        }
    }
}

/// Argon2id(passphrase, salt) ->32-byte KEK, version1.3, parameters as
/// stored with the account. Byte-identical to fxcrypto.js `deriveKek`
/// (hash-wasm argon2 with the same inputs) - pinned by the golden vectors.
pub fn derive_kek(
    passphrase: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<[u8; KEY_LEN], Error> {
    let argon_params =
        argon2::Params::new(params.m, params.t, params.p, Some(KEY_LEN)).map_err(|_| Error::Kdf)?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut kek = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|_| Error::Kdf)?;
    Ok(kek)
}

/// HKDF-SHA-256 (ENCRYPTION.md5.1) - same construction as fxcrypto.js
/// `hkdf`: WebCrypto and RustCrypto agree bit for bit (RFC5869).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).map_err(|_| Error::Hkdf)?;
    Ok(okm)
}

/// The recovery key's KEK: HKDF with a dedicated label, never the raw key
/// (5.7: a future second recovery mechanism must not collide).
pub fn derive_recovery_kek(recovery_key: &[u8], salt: &[u8]) -> Result<Vec<u8>, Error> {
    hkdf_sha256(recovery_key, salt, AAD_RECOVERY_KEK, KEY_LEN)
}

// ---- symmetric wrap / unwrap (mirror fxcrypto.js227) ---------------------

/// `AES-256-GCM(key, value, aad)` as `nonce(12) || ciphertext || tag`,
/// fresh nonce per wrap - re-wrapping the same value never repeats bytes.
pub fn wrap(wrapping_key: &[u8], value: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if wrapping_key.len() != KEY_LEN {
        return Err(Error::KeyLength);
    }
    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| Error::KeyLength)?;
    let mut iv = [0u8; NONCE_LEN];
    rand::fill(&mut iv);
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: value, aad })
        .map_err(|_| Error::Aead)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Reverse of [`wrap`]. One failure message for wrong key, tampered bytes
/// and AAD mismatch - deliberately (fxcrypto.js `unwrap`).
pub fn unwrap(wrapping_key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::WrappedTooShort);
    }
    if wrapping_key.len() != KEY_LEN {
        return Err(Error::KeyLength);
    }
    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| Error::KeyLength)?;
    let iv = &blob[..NONCE_LEN];
    let ct = &blob[NONCE_LEN..];
    cipher
        .decrypt(Nonce::from_slice(iv), Payload { msg: ct, aad })
        .map_err(|_| Error::Unwrap)
}

/// AAD for a parent-wrapped child key: `child_id || version` (5.4).
pub fn child_key_aad(child_id: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&child_id.to_be_bytes());
    aad[8] = KEY_RECORD_VERSION;
    aad
}

/// Wrap a folder/file key under its parent key (5.4). Returns raw bytes;
/// the JS twin base64-encodes on its side of the boundary.
pub fn wrap_child_key(
    parent_key: &[u8],
    child_id: u64,
    child_key: &[u8],
) -> Result<Vec<u8>, Error> {
    wrap(parent_key, child_key, &child_key_aad(child_id))
}

/// Reverse of [`wrap_child_key`].
pub fn unwrap_child_key(
    parent_key: &[u8],
    child_id: u64,
    wrapped: &[u8],
) -> Result<Vec<u8>, Error> {
    unwrap(parent_key, wrapped, &child_key_aad(child_id))
}

// ---- fingerprint (mirror fxcrypto.js397) ---------------------------------

/// Display fingerprint (DECISION 6): SHA-256 over the *published* blob,
/// truncated to128 bits, lowercase hex32 -32 hex digits a human compares
/// out of band.
pub fn fingerprint_hex(public_blob: &[u8]) -> String {
    let digest = <sha2::Sha256 as sha2::Digest>::digest(public_blob);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for &b in &digest[..16] {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ---- account access: unlock / recovery / rewrap (mirror fxcrypto.js587) --

/// Everything a *stored* account row carries for opening sessions, as raw
/// bytes (the JS twin holds base64 strings - decoding stays the caller's
/// job on both sides, so no format decision hides in this struct).
#[derive(Debug, Clone)]
pub struct AccountKeys {
    pub kdf_salt: Vec<u8>,
    pub kdf_params: KdfParams,
    pub wrapped_ark: Vec<u8>,
    pub wrapped_root_key: Vec<u8>,
    pub private_key_wrapped: Vec<u8>,
    pub public_key: Vec<u8>,
    pub wrapped_ark_recovery: Vec<u8>,
}

/// The plaintext material a tab keeps in memory (DECISION 7): the opened
/// ARK, the root key, the PKCS#8 private key and the published public blob.
/// Curve *objects* are deliberately absent - importing a CryptoKey is a
/// browser concern; bytes are the contract.
#[derive(Debug, Clone)]
pub struct Session {
    pub ark: Vec<u8>,
    pub root_key: Vec<u8>,
    pub private_key_pkcs8: Vec<u8>,
    pub public_blob: Vec<u8>,
    pub suite: u8,
}

/// Everything that hangs off an opened ARK: root key and private key
/// (fxcrypto.js `sessionFromArk`). The passphrase, recovery and device
/// paths all end here - only how the ARK was obtained differs.
pub fn session_from_ark(keys: &AccountKeys, ark: &[u8]) -> Result<Session, Error> {
    let root_key = unwrap(ark, &keys.wrapped_root_key, AAD_ROOTKEY)?;
    let private_key_pkcs8 = unwrap(ark, &keys.private_key_wrapped, AAD_PRIVKEY)?;
    // importPublicKey's own guard: a suite byte with no point behind it is
    // not a public key (fxcrypto.js throws the very message below).
    if keys.public_key.len() < 2 {
        return Err(Error::PublicBlob);
    }
    Ok(Session {
        ark: ark.to_vec(),
        root_key,
        private_key_pkcs8,
        public_blob: keys.public_key.clone(),
        suite: keys.public_key[0],
    })
}

/// Open a stored account with the storage passphrase (fxcrypto.js
/// `unlockAccount`): stored params -> KEK -> ARK -> session.
pub fn unlock_account(keys: &AccountKeys, passphrase: &str) -> Result<Session, Error> {
    let kek = derive_kek(passphrase, &keys.kdf_salt, keys.kdf_params)?;
    let ark = unwrap(&kek, &keys.wrapped_ark, AAD_ARK)?;
    session_from_ark(keys, &ark)
}

/// Open a stored account with the recovery key (5.7) - a full session, not
/// a read-only peek (fxcrypto.js `openWithRecovery`).
pub fn open_with_recovery(keys: &AccountKeys, recovery_key: &[u8]) -> Result<Session, Error> {
    let recovery_kek = derive_recovery_kek(recovery_key, &keys.kdf_salt)?;
    let ark = unwrap(&recovery_kek, &keys.wrapped_ark_recovery, AAD_ARK_RECOVERY)?;
    session_from_ark(keys, &ark)
}

/// The result of a passphrase change (5.7, DECISION 3 consequence2):
/// O(1) - the ARK and everything under it do not move.
#[derive(Debug, Clone)]
pub struct RewrappedArk {
    pub wrapped_ark: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: KdfParams,
}

/// Re-wrap the ARK under a fresh passphrase KEK (fxcrypto.js
/// `rewrapAccount`): new salt, new KEK, one wrap.
pub fn rewrap_account(ark: &[u8], new_passphrase: &str) -> Result<RewrappedArk, Error> {
    let mut salt = [0u8; SALT_LEN];
    rand::fill(&mut salt);
    let params = KdfParams::default();
    let kek = derive_kek(new_passphrase, &salt, params)?;
    let wrapped_ark = wrap(&kek, ark, AAD_ARK)?;
    Ok(RewrappedArk {
        wrapped_ark,
        kdf_salt: salt.to_vec(),
        kdf_params: params,
    })
}

// ---- key pairs and share envelopes (mirror fxcrypto.js397/487, ENCRYPTION.md5.5) ----

/// HKDF labels for one envelope's key agreement (5.5): fixed labels, no
/// per-share salt - the shared secret is already fresh (a new ephemeral
/// pair per envelope) and the AAD binds the result to one share.
pub const SHARE_HKDF_SALT: &[u8] = b"fx1:share-kek:v1";
pub const SHARE_HKDF_INFO: &[u8] = b"fx1:share:v1";

/// X25519 PKCS#8 v2 private-key prefix (RFC8410): SEQUENCE { INTEGER0,
/// id-X25519, OCTET STRING { OCTET STRING raw } }. WebCrypto exports
/// exactly this shape; the golden vectors pin our reading of it.
const X25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// Raw point length behind a suite byte (fxcrypto.js `publicKeyLen`).
fn public_key_len(suite: u8) -> Result<usize, Error> {
    match suite {
        SUITE_X25519 => Ok(32),
        SUITE_P256 => Ok(65), // uncompressed point: "04" || x || y
        s => Err(Error::UnknownSuite(s)),
    }
}

/// A published key (suite || point), parsed per its suite.
enum CurvePublic {
    X25519(x25519_dalek::PublicKey),
    P256(p256::PublicKey),
}

fn import_public_blob(blob: &[u8]) -> Result<CurvePublic, Error> {
    if blob.len() < 2 {
        return Err(Error::PublicBlob);
    }
    let point_len = public_key_len(blob[0])?;
    if blob.len() != 1 + point_len {
        return Err(Error::PublicBlob);
    }
    match blob[0] {
        SUITE_X25519 => {
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&blob[1..33]);
            Ok(CurvePublic::X25519(x25519_dalek::PublicKey::from(raw)))
        }
        _ => Ok(CurvePublic::P256(
            p256::PublicKey::from_sec1_bytes(&blob[1..]).map_err(|_| Error::PublicBlob)?,
        )),
    }
}

/// My private key (PKCS#8), parsed per its suite.
enum CurveSecret {
    X25519(x25519_dalek::StaticSecret),
    P256(p256::SecretKey),
}

impl CurveSecret {
    fn suite(&self) -> u8 {
        match self {
            CurveSecret::X25519(_) => SUITE_X25519,
            CurveSecret::P256(_) => SUITE_P256,
        }
    }

    /// ECDH against the ephemeral blob of an envelope; the raw shared
    /// secret is byte-for-byte what WebCrypto `deriveBits(..., 256)`
    /// returns (X25519 u-coordinate / P-256 X coordinate,32 bytes).
    fn diffie_hellman(&self, eph_blob: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            CurveSecret::X25519(secret) => {
                if eph_blob.len() != 33 {
                    return Err(Error::PublicBlob);
                }
                let mut raw = [0u8; 32];
                raw.copy_from_slice(&eph_blob[1..33]);
                let eph = x25519_dalek::PublicKey::from(raw);
                Ok(secret.diffie_hellman(&eph).as_bytes().to_vec())
            }
            CurveSecret::P256(secret) => {
                let point = eph_blob.get(1..).ok_or(Error::PublicBlob)?;
                let eph = p256::PublicKey::from_sec1_bytes(point).map_err(|_| Error::PublicBlob)?;
                Ok(secret.diffie_hellman(&eph).raw_secret_bytes().to_vec())
            }
        }
    }
}

fn import_private_key(pkcs8: &[u8]) -> Result<CurveSecret, Error> {
    if pkcs8.len() == X25519_PKCS8_PREFIX.len() + 32 && pkcs8[..16] == X25519_PKCS8_PREFIX {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&pkcs8[16..]);
        return Ok(CurveSecret::X25519(x25519_dalek::StaticSecret::from(raw)));
    }
    p256::SecretKey::from_der(pkcs8)
        .map(CurveSecret::P256)
        .map_err(|_| Error::Pkcs8)
}

/// A fresh key pair (fxcrypto.js `generateKeyPair`): X25519 first, P-256
/// when asked for (DECISION 1). The private key travels as PKCS#8 - the
/// RFC8410 layout for X25519, the crate's DER for P-256.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub suite: u8,
    pub public_blob: Vec<u8>,
    pub pkcs8: Vec<u8>,
}

pub fn generate_key_pair(preferred: Option<u8>) -> Result<KeyPair, Error> {
    match preferred {
        Some(SUITE_P256) => {
            let secret = p256::SecretKey::generate();
            let pkcs8 = secret
                .to_pkcs8_der()
                .map_err(|_| Error::Pkcs8)?
                .as_bytes()
                .to_vec();
            let mut public_blob = Vec::with_capacity(66);
            public_blob.push(SUITE_P256);
            public_blob.extend_from_slice(secret.public_key().to_sec1_point(false).as_bytes());
            Ok(KeyPair {
                suite: SUITE_P256,
                public_blob,
                pkcs8,
            })
        }
        // None, X25519, or anything unknown: the JS else-branch picks
        // X25519 (it only falls back to P-256 when the browser cannot).
        _ => {
            let secret = x25519_dalek::StaticSecret::random();
            let mut public_blob = Vec::with_capacity(33);
            public_blob.push(SUITE_X25519);
            public_blob.extend_from_slice(&x25519_dalek::PublicKey::from(&secret).to_bytes());
            let mut pkcs8 = X25519_PKCS8_PREFIX.to_vec();
            pkcs8.extend_from_slice(&secret.to_bytes());
            Ok(KeyPair {
                suite: SUITE_X25519,
                public_blob,
                pkcs8,
            })
        }
    }
}

/// AAD binding one envelope to its share (5.5): the source row and the
/// grantee it was sealed for, plus the key-record version so a future
/// record format cannot be replayed as this one. Both bindings do real
/// work: no replaying a stored envelope against a second share of the
/// same source, and no handing a colleague *your* envelope as if it had
/// been sealed for them.
pub fn share_envelope_aad(source_id: u64, grantee: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + grantee.len() + 1);
    aad.extend_from_slice(&source_id.to_be_bytes());
    aad.extend_from_slice(grantee.as_bytes());
    aad.push(KEY_RECORD_VERSION);
    aad
}

/// Seal one key record to a recipient's published key (5.5): ephemeral
/// ECDH in the *recipient's* suite -> HKDF-SHA-256 -> AES-256-GCM. The
/// result is `eph.publicBlob || nonce12 || ct||tag` - the suite byte
/// travels with the ephemeral blob, so sender and recipient never
/// negotiate anything out of band. Returns raw bytes (the JS twin
/// base64-encodes on its side of the boundary).
pub fn ecies_seal(
    recipient_public_blob: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    if recipient_public_blob.len() < 2 {
        return Err(Error::RecipientKeyShort);
    }
    // Parse before generating anything: a garbage suite byte fails here
    // instead of producing an envelope nobody can open.
    let recipient = import_public_blob(recipient_public_blob)?;
    let (eph_blob, shared) = match recipient {
        CurvePublic::X25519(recipient) => {
            let eph = x25519_dalek::StaticSecret::random();
            let eph_pub = x25519_dalek::PublicKey::from(&eph);
            let mut blob = Vec::with_capacity(33);
            blob.push(SUITE_X25519);
            blob.extend_from_slice(&eph_pub.to_bytes());
            let shared = eph.diffie_hellman(&recipient).as_bytes().to_vec();
            (blob, shared)
        }
        CurvePublic::P256(recipient) => {
            let eph = p256::ecdh::EphemeralSecret::generate();
            let eph_pub = eph.public_key();
            let mut blob = Vec::with_capacity(66);
            blob.push(SUITE_P256);
            blob.extend_from_slice(eph_pub.to_sec1_point(false).as_bytes());
            let shared = eph.diffie_hellman(&recipient).raw_secret_bytes().to_vec();
            (blob, shared)
        }
    };
    let wrap_key = hkdf_sha256(&shared, SHARE_HKDF_SALT, SHARE_HKDF_INFO, KEY_LEN)?;
    let wrapped = wrap(&wrap_key, plaintext, aad)?;
    let mut out = eph_blob;
    out.extend_from_slice(&wrapped);
    Ok(out)
}

/// Open a sealed envelope with my own private key (fxcrypto.js
/// `eciesOpen`). Unknown suite, short blob, wrong recipient, tampering
/// and a foreign AAD all end in the unified message on purpose (5.5):
/// telling them apart would tell a prober something.
pub fn ecies_open(private_key_pkcs8: &[u8], envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let suite = match envelope.first() {
        Some(&s) => s,
        None => return Err(Error::Unwrap),
    };
    let point_len = match suite {
        SUITE_X25519 => 32usize,
        SUITE_P256 => 65,
        // JS: publicKeyLen throws and eciesOpen folds it into the message.
        _ => return Err(Error::Unwrap),
    };
    if envelope.len() < 1 + point_len + NONCE_LEN + TAG_LEN {
        return Err(Error::Unwrap);
    }
    let secret = import_private_key(private_key_pkcs8)?;
    if secret.suite() != suite {
        // JS hits a WebCrypto type error here (browser-defined text);
        // "not mine" is the unified answer either way.
        return Err(Error::Unwrap);
    }
    let shared = secret.diffie_hellman(&envelope[..1 + point_len])?;
    let wrap_key = hkdf_sha256(&shared, SHARE_HKDF_SALT, SHARE_HKDF_INFO, KEY_LEN)?;
    unwrap(&wrap_key, &envelope[1 + point_len..], aad)
}
