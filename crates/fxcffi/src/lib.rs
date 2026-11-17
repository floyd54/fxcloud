//! C ABI over the fxcloud client crypto core (ENCRYPTION.md 5, phase 5
//! slice 3): the surface the native apps (phase 7) call from Kotlin/Swift,
//! and a surface every golden vector runs through as a *third* reader
//! (`tests/ffi_vectors.rs`) - `c/smoke.c` proves the shipped header itself
//! compiles and links against the built static library.
//!
//! Boundary contract (also stated in `include/fxcffi.h`, which is the ABI
//! document of record):
//! - Input pointers may be NULL only together with a length of 0; inputs
//!   are read, never freed, never retained past the call.
//! - Outputs come from Rust's allocator and are released only through
//!   `fx_free`/`fx_*_free`, never through the C `free()`.
//! - Codes are stable (append only):0 success, negative failure.
//! - Panics are caught at the boundary and reported as `FX_ERR_PANIC`.
//!
//! Every entry point that touches caller memory is an `unsafe fn` whose
//! `# Safety` section restates the header's contract; NULL/length problems
//! are still answered with `FX_ERR_ARG` rather than a crash, because C
//! callers hit those mistakes at runtime.

use fxcrypto::{
    child_key_aad, decrypt_bytes, derive_kek, ecies_open, ecies_seal, encrypt_bytes,
    fingerprint_hex, generate_key_pair, hkdf_sha256, open_with_recovery, rewrap_account,
    session_from_ark, share_envelope_aad, unlock_account, unwrap, unwrap_child_key, wrap,
    wrap_child_key, AccountKeys, Error, FormatError, KdfParams, Session, SUITE_P256,
};
use std::os::raw::c_char;

// ---- stable error codes (fxcffi.h is the document of record) -----------

pub const FX_OK: i32 = 0;
pub const FX_ERR_ARG: i32 = -1;
pub const FX_ERR_PANIC: i32 = -2;

pub const FX_ERR_FORMAT_TOO_SHORT: i32 = -10;
pub const FX_ERR_FORMAT_MAGIC: i32 = -11;
pub const FX_ERR_FORMAT_VERSION: i32 = -12;
pub const FX_ERR_FORMAT_SUITE: i32 = -13;
pub const FX_ERR_FORMAT_CHUNK: i32 = -14;

pub const FX_ERR_MALFORMED_TAIL: i32 = -15;
pub const FX_ERR_KEY_LENGTH: i32 = -20;
pub const FX_ERR_AEAD: i32 = -21;
pub const FX_ERR_CHUNK: i32 = -22;
pub const FX_ERR_KDF: i32 = -30;
pub const FX_ERR_HKDF: i32 = -31;
pub const FX_ERR_TOO_SHORT: i32 = -32;
pub const FX_ERR_UNWRAP: i32 = -33;
pub const FX_ERR_PUBLIC_BLOB: i32 = -34;
pub const FX_ERR_UNKNOWN_SUITE: i32 = -35;
pub const FX_ERR_RECIPIENT_SHORT: i32 = -36;
pub const FX_ERR_PKCS8: i32 = -37;

/// One code per `fxcrypto::Error` variant (and per `FormatError` variant):
/// the mapping is part of the ABI, so it only ever grows.
fn code_of(e: Error) -> i32 {
    match e {
        Error::Format(FormatError::TooShort) => FX_ERR_FORMAT_TOO_SHORT,
        Error::Format(FormatError::BadMagic) => FX_ERR_FORMAT_MAGIC,
        Error::Format(FormatError::UnsupportedVersion(_)) => FX_ERR_FORMAT_VERSION,
        Error::Format(FormatError::UnsupportedSuite(_)) => FX_ERR_FORMAT_SUITE,
        Error::Format(FormatError::ImplausibleChunkSize(_)) => FX_ERR_FORMAT_CHUNK,
        Error::KeyLength => FX_ERR_KEY_LENGTH,
        Error::Aead => FX_ERR_AEAD,
        Error::MalformedTail => FX_ERR_MALFORMED_TAIL,
        Error::Chunk(_) => FX_ERR_CHUNK,
        Error::Kdf => FX_ERR_KDF,
        Error::Hkdf => FX_ERR_HKDF,
        Error::WrappedTooShort => FX_ERR_TOO_SHORT,
        Error::Unwrap => FX_ERR_UNWRAP,
        Error::PublicBlob => FX_ERR_PUBLIC_BLOB,
        Error::UnknownSuite(_) => FX_ERR_UNKNOWN_SUITE,
        Error::RecipientKeyShort => FX_ERR_RECIPIENT_SHORT,
        Error::Pkcs8 => FX_ERR_PKCS8,
    }
}

/// Static name of a code for logs; never NULL.
#[no_mangle]
pub extern "C" fn fx_error_name(code: i32) -> *const c_char {
    match code {
        FX_OK => c"FX_OK".as_ptr(),
        FX_ERR_ARG => c"FX_ERR_ARG".as_ptr(),
        FX_ERR_PANIC => c"FX_ERR_PANIC".as_ptr(),
        FX_ERR_FORMAT_TOO_SHORT => c"FX_ERR_FORMAT_TOO_SHORT".as_ptr(),
        FX_ERR_FORMAT_MAGIC => c"FX_ERR_FORMAT_MAGIC".as_ptr(),
        FX_ERR_FORMAT_VERSION => c"FX_ERR_FORMAT_VERSION".as_ptr(),
        FX_ERR_FORMAT_SUITE => c"FX_ERR_FORMAT_SUITE".as_ptr(),
        FX_ERR_FORMAT_CHUNK => c"FX_ERR_FORMAT_CHUNK".as_ptr(),
        FX_ERR_MALFORMED_TAIL => c"FX_ERR_MALFORMED_TAIL".as_ptr(),
        FX_ERR_KEY_LENGTH => c"FX_ERR_KEY_LENGTH".as_ptr(),
        FX_ERR_AEAD => c"FX_ERR_AEAD".as_ptr(),
        FX_ERR_CHUNK => c"FX_ERR_CHUNK".as_ptr(),
        FX_ERR_KDF => c"FX_ERR_KDF".as_ptr(),
        FX_ERR_HKDF => c"FX_ERR_HKDF".as_ptr(),
        FX_ERR_TOO_SHORT => c"FX_ERR_TOO_SHORT".as_ptr(),
        FX_ERR_UNWRAP => c"FX_ERR_UNWRAP".as_ptr(),
        FX_ERR_PUBLIC_BLOB => c"FX_ERR_PUBLIC_BLOB".as_ptr(),
        FX_ERR_UNKNOWN_SUITE => c"FX_ERR_UNKNOWN_SUITE".as_ptr(),
        FX_ERR_RECIPIENT_SHORT => c"FX_ERR_RECIPIENT_SHORT".as_ptr(),
        FX_ERR_PKCS8 => c"FX_ERR_PKCS8".as_ptr(),
        _ => c"FX_ERR_UNKNOWN_CODE".as_ptr(),
    }
}

// ---- boundary plumbing ---------------------------------------------------

/// A library-allocated buffer (outputs) or a borrowed one (fields of
/// [`FxAccountKeys`]). `ptr` is NULL iff `len` is 0.
#[repr(C)]
#[derive(Debug)]
pub struct FxBytes {
    pub ptr: *mut u8,
    pub len: usize,
}

impl FxBytes {
    fn empty() -> Self {
        FxBytes {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }

    /// Hand a Rust `Vec` to C: boxed first so capacity equals length -
    /// [`fx_free`] reconstructs the vector from exactly that pair.
    fn from_vec(v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::empty();
        }
        let len = v.len();
        let ptr = Box::into_raw(v.into_boxed_slice()) as *mut u8;
        FxBytes { ptr, len }
    }

    /// Borrow an input buffer. C may pass NULL with length 0 for "empty";
    /// anything else must point at `len` readable bytes (the caller's
    /// contract, restated in the header).
    fn read(&self) -> Result<&[u8], i32> {
        if self.len == 0 {
            return Ok(&[]);
        }
        if self.ptr.is_null() {
            return Err(FX_ERR_ARG);
        }
        // SAFETY: caller contract above; NULL was excluded for len > 0.
        Ok(unsafe { std::slice::from_raw_parts(self.ptr, self.len) })
    }
}

/// Borrow a (ptr, len) input pair - NULL allowed only with len 0.
fn input<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(FX_ERR_ARG);
    }
    // SAFETY: caller contract (header): ptr readable for len bytes.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Borrow a NUL-terminated UTF-8 argument.
fn cstr_arg<'a>(ptr: *const c_char) -> Result<&'a str, i32> {
    if ptr.is_null() {
        return Err(FX_ERR_ARG);
    }
    // SAFETY: caller contract (header): NUL-terminated string.
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
    s.to_str().map_err(|_| FX_ERR_ARG)
}

/// Run one entry point: every fallible step maps to a code, and a panic
/// stops at the boundary instead of unwinding into C.
fn guarded(f: impl FnOnce() -> Result<(), i32>) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => FX_OK,
        Ok(Err(code)) => code,
        Err(_) => FX_ERR_PANIC,
    }
}

/// Release a buffer handed out by [`FxBytes::from_vec`] and zero it.
fn free_bytes(b: &mut FxBytes) {
    if !b.ptr.is_null() && b.len > 0 {
        // SAFETY: from_vec produced a boxed slice, so capacity == len and
        // the pointer came from Rust's allocator (the header forbids C
        // free() on these). Zeroing makes a double free a no-op.
        unsafe { drop(Vec::from_raw_parts(b.ptr, b.len, b.len)) };
    }
    b.ptr = std::ptr::null_mut();
    b.len = 0;
}

/// Release any buffer this library returned; NULL/0 is a no-op.
///
/// # Safety
/// `ptr`/`len` must be a pair this library returned through an `FxBytes`
/// output (capacity equals length); NULL or `len == 0` is a no-op.
#[no_mangle]
pub unsafe extern "C" fn fx_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: contract above; from_vec produced capacity == len.
    unsafe { drop(Vec::from_raw_parts(ptr, len, len)) };
}

// ---- container (5.3) -----------------------------------------------------

/// Encrypt `plain` into an FXE1 container (fresh nonce base per call).
///
/// # Safety
/// `fxcffi.h` contract: input pointers readable for their lengths (NULL
/// only with length0), `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx1_encrypt(
    file_id: u64,
    key: *const u8,
    key_len: usize,
    plain: *const u8,
    plain_len: usize,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let key = input(key, key_len)?;
        let plain = input(plain, plain_len)?;
        let container = encrypt_bytes(file_id, key, plain).map_err(code_of)?;
        *out = FxBytes::from_vec(container);
        Ok(())
    })
}

/// Decrypt an FXE1 container; wrong key, tampering and row moves all
/// answer `FX_ERR_CHUNK`.
///
/// # Safety
/// `fxcffi.h` contract: input pointers readable for their lengths (NULL
/// only with length0), `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx1_decrypt(
    file_id: u64,
    key: *const u8,
    key_len: usize,
    container: *const u8,
    container_len: usize,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let key = input(key, key_len)?;
        let container = input(container, container_len)?;
        let plain = decrypt_bytes(file_id, key, container).map_err(code_of)?;
        *out = FxBytes::from_vec(plain);
        Ok(())
    })
}

// ---- KDF and key records (5.1 / 5.4) -------------------------------------

/// Argon2id(passphrase, salt) -> 32-byte KEK; `0` parameters mean floor.
///
/// # Safety
/// `fxcffi.h` contract: `passphrase` NUL-terminated UTF-8, `salt` readable
/// for `salt_len`, `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_derive_kek(
    passphrase: *const c_char,
    salt: *const u8,
    salt_len: usize,
    kdf_m: u32,
    kdf_t: u32,
    kdf_p: u32,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let passphrase = cstr_arg(passphrase)?;
        let salt = input(salt, salt_len)?;
        let params = KdfParams::with_defaults(kdf_m, kdf_t, kdf_p);
        let kek = derive_kek(passphrase, salt, params).map_err(code_of)?;
        *out = FxBytes::from_vec(kek.to_vec());
        Ok(())
    })
}

/// HKDF-SHA-256 subkey derivation (ENCRYPTION.md 5.1).
///
/// # Safety
/// `fxcffi.h` contract: input pointers readable for their lengths (NULL
/// only with length0), `out` points at writable storage.
// The C surface spells (ptr, len) pairs out instead of bundling them, so
// this one entry point crosses clippy's argument threshold honestly.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn fx_hkdf(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out_len: u32,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let ikm = input(ikm, ikm_len)?;
        let salt = input(salt, salt_len)?;
        let info = input(info, info_len)?;
        let okm = hkdf_sha256(ikm, salt, info, out_len as usize).map_err(code_of)?;
        *out = FxBytes::from_vec(okm);
        Ok(())
    })
}

/// AES-256-GCM wrap: `nonce12 || ct || tag`, fresh nonce per call.
///
/// # Safety
/// `fxcffi.h` contract: input pointers readable for their lengths (NULL
/// only with length0), `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_wrap(
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let key = input(key, key_len)?;
        let value = input(value, value_len)?;
        let aad = input(aad, aad_len)?;
        let blob = wrap(key, value, aad).map_err(code_of)?;
        *out = FxBytes::from_vec(blob);
        Ok(())
    })
}

/// Reverse of [`fx_wrap`]; one message for every way of failing (5.4).
///
/// # Safety
/// `fxcffi.h` contract: input pointers readable for their lengths (NULL
/// only with length0), `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_unwrap(
    key: *const u8,
    key_len: usize,
    blob: *const u8,
    blob_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let key = input(key, key_len)?;
        let blob = input(blob, blob_len)?;
        let aad = input(aad, aad_len)?;
        let value = unwrap(key, blob, aad).map_err(code_of)?;
        *out = FxBytes::from_vec(value);
        Ok(())
    })
}

/// AAD for a parent-wrapped child key: `u64be(child_id) || version`.
///
/// # Safety
/// `out` must point at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_child_key_aad(child_id: u64, out: *mut FxBytes) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let aad = child_key_aad(child_id);
        *out = FxBytes::from_vec(aad.to_vec());
        Ok(())
    })
}

/// Wrap a folder/file key under its parent key (5.4).
///
/// # Safety
/// `fxcffi.h` contract: input pointers readable for their lengths (NULL
/// only with length0), `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_wrap_child_key(
    parent: *const u8,
    parent_len: usize,
    child_id: u64,
    child: *const u8,
    child_len: usize,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let parent = input(parent, parent_len)?;
        let child = input(child, child_len)?;
        let wrapped = wrap_child_key(parent, child_id, child).map_err(code_of)?;
        *out = FxBytes::from_vec(wrapped);
        Ok(())
    })
}

/// Reverse of [`fx_wrap_child_key`].
///
/// # Safety
/// `fxcffi.h` contract: input pointers readable for their lengths (NULL
/// only with length0), `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_unwrap_child_key(
    parent: *const u8,
    parent_len: usize,
    child_id: u64,
    wrapped: *const u8,
    wrapped_len: usize,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let parent = input(parent, parent_len)?;
        let wrapped = input(wrapped, wrapped_len)?;
        let child = unwrap_child_key(parent, child_id, wrapped).map_err(code_of)?;
        *out = FxBytes::from_vec(child);
        Ok(())
    })
}

/// Display fingerprint (DECISION 6): 32 lowercase hex chars.
///
/// # Safety
/// `public_blob` readable for `public_blob_len`, `out` points at writable
/// storage.
#[no_mangle]
pub unsafe extern "C" fn fx_fingerprint(
    public_blob: *const u8,
    public_blob_len: usize,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let blob = input(public_blob, public_blob_len)?;
        let hex = fingerprint_hex(blob);
        *out = FxBytes::from_vec(hex.into_bytes());
        Ok(())
    })
}

// ---- account access (5.7) ------------------------------------------------

/// A stored account row (5.4), caller-filled; the library only reads it.
#[repr(C)]
#[derive(Debug)]
pub struct FxAccountKeys {
    pub kdf_salt: FxBytes,
    pub wrapped_ark: FxBytes,
    pub wrapped_root_key: FxBytes,
    pub private_key_wrapped: FxBytes,
    pub public_key: FxBytes,
    pub wrapped_ark_recovery: FxBytes,
    pub kdf_m: u32,
    pub kdf_t: u32,
    pub kdf_p: u32,
}

fn account_keys(k: &FxAccountKeys) -> Result<AccountKeys, i32> {
    Ok(AccountKeys {
        kdf_salt: k.kdf_salt.read()?.to_vec(),
        kdf_params: KdfParams::with_defaults(k.kdf_m, k.kdf_t, k.kdf_p),
        wrapped_ark: k.wrapped_ark.read()?.to_vec(),
        wrapped_root_key: k.wrapped_root_key.read()?.to_vec(),
        private_key_wrapped: k.private_key_wrapped.read()?.to_vec(),
        public_key: k.public_key.read()?.to_vec(),
        wrapped_ark_recovery: k.wrapped_ark_recovery.read()?.to_vec(),
    })
}

/// The opened session: material, not key objects (DECISION 7).
#[repr(C)]
#[derive(Debug)]
pub struct FxSession {
    pub ark: FxBytes,
    pub root_key: FxBytes,
    pub private_key_pkcs8: FxBytes,
    pub public_blob: FxBytes,
    pub suite: u8,
}

fn session_into(s: Session) -> FxSession {
    FxSession {
        ark: FxBytes::from_vec(s.ark),
        root_key: FxBytes::from_vec(s.root_key),
        private_key_pkcs8: FxBytes::from_vec(s.private_key_pkcs8),
        public_blob: FxBytes::from_vec(s.public_blob),
        suite: s.suite,
    }
}

/// Open a session from a known ARK (the passphrase/recovery/device paths
/// all end here in Rust; this entry point is the direct door).
///
/// # Safety
/// `keys` must be NULL or a valid [`FxAccountKeys`] whose `FxBytes`
/// fields are readable for their lengths, `ark` readable for `ark_len`,
/// `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_session_from_ark(
    keys: *const FxAccountKeys,
    ark: *const u8,
    ark_len: usize,
    out: *mut FxSession,
) -> i32 {
    if keys.is_null() || out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let keys = account_keys(&*keys)?;
        let ark = input(ark, ark_len)?;
        let session = session_from_ark(&keys, ark).map_err(code_of)?;
        *out = session_into(session);
        Ok(())
    })
}

/// Open a stored account with the storage passphrase (stored params ->
/// KEK -> ARK -> session).
///
/// # Safety
/// `keys` as in [`fx_session_from_ark`], `passphrase` NUL-terminated
/// UTF-8, `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_unlock_account(
    keys: *const FxAccountKeys,
    passphrase: *const c_char,
    out: *mut FxSession,
) -> i32 {
    if keys.is_null() || out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let keys = account_keys(&*keys)?;
        let passphrase = cstr_arg(passphrase)?;
        let session = unlock_account(&keys, passphrase).map_err(code_of)?;
        *out = session_into(session);
        Ok(())
    })
}

/// Open a stored account with the recovery key - a full session (5.7).
///
/// # Safety
/// `keys` as in [`fx_session_from_ark`], `recovery` readable for
/// `recovery_len`, `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_open_with_recovery(
    keys: *const FxAccountKeys,
    recovery: *const u8,
    recovery_len: usize,
    out: *mut FxSession,
) -> i32 {
    if keys.is_null() || out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let keys = account_keys(&*keys)?;
        let recovery = input(recovery, recovery_len)?;
        let session = open_with_recovery(&keys, recovery).map_err(code_of)?;
        *out = session_into(session);
        Ok(())
    })
}

/// Result of a passphrase change (5.7): only the ARK wrap moves.
#[repr(C)]
#[derive(Debug)]
pub struct FxRewrapped {
    pub wrapped_ark: FxBytes,
    pub kdf_salt: FxBytes,
    pub kdf_m: u32,
    pub kdf_t: u32,
    pub kdf_p: u32,
}

/// Re-wrap the ARK under a new passphrase: fresh salt, floor params.
///
/// # Safety
/// `ark` readable for `ark_len`, `new_passphrase` NUL-terminated UTF-8,
/// `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_rewrap_account(
    ark: *const u8,
    ark_len: usize,
    new_passphrase: *const c_char,
    out: *mut FxRewrapped,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let ark = input(ark, ark_len)?;
        let new_passphrase = cstr_arg(new_passphrase)?;
        let re = rewrap_account(ark, new_passphrase).map_err(code_of)?;
        *out = FxRewrapped {
            wrapped_ark: FxBytes::from_vec(re.wrapped_ark),
            kdf_salt: FxBytes::from_vec(re.kdf_salt),
            kdf_m: re.kdf_params.m,
            kdf_t: re.kdf_params.t,
            kdf_p: re.kdf_params.p,
        };
        Ok(())
    })
}

/// Release a session; NULL is a no-op, a second call is a no-op too.
///
/// # Safety
/// `session` must be NULL or a session this library handed out; after
/// the call its buffers are NULL again, so a double free is harmless.
#[no_mangle]
pub unsafe extern "C" fn fx_session_free(session: *mut FxSession) {
    if session.is_null() {
        return;
    }
    let s = &mut *session;
    free_bytes(&mut s.ark);
    free_bytes(&mut s.root_key);
    free_bytes(&mut s.private_key_pkcs8);
    free_bytes(&mut s.public_blob);
    s.suite = 0;
}

/// Release a rewrap result; NULL is a no-op, a second call is a no-op.
///
/// # Safety
/// `rewrapped` must be NULL or a result this library handed out; its
/// buffers are NULL again afterwards.
#[no_mangle]
pub unsafe extern "C" fn fx_rewrapped_free(rewrapped: *mut FxRewrapped) {
    if rewrapped.is_null() {
        return;
    }
    let r = &mut *rewrapped;
    free_bytes(&mut r.wrapped_ark);
    free_bytes(&mut r.kdf_salt);
    r.kdf_m = 0;
    r.kdf_t = 0;
    r.kdf_p = 0;
}

// ---- share envelopes (5.5) -----------------------------------------------

/// AAD binding one envelope to its share: `u64be(source_id) ||
/// utf8(grantee) || version`.
///
/// # Safety
/// `grantee` NUL-terminated UTF-8, `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_share_envelope_aad(
    source_id: u64,
    grantee: *const c_char,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let grantee = cstr_arg(grantee)?;
        let aad = share_envelope_aad(source_id, grantee);
        *out = FxBytes::from_vec(aad);
        Ok(())
    })
}

/// A fresh key pair: `preferred_suite == 2` requests P-256, anything else
/// gets X25519 (the JS `generateKeyPair` else-branch semantics).
///
/// # Safety
/// `out` must point at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_generate_key_pair(preferred_suite: i32, out: *mut FxKeyPair) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let preferred = if preferred_suite == i32::from(SUITE_P256) {
            Some(SUITE_P256)
        } else {
            None
        };
        let kp = generate_key_pair(preferred).map_err(code_of)?;
        *out = FxKeyPair {
            suite: kp.suite,
            public_blob: FxBytes::from_vec(kp.public_blob),
            pkcs8: FxBytes::from_vec(kp.pkcs8),
        };
        Ok(())
    })
}

/// A fresh key pair (5.5): published form `suite || raw point`.
#[repr(C)]
#[derive(Debug)]
pub struct FxKeyPair {
    pub suite: u8,
    pub public_blob: FxBytes,
    pub pkcs8: FxBytes,
}

/// Seal a key record to a recipient's published key:
/// `eph.publicBlob || nonce12 || ct||tag`.
///
/// # Safety
/// `fxcffi.h` contract: input pointers readable for their lengths (NULL
/// only with length0), `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_ecies_seal(
    recipient_public: *const u8,
    recipient_public_len: usize,
    plain: *const u8,
    plain_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let recipient = input(recipient_public, recipient_public_len)?;
        let plain = input(plain, plain_len)?;
        let aad = input(aad, aad_len)?;
        let envelope = ecies_seal(recipient, plain, aad).map_err(code_of)?;
        *out = FxBytes::from_vec(envelope);
        Ok(())
    })
}

/// Open a sealed envelope; wrong recipient, tampering and a foreign AAD
/// all answer `FX_ERR_UNWRAP` (5.5: one message on purpose).
///
/// # Safety
/// `fxcffi.h` contract: input pointers readable for their lengths (NULL
/// only with length0), `out` points at writable storage.
#[no_mangle]
pub unsafe extern "C" fn fx_ecies_open(
    pkcs8: *const u8,
    pkcs8_len: usize,
    envelope: *const u8,
    envelope_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut FxBytes,
) -> i32 {
    if out.is_null() {
        return FX_ERR_ARG;
    }
    guarded(|| {
        let pkcs8 = input(pkcs8, pkcs8_len)?;
        let envelope = input(envelope, envelope_len)?;
        let aad = input(aad, aad_len)?;
        let plain = ecies_open(pkcs8, envelope, aad).map_err(code_of)?;
        *out = FxBytes::from_vec(plain);
        Ok(())
    })
}

/// Release a key pair; NULL is a no-op, a second call is a no-op.
///
/// # Safety
/// `keypair` must be NULL or a pair this library handed out; its buffers
/// are NULL again afterwards.
#[no_mangle]
pub unsafe extern "C" fn fx_keypair_free(keypair: *mut FxKeyPair) {
    if keypair.is_null() {
        return;
    }
    let k = &mut *keypair;
    free_bytes(&mut k.public_blob);
    free_bytes(&mut k.pkcs8);
    k.suite = 0;
}
