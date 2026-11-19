//! JNI bridge for the native Android app (phase 7, concepts/android.md A3):
//! Kotlin's `FxCore` calls land here and go straight through `fxcffi` -
//! the same C ABI the golden vectors, the C smoke test and `fxcffi.h`
//! already pin. No crypto lives in this crate: it translates types,
//! error codes and panics between the two worlds.
//!
//! Boundary rules (the JNI half of the spec):
//! - bytes are copied in and out on every call, no pointer ever escapes
//!   into the JVM; every C buffer is released with `fx_free`
//! - the i32 codes become Java exceptions (`FxException` in Kotlin, a
//!   plain RuntimeException fallback here), because Kotlin has no
//!   C-style return channel
//! - a panic inside the core is caught by `fxcffi` (`FX_ERR_PANIC`) and
//!   arrives as an exception, never as a JVM abort

use base64::Engine as _;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

/// Compute the display fingerprint (DECISION 6) over a published key
/// blob: bytes in,32 hex characters out - the first JNI entry point,
/// and the smoke test of the whole boundary (slice S1). Kotlin calls it
/// as `FxCore.fingerprint(blob: ByteArray): String`.
///
/// # Safety
/// Standard JNI contract: `env` and `blob` come from the JVM and are
/// valid for this call; nothing is retained past it.
#[no_mangle]
pub extern "system" fn Java_de_frischux_fxcloud_FxCore_fingerprint(
    mut env: JNIEnv,
    _class: JClass,
    blob: JByteArray,
) -> jstring {
    let result = fingerprint_impl(&mut env, &blob);
    match result {
        Ok(hex) => match env.new_string(&hex) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalStateException", e.to_string());
                std::ptr::null_mut()
            }
        },
        Err(msg) => {
            let _ = env.throw_new("java/lang/RuntimeException", &msg);
            std::ptr::null_mut()
        }
    }
}

fn fingerprint_impl(env: &mut JNIEnv, blob: &JByteArray) -> Result<String, String> {
    // Copy in (A3: no view into the JVM's heap survives this call).
    let bytes = env
        .convert_byte_array(blob)
        .map_err(|e| format!("blob: {e}"))?;

    let mut out = fxcffi::FxBytes {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    // SAFETY: the buffer is valid for this call (the slice above), out is
    // our own local; fx_free releases what the core allocated.
    let code = unsafe {
        fxcffi::fx_fingerprint(
            bytes.as_ptr(),
            bytes.len(),
            &mut out as *mut fxcffi::FxBytes,
        )
    };
    let hex = if code == fxcffi::FX_OK {
        let text = if out.ptr.is_null() {
            String::new()
        } else {
            // SAFETY: out was filled by the core with len bytes.
            let slice = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
            String::from_utf8_lossy(slice).into_owned()
        };
        // SAFETY: a buffer from fx_fingerprint goes back through fx_free.
        unsafe { fxcffi::fx_free(out.ptr, out.len) };
        text
    } else {
        // SAFETY: nothing was allocated on the error path; fx_free on a
        // null/zero pair is a documented no-op.
        unsafe { fxcffi::fx_free(out.ptr, out.len) };
        let name = unsafe {
            std::ffi::CStr::from_ptr(fxcffi::fx_error_name(code))
                .to_string_lossy()
                .into_owned()
        };
        return Err(format!("fingerprint failed: {name}"));
    };
    Ok(hex)
}

// ---- S2: unlock and the name/record unwrap ------------------------------

/// The account material as `GET /api/keys/me` sends it (the `keys`
/// object): base64 blobs plus the Argon2id parameters. Parsed here so
/// the boundary stays one JSON string, not nine parameters.
#[derive(serde::Deserialize)]
struct KeysPayload {
    wrapped_ark: String,
    wrapped_root_key: String,
    private_key_wrapped: String,
    public_key: String,
    wrapped_ark_recovery: String,
    kdf_salt: String,
    #[serde(default)]
    kdf_params: KdfParamsDto,
}

/// `kdf_params` as stored: m/t/p may be absent (floor) - the same
/// `0 = floor` semantics the JS twin has.
#[derive(serde::Deserialize, Default)]
struct KdfParamsDto {
    #[serde(default)]
    m: Option<u32>,
    #[serde(default)]
    t: Option<u32>,
    #[serde(default)]
    p: Option<u32>,
}

/// Unlock an account with the storage passphrase: Argon2id, ARK, then
/// the session material packed as `root_key(32) || u32be(pkcs8_len) ||
/// pkcs8` - the first32 bytes are what S2's name decryption needs; the
/// rest rides along for S3's envelopes without a second Argon2id run.
/// Kotlin calls it as `FxCore.unlock(keysJson, passphrase)`.
///
/// # Safety
/// Standard JNI contract: both strings are valid JVM objects for this
/// call; nothing is retained past it.
#[no_mangle]
pub extern "system" fn Java_de_frischux_fxcloud_FxCore_unlock(
    mut env: JNIEnv,
    _class: JClass,
    keys: JString,
    passphrase: JString,
) -> jni::sys::jbyteArray {
    match unlock_impl(&mut env, &keys, &passphrase) {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalStateException", e.to_string());
                std::ptr::null_mut()
            }
        },
        Err(msg) => {
            let _ = env.throw_new("java/lang/RuntimeException", &msg);
            std::ptr::null_mut()
        }
    }
}

/// The account material decoded from the /api/keys/me JSON: the Vecs the
/// C struct borrows from, so they outlive the call - the same discipline
/// every C caller of fxcffi follows.
struct DecodedKeys {
    kdf_salt: Vec<u8>,
    wrapped_ark: Vec<u8>,
    wrapped_root_key: Vec<u8>,
    private_key_wrapped: Vec<u8>,
    public_key: Vec<u8>,
    wrapped_ark_recovery: Vec<u8>,
    kdf_m: u32,
    kdf_t: u32,
    kdf_p: u32,
}

impl DecodedKeys {
    fn from_json(keys_json: &str) -> Result<Self, String> {
        let payload: KeysPayload =
            serde_json::from_str(keys_json).map_err(|e| format!("keys json: {e}"))?;
        let b64 = |s: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| format!("base64: {e}"))
        };
        Ok(Self {
            kdf_salt: b64(&payload.kdf_salt)?,
            wrapped_ark: b64(&payload.wrapped_ark)?,
            wrapped_root_key: b64(&payload.wrapped_root_key)?,
            private_key_wrapped: b64(&payload.private_key_wrapped)?,
            public_key: b64(&payload.public_key)?,
            wrapped_ark_recovery: b64(&payload.wrapped_ark_recovery)?,
            kdf_m: payload.kdf_params.m.unwrap_or(0),
            kdf_t: payload.kdf_params.t.unwrap_or(0),
            kdf_p: payload.kdf_params.p.unwrap_or(0),
        })
    }

    fn account(&self) -> fxcffi::FxAccountKeys {
        let borrow = |v: &Vec<u8>| fxcffi::FxBytes {
            ptr: v.as_ptr() as *mut u8,
            len: v.len(),
        };
        fxcffi::FxAccountKeys {
            kdf_salt: borrow(&self.kdf_salt),
            wrapped_ark: borrow(&self.wrapped_ark),
            wrapped_root_key: borrow(&self.wrapped_root_key),
            private_key_wrapped: borrow(&self.private_key_wrapped),
            public_key: borrow(&self.public_key),
            wrapped_ark_recovery: borrow(&self.wrapped_ark_recovery),
            kdf_m: self.kdf_m,
            kdf_t: self.kdf_t,
            kdf_p: self.kdf_p,
        }
    }
}

fn empty_session() -> fxcffi::FxSession {
    let empty = || fxcffi::FxBytes {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    fxcffi::FxSession {
        ark: empty(),
        root_key: empty(),
        private_key_pkcs8: empty(),
        public_blob: empty(),
        suite: 0,
    }
}

fn read_bytes(b: &fxcffi::FxBytes) -> Vec<u8> {
    if b.ptr.is_null() {
        Vec::new()
    } else {
        // SAFETY: the core filled this buffer; copied before free.
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
    }
}

/// Read a session's root key and pkcs8, release it, and pack them the
/// way Kotlin expects: root(32) || u32be(pkcs8_len) || pkcs8.
fn take_packed_session(out: &mut fxcffi::FxSession) -> Result<Vec<u8>, String> {
    let root = read_bytes(&out.root_key);
    let pkcs8 = read_bytes(&out.private_key_pkcs8);
    // SAFETY: a session from fxcffi goes back through its free, once.
    unsafe { fxcffi::fx_session_free(out) };
    if root.len() != 32 {
        return Err(format!("root key is {} bytes", root.len()));
    }
    let mut packed = Vec::with_capacity(36 + pkcs8.len());
    packed.extend_from_slice(&root);
    packed.extend_from_slice(&(pkcs8.len() as u32).to_be_bytes());
    packed.extend_from_slice(&pkcs8);
    Ok(packed)
}

/// The recovery key as the web shows it: hex, possibly grouped with
/// spaces or dashes - anything that is not a hex digit is dropped.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let filtered: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if filtered.is_empty() || !filtered.len().is_multiple_of(2) {
        return Err("recovery key is not hex".to_string());
    }
    (0..filtered.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&filtered[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn unlock_impl(env: &mut JNIEnv, keys: &JString, passphrase: &JString) -> Result<Vec<u8>, String> {
    let keys_json = String::from(env.get_string(keys).map_err(|e| format!("keys: {e}"))?);
    let pass = String::from(
        env.get_string(passphrase)
            .map_err(|e| format!("passphrase: {e}"))?,
    );
    let decoded = DecodedKeys::from_json(&keys_json)?;
    let account = decoded.account();
    let c_pass =
        std::ffi::CString::new(pass).map_err(|_| "passphrase contains a NUL".to_string())?;
    let mut out = empty_session();
    // SAFETY: the account borrows live Vecs, the passphrase is NUL-
    // terminated, out is our local - all valid for the duration of the
    // call, which is exactly fxcffi.h's contract.
    let code = unsafe { fxcffi::fx_unlock_account(&account, c_pass.as_ptr(), &mut out) };
    let packed = take_packed_session(&mut out);
    if code != fxcffi::FX_OK {
        return Err(format!("unlock: {}", unsafe_name(code)));
    }
    packed
}

/// The same session, opened with the recovery key instead of the
/// passphrase (S3: `unlock (passphrase + recovery)`).
fn unlock_recovery_impl(
    env: &mut JNIEnv,
    keys: &JString,
    recovery_hex: &JString,
) -> Result<Vec<u8>, String> {
    let keys_json = String::from(env.get_string(keys).map_err(|e| format!("keys: {e}"))?);
    let hex = String::from(
        env.get_string(recovery_hex)
            .map_err(|e| format!("recovery key: {e}"))?,
    );
    let decoded = DecodedKeys::from_json(&keys_json)?;
    let account = decoded.account();
    let recovery = decode_hex(&hex)?;
    let mut out = empty_session();
    // SAFETY: account borrows live Vecs, recovery is our own buffer,
    // out is our local - all valid for the call (fxcffi.h's contract).
    let code = unsafe {
        fxcffi::fx_open_with_recovery(&account, recovery.as_ptr(), recovery.len(), &mut out)
    };
    let packed = take_packed_session(&mut out);
    if code != fxcffi::FX_OK {
        return Err(format!("recovery: {}", unsafe_name(code)));
    }
    packed
}

/// Unwrap a child record or a wrapped name under its parent key:
/// `parentKey(32) || childId || blob` -> the raw value (a name as
/// UTF-8, a key as bytes). The blob may be standard or URL-safe base64
/// (names are URL-safe per concepts/names.md N3). Failure arrives as a
/// Java exception - the caller distinguishes "not mine" by catching,
/// exactly like the JS twin's `null`.
///
/// # Safety
/// Standard JNI contract: `parent_key` is a JVM array for this call.
#[no_mangle]
pub extern "system" fn Java_de_frischux_fxcloud_FxCore_unwrapChild(
    mut env: JNIEnv,
    _class: JClass,
    parent_key: jni::objects::JByteArray,
    child_id: jni::sys::jlong,
    wrapped: JString,
) -> jni::sys::jbyteArray {
    match unwrap_child_impl(&mut env, &parent_key, child_id, &wrapped) {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalStateException", e.to_string());
                std::ptr::null_mut()
            }
        },
        Err(msg) => {
            let _ = env.throw_new("java/lang/RuntimeException", &msg);
            std::ptr::null_mut()
        }
    }
}

fn unwrap_child_impl(
    env: &mut JNIEnv,
    parent_key: &jni::objects::JByteArray,
    child_id: jni::sys::jlong,
    wrapped: &JString,
) -> Result<Vec<u8>, String> {
    let parent = env
        .convert_byte_array(parent_key)
        .map_err(|e| format!("parent key: {e}"))?;
    if parent.len() != 32 {
        return Err(format!("parent key must be32 bytes, got {}", parent.len()));
    }
    let blob_str = String::from(
        env.get_string(wrapped)
            .map_err(|e| format!("wrapped: {e}"))?,
    );
    // Names are URL-safe, key records standard: normalize, then one
    // decoder handles both (both arrive padded).
    let normalized = blob_str.replace('-', "+").replace('_', "/");
    let blob = base64::engine::general_purpose::STANDARD
        .decode(normalized.trim())
        .map_err(|e| format!("base64: {e}"))?;

    let mut aad = fxcffi::FxBytes {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    // SAFETY: out is our local; the core fills it on success.
    let code = unsafe { fxcffi::fx_child_key_aad(child_id as u64, &mut aad) };
    if code != fxcffi::FX_OK {
        unsafe { fxcffi::fx_free(aad.ptr, aad.len) };
        return Err(format!("aad: {}", unsafe_name(code)));
    }

    let mut out = fxcffi::FxBytes {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    // SAFETY: inputs valid for this call (slices above), out is local.
    let code = unsafe {
        fxcffi::fx_unwrap(
            parent.as_ptr(),
            parent.len(),
            blob.as_ptr(),
            blob.len(),
            aad.ptr,
            aad.len,
            &mut out,
        )
    };
    // SAFETY: aad was allocated by the core, release it either way.
    unsafe { fxcffi::fx_free(aad.ptr, aad.len) };
    if code != fxcffi::FX_OK {
        unsafe { fxcffi::fx_free(out.ptr, out.len) };
        return Err(format!("unwrap: {}", unsafe_name(code)));
    }
    let value = if out.ptr.is_null() {
        Vec::new()
    } else {
        // SAFETY: the core filled out with out.len bytes.
        unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec()
    };
    // SAFETY: a buffer from fx_unwrap goes back through fx_free.
    unsafe { fxcffi::fx_free(out.ptr, out.len) };
    Ok(value)
}

/// The static name of a code, without unwrapping Result plumbing.
fn unsafe_name(code: i32) -> String {
    // SAFETY: fx_error_name returns a static NUL-terminated string.
    unsafe {
        std::ffi::CStr::from_ptr(fxcffi::fx_error_name(code))
            .to_string_lossy()
            .into_owned()
    }
}

// ---- S3: content crypto, recovery sessions, share envelopes -------------

fn empty_bytes() -> fxcffi::FxBytes {
    fxcffi::FxBytes {
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

fn bytes_arg(env: &mut JNIEnv, arr: &JByteArray, what: &str) -> Result<Vec<u8>, String> {
    env.convert_byte_array(arr)
        .map_err(|e| format!("{what}: {e}"))
}

/// Copy an fxcffi result out, release it, and translate a failing code
/// into the exception text (the code name, as everywhere in this glue).
fn take_out(code: i32, out: &mut fxcffi::FxBytes, what: &str) -> Result<Vec<u8>, String> {
    let bytes = read_bytes(out);
    // SAFETY: a buffer from fxcffi goes back through fx_free (NULL is a no-op).
    unsafe { fxcffi::fx_free(out.ptr, out.len) };
    if code != fxcffi::FX_OK {
        return Err(format!("{what}: {}", unsafe_name(code)));
    }
    Ok(bytes)
}

/// The AAD binding a share envelope to its source id and grantee (5.5).
fn envelope_aad(source_id: u64, grantee: &std::ffi::CStr) -> Result<Vec<u8>, String> {
    let mut out = empty_bytes();
    // SAFETY: grantee is our CString, out is our local.
    let code = unsafe { fxcffi::fx_share_envelope_aad(source_id, grantee.as_ptr(), &mut out) };
    take_out(code, &mut out, "envelope aad")
}

fn to_jbytes(env: &mut JNIEnv, result: Result<Vec<u8>, String>) -> jni::sys::jbyteArray {
    match result {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalStateException", e.to_string());
                std::ptr::null_mut()
            }
        },
        Err(msg) => {
            let _ = env.throw_new("java/lang/RuntimeException", &msg);
            std::ptr::null_mut()
        }
    }
}

/// FXE1-encrypt a file body (S3): file id +32-byte content key in, the
/// container the server stores without reading it out. Bound to the id:
/// a row move fails decryption, exactly like the web's write side.
///
/// # Safety
/// Standard JNI contract: the arrays are valid JVM objects for this call.
#[no_mangle]
pub extern "system" fn Java_de_frischux_fxcloud_FxCore_encryptBytes(
    mut env: JNIEnv,
    _class: JClass,
    file_id: jni::sys::jlong,
    key: JByteArray,
    plain: JByteArray,
) -> jni::sys::jbyteArray {
    let result = encrypt_impl(&mut env, file_id, &key, &plain);
    to_jbytes(&mut env, result)
}

fn encrypt_impl(
    env: &mut JNIEnv,
    file_id: jni::sys::jlong,
    key: &JByteArray,
    plain: &JByteArray,
) -> Result<Vec<u8>, String> {
    let key = bytes_arg(env, key, "key")?;
    let plain = bytes_arg(env, plain, "plain")?;
    let mut out = empty_bytes();
    // SAFETY: our copies are readable for their lengths, out is local.
    let code = unsafe {
        fxcffi::fx1_encrypt(
            file_id as u64,
            key.as_ptr(),
            key.len(),
            plain.as_ptr(),
            plain.len(),
            &mut out,
        )
    };
    take_out(code, &mut out, "encrypt")
}

/// Decrypt an FXE1 container (S3 read side); wrong key, wrong id,
/// tampering and non-containers all arrive as `FX_ERR_*` exceptions.
///
/// # Safety
/// Standard JNI contract: the arrays are valid JVM objects for this call.
#[no_mangle]
pub extern "system" fn Java_de_frischux_fxcloud_FxCore_decryptBytes(
    mut env: JNIEnv,
    _class: JClass,
    file_id: jni::sys::jlong,
    key: JByteArray,
    container: JByteArray,
) -> jni::sys::jbyteArray {
    let result = decrypt_impl(&mut env, file_id, &key, &container);
    to_jbytes(&mut env, result)
}

fn decrypt_impl(
    env: &mut JNIEnv,
    file_id: jni::sys::jlong,
    key: &JByteArray,
    container: &JByteArray,
) -> Result<Vec<u8>, String> {
    let key = bytes_arg(env, key, "key")?;
    let container = bytes_arg(env, container, "container")?;
    let mut out = empty_bytes();
    // SAFETY: our copies are readable for their lengths, out is local.
    let code = unsafe {
        fxcffi::fx1_decrypt(
            file_id as u64,
            key.as_ptr(),
            key.len(),
            container.as_ptr(),
            container.len(),
            &mut out,
        )
    };
    take_out(code, &mut out, "decrypt")
}

/// Open the account with the32-byte recovery key instead of the
/// passphrase (S3): hex in, the same packed session `unlock` returns.
///
/// # Safety
/// Standard JNI contract: both strings are valid JVM objects for this call.
#[no_mangle]
pub extern "system" fn Java_de_frischux_fxcloud_FxCore_unlockWithRecovery(
    mut env: JNIEnv,
    _class: JClass,
    keys: JString,
    recovery_hex: JString,
) -> jni::sys::jbyteArray {
    let result = unlock_recovery_impl(&mut env, &keys, &recovery_hex);
    to_jbytes(&mut env, result)
}

/// The AAD that binds a share envelope to source id + grantee (5.5),
/// so an envelope from another share or user cannot open.
///
/// # Safety
/// Standard JNI contract: both arguments are valid JVM objects.
#[no_mangle]
pub extern "system" fn Java_de_frischux_fxcloud_FxCore_shareEnvelopeAad(
    mut env: JNIEnv,
    _class: JClass,
    source_id: jni::sys::jlong,
    grantee: JString,
) -> jni::sys::jbyteArray {
    let result = share_aad_impl(&mut env, source_id, &grantee);
    to_jbytes(&mut env, result)
}

fn share_aad_impl(
    env: &mut JNIEnv,
    source_id: jni::sys::jlong,
    grantee: &JString,
) -> Result<Vec<u8>, String> {
    let grantee = String::from(
        env.get_string(grantee)
            .map_err(|e| format!("grantee: {e}"))?,
    );
    let c_grantee =
        std::ffi::CString::new(grantee).map_err(|_| "grantee contains a NUL".to_string())?;
    envelope_aad(source_id as u64, &c_grantee)
}

/// Open an envelope sealed to me with my pkcs8 (S3/S4): the share
/// record out, `FX_ERR_UNWRAP` for a wrong recipient, a tampered blob
/// or a foreign AAD - one message on purpose (5.5).
///
/// # Safety
/// Standard JNI contract: the arrays are valid JVM objects for this call.
#[no_mangle]
pub extern "system" fn Java_de_frischux_fxcloud_FxCore_eciesOpen(
    mut env: JNIEnv,
    _class: JClass,
    envelope: JByteArray,
    recipient_pkcs8: JByteArray,
    source_id: jni::sys::jlong,
    grantee: JString,
) -> jni::sys::jbyteArray {
    let result = ecies_open_impl(&mut env, &envelope, &recipient_pkcs8, source_id, &grantee);
    to_jbytes(&mut env, result)
}

fn ecies_open_impl(
    env: &mut JNIEnv,
    envelope: &JByteArray,
    recipient_pkcs8: &JByteArray,
    source_id: jni::sys::jlong,
    grantee: &JString,
) -> Result<Vec<u8>, String> {
    let envelope = bytes_arg(env, envelope, "envelope")?;
    let pkcs8 = bytes_arg(env, recipient_pkcs8, "recipient key")?;
    let grantee = String::from(
        env.get_string(grantee)
            .map_err(|e| format!("grantee: {e}"))?,
    );
    let c_grantee =
        std::ffi::CString::new(grantee).map_err(|_| "grantee contains a NUL".to_string())?;
    let aad = envelope_aad(source_id as u64, &c_grantee)?;
    let mut out = empty_bytes();
    // SAFETY: our copies and the aad are readable, out is local.
    let code = unsafe {
        fxcffi::fx_ecies_open(
            pkcs8.as_ptr(),
            pkcs8.len(),
            envelope.as_ptr(),
            envelope.len(),
            aad.as_ptr(),
            aad.len(),
            &mut out,
        )
    };
    take_out(code, &mut out, "ecies open")
}

/// Seal a share record to a recipient's public key (the primitive S4's
/// share dialog calls): ephemeral key inside, so the envelope bytes are
/// fresh every time - the golden pin is the error side plus a
/// seal->open roundtrip on the JVM.
///
/// # Safety
/// Standard JNI contract: the arrays are valid JVM objects for this call.
#[no_mangle]
pub extern "system" fn Java_de_frischux_fxcloud_FxCore_eciesSeal(
    mut env: JNIEnv,
    _class: JClass,
    recipient_public: JByteArray,
    plain: JByteArray,
    source_id: jni::sys::jlong,
    grantee: JString,
) -> jni::sys::jbyteArray {
    let result = ecies_seal_impl(&mut env, &recipient_public, &plain, source_id, &grantee);
    to_jbytes(&mut env, result)
}

fn ecies_seal_impl(
    env: &mut JNIEnv,
    recipient_public: &JByteArray,
    plain: &JByteArray,
    source_id: jni::sys::jlong,
    grantee: &JString,
) -> Result<Vec<u8>, String> {
    let recipient = bytes_arg(env, recipient_public, "recipient public key")?;
    let plain = bytes_arg(env, plain, "plain")?;
    let grantee = String::from(
        env.get_string(grantee)
            .map_err(|e| format!("grantee: {e}"))?,
    );
    let c_grantee =
        std::ffi::CString::new(grantee).map_err(|_| "grantee contains a NUL".to_string())?;
    let aad = envelope_aad(source_id as u64, &c_grantee)?;
    let mut out = empty_bytes();
    // SAFETY: our copies and the aad are readable, out is local.
    let code = unsafe {
        fxcffi::fx_ecies_seal(
            recipient.as_ptr(),
            recipient.len(),
            plain.as_ptr(),
            plain.len(),
            aad.as_ptr(),
            aad.len(),
            &mut out,
        )
    };
    take_out(code, &mut out, "ecies seal")
}
