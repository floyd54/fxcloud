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

fn unlock_impl(env: &mut JNIEnv, keys: &JString, passphrase: &JString) -> Result<Vec<u8>, String> {
    let keys_json = String::from(env.get_string(keys).map_err(|e| format!("keys: {e}"))?);
    let pass = String::from(
        env.get_string(passphrase)
            .map_err(|e| format!("passphrase: {e}"))?,
    );
    let payload: KeysPayload =
        serde_json::from_str(&keys_json).map_err(|e| format!("keys json: {e}"))?;
    let b64 = |s: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| format!("base64: {e}"))
    };
    // Decode first, then borrow into the C struct: the Vecs must outlive
    // the call (the same discipline every C caller of fxcffi follows).
    let kdf_salt = b64(&payload.kdf_salt)?;
    let wrapped_ark = b64(&payload.wrapped_ark)?;
    let wrapped_root_key = b64(&payload.wrapped_root_key)?;
    let private_key_wrapped = b64(&payload.private_key_wrapped)?;
    let public_key = b64(&payload.public_key)?;
    let wrapped_ark_recovery = b64(&payload.wrapped_ark_recovery)?;
    let borrow = |v: &Vec<u8>| fxcffi::FxBytes {
        ptr: v.as_ptr() as *mut u8,
        len: v.len(),
    };
    let account = fxcffi::FxAccountKeys {
        kdf_salt: borrow(&kdf_salt),
        wrapped_ark: borrow(&wrapped_ark),
        wrapped_root_key: borrow(&wrapped_root_key),
        private_key_wrapped: borrow(&private_key_wrapped),
        public_key: borrow(&public_key),
        wrapped_ark_recovery: borrow(&wrapped_ark_recovery),
        kdf_m: payload.kdf_params.m.unwrap_or(0),
        kdf_t: payload.kdf_params.t.unwrap_or(0),
        kdf_p: payload.kdf_params.p.unwrap_or(0),
    };
    let c_pass =
        std::ffi::CString::new(pass).map_err(|_| "passphrase contains a NUL".to_string())?;
    let empty = || fxcffi::FxBytes {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    let mut out = fxcffi::FxSession {
        ark: empty(),
        root_key: empty(),
        private_key_pkcs8: empty(),
        public_blob: empty(),
        suite: 0,
    };
    // SAFETY: the account borrows live Vecs, the passphrase is NUL-
    // terminated, out is our local - all valid for the duration of the
    // call, which is exactly fxcffi.h's contract.
    let code = unsafe { fxcffi::fx_unlock_account(&account, c_pass.as_ptr(), &mut out) };
    let read = |b: &fxcffi::FxBytes| -> Vec<u8> {
        if b.ptr.is_null() {
            Vec::new()
        } else {
            // SAFETY: the core filled this buffer; copied before free.
            unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
        }
    };
    let root = read(&out.root_key);
    let pkcs8 = read(&out.private_key_pkcs8);
    // SAFETY: a session from fx_unlock_account goes back through its free.
    unsafe { fxcffi::fx_session_free(&mut out) };
    if code != fxcffi::FX_OK {
        return Err(format!("unlock: {}", unsafe_name(code)));
    }
    if root.len() != 32 {
        return Err(format!("root key is {} bytes", root.len()));
    }
    let mut packed = Vec::with_capacity(36 + pkcs8.len());
    packed.extend_from_slice(&root);
    packed.extend_from_slice(&(pkcs8.len() as u32).to_be_bytes());
    packed.extend_from_slice(&pkcs8);
    Ok(packed)
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
