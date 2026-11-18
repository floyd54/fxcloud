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

use jni::objects::{JByteArray, JClass};
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
