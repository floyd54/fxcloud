//! Third-reader parity: every golden vector through the C ABI.
//!
//! `tests/fixtures/fx1-vectors.json` and `tests/fixtures/fx-keys-vectors.json`
//! are already read by the JS implementation (gen-* --check) and by the
//! Rust implementation (crates/fxcrypto/tests/{golden,keys}.rs). This file
//! reads them a third way - across the boundary the native apps will use -
//! so a vector that only two readers can open turns red here too. It also
//! pins the code table (every reject must arrive as the *committed* stable
//! code) and the ownership contract (every success output is handed back
//! through `fx_free`/`fx_session_free`).

use base64::Engine as _;
use fxcffi::*;
use serde_json::Value;
use std::ffi::CStr;
use std::os::raw::c_char;

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("base64")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex must be even-length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// NUL-terminated copy of a fixture string for the `*const c_char` args.
fn cstr(s: &str) -> Vec<c_char> {
    s.bytes()
        .map(|b| b as c_char)
        .chain(std::iter::once(0))
        .collect()
}

fn cname(code: i32) -> String {
    // SAFETY: fx_error_name returns a static NUL-terminated string.
    unsafe { CStr::from_ptr(fx_error_name(code)) }
        .to_str()
        .expect("static name")
        .to_string()
}

fn null_bytes() -> FxBytes {
    FxBytes {
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

/// Read an output buffer and release it through the library's own free.
fn take(out: FxBytes) -> Vec<u8> {
    let v = if out.ptr.is_null() {
        Vec::new()
    } else {
        // SAFETY: out came from this library; freed right below.
        unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec()
    };
    // SAFETY: out came from this library; released through its own free.
    unsafe { fx_free(out.ptr, out.len) };
    v
}

fn slice_of(bytes: &FxBytes) -> &[u8] {
    if bytes.ptr.is_null() {
        &[]
    } else {
        // SAFETY: session fields came from this library and outlive the
        // borrow here (freed by fx_session_free afterwards).
        unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len) }
    }
}

/// The committed `error_contains` strings -> the stable code the C ABI
/// must answer with. Order matters: the recipient message contains the
/// generic public-key one.
fn expected_code(substr: &str) -> i32 {
    if substr.starts_with("not an FXE1") {
        FX_ERR_FORMAT_MAGIC
    } else if substr.starts_with("unsupported fxcloud") {
        FX_ERR_FORMAT_VERSION
    } else if substr.starts_with("unsupported cipher") {
        FX_ERR_FORMAT_SUITE
    } else if substr.starts_with("implausible chunk") {
        FX_ERR_FORMAT_CHUNK
    } else if substr.starts_with("malformed FXE1") {
        FX_ERR_MALFORMED_TAIL
    } else if substr.starts_with("file is too short") {
        FX_ERR_FORMAT_TOO_SHORT
    } else if substr.starts_with("decryption failed for chunk") {
        FX_ERR_CHUNK
    } else if substr.contains("recipient public key is too short") {
        FX_ERR_RECIPIENT_SHORT
    } else if substr.contains("wrapped value is too short") {
        FX_ERR_TOO_SHORT
    } else if substr.contains("public key is too short") {
        FX_ERR_PUBLIC_BLOB
    } else if substr.contains("unknown key suite") {
        FX_ERR_UNKNOWN_SUITE
    } else if substr.contains("could not unwrap this key") {
        FX_ERR_UNWRAP
    } else {
        panic!("no FFI code mapping for {substr:?}");
    }
}

// ---- fixture shapes ------------------------------------------------------

#[derive(serde::Deserialize)]
struct Fx1Vectors {
    cases: Vec<Fx1Case>,
}

#[derive(serde::Deserialize)]
struct Fx1Case {
    name: String,
    file_id: u64,
    key_hex: String,
    container_b64: String,
    #[serde(default)]
    plain_b64: Option<String>,
    #[serde(default)]
    expect_error: bool,
    #[serde(default)]
    error_contains: Option<String>,
}

#[derive(serde::Deserialize)]
struct KeyVectors {
    cases: Vec<KeyCase>,
}

/// One flat record: each kind fills a different subset (the generator
/// documents which); serde ignores the rest.
#[derive(serde::Deserialize)]
struct KeyCase {
    name: String,
    kind: String,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    salt_b64: Option<String>,
    #[serde(default)]
    params: Option<Value>,
    #[serde(default)]
    kek_hex: Option<String>,
    #[serde(default)]
    keys: Option<Value>,
    #[serde(default)]
    ark_b64: Option<String>,
    #[serde(default)]
    recovery_key_b64: Option<String>,
    #[serde(default)]
    new_passphrase: Option<String>,
    #[serde(default)]
    rewrap: Option<Value>,
    #[serde(default)]
    expect: Option<Value>,
    #[serde(default)]
    parent_key_hex: Option<String>,
    #[serde(default)]
    child_id: Option<u64>,
    #[serde(default)]
    wrapped_child_b64: Option<String>,
    #[serde(default)]
    child_key_hex: Option<String>,
    #[serde(default)]
    public_blob_b64: Option<String>,
    #[serde(default)]
    fingerprint_hex: Option<String>,
    #[serde(default)]
    envelope_b64: Option<String>,
    #[serde(default)]
    recipient_pkcs8_b64: Option<String>,
    #[serde(default)]
    recipient_public_b64: Option<String>,
    #[serde(default)]
    plaintext_b64: Option<String>,
    #[serde(default)]
    aad: Option<Value>,
    #[serde(default)]
    key_hex: Option<String>,
    #[serde(default)]
    wrapped_b64: Option<String>,
    #[serde(default)]
    aad_b64: Option<String>,
    #[serde(default)]
    expect_error: bool,
    #[serde(default)]
    error_contains: Option<String>,
}

/// A stored row: the byte fields live in this struct, the FxAccountKeys
/// handed to C only borrows their heap buffers (stable while `row` lives).
struct Row {
    salt: Vec<u8>,
    wrapped_ark: Vec<u8>,
    wrapped_root_key: Vec<u8>,
    private_key_wrapped: Vec<u8>,
    public_key: Vec<u8>,
    wrapped_ark_recovery: Vec<u8>,
    m: u32,
    t: u32,
    p: u32,
}

impl Row {
    fn from_json(v: &Value) -> Row {
        let field = |name: &str| b64(v[name].as_str().unwrap_or_else(|| panic!("{name} present")));
        let params = v.get("kdf_params");
        Row {
            salt: field("kdf_salt"),
            wrapped_ark: field("wrapped_ark"),
            wrapped_root_key: field("wrapped_root_key"),
            private_key_wrapped: field("private_key_wrapped"),
            public_key: field("public_key"),
            wrapped_ark_recovery: field("wrapped_ark_recovery"),
            // Absent or zeroed parameters mean floor (the `|| FLOOR`
            // semantics live inside the library, same as the JS twin).
            m: params.and_then(|p| p["m"].as_u64()).unwrap_or(0) as u32,
            t: params.and_then(|p| p["t"].as_u64()).unwrap_or(0) as u32,
            p: params.and_then(|p| p["p"].as_u64()).unwrap_or(0) as u32,
        }
    }

    fn keys(&self) -> FxAccountKeys {
        let borrow = |b: &Vec<u8>| FxBytes {
            ptr: b.as_ptr() as *mut u8,
            len: b.len(),
        };
        FxAccountKeys {
            kdf_salt: borrow(&self.salt),
            wrapped_ark: borrow(&self.wrapped_ark),
            wrapped_root_key: borrow(&self.wrapped_root_key),
            private_key_wrapped: borrow(&self.private_key_wrapped),
            public_key: borrow(&self.public_key),
            wrapped_ark_recovery: borrow(&self.wrapped_ark_recovery),
            kdf_m: self.m,
            kdf_t: self.t,
            kdf_p: self.p,
        }
    }
}

fn session_diff(s: &FxSession, expect: &Value) -> Option<String> {
    let pairs: [(&str, &[u8]); 4] = [
        ("ark_b64", slice_of(&s.ark)),
        ("root_key_b64", slice_of(&s.root_key)),
        ("private_key_pkcs8_b64", slice_of(&s.private_key_pkcs8)),
        ("public_blob_b64", slice_of(&s.public_blob)),
    ];
    for (field, got) in pairs {
        if b64(expect[field].as_str().unwrap_or("")) != got {
            return Some(format!("session field {field} differs"));
        }
    }
    if expect["suite"].as_u64() != Some(u64::from(s.suite)) {
        return Some("session field suite differs".to_string());
    }
    None
}

// ---- the two readers -----------------------------------------------------

#[test]
fn fx1_vectors_through_the_c_abi() {
    // SAFETY: every fixture buffer is a live local that outlives its call.
    unsafe {
        let doc: Fx1Vectors =
            serde_json::from_str(include_str!("../../../tests/fixtures/fx1-vectors.json"))
                .expect("fx1-vectors.json parses");
        assert!(!doc.cases.is_empty(), "no vectors loaded");
        let (mut passed, mut rejects) = (0usize, 0usize);
        for c in &doc.cases {
            let key = hex_decode(&c.key_hex);
            let container = b64(&c.container_b64);
            let mut out = null_bytes();
            let code = fx1_decrypt(
                c.file_id,
                key.as_ptr(),
                key.len(),
                container.as_ptr(),
                container.len(),
                &mut out,
            );
            if c.expect_error {
                let want = expected_code(c.error_contains.as_deref().unwrap_or(""));
                assert_eq!(
                    code,
                    want,
                    "{}: wrong code, got {} ({})",
                    c.name,
                    code,
                    cname(code)
                );
                rejects += 1;
            } else {
                assert_eq!(code, FX_OK, "{}: decrypt failed ({})", c.name, cname(code));
                let got = take(out);
                let want = b64(c.plain_b64.as_deref().expect("plain present"));
                assert_eq!(got, want, "{}: decrypted bytes differ", c.name);
                passed += 1;
            }
        }
        assert!(passed >= 4 && rejects >= 5, "matrix incomplete");
        assert_eq!(passed + rejects, doc.cases.len());
    }
}

enum Fail {
    /// The C call itself failed with this stable code.
    Code(i32),
    /// The call succeeded but the bytes did not match the fixture.
    Text(String),
}

/// # Safety
/// Same contract as the C ABI: every pointer passed in is valid for its
/// length (the fixtures build them from live `Vec`s that outlive the call).
unsafe fn run_key_case(c: &KeyCase) -> Result<(), Fail> {
    match c.kind.as_str() {
        "kdf" => {
            let salt = b64(c
                .salt_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("salt missing".into()))?);
            let pass = cstr(
                c.passphrase
                    .as_deref()
                    .ok_or_else(|| Fail::Text("passphrase missing".into()))?,
            );
            let p = c.params.as_ref();
            let m = p.and_then(|p| p["m"].as_u64()).unwrap_or(0) as u32;
            let t = p.and_then(|p| p["t"].as_u64()).unwrap_or(0) as u32;
            let pl = p.and_then(|p| p["p"].as_u64()).unwrap_or(0) as u32;
            let mut out = null_bytes();
            let code = fx_derive_kek(pass.as_ptr(), salt.as_ptr(), salt.len(), m, t, pl, &mut out);
            if code != FX_OK {
                return Err(Fail::Code(code));
            }
            let got = take(out);
            let want = c
                .kek_hex
                .as_ref()
                .ok_or_else(|| Fail::Text("kek missing".into()))?;
            if &hex_encode(&got) != want {
                return Err(Fail::Text("kek differs".into()));
            }
        }
        "session" | "unlock" | "recovery_open" => {
            let row = Row::from_json(
                c.keys
                    .as_ref()
                    .ok_or_else(|| Fail::Text("keys missing".into()))?,
            );
            let keys = row.keys();
            let mut sess = FxSession {
                ark: null_bytes(),
                root_key: null_bytes(),
                private_key_pkcs8: null_bytes(),
                public_blob: null_bytes(),
                suite: 0,
            };
            let code = match c.kind.as_str() {
                "session" => {
                    let ark = b64(c
                        .ark_b64
                        .as_ref()
                        .ok_or_else(|| Fail::Text("ark missing".into()))?);
                    fx_session_from_ark(&keys, ark.as_ptr(), ark.len(), &mut sess)
                }
                "unlock" => {
                    let pass = cstr(
                        c.passphrase
                            .as_deref()
                            .ok_or_else(|| Fail::Text("passphrase missing".into()))?,
                    );
                    fx_unlock_account(&keys, pass.as_ptr(), &mut sess)
                }
                _ => {
                    let rec = b64(c
                        .recovery_key_b64
                        .as_ref()
                        .ok_or_else(|| Fail::Text("recovery missing".into()))?);
                    fx_open_with_recovery(&keys, rec.as_ptr(), rec.len(), &mut sess)
                }
            };
            let diff = if code == FX_OK {
                session_diff(
                    &sess,
                    c.expect
                        .as_ref()
                        .ok_or_else(|| Fail::Text("expect missing".into()))?,
                )
            } else {
                None
            };
            fx_session_free(&mut sess);
            if code != FX_OK {
                return Err(Fail::Code(code));
            }
            if let Some(d) = diff {
                return Err(Fail::Text(d));
            }
        }
        "rewrap" => {
            // The committed rewrap output must reopen the same ARK.
            let mut row = Row::from_json(
                c.keys
                    .as_ref()
                    .ok_or_else(|| Fail::Text("keys missing".into()))?,
            );
            let re = c
                .rewrap
                .as_ref()
                .ok_or_else(|| Fail::Text("rewrap missing".into()))?;
            row.wrapped_ark = b64(re["wrapped_ark"]
                .as_str()
                .ok_or_else(|| Fail::Text("wrapped_ark missing".into()))?);
            row.salt = b64(re["kdf_salt"]
                .as_str()
                .ok_or_else(|| Fail::Text("kdf_salt missing".into()))?);
            row.m = re["kdf_params"]["m"].as_u64().unwrap_or(0) as u32;
            row.t = re["kdf_params"]["t"].as_u64().unwrap_or(0) as u32;
            row.p = re["kdf_params"]["p"].as_u64().unwrap_or(0) as u32;
            let keys = row.keys();
            let pass = cstr(
                c.new_passphrase
                    .as_deref()
                    .ok_or_else(|| Fail::Text("new_passphrase missing".into()))?,
            );
            let mut sess = FxSession {
                ark: null_bytes(),
                root_key: null_bytes(),
                private_key_pkcs8: null_bytes(),
                public_blob: null_bytes(),
                suite: 0,
            };
            let code = fx_unlock_account(&keys, pass.as_ptr(), &mut sess);
            let ark_ok = code == FX_OK
                && slice_of(&sess.ark)
                    == b64(c
                        .ark_b64
                        .as_ref()
                        .ok_or_else(|| Fail::Text("ark missing".into()))?);
            fx_session_free(&mut sess);
            if code != FX_OK {
                return Err(Fail::Code(code));
            }
            if !ark_ok {
                return Err(Fail::Text("rewrapped ark does not reopen".into()));
            }
        }
        "child" => {
            let parent = hex_decode(
                c.parent_key_hex
                    .as_ref()
                    .ok_or_else(|| Fail::Text("parent missing".into()))?,
            );
            let wrapped = b64(c
                .wrapped_child_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("wrapped missing".into()))?);
            let mut out = null_bytes();
            let code = fx_unwrap_child_key(
                parent.as_ptr(),
                parent.len(),
                c.child_id
                    .ok_or_else(|| Fail::Text("child_id missing".into()))?,
                wrapped.as_ptr(),
                wrapped.len(),
                &mut out,
            );
            if code != FX_OK {
                return Err(Fail::Code(code));
            }
            let got = take(out);
            let want = hex_decode(
                c.child_key_hex
                    .as_ref()
                    .ok_or_else(|| Fail::Text("child_key missing".into()))?,
            );
            if got != want {
                return Err(Fail::Text("child key differs".into()));
            }
        }
        "fingerprint" => {
            let blob = b64(c
                .public_blob_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("public_blob missing".into()))?);
            let mut out = null_bytes();
            let code = fx_fingerprint(blob.as_ptr(), blob.len(), &mut out);
            if code != FX_OK {
                return Err(Fail::Code(code));
            }
            let got = String::from_utf8(take(out))
                .map_err(|_| Fail::Text("fingerprint not utf8".into()))?;
            let want = c
                .fingerprint_hex
                .as_ref()
                .ok_or_else(|| Fail::Text("fingerprint missing".into()))?;
            if &got != want {
                return Err(Fail::Text("fingerprint differs".into()));
            }
        }
        "unwrap" => {
            let key = hex_decode(
                c.key_hex
                    .as_ref()
                    .ok_or_else(|| Fail::Text("key missing".into()))?,
            );
            let wrapped = b64(c
                .wrapped_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("wrapped missing".into()))?);
            let aad = b64(c
                .aad_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("aad missing".into()))?);
            let mut out = null_bytes();
            let code = fx_unwrap(
                key.as_ptr(),
                key.len(),
                wrapped.as_ptr(),
                wrapped.len(),
                aad.as_ptr(),
                aad.len(),
                &mut out,
            );
            if code == FX_OK {
                fx_free(out.ptr, out.len);
            } else {
                return Err(Fail::Code(code));
            }
        }
        "ecies_open" => {
            let pkcs8 = b64(c
                .recipient_pkcs8_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("recipient_pkcs8 missing".into()))?);
            let envelope = b64(c
                .envelope_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("envelope missing".into()))?);
            let aad = envelope_aad(c);
            let mut out = null_bytes();
            let code = fx_ecies_open(
                pkcs8.as_ptr(),
                pkcs8.len(),
                envelope.as_ptr(),
                envelope.len(),
                aad.as_ptr(),
                aad.len(),
                &mut out,
            );
            if code != FX_OK {
                return Err(Fail::Code(code));
            }
            let got = take(out);
            let want = b64(c
                .plaintext_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("plaintext missing".into()))?);
            if got != want {
                return Err(Fail::Text("plaintext differs".into()));
            }
        }
        "ecies_seal" => {
            let recipient = b64(c
                .recipient_public_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("recipient missing".into()))?);
            let plain = b64(c
                .plaintext_b64
                .as_ref()
                .ok_or_else(|| Fail::Text("plaintext missing".into()))?);
            let aad = envelope_aad(c);
            let mut out = null_bytes();
            let code = fx_ecies_seal(
                recipient.as_ptr(),
                recipient.len(),
                plain.as_ptr(),
                plain.len(),
                aad.as_ptr(),
                aad.len(),
                &mut out,
            );
            if code == FX_OK {
                fx_free(out.ptr, out.len);
            } else {
                return Err(Fail::Code(code));
            }
        }
        other => return Err(Fail::Text(format!("unknown case kind {other}"))),
    }
    Ok(())
}

fn envelope_aad(c: &KeyCase) -> Vec<u8> {
    let aad = c.aad.as_ref().expect("aad present");
    let grantee = aad["grantee"].as_str().expect("grantee");
    let mut out = null_bytes();
    // SAFETY: grantee is a fixture string (NUL-terminated copy), out is
    // our own local buffer.
    let code = unsafe {
        fx_share_envelope_aad(
            aad["source_id"].as_u64().expect("source_id"),
            cstr(grantee).as_ptr(),
            &mut out,
        )
    };
    assert_eq!(
        code,
        FX_OK,
        "fx_share_envelope_aad failed ({})",
        cname(code)
    );
    take(out)
}

#[test]
fn key_vectors_through_the_c_abi() {
    // SAFETY: every fixture buffer is a live local that outlives its call.
    unsafe {
        let doc: KeyVectors =
            serde_json::from_str(include_str!("../../../tests/fixtures/fx-keys-vectors.json"))
                .expect("fx-keys-vectors.json parses");
        assert!(!doc.cases.is_empty(), "no vectors loaded");
        let (mut passed, mut rejects) = (0usize, 0usize);
        for c in &doc.cases {
            match run_key_case(c) {
                Ok(()) => {
                    assert!(
                        !c.expect_error,
                        "{}: expected an error, got success",
                        c.name
                    );
                    passed += 1;
                }
                Err(Fail::Text(t)) => panic!("{}: {t}", c.name),
                Err(Fail::Code(code)) => {
                    assert!(
                        c.expect_error,
                        "{}: unexpected failure {} ({})",
                        c.name,
                        code,
                        cname(code)
                    );
                    let want = expected_code(c.error_contains.as_deref().unwrap_or(""));
                    assert_eq!(
                        code,
                        want,
                        "{}: wrong code, got {} ({})",
                        c.name,
                        code,
                        cname(code)
                    );
                    rejects += 1;
                }
            }
        }
        assert!(passed >= 10 && rejects >= 6, "matrix incomplete");
        assert_eq!(passed + rejects, doc.cases.len());
    }
}

/// The boundary contract itself: argument checks, the name table, and
/// idempotent frees.
#[test]
fn boundary_contract() {
    // SAFETY: only NULLs, statics and our own locals cross into the API.
    unsafe {
        // NULL out struct is an argument error, not a crash.
        assert_eq!(
            fx1_encrypt(
                1,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut()
            ),
            FX_ERR_ARG
        );
        // NULL input with a non-zero length is an argument error.
        let mut out = null_bytes();
        assert_eq!(
            fx1_decrypt(1, std::ptr::null(), 32, std::ptr::null(), 0, &mut out),
            FX_ERR_ARG
        );
        // Non-UTF-8 passphrase never reaches Argon2.
        let bad_pass: [c_char; 2] = [-1, 0];
        let salt = [0u8; 16];
        assert_eq!(
            fx_derive_kek(
                bad_pass.as_ptr(),
                salt.as_ptr(),
                salt.len(),
                0,
                0,
                0,
                &mut out
            ),
            FX_ERR_ARG
        );
        // NULL grantee is an argument error too.
        assert_eq!(
            fx_share_envelope_aad(1, std::ptr::null(), &mut out),
            FX_ERR_ARG
        );

        // Frees are NULL-safe; the name table covers every code and unknown
        // codes answer with the sentinel.
        fx_free(std::ptr::null_mut(), 0);
        fx_session_free(std::ptr::null_mut());
        fx_rewrapped_free(std::ptr::null_mut());
        fx_keypair_free(std::ptr::null_mut());
        for code in [
            FX_OK,
            FX_ERR_ARG,
            FX_ERR_PANIC,
            FX_ERR_FORMAT_TOO_SHORT,
            FX_ERR_FORMAT_MAGIC,
            FX_ERR_FORMAT_VERSION,
            FX_ERR_FORMAT_SUITE,
            FX_ERR_FORMAT_CHUNK,
            FX_ERR_MALFORMED_TAIL,
            FX_ERR_KEY_LENGTH,
            FX_ERR_AEAD,
            FX_ERR_CHUNK,
            FX_ERR_KDF,
            FX_ERR_HKDF,
            FX_ERR_TOO_SHORT,
            FX_ERR_UNWRAP,
            FX_ERR_PUBLIC_BLOB,
            FX_ERR_UNKNOWN_SUITE,
            FX_ERR_RECIPIENT_SHORT,
            FX_ERR_PKCS8,
        ] {
            let name = cname(code);
            assert!(name.starts_with("FX_"), "unnamed code {code}: {name}");
            assert_ne!(name, "FX_ERR_UNKNOWN_CODE", "code {code} missing a name");
        }
        assert_eq!(cname(-999), "FX_ERR_UNKNOWN_CODE");
    }
}
