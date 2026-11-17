//! Golden-vector parity for the account-key layer (Phase 5 Slice 2a).
//!
//! `tests/fixtures/fx-keys-vectors.json` is written by
//! `frontend/tests/gen-key-vectors.js` (the spec side: it holds the AAD
//! labels, runs the real fxcrypto.js once per artifact) and verified by
//! the JS implementation on every suite run. This file pins the *Rust*
//! twin to the same bytes: every kdf/unlock/session/recovery/child/
//! fingerprint case must agree field for field, every reject case must
//! fail with the committed message - a drift in either implementation
//! turns CI red.
//!
//! The vector cases pin the read side (wraps carry fresh nonces); the
//! tests at the bottom roundtrip the Rust write side on itself.

use base64::Engine as _;
use fxcrypto::{
    child_key_aad, derive_kek, derive_recovery_kek, ecies_open, ecies_seal, fingerprint_hex,
    generate_key_pair, open_with_recovery, rewrap_account, session_from_ark, share_envelope_aad,
    unlock_account, unwrap, unwrap_child_key, wrap, wrap_child_key, AccountKeys, Error, KdfParams,
    Session, AAD_ARK, AAD_ARK_RECOVERY, AAD_PRIVKEY, AAD_ROOTKEY, KDF_M_KIB, KDF_P, KDF_T,
    SALT_LEN, SUITE_P256,
};
use serde_json::Value;

#[derive(serde::Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

/// One flat record: every kind fills a different subset of the optional
/// fields (the JS generator documents which ones each kind carries).
#[derive(serde::Deserialize)]
struct Case {
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
    aad: Option<Value>,
    #[serde(default)]
    plaintext_b64: Option<String>,
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

fn load_vectors() -> Vectors {
    serde_json::from_str(include_str!("../../../tests/fixtures/fx-keys-vectors.json"))
        .expect("fx-keys-vectors.json parses")
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("base64")
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex must be even-length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// Stored `kdf_params` -> [`KdfParams`], `0`/absent = floor (the `|| FLOOR`
/// semantics of fxcrypto.js `deriveKek`).
fn kdf_params_of(v: Option<&Value>) -> KdfParams {
    let p = match v {
        Some(p) => p,
        None => return KdfParams::default(),
    };
    KdfParams::with_defaults(
        p["m"].as_u64().unwrap_or(0) as u32,
        p["t"].as_u64().unwrap_or(0) as u32,
        p["p"].as_u64().unwrap_or(0) as u32,
    )
}

fn keys_of(v: &Value) -> AccountKeys {
    let field = |name: &str| b64(v[name].as_str().unwrap_or_else(|| panic!("{name} present")));
    AccountKeys {
        kdf_salt: field("kdf_salt"),
        kdf_params: kdf_params_of(v.get("kdf_params")),
        wrapped_ark: field("wrapped_ark"),
        wrapped_root_key: field("wrapped_root_key"),
        private_key_wrapped: field("private_key_wrapped"),
        public_key: field("public_key"),
        wrapped_ark_recovery: field("wrapped_ark_recovery"),
    }
}

/// Field-by-field session comparison against the committed expect block;
/// `None` = match.
fn session_diff(s: &Session, expect: &Value) -> Option<String> {
    let pairs: [(&str, &[u8]); 4] = [
        ("ark_b64", &s.ark),
        ("root_key_b64", &s.root_key),
        ("private_key_pkcs8_b64", &s.private_key_pkcs8),
        ("public_blob_b64", &s.public_blob),
    ];
    for (field, got) in pairs {
        let want = b64(expect[field].as_str().unwrap_or(""));
        if want != got {
            return Some(format!("session field {field} differs"));
        }
    }
    if expect["suite"].as_u64() != Some(u64::from(s.suite)) {
        return Some("session field suite differs".to_string());
    }
    None
}

/// The envelope AAD a case names ({source_id, grantee}), through the spec
/// function both implementations share.
fn envelope_aad(c: &Case) -> Vec<u8> {
    let aad = c.aad.as_ref().expect("aad present");
    share_envelope_aad(
        aad["source_id"].as_u64().expect("source_id"),
        aad["grantee"].as_str().expect("grantee"),
    )
}

/// Run one case; `Ok(())` = matched (or, for reject cases, failed with the
/// committed message), `Err(msg)` = mismatch.
fn run_case(c: &Case) -> Result<(), String> {
    match c.kind.as_str() {
        "kdf" => {
            let salt = b64(c.salt_b64.as_ref().ok_or("salt missing")?);
            let got = derive_kek(
                c.passphrase.as_deref().ok_or("passphrase missing")?,
                &salt,
                kdf_params_of(c.params.as_ref()),
            )
            .map_err(|e| e.to_string())?;
            if hex_decode(c.kek_hex.as_ref().ok_or("kek_hex missing")?) != got[..] {
                return Err("kek differs".to_string());
            }
        }
        "session" | "unlock" | "recovery_open" => {
            let keys = keys_of(c.keys.as_ref().ok_or("keys missing")?);
            let session = match c.kind.as_str() {
                "session" => {
                    session_from_ark(&keys, &b64(c.ark_b64.as_ref().ok_or("ark missing")?))
                }
                "unlock" => {
                    unlock_account(&keys, c.passphrase.as_deref().ok_or("passphrase missing")?)
                }
                _ => open_with_recovery(
                    &keys,
                    &b64(c.recovery_key_b64.as_ref().ok_or("recovery missing")?),
                ),
            }
            .map_err(|e| e.to_string())?;
            if let Some(diff) = session_diff(&session, c.expect.as_ref().ok_or("expect missing")?) {
                return Err(diff);
            }
        }
        "rewrap" => {
            // The committed rewrap output must reopen the same ARK under
            // the new passphrase (the generator produced it with the real
            // rewrapAccount, random nonce and all).
            let mut keys = keys_of(c.keys.as_ref().ok_or("keys missing")?);
            let re = c.rewrap.as_ref().ok_or("rewrap missing")?;
            keys.wrapped_ark = b64(re["wrapped_ark"].as_str().ok_or("wrapped_ark missing")?);
            keys.kdf_salt = b64(re["kdf_salt"].as_str().ok_or("kdf_salt missing")?);
            keys.kdf_params = kdf_params_of(re.get("kdf_params"));
            let session = unlock_account(
                &keys,
                c.new_passphrase
                    .as_deref()
                    .ok_or("new_passphrase missing")?,
            )
            .map_err(|e| e.to_string())?;
            let want = b64(c.ark_b64.as_ref().ok_or("ark missing")?);
            if session.ark != want {
                return Err("rewrapped ark does not reopen".to_string());
            }
        }
        "child" => {
            let parent = hex_decode(c.parent_key_hex.as_ref().ok_or("parent missing")?);
            let wrapped = b64(c.wrapped_child_b64.as_ref().ok_or("wrapped missing")?);
            let got = unwrap_child_key(&parent, c.child_id.ok_or("child_id missing")?, &wrapped)
                .map_err(|e| e.to_string())?;
            let want = hex_decode(c.child_key_hex.as_ref().ok_or("child_key missing")?);
            if got != want {
                return Err("child key differs".to_string());
            }
        }
        "fingerprint" => {
            let blob = b64(c.public_blob_b64.as_ref().ok_or("public_blob missing")?);
            let got = fingerprint_hex(&blob);
            let want = c.fingerprint_hex.as_ref().ok_or("fingerprint missing")?;
            if &got != want {
                return Err("fingerprint differs".to_string());
            }
        }
        "unwrap" => {
            let key = hex_decode(c.key_hex.as_ref().ok_or("key missing")?);
            let wrapped = b64(c.wrapped_b64.as_ref().ok_or("wrapped missing")?);
            let aad = b64(c.aad_b64.as_ref().ok_or("aad missing")?);
            unwrap(&key, &wrapped, &aad).map_err(|e| e.to_string())?;
        }
        "ecies_open" => {
            let aad = envelope_aad(c);
            let pkcs8 = b64(c
                .recipient_pkcs8_b64
                .as_ref()
                .ok_or("recipient_pkcs8 missing")?);
            let envelope = b64(c.envelope_b64.as_ref().ok_or("envelope missing")?);
            let got = ecies_open(&pkcs8, &envelope, &aad).map_err(|e| e.to_string())?;
            let want = b64(c.plaintext_b64.as_ref().ok_or("plaintext missing")?);
            if got != want {
                return Err("plaintext differs".to_string());
            }
        }
        "ecies_seal" => {
            let aad = envelope_aad(c);
            let recipient = b64(c.recipient_public_b64.as_ref().ok_or("recipient missing")?);
            let plain = b64(c.plaintext_b64.as_ref().ok_or("plaintext missing")?);
            ecies_seal(&recipient, &plain, &aad).map_err(|e| e.to_string())?;
        }
        other => return Err(format!("unknown case kind {other}")),
    }
    Ok(())
}

#[test]
fn golden_key_vectors_open_or_reject_exactly_as_committed() {
    let vectors = load_vectors();
    assert!(!vectors.cases.is_empty(), "no vectors loaded");
    let (mut passed, mut rejects) = (0usize, 0usize);
    for case in &vectors.cases {
        match run_case(case) {
            Ok(()) => {
                assert!(
                    !case.expect_error,
                    "{}: expected an error, got success",
                    case.name
                );
                passed += 1;
            }
            Err(msg) => {
                assert!(case.expect_error, "{}: {msg}", case.name);
                let want = case.error_contains.as_deref().unwrap_or("");
                assert!(
                    msg.contains(want),
                    "{}: error {msg:?} does not contain {want:?}",
                    case.name
                );
                rejects += 1;
            }
        }
    }
    assert!(passed >= 10 && rejects >= 6, "matrix incomplete");
    assert_eq!(passed + rejects, vectors.cases.len());
}

/// The Rust write side on itself: a mini-setup (the same primitives the
/// vectors use), then all three doors open the same session, then a
/// passphrase change moves only the ARK wrap.
#[test]
fn rust_side_full_unlock_roundtrip() {
    let pass = "rust roundtrip passphrase";
    let mut salt = [0u8; SALT_LEN];
    rand::fill(&mut salt);
    let kek = derive_kek(pass, &salt, KdfParams::default()).expect("floor params derive");

    let ark = [11u8; fxcrypto::KEY_LEN];
    let root = [12u8; fxcrypto::KEY_LEN];
    let pkcs8 = [13u8; fxcrypto::KEY_LEN];
    let recovery = [14u8; fxcrypto::KEY_LEN];
    let mut public_blob = vec![fxcrypto::SUITE_X25519];
    public_blob.extend_from_slice(&[22u8; 32]);

    let recovery_kek = derive_recovery_kek(&recovery, &salt).expect("recovery kek");
    let keys = AccountKeys {
        kdf_salt: salt.to_vec(),
        kdf_params: KdfParams::default(),
        wrapped_ark: wrap(&kek, &ark, AAD_ARK).expect("wrap ark"),
        wrapped_root_key: wrap(&ark, &root, AAD_ROOTKEY).expect("wrap root"),
        private_key_wrapped: wrap(&ark, &pkcs8, AAD_PRIVKEY).expect("wrap priv"),
        public_key: public_blob.clone(),
        wrapped_ark_recovery: wrap(&recovery_kek, &ark, AAD_ARK_RECOVERY).expect("wrap rec"),
    };

    let by_pass = unlock_account(&keys, pass).expect("passphrase opens");
    let by_recovery = open_with_recovery(&keys, &recovery).expect("recovery opens");
    let by_ark = session_from_ark(&keys, &ark).expect("ark opens");
    for s in [&by_pass, &by_recovery, &by_ark] {
        assert_eq!(s.root_key, root, "root key");
        assert_eq!(s.private_key_pkcs8, pkcs8, "private key");
        assert_eq!(s.public_blob, public_blob, "public blob");
        assert_eq!(s.suite, fxcrypto::SUITE_X25519, "suite");
        assert_eq!(s.ark, ark, "ark");
    }

    // Wrong passphrase fails with the unified message (5.4).
    let err = unlock_account(&keys, "wrong passphrase")
        .expect_err("must fail")
        .to_string();
    assert!(
        err.contains("could not unwrap this key - wrong passphrase, or the data was altered"),
        "unified message: {err}"
    );

    // Passphrase change: O(1), old passphrase stops working.
    let re = rewrap_account(&ark, "brand new rust passphrase").expect("rewrap");
    assert_eq!(re.kdf_salt.len(), SALT_LEN, "fresh salt length");
    assert_eq!(re.kdf_params, KdfParams::default(), "floor params");
    let mut keys2 = keys.clone();
    keys2.wrapped_ark = re.wrapped_ark;
    keys2.kdf_salt = re.kdf_salt;
    keys2.kdf_params = re.kdf_params;
    unlock_account(&keys2, "brand new rust passphrase").expect("new passphrase opens");
    unlock_account(&keys2, pass).expect_err("old passphrase stops working");
}

/// Wrap/unwrap: fresh nonces, domain separation, and the exact rejection
/// messages both implementations must share.
#[test]
fn wrap_unwrap_domain_separation_and_messages() {
    let key = [7u8; fxcrypto::KEY_LEN];
    let value = b"record bytes".to_vec();
    let blob = wrap(&key, &value, AAD_ARK).expect("wrap");
    assert_eq!(unwrap(&key, &blob, AAD_ARK).expect("unwrap"), value);
    assert_ne!(
        wrap(&key, &value, AAD_ARK).expect("wrap"),
        blob,
        "fresh nonce per wrap"
    );

    // Same blob, other purpose: AAD mismatch is indistinguishable from a
    // wrong key (5.4) - one unified message.
    let err = unwrap(&key, &blob, AAD_ROOTKEY)
        .expect_err("aad mismatch")
        .to_string();
    assert!(
        err.contains("could not unwrap this key - wrong passphrase, or the data was altered"),
        "unified message: {err}"
    );

    // One byte under nonce + tag: the exact short-blob message.
    let err = unwrap(&key, &blob[..27], AAD_ARK)
        .expect_err("too short")
        .to_string();
    assert_eq!(err, "wrapped value is too short to be a key record");

    // Tampering flips the tag check into the same unified message.
    let mut tampered = blob.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        unwrap(&key, &tampered, AAD_ARK),
        Err(Error::Unwrap)
    ));

    // Key length is checked by both sides.
    assert!(matches!(
        wrap(&[0u8; fxcrypto::KEY_LEN - 1], &value, AAD_ARK),
        Err(Error::KeyLength)
    ));

    // child aad = u64be(child) || version byte.
    let aad = child_key_aad(0x0102_0304_0506_0708);
    assert_eq!(&aad[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(aad[8], fxcrypto::KEY_RECORD_VERSION);

    // A child record only opens under the right parent and id.
    let child = [9u8; fxcrypto::KEY_LEN];
    let parent = [8u8; fxcrypto::KEY_LEN];
    let wrapped = wrap_child_key(&parent, 42, &child).expect("wrap child");
    assert_eq!(
        unwrap_child_key(&parent, 42, &wrapped).expect("unwrap child"),
        child
    );
    assert!(matches!(
        unwrap_child_key(&parent, 43, &wrapped),
        Err(Error::Unwrap)
    ));
    let mut other = parent;
    other[0] ^= 1;
    assert!(matches!(
        unwrap_child_key(&other, 42, &wrapped),
        Err(Error::Unwrap)
    ));
}

/// KDF parameter semantics: floor defaults, `0`/absent = floor, and
/// argon2id rejects implausible parameters with the Kdf error.
#[test]
fn kdf_parameter_semantics() {
    assert_eq!(
        KdfParams::default(),
        KdfParams {
            m: KDF_M_KIB,
            t: KDF_T,
            p: KDF_P
        }
    );
    assert_eq!(KdfParams::with_defaults(0, 0, 0), KdfParams::default());
    assert_eq!(
        KdfParams::with_defaults(131072, 2, 1),
        KdfParams {
            m: 131072,
            t: 2,
            p: 1
        }
    );
    let salt = [3u8; SALT_LEN];
    assert!(matches!(
        derive_kek("x", &salt, KdfParams { m: 1, t: 1, p: 1 }),
        Err(Error::Kdf)
    ));
    // A too-short salt is argon2's complaint, surfaced as Kdf (5.1 has no
    // separate salt rule; the floor parameters require >=8 bytes * p).
    assert!(matches!(
        derive_kek("x", &[], KdfParams::default()),
        Err(Error::Kdf)
    ));
}

/// ECIES on both suites (5.5): seal -> open roundtrip, the unified
/// failures, and the committed messages for garbage recipients.
#[test]
fn envelope_roundtrip_on_both_suites() {
    let aad = share_envelope_aad(77, "user-9");
    let plain = b"sealed folder key".to_vec();
    for preferred in [None, Some(SUITE_P256)] {
        let kp = generate_key_pair(preferred).expect("key pair");
        assert_eq!(kp.suite, preferred.unwrap_or(fxcrypto::SUITE_X25519));
        assert_eq!(kp.public_blob[0], kp.suite, "suite leads the blob");

        let env = ecies_seal(&kp.public_blob, &plain, &aad).expect("seal");
        let point_len = if kp.suite == fxcrypto::SUITE_X25519 {
            33
        } else {
            66
        };
        assert_eq!(
            env.len(),
            point_len + fxcrypto::NONCE_LEN + plain.len() + 16,
            "layout: suite||point||nonce12||ct||tag16"
        );
        assert_eq!(env[0], kp.suite, "suite byte leads");
        assert_eq!(ecies_open(&kp.pkcs8, &env, &aad).expect("open"), plain);

        // Every way of not being the recipient ends in one message.
        let foreign = share_envelope_aad(77, "user-10");
        let err = ecies_open(&kp.pkcs8, &env, &foreign)
            .expect_err("foreign aad")
            .to_string();
        assert!(
            err.contains("could not unwrap this key - wrong passphrase, or the data was altered"),
            "unified message: {err}"
        );
        let mut tampered = env.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            ecies_open(&kp.pkcs8, &tampered, &aad),
            Err(Error::Unwrap)
        ));
        assert!(matches!(
            ecies_open(&kp.pkcs8, &env[..10], &aad),
            Err(Error::Unwrap)
        ));
        let mut unknown = env.clone();
        unknown[0] = 9;
        assert!(matches!(
            ecies_open(&kp.pkcs8, &unknown, &aad),
            Err(Error::Unwrap)
        ));
        let stranger = generate_key_pair(Some(kp.suite)).expect("stranger");
        assert!(matches!(
            ecies_open(&stranger.pkcs8, &env, &aad),
            Err(Error::Unwrap)
        ));
    }

    // Cross-suite: an X25519 key must not open a P-256 envelope (JS hits a
    // WebCrypto type error with browser-defined text; unified is ours).
    let x = generate_key_pair(None).expect("x key");
    let p = generate_key_pair(Some(SUITE_P256)).expect("p key");
    let env = ecies_seal(&p.public_blob, &plain, &aad).expect("seal p");
    assert!(matches!(
        ecies_open(&x.pkcs8, &env, &aad),
        Err(Error::Unwrap)
    ));

    // Sealing refuses garbage recipients with the committed messages.
    let err = ecies_seal(&[1], &plain, &aad)
        .expect_err("one-byte recipient")
        .to_string();
    assert_eq!(err, "recipient public key is too short");
    let err = ecies_seal(&[9, 1, 2], &plain, &aad)
        .expect_err("unknown suite")
        .to_string();
    assert_eq!(err, "unknown key suite 9");
}
