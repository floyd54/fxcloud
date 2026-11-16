//! Golden-vector parity for the FXE1 format.
//!
//! `tests/fixtures/fx1-vectors.json` is written by
//! `frontend/tests/gen-fx1-vectors.js` (the spec side: it may pick its own
//! chunk size, which lives in the header) and verified by the JS
//! implementation on every suite run. This file pins the *Rust* twin to
//! the same bytes: every decrypt case must return exactly the committed
//! plaintext, every reject case must fail with the committed message -
//! a drift in either implementation turns CI red.

use base64::Engine as _;
use fxcrypto::{
    decrypt_bytes, encrypt_bytes, encrypt_bytes_with_chunk_size, read_header, Error, FormatError,
    CHUNK_SIZE, HEADER_LEN, KEY_LEN,
};

#[derive(serde::Deserialize)]
struct Vectors {
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    file_id: u64,
    key_hex: String,
    #[serde(default)]
    plain_b64: Option<String>,
    container_b64: String,
    #[serde(default)]
    expect_error: bool,
    #[serde(default)]
    error_contains: Option<String>,
}

fn load_vectors() -> Vectors {
    serde_json::from_str(include_str!("../../../tests/fixtures/fx1-vectors.json"))
        .expect("fx1-vectors.json parses")
}

fn key_of(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "key_hex must be even-length");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("key_hex is hex"))
        .collect()
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("base64")
}

#[test]
fn golden_vectors_decrypt_or_reject_exactly_as_committed() {
    let vectors = load_vectors();
    assert!(!vectors.cases.is_empty(), "no vectors loaded");
    let (mut decrypts, mut rejects) = (0usize, 0usize);
    for case in &vectors.cases {
        let key = key_of(&case.key_hex);
        let container = b64(&case.container_b64);
        let result = decrypt_bytes(case.file_id, &key, &container);
        if case.expect_error {
            rejects += 1;
            let err = match result {
                Ok(_) => panic!("{}: expected an error, got success", case.name),
                Err(e) => e,
            };
            let msg = err.to_string();
            let want = case.error_contains.as_deref().unwrap_or("");
            assert!(
                msg.contains(want),
                "{}: error {msg:?} does not contain {want:?}",
                case.name
            );
        } else {
            decrypts += 1;
            let plain = result.unwrap_or_else(|e| panic!("{}: decrypt failed: {e}", case.name));
            let expect = b64(case.plain_b64.as_deref().expect("plain present"));
            assert_eq!(plain, expect, "{}: decrypted bytes differ", case.name);
        }
    }
    assert!(decrypts >= 4 && rejects >= 5, "matrix incomplete");
}

#[test]
fn roundtrip_at_every_chunk_boundary() {
    let key = [7u8; fxcrypto::KEY_LEN];
    let lengths = [0usize, 1, 63, 64, 65, 66, 127, 128, 200, 16449];
    let chunk_sizes = [1u32, 7, 64, 65, 1024];
    for &len in &lengths {
        let plain: Vec<u8> = (0..len).map(|i| (i * 31 + 5) as u8).collect();
        let file_id = 0x0000_FFFF_FFFF_FFFFu64 + len as u64;
        for &cs in &chunk_sizes {
            let enc = encrypt_bytes_with_chunk_size(file_id, &key, &plain, cs)
                .expect("encrypt rejects nothing legal");
            let (header, header_cs) = read_header(&enc).expect("own header reads");
            assert_eq!(header_cs, cs, "header carries the chunk size");
            assert_eq!(header.len(), HEADER_LEN);
            let back = decrypt_bytes(file_id, &key, &enc).expect("own output decrypts");
            assert_eq!(back, plain, "len={len} cs={cs}");
        }
    }
}

#[test]
fn default_chunk_size_matches_the_js_encoder() {
    let plain = b"cross check at the reference chunk size".to_vec();
    let key = [9u8; fxcrypto::KEY_LEN];
    let enc = encrypt_bytes(42, &key, &plain).expect("encrypt");
    assert_eq!(read_header(&enc).expect("header").1, CHUNK_SIZE as u32);
    assert_eq!(decrypt_bytes(42, &key, &enc).expect("decrypt"), plain);
}

#[test]
fn encrypt_refuses_what_the_reader_would_refuse() {
    let plain = [1u8, 2, 3];
    assert!(matches!(
        encrypt_bytes(1, &[0u8; KEY_LEN - 1], &plain),
        Err(Error::KeyLength)
    ));
    assert!(matches!(
        encrypt_bytes_with_chunk_size(1, &[0u8; KEY_LEN], &plain, 0),
        Err(Error::Format(FormatError::ImplausibleChunkSize(0)))
    ));
    assert!(matches!(
        encrypt_bytes_with_chunk_size(1, &[0u8; KEY_LEN], &plain, 64 * 1024 * 1024 + 1),
        Err(Error::Format(FormatError::ImplausibleChunkSize(_)))
    ));
}

#[test]
fn read_header_rejects_every_malformed_header() {
    let mut buf = vec![0u8; HEADER_LEN];
    buf[0..4].copy_from_slice(&fxcrypto::MAGIC);
    buf[4] = fxcrypto::ENC_VERSION;
    buf[5] = fxcrypto::SUITE_AES256_GCM;
    buf[6..10].copy_from_slice(&64u32.to_be_bytes());
    assert!(read_header(&buf).is_ok());

    assert!(matches!(
        read_header(&buf[..10]),
        Err(FormatError::TooShort)
    ));
    let mut b = buf.clone();
    b[0] ^= 1;
    assert!(matches!(read_header(&b), Err(FormatError::BadMagic)));
    let mut b = buf.clone();
    b[4] = 2;
    assert!(matches!(
        read_header(&b),
        Err(FormatError::UnsupportedVersion(2))
    ));
    let mut b = buf.clone();
    b[5] = 9;
    assert!(matches!(
        read_header(&b),
        Err(FormatError::UnsupportedSuite(9))
    ));
    for bad in [0u32, u32::MAX] {
        let mut b = buf.clone();
        b[6..10].copy_from_slice(&bad.to_be_bytes());
        assert!(matches!(
            read_header(&b),
            Err(FormatError::ImplausibleChunkSize(_))
        ));
    }
}
