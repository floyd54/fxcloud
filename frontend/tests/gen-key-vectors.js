#!/usr/bin/env node
/*
 * Golden vector writer/checker for the account-key layer
 * (ENCRYPTION.md 5.1 KDF, 5.4 key records, 5.7 recovery - Phase 5 Slice 2a).
 *
 *   node frontend/tests/gen-key-vectors.js          # (re)write the vectors
 *   node frontend/tests/gen-key-vectors.js --check  # verify them (suite/CI)
 *
 * Like gen-fx1-vectors.js, this pins the READ side: every committed blob
 * (wrapped keys, salts, the rewrapped ARK) was produced once by the real
 * fxcrypto.js, and BOTH implementations must open it byte for byte -
 * --check runs fxcrypto.js over every case, crates/fxcrypto/tests/keys.rs
 * runs the Rust twin over the same file. Nonce-bearing wraps are not
 * reproducible by design, so --check re-opens committed artifacts and
 * re-runs only the deterministic steps (Argon2id, HKDF, SHA-256); the JS
 * write side is roundtripped in crypto-roundtrip.js (generateAccount,
 * unlock, child keys, rewrapAccount).
 *
 * The AAD labels below are spec constants (5.4) and deliberately not part
 * of FX's public surface - this file restates them, the way gen-fx1
 * restates the container header.
 */
"use strict";

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const ASSETS = path.join(__dirname, "..", "assets");
// Same bootstrap as crypto-roundtrip.js: fxcrypto expects the Argon2
// global before it loads.
globalThis.hashwasm = require(path.join(ASSETS, "hashwasm-argon2.js"));
const FX = require(path.join(ASSETS, "fxcrypto.js"));

const subtle = globalThis.crypto && globalThis.crypto.subtle;
if (!subtle) {
  console.error("node >=20 required (WebCrypto subtle)");
  process.exit(2);
}

const OUT = path.join(__dirname, "..", "..", "tests", "fixtures", "fx-keys-vectors.json");

const AAD = {
  ark: Buffer.from("fx1:ark:v1"),
  arkRecovery: Buffer.from("fx1:ark-recovery:v1"),
  privkey: Buffer.from("fx1:privkey:v1"),
  rootkey: Buffer.from("fx1:rootkey:v1"),
};

const hex = (b) => Buffer.from(b).toString("hex");
const b64 = (b) => Buffer.from(b).toString("base64");
const unb64 = (s) => Buffer.from(s, "base64");
const unhex = (s) => Buffer.from(s, "hex");

// HKDF labels for one envelope's key agreement (5.5) - restated here as
// the spec side, the way gen-fx1 restates the container header.
const SHARE_SALT = Buffer.from("fx1:share-kek:v1");
const SHARE_INFO = Buffer.from("fx1:share:v1");

/** ECDH (WebCrypto) + HKDF + wrap under a *committed* ephemeral key. The
 *  real eciesSeal mints a fresh pair per call - exactly what a reproducible
 *  vector cannot hold - so this file does the spec side and both readers
 *  must open the result. */
async function sealWithEph(ephPkcs8, ephPublicBlob, recipientPublicBlob, plaintext, aad) {
  const suite = recipientPublicBlob[0];
  const ephPriv = await FX.importPrivateKey(ephPkcs8, suite);
  const recipient = await FX.importPublicKey(recipientPublicBlob);
  const shared = new Uint8Array(
    await subtle.deriveBits(
      { name: suite === FX.SUITE_X25519 ? "X25519" : "ECDH", public: recipient },
      ephPriv,
      256
    )
  );
  const wrapKey = await FX.hkdf(shared, SHARE_SALT, SHARE_INFO, 32);
  const wrapped = await FX.wrap(wrapKey, plaintext, aad);
  return Buffer.concat([Buffer.from(ephPublicBlob), Buffer.from(wrapped)]);
}

/** Byte-exact re-seal under the envelope's OWN ephemeral key and nonce:
 *  pins the layout (suite || ephPub || iv || ct), the HKDF labels and the
 *  ephemeral-key binding on the JS side - the Rust side pins the same file
 *  by opening it. */
async function resealMatches(c, aad) {
  const env = unb64(c.envelope_b64);
  const pubLen = c.recipient_suite === FX.SUITE_X25519 ? 32 : 65;
  if (!Buffer.from(env.subarray(0, 1 + pubLen)).equals(unb64(c.eph_public_blob_b64))) {
    return false;
  }
  const ephPriv = await FX.importPrivateKey(unb64(c.eph_pkcs8_b64), c.recipient_suite);
  const recipient = await FX.importPublicKey(unb64(c.recipient_public_b64));
  const shared = new Uint8Array(
    await subtle.deriveBits(
      { name: c.recipient_suite === FX.SUITE_X25519 ? "X25519" : "ECDH", public: recipient },
      ephPriv,
      256
    )
  );
  const wrapKey = await FX.hkdf(shared, SHARE_SALT, SHARE_INFO, 32);
  const key = await subtle.importKey("raw", wrapKey, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = env.subarray(1 + pubLen, 1 + pubLen + 12);
  const ct = Buffer.from(
    await subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      unb64(c.plaintext_b64)
    )
  );
  return Buffer.from(env.subarray(1 + pubLen + 12)).equals(ct);
}

async function expectFromSession(s) {
  // session.privateKey is a CryptoKey, but generateKeyPair/importPrivateKey
  // both build it extractable, so the pkcs8 bytes can be compared back.
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", s.privateKey));
  return {
    ark_b64: b64(s.ark),
    root_key_b64: b64(s.rootKey),
    private_key_pkcs8_b64: b64(pkcs8),
    public_blob_b64: b64(s.publicBlob),
    suite: s.suite,
  };
}

async function buildCases() {
  const cases = [];
  const PASS = "correct horse battery staple";

  // --- kdf: deriveKek determinism (floor, stored, zero-means-floor) ---
  const kdfRuns = [
    ["kdf: floor params", FX.KDF_FLOOR],
    ["kdf: stored params (128 MiB x2)", { kdf: "argon2id", m: 131072, t: 2, p: 1 }],
    ["kdf: zeroed params mean floor", { kdf: "argon2id", m: 0, t: 0, p: 0 }],
  ];
  for (const [name, params] of kdfRuns) {
    const salt = crypto.randomBytes(16);
    const kek = await FX.deriveKek(PASS, salt, params);
    cases.push({
      kind: "kdf",
      name,
      passphrase: PASS,
      salt_b64: b64(salt),
      params,
      kek_hex: hex(kek),
    });
  }

  // --- one generated account, three read paths off it ---
  const acc = await FX.generateAccount(PASS);
  const accExpect = await expectFromSession(acc.session);
  cases.push({
    kind: "unlock",
    name: "unlock: passphrase -> session (floor params)",
    passphrase: PASS,
    keys: acc.payload,
    expect: accExpect,
  });
  cases.push({
    kind: "session",
    name: "session: ARK handed over directly",
    ark_b64: b64(acc.session.ark),
    keys: acc.payload,
    expect: accExpect,
  });
  cases.push({
    kind: "recovery_open",
    name: "recovery key -> full session",
    recovery_key_b64: b64(acc.recovery),
    keys: acc.payload,
    expect: accExpect,
  });

  // --- a row set up with non-floor stored params (higher is allowed) ---
  const pass2 = "a different passphrase entirely";
  const salt2 = crypto.randomBytes(16);
  const params2 = { kdf: "argon2id", m: 131072, t: 2, p: 1 };
  const kek2 = await FX.deriveKek(pass2, salt2, params2);
  const ark2 = crypto.randomBytes(32);
  const root2 = crypto.randomBytes(32);
  const kp2 = await FX.generateKeyPair();
  const recovery2 = crypto.randomBytes(32);
  const recoveryKek2 = await FX.deriveRecoveryKek(recovery2, salt2);
  const keys2 = {
    public_key: b64(kp2.publicBlob),
    private_key_wrapped: b64(await FX.wrap(ark2, kp2.pkcs8, AAD.privkey)),
    wrapped_ark: b64(await FX.wrap(kek2, ark2, AAD.ark)),
    wrapped_root_key: b64(await FX.wrap(ark2, root2, AAD.rootkey)),
    wrapped_ark_recovery: b64(await FX.wrap(recoveryKek2, ark2, AAD.arkRecovery)),
    kdf_salt: b64(salt2),
    kdf_params: params2,
  };
  cases.push({
    kind: "unlock",
    name: "unlock: non-floor stored kdf params",
    passphrase: pass2,
    keys: keys2,
    expect: {
      ark_b64: b64(ark2),
      root_key_b64: b64(root2),
      private_key_pkcs8_b64: b64(kp2.pkcs8),
      public_blob_b64: b64(kp2.publicBlob),
      suite: kp2.suite,
    },
  });

  // --- passphrase change: committed rewrap output must reopen the ARK ---
  const NEW_PASS = "a brand new passphrase";
  const re = await FX.rewrapAccount(acc.session.ark, NEW_PASS);
  cases.push({
    kind: "rewrap",
    name: "rewrap: committed output reopens the same ARK",
    keys: acc.payload,
    ark_b64: b64(acc.session.ark),
    new_passphrase: NEW_PASS,
    rewrap: re,
  });

  // --- child key records (5.4) ---
  const parent = crypto.randomBytes(32);
  const childKey = crypto.randomBytes(32);
  const wrappedChild = await FX.wrapChildKey(parent, 42, childKey);
  cases.push({
    kind: "child",
    name: "child key under parent",
    parent_key_hex: hex(parent),
    child_id: 42,
    wrapped_child_b64: wrappedChild,
    child_key_hex: hex(childKey),
  });

  // --- fingerprints: both suite blobs, pure SHA-256 ---
  cases.push({
    kind: "fingerprint",
    name: "fingerprint: x25519 blob",
    public_blob_b64: acc.payload.public_key,
    fingerprint_hex: acc.fingerprint,
  });
  const kpP = await FX.generateKeyPair(FX.SUITE_P256);
  cases.push({
    kind: "fingerprint",
    name: "fingerprint: p256 blob",
    public_blob_b64: b64(kpP.publicBlob),
    fingerprint_hex: await FX.fingerprint(kpP.publicBlob),
  });

  // --- ECIES share envelopes (5.5): both suites, committed eph key ---
  const accPkcs8 = new Uint8Array(
    await subtle.exportKey("pkcs8", acc.session.privateKey)
  );
  const recAcc = {
    suite: acc.session.suite,
    publicBlob: acc.session.publicBlob,
    pkcs8: accPkcs8,
  };
  const envelopeCase = async (name, recipient, sourceId, grantee, plain) => {
    const eph = await FX.generateKeyPair(recipient.suite);
    const aad = FX.shareEnvelopeAad(sourceId, grantee);
    const env = await sealWithEph(
      eph.pkcs8,
      eph.publicBlob,
      recipient.publicBlob,
      plain,
      aad
    );
    cases.push({
      kind: "ecies_open",
      name,
      envelope_b64: b64(env),
      recipient_pkcs8_b64: b64(recipient.pkcs8),
      recipient_public_b64: b64(recipient.publicBlob),
      recipient_suite: recipient.suite,
      plaintext_b64: b64(plain),
      aad: { source_id: sourceId, grantee },
      eph_pkcs8_b64: b64(eph.pkcs8),
      eph_public_blob_b64: b64(eph.publicBlob),
    });
    return { env, aad: { source_id: sourceId, grantee }, recipient };
  };

  const base = await envelopeCase(
    "ecies: x25519 recipient opens",
    recAcc,
    77,
    "user-9",
    FX.utf8("folder key bytes")
  );
  await envelopeCase(
    "ecies: p256 recipient opens",
    await FX.generateKeyPair(FX.SUITE_P256),
    77,
    "user-9",
    FX.utf8("folder key bytes")
  );

  // --- rejections: the exact messages both readers must produce ---
  const UNIFIED = "could not unwrap this key - wrong passphrase, or the data was altered";
  const pushReject = (name, kind, fields, errorContains) =>
    cases.push({ name, kind, expect_error: true, error_contains: errorContains, ...fields });

  pushReject("reject: wrong passphrase", "unlock", {
    passphrase: PASS + "x",
    keys: acc.payload,
  }, UNIFIED);

  {
    const r = Buffer.from(acc.recovery);
    r[0] ^= 1;
    pushReject("reject: wrong recovery key", "recovery_open", {
      recovery_key_b64: b64(r),
      keys: acc.payload,
    }, UNIFIED);
  }

  // sessionFromArk reaches importPublicKey's guard (suite byte, no point).
  pushReject("reject: public key is only a suite byte", "session", {
    ark_b64: b64(acc.session.ark),
    keys: { ...acc.payload, public_key: b64(Buffer.from([1])) },
  }, "public key is too short");

  {
    const wkey = crypto.randomBytes(32);
    const good = await FX.wrap(wkey, Buffer.from("secret material"), AAD.ark);
    const short = Buffer.from(good.subarray(0, 27)); // one byte under nonce+tag
    pushReject("reject: wrapped blob too short", "unwrap", {
      key_hex: hex(wkey),
      wrapped_b64: b64(short),
      aad_b64: b64(AAD.ark),
    }, "wrapped value is too short to be a key record");
    const tampered = Buffer.from(good);
    tampered[tampered.length - 1] ^= 1;
    pushReject("reject: tampered wrap", "unwrap", {
      key_hex: hex(wkey),
      wrapped_b64: b64(tampered),
      aad_b64: b64(AAD.ark),
    }, UNIFIED);
  }

  pushReject("reject: child moved to another id", "child", {
    parent_key_hex: hex(parent),
    child_id: 43,
    wrapped_child_b64: wrappedChild,
  }, UNIFIED);
  {
    const wrong = Buffer.from(parent);
    wrong[0] ^= 1;
    pushReject("reject: child under the wrong parent", "child", {
      parent_key_hex: hex(wrong),
      child_id: 42,
      wrapped_child_b64: wrappedChild,
    }, UNIFIED);
  }

  // --- ECIES rejections: one unified answer for "not mine"/"tampered" ---
  const envReject = (name, env, recipient, aad, errorContains) =>
    pushReject(name, "ecies_open", {
      envelope_b64: b64(env),
      recipient_pkcs8_b64: b64(recipient.pkcs8),
      recipient_suite: recipient.suite,
      aad,
    }, errorContains);

  {
    const tampered = Buffer.from(base.env);
    tampered[tampered.length - 1] ^= 1;
    envReject("reject: tampered envelope", tampered, recAcc, base.aad, UNIFIED);
    envReject(
      "reject: envelope for another grantee",
      base.env,
      recAcc,
      { source_id: 77, grantee: "user-10" },
      UNIFIED
    );
    envReject("reject: truncated envelope", base.env.subarray(0, 40), recAcc, base.aad, UNIFIED);
    const wrongSuite = Buffer.from(base.env);
    wrongSuite[0] = 9;
    envReject("reject: envelope with unknown suite", wrongSuite, recAcc, base.aad, UNIFIED);
    const stranger = await FX.generateKeyPair(FX.SUITE_X25519);
    envReject("reject: opened by the wrong recipient", base.env, stranger, base.aad, UNIFIED);
  }

  pushReject("reject: seal to a one-byte key", "ecies_seal", {
    recipient_public_b64: b64(Buffer.from([1])),
    plaintext_b64: b64(Buffer.from("x")),
    aad: { source_id: 77, grantee: "user-9" },
  }, "recipient public key is too short");
  pushReject("reject: seal to an unknown suite", "ecies_seal", {
    recipient_public_b64: b64(Buffer.from([9, 1, 2])),
    plaintext_b64: b64(Buffer.from("x")),
    aad: { source_id: 77, grantee: "user-9" },
  }, "unknown key suite 9");

  return cases;
}

async function verify() {
  let raw;
  try {
    raw = fs.readFileSync(OUT, "utf8");
  } catch (_) {
    console.error("FAIL vectors file missing: " + OUT);
    process.exit(1);
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    console.error("FAIL vectors JSON: " + e.message);
    process.exit(1);
  }
  if (doc.format !== "fx-keys-golden-vectors" || !Array.isArray(doc.cases)) {
    console.error("FAIL vectors have the wrong shape");
    process.exit(1);
  }

  let bad = 0;
  let passed = 0;
  const fail = (c, msg) => {
    bad++;
    console.log("FAIL " + c.name + " - " + msg);
  };

  for (const c of doc.cases) {
    try {
      switch (c.kind) {
        case "kdf": {
          const got = await FX.deriveKek(c.passphrase, unb64(c.salt_b64), c.params);
          if (c.expect_error) {
            fail(c, "expected an error, got success");
          } else if (hex(got) !== c.kek_hex) {
            fail(c, "kek differs");
          } else {
            passed++;
          }
          break;
        }
        case "session": {
          const s = await FX.sessionFromArk(c.keys, unb64(c.ark_b64));
          if (c.expect_error) {
            fail(c, "expected an error, got success");
          } else {
            const diff = await sessionDiff(c, s);
        if (diff) fail(c, diff);
        else passed++;
          }
          break;
        }
        case "unlock": {
          const s = await FX.unlockAccount(c.keys, c.passphrase);
          if (c.expect_error) {
            fail(c, "expected an error, got success");
          } else {
            const diff = await sessionDiff(c, s);
        if (diff) fail(c, diff);
        else passed++;
          }
          break;
        }
        case "recovery_open": {
          const s = await FX.openWithRecovery(c.keys, unb64(c.recovery_key_b64));
          if (c.expect_error) {
            fail(c, "expected an error, got success");
          } else {
            const diff = await sessionDiff(c, s);
        if (diff) fail(c, diff);
        else passed++;
          }
          break;
        }
        case "rewrap": {
          // Committed rewrap output, reopened under the new passphrase.
          const rebuilt = {
            ...c.keys,
            wrapped_ark: c.rewrap.wrapped_ark,
            kdf_salt: c.rewrap.kdf_salt,
            kdf_params: c.rewrap.kdf_params,
          };
          const s = await FX.unlockAccount(rebuilt, c.new_passphrase);
          if (b64(s.ark) !== c.ark_b64) {
            fail(c, "rewrapped ark does not reopen");
          } else {
            passed++;
          }
          break;
        }
        case "child": {
          const got = await FX.unwrapChildKey(
            unhex(c.parent_key_hex),
            c.child_id,
            c.wrapped_child_b64
          );
          if (c.expect_error) {
            fail(c, "expected an error, got success");
          } else if (hex(got) !== c.child_key_hex) {
            fail(c, "child key differs");
          } else {
            passed++;
          }
          break;
        }
        case "fingerprint": {
          const got = await FX.fingerprint(unb64(c.public_blob_b64));
          if (got !== c.fingerprint_hex) {
            fail(c, "fingerprint differs");
          } else {
            passed++;
          }
          break;
        }
        case "unwrap": {
          await FX.unwrap(unhex(c.key_hex), unb64(c.wrapped_b64), unb64(c.aad_b64));
          if (c.expect_error) {
            fail(c, "expected an error, got success");
          } else {
            passed++;
          }
          break;
        }
        case "ecies_open": {
          const priv = await FX.importPrivateKey(
            unb64(c.recipient_pkcs8_b64),
            c.recipient_suite
          );
          const aad = FX.shareEnvelopeAad(c.aad.source_id, c.aad.grantee);
          if (c.eph_pkcs8_b64 && !(await resealMatches(c, aad))) {
            fail(c, "committed envelope does not re-seal byte for byte under its own eph key");
            break;
          }
          const got = await FX.eciesOpen(priv, c.envelope_b64, aad);
          if (c.expect_error) {
            fail(c, "expected an error, got success");
          } else if (!Buffer.from(got).equals(unb64(c.plaintext_b64))) {
            fail(c, "plaintext differs");
          } else {
            passed++;
          }
          break;
        }
        case "ecies_seal": {
          await FX.eciesSeal(
            unb64(c.recipient_public_b64),
            unb64(c.plaintext_b64),
            FX.shareEnvelopeAad(c.aad.source_id, c.aad.grantee)
          );
          if (c.expect_error) {
            fail(c, "expected an error, got success");
          } else {
            passed++;
          }
          break;
        }
        default:
          fail(c, "unknown case kind");
      }
    } catch (e) {
      if (!c.expect_error) {
        fail(c, e.message);
      } else if (!e.message.includes(c.error_contains)) {
        fail(c, 'error "' + e.message + '" lacks "' + c.error_contains + '"');
      } else {
        passed++;
      }
    }
  }

  if (bad) {
    console.log("key vectors: " + bad + " failed of " + doc.cases.length);
    process.exit(1);
  }
  console.log("key vectors verified under fxcrypto.js (" + passed + " cases)");
}

/** Compare a session against the committed expect block; null = match. */
async function sessionDiff(c, s) {
  const got = await expectFromSession(s);
  for (const field of Object.keys(c.expect)) {
    if (got[field] !== c.expect[field]) {
      return "session field " + field + " differs";
    }
  }
  return null;
}

async function write() {
  const cases = await buildCases();
  const doc = {
    format: "fx-keys-golden-vectors",
    spec:
      "ENCRYPTION.md 5.1/5.4/5.5/5.7: Argon2id KEK (m,t,p;0/absent = floor), " +
      "wrap = nonce12||ct||tag under a domain-separated AAD (ark, ark-recovery, " +
      "privkey, rootkey), session = ark -> root key + pkcs8 + published blob " +
      "(suite || point), recovery = HKDF(recovery, salt, 'fx1:recovery-kek:v1'), " +
      "child aad = u64be(id) || version1, fingerprint = sha256(blob)[0..16] " +
      "hex32, ECIES envelope = eph.publicBlob(suite||point) || nonce12 || ct with " +
      "wrapKey = HKDF-SHA256(ECDH, 'fx1:share-kek:v1', 'fx1:share:v1') and aad = " +
      "u64be(source_id) || utf8(grantee) || version1. Wraps carry fresh nonces, " +
      "so vectors pin the read side - committed ephemeral keys make the seal " +
      "reproducible for --check; the JS write side roundtrips in " +
      "crypto-roundtrip.js.",
    cases,
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(doc, null, 1) + "\n");
  console.log("wrote " + OUT + " (" + cases.length + " cases, " + fs.statSync(OUT).size + " bytes)");
}

if (process.argv.includes("--check")) {
  verify().catch((e) => {
    console.error("FAIL " + (e && e.message));
    process.exit(1);
  });
} else {
  write().catch((e) => {
    console.error("FAIL " + (e && e.message));
    process.exit(1);
  });
}
