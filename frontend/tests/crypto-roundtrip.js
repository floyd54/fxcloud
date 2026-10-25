/*
 * DECISION 10 - WebCrypto round-trip harness for the fxcloud file format.
 *
 * Runs the *same* fxcrypto.js the browser and the Web Worker load, against
 * Node's own WebCrypto, so a change to the container, the key records or the
 * account lifecycle has to prove itself before it reaches a user's files.
 *
 *   /root/node-v22.14.0-linux-x64/bin/node frontend/tests/crypto-roundtrip.js
 *
 * The server-side half of DECISION 10 (API visibility) lives in
 * /root/fxtest.sh, which calls this script.
 */
"use strict";

const path = require("path");

const ASSETS = path.join(__dirname, "..", "assets");

// hash-wasm only publishes the global when it is loaded as a plain script;
// under Node it fills `module.exports` instead, so stand it up by hand.
globalThis.hashwasm = require(path.join(ASSETS, "hashwasm-argon2.js"));
const FX = require(path.join(ASSETS, "fxcrypto.js"));

let passed = 0;
const failures = [];

function ok(label) {
  passed += 1;
  console.log("OK   " + label);
}

function bad(label, err) {
  failures.push(label);
  console.log("FAIL " + label + " - " + (err && err.message ? err.message : err));
}

async function check(label, fn) {
  try {
    await fn();
    ok(label);
  } catch (e) {
    bad(label, e);
  }
}

/** Assert that `fn` rejects; anything else is a failure. */
async function rejects(label, fn) {
  try {
    await fn();
    bad(label, new Error("expected a rejection, but it succeeded"));
  } catch (e) {
    if (String(e.message).indexOf("expected a rejection") === 0) bad(label, e);
    else ok(label);
  }
}

function assert(cond, message) {
  if (!cond) throw new Error(message);
}

async function main() {
  // ---------------------------------------------------------------- setup

  let account;
  await check("setup produces every field /api/keys/setup requires", async () => {
    account = await FX.generateAccount("correct horse battery staple");
    const p = account.payload;
    for (const field of [
      "public_key",
      "private_key_wrapped",
      "wrapped_ark",
      "wrapped_root_key",
      "wrapped_ark_recovery",
      "kdf_salt",
      "kdf_params",
      "fingerprint",
    ]) {
      assert(p[field] != null, "missing " + field);
    }
    assert(p.kdf_params.kdf === "argon2id", "kdf_params.kdf must be argon2id");
    assert(
      p.kdf_params.m >= 65536 && p.kdf_params.t >= 3 && p.kdf_params.p >= 1,
      "kdf_params below the server-side floor"
    );
    assert(p.fingerprint.length === 32, "fingerprint must be 32 hex digits");
    // Everything but kdf_params and fingerprint is opaque base64 - the server
    // has to be able to store it without interpreting a byte.
    for (const field of ["public_key", "private_key_wrapped", "wrapped_ark",
                         "wrapped_root_key", "wrapped_ark_recovery", "kdf_salt"]) {
      FX.b64decode(p[field]);
    }
    assert(FX.toHex(account.recovery).length === 64, "recovery key must be 256 bits");
  });

  await check("a recovery key is parsed leniently but never ambiguously", async () => {
    // Dashes, spaces and newlines are what a human re-types from a printout.
    assert(FX.fromHex("de ad-be-ef").length === 4, "fromHex must strip separators");
    assert(FX.toHex(FX.fromHex("deadbeef")) === "deadbeef", "fromHex/toHex must round-trip");
    let oddThrew = false;
    try {
      FX.fromHex("abc");
    } catch (_) {
      oddThrew = true;
    }
    assert(oddThrew, "an odd number of hex digits must be rejected");
  });

  await check("unlock with the right passphrase recovers the same material", async () => {
    const unlocked = await FX.unlockAccount(account.payload, "correct horse battery staple");
    assert(FX.equalBytes(unlocked.ark, account.session.ark), "ARK differs");
    assert(FX.equalBytes(unlocked.rootKey, account.session.rootKey), "root key differs");
    assert(unlocked.privateKey != null && unlocked.publicKey != null, "key pair missing");
    assert(FX.equalBytes(unlocked.publicBlob, FX.b64decode(account.payload.public_key)),
      "public blob differs");
  });

  await rejects("unlock with the wrong passphrase is refused", async () =>
    FX.unlockAccount(account.payload, "correct horse battery stapl")
  );

  // ------------------------------------------------------------ container

  const fileKey = FX.randomBytes(32);
  const sizes = [0, 1, FX.CHUNK_SIZE - 1, FX.CHUNK_SIZE, FX.CHUNK_SIZE + 1, 3 * FX.CHUNK_SIZE + 7];

  for (const size of sizes) {
    await check("encrypt/decrypt round trip at " + size + " bytes", async () => {
      const plain = new Uint8Array(size);
      for (let i = 0; i < size; i++) plain[i] = (i * 31 + 7) & 0xff;
      const blob = await FX.encryptBytes(4242, fileKey, plain);
      const h = FX.readHeader(blob);
      assert(h.chunkSize === FX.CHUNK_SIZE, "header chunk size not round-tripped");
      const back = await FX.decryptBytes(4242, fileKey, blob);
      assert(FX.equalBytes(back, plain), "plaintext differs after round trip");
      if (size > 0) {
        // 16-byte tag per chunk: the overhead the server sees in `files.size`.
        const chunks = Math.ceil(size / FX.CHUNK_SIZE);
        assert(blob.length === FX.HEADER_LEN + size + chunks * 16, "unexpected container size");
      } else {
        assert(blob.length === FX.HEADER_LEN, "empty file must be header only");
      }
    });
  }

  await check("the container is identified by its magic", async () => {
    const blob = await FX.encryptBytes(1, fileKey, FX.utf8("hello"));
    assert(String.fromCharCode(...blob.subarray(0, 4)) === "FXE1", "magic is not FXE1");
    assert(blob[4] === 1, "format version byte must be 1");
    assert(blob[5] === 1, "suite byte must be AES-256-GCM");
  });

  await rejects("a plaintext body is not an FXE1 container", async () =>
    FX.decryptBytes(1, fileKey, FX.utf8("just some ordinary bytes"))
  );

  await rejects("the wrong file key is refused", async () => {
    const blob = await FX.encryptBytes(7, fileKey, FX.utf8("secret"));
    return FX.decryptBytes(7, FX.randomBytes(32), blob);
  });

  await rejects("a tampered chunk is refused", async () => {
    const blob = await FX.encryptBytes(7, fileKey, FX.utf8("secret contents here"));
    blob[FX.HEADER_LEN + 3] ^= 0x40;
    return FX.decryptBytes(7, fileKey, blob);
  });

  await rejects("a tampered chunk tag is refused", async () => {
    const blob = await FX.encryptBytes(7, fileKey, FX.utf8("secret contents here"));
    blob[blob.length - 1] ^= 0x01;
    return FX.decryptBytes(7, fileKey, blob);
  });

  await rejects("a tampered header nonce is refused (it is authenticated)", async () => {
    const blob = await FX.encryptBytes(7, fileKey, FX.utf8("secret contents here"));
    blob[FX.HEADER_LEN - 1] ^= 0x01;
    return FX.decryptBytes(7, fileKey, blob);
  });

  await rejects("the row id is bound: another id cannot decrypt this file", async () => {
    const blob = await FX.encryptBytes(7, fileKey, FX.utf8("secret contents here"));
    return FX.decryptBytes(8, fileKey, blob);
  });

  await rejects("chunks cannot be reordered inside a file", async () => {
    const size = FX.CHUNK_SIZE + 64;
    const plain = new Uint8Array(size).fill(9);
    const blob = await FX.encryptBytes(7, fileKey, plain);
    const stride = FX.CHUNK_SIZE + 16;
    const a = blob.slice(FX.HEADER_LEN, FX.HEADER_LEN + stride);
    const b = blob.slice(FX.HEADER_LEN + stride, FX.HEADER_LEN + 2 * stride);
    blob.set(b, FX.HEADER_LEN);
    blob.set(a, FX.HEADER_LEN + stride);
    return FX.decryptBytes(7, fileKey, blob);
  });

  await rejects("a header with a zero chunk size is refused", async () => {
    const blob = await FX.encryptBytes(7, fileKey, FX.utf8("x"));
    new DataView(blob.buffer).setUint32(6, 0, false);
    return FX.decryptBytes(7, fileKey, blob);
  });

  // --------------------------------------------------------- key records

  const parentKey = FX.randomBytes(32);

  await check("a parent-wrapped child key round-trips through base64", async () => {
    const wrapped = await FX.wrapChildKey(parentKey, 9911, fileKey);
    const back = await FX.unwrapChildKey(parentKey, 9911, wrapped);
    assert(FX.equalBytes(back, fileKey), "unwrapped key differs");
  });

  await rejects("a key record does not open under another row's id", async () => {
    const wrapped = await FX.wrapChildKey(parentKey, 9911, fileKey);
    return FX.unwrapChildKey(parentKey, 9912, wrapped);
  });

  await rejects("a key record does not open under the wrong parent key", async () => {
    const wrapped = await FX.wrapChildKey(parentKey, 9911, fileKey);
    return FX.unwrapChildKey(FX.randomBytes(32), 9911, wrapped);
  });

  // ------------------------------------------------------------ recovery

  await check("the recovery key opens the account root key", async () => {
    const recovered = await FX.openWithRecovery(account.payload, account.recovery);
    assert(FX.equalBytes(recovered.ark, account.session.ark), "recovered ARK differs");
    assert(FX.equalBytes(recovered.rootKey, account.session.rootKey), "recovered root key differs");
  });

  await rejects("a wrong recovery key is refused", async () =>
    FX.openWithRecovery(account.payload, FX.randomBytes(32))
  );

  await check("the recovery file is ASCII and carries the 64 hex digits", async () => {
    const text = FX.recoveryFile("alice", account.recoveryHex);
    // eslint-disable-next-line no-control-regex
    assert(!/[^\x00-\x7F]/.test(text), "recovery file must be pure ASCII");
    const compact = text.replace(/[^0-9a-f]/g, "");
    assert(
      compact.indexOf(account.recoveryHex) >= 0,
      "recovery file does not contain the key"
    );
    assert(FX.fromHex(account.recoveryHex).length === 32, "recovery key must decode to 32 bytes");
  });

  // -------------------------------------------------------- passphrase change

  await check("rewrapping under a new passphrase leaves the keys untouched", async () => {
    const rewrap = await FX.rewrapAccount(account.session.ark, "a brand new passphrase");
    const changed = Object.assign({}, account.payload, rewrap);
    const unlocked = await FX.unlockAccount(changed, "a brand new passphrase");
    assert(FX.equalBytes(unlocked.ark, account.session.ark), "ARK moved during rewrap");
    assert(FX.equalBytes(unlocked.rootKey, account.session.rootKey), "root key moved during rewrap");
  });

  await rejects("the old passphrase stops working after a rewrap", async () => {
    const rewrap = await FX.rewrapAccount(account.session.ark, "a brand new passphrase");
    const changed = Object.assign({}, account.payload, rewrap);
    return FX.unlockAccount(changed, "correct horse battery staple");
  });

  await rejects("a rewrapped ARK still opens under the recovery key", async () => {
    const rewrap = await FX.rewrapAccount(account.session.ark, "a brand new passphrase");
    const changed = Object.assign({}, account.payload, rewrap);
    return FX.openWithRecovery(changed, account.recovery);
  });

  // ------------------------------------------------------- keys & identity

  await check("fingerprints are stable, readable and key-specific", async () => {
    const f1 = await FX.fingerprint(FX.b64decode(account.payload.public_key));
    assert(f1 === account.payload.fingerprint, "fingerprint does not match the published key");
    assert(/^[0-9a-f]{32}$/.test(f1), "fingerprint must be 32 lower-case hex digits");
    assert(
      FX.formatFingerprint(f1).replace(/ /g, "") === f1,
      "formatFingerprint must only add grouping"
    );
    const other = await FX.generateKeyPair();
    const f2 = await FX.fingerprint(other.publicBlob);
    assert(f1 !== f2, "two different keys produced the same fingerprint");
  });

  await check("key pairs round-trip through the published blob", async () => {
    const kp = await FX.generateKeyPair();
    assert(kp.publicBlob[0] === kp.suite, "suite byte must lead the public blob");
    assert(kp.publicBlob.length === kp.publicRaw.length + 1, "suite byte not prepended");
    const imported = await FX.importPublicKey(kp.publicBlob);
    assert(imported != null, "public key could not be re-imported");
    const priv = await FX.importPrivateKey(kp.pkcs8, kp.suite);
    assert(priv != null, "private key could not be re-imported");
  });

  // ------------------------------------------------------------- MIME

  await check("decrypted HTML and SVG never get a renderable content type", async () => {
    assert(FX.mimeForDownload("page.html") === "application/octet-stream", "html must not render");
    assert(FX.mimeForDownload("logo.svg") === "application/octet-stream", "svg must not render");
    assert(FX.mimeForDownload("photo.png") === "image/png", "png should keep its type");
    assert(FX.mimeForDownload("noextension") === "application/octet-stream", "unknown -> octet-stream");
  });

  console.log("");
  if (failures.length) {
    console.log(`${passed} passed, ${failures.length} FAILED`);
    process.exit(1);
  }
  console.log(`ALL ${passed} CRYPTO CHECKS PASSED`);
}

main().catch((e) => {
  console.log("FAIL harness crashed - " + (e && e.stack ? e.stack : e));
  process.exit(1);
});
