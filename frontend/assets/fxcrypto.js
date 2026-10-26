/*
 * fxcloud client-side encryption primitives (ENCRYPTION.md section 5).
 *
 * Everything here runs on the client - in a Web Worker for the heavy parts,
 * and under Node for the round-trip harness (DECISION 10). The module never
 * touches the network and never sees a session: it is a pure function of the
 * bytes it is handed.
 *
 * Load order: hashwasm-argon2.js first (it provides the global `hashwasm`),
 * then this file, which publishes `FXCrypto`.
 */
(function (root, factory) {
  "use strict";
  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.FXCrypto = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // ---- format constants ------------------------------------------------

  /** Magic of the encrypted blob container (ENCRYPTION.md 5.3). */
  var MAGIC = [0x46, 0x58, 0x45, 0x31]; // "FXE1"
  /** `files.enc_version` value this container corresponds to. */
  var ENC_VERSION = 1;
  /** Suite byte for the only content cipher shipped so far (AES-256-GCM). */
  var SUITE_AES256_GCM = 1;
  /** Suite bytes for key pairs (DECISION 1: X25519 first, P-256 fallback). */
  var SUITE_X25519 = 1;
  var SUITE_P256 = 2;

  /** Plaintext bytes per chunk. */
  var CHUNK_SIZE = 4 * 1024 * 1024;
  /**
   * Header: magic(4) || version(1) || suite(1) || chunk size(4) || nonce(8).
   * All integers big-endian, so a future reader can parse this without the
   * rest of the file.
   */
  var HEADER_LEN = 18;
  var NONCE_BASE_OFF = 10;
  var NONCE_LEN = 12; // AES-GCM: 8-byte per-file base || 4-byte chunk index
  var TAG_LEN = 16;
  var KEY_LEN = 32;
  var SALT_LEN = 16;

  /**
   * Argon2id floor: the client KDF is held to exactly what the *server* uses
   * for new login hashes, so DECISION 3's "the login hash must be at least as
   * expensive as the client KDF" holds as an equality rather than a promise.
   * Mirrors LOGIN_KDF_M_KIB / _T / _P in src/auth/mod.rs; setup rejects
   * anything weaker server-side (`enforce_kdf_floor`).
   */
  var KDF_FLOOR = { kdf: "argon2id", m: 65536, t: 3, p: 1 };

  /** Version byte folded into every key record's AAD (ENCRYPTION.md 5.4). */
  var KEY_RECORD_VERSION = 1;

  /**
   * Domain separation for the account-level wraps. The key record under a
   * folder gets `child_id || version` instead (5.4), which is what binds it
   * to its row; these four have no row to bind to, so they are bound to their
   * *purpose* instead - a blob written as "wrap the root key" cannot be
   * replayed as "wrap the private key".
   */
  var AAD = {
    ark: utf8("fx1:ark:v1"),
    arkRecovery: utf8("fx1:ark-recovery:v1"),
    privkey: utf8("fx1:privkey:v1"),
    rootkey: utf8("fx1:rootkey:v1"),
    recoveryKek: utf8("fx1:recovery-kek:v1"),
  };

  // ---- small byte helpers ---------------------------------------------

  function utf8(str) {
    return new TextEncoder().encode(str);
  }

  function concat() {
    var total = 0;
    var i;
    for (i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total);
    var off = 0;
    for (i = 0; i < arguments.length; i++) {
      out.set(arguments[i], off);
      off += arguments[i].length;
    }
    return out;
  }

  function u32be(n) {
    var b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n >>> 0, false);
    return b;
  }

  function u64be(n) {
    var b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
    return b;
  }

  function toHex(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
    return s;
  }

  function fromHex(str) {
    var clean = String(str).replace(/[^0-9a-fA-F]/g, "");
    if (clean.length % 2 !== 0) throw new Error("recovery key has an odd number of hex digits");
    var out = new Uint8Array(clean.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }

  function b64encode(bytes) {
    var s = "";
    var CH = 0x8000; // keeps String.fromCharCode.apply within argument limits
    for (var i = 0; i < bytes.length; i += CH) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    }
    return btoa(s);
  }

  function b64decode(str) {
    var bin = atob(String(str).trim());
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // ---- WebCrypto plumbing ---------------------------------------------

  function cryptoObj() {
    var c = typeof globalThis !== "undefined" ? globalThis.crypto : null;
    if (!c || !c.subtle) {
      throw new Error(
        "WebCrypto is unavailable - fxcloud encryption needs a secure context " +
          "(HTTPS or localhost)."
      );
    }
    return c;
  }

  function subtle() {
    return cryptoObj().subtle;
  }

  function randomBytes(n) {
    var b = new Uint8Array(n);
    cryptoObj().getRandomValues(b);
    return b;
  }

  function argon2id() {
    var hw = typeof globalThis !== "undefined" ? globalThis.hashwasm : null;
    if (!hw || typeof hw.argon2id !== "function") {
      throw new Error("hash-wasm argon2 is not loaded (global `hashwasm` missing)");
    }
    return hw.argon2id;
  }

  async function importAes(raw) {
    if (raw.length !== KEY_LEN) throw new Error("expected a 256-bit key");
    return subtle().importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }

  // ---- KDF and key derivation -----------------------------------------

  /**
   * The default KDF: Argon2id(password, salt) -> 32-byte KEK, run wherever
   * this module happens to be loaded.
   *
   * `params` comes from the stored `kdf_params`, so an account set up with
   * different (but floor-clearing) numbers still unlocks.
   */
  async function deriveKek(password, salt, params) {
    var p = params || {};
    var out = await argon2id()({
      password: String(password),
      salt: salt,
      parallelism: p.p || KDF_FLOOR.p,
      iterations: p.t || KDF_FLOOR.t,
      memorySize: p.m || KDF_FLOOR.m,
      hashLength: KEY_LEN,
      outputType: "binary",
    });
    return new Uint8Array(out);
  }

  /** HKDF-SHA-256 subkey derivation (ENCRYPTION.md 5.1). */
  async function hkdf(ikm, salt, info, length) {
    var key = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    var bits = await subtle().deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: salt, info: info },
      key,
      length * 8
    );
    return new Uint8Array(bits);
  }

  /**
   * The recovery key is 256 bits of CSPRNG output; the server stores only the
   * envelope it opens (5.7). HKDF with a label rather than the raw bytes so a
   * future second recovery mechanism cannot collide with this one.
   */
  async function deriveRecoveryKek(recoveryKey, salt) {
    return hkdf(recoveryKey, salt, AAD.recoveryKek, KEY_LEN);
  }

  // ---- symmetric wrap / unwrap -----------------------------------------

  /**
   * `AES-GCM(wrapping_key, value, aad)` as `nonce(12) || ciphertext || tag`.
   * Short, self-contained, and re-randomised on every wrap so re-wrapping the
   * same value twice never produces the same bytes.
   */
  async function wrap(wrappingKey, value, aad) {
    var key = await importAes(wrappingKey);
    var iv = randomBytes(NONCE_LEN);
    var ct = await subtle().encrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: TAG_LEN * 8 },
      key,
      value
    );
    return concat(iv, new Uint8Array(ct));
  }

  async function unwrap(wrappingKey, blob, aad) {
    if (blob.length < NONCE_LEN + TAG_LEN) {
      throw new Error("wrapped value is too short to be a key record");
    }
    var key = await importAes(wrappingKey);
    var iv = blob.subarray(0, NONCE_LEN);
    var ct = blob.subarray(NONCE_LEN);
    try {
      var pt = await subtle().decrypt(
        { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: TAG_LEN * 8 },
        key,
        ct
      );
      return new Uint8Array(pt);
    } catch (_) {
      // GCM does not distinguish "wrong key" from "tampered bytes", and it
      // should not: reporting which one failed would help an attacker probing
      // for the right key. One message covers both.
      throw new Error("could not unwrap this key - wrong passphrase, or the data was altered");
    }
  }

  /** AAD for a parent-wrapped child key: `child_id || version` (5.4). */
  function childKeyAad(childId) {
    return concat(u64be(childId), new Uint8Array([KEY_RECORD_VERSION]));
  }

  // ---- FXE1 container ---------------------------------------------------

  function buildHeader() {
    return concat(
      new Uint8Array(MAGIC),
      new Uint8Array([ENC_VERSION]),
      new Uint8Array([SUITE_AES256_GCM]),
      u32be(CHUNK_SIZE),
      randomBytes(8) // per-file nonce base
    );
  }

  /** The 12-byte chunk nonce: `nonce_base || chunk_index` (5.3). */
  function chunkNonce(header, index) {
    return concat(header.subarray(NONCE_BASE_OFF, HEADER_LEN), u32be(index));
  }

  function readHeader(blob) {
    if (blob.length < HEADER_LEN) throw new Error("file is too short to be an FXE1 container");
    for (var i = 0; i < MAGIC.length; i++) {
      if (blob[i] !== MAGIC[i]) throw new Error("not an FXE1 container (bad magic)");
    }
    if (blob[4] !== ENC_VERSION) {
      throw new Error("unsupported fxcloud container version " + blob[4]);
    }
    if (blob[5] !== SUITE_AES256_GCM) {
      throw new Error("unsupported cipher suite " + blob[5]);
    }
    var chunkSize = new DataView(blob.buffer, blob.byteOffset).getUint32(6, false);
    if (chunkSize < 1 || chunkSize > 64 * 1024 * 1024) {
      throw new Error("implausible chunk size in container header");
    }
    return { header: blob.subarray(0, HEADER_LEN), chunkSize: chunkSize };
  }

  /**
   * Encrypt `plain` into an FXE1 container bound to row `fileId`.
   *
   * Per-chunk AAD is `header || file_id || chunk_index` (5.3): the header
   * makes each file's nonces unique, the row id stops one row's bytes being
   * installed in another, and the index stops chunks being reordered inside a
   * single file. All three are known *before* the bytes are written, which is
   * why the caller has to create the row first (the two-phase upload).
   */
  async function encryptBytes(fileId, keyRaw, plain) {
    if (keyRaw.length !== KEY_LEN) throw new Error("expected a 256-bit file key");
    var header = buildHeader();
    var count = Math.ceil(plain.length / CHUNK_SIZE);
    var out = new Uint8Array(HEADER_LEN + plain.length + count * TAG_LEN);
    out.set(header, 0);
    if (count === 0) return out;

    var key = await importAes(keyRaw);
    for (var i = 0; i < count; i++) {
      var start = i * CHUNK_SIZE;
      var chunk = plain.subarray(start, Math.min(start + CHUNK_SIZE, plain.length));
      var aad = concat(header, u64be(fileId), u32be(i));
      var ct = await subtle().encrypt(
        { name: "AES-GCM", iv: chunkNonce(header, i), additionalData: aad, tagLength: TAG_LEN * 8 },
        key,
        chunk
      );
      out.set(new Uint8Array(ct), HEADER_LEN + i * (CHUNK_SIZE + TAG_LEN));
    }
    return out;
  }

  /** Reverse of [`encryptBytes`]; throws on any tampering. */
  async function decryptBytes(fileId, keyRaw, blob) {
    var h = readHeader(blob);
    var header = h.header;
    var chunkSize = h.chunkSize;
    var bodyLen = blob.length - HEADER_LEN;
    if (bodyLen === 0) return new Uint8Array(0);

    var stride = chunkSize + TAG_LEN;
    var count = Math.ceil(bodyLen / stride);
    var lastLen = bodyLen - (count - 1) * stride;
    if (lastLen <= TAG_LEN) {
      // Our encoder never emits an empty trailing chunk, so a container whose
      // final segment is only (or less than) the tag was not produced here.
      throw new Error("malformed FXE1 container (truncated final chunk)");
    }

    var out = new Uint8Array(bodyLen - count * TAG_LEN);
    var key = await importAes(keyRaw);
    var off = HEADER_LEN;
    for (var i = 0; i < count; i++) {
      var ctLen = i === count - 1 ? lastLen : stride;
      var aad = concat(header, u64be(fileId), u32be(i));
      var ct = blob.subarray(off, off + ctLen);
      try {
        var pt = await subtle().decrypt(
          {
            name: "AES-GCM",
            iv: chunkNonce(header, i),
            additionalData: aad,
            tagLength: TAG_LEN * 8,
          },
          key,
          ct
        );
        out.set(new Uint8Array(pt), i * chunkSize);
      } catch (_) {
        throw new Error(
          "decryption failed for chunk " + i + " - wrong key, a tampered file, or a " +
            "file moved to another row"
        );
      }
      off += ctLen;
    }
    return out;
  }

  // ---- key records ------------------------------------------------------

  /** Wrap a file/folder key under its parent key; returns base64 (5.4). */
  async function wrapChildKey(parentKey, childId, childKey) {
    return b64encode(await wrap(parentKey, childKey, childKeyAad(childId)));
  }

  async function unwrapChildKey(parentKey, childId, wrappedB64) {
    return unwrap(parentKey, b64decode(wrappedB64), childKeyAad(childId));
  }

  // ---- key pairs and fingerprints ---------------------------------------

  /**
   * DECISION 1: try X25519 first, fall back to P-256. Which one a given
   * browser gets is recorded in the leading byte of `public_key`, so the
   * share envelopes of phase 3 can dispatch on it instead of guessing.
   */
  async function generateKeyPair() {
    var kp;
    var suite;
    try {
      kp = await subtle().generateKey({ name: "X25519" }, true, ["deriveBits"]);
      suite = SUITE_X25519;
    } catch (_) {
      kp = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      suite = SUITE_P256;
    }
    var raw = new Uint8Array(await subtle().exportKey("raw", kp.publicKey));
    var pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", kp.privateKey));
    return {
      suite: suite,
      publicRaw: raw,
      // Published form: suite byte || raw point, so a reader never has to
      // probe for a curve.
      publicBlob: concat(new Uint8Array([suite]), raw),
      pkcs8: pkcs8,
      privateKey: kp.privateKey,
      publicKey: kp.publicKey,
    };
  }

  /** Re-import a stored `public_key` (suite byte || raw point). */
  async function importPublicKey(blob) {
    if (blob.length < 2) throw new Error("public key is too short");
    var suite = blob[0];
    var raw = blob.subarray(1);
    // A public key carries no usages in WebCrypto: the *private* key is what
    // `deriveBits` is restricted to, and it is passed alongside this one.
    if (suite === SUITE_X25519) {
      return subtle().importKey("raw", raw, { name: "X25519" }, true, []);
    }
    if (suite === SUITE_P256) {
      return subtle().importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
    }
    throw new Error("unknown key suite " + suite);
  }

  /** Re-import the wrapped private key (PKCS#8) once it has been unwrapped. */
  async function importPrivateKey(pkcs8, suite) {
    if (suite === SUITE_X25519) {
      return subtle().importKey("pkcs8", pkcs8, { name: "X25519" }, true, ["deriveBits"]);
    }
    return subtle().importKey("pkcs8", pkcs8, { name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
    ]);
  }

  /**
   * Display fingerprint (DECISION 6): SHA-256 over the *published* blob
   * (suite byte included), truncated to 128 bits and shown as 32 hex digits.
   * Truncated for humans to compare out of band, not for speed - 128 bits
   * leaves no practical way to hand a victim a different key with the same
   * fingerprint.
   */
  async function fingerprint(publicBlob) {
    var digest = new Uint8Array(await subtle().digest("SHA-256", publicBlob));
    return toHex(digest.subarray(0, 16));
  }

  /** `a1b2c3d4 e5f6...` - four groups of eight, for the share dialog. */
  function formatFingerprint(hex) {
    var s = String(hex).toLowerCase();
    if (s.length !== 32) return s;
    return s.slice(0, 8) + " " + s.slice(8, 16) + " " + s.slice(16, 24) + " " + s.slice(24, 32);
  }

  // ---- account setup / unlock -------------------------------------------

  /**
   * Every entry point below takes an optional `derive(password, salt, params)`
   * so the one genuinely slow step - Argon2id at 64 MiB x 3 - can be handed
   * to the crypto worker while everything else stays here. With no callback
   * the module simply derives on its own thread, which is what the round-trip
   * harness wants.
   */
  function kdfer(derive) {
    return derive || deriveKek;
  }

  /**
   * Everything setup produces: the payload POSTed to `/api/keys/setup`, the
   * plaintext material the tab keeps in memory, and the one-time recovery key
   * the user has to save (5.7, DECISION 3 consequence 3).
   */
  async function generateAccount(passphrase, derive) {
    var salt = randomBytes(SALT_LEN);
    var kek = await kdfer(derive)(passphrase, salt, KDF_FLOOR);
    var ark = randomBytes(KEY_LEN);
    var rootKey = randomBytes(KEY_LEN);
    var kp = await generateKeyPair();

    var wrappedArk = await wrap(kek, ark, AAD.ark);
    var wrappedRoot = await wrap(ark, rootKey, AAD.rootkey);
    var wrappedPriv = await wrap(ark, kp.pkcs8, AAD.privkey);

    var recovery = randomBytes(KEY_LEN);
    var recoveryKek = await deriveRecoveryKek(recovery, salt);
    var wrappedRecovery = await wrap(recoveryKek, ark, AAD.arkRecovery);

    return {
      payload: {
        public_key: b64encode(kp.publicBlob),
        private_key_wrapped: b64encode(wrappedPriv),
        wrapped_ark: b64encode(wrappedArk),
        wrapped_root_key: b64encode(wrappedRoot),
        wrapped_ark_recovery: b64encode(wrappedRecovery),
        kdf_salt: b64encode(salt),
        kdf_params: Object.assign({}, KDF_FLOOR),
        fingerprint: await fingerprint(kp.publicBlob),
      },
      // In-memory only from here on (DECISION 7): nothing below is written to
      // localStorage or sessionStorage anywhere in this codebase. The single
      // value that does cross a page load is the login password that
      // login.js parks for one navigation; fxenc.js deletes it on its first
      // read, and it opens this row rather than being the row's key material.
      session: {
        ark: ark,
        rootKey: rootKey,
        privateKey: kp.privateKey,
        publicKey: kp.publicKey,
        publicBlob: kp.publicBlob,
        suite: kp.suite,
      },
      recovery: recovery,
      recoveryHex: toHex(recovery),
      fingerprint: await fingerprint(kp.publicBlob),
    };
  }

  /** Open a stored account with the storage passphrase. */
  async function unlockAccount(keys, passphrase, derive) {
    var params = keys.kdf_params || KDF_FLOOR;
    var kek = await kdfer(derive)(passphrase, b64decode(keys.kdf_salt), params);
    var ark = await unwrap(kek, b64decode(keys.wrapped_ark), AAD.ark);
    var rootKey = await unwrap(ark, b64decode(keys.wrapped_root_key), AAD.rootkey);
    var privPkcs8 = await unwrap(ark, b64decode(keys.private_key_wrapped), AAD.privkey);
    var publicBlob = b64decode(keys.public_key);
    var suite = publicBlob[0];
    return {
      ark: ark,
      rootKey: rootKey,
      privateKey: await importPrivateKey(privPkcs8, suite),
      publicKey: await importPublicKey(publicBlob),
      publicBlob: publicBlob,
      suite: suite,
    };
  }

  /**
   * Open a stored account with the recovery key (5.7) - the only path left
   * when the passphrase is gone. Returns the ARK so the caller can rewrap it
   * under a *new* passphrase through `rewrap`.
   */
  async function openWithRecovery(keys, recoveryKey) {
    var salt = b64decode(keys.kdf_salt);
    var recoveryKek = await deriveRecoveryKek(recoveryKey, salt);
    var ark = await unwrap(recoveryKek, b64decode(keys.wrapped_ark_recovery), AAD.arkRecovery);
    // Everything below hangs off the ARK, so a recovered session is a full
    // session - not a read-only peek.
    var rootKey = await unwrap(ark, b64decode(keys.wrapped_root_key), AAD.rootkey);
    var privPkcs8 = await unwrap(ark, b64decode(keys.private_key_wrapped), AAD.privkey);
    var publicBlob = b64decode(keys.public_key);
    var suite = publicBlob[0];
    return {
      ark: ark,
      rootKey: rootKey,
      privateKey: await importPrivateKey(privPkcs8, suite),
      publicKey: await importPublicKey(publicBlob),
      publicBlob: publicBlob,
      suite: suite,
    };
  }

  /**
   * Re-wrap the ARK under a fresh passphrase KEK (5.7, DECISION 3
   * consequence 2). O(1): the ARK, the private key and the root key do not
   * move, so no file key and no share envelope has to be touched.
   */
  async function rewrapAccount(ark, newPassphrase, derive) {
    var salt = randomBytes(SALT_LEN);
    var kek = await kdfer(derive)(newPassphrase, salt, KDF_FLOOR);
    return {
      wrapped_ark: b64encode(await wrap(kek, ark, AAD.ark)),
      kdf_salt: b64encode(salt),
      kdf_params: Object.assign({}, KDF_FLOOR),
    };
  }

  // ---- recovery key file ------------------------------------------------

  /**
   * The downloadable record (5.7). Plain ASCII on purpose: it has to survive
   * being printed, mailed and pasted into a text editor.
   */
  function recoveryFile(username, hex) {
    var groups = [];
    for (var i = 0; i < hex.length; i += 16) groups.push(hex.slice(i, i + 16));
    return [
      "fxcloud recovery key",
      "=====================",
      "account:   " + username,
      "created:   " + new Date().toISOString(),
      "",
      "key:",
      groups.map(function (g) {
        return "  " + g;
      }).join("\n"),
      "",
      "This key opens the account root key of an fxcloud account and therefore",
      "decrypts every encrypted file in it. It is shown once. Anyone holding this",
      "file can read those files, so keep it offline and out of the cloud folder",
      "it protects.",
      "",
      "To recover: sign in to fxcloud, choose 'Use recovery key' on the unlock",
      "prompt, paste the 64 hex digits above (dashes, spaces and newlines are",
      "ignored), and pick a new storage passphrase.",
      "",
    ].join("\n");
  }

  // ---- MIME mapping (client side) ---------------------------------------

  /**
   * Server rows with `enc_version = 1` always arrive as
   * `application/octet-stream` - the server has no plaintext to type (section
   * 7). The real type only ever materialises here, from the name, and it is
   * deliberately conservative: anything that a browser would *render* rather
   * than store stays octet-stream, so a decrypted HTML or SVG cannot be
   * handed to a navigation that would run it in this origin.
   */
  var MIME_BY_EXT = {
    txt: "text/plain", csv: "text/csv", md: "text/markdown", json: "application/json",
    pdf: "application/pdf", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg",
    gif: "image/gif", webp: "image/webp", avif: "image/avif", bmp: "image/bmp",
    ico: "image/x-icon", svg: "image/svg+xml",
    mp3: "audio/mpeg", m4a: "audio/mp4", ogg: "audio/ogg", wav: "audio/wav",
    mp4: "video/mp4", webm: "video/webm", mov: "video/quicktime",
    zip: "application/zip", gz: "application/gzip", tar: "application/x-tar",
    doc: "application/msword", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xls: "application/vnd.ms-excel", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    css: "text/css", js: "text/javascript", xml: "text/xml",
  };
  var RENDERED_AS_DOCUMENT = { html: 1, htm: 1, xhtml: 1, svg: 1, xml: 1 };

  function mimeForDownload(name) {
    var ext = String(name).split(".").pop();
    ext = ext === String(name) ? "" : ext.toLowerCase();
    if (RENDERED_AS_DOCUMENT[ext]) return "application/octet-stream";
    return MIME_BY_EXT[ext] || "application/octet-stream";
  }

  // ---- public surface ---------------------------------------------------

  return {
    MAGIC: MAGIC,
    ENC_VERSION: ENC_VERSION,
    CHUNK_SIZE: CHUNK_SIZE,
    HEADER_LEN: HEADER_LEN,
    KDF_FLOOR: KDF_FLOOR,
    SUITE_X25519: SUITE_X25519,
    SUITE_P256: SUITE_P256,

    // byte helpers (the harness and the UI both need these)
    utf8: utf8,
    concat: concat,
    toHex: toHex,
    fromHex: fromHex,
    b64encode: b64encode,
    b64decode: b64decode,
    equalBytes: equalBytes,
    randomBytes: randomBytes,
    fingerprint: fingerprint,
    formatFingerprint: formatFingerprint,
    mimeForDownload: mimeForDownload,

    // primitives
    deriveKek: deriveKek,
    hkdf: hkdf,
    deriveRecoveryKek: deriveRecoveryKek,
    wrap: wrap,
    unwrap: unwrap,
    childKeyAad: childKeyAad,
    wrapChildKey: wrapChildKey,
    unwrapChildKey: unwrapChildKey,

    // container
    buildHeader: buildHeader,
    readHeader: readHeader,
    encryptBytes: encryptBytes,
    decryptBytes: decryptBytes,

    // key pairs
    generateKeyPair: generateKeyPair,
    importPublicKey: importPublicKey,
    importPrivateKey: importPrivateKey,

    // account lifecycle
    generateAccount: generateAccount,
    unlockAccount: unlockAccount,
    openWithRecovery: openWithRecovery,
    rewrapAccount: rewrapAccount,
    recoveryFile: recoveryFile,
  };
});
