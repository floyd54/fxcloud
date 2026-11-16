#!/usr/bin/env node
/*
 * Golden vector writer/checker for the FXE1 container format
 * (ENCRYPTION.md 5.3).
 *
 *   node frontend/tests/gen-fx1-vectors.js          # (re)write the vectors
 *   node frontend/tests/gen-fx1-vectors.js --check  # verify them (suite/CI)
 *
 * Why this script encrypts itself instead of using FX.encryptBytes: the
 * chunk size is a HEADER field, but the JS API hardcodes4 MiB - and a
 * committed vector of4 MiB per case would bloat the repo for no extra
 * coverage. So this file implements the spec side once (header, chunk
 * nonce, row-bound AAD) with a tiny chunk size, and BOTH implementations
 * must read the result: --check runs the real frontend/assets/fxcrypto.js
 * against every case, and crates/fxcrypto/tests/golden.rs runs the Rust
 * twin against the same file. A drift anywhere turns CI red.
 *
 * Vectors pin the READ side (encryption uses a fresh random nonce base,
 * outputs are deliberately not reproducible); crypto-roundtrip.js pins
 * the JS write side by roundtripping it on every run.
 */
"use strict";

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const ASSETS = path.join(__dirname, "..", "assets");
// Same bootstrap as crypto-roundtrip.js: fxcrypto expects the Argon2
// global before it loads (unused for containers, loaded for safety).
globalThis.hashwasm = require(path.join(ASSETS, "hashwasm-argon2.js"));
const FX = require(path.join(ASSETS, "fxcrypto.js"));

const subtle = globalThis.crypto && globalThis.crypto.subtle;
if (!subtle) {
  console.error("node >=20 required (WebCrypto subtle)");
  process.exit(2);
}

const OUT = path.join(__dirname, "..", "..", "tests", "fixtures", "fx1-vectors.json");
const MAGIC = Buffer.from([0x46, 0x58, 0x45, 0x31]); // FXE1
const ENC_VERSION = 1;
const SUITE = 1; // SUITE_AES256_GCM
const TAG_LEN = 16;
const HEADER_LEN = 18;
const CHUNK = 64; // small chunks, all boundaries affordable in git

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
}
function u64be(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}
function hex(buf) {
  return Buffer.from(buf).toString("hex");
}
function b64(buf) {
  return Buffer.from(buf).toString("base64");
}
/** Deterministic test content: not random, never compressible-looking. */
function pattern(len, seed) {
  const b = Buffer.alloc(len);
  for (let i = 0; i < len; i++) b[i] = (i * 31 + seed * 7) % 251;
  return b;
}

/** The spec side: header || per-chunk AES-GCM, exactly as5.3 defines. */
async function encryptSpec(fileId, key, plain, chunkSize) {
  const nonceBase = crypto.randomBytes(8);
  const header = Buffer.concat([
    MAGIC,
    Buffer.from([ENC_VERSION, SUITE]),
    u32be(chunkSize),
    nonceBase,
  ]);
  const count = Math.ceil(plain.length / chunkSize);
  if (count === 0) return header; // empty plaintext: header only
  const out = Buffer.alloc(HEADER_LEN + plain.length + count * TAG_LEN);
  header.copy(out, 0);
  const ck = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
  for (let i = 0; i < count; i++) {
    const start = i * chunkSize;
    const chunk = plain.subarray(start, Math.min(start + chunkSize, plain.length));
    const iv = Buffer.concat([nonceBase, u32be(i)]);
    const aad = Buffer.concat([header, u64be(fileId), u32be(i)]);
    const ct = Buffer.from(
      await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, ck, chunk)
    );
    ct.copy(out, HEADER_LEN + i * (chunkSize + TAG_LEN));
  }
  return out;
}

async function buildCases() {
  const cases = [];
  const pushDecrypt = async (name, fileId, plain) => {
    const key = crypto.randomBytes(32);
    const container = await encryptSpec(fileId, key, plain, CHUNK);
    cases.push({
      name,
      file_id: fileId,
      key_hex: hex(key),
      container_b64: b64(container),
      plain_b64: b64(plain),
    });
    return { key, container, fileId };
  };

  // Happy paths, one per structural branch of the reader.
  await pushDecrypt("empty body (header only)", 7, Buffer.alloc(0));
  const one = await pushDecrypt("single byte", 1, Buffer.from([0xab]));
  const exact = await pushDecrypt("exactly one chunk", 7, pattern(CHUNK, 1));
  const tail = await pushDecrypt("one chunk plus one-byte tail", 7, pattern(CHUNK + 1, 2));
  //16449 =257 chunks: exercises a multi-byte chunk index in both the
  // nonce and the AAD, and a file_id whose high bytes are all0xff.
  await pushDecrypt(
    "multi-chunk with high file id",
    0x0000ffffffffffff,
    pattern(CHUNK * 257 + 1, 3)
  );

  const reject = (name, container, fileId, key, errorContains) => {
    cases.push({
      name,
      file_id: fileId,
      key_hex: hex(key),
      container_b64: b64(container),
      expect_error: true,
      error_contains: errorContains,
    });
  };

  // Header rejections (readHeader before any key work).
  let b = Buffer.from(one.container);
  b[0] ^= 1;
  reject("reject: broken magic", b, one.fileId, one.key, "not an FXE1 container (bad magic)");
  b = Buffer.from(one.container);
  b[4] = 2;
  reject("reject: unknown version", b, one.fileId, one.key, "unsupported fxcloud container version");
  b = Buffer.from(one.container);
  b[5] = 9;
  reject("reject: unknown suite", b, one.fileId, one.key, "unsupported cipher suite");
  b = Buffer.from(one.container);
  b.writeUInt32BE(0, 6);
  reject("reject: zero chunk size", b, one.fileId, one.key, "implausible chunk size");

  // Shape rejection: append15 bytes so the tail becomes exactly one tag
  // (the encoder never emits that).
  b = Buffer.concat([Buffer.from(exact.container), Buffer.alloc(15)]);
  reject(
    "reject: truncated final chunk",
    b,
    exact.fileId,
    exact.key,
    "malformed FXE1 container (truncated final chunk)"
  );

  // Authentication rejections (the AAD does its job).
  b = Buffer.from(tail.container);
  b[HEADER_LEN + 10] ^= 0xff;
  reject("reject: tampered ciphertext", b, tail.fileId, tail.key, "decryption failed for chunk");
  reject(
    "reject: moved to another row",
    tail.container,
    tail.fileId + 1,
    tail.key,
    "decryption failed for chunk"
  );
  const wrongKey = Buffer.from(tail.key);
  wrongKey[0] ^= 1;
  reject("reject: wrong key", tail.container, tail.fileId, wrongKey, "decryption failed for chunk");

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
  if (doc.format !== "fx1-golden-vectors" || !Array.isArray(doc.cases)) {
    console.error("FAIL vectors have the wrong shape");
    process.exit(1);
  }
  let bad = 0;
  let decrypts = 0;
  let rejects = 0;
  for (const c of doc.cases) {
    const key = Buffer.from(c.key_hex, "hex");
    const container = Buffer.from(c.container_b64, "base64");
    try {
      const out = Buffer.from(await FX.decryptBytes(c.file_id, key, container));
      if (c.expect_error) {
        bad++;
        console.log("FAIL " + c.name + " - expected an error, got success");
      } else {
        const want = Buffer.from(c.plain_b64, "base64");
        if (!out.equals(want)) {
          bad++;
          console.log("FAIL " + c.name + " - decrypted bytes differ");
        } else {
          decrypts++;
        }
      }
    } catch (e) {
      if (!c.expect_error) {
        bad++;
        console.log("FAIL " + c.name + " - " + e.message);
      } else if (!e.message.includes(c.error_contains)) {
        bad++;
        console.log(
          'FAIL ' + c.name + ' - error "' + e.message + '" lacks "' + c.error_contains + '"'
        );
      } else {
        rejects++;
      }
    }
  }
  if (bad) {
    console.log("vectors: " + bad + " failed of " + doc.cases.length);
    process.exit(1);
  }
  console.log(
    "FXE1 vectors verified under fxcrypto.js (" + decrypts + " decrypt, " + rejects + " reject)"
  );
}

async function write() {
  const cases = await buildCases();
  const doc = {
    format: "fx1-golden-vectors",
    spec:
      "ENCRYPTION.md 5.3: header(magic,version,suite,chunk_size,nonce_base8), " +
      "chunk nonce = nonce_base || u32be(index), aad = header || u64be(file_id) || " +
      "u32be(index). Chunk size64 keeps every vector small; the reader takes the " +
      "value from the header. Encryption uses a fresh nonce base, so vectors pin " +
      "the read side - the JS write side is pinned by crypto-roundtrip.js.",
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
