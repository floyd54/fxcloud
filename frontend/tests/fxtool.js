#!/usr/bin/env node
/*
 * fxtool.js - a thin CLI over fxcrypto.js, so the bash suite can drive a
 * *real* encrypted round trip through the HTTP API instead of a synthetic
 * FXE1 body. The server never verifies the cryptography (it cannot), so the
 * only way to prove the client contract end to end is to run the same
 * frontend module against a live instance.
 *
 *   fxtool.js setup   <passphrase> <payload.json> <state.json>
 *                     -> writes the POST /api/keys/setup body, prints the
 *                        fingerprint, and parks the unwrapped keys in
 *                        <state.json> for the later steps.
 *   fxtool.js unlock  <passphrase> <keys.json> <state.json>
 *                     -> opens material read back from GET /api/keys/me, so
 *                        a round trip through the database is proven too.
 *   fxtool.js encrypt <state.json> <fileId> <plain> <cipher>
 *                     -> writes the container and prints the wrapped key.
 *   fxtool.js decrypt <state.json> <fileId> <cipher> <wrappedKey> <out>
 *   fxtool.js rewrap  <state.json> <newPassphrase> <out.json>
 *                     -> prints a PUT /api/keys/me body (the ARK moves
 *                        wrapper, not value).
 *
 * The state file holds only base64 key bytes - the same bytes a browser tab
 * would keep in memory. It is a test fixture and is deleted with the run.
 */
"use strict";

const path = require("path");
const fs = require("fs");

const ASSETS = path.join(__dirname, "..", "assets");

// hash-wasm publishes a global only when loaded as a plain <script>; under
// Node it fills module.exports, so stand it up by hand (same as the harness).
globalThis.hashwasm = require(path.join(ASSETS, "hashwasm-argon2.js"));
const FX = require(path.join(ASSETS, "fxcrypto.js"));

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function writeState(p, session, extra) {
  const out = Object.assign(
    {
      rootKey: FX.b64encode(session.rootKey),
      ark: FX.b64encode(session.ark),
      public_key: FX.b64encode(session.publicBlob),
    },
    extra || {}
  );
  fs.writeFileSync(p, JSON.stringify(out));
  return out;
}

async function main() {
  const [, , cmd, ...rest] = process.argv;

  if (cmd === "setup") {
    const [pass, payloadPath, statePath] = rest;
    const account = await FX.generateAccount(pass);
    fs.writeFileSync(payloadPath, JSON.stringify(account.payload));
    writeState(statePath, account.session, {
      fingerprint: account.payload.fingerprint,
      recoveryHex: account.recoveryHex,
    });
    process.stdout.write(account.payload.fingerprint + "\n");
    return;
  }

  if (cmd === "unlock") {
    const [pass, keysPath, statePath] = rest;
    const keys = readJson(keysPath);
    const session = await FX.unlockAccount(keys, pass);
    writeState(statePath, session, { fingerprint: keys.fingerprint });
    process.stdout.write("unlocked\n");
    return;
  }

  if (cmd === "encrypt") {
    const [statePath, fileId, plainPath, cipherPath] = rest;
    const state = readJson(statePath);
    const rootKey = FX.b64decode(state.rootKey);
    const id = Number(fileId);
    const plain = new Uint8Array(fs.readFileSync(plainPath));
    const fileKey = FX.randomBytes(32);
    const wrapped = await FX.wrapChildKey(rootKey, id, fileKey);
    const cipher = await FX.encryptBytes(id, fileKey, plain);
    fs.writeFileSync(cipherPath, Buffer.from(cipher));
    process.stdout.write(wrapped + "\n");
    return;
  }

  if (cmd === "decrypt") {
    const [statePath, fileId, cipherPath, wrapped, outPath] = rest;
    const state = readJson(statePath);
    const rootKey = FX.b64decode(state.rootKey);
    const id = Number(fileId);
    const fileKey = await FX.unwrapChildKey(rootKey, id, wrapped);
    const cipher = new Uint8Array(fs.readFileSync(cipherPath));
    const plain = await FX.decryptBytes(id, fileKey, cipher);
    fs.writeFileSync(outPath, Buffer.from(plain));
    process.stdout.write(String(plain.length) + "\n");
    return;
  }

  if (cmd === "rewrap") {
    const [statePath, newPass, outPath] = rest;
    const state = readJson(statePath);
    const ark = FX.b64decode(state.ark);
    const body = await FX.rewrapAccount(ark, newPass);
    fs.writeFileSync(outPath, JSON.stringify(body));
    // The ARK did not move, so everything wrapped under it - the root key
    // above all - still opens. Only the outer shell changed.
    process.stdout.write("rewrapped\n");
    return;
  }

  process.stderr.write(
    "usage: fxtool.js setup|unlock|encrypt|decrypt|rewrap <args...>\n"
  );
  process.exit(2);
}

main().catch((e) => {
  process.stderr.write(String((e && e.message) || e) + "\n");
  process.exit(1);
});
