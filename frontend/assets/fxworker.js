/*
 * fxcloud crypto worker: the parts of ENCRYPTION.md section 5 that would
 * otherwise freeze the UI.
 *
 * Three jobs, all deliberately narrow:
 *   - `deriveKek`    the Argon2id run (64 MiB x 3 passes) behind setup,
 *                    unlock and passphrase change - 170-400 ms of WASM;
 *   - `encryptBytes` whole-file FXE1 chunking on upload;
 *   - `decryptBytes` whole-file FXE1 chunking on download.
 *
 * The op names are the *same* as the fxcrypto.js functions, and the argument
 * lists are identical too, which is what lets the page fall back to running
 * them on its own thread when a Worker is unavailable (CSP, old engine): the
 * call site does not have to know which one it got.
 *
 * Everything short and snappy - key generation, wrapping a 32-byte key,
 * fingerprints - stays on the calling thread, so the account's key material
 * has exactly one home: memory, in this worker and in the page (DECISION 7).
 * Nothing is written to disk, to localStorage or to IndexedDB.
 *
 * The worker owns no state between messages: it is given bytes, it returns
 * bytes, and it forgets them.
 */
"use strict";

importScripts("/assets/hashwasm-argon2.js", "/assets/fxcrypto.js");

var FX = globalThis.FXCrypto;

self.onmessage = async function (event) {
  var msg = event.data || {};
  try {
    if (typeof FX[msg.op] !== "function") {
      throw new Error("unknown crypto operation: " + msg.op);
    }
    // Same shape as the direct call, wrapped so the result always travels as
    // `{ bytes }` and can be moved rather than copied.
    var value = await FX[msg.op].apply(null, msg.args || []);
    var result = { bytes: value };
    // Zero-copy on the way out: a 40 MB file would otherwise be duplicated
    // once per hop. The input buffer arrived transferred as well, so this
    // only hands back what was borrowed.
    var transfer = [];
    if (value instanceof Uint8Array && value.buffer instanceof ArrayBuffer) {
      transfer.push(value.buffer);
    }
    self.postMessage({ id: msg.id, ok: true, result: result }, transfer);
  } catch (e) {
    self.postMessage({
      id: msg.id,
      ok: false,
      error: String((e && e.message) || e),
    });
  }
};
