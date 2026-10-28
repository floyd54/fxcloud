#!/usr/bin/env node
/*
 * fxenc-harness.js - the encryption code the user actually runs (DECISION 10).
 *
 * crypto-roundtrip.js proves fxcrypto.js and fxtool.js drives it through the
 * API, but neither touches fxenc.js: the file that picks the arguments for
 * every crypto call and writes every encrypted request. That blind spot has
 * shipped twice - `jsonCall` once lost a parameter, and `encryptBytes(plain,
 * id, fileKey)` scrambled one, so every upload died with "expected a 256-bit
 * file key" while the whole suite stayed green.
 *
 * So this harness loads the *real* fxenc.js behind a fake DOM and a fetch
 * that prefixes the base URL and carries the session cookie, then drives it
 * against a live instance exactly as a browser tab would:
 *
 *   unlock through the pane  -> encryptUpload -> download -> bytes identical
 *   writeText -> readText    -> text identical, the file key kept per row
 *   reopening                -> through a fresh listing, not a saved object
 *   overlapping saves        -> never a row whose key and bytes disagree
 *   a brand new file         -> encrypted from its first second
 *   a folder chain (5.2)     -> the folder gains a record, files chain to it
 *   a share envelope (5.5)   -> sealed to a peer, opened down to the bytes
 *
 * It runs twice, because those are two different paths. By default `Worker`
 * is undefined here, so every whole-file operation takes the documented
 * main-thread fallback. With FXENC_WORKER=1 a Worker is installed whose
 * message handler *is* the real fxworker.js source, cloned on both hops the
 * way a browser serialises them - that is the path a browser tab always
 * takes, and nothing else in the suite could see it. Fixture rows carry the
 * mode in their name so both runs can share one instance.
 *
 * Usage: fxenc-harness.js <base-url> <cookie-header> <passphrase> [user]
 *
 * Prints one "OK   <label>" or "FAIL <label> - <why>" line per check and
 * exits non-zero if anything failed; tests/suite.sh turns every line into a
 * check of its own.
 */
"use strict";

const path = require("path");

const ASSETS = path.join(__dirname, "..", "assets");

const BASE = String(process.argv[2] || "").replace(/\/+$/, "");
const COOKIE = String(process.argv[3] || "");
const PASSPHRASE = String(process.argv[4] || "");
const USERNAME = String(process.argv[5] || "alice");

if (!BASE || !PASSPHRASE) {
  console.log("FAIL usage - fxenc-harness.js <base-url> <cookie> <passphrase> [user]");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Fake DOM
//
// fxenc.js touches a small, fixed set of element features; anything it asks
// for that this does not model would throw, which is exactly what we want -
// a silently missing control is how wiring bugs hide.
// ---------------------------------------------------------------------------

const elements = new Map();

function makeElement(id) {
  const el = {
    id: id,
    value: "",
    textContent: "",
    innerHTML: "",
    title: "",
    className: "",
    href: "",
    download: "",
    disabled: false,
    hidden: false,
    checked: false,
    handlers: {},
    style: {
      display: "",
      setProperty: function (k, v) {
        this[k] = v;
      },
      removeProperty: function (k) {
        delete this[k];
      },
      getPropertyValue: function (k) {
        return this[k] || "";
      },
    },
    classList: {
      add: function () {},
      remove: function () {},
      toggle: function () {},
      contains: function () {
        return false;
      },
    },
  };

  el.addEventListener = function (ev, fn) {
    (el.handlers[ev] = el.handlers[ev] || []).push(fn);
  };
  el.removeEventListener = function () {};
  el.setAttribute = function () {};
  el.getAttribute = function () {
    return null;
  };
  el.removeAttribute = function () {};
  el.querySelector = function () {
    return makeElement(id + ">child");
  };
  el.closest = function () {
    return makeElement(id + "~ancestor");
  };
  el.focus = function () {};
  el.blur = function () {};
  el.select = function () {};
  el.remove = function () {};
  el.appendChild = function () {};
  el.click = function () {};
  /** Run every click handler, the way a real button press would. */
  el.press = async function () {
    const fns = el.handlers.click || [];
    for (const fn of fns) await fn({ preventDefault: function () {}, key: "Enter" });
    return fns.length;
  };
  return el;
}

function element(id) {
  if (!elements.has(id)) elements.set(id, makeElement(id));
  return elements.get(id);
}

globalThis.document = {
  getElementById: element,
  createElement: function (tag) {
    // Deliberately not memoized: an <a> built per download must be a fresh
    // node every time, like document.createElement gives.
    return makeElement("<" + tag + ">");
  },
  addEventListener: function () {},
  removeEventListener: function () {},
  body: makeElement("body"),
  documentElement: makeElement("html"),
};

// `window.location.href = "/login"` runs on a 401; Node has no location.
globalThis.window = globalThis;
if (!globalThis.location) globalThis.location = { href: "" };
globalThis.alert = function () {};
globalThis.confirm = function () {
  return true;
};

// Node has no sessionStorage, and fxenc.js's sign-in handoff reads and clears
// exactly this one key. A Map behind the same three methods is the stand-in;
// anything fxenc.js asks for that this does not model throws, which is the
// point - a silently missing control is how wiring bugs hide.
const parkedSecrets = new Map();
globalThis.sessionStorage = {
  getItem: function (key) {
    return parkedSecrets.has(key) ? parkedSecrets.get(key) : null;
  },
  setItem: function (key, value) {
    parkedSecrets.set(key, String(value));
  },
  removeItem: function (key) {
    parkedSecrets.delete(key);
  },
  clear: function () {
    parkedSecrets.clear();
  },
};

// Capture the download instead of handing it to a browser.
let lastBlob = null;
globalThis.URL.createObjectURL = function (blob) {
  lastBlob = blob;
  return "blob:fxenc-harness";
};
globalThis.URL.revokeObjectURL = function () {};

// Node's fetch has no cookie jar and no relative URLs.
const realFetch = globalThis.fetch;
globalThis.fetch = function (input, init) {
  const raw = typeof input === "string" ? input : input.url;
  const abs = /^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : BASE + raw;
  const opts = Object.assign({}, init);
  const headers = new Headers((init && init.headers) || {});
  if (COOKIE) headers.set("Cookie", COOKIE);
  opts.headers = headers;
  return realFetch(abs, opts);
};

// hash-wasm publishes its global only as a plain <script>; under Node it
// fills module.exports (same trick as crypto-roundtrip.js and fxtool.js).
globalThis.hashwasm = require(path.join(ASSETS, "hashwasm-argon2.js"));
globalThis.FXCrypto = require(path.join(ASSETS, "fxcrypto.js"));

// ---------------------------------------------------------------------------
// The other half of the path: the real fxworker.js
//
// A browser tab always has a Worker, so fxenc.js hands every whole-file
// operation to fxworker.js and the page never runs those itself. Node has no
// global `Worker`, which meant this harness quietly tested only the fallback
// - a bug that lives on the cloned hop could stay green here forever.
//
// With FXENC_WORKER=1 this installs a Worker whose message handler *is* the
// real fxworker.js source, wired to the same `self`/`importScripts` globals a
// browser gives it, and both hops are structured clones exactly as the
// browser serialises them. Counted so the run can prove which path it took.
// ---------------------------------------------------------------------------

const fs = require("fs");
const USE_WORKER = process.env.FXENC_WORKER === "1";
let workerMessages = 0;
// The suite runs this harness once per crypto path against one instance, so
// fixture rows carry the mode in their name and the second run cannot collide
// with the files the first one left behind.
const TAG = USE_WORKER ? "worker" : "page";

if (USE_WORKER) {
  const workerSource = fs.readFileSync(path.join(ASSETS, "fxworker.js"), "utf8");

  globalThis.Worker = class FakeWorker {
    constructor() {
      this.onmessage = null;
      this.onerror = null;
      const page = this;
      const workerGlobal = {
        postMessage: function (data) {
          const cloned = structuredClone(data);
          queueMicrotask(() => {
            if (typeof page.onmessage === "function") page.onmessage({ data: cloned });
          });
        },
      };
      const importScripts = function () {
        for (const p of arguments) {
          require(path.join(ASSETS, p.replace("/assets/", "")));
        }
      };
      new Function("self", "importScripts", workerSource)(workerGlobal, importScripts);
      this.handle = workerGlobal.onmessage;
      if (typeof this.handle !== "function") {
        throw new Error("fxworker.js never assigned self.onmessage");
      }
    }
    postMessage(msg) {
      workerMessages += 1;
      const cloned = structuredClone(msg);
      queueMicrotask(() => {
        if (this.handle) this.handle({ data: cloned });
      });
    }
    terminate() {}
  };
}

// i18n.js first, exactly like both pages load it: fxenc.js translates its
// badge and pane strings through it. English is the default and the engine
// needs no init() here - without a real document it stays on the source.
require(path.join(ASSETS, "i18n.js"));
// The module under test: an IIFE that publishes globalThis.FXEnc.
require(path.join(ASSETS, "fxenc.js"));
const FXEnc = globalThis.FXEnc;

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

let passed = 0;
const failures = [];

function ok(label) {
  passed += 1;
  console.log("OK   " + label);
}

function bad(label, why) {
  failures.push(label);
  console.log("FAIL " + label + " - " + (why && why.message ? why.message : why));
}

function expect(label, cond, why) {
  if (cond) ok(label);
  else bad(label, why);
}

async function step(label, fn) {
  try {
    await fn();
    ok(label);
  } catch (e) {
    bad(label, e);
  }
}

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function magicOf(bytes) {
  let s = "";
  for (let i = 0; i < 4 && i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

async function rawGet(url, asBytes) {
  const res = await realFetch(BASE + url, {
    headers: COOKIE ? { Cookie: COOKIE } : {},
  });
  if (!res.ok) throw new Error("GET " + url + " -> " + res.status);
  return asBytes ? new Uint8Array(await res.arrayBuffer()) : res.text();
}

async function rawPut(url, body, type) {
  const res = await realFetch(BASE + url, {
    method: "PUT",
    headers: Object.assign({ "Content-Type": type || "text/plain" }, COOKIE ? { Cookie: COOKIE } : {}),
    body: body,
  });
  return res.status;
}

async function createRow(name) {
  const res = await realFetch(BASE + "/api/files/file", {
    method: "POST",
    headers: Object.assign({ "Content-Type": "application/json" }, COOKIE ? { Cookie: COOKIE } : {}),
    body: JSON.stringify({ parent_id: null, name: name }),
  });
  if (!res.ok) throw new Error("POST /api/files/file -> " + res.status);
  return (await res.json()).entry;
}

// What app.js transfers with: one batch move, `dest_parent: null` meaning
// the caller's root.
async function moveRow(id, destParent) {
  const res = await realFetch(BASE + "/api/files/batch/move", {
    method: "POST",
    headers: Object.assign({ "Content-Type": "application/json" }, COOKIE ? { Cookie: COOKIE } : {}),
    body: JSON.stringify({ ids: [id], dest_parent: destParent }),
  });
  if (!res.ok) throw new Error("POST /api/files/batch/move -> " + res.status);
  return await res.json();
}

async function main() {
  const FX = globalThis.FXCrypto;
  if (!FXEnc) throw new Error("fxenc.js did not publish globalThis.FXEnc");
  if (!FX) throw new Error("fxcrypto.js did not publish globalThis.FXCrypto");

  // ---- 1. the tab starts locked, having read the key record itself --------
  await FXEnc.init(USERNAME);
  expect(
    "init fetches the key record and reports the tab locked",
    FXEnc.status() === "locked" && FXEnc.unlocked() === false && FXEnc.enabled() === true,
    "status=" + FXEnc.status()
  );
  // The badge answers "are new writes encrypted in this tab?" and the answer
  // for a tab that has keys but not loaded them is the honest one: this tab
  // stores files as-is (ENCRYPTION.md 9, flows 2-3, DECISION 11).
  expect(
    "the badge calls a tab without keys 'Unencrypted', not 'Locked'",
    element("enc-badge").textContent === "\uD83D\uDD13 Unencrypted",
    "badge=" + element("enc-badge").textContent
  );

  // ---- 2. unlock exactly as a user would: type the passphrase, press go ---
  element("enc-unlock-pass").value = PASSPHRASE;
  await element("enc-unlock-go").press();
  expect(
    "typing the storage passphrase unlocks the tab",
    FXEnc.unlocked() === true,
    "status=" + FXEnc.status() + " / " + element("enc-status").textContent
  );
  expect(
    "the badge flips to 'Encrypted' once the keys are in memory",
    element("enc-badge").textContent === "\uD83D\uDD12 Encrypted",
    "badge=" + element("enc-badge").textContent
  );
  expect(
    "whole-file crypto runs on " + (USE_WORKER ? "the real fxworker.js" : "the page fallback"),
    USE_WORKER ? workerMessages > 0 : workerMessages === 0,
    "messages through the worker=" + workerMessages
  );

  // ---- 3. the two-phase upload the browser really performs ----------------
  const PLAIN = new TextEncoder().encode(
    "fxenc harness payload\n" + "abcdefghij".repeat(410) + "\nend\n"
  );
  const file = {
    name: `harness-${TAG}.bin`,
    // A copy: encryptUpload may transfer its buffer to the worker.
    arrayBuffer: async function () {
      return PLAIN.slice().buffer;
    },
  };

  let upEntry = null;
  await step("encryptUpload returns the row as the server has it", async () => {
    upEntry = await FXEnc.encryptUpload(file, null, `harness-${TAG}.bin`);
    if (!upEntry || !upEntry.id) throw new Error("no entry returned");
    if (upEntry.enc_version !== 1) throw new Error("enc_version=" + upEntry.enc_version);
    if (!upEntry.enc_key) throw new Error("no enc_key on the returned entry");
  });

  if (upEntry) {
    const stored = await rawGet("/api/files/download?id=" + upEntry.id, true);
    expect(
      "the bytes on the server are an FXE1 container, not the file",
      magicOf(stored) === "FXE1" && !bytesEqual(stored, PLAIN),
      "magic=" + magicOf(stored) + " len=" + stored.length + " vs " + PLAIN.length
    );

    lastBlob = null;
    await step("download decrypts back to the original bytes", async () => {
      await FXEnc.download(upEntry);
      if (!lastBlob) throw new Error("no blob captured from URL.createObjectURL");
      const got = new Uint8Array(await lastBlob.arrayBuffer());
      if (!bytesEqual(got, PLAIN)) {
        throw new Error("got " + got.length + " bytes, want " + PLAIN.length);
      }
    });
  }

  // ---- 4. a file inside a folder follows the chain of 5.2 ----------------
  //
  // encryptUpload has to wrap this row's key under the *folder's* key, not
  // under the root key: that folder key is what a share seals (5.5), so a
  // file chained any other way would stay unreadable for a grantee. The
  // folder gains its own record on demand, exactly as 5.2 describes it, and
  // nothing here creates one up front for a folder nobody wrote into.
  const dirName = `harness-dir-${TAG}`;
  const chainName = `harness-chain-${TAG}.bin`;
  let dirEntry = null;
  let chainEntry = null;

  await step("uploading into a folder keys the folder and chains the file", async () => {
    const res = await realFetch(BASE + "/api/files/folder", {
      method: "POST",
      headers: Object.assign(
        { "Content-Type": "application/json" },
        COOKIE ? { Cookie: COOKIE } : {}
      ),
      body: JSON.stringify({ parent_id: null, name: dirName }),
    });
    if (!res.ok) throw new Error("POST /api/files/folder -> " + res.status);
    dirEntry = (await res.json()).entry;

    const file = {
      name: chainName,
      // A copy: encryptUpload may transfer its buffer to the worker.
      arrayBuffer: async function () {
        return PLAIN.slice().buffer;
      },
    };
    chainEntry = await FXEnc.encryptUpload(file, dirEntry.id, chainName);
    if (!chainEntry || !chainEntry.id) throw new Error("no entry returned");
    if (!chainEntry.enc_key) throw new Error("no key record on the file");

    // The folder row as the server holds it *now* - the listing is what a
    // later breadcrumb walk reads, so the record has to be there, not just
    // in this tab's cache. A folder is marked by its record alone: unlike a
    // file it carries no FXE1 version, there are no bytes under it to name
    // a version for.
    const folder = JSON.parse(await rawGet("/api/files/info?id=" + dirEntry.id, false)).entry;
    if (!folder || !folder.enc_key) {
      throw new Error(
        "folder record: enc_key=" + (folder && folder.enc_key ? "yes" : "no") +
          " enc_version=" + (folder && folder.enc_version)
      );
    }
  });

  if (chainEntry) {
    lastBlob = null;
    await step("a file under a keyed folder still downloads to the same bytes", async () => {
      await FXEnc.download(chainEntry);
      if (!lastBlob) throw new Error("no blob captured from URL.createObjectURL");
      const got = new Uint8Array(await lastBlob.arrayBuffer());
      if (!bytesEqual(got, PLAIN)) {
        throw new Error("got " + got.length + " bytes, want " + PLAIN.length);
      }
    });
  }

  // ---- 5. the editor round trip a new .md file depends on -----------------
  const TEXT1 = "# Notiz\n\nErste Zeile mit Umlauten: aoeu\n\n- eins\n- zwei\n";
  const TEXT2 = "# Notiz (neu)\n\nZweite Fassung.\n";
  let textRow = null;

  await step("writeText turns a fresh plaintext row into an encrypted one", async () => {
    textRow = await createRow(`harness-note-${TAG}.md`);
    if (textRow.enc_version !== 0) throw new Error("fixture is already encrypted");
    const saved = await FXEnc.writeText(textRow, TEXT1);
    if (saved.enc_version !== 1) throw new Error("enc_version=" + saved.enc_version);
    if (!saved.enc_key) throw new Error("no enc_key after the save");
    textRow = saved;
  });

  if (textRow) {
    await step("readText gives the editor exactly what was written", async () => {
      const back = await FXEnc.readText(textRow);
      if (back !== TEXT1) throw new Error("round trip: " + JSON.stringify(back.slice(0, 40)));
    });

    const stored1 = textRow.enc_key;
    // 5.4 / DECISION 5: an overwrite passes the row's own key back, it never
    // rotates it. A fresh key per save would still decrypt - but it would
    // rotate the very record a share envelope and a grantee's unwrapping
    // depend on, so the key that first reached this row has to be the one
    // every later save keeps.
    await step("a second save keeps the same file key (no rotation)", async () => {
      const saved = await FXEnc.writeText(textRow, TEXT2);
      if (saved.enc_key !== stored1) throw new Error("enc_key rotated on an overwrite");
      textRow = saved;
      const back = await FXEnc.readText(saved);
      if (back !== TEXT2) throw new Error("second round trip: " + JSON.stringify(back));
    });

    const rc = await rawPut(
      "/api/files/content?id=" + textRow.id,
      "plaintext overwrite",
      "text/plain"
    );
    expect(
      "the server still refuses a plaintext write onto that row (409)",
      rc === 409,
      "status=" + rc
    );

    // The UI never reuses the entry object it saved with: reopening reads a
    // fresh listing and hands *that* row to readText. So the key that reaches
    // the decryptor comes from here, and a listing that disagreed with what
    // the save returned would show up as "decryption failed for chunk 0".
    await step("reopening through a fresh listing still decrypts", async () => {
      const listing = JSON.parse(await rawGet("/api/files", false));
      const row = (listing.entries || []).filter((e) => e.name === `harness-note-${TAG}.md`)[0];
      if (!row) throw new Error("row missing from the listing");
      if (row.enc_key !== textRow.enc_key) {
        throw new Error("listing enc_key differs from the one the save returned");
      }
      if (row.enc_version !== 1) throw new Error("listing enc_version=" + row.enc_version);
      const back = await FXEnc.readText(row);
      if (back !== TEXT2) throw new Error("got " + JSON.stringify(back.slice(0, 40)));
    });

    // Overlapping saves of one row. `save_content` writes the row's key and
    // then its bytes, so without `FileService::begin_replace` two saves that
    // interleave leave one save's `enc_key` next to another save's ciphertext
    // - the row then unwraps fine and fails only when the file is next
    // opened, as "decryption failed for chunk 0". Several rounds, because
    // that tear needs the interleaving to actually happen.
    await step("overlapping saves never pair one key with another's bytes", async () => {
      const created = await createRow(`harness-race-${TAG}.md`);
      const first = await FXEnc.writeText(created, "race-base");
      let checked = 0;
      for (let round = 0; round < 3; round++) {
        const writes = [];
        for (let i = 0; i < 6; i++) {
          writes.push(FXEnc.writeText(first, "race-" + round + "-" + i));
        }
        const results = await Promise.all(writes.map((p) => p.then(() => null, (e) => e)));
        const rejected = results.filter((e) => e).length;
        if (rejected) throw new Error(rejected + " of 6 saves were rejected");
        const listing = JSON.parse(await rawGet("/api/files", false));
        const row = (listing.entries || []).filter((e) => e.name === `harness-race-${TAG}.md`)[0];
        const back = await FXEnc.readText(row);
        if (!/^race-\d+-\d+$/.test(back)) {
          throw new Error("round " + round + " stored a row that no longer matches its key");
        }
        checked += 1;
      }
      if (checked !== 3) throw new Error("only " + checked + " rounds checked");
    });
  }

  // ---- 6. the case the user reported: a brand new .md file ---------------
  await step("a newly created file is encrypted before anything reads it", async () => {
    const created = await createRow(`harness-empty-${TAG}.md`);
    // This is precisely what app.js newFile() now does when encryption is on.
    const saved = await FXEnc.writeText(created, "");
    if (saved.enc_version !== 1) throw new Error("enc_version=" + saved.enc_version);
    if (!saved.enc_key) throw new Error("no enc_key");
    const back = await FXEnc.readText(saved);
    if (back !== "") throw new Error("empty file came back as " + JSON.stringify(back));
    const stored = await rawGet("/api/files/download?id=" + saved.id, true);
    if (magicOf(stored) !== "FXE1") throw new Error("stored magic=" + magicOf(stored));
  });

  // ---- 7. a plaintext file keeps working the way it always did ------------
  await step("a plaintext row still saves and reads in the clear", async () => {
    const created = await createRow(`harness-plain-${TAG}.txt`);
    const res = await realFetch(BASE + "/api/files/content?id=" + created.id, {
      method: "PUT",
      headers: Object.assign(
        { "Content-Type": "text/plain; charset=utf-8" },
        COOKIE ? { Cookie: COOKIE } : {}
      ),
      body: "no encryption here",
    });
    if (!res.ok) throw new Error("PUT -> " + res.status);
    const back = await rawGet("/api/files/preview?id=" + created.id, false);
    if (back !== "no encryption here") throw new Error("read back " + JSON.stringify(back));
  });

  // ---- 8. sharing: one envelope per row, opened by the recipient ---------
  //
  // The whole point of 5.5: somebody who holds nothing but their own private
  // key and the envelope ends up with the *exact bytes* of the file. Two
  // fresh key pairs stand in for the second account - the seal side runs the
  // way this tab's share dialog does it, the open side runs the way the
  // grantee's tab does it after `openIncomingShares` (envelope, then one
  // record per level down to the file).
  const PEER = await FX.generateKeyPair();
  const OTHER = await FX.generateKeyPair();
  const PEER_USER = "harness-peer";
  const SECRET = new TextEncoder().encode("sealed for one reader only");

  await step("an ECIES envelope opens with the recipient key alone", async () => {
    const env = await FX.eciesSeal(PEER.publicBlob, SECRET, FX.shareEnvelopeAad(7, PEER_USER));
    const opened = await FX.eciesOpen(PEER.privateKey, env, FX.shareEnvelopeAad(7, PEER_USER));
    if (!bytesEqual(opened, SECRET)) throw new Error("the bytes came back different");
  });

  await step("the wrong recipient key and the wrong share are refused", async () => {
    const env = await FX.eciesSeal(PEER.publicBlob, SECRET, FX.shareEnvelopeAad(7, PEER_USER));
    const refusals = [
      // a different reader entirely (a colleague trying somebody else's blob)
      () => FX.eciesOpen(OTHER.privateKey, env, FX.shareEnvelopeAad(7, PEER_USER)),
      // the same envelope replayed against a different row's share
      () => FX.eciesOpen(PEER.privateKey, env, FX.shareEnvelopeAad(8, PEER_USER)),
      // a grantee handing a colleague *their* envelope as if it were his
      () => FX.eciesOpen(PEER.privateKey, env, FX.shareEnvelopeAad(7, "someone-else")),
    ];
    let refused = 0;
    for (const open of refusals) {
      try {
        await open();
      } catch (_) {
        refused += 1;
      }
    }
    if (refused !== refusals.length) {
      throw new Error(refused + " of " + refusals.length + " openings were not refused");
    }
  });

  // The ephemeral pair is generated in the *recipient's* suite (5.5), so an
  // account on the other curve is served, not accidentally excluded.
  await step("a P-256 recipient gets an envelope it can open", async () => {
    const P = await FX.generateKeyPair(FX.SUITE_P256);
    if (P.suite !== FX.SUITE_P256) throw new Error("no P-256 pair available here");
    const env = await FX.eciesSeal(P.publicBlob, SECRET, FX.shareEnvelopeAad(9, PEER_USER));
    const opened = await FX.eciesOpen(P.privateKey, env, FX.shareEnvelopeAad(9, PEER_USER));
    if (!bytesEqual(opened, SECRET)) throw new Error("P-256 round trip mismatch");
  });

  expect(
    "the fingerprint in the share dialog reads as four blocks of eight",
    FXEnc.formatFingerprint("0123456789abcdef0123456789abcdef") ===
      "01234567 89abcdef 01234567 89abcdef",
    "got " + FXEnc.formatFingerprint("0123456789abcdef0123456789abcdef")
  );

  await step("the sealed folder key opens a file below it down to the bytes", async () => {
    if (!dirEntry || !chainEntry) throw new Error("no chained fixture from section 4");
    // What the share dialog posts: one envelope for the folder row, sealed to
    // the grantee's published key (shareEnvelope keys the subtree first, so
    // every row under it unwraps from this one key - 5.2, 5.5).
    const envelope = await FXEnc.shareEnvelope(dirEntry, PEER_USER, FX.b64encode(PEER.publicBlob));
    if (!envelope) throw new Error("no envelope for an encrypted folder");
    // What the grantee's tab does with it: open the envelope, then walk the
    // child records down from the folder key instead of from a root key they
    // never held.
    const folderRaw = await FX.eciesOpen(
      PEER.privateKey,
      envelope,
      FX.shareEnvelopeAad(dirEntry.id, PEER_USER)
    );
    const listing = JSON.parse(await rawGet("/api/files?parent=" + dirEntry.id, false));
    const row = (listing.entries || []).filter((e) => e.name === chainName)[0];
    if (!row) throw new Error("the chained file is not in its folder's listing");
    if (!row.enc_key) throw new Error("the chained file has no key record");
    const fileRaw = await FX.unwrapChildKey(folderRaw, row.id, row.enc_key);
    const stored = await rawGet("/api/files/download?id=" + row.id, true);
    const plain = await FX.decryptBytes(row.id, fileRaw, stored);
    if (!bytesEqual(plain, PLAIN)) {
      throw new Error("got " + plain.length + " bytes back, want " + PLAIN.length);
    }
  });

  await step("a plaintext source needs no envelope at all", async () => {
    const ptRow = await createRow(`harness-ptshare-${TAG}.txt`);
    const envelope = await FXEnc.shareEnvelope(ptRow, PEER_USER, FX.b64encode(PEER.publicBlob));
    if (envelope !== null) throw new Error("a plaintext row got an envelope");
  });

  // ---- 9. an encrypted row travels: re-bind first, then move (5.4) -------
  //
  // Its record is wrapped for the folder it stands in, so app.js re-wraps it
  // for the destination *before* the row moves - which is also the reason the
  // JSON move may cross folders at all: the server cannot read keys, and in a
  // keyed tree every folder carries its own record. What has to hold is the
  // simple thing: after the trip, in both directions, the same bytes open.
  await step("an encrypted row moves into a keyed folder and still opens", async () => {
    const destRes = await realFetch(BASE + "/api/files/folder", {
      method: "POST",
      headers: Object.assign(
        { "Content-Type": "application/json" },
        COOKIE ? { Cookie: COOKIE } : {}
      ),
      body: JSON.stringify({ parent_id: null, name: `harness-dest-${TAG}` }),
    });
    if (!destRes.ok) throw new Error("POST /api/files/folder -> " + destRes.status);
    const dest = (await destRes.json()).entry;
    if (!chainEntry) throw new Error("no chained fixture from section 4");

    // Exactly the order transferConfirm uses: re-bind, then move. The
    // re-bind is what gives the destination folder its own record too.
    await FXEnc.rewrapForParent(chainEntry, dirEntry.id, dest.id);
    const out = await moveRow(chainEntry.id, dest.id);
    if (!out.ok || out.ok.indexOf(chainEntry.id) === -1) {
      throw new Error("the prepared move was refused: " + JSON.stringify(out));
    }

    // Reopen the way the UI does: a fresh listing under the new parent,
    // handed to download as a row nobody has seen before.
    const listed = JSON.parse(await rawGet("/api/files?parent=" + dest.id, false));
    const movedRow = (listed.entries || []).filter((e) => e.name === chainName)[0];
    if (!movedRow) throw new Error("the row is not in its new folder");
    lastBlob = null;
    await FXEnc.download(movedRow);
    if (!lastBlob) throw new Error("no blob captured after the move");
    const afterMove = new Uint8Array(await lastBlob.arrayBuffer());
    if (!bytesEqual(afterMove, PLAIN)) {
      throw new Error("got " + afterMove.length + " bytes after the move, want " + PLAIN.length);
    }

    // And back, so both key domains were crossed in both directions.
    await FXEnc.rewrapForParent(movedRow, dest.id, dirEntry.id);
    const back = await moveRow(movedRow.id, dirEntry.id);
    if (!back.ok || back.ok.indexOf(movedRow.id) === -1) {
      throw new Error("the return move was refused: " + JSON.stringify(back));
    }
    const home = JSON.parse(await rawGet("/api/files?parent=" + dirEntry.id, false));
    const homeRow = (home.entries || []).filter((e) => e.name === chainName)[0];
    if (!homeRow) throw new Error("the row did not come back to its folder");
    lastBlob = null;
    await FXEnc.download(homeRow);
    if (!lastBlob) throw new Error("no blob captured after the return");
    const afterReturn = new Uint8Array(await lastBlob.arrayBuffer());
    if (!bytesEqual(afterReturn, PLAIN)) {
      throw new Error("got " + afterReturn.length + " bytes after the return, want " + PLAIN.length);
    }
    chainEntry = homeRow; // the fixture stays where section 4 left it
  });

  // ---- 10. an encrypted row previews: decrypt here, render from a blob ---
  //
  // Phase 2 (ENCRYPTION.md 12): images, video, audio, PDF and HTML used to
  // be refused on an encrypted row, because the preview endpoint answers
  // 400 on ciphertext. previewBlob() walks download's route - container,
  // row key, worker - and returns the plaintext as a Blob whose type is
  // chosen for the *renderer*, which is the one place it must differ from
  // mimeForDownload: a previewed HTML file reaches the sandboxed frame as
  // text/html, while a saved one is still forced to octet-stream so it
  // cannot script a browser straight off disk.
  await step("an encrypted row previews to its own bytes and render type", async () => {
    const cases = [
      { name: `harness-pix-${TAG}.png`, type: "image/png" },
      { name: `harness-doc-${TAG}.pdf`, type: "application/pdf" },
      { name: `harness-page-${TAG}.html`, type: "text/html" },
    ];
    for (const c of cases) {
      const f = {
        name: c.name,
        // A copy: previewBlob may transfer the buffer to the worker.
        arrayBuffer: async function () {
          return PLAIN.slice().buffer;
        },
      };
      const row = await FXEnc.encryptUpload(f, null, c.name);
      const blob = await FXEnc.previewBlob(row);
      if (!blob) throw new Error(c.name + ": no blob returned");
      if (blob.type !== c.type) throw new Error(c.name + ": type=" + blob.type + " want " + c.type);
      const got = new Uint8Array(await blob.arrayBuffer());
      if (!bytesEqual(got, PLAIN)) {
        throw new Error(c.name + ": got " + got.length + " bytes, want " + PLAIN.length);
      }
    }
    // The download map still calls the same HTML file octet-stream: the
    // renderer type is for a blob URL that only this tab can open, and a
    // download that would run on double-click keeps its harder answer.
    const dlType = globalThis.FXCrypto.mimeForDownload("x.html");
    if (dlType !== "application/octet-stream") {
      throw new Error("downloads of html should stay octet-stream, got " + dlType);
    }
  });

  // ---- 11. the sign-in handoff: the tab that just signed in must not ask ---
  //
  // login.js parks the password for one page load; fxenc.js has to take it
  // exactly once, decline a wrong, stale or "separate" one without breaking
  // anything, and leave the pane as the fallback. Every case here fails
  // *open*: the tab ends up locked and asking, never in an error state.
  const HANDOFF_KEY = "fxcloud.handoff";

  function park(password, at) {
    sessionStorage.setItem(HANDOFF_KEY, JSON.stringify({ password: password, at: at }));
  }

  function handoffLeft() {
    return sessionStorage.getItem(HANDOFF_KEY);
  }

  await step("a parked sign-in secret unlocks the tab without the pane", async () => {
    FXEnc.lockNow();
    park(PASSPHRASE, Date.now());
    await FXEnc.init(USERNAME);
    if (!FXEnc.unlocked()) throw new Error("status=" + FXEnc.status());
    if (handoffLeft() !== null) throw new Error("the parked secret survived its own read");
  });

  await step("a wrong parked secret leaves the tab locked and clears the spot", async () => {
    FXEnc.lockNow();
    park("not-the-passphrase", Date.now());
    await FXEnc.init(USERNAME);
    if (FXEnc.unlocked()) throw new Error("a wrong secret unlocked the tab");
    if (FXEnc.status() !== "locked") throw new Error("status=" + FXEnc.status());
    if (handoffLeft() !== null) throw new Error("the spot was not cleared");
  });

  await step("a stale parked secret is ignored (a restored tab, not a sign-in)", async () => {
    FXEnc.lockNow();
    park(PASSPHRASE, Date.now() - 120000);
    await FXEnc.init(USERNAME);
    if (FXEnc.unlocked()) throw new Error("a stale secret unlocked the tab");
    if (handoffLeft() !== null) throw new Error("the spot was not cleared");
  });

  // The marker decides whether the login password is the right secret for a
  // row at all: written at setup and at recovery, read on every sign-in, so
  // it has to survive a round trip through the server's opaque kdf_params.
  await step("a row marked 'separate' refuses the parked login password", async () => {
    const res = await realFetch(BASE + "/api/keys/me", {
      headers: COOKIE ? { Cookie: COOKIE } : {},
    });
    if (!res.ok) throw new Error("GET /api/keys/me -> " + res.status);
    const original = (await res.json()).keys;
    const marked = JSON.parse(JSON.stringify(original));
    marked.kdf_params = Object.assign({}, marked.kdf_params, { secret: "separate" });

    const put = async (keys) => {
      const r = await realFetch(BASE + "/api/keys/me", {
        method: "PUT",
        headers: Object.assign(
          { "Content-Type": "application/json" },
          COOKIE ? { Cookie: COOKIE } : {}
        ),
        body: JSON.stringify({
          wrapped_ark: keys.wrapped_ark,
          kdf_salt: keys.kdf_salt,
          kdf_params: keys.kdf_params,
        }),
      });
      if (!r.ok) throw new Error("PUT /api/keys/me -> " + r.status);
    };

    try {
      await put(marked);
      FXEnc.lockNow();
      park(PASSPHRASE, Date.now());
      await FXEnc.init(USERNAME);
      if (FXEnc.unlocked()) throw new Error("the marker did not stop the handoff");
      if (FXEnc.status() !== "locked") throw new Error("status=" + FXEnc.status());
      if (handoffLeft() !== null) throw new Error("the spot was not cleared");
    } finally {
      await put(original); // whatever happened, leave the row as it was
    }
  });

  await step("the pane still unlocks after a declined handoff", async () => {
    FXEnc.lockNow();
    element("enc-unlock-pass").value = PASSPHRASE;
    await element("enc-unlock-go").press();
    if (!FXEnc.unlocked()) {
      throw new Error("status=" + FXEnc.status() + " / " + element("enc-status").textContent);
    }
  });

  console.log(
    "DONE " + passed + " passed, " + failures.length + " failed" +
      (failures.length ? " (" + failures.join("; ") + ")" : "")
  );
  process.exit(failures.length ? 1 : 0);
}

main().catch((e) => {
  console.log("FAIL harness crashed - " + (e && e.stack ? e.stack : e));
  process.exit(1);
});
