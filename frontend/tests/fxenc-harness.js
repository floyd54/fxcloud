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
 *   writeText -> readText    -> text identical, wrapped key rotated per save
 *   reopening                -> through a fresh listing, not a saved object
 *   overlapping saves        -> never a row whose key and bytes disagree
 *   a brand new file         -> encrypted from its first second
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

  // ---- 2. unlock exactly as a user would: type the passphrase, press go ---
  element("enc-unlock-pass").value = PASSPHRASE;
  await element("enc-unlock-go").press();
  expect(
    "typing the storage passphrase unlocks the tab",
    FXEnc.unlocked() === true,
    "status=" + FXEnc.status() + " / " + element("enc-status").textContent
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

  // ---- 4. the editor round trip a new .md file depends on -----------------
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
    await step("a second save re-wraps under a fresh file key", async () => {
      const saved = await FXEnc.writeText(textRow, TEXT2);
      if (saved.enc_key === stored1) throw new Error("enc_key did not rotate");
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

  // ---- 5. the case the user reported: a brand new .md file ---------------
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

  // ---- 6. a plaintext file keeps working the way it always did ------------
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
