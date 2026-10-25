/*
 * fxcloud encryption - main-thread glue (ENCRYPTION.md sections 7 and 12).
 *
 * fxcrypto.js holds the primitives and fxworker.js runs the slow ones; this
 * file is the only place that knows about both *and* about the four key
 * endpoints. It owns:
 *
 *   - the status machine   unsupported -> setup -> locked -> unlocked
 *   - the worker RPC, with a main-thread fallback for engines where a
 *     Worker (or its importScripts) is unavailable;
 *   - the setup / unlock / recovery-key panes;
 *   - the two-phase encrypted upload and decrypt-on-download.
 *
 * Key material lives in `state.session` and nowhere else: no localStorage,
 * no sessionStorage, no cookies, no cached response body (DECISION 7). A
 * reload puts the tab back to `locked`, which is the intended behaviour -
 * each tab proves the passphrase itself.
 */
(function () {
  "use strict";

  function FX() {
    return globalThis.FXCrypto;
  }

  // ------------------------------------------------------------------------
  // HTTP - deliberately separate from app.js's `api()` so a failure here
  // still carries a status code the panes can react to.
  // ------------------------------------------------------------------------

  async function http(url, opts) {
    const res = await fetch(url, opts);
    if (res.status === 401) {
      window.location.href = "/login";
      const err = new Error("unauthorized");
      err.status = 401;
      throw err;
    }
    if (!res.ok) {
      let msg = "Request failed (" + res.status + ")";
      try {
        const body = await res.json();
        if (body && body.error) msg = body.error;
      } catch (_) {
        /* not JSON; keep the status line */
      }
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }
    return res;
  }

  // Note the arity: every call site passes (method, payload) only - a third
  // parameter here silently becomes `undefined`, JSON.stringify turns that
  // into no body at all, and the server answers 400 for an empty JSON
  // request. tests/suite.sh pins call sites against this signature.
  const jsonCall = (method, payload) => ({
    method: method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  // ------------------------------------------------------------------------
  // Worker RPC
  // ------------------------------------------------------------------------

  let worker = null;
  let seq = 0;
  const pending = new Map();

  function startWorker() {
    if (worker !== null) return worker;
    try {
      const w = new Worker("/assets/fxworker.js");
      w.onmessage = (ev) => {
        const msg = ev.data || {};
        const entry = pending.get(msg.id);
        if (!entry) return;
        pending.delete(msg.id);
        if (msg.ok) entry.resolve(msg.result);
        else entry.reject(new Error(msg.error || "crypto worker error"));
      };
      w.onerror = (ev) => {
        console.warn(
          "fxcloud: crypto worker stopped, falling back to the page:",
          ev.message || ev
        );
        try {
          w.terminate();
        } catch (_) {
          /* already gone */
        }
        worker = null;
        for (const [, entry] of pending) entry.reject(new Error("crypto worker stopped"));
        pending.clear();
      };
      worker = w;
    } catch (e) {
      console.warn(
        "fxcloud: no Web Worker available, running crypto on the page:",
        e.message || e
      );
      worker = null;
    }
    return worker;
  }

  /**
   * Run one fxcrypto operation, preferably off the page's thread.
   *
   * The op names and argument lists are exactly fxcrypto's, so the fallback
   * is the same call without the round trip. `transfer` lists buffers that
   * may be moved rather than copied - it is ignored on the fallback path,
   * where the caller still owns its bytes.
   *
   * Resolves to `{ bytes }` in both cases, so callers never branch.
   */
  function heavy(op, args, transfer) {
    const w = worker;
    if (!w) {
      return Promise.resolve()
        .then(() => FX()[op].apply(null, args))
        .then((bytes) => ({ bytes: bytes }));
    }
    return new Promise((resolve, reject) => {
      const id = ++seq;
      pending.set(id, { resolve: resolve, reject: reject });
      try {
        w.postMessage({ id: id, op: op, args: args }, transfer || []);
      } catch (e) {
        pending.delete(id);
        reject(e);
      }
    });
  }

  /** Argon2id, routed to the worker: the one step worth moving. */
  function derive(password, salt, params) {
    return heavy("deriveKek", [password, salt, params]).then((r) => r.bytes);
  }

  // ------------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------------

  const state = {
    status: "unsupported", // unsupported | setup | locked | unlocked
    keys: null, // the stored, wrapped row (GET /api/keys/me)
    session: null, // { ark, rootKey, privateKey, publicKey, ... } - memory only
    fingerprint: null,
    username: null,
    recoveryHex: null, // only between setup and the "saved" pane
  };

  const listeners = [];

  function emit() {
    for (const fn of listeners) {
      try {
        fn(state.status);
      } catch (_) {
        /* a listener must never break the page */
      }
    }
    render();
  }

  // One promise gate: an upload that arrives while everything is locked waits
  // for the user's decision instead of silently writing plaintext.
  let gateResolve = null;

  function settleGate(value) {
    if (!gateResolve) return;
    const resolve = gateResolve;
    gateResolve = null;
    resolve(value);
  }

  /** @returns {Promise<boolean>} - true when the keys are usable right now. */
  function requestKeys() {
    if (state.status === "unlocked") return Promise.resolve(true);
    if (state.status === "unsupported") {
      alert(
        "This browser has no WebCrypto, so encrypted uploads are unavailable. " +
          "HTTPS (or localhost) and a current browser are required."
      );
      return Promise.resolve(false);
    }
    openPane(state.status === "setup" ? "setup" : "unlock");
    return new Promise((resolve) => {
      gateResolve = resolve;
    });
  }

  // ------------------------------------------------------------------------
  // DOM
  // ------------------------------------------------------------------------

  const PANES = ["setup", "saved", "unlock", "recover", "info"];

  function $(id) {
    return document.getElementById(id);
  }

  function openPane(name) {
    for (let i = 0; i < PANES.length; i++) {
      const el = $("enc-pane-" + PANES[i]);
      if (el) el.style.display = PANES[i] === name ? "" : "none";
    }
    setStatus("");
    const m = $("enc-modal");
    if (m) m.style.display = "flex";
    const pane = $("enc-pane-" + name);
    const field = pane && pane.querySelector("input:not([type=checkbox]), textarea");
    if (field) field.focus();
  }

  function closeModal() {
    const m = $("enc-modal");
    if (m) m.style.display = "none";
    state.recoveryHex = null;
    settleGate(false);
  }

  function setStatus(text, isError) {
    const el = $("enc-status");
    if (!el) return;
    el.textContent = text || "";
    el.className = "enc-status" + (isError ? " error" : "");
  }

  function render() {
    const badge = $("enc-badge");
    if (!badge) return;
    if (state.status === "unsupported") {
      badge.style.display = "none";
      return;
    }
    badge.style.display = "";
    badge.className = "enc-badge " + state.status;
    if (state.status === "setup") {
      badge.textContent = "Encrypt uploads";
      badge.title =
        "Client-side encryption is not set up yet. Files you upload are stored " +
        "as-is until you turn it on. Click to set it up.";
    } else if (state.status === "locked") {
      badge.textContent = "\uD83D\uDD12 Locked";
      badge.title =
        "Encrypted files cannot be decrypted in this tab yet. Click to unlock.";
    } else {
      badge.textContent = "\uD83D\uDD13 Encrypted";
      badge.title =
        "Uploads are encrypted in this browser before they leave the device. " +
        "Click to lock or to see this account's key fingerprint.";
    }
  }

  function setBusy(on) {
    const ids = ["enc-setup-go", "enc-saved-go", "enc-unlock-go", "enc-rcv-go"];
    for (let i = 0; i < ids.length; i++) {
      const el = $(ids[i]);
      if (el) el.disabled = on;
    }
  }

  // ------------------------------------------------------------------------
  // Account lifecycle
  // ------------------------------------------------------------------------

  async function init(username) {
    if (username) state.username = username;
    if (!window.crypto || !window.crypto.subtle) {
      state.status = "unsupported";
      emit();
      return;
    }
    startWorker();
    wire();
    try {
      const body = await http("/api/keys/me").then((r) => r.json());
      adoptKeys(body.keys, "locked");
    } catch (e) {
      // 404 = no key row yet. Anything else (offline, 5xx) also lands here:
      // showing "setup" is the honest default, and a genuine key row will
      // refuse a second, different setup with 409 - which runSetup reports.
      void e;
      state.status = "setup";
      state.keys = null;
      emit();
    }
  }

  function adoptKeys(keys, nextStatus) {
    state.keys = keys;
    state.fingerprint = keys ? keys.fingerprint : null;
    state.status = nextStatus;
    emit();
  }

  async function runSetup() {
    const pass = $("enc-setup-pass").value;
    const pass2 = $("enc-setup-pass2").value;
    if (!pass) return setStatus("Choose a storage passphrase.", true);
    if (pass !== pass2) return setStatus("The two passphrases do not match.", true);

    setStatus("Deriving keys (Argon2id, 64 MiB)…");
    setBusy(true);
    try {
      const account = await FX().generateAccount(pass, derive);
      let body;
      try {
        body = await http("/api/keys/setup", jsonCall("POST", account.payload)).then((r) =>
          r.json()
        );
      } catch (e) {
        if (e.status === 409) {
          // A key row already exists with different material (an earlier
          // tab, or the transient failure that put us in `setup`). Never
          // overwrite it: adopt what is stored and unlock against that.
          const existing = await http("/api/keys/me").then((r) => r.json());
          state.session = null;
          adoptKeys(existing.keys, "locked");
          setStatus(
            "This account already has a key record; unlock with its " +
              "passphrase instead.",
            true
          );
          return;
        }
        throw e;
      }
      state.session = account.session;
      state.recoveryHex = account.recoveryHex;
      $("enc-saved-key").textContent = groupRecovery(account.recoveryHex);
      $("enc-saved-ack").checked = false;
      adoptKeys(body.keys, "unlocked");
      openPane("saved");
    } catch (e) {
      setStatus(e.message, true);
    } finally {
      setBusy(false);
    }
  }

  /**
   * The one moment the recovery key exists in the clear. The pane cannot be
   * left without an explicit "I saved it" - the risk acknowledgement that
   * makes losing *both* the passphrase and this key the user's choice rather
   * than our surprise.
   */
  function finishSetup() {
    state.recoveryHex = null;
    $("enc-saved-key").textContent = "";
    const m = $("enc-modal");
    if (m) m.style.display = "none";
    settleGate(true);
  }

  function downloadRecoveryKey() {
    if (!state.recoveryHex) return;
    const text = FX().recoveryFile(state.username || "account", state.recoveryHex);
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "fxcloud-recovery-key.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    $("enc-saved-ack").checked = true;
    armSaved();
  }

  function groupRecovery(hex) {
    const out = [];
    for (let i = 0; i < hex.length; i += 16) out.push(hex.slice(i, i + 16));
    return out.join("\n");
  }

  function armSaved() {
    const go = $("enc-saved-go");
    if (go) go.disabled = !$("enc-saved-ack").checked;
  }

  async function runUnlock() {
    const pass = $("enc-unlock-pass").value;
    if (!pass) return setStatus("Enter your storage passphrase.", true);
    setStatus("Deriving keys (Argon2id, 64 MiB)…");
    setBusy(true);
    try {
      state.session = await FX().unlockAccount(state.keys, pass, derive);
      state.status = "unlocked";
      $("enc-unlock-pass").value = "";
      emit();
      closeModal();
      settleGate(true);
    } catch (e) {
      setStatus(e.message, true);
      $("enc-unlock-pass").select();
    } finally {
      setBusy(false);
    }
  }

  async function runRecover() {
    const raw = $("enc-rcv-key").value;
    const pass = $("enc-rcv-pass").value;
    const pass2 = $("enc-rcv-pass2").value;
    if (!raw.trim()) return setStatus("Paste the 64 hex digits from your recovery key.", true);
    if (!pass) return setStatus("Choose a new storage passphrase.", true);
    if (pass !== pass2) return setStatus("The two passphrases do not match.", true);

    let recovery;
    try {
      recovery = FX().fromHex(raw);
    } catch (e) {
      return setStatus(e.message, true);
    }
    if (recovery.length !== 32) return setStatus("A recovery key is 32 bytes - 64 hex digits.", true);

    setStatus("Opening the account root key…");
    setBusy(true);
    try {
      // Recovery opens the ARK directly; the private key and the root key
      // hang off it, so a recovered session is a full session rather than a
      // read-only peek (ENCRYPTION.md 5.7).
      const session = await FX().openWithRecovery(state.keys, recovery);
      setStatus("Re-wrapping under the new passphrase…");
      const rewrap = await FX().rewrapAccount(session.ark, pass, derive);
      await http("/api/keys/me", jsonCall("PUT", rewrap));
      const merged = Object.assign({}, state.keys, rewrap);
      state.session = session;
      $("enc-rcv-key").value = "";
      $("enc-rcv-pass").value = "";
      $("enc-rcv-pass2").value = "";
      adoptKeys(merged, "unlocked");
      closeModal();
      settleGate(true);
    } catch (e) {
      setStatus(e.message, true);
    } finally {
      setBusy(false);
    }
  }

  function lockNow() {
    // Drop every reference; the GC reclaims the bytes. DECISION 7 - per tab,
    // memory only, until the user asks for it again.
    state.session = null;
    state.status = state.keys ? "locked" : "setup";
    emit();
    const m = $("enc-modal");
    if (m) m.style.display = "none";
    settleGate(false);
  }

  // ------------------------------------------------------------------------
  // Encrypted transfer
  // ------------------------------------------------------------------------

  /**
   * Two-phase encrypted upload (ENCRYPTION.md 7): create the row first, so
   * the ciphertext and its wrapped key can both be bound to an id that
   * already exists, then fill it.
   *
   * `POST /api/files/file` also fails fast on a duplicate name, before a
   * single byte of a possibly large file has been read or encrypted.
   */
  async function encryptUpload(file, parentId, fileName) {
    if (!(await requestKeys())) throw new Error("encrypted upload cancelled");

    const created = await http(
      "/api/files/file",
      jsonCall("POST", { parent_id: parentId, name: fileName })
    ).then((r) => r.json());
    const id = created.entry.id;

    try {
      const plain = new Uint8Array(await file.arrayBuffer());
      const fileKey = FX().randomBytes(32);
      // Wrapped under *our* root key and bound to this row: the record is
      // stored on the row we just created, which is ours by construction
      // (create_file always mints the row under the uploader's id), so the
      // destination folder's owner never has to be consulted.
      const wrappedKey = await FX().wrapChildKey(state.session.rootKey, id, fileKey);
      const out = await heavy("encryptBytes", [plain, id, fileKey], [plain.buffer]);
      await http("/api/files/content?id=" + id + "&enc=1&key=" + encodeURIComponent(wrappedKey), {
        method: "PUT",
        headers: { "Content-Type": "application/octet-stream" },
        body: out.bytes,
      });
      return created.entry;
    } catch (e) {
      await discardRow(id);
      throw e;
    }
  }

  /** Best-effort removal of a half-made row (delete, then purge the trash). */
  async function discardRow(id) {
    try {
      await http("/api/files/batch/delete", jsonCall("POST", { ids: [id] }));
    } catch (_) {
      return;
    }
    try {
      await http("/api/files/trash/purge", jsonCall("POST", { id: id }));
    } catch (_) {
      /* already gone */
    }
  }

  /** Fetch, decrypt and save - the only way an encrypted row leaves fxcloud. */
  async function download(entry) {
    if (state.status !== "unlocked") throw new Error("unlock encryption to download this file");
    const res = await http("/api/files/download?id=" + entry.id);
    const body = new Uint8Array(await res.arrayBuffer());
    const fileKey = await FX().unwrapChildKey(state.session.rootKey, entry.id, entry.enc_key);
    const out = await heavy("decryptBytes", [body, entry.id, fileKey], [body.buffer]);
    const blob = new Blob([out.bytes], { type: FX().mimeForDownload(entry.name) });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = entry.name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  // ------------------------------------------------------------------------
  // Wiring
  // ------------------------------------------------------------------------

  let wired = false;

  function wire() {
    if (wired) return;
    wired = true;

    const on = (id, fn) => {
      const el = $(id);
      if (el) el.addEventListener("click", fn);
    };

    const badge = $("enc-badge");
    if (badge) {
      badge.addEventListener("click", () => {
        if (state.status === "setup") openPane("setup");
        else if (state.status === "locked") openPane("unlock");
        else {
          $("enc-info-fp").textContent = state.fingerprint
            ? FX().formatFingerprint(state.fingerprint)
            : "—";
          openPane("info");
        }
      });
    }

    on("enc-setup-go", runSetup);
    on("enc-setup-cancel", closeModal);
    on("enc-saved-dl", downloadRecoveryKey);
    on("enc-saved-go", finishSetup);
    on("enc-unlock-go", runUnlock);
    on("enc-unlock-cancel", closeModal);
    on("enc-unlock-recover", () => openPane("recover"));
    on("enc-rcv-go", runRecover);
    on("enc-rcv-back", () => openPane("unlock"));
    on("enc-info-close", closeModal);
    on("enc-info-lock", lockNow);

    // Enter submits in whichever pane is showing (buttons are type=button).
    const enterTo = (inputId, buttonId) => {
      const el = $(inputId);
      if (!el) return;
      el.addEventListener("keydown", (e) => {
        if (e.key !== "Enter") return;
        e.preventDefault();
        const btn = $(buttonId);
        if (btn && !btn.disabled) btn.click();
      });
    };
    enterTo("enc-setup-pass2", "enc-setup-go");
    enterTo("enc-unlock-pass", "enc-unlock-go");
    enterTo("enc-rcv-pass2", "enc-rcv-go");

    // The setup button only arms once both passphrase fields agree.
    const armSetup = () => {
      const go = $("enc-setup-go");
      if (!go) return;
      const pass = $("enc-setup-pass").value;
      go.disabled = !pass || pass !== $("enc-setup-pass2").value;
    };
    for (const id of ["enc-setup-pass", "enc-setup-pass2"]) {
      const el = $(id);
      if (el) el.addEventListener("input", armSetup);
    }
    armSetup();
    armSaved();

    const ack = $("enc-saved-ack");
    if (ack) ack.addEventListener("change", armSaved);

    const backdrop = $("enc-modal");
    if (backdrop) {
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) closeModal();
      });
    }
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if (backdrop && backdrop.style.display !== "none") closeModal();
    });
  }

  // ------------------------------------------------------------------------
  // Public surface for app.js
  // ------------------------------------------------------------------------

  globalThis.FXEnc = {
    init: init,
    onChange: (fn) => listeners.push(fn),
    status: () => state.status,
    unlocked: () => state.status === "unlocked",
    enabled: () => state.status === "unlocked" || state.status === "locked",
    requestKeys: requestKeys,
    encryptUpload: encryptUpload,
    download: download,
    lockNow: lockNow,
    isEncrypted: (entry) => !!entry && entry.enc_version > 0,
  };
})();
