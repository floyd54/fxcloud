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
 * no sessionStorage, no cookies, no cached response body (DECISION 7). The
 * single exception is the sign-in handoff below: login.js parks the login
 * password for the length of one page load so the tab that just signed in
 * is not asked for it again, and this file deletes it on its first read. A
 * reload still puts the tab back to `locked` - each tab proves the
 * passphrase itself.
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
    // Mounts someone shared with me (GET /api/shares/incoming) - rows and
    // sealed blobs, useful while still locked; their envelopes are opened
    // once the private key exists.
    incomingShares: [],
  };

  // Raw keys, memory only like everything else here (DECISION 7):
  //  - shareKeys:  source id -> the record an envelope opened for me
  //  - folderKeys: folder id -> resolved key, so the next read or write
  //                skips the breadcrumb walk it came from
  const shareKeys = new Map();
  const folderKeys = new Map();

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
      // The badge answers exactly one question: are new writes encrypted in
      // this tab? "Unencrypted" is the honest answer for a tab whose keys
      // are not loaded - and it is what every reload lands on, since keys
      // live in memory only (DECISION 7).
      badge.textContent = "\uD83D\uDD13 Unencrypted";
      badge.title =
        "New files and uploads in this tab are stored as-is. Click to turn " +
        "encryption on here - that also opens this account's encrypted files.";
    } else {
      badge.textContent = "\uD83D\uDD12 Encrypted";
      badge.title =
        "Uploads are encrypted in this browser before they leave the device. " +
        "Click to turn it off for this tab or to see this account's key fingerprint.";
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
    // Taken first, whatever happens below: the parked secret must not
    // outlive the document it arrived with, so even a failing key fetch or
    // an unsupported browser drops it instead of leaving it behind.
    const parked = takeHandoff();
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
      // Awaited rather than fired: app.js draws the folder as soon as init()
      // resolves, so a listing rendered before this finished would show every
      // encrypted row still locked.
      await adoptHandoff(parked);
    } catch (e) {
      // 404 = no key row yet. A passphrase parked by registering is the one
      // reason to still be here with a secret in hand: create the keys from
      // it right now, so an account that chose a passphrase at sign-up starts
      // unlocked instead of being asked for the same string a second time.
      // Anything else (offline, 5xx) lands in "setup" as it always did -
      // honest, and a genuine key row still refuses a second, different
      // setup with 409 - which runSetup reports.
      if (e && e.status === 404 && parked && parked.kind === "passphrase") {
        try {
          await setupFromHandoff(parked.value);
          return;
        } catch (_) {
          /* fall through to the setup pane: it is the safe default */
        }
      }
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

  // ------------------------------------------------------------------------
  // The sign-in handoff
  //
  // Signing in and opening the app are two page loads, so the string the user
  // typed does not survive the redirect by itself. login.js parks it in
  // sessionStorage: the login password for a `login` row, the passphrase for
  // a `separate` one, and a passphrase chosen during registration for the row
  // that does not exist yet. Everything here is about taking it exactly once.
  // ------------------------------------------------------------------------

  const HANDOFF_KEY = "fxcloud.handoff";
  // Longer than any redirect, shorter than "back to this tab tomorrow": a
  // value this old is a restored tab rather than a sign-in, and it must not
  // open anything.
  const HANDOFF_TTL_MS = 60000;

  /**
   * Take the parked secret and drop it in the same tick.
   *
   * Read and remove are adjacent on purpose: a reload during the derivation
   * below has to find nothing, so the secret exists in storage only between
   * the sign-in redirect and this call - one page load, which is the
   * DECISION 7 lifetime with the handoff spliced into it.
   *
   * @returns {{value: string, kind: string}|null} the secret to try, where
   *   `kind` is "password" or "passphrase", or null for "ask instead". A
   *   handoff without a kind predates passphrase sign-in and is the login
   *   password.
   */
  function takeHandoff() {
    let raw = null;
    try {
      raw = sessionStorage.getItem(HANDOFF_KEY);
      sessionStorage.removeItem(HANDOFF_KEY);
    } catch (_) {
      return null; // storage unavailable: the pane asks, as it always did
    }
    if (!raw) return null;
    try {
      const parked = JSON.parse(raw);
      if (!parked || typeof parked.password !== "string" || !parked.password) return null;
      if (typeof parked.at !== "number") return null;
      if (Date.now() - parked.at > HANDOFF_TTL_MS) return null;
      const kind = parked.kind === "passphrase" ? "passphrase" : "password";
      return { value: parked.password, kind: kind };
    } catch (_) {
      return null;
    }
  }

  /**
   * Unlock this tab without a prompt when sign-in already carried the secret.
   *
   * `parked` is what init() took from the parking spot; here it either opens
   * this row or is dropped. The value has to be the secret the row is
   * wrapped under: the login password for a `login` row, the passphrase for
   * a `separate` one - a sign-in with the other credential carries the other
   * string, and this row was not wrapped with it. Every way that fails is a
   * normal state rather than an error: nothing was carried (a second tab, a
   * reload), the kinds do not match, or the string does not open the stored
   * ARK. The tab then stays `locked` and the pane is the fallback - which is
   * also the path a stale or tampered handoff takes.
   *
   * @param {{value: string, kind: string}|null} parked
   * @returns {Promise<boolean>} true when the tab is unlocked now.
   */
  async function adoptHandoff(parked) {
    if (!parked || !state.keys) return false;
    try {
      const params = state.keys.kdf_params || {};
      const wanted = params.secret === "separate" ? "passphrase" : "password";
      if (parked.kind !== wanted) return false;
      const badge = $("enc-badge");
      if (badge) badge.textContent = "Unlocking\u2026";
      state.session = await FX().unlockAccount(state.keys, parked.value, derive);
      state.status = "unlocked";
      // Envelopes can be opened now - awaited, so a listing drawn right
      // after this resolves already knows which mounts it can open.
      await refreshShareKeys();
      emit();
      return true;
    } catch (_) {
      state.session = null;
      emit(); // renders the padlock again from the unchanged status
      return false;
    }
  }

  /**
   * Publish freshly generated key material and open the recovery pane.
   *
   * The shared tail of every path that *creates* a row - the setup pane, the
   * registration handoff and passphrase enrollment - because they all end on
   * the same obligation: the recovery key exists in the clear right now, and
   * the pane that makes the user save it must open before anything else is
   * offered.
   *
   * @param {Object} account - from generateAccount(): session + recoveryHex.
   * @param {Object} keys - the row the server just accepted (body.keys).
   */
  async function publishAccount(account, keys) {
    state.session = account.session;
    state.recoveryHex = account.recoveryHex;
    $("enc-saved-key").textContent = groupRecovery(account.recoveryHex);
    $("enc-saved-ack").checked = false;
    adoptKeys(keys, "unlocked");
    await refreshShareKeys();
    openPane("saved");
  }

  /**
   * Create the key row for an account that registered with a passphrase.
   *
   * Runs from init()'s 404 branch with the value login.js parked: the
   * server verified this string as the account's passphrase during the
   * sign-in that just happened, so - unlike runSetup's "reuse login
   * password" branch, which types the password again to prove the default -
   * there is nothing left to prove here. `kdf_params.secret` is claimed as
   * "separate" for what the account really has: a passphrase distinct from
   * the password, never the login secret.
   *
   * @param {string} passphrase - the value just verified at sign-in.
   */
  async function setupFromHandoff(passphrase) {
    const badge = $("enc-badge");
    if (badge) badge.textContent = "Setting up encryption\u2026";
    const account = await FX().generateAccount(passphrase, derive);
    account.payload.kdf_params = Object.assign({}, account.payload.kdf_params, {
      secret: "separate",
    });
    let body;
    try {
      body = await http("/api/keys/setup", jsonCall("POST", account.payload)).then((r) =>
        r.json()
      );
    } catch (e) {
      if (e && e.status === 409) {
        // Another tab (or an earlier attempt) published keys first. Keep
        // theirs locked and let the pane do its job rather than wrap a
        // second row over the first.
        const existing = await http("/api/keys/me").then((r) => r.json());
        state.session = null;
        adoptKeys(existing.keys, "locked");
        return;
      }
      throw e;
    }
    await publishAccount(account, body.keys);
  }

  /**
   * Prove that the typed secret really is the account's login password.
   *
   * The client has no way to know that string, and a typo in the default
   * would not surface until a later tab tried to unlock - by then the only
   * way back in is the recovery key. So the one time the default is chosen,
   * the string is checked against the account first.
   *
   * Deliberately not `http()`: a wrong password answers 401 and `http()`
   * treats every 401 as a dead session, redirecting to /login - which would
   * throw the user out of this dialog over a mere typo. Here a 401 is the
   * verdict, not a session failure.
   */
  async function verifyLogin(password) {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: state.username, password: password }),
    });
    if (res.ok) return true;
    if (res.status === 401) return false;
    let msg = "Could not check the login password (" + res.status + ")";
    try {
      const b = await res.json();
      if (b && b.error) msg = b.error;
    } catch (_) {
      /* not JSON; keep the status line */
    }
    throw new Error(msg);
  }

  async function runSetup() {
    const reuseLogin = $("enc-use-login").checked;
    const pass = $("enc-setup-pass").value;
    const pass2 = $("enc-setup-pass2").value;
    if (!pass)
      return setStatus(
        reuseLogin ? "Enter your fxcloud login password." : "Choose a storage passphrase.",
        true
      );
    if (!reuseLogin && pass !== pass2)
      return setStatus("The two passphrases do not match.", true);

    setBusy(true);
    try {
      if (reuseLogin) {
        setStatus("Checking your login password…");
        if (!(await verifyLogin(pass))) {
          setStatus("That is not your fxcloud login password.", true);
          return;
        }
      }

      setStatus("Deriving keys (Argon2id, 64 MiB)…");
      const account = await FX().generateAccount(pass, derive);
      // DECISION 3's default only pays off if the next tab can tell which
      // secret the row is wrapped under: sign-in carries the login password
      // across the page load and never a separate one. kdf_params is opaque
      // to the server (ENCRYPTION.md 5.4), so the marker rides inside it and
      // needs no schema change - and "login" is claimed only after the check
      // above, where the server agreed this string is the login password.
      account.payload.kdf_params = Object.assign({}, account.payload.kdf_params, {
        secret: reuseLogin ? "login" : "separate",
      });
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
      // A brand-new account has no envelopes yet - a share sealed to this
      // key row cannot exist before it does - but taking the same step on
      // every path into `unlocked` keeps the invariant unguessable-simple.
      await refreshShareKeys();
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
      await refreshShareKeys();
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
      // The secret just changed, so any earlier marker is void. Claim "login"
      // only when the server agrees this string is the login password - the
      // rule setup follows - and "separate" on any doubt, which costs nothing
      // but the prompt the pane gives anyway.
      let matchesLogin = false;
      try {
        matchesLogin = await verifyLogin(pass);
      } catch (_) {
        matchesLogin = false;
      }
      rewrap.kdf_params = Object.assign({}, rewrap.kdf_params, {
        secret: matchesLogin ? "login" : "separate",
      });
      await http("/api/keys/me", jsonCall("PUT", rewrap));
      const merged = Object.assign({}, state.keys, rewrap);
      state.session = session;
      $("enc-rcv-key").value = "";
      $("enc-rcv-pass").value = "";
      $("enc-rcv-pass2").value = "";
      adoptKeys(merged, "unlocked");
      await refreshShareKeys();
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
    // memory only, until the user asks for it again. The resolved keys go
    // with the session: they are only worth anything *with* it, and a later
    // unlock rebuilds both maps from the rows and envelopes anyway.
    state.session = null;
    shareKeys.clear();
    folderKeys.clear();
    state.status = state.keys ? "locked" : "setup";
    emit();
    const m = $("enc-modal");
    if (m) m.style.display = "none";
    settleGate(false);
  }

  // ------------------------------------------------------------------------
  // The key hierarchy (5.2): every child record is wrapped with its parent's
  //
  // Top of the tree sits my root key for my own rows, and for a mount I was
  // given the key its envelope opened (5.5). The breadcrumb is the trail a
  // read walks to connect the two: it is one request the app makes anyway,
  // it ends at the entry itself, and it carries every crumb's `enc_key` - so
  // one round trip brings the whole chain, and the last unwrap is the row's
  // own record.
  // ------------------------------------------------------------------------

  async function loadIncomingShares() {
    try {
      const body = await http("/api/shares/incoming").then((r) => r.json());
      state.incomingShares = body.shares || [];
    } catch (_) {
      // No list, no envelopes: the mounts still appear in the listing and
      // open as plaintext; a read that needs one reports the usual message.
      state.incomingShares = [];
    }
  }

  /**
   * Open every envelope sealed to me (5.5). Needs the private key, so this
   * runs on each path into `unlocked`. One envelope that fails to open is
   * skipped, not fatal: a single stale blob must not take the rest of the
   * mounts down with it, and the read that eventually hits it reports the
   * standard "could not unwrap this key" - which is what it is.
   */
  async function openIncomingShares() {
    shareKeys.clear();
    if (!state.session || !state.session.privateKey) return;
    for (const share of state.incomingShares) {
      if (!share.envelope) continue; // plaintext share: nothing was sealed
      try {
        const aad = FX().shareEnvelopeAad(share.file_id, state.username);
        shareKeys.set(share.file_id, await FX().eciesOpen(state.session.privateKey, share.envelope, aad));
      } catch (_) {
        /* sealed for another key, or altered: the read reports it */
      }
    }
  }

  /** Called on every unlock: fresh mounts, freshly opened envelopes. */
  async function refreshShareKeys() {
    await loadIncomingShares();
    await openIncomingShares();
  }

  /**
   * The raw key behind an entry, resolved where the row stands *now*.
   *
   * Start at the top of the trail - my root key, or the mount's envelope
   * (the mount's own stored record belongs to the owner's chain, not mine,
   * so it is skipped) - then unwrap down one crumb per level, the entry's
   * own record last. A record that predates this hierarchy (wrapped
   * straight to the root key, 5.4) still opens through the fallback; a
   * grantee hitting one has no fallback to hit, because they never held
   * that root key.
   */
  async function resolveFileKey(entry) {
    if (!state.session) throw new Error("unlock encryption to open this file");
    const cached = folderKeys.get(entry.id);
    if (cached) return cached;
    const trail = await http("/api/files/breadcrumb?id=" + entry.id).then((r) => r.json());
    const crumbs = (trail.breadcrumbs || []).filter((c) => c.id != null);
    let key;
    let start;
    if (crumbs.length > 0 && shareKeys.has(crumbs[0].id)) {
      key = shareKeys.get(crumbs[0].id);
      start = 1;
    } else {
      key = state.session.rootKey;
      start = 0;
    }
    for (let i = start; i < crumbs.length; i++) {
      if (!crumbs[i].enc_key) {
        key = null; // the chain stops here; the fallback decides
        break;
      }
      try {
        key = await FX().unwrapChildKey(key, crumbs[i].id, crumbs[i].enc_key);
      } catch (_) {
        key = null;
        break;
      }
    }
    if (key) {
      folderKeys.set(entry.id, key);
      return key;
    }
    // Legacy flat record (5.4): wrapped straight to my root key. Only my own
    // tree can hold one, and only a tab that holds the root key opens it.
    if (state.session && entry.enc_key) {
      const legacy = await FX()
        .unwrapChildKey(state.session.rootKey, entry.id, entry.enc_key)
        .catch(() => null);
      if (legacy) return legacy;
    }
    throw new Error("could not unwrap this key - wrong passphrase, or the data was altered");
  }

  /**
   * The raw key behind a row's record *as of a given parent*. A move leaves
   * the record wrapped for where the row came from until the re-binding
   * lands, and the trail only ever shows where the row now is - so the
   * caller that knows both says which parent to believe.
   */
  async function resolveRecordUnder(entry, parentId) {
    if (!entry.enc_key) throw new Error("this file has no stored key to open it with");
    // A mount's own record came from its envelope, wherever the row stands.
    if (shareKeys.has(entry.id)) return shareKeys.get(entry.id);
    // At a top level the trail tells the truth (own root), so the ordinary
    // resolution is the right one.
    if (parentId == null) return await resolveFileKey(entry);
    return await FX().unwrapChildKey(await chainKey(parentId), entry.id, entry.enc_key);
  }

  /** A folder's key as it stands: resolve, never create. */
  async function chainKey(folderId) {
    const cached = folderKeys.get(folderId);
    if (cached) return cached;
    const info = await http("/api/files/info?id=" + folderId).then((r) => r.json());
    return await resolveFileKey(info.entry);
  }

  /**
   * The key a *new* record under `parentId` gets wrapped with - creating the
   * folder's own record if it has none yet (5.5: folders start unkeyed and
   * are keyed on the first encrypted write below them, stored through
   * `PUT /api/files/key`). Recursive, so a folder born in a plaintext tree
   * gains its whole chain on demand, and a folder inside a shared mount is
   * keyed from the envelope key I hold for that mount.
   */
  async function ensureChainKey(parentId) {
    if (parentId == null) return state.session.rootKey;
    const cached = folderKeys.get(parentId);
    if (cached) return cached;
    const info = await http("/api/files/info?id=" + parentId).then((r) => r.json());
    const folder = info.entry;
    if (!folder || !folder.is_dir) throw new Error("destination is not a folder");
    if (folder.enc_key) return await resolveFileKey(folder);
    // No record yet. Wrap the new one under its *parent's* key first, so the
    // chain above stays walkable for whoever opens below this folder later.
    const parentKey = await ensureChainKey(folder.parent_id);
    const folderKey = FX().randomBytes(32);
    const wrapped = await FX().wrapChildKey(parentKey, folder.id, folderKey);
    await http("/api/files/key", jsonCall("PUT", { id: folder.id, key: wrapped }));
    folderKeys.set(folder.id, folderKey);
    return folderKey;
  }

  /**
   * Store `entry`'s record wrapped under `parentId`'s key, keeping the raw
   * key itself untouched (5.4/5.5): what a grantee was sealed stays valid
   * across a re-bind, and what the owner holds keeps opening. `resolve`
   * supplies the raw key, because *where the record stands right now*
   * decides how it unwraps - a row about to move still unwraps under its
   * old parent, a row being prepared for a share unwraps through the trail.
   */
  async function bindRecordTo(entry, parentId, resolve) {
    const raw = await resolve();
    const parentKey = await ensureChainKey(parentId);
    const wrapped = await FX().wrapChildKey(parentKey, entry.id, raw);
    return await http("/api/files/key", jsonCall("PUT", { id: entry.id, key: wrapped })).then(
      (r) => r.json()
    );
  }

  /**
   * Re-bind a moved row's record to its destination (app.js calls this after
   * the move went through, with the folder the selection came from). The raw
   * key never changes, so envelopes stay sealed to the right value and only
   * the wrapper moves. Moving an encrypted row is a keyed operation in the
   * same sense opening one is: without keys there is nothing to re-bind.
   */
  async function rewrapForParent(entry, oldParentId, newParentId) {
    if (!entry.enc_key) return entry; // plaintext move: no record to re-bind
    const openRecord = async () => {
      try {
        return await resolveRecordUnder(entry, oldParentId);
      } catch (first) {
        // A previous re-bind half-landed: the record already names the
        // destination while the row still sits at its origin (or the other
        // way round after an undone move). The raw key is the same either
        // way, so accept whichever record opens rather than refusing to
        // touch a row this dialog itself got halfway into that state.
        try {
          return await resolveRecordUnder(entry, newParentId);
        } catch (_) {
          throw first;
        }
      }
    };
    const saved = await bindRecordTo(entry, newParentId, openRecord);
    return (saved && saved.entry) || entry;
  }

  /**
   * Key the subtree under `folderId` for a share (5.5): every encrypted
   * file's record re-bound to its parent folder's key, so a grantee walking
   * down from the mount unwraps each row with a record they were given
   * rather than with a root key they never had.
   *
   * Folders with nothing encrypted below them are left alone: they hold no
   * record, plaintext rows need none, and the folder gains its record on
   * the first encrypted write below it - which the grantee can do themselves
   * inside a shared subtree, because they hold every key in it.
   */
  async function keySubtree(folderId) {
    const list = await http("/api/files?parent=" + folderId).then((r) => r.json());
    for (const row of list.entries || []) {
      if (row.is_dir) {
        await keySubtree(row.id);
        continue;
      }
      if (row.enc_version === 0 || !row.enc_key) continue; // plaintext row
      // The record as it stands was wrapped where the file was born - the
      // root key for anything from before the hierarchy existed. Re-bind it
      // to the parent folder's key, which is what the mount's envelope
      // eventually leads a grantee to.
      await bindRecordTo(row, folderId, () => resolveFileKey(row));
    }
  }

  /**
   * Seal this source's key record to `grantee` (5.5) - the envelope half of
   * a share, and the only part the server ever sees of it.
   *
   * A folder's subtree is keyed first, so what the grantee unwraps at the
   * mount reaches every encrypted row below it - and keeps reaching new
   * ones, because every later encrypted write under that mount wraps to the
   * same folder key (5.5: "adding a file to an already shared folder"
   * costs exactly one wrap and knows nothing about who the grantees are).
   *
   * Returns null when there is nothing to seal: plaintext sources need no
   * exchange, and saying so keeps plaintext shares exactly as they were.
   */
  async function shareEnvelope(entry, granteeUsername, recipientPublicB64) {
    let raw;
    if (entry.is_dir) {
      await ensureChainKey(entry.id);
      await keySubtree(entry.id);
      raw = await resolveFileKey(entry);
    } else if (entry.enc_key) {
      raw = await resolveFileKey(entry);
    } else {
      return null;
    }
    const aad = FX().shareEnvelopeAad(entry.id, granteeUsername);
    return FX().eciesSeal(FX().b64decode(recipientPublicB64), raw, aad);
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
      // Wrapped under the *destination folder's* key and bound to this row
      // (5.2/5.4): the folder gains its record on the spot if it has none
      // yet, so the chain from my root - or from a share mount - down to
      // this file stays walkable for everyone who may open it later. The row
      // is ours by construction (create_file always mints under the
      // uploader's id), so nobody else has to be consulted.
      const parentKey = await ensureChainKey(parentId);
      const wrappedKey = await FX().wrapChildKey(parentKey, id, fileKey);
      const out = await heavy("encryptBytes", [id, fileKey, plain], [plain.buffer]);
      const saved = await http(
        "/api/files/content?id=" + id + "&enc=1&key=" + encodeURIComponent(wrappedKey),
        {
          method: "PUT",
          headers: { "Content-Type": "application/octet-stream" },
          body: out.bytes,
        }
      ).then((r) => r.json());
      // The row holds ciphertext and its wrapped key now. Hand back the
      // server's fresh copy rather than the row as it looked before the
      // write: the caller's own object has no `enc_key` and an
      // `enc_version` of 0, so downloading straight after an upload would
      // try to unwrap a key the row does not carry.
      return (saved && saved.entry) || created.entry;
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
    const fileKey = await resolveFileKey(entry);
    const out = await heavy("decryptBytes", [entry.id, fileKey, body], [body.buffer]);
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

  /**
   * Fetch, decrypt and hand back the plaintext as a Blob - the phase 2
   * preview (ENCRYPTION.md 12): images, video, audio, PDF and HTML open in
   * the lightbox instead of being refused. The walk is `download`'s - the
   * container comes from the download endpoint (the only route that serves
   * ciphertext), the row key resolves, the worker decrypts - and only the
   * last step differs: the bytes stay in memory for a renderer instead of
   * being saved under a name, so the MIME type is mimeForPreview's (the
   * real, renderable type - an HTML preview must reach the frame as HTML
   * and be sandboxed there, not forced to octet-stream by the download map).
   * The caller owns the object URL and its lifetime.
   */
  async function previewBlob(entry) {
    if (state.status !== "unlocked") throw new Error("unlock encryption to preview this file");
    const res = await http("/api/files/download?id=" + entry.id);
    const body = new Uint8Array(await res.arrayBuffer());
    const fileKey = await resolveFileKey(entry);
    const out = await heavy("decryptBytes", [entry.id, fileKey, body], [body.buffer]);
    return new Blob([out.bytes], { type: FX().mimeForPreview(entry.name) });
  }

  /**
   * Read an encrypted row back as text for the editor.
   *
   * `/api/files/preview` refuses ciphertext outright - it has no plaintext
   * to describe - and `/api/files/content` is PUT-only (the editor's write
   * side), so the read side goes through the download endpoint and turns the
   * FXE1 container back into text here.
   */
  async function readText(entry) {
    if (state.status !== "unlocked") throw new Error("unlock encryption to open this file");
    if (!entry.enc_key) throw new Error("this file has no stored key to open it with");
    const res = await http("/api/files/download?id=" + entry.id);
    const body = new Uint8Array(await res.arrayBuffer());
    const fileKey = await resolveFileKey(entry);
    const out = await heavy("decryptBytes", [entry.id, fileKey, body], [body.buffer]);
    return new TextDecoder().decode(out.bytes);
  }

  /**
   * Encrypt text and store it as this row's content in one request.
   *
   * A row that already has a record keeps its key (DECISION 5: no rotation
   * on overwrite) and sends the stored wrapper back verbatim - which is also
   * what makes a share's UPDATE grantee safe here: they re-encrypt with the
   * key the envelope gave them, and the owner's wrapper, which they cannot
   * produce, never changes (5.5). Only a plaintext row gains a record, and
   * that one is wrapped under its folder's key so the chain below the
   * folder stays walkable.
   */
  async function writeText(entry, text) {
    if (state.status !== "unlocked") throw new Error("unlock encryption to save this file");
    const plain = new TextEncoder().encode(text);
    let fileKey;
    let wrappedKey;
    if (entry.enc_key) {
      fileKey = await resolveFileKey(entry);
      wrappedKey = entry.enc_key;
    } else {
      fileKey = FX().randomBytes(32);
      const parentKey = await ensureChainKey(entry.parent_id);
      wrappedKey = await FX().wrapChildKey(parentKey, entry.id, fileKey);
    }
    const out = await heavy("encryptBytes", [entry.id, fileKey, plain], [plain.buffer]);
    const res = await http(
      "/api/files/content?id=" + entry.id + "&enc=1&key=" + encodeURIComponent(wrappedKey),
      {
        method: "PUT",
        headers: { "Content-Type": "application/octet-stream" },
        body: out.bytes,
      }
    );
    return (await res.json()).entry;
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
    enterTo("enc-setup-pass", "enc-setup-go");
    enterTo("enc-setup-pass2", "enc-setup-go");
    enterTo("enc-unlock-pass", "enc-unlock-go");
    enterTo("enc-rcv-pass2", "enc-rcv-go");

    // The setup button arms on whichever fields are actually showing: one in
    // the default login mode, both once a separate passphrase is chosen.
    const armSetup = () => {
      const go = $("enc-setup-go");
      if (!go) return;
      const reuseLogin = $("enc-use-login").checked;
      const pass = $("enc-setup-pass").value;
      go.disabled = !pass || (!reuseLogin && pass !== $("enc-setup-pass2").value);
    };

    // DECISION 3: "reuse login password" is pre-selected, the separate
    // passphrase one click away. The choice changes more than a label - the
    // default mode sends the string to the server once for verification,
    // while a separate passphrase never leaves this browser - so the wording
    // and the autofill hint have to follow it.
    const syncSecretMode = () => {
      const reuseLogin = $("enc-use-login").checked;
      $("enc-setup-pass-label").textContent = reuseLogin
        ? "Your fxcloud login password"
        : "Storage passphrase";
      $("enc-setup-pass").setAttribute(
        "autocomplete",
        reuseLogin ? "current-password" : "new-password"
      );
      $("enc-setup-row2").style.display = reuseLogin ? "none" : "";
      $("enc-setup-hint").textContent = reuseLogin
        ? "Signing in already makes the server spend a 64 MiB Argon2id hash, " +
          "so one strong password can cover both. Your browser can fill this " +
          "from the password you signed in with, and it is checked against " +
          "your account before any key is created."
        : "A separate passphrase is never sent anywhere; only the 64 MiB " +
          "Argon2id derivation runs here. It is one more secret to keep: " +
          "without it your files cannot be opened again.";
      for (const id of ["enc-use-login", "enc-use-pass"]) {
        const el = $(id);
        const wrap = el && el.closest ? el.closest(".enc-option") : null;
        if (wrap) wrap.classList.toggle("is-on", el.checked);
      }
      armSetup();
    };
    for (const id of ["enc-use-login", "enc-use-pass"]) {
      const el = $(id);
      if (el) el.addEventListener("change", syncSecretMode);
    }
    syncSecretMode();
    for (const id of ["enc-setup-pass", "enc-setup-pass2"]) {
      const el = $(id);
      if (el) el.addEventListener("input", armSetup);
    }
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
  // Passphrase enrollment (settings dialog, README "passphrase sign-in")
  //
  // The passphrase is two things at once: the credential POST /api/login
  // accepts with mode "passphrase", and the secret the key row is wrapped
  // under (kdf_params.secret = "separate"). Both halves change here, always
  // in the same order - the server endpoint first, because it validates the
  // current password: a mistyped proof then costs one request and touches
  // nothing, while the reverse order could wrap the keys under a passphrase
  // the server refuses at sign-in. The re-wrap runs second and can fail on
  // its own; nothing is lost when it does (the row keeps its old secret),
  // the message says which half succeeded, and both halves can be repeated
  // until they agree.
  // ------------------------------------------------------------------------

  /**
   * PUT/DELETE the passphrase credential without http().
   *
   * Deliberately a raw fetch, for the reason verifyLogin is one: these
   * endpoints answer 401 for "that password is wrong", and http() reads
   * every 401 as a dead session, redirecting to /login over a mere typo.
   *
   * @param {string} method - "PUT" to set, "DELETE" to remove.
   * @param {Object} payload - { current_password, passphrase? }.
   * @returns {Promise<Error|null>} null on success, the problem otherwise.
   */
  async function callPassphraseApi(method, payload) {
    const res = await fetch("/api/me/passphrase", {
      method: method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (res.ok) return null;
    if (res.status === 401) return new Error("That is not your current password.");
    let msg = "Request failed (" + res.status + ")";
    try {
      const b = await res.json();
      if (b && b.error) msg = b.error;
    } catch (_) {
      /* not JSON; keep the status line */
    }
    return new Error(msg);
  }

  /**
   * Set (or replace) the sign-in passphrase from the settings dialog.
   *
   * Accounts without a key row get one right here - the passphrase is the
   * secret it will be wrapped under, so enrolling it *is* turning
   * encryption on; the recovery pane then opens as it does at any other
   * setup. Accounts with a row are re-wrapped, which needs the ARK and
   * therefore an unlocked tab: a locked one gets the unlock pane through
   * requestKeys(), the same wait an encrypted download makes.
   *
   * @param {string} passphrase - 16+ characters, exactly as typed.
   * @param {string} currentPassword - the proof for the server endpoint.
   * @returns {Promise<{ok: boolean, message: string}>}
   */
  async function enrollPassphrase(passphrase, currentPassword) {
    if (state.status === "unsupported") {
      return {
        ok: false,
        credentialSet: false,
        message: "This browser has no WebCrypto, so a passphrase cannot wrap your files.",
      };
    }
    if (typeof passphrase !== "string" || passphrase.length < 16) {
      return {
        ok: false,
        credentialSet: false,
        message: "A passphrase needs at least 16 characters.",
      };
    }
    if (!currentPassword) {
      return { ok: false, credentialSet: false, message: "Enter your current password to confirm." };
    }
    const credErr = await callPassphraseApi("PUT", {
      current_password: currentPassword,
      passphrase: passphrase,
    });
    if (credErr) return { ok: false, credentialSet: false, message: credErr.message };

    let created = false;
    try {
      if (state.keys) {
        if (state.status !== "unlocked") {
          const ok = await requestKeys();
          if (!ok) {
            return {
              ok: false,
              credentialSet: true,
              message:
                "Passphrase saved for sign-in. Unlock your files once, then set it " +
                "again so they are wrapped under it.",
            };
          }
        }
        const rewrap = await FX().rewrapAccount(state.session.ark, passphrase, derive);
        rewrap.kdf_params = Object.assign({}, rewrap.kdf_params, { secret: "separate" });
        await http("/api/keys/me", jsonCall("PUT", rewrap));
        adoptKeys(Object.assign({}, state.keys, rewrap), "unlocked");
        await refreshShareKeys();
      } else {
        created = true;
        const account = await FX().generateAccount(passphrase, derive);
        account.payload.kdf_params = Object.assign({}, account.payload.kdf_params, {
          secret: "separate",
        });
        const body = await http("/api/keys/setup", jsonCall("POST", account.payload)).then((r) =>
          r.json()
        );
        // The recovery pane has to be answered before anything else, so the
        // settings dialog behind it would only be in the way.
        const settings = document.getElementById("settings-modal");
        if (settings) settings.style.display = "none";
        await publishAccount(account, body.keys);
      }
    } catch (e) {
      return {
        ok: false,
        credentialSet: true,
        message:
          (created
            ? "Passphrase saved for sign-in, but creating your file keys failed: "
            : "Passphrase saved for sign-in, but re-wrapping your files failed: ") +
          e.message +
          " Your previous secret still unlocks them.",
      };
    }
    return {
      ok: true,
      credentialSet: true,
      message: created
        ? "Passphrase set. Save your recovery key."
        : "Passphrase set. You can now sign in with it.",
    };
  }

  /**
   * Remove the sign-in passphrase and move the key row back under the
   * password that stays.
   *
   * The proof doubles as the secret to re-wrap with: the DELETE just had
   * the server check it against password_hash, which is exactly the
   * condition under which `kdf_params.secret: "login"` may be claimed - the
   * rule setup and recovery follow. Unlocking first needs the passphrase
   * itself (it still opens the row), which the person removing it knows.
   *
   * @param {string} currentPassword - the password that remains.
   * @returns {Promise<{ok: boolean, message: string}>}
   */
  async function removePassphrase(currentPassword) {
    if (!currentPassword) {
      return { ok: false, credentialRemoved: false, message: "Enter your current password to confirm." };
    }
    const credErr = await callPassphraseApi("DELETE", { current_password: currentPassword });
    if (credErr) return { ok: false, credentialRemoved: false, message: credErr.message };

    if (!state.keys) {
      return { ok: true, credentialRemoved: true, message: "Passphrase removed." };
    }

    try {
      if (state.status !== "unlocked") {
        const ok = await requestKeys();
        if (!ok) {
          return {
            ok: false,
            credentialRemoved: true,
            message:
              "Passphrase removed from sign-in. Unlock your files once, then remove it " +
              "again so they are wrapped back under your password.",
          };
        }
      }
      const rewrap = await FX().rewrapAccount(state.session.ark, currentPassword, derive);
      rewrap.kdf_params = Object.assign({}, rewrap.kdf_params, { secret: "login" });
      await http("/api/keys/me", jsonCall("PUT", rewrap));
      adoptKeys(Object.assign({}, state.keys, rewrap), "unlocked");
      await refreshShareKeys();
    } catch (e) {
      return {
        ok: false,
        credentialRemoved: true,
        message:
          "Passphrase removed from sign-in, but re-wrapping under your password failed: " +
          e.message +
          " Unlock with your passphrase and try again.",
      };
    }
    return {
      ok: true,
      credentialRemoved: true,
      message: "Passphrase removed. Your files are wrapped under your password again.",
    };
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
    readText: readText,
    writeText: writeText,
    download: download,
    previewBlob: previewBlob,
    // passphrase sign-in (README): the settings dialog drives these; each one
    // moves the server credential and the key row's wrapping in one flow
    enrollPassphrase: enrollPassphrase,
    removePassphrase: removePassphrase,
    // key hierarchy + sharing (5.2 / 5.5), used by the share dialog and the
    // move path in app.js
    shareEnvelope: shareEnvelope,
    rewrapForParent: rewrapForParent,
    formatFingerprint: (hex) => FX().formatFingerprint(hex),
    lockNow: lockNow,
    isEncrypted: (entry) => !!entry && entry.enc_version > 0,
  };
})();
