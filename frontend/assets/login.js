(function () {
  "use strict";

  const tabLogin = document.getElementById("tab-login");
  const tabRegister = document.getElementById("tab-register");
  const tabPasskey = document.getElementById("tab-passkey");
  const form = document.getElementById("auth-form");
  const errorBox = document.getElementById("error");
  const submitBtn = document.getElementById("submit-btn");
  const displayField = document.getElementById("display-field");
  const displayInput = document.getElementById("display_name");
  const passkeyForm = document.getElementById("passkey-form");
  const passkeyBtn = document.getElementById("passkey-btn");

  // The dictionary lives in i18n.js, which the page loads before this file.
  // A function declaration, so call sites pass one or two arguments.
  function t(key, params) {
    return globalThis.I18N ? globalThis.I18N.t(key, params) : key;
  }

  /**
   * Turn an error body into a message in the selected language. The server
   * sends a stable `code` (src/error.rs) beside the English text; a code
   * this build does not know yet falls back to that text.
   */
  function errMessage(status, body) {
    if (body && body.code && t("err." + body.code) !== "err." + body.code) {
      return t("err." + body.code, {
        used: body.used != null ? String(body.used) : "",
        quota: body.quota != null ? String(body.quota) : "",
        seconds: body.retry_after != null ? String(body.retry_after) : "",
      });
    }
    return body && body.error ? body.error : null;
  }

  let mode = "login"; // or "register" or "passkey"

  function setMode(next) {
    mode = next;
    const isRegister = mode === "register";
    const isPasskey = mode === "passkey";
    tabLogin.classList.toggle("active", mode === "login");
    tabRegister.classList.toggle("active", isRegister);
    tabPasskey.classList.toggle("active", isPasskey);
    displayField.style.display = isRegister ? "block" : "none";
    displayInput.required = false;
    submitBtn.textContent = isRegister ? t("login.tab.register") : t("login.tab.signin");
    form.password.autocomplete = isRegister ? "new-password" : "current-password";
    // The passkey tab is its own form: the password field's `required`
    // must not block a sign-in that never types one.
    form.style.display = isPasskey ? "none" : "";
    passkeyForm.style.display = isPasskey ? "" : "none";
    hideError();
  }

  function showMessage(message, kind) {
    errorBox.textContent = message;
    errorBox.classList.toggle("success", kind === "success");
    errorBox.style.display = "block";
  }
  function showError(message) {
    showMessage(message, "error");
  }
  function hideError() {
    errorBox.style.display = "none";
    errorBox.classList.remove("success");
  }

  /**
   * Carry the password that just signed the user in across the page load.
   *
   * Sign-in and the app are two documents, so nothing in memory survives the
   * redirect below - without this the encryption pane asks for the very
   * string typed a moment ago, whenever the account's keys are wrapped under
   * the login password (ENCRYPTION.md 5.7, the DECISION 3 default).
   *
   * It is written only when the stored key row says the row is wrapped under
   * the login password, it lives in sessionStorage for the length of one
   * navigation, and fxenc.js deletes it on its first read - so a reload, a
   * second tab or a restored one asks again (DECISION 7). A separate
   * passphrase is never carried: this page does not know it. Any failure
   * costs the handoff only; the pane is the fallback, not an error.
   */
  async function carrySecretAcrossRedirect(password) {
    try {
      const ctrl = typeof AbortController === "function" ? new AbortController() : null;
      const timer = ctrl ? setTimeout(() => ctrl.abort(), 3000) : null;
      // The session cookie from the sign-in above travels with this request.
      const res = await fetch("/api/keys/me", ctrl ? { signal: ctrl.signal } : {});
      if (timer) clearTimeout(timer);
      if (!res.ok) return; // no key row: nothing is wrapped under anything
      const body = await res.json();
      const params = (body.keys && body.keys.kdf_params) || {};
      if (params.secret === "separate") return;
      sessionStorage.setItem(
        "fxcloud.handoff",
        JSON.stringify({ password: password, at: Date.now() })
      );
    } catch (_) {
      /* no handoff - the pane asks, exactly as it did before this existed */
    }
  }

  function setLoading(loading) {
    if (loading) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="spinner"></span>' + t("login.wait");
    } else {
      submitBtn.disabled = false;
      submitBtn.textContent = mode === "register" ? t("login.tab.register") : t("login.tab.signin");
    }
  }

  tabLogin.addEventListener("click", () => setMode("login"));
  tabRegister.addEventListener("click", () => setMode("register"));
  tabPasskey.addEventListener("click", () => setMode("passkey"));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideError();
    setLoading(true);

    const payload = {
      username: form.username.value.trim(),
      password: form.password.value,
    };
    if (mode === "register" && displayInput.value.trim()) {
      payload.display_name = displayInput.value.trim();
    }

    const endpoint = mode === "register" ? "/api/register" : "/api/login";

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        let message = t("login.err.generic");
        try {
          const body = await res.json();
          message = errMessage(res.status, body) || message;
        } catch (_) {}
        // Friendly fallbacks for common failures.
        if (res.status === 401) message = t("login.err.invalid");
        showError(message);
        return;
      }

      let body = null;
      try {
        body = await res.json();
      } catch (_) {}

      // The account was created but is still inactive: no session was issued,
      // so explain the situation instead of pretending the user is signed in.
      if (body && body.pending_activation) {
        setMode("login");
        showMessage(t("login.err.inactive"), "success");
        return;
      }

      // Success – the session cookie is set; go to the app. The handoff has
      // to be written while this document still exists.
      await carrySecretAcrossRedirect(form.password.value);
      window.location.href = "/";
    } catch (err) {
      showError(t("login.err.network"));
    } finally {
      setLoading(false);
    }
  });

  function setPasskeyLoading(loading) {
    passkeyBtn.disabled = loading;
    passkeyBtn.innerHTML = loading
      ? '<span class="spinner"></span>' + t("login.waiting")
      : t("login.passkeyBtn");
  }

  /**
   * Username-first passkey sign-in: challenge for the name, the browser's
   * credential prompt, then the assertion back to the server. The start
   * response is identical for unknown names and accounts without passkeys,
   * and the failure the user sees is too - this page must not turn into an
   * account-existence oracle either.
   */
  passkeyForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideError();

    if (
      !window.isSecureContext ||
      !navigator.credentials ||
      !navigator.credentials.get
    ) {
      showError(t("login.err.https"));
      return;
    }
    const username = passkeyForm.username.value.trim();
    if (!username) {
      showError(t("login.err.needUser"));
      return;
    }

    setPasskeyLoading(true);
    try {
      const startRes = await fetch("/api/passkeys/login/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username }),
      });
      if (!startRes.ok) {
        let message = t("login.err.startFail");
        try {
          const body = await startRes.json();
          message = errMessage(startRes.status, body) || message;
        } catch (_) {}
        showError(message);
        return;
      }
      const options = await startRes.json();

      let cred = null;
      try {
        cred = await navigator.credentials.get({
          publicKey: FxWebAuthn.assertionOptions(options),
        });
      } catch (err) {
        showError(
          err.name === "NotAllowedError"
            ? t("login.err.noPasskeyUsed")
            : t("login.err.passkeyFail", { msg: err.message })
        );
        return;
      }
      if (!cred) {
        showError(t("login.err.noPasskey"));
        return;
      }

      const finishRes = await fetch("/api/passkeys/login/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: FxWebAuthn.credentialToJson(cred, "assert") }),
      });
      if (!finishRes.ok) {
        let message = t("login.err.finishFail");
        try {
          const body = await finishRes.json();
          message = errMessage(finishRes.status, body) || message;
        } catch (_) {}
        if (finishRes.status === 401) message = t("login.err.unknown");
        showError(message);
        return;
      }

      // Signed in - the session cookie is set. There is no typed password
      // to carry across the redirect, so the encryption pane simply asks
      // for the storage passphrase when it needs one (it always was the
      // fallback, ENCRYPTION.md DECISION 7).
      window.location.href = "/";
    } catch (_) {
      showError(t("login.err.network"));
    } finally {
      setPasskeyLoading(false);
    }
  });
})();
