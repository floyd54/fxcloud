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
    submitBtn.textContent = isRegister ? "Create account" : "Sign in";
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
      submitBtn.innerHTML = '<span class="spinner"></span>Please wait…';
    } else {
      submitBtn.disabled = false;
      submitBtn.textContent = mode === "register" ? "Create account" : "Sign in";
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
        let message = "Something went wrong.";
        try {
          const body = await res.json();
          if (body.error) message = body.error;
        } catch (_) {}
        // Friendly fallbacks for common failures.
        if (res.status === 401) message = "Invalid username or password.";
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
        showMessage(
          "Account created. It has to be activated before you can sign in – please contact your administrator.",
          "success"
        );
        return;
      }

      // Success – the session cookie is set; go to the app. The handoff has
      // to be written while this document still exists.
      await carrySecretAcrossRedirect(form.password.value);
      window.location.href = "/";
    } catch (err) {
      showError("Network error. Is the server running?");
    } finally {
      setLoading(false);
    }
  });

  function setPasskeyLoading(loading) {
    passkeyBtn.disabled = loading;
    passkeyBtn.innerHTML = loading
      ? '<span class="spinner"></span>Waiting for your device...'
      : "Sign in with passkey";
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
      showError("This browser cannot use passkeys here - open the site over HTTPS (or on localhost).");
      return;
    }
    const username = passkeyForm.username.value.trim();
    if (!username) {
      showError("Enter your username.");
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
        let message = "Could not start the passkey sign-in.";
        try {
          const body = await startRes.json();
          if (body.error) message = body.error;
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
            ? "No passkey was used - the prompt was cancelled, timed out, or this account has none on this device."
            : "Passkey sign-in failed: " + err.message
        );
        return;
      }
      if (!cred) {
        showError("No passkey was used.");
        return;
      }

      const finishRes = await fetch("/api/passkeys/login/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: FxWebAuthn.credentialToJson(cred, "assert") }),
      });
      if (!finishRes.ok) {
        let message = "Passkey sign-in failed.";
        try {
          const body = await finishRes.json();
          if (body.error) message = body.error;
        } catch (_) {}
        if (finishRes.status === 401) message = "Unknown user or no matching passkey.";
        showError(message);
        return;
      }

      // Signed in - the session cookie is set. There is no typed password
      // to carry across the redirect, so the encryption pane simply asks
      // for the storage passphrase when it needs one (it always was the
      // fallback, ENCRYPTION.md DECISION 7).
      window.location.href = "/";
    } catch (_) {
      showError("Network error. Is the server running?");
    } finally {
      setPasskeyLoading(false);
    }
  });
})();
