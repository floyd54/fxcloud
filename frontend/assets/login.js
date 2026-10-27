(function () {
  "use strict";

  const tabLogin = document.getElementById("tab-login");
  const tabRegister = document.getElementById("tab-register");
  const form = document.getElementById("auth-form");
  const errorBox = document.getElementById("error");
  const submitBtn = document.getElementById("submit-btn");
  const displayField = document.getElementById("display-field");
  const displayInput = document.getElementById("display_name");
  const credTabs = document.getElementById("cred-tabs");
  const credPassword = document.getElementById("cred-password");
  const credPassphrase = document.getElementById("cred-passphrase");
  const passwordLabel = document.getElementById("password-label");
  const authHint = document.getElementById("auth-hint");
  const regPassField = document.getElementById("reg-pass-field");
  const regPass2Field = document.getElementById("reg-pass2-field");
  const regPass = document.getElementById("reg-passphrase");
  const regPass2 = document.getElementById("reg-passphrase2");

  let mode = "login"; // or "register"
  let credential = "password"; // or "passphrase" (sign-in tab only)

  // Shown under the secret fields. The example is a real Diceware-style
  // phrase: five hyphen-separated words clear the 16-character floor with
  // room, which is the point of the higher bar for this credential.
  const HINT_PASSPHRASE =
    "A passphrase is at least 16 characters and signs you in instead of your " +
    "password. A few random words work well: orbit-cabin-drift-velvet-meadow";
  const HINT_REGISTER =
    "Optional: a 16+ character passphrase signs you in and unlocks your files. " +
    "A few random words work well: orbit-cabin-drift-velvet-meadow. " +
    "Leave both fields blank to sign in with your password only.";

  // One place that owns the label, the browser-enforced floor and the hint,
  // so the three inputs can never disagree with the server about which
  // credential is being collected (8 for the password, 16 for a passphrase).
  function syncAuthRules() {
    const isRegister = mode === "register";
    const passphraseLogin = !isRegister && credential === "passphrase";
    form.password.minLength = passphraseLogin ? 16 : 8;
    passwordLabel.textContent = passphraseLogin ? "Passphrase" : "Password";
    if (isRegister) {
      authHint.textContent = HINT_REGISTER;
      authHint.style.display = "block";
    } else if (passphraseLogin) {
      authHint.textContent = HINT_PASSPHRASE;
      authHint.style.display = "block";
    } else {
      authHint.style.display = "none";
    }
  }

  function setMode(next) {
    mode = next;
    const isRegister = mode === "register";
    tabLogin.classList.toggle("active", !isRegister);
    tabRegister.classList.toggle("active", isRegister);
    displayField.style.display = isRegister ? "block" : "none";
    displayInput.required = false;
    submitBtn.textContent = isRegister ? "Create account" : "Sign in";
    form.password.autocomplete = isRegister ? "new-password" : "current-password";
    // The credential choice belongs to signing in; registering collects the
    // password and the optional passphrase side by side instead.
    credTabs.style.display = isRegister ? "none" : "block";
    regPassField.style.display = isRegister ? "block" : "none";
    regPass2Field.style.display = isRegister ? "block" : "none";
    if (isRegister) {
      regPass.value = "";
      regPass2.value = "";
    }
    syncAuthRules();
    hideError();
  }

  function setCredential(next) {
    if (next === credential) return;
    credential = next;
    // Never let a value typed for one credential be submitted as the other.
    form.password.value = "";
    credPassword.classList.toggle("active", next === "password");
    credPassphrase.classList.toggle("active", next === "passphrase");
    syncAuthRules();
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
   * Carry the secret that just signed the user in across the page load.
   *
   * Sign-in and the app are two documents, so nothing in memory survives the
   * redirect below - without this the encryption pane asks for the very
   * string typed a moment ago.
   *
   * What gets parked has to be the secret the stored key row is actually
   * wrapped under: `kind` is "password" for a `secret: login` row (the
   * DECISION 3 default) and "passphrase" for a `separate` one, and a value
   * whose kind does not match the row is dropped instead of tried. The one
   * case that parks without a row is registering with a passphrase
   * (`allowNoRow`): the account has no keys yet, and fxenc.js creates them
   * from this value on the next page.
   *
   * It lives in sessionStorage for the length of one navigation and fxenc.js
   * deletes it on its first read - so a reload, a second tab or a restored
   * one asks again (DECISION 7). Any failure costs the handoff only; the
   * pane is the fallback, not an error.
   */
  async function carrySecretAcrossRedirect(secret, kind, allowNoRow) {
    try {
      const ctrl = typeof AbortController === "function" ? new AbortController() : null;
      const timer = ctrl ? setTimeout(() => ctrl.abort(), 3000) : null;
      // The session cookie from the sign-in above travels with this request.
      const res = await fetch("/api/keys/me", ctrl ? { signal: ctrl.signal } : {});
      if (timer) clearTimeout(timer);
      if (!res.ok) {
        // No key row yet is the normal state right after registering with a
        // passphrase, and only for that case is the value worth keeping.
        if (res.status === 404 && allowNoRow) {
          sessionStorage.setItem(
            "fxcloud.handoff",
            JSON.stringify({ password: secret, kind: kind, at: Date.now() })
          );
        }
        return;
      }
      const body = await res.json();
      const params = (body.keys && body.keys.kdf_params) || {};
      const rowKind = params.secret === "separate" ? "passphrase" : "password";
      if (rowKind !== kind) return; // the row is not wrapped under this
      sessionStorage.setItem(
        "fxcloud.handoff",
        JSON.stringify({ password: secret, kind: kind, at: Date.now() })
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
  credPassword.addEventListener("click", () => setCredential("password"));
  credPassphrase.addEventListener("click", () => setCredential("passphrase"));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideError();

    const payload = {
      username: form.username.value.trim(),
      password: form.password.value,
    };
    if (mode === "register") {
      if (displayInput.value.trim()) payload.display_name = displayInput.value.trim();
      // Optional, and only ever sent exactly as typed: the server floors a
      // provided passphrase at 16 characters and no length check here may
      // trim a secret the user is about to rely on twice.
      const passphrase = regPass.value;
      if (passphrase) {
        if (passphrase !== regPass2.value) {
          showError("The two passphrases do not match.");
          return;
        }
        payload.passphrase = passphrase;
      }
    } else if (credential === "passphrase") {
      payload.mode = "passphrase";
    }

    setLoading(true);

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
        // Friendly fallbacks for common failures. Both credentials answer
        // 401, so say which one was being tried - never which exists.
        if (res.status === 401) {
          message =
            mode === "login" && credential === "passphrase"
              ? "Invalid username or passphrase."
              : "Invalid username or password.";
        }
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
      if (mode === "register") {
        // Only a passphrase is worth carrying: an account that registered
        // without one has no keys either, and the pane sets those up.
        if (payload.passphrase) {
          await carrySecretAcrossRedirect(payload.passphrase, "passphrase", true);
        }
      } else {
        await carrySecretAcrossRedirect(form.password.value, credential, false);
      }
      window.location.href = "/";
    } catch (err) {
      showError("Network error. Is the server running?");
    } finally {
      setLoading(false);
    }
  });
})();
