(function () {
  "use strict";

  const tabLogin = document.getElementById("tab-login");
  const tabRegister = document.getElementById("tab-register");
  const form = document.getElementById("auth-form");
  const errorBox = document.getElementById("error");
  const submitBtn = document.getElementById("submit-btn");
  const displayField = document.getElementById("display-field");
  const displayInput = document.getElementById("display_name");

  let mode = "login"; // or "register"

  function setMode(next) {
    mode = next;
    const isRegister = mode === "register";
    tabLogin.classList.toggle("active", !isRegister);
    tabRegister.classList.toggle("active", isRegister);
    displayField.style.display = isRegister ? "block" : "none";
    displayInput.required = false;
    submitBtn.textContent = isRegister ? "Create account" : "Sign in";
    form.password.autocomplete = isRegister ? "new-password" : "current-password";
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
})();
