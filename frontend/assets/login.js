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

  function showError(message) {
    errorBox.textContent = message;
    errorBox.style.display = "block";
  }
  function hideError() {
    errorBox.style.display = "none";
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

      // Success – the session cookie is set; go to the app.
      window.location.href = "/";
    } catch (err) {
      showError("Network error. Is the server running?");
    } finally {
      setLoading(false);
    }
  });
})();
