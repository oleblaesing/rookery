import {
  exportSessionKey,
  unlockPrivateKey,
  signChallenge,
} from "../crypto.js";

(function () {
  "use strict";

  if (location.pathname !== "/settings") {
    return;
  }

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
      return;
    }

    document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    const form = document.getElementById("export-form");
    const btn = document.getElementById("export-btn");
    const input = document.getElementById("export-passphrase");
    const confirm = document.getElementById("export-passphrase-confirm");
    const errorEl = document.getElementById("export-error");

    if (!form || !input || !confirm) {
      return;
    }

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.style.display = "";
    }

    function clearError() {
      errorEl.textContent = "";
      errorEl.style.display = "none";
    }

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      clearError();

      const passphrase = input.value;

      if (passphrase !== confirm.value) {
        showError("Passphrases do not match.");
        confirm.focus();

        return;
      }

      btn.disabled = true;
      btn.textContent = "exporting…";

      try {
        const { armoredKey, fingerprint } = await exportSessionKey(passphrase);

        const blob = new Blob([armoredKey], { type: "application/pgp-keys" });
        const url = URL.createObjectURL(blob);
        const suffix = fingerprint
          ? fingerprint.slice(-8).toLowerCase()
          : "key";

        const a = document.createElement("a");
        a.href = url;
        a.download = "rookery-recovery-" + suffix + ".asc";
        a.style.display = "none";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        input.value = "";
        confirm.value = "";
      } catch (err) {
        showError("Export failed: " + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = "export recovery file";
      }
    });
  });
})();

(function () {
  "use strict";

  if (location.pathname !== "/settings") {
    return;
  }

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
      return;
    }

    document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    const form = document.getElementById("delete-account-form");
    const btn = document.getElementById("delete-account-btn");
    const errorEl = document.getElementById("delete-account-error");

    if (!form) {
      return;
    }

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.style.display = "";
    }

    function clearError() {
      errorEl.textContent = "";
      errorEl.style.display = "none";
    }

    function csrfToken() {
      const meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.getAttribute("content") : "";
    }

    function setBusy(label) {
      btn.disabled = true;
      btn.textContent = label;
    }

    function setReady() {
      btn.disabled = false;
      btn.textContent = "delete account";
    }

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      clearError();

      const confirmAddress = form
        .querySelector('[name="confirm_address"]')
        .value.trim()
        .toLowerCase();
      const passphrase = form.querySelector('[name="passphrase"]').value;
      const fileInput = form.querySelector('[name="recovery_file"]');

      // The server also enforces this; the client check is just for fast feedback.
      const expectedAddress = form
        .querySelector('[name="confirm_address"]')
        .placeholder.toLowerCase();

      if (confirmAddress !== expectedAddress) {
        showError("Typed address does not match your primary address.");

        return;
      }

      if (!fileInput.files.length) {
        showError("Select your recovery file (.asc).");

        return;
      }

      setBusy("unlocking key…");

      let privateKey;
      try {
        const armoredKey = await fileInput.files[0].text();
        privateKey = await unlockPrivateKey(armoredKey, passphrase);
      } catch {
        showError(
          "Could not unlock the recovery file — wrong passphrase or invalid file.",
        );
        setReady();

        return;
      }

      setBusy("requesting challenge…");

      let challengeID, nonce;
      try {
        const resp = await fetch("/api/v1/users/me/deletion/challenge", {
          method: "POST",
          headers: { "X-CSRF-Token": csrfToken() },
          credentials: "same-origin",
        });
        const body = await resp.json();

        if (!resp.ok) {
          showError(body.message || "Could not obtain deletion challenge.");
          setReady();

          return;
        }

        challengeID = body.challenge_id;
        nonce = body.nonce;
      } catch {
        showError(
          "Could not reach the server. Check your connection and try again.",
        );
        setReady();

        return;
      }

      setBusy("signing challenge…");

      let signedChallenge;
      try {
        signedChallenge = await signChallenge(privateKey, nonce);
      } catch (err) {
        showError("Signing failed: " + err.message);
        setReady();

        return;
      }

      setBusy("deleting account…");

      try {
        const resp = await fetch("/api/v1/users/me/deletion", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken(),
          },
          body: JSON.stringify({
            challenge_id: challengeID,
            signed_challenge: signedChallenge,
            confirm_address: confirmAddress,
          }),
          credentials: "same-origin",
        });
        const body = await resp.json();

        if (!resp.ok) {
          showError(body.message || "Account deletion failed.");
          setReady();

          return;
        }
      } catch {
        showError(
          "Could not reach the server. Check your connection and try again.",
        );
        setReady();

        return;
      }

      // Server has already destroyed the session row; drop the local key cache too.
      try {
        localStorage.removeItem("rookery_session_key");
        localStorage.removeItem("rookery_session_key_wrap");
        localStorage.removeItem("rookery_session_key_fp");
      } catch {
        /* localStorage may be unavailable; deletion already succeeded */
      }

      window.location.href = "/login?deleted=1";
    });
  });
})();

(function () {
  "use strict";

  if (location.pathname !== "/settings") {
    return;
  }

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
      return;
    }

    document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    const form = document.getElementById("export-archive-form");
    const btn = document.getElementById("export-archive-btn");
    const statusEl = document.getElementById("export-archive-status");
    const newInstance = document.getElementById("export-new-instance");

    if (!form || !btn) {
      return;
    }

    function csrfToken() {
      const meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.getAttribute("content") : "";
    }

    function setStatus(msg) {
      statusEl.textContent = msg;
      statusEl.style.display = "";
    }

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      btn.disabled = true;

      try {
        const body =
          newInstance && newInstance.value.trim()
            ? JSON.stringify({ new_instance: newInstance.value.trim() })
            : null;
        const resp = await fetch("/api/v1/users/me/export", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken(),
          },
          body,
          credentials: "same-origin",
        });

        if (!resp.ok) {
          const data = await resp.json().catch(function () {
            return {};
          });
          setStatus(
            "Could not start export: " +
              ((data.error && data.error.message) || "unknown error"),
          );
        } else {
          setStatus(
            "Export started. You will receive an inbox message when the archive is ready.",
          );
        }
      } catch {
        setStatus("Could not reach the server.");
        btn.disabled = false;
      }
    });
  });
})();
