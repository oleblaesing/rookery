import { generateKeypair, readPrivateKey, storeSessionKey } from "../crypto.js";

(function () {
  "use strict";

  if (!location.pathname.startsWith("/invite/")) {
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
    const submitBtn = document.getElementById("submit-btn");
    const statusDiv = document.getElementById("keygen-status");
    const localPartInput = document.getElementById("local_part");
    const inviteInput = document.querySelector('input[name="invite_token"]');
    const csrfInput = document.querySelector('input[name="_csrf"]');
    const domainSuffix = document.querySelector(".input-suffix");
    const form = document.getElementById("register-form");

    if (!form || !submitBtn) {
      return;
    }

    function domain() {
      return domainSuffix
        ? domainSuffix.textContent.replace("@", "").trim()
        : "";
    }

    function setStatus(msg, type) {
      statusDiv.textContent = msg;
      statusDiv.className = "keygen-status" + (type ? " " + type : "");
    }

    form.addEventListener("submit", async function (e) {
      e.preventDefault();

      const localPart = localPartInput.value.trim();

      if (!localPart) {
        setStatus("Please enter a username.", "error");

        return;
      }

      submitBtn.disabled = true;
      setStatus("generating keypair…", "");

      try {
        const address = localPart + "@" + domain();

        // Unencrypted keypair — the passphrase and recovery file come later, on settings.
        const result = await generateKeypair(address, null);

        setStatus("registering…", "");

        const csrfToken = csrfInput ? csrfInput.value : "";
        const resp = await fetch("/api/v1/users/register", {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
          },
          body: JSON.stringify({
            invite_token: inviteInput ? inviteInput.value : "",
            local_part: localPart,
            armored_public_key: result.publicKeyArmored,
          }),
        });

        if (!resp.ok) {
          const body = await resp.json().catch(() => ({}));
          const msg =
            (body && body.error && body.error.message) ||
            "Registration failed (" + resp.status + ").";
          setStatus(msg, "error");
          submitBtn.disabled = false;

          return;
        }

        // Session cookie is now set. The just-generated key is unlocked (no
        // passphrase), so cache it for this session — otherwise the read page
        // would bounce us straight to /logout.
        try {
          const unlocked = await readPrivateKey(result.privateKeyArmored);
          await storeSessionKey(unlocked);
        } catch (e) {
          // Account exists but the key never reached localStorage; surface this
          // rather than navigating away into an immediate /logout bounce.
          setStatus(
            "Account created, but session setup failed: " +
              e.message +
              ". Please log in.",
            "error",
          );
          submitBtn.disabled = false;

          return;
        }

        // On to settings, where the user sets a passphrase and exports recovery.
        window.location.href = "/settings";
      } catch (err) {
        setStatus("Error: " + err.message, "error");
        submitBtn.disabled = false;
      }
    });
  });
})();
