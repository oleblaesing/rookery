import {
  unlockPrivateKey,
  decryptArchive,
  publicKeyArmoredFromPrivate,
  storeSessionKey,
} from "../crypto.js";

(function () {
  "use strict";

  if (location.pathname !== "/migrate") {
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
    const form = document.getElementById("migrate-form");

    if (!form) {
      return;
    }

    const section = form.closest("section");
    const errorEl = section.querySelector('.error[role="alert"]');
    const statusEl = document.getElementById("migrate-status");
    const btn = document.getElementById("migrate-btn");

    // Carried across a retry once the account has been created.
    let privateKey = null;
    let decryptedBytes = null;
    let registered = false;

    function readCookie(name) {
      const escaped = name.replace(/([.*+?^${}()|[\]\\])/g, "\\$1");
      const m = document.cookie.match("(?:^|; )" + escaped + "=([^;]*)");

      return m ? decodeURIComponent(m[1]) : "";
    }

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.hidden = false;
    }
    function clearError() {
      errorEl.textContent = "";
      errorEl.hidden = true;
    }
    function setStatus(msg) {
      statusEl.textContent = msg;
    }

    function setBusy(busy, label) {
      btn.disabled = busy;

      if (label) {
        btn.textContent = label;
      }
    }

    async function runImport() {
      setBusy(true, "importing…");
      setStatus("importing your mailbox…");

      let resp, body;
      try {
        resp = await fetch("/api/v1/users/me/import", {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            "X-CSRF-Token": readCookie("rookery_csrf"),
          },
          body: decryptedBytes,
          credentials: "same-origin",
        });
        body = await resp.json().catch(function () {
          return {};
        });
      } catch {
        showError(
          'Could not reach the server. Your account was created — press "retry import" to finish.',
        );
        setBusy(false, "retry import");
        setStatus("");

        return;
      }

      if (!resp.ok) {
        showError(
          "Import failed: " +
            ((body.error && body.error.message) || "unknown error") +
            ' — press "retry import" to try again.',
        );
        setBusy(false, "retry import");
        setStatus("");

        return;
      }

      try {
        await storeSessionKey(privateKey);
      } catch {
        /* non-fatal — session cookie is already set */
      }

      const msgs = body.imported_messages || 0;
      setStatus("imported " + msgs + " message(s). redirecting…");
      window.location.href = "/inbox";
    }

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      clearError();

      // Retry path: account already exists and the tar is in memory.
      if (registered && decryptedBytes) {
        await runImport();

        return;
      }

      const inviteToken = form
        .querySelector('[name="invite_token"]')
        .value.trim();
      const localPart = form.querySelector('[name="local_part"]').value.trim();
      const archiveURL = form
        .querySelector('[name="archive_url"]')
        .value.trim();
      const fileInput = form.querySelector('[name="recovery_file"]');
      const passphrase = form.querySelector('[name="passphrase"]').value;
      const csrf = form.querySelector('[name="_csrf"]').value;

      if (!inviteToken) {
        showError("Enter the invite token for this instance.");
        return;
      }
      if (!localPart) {
        showError("Choose a username for this instance.");
        return;
      }
      if (!archiveURL) {
        showError("Paste the archive URL from your old instance.");
        return;
      }
      if (!fileInput.files.length) {
        showError("Select your recovery file (.asc).");
        return;
      }

      setBusy(true, "unlocking key…");
      setStatus("unlocking your key…");

      try {
        const armoredKey = await fileInput.files[0].text();
        privateKey = await unlockPrivateKey(armoredKey, passphrase);
      } catch {
        showError(
          "Could not unlock the recovery file — wrong passphrase or invalid file.",
        );
        setBusy(false, "migrate");
        setStatus("");

        return;
      }

      setStatus("fetching archive…");

      let encryptedBytes;
      try {
        const proxyURL =
          "/api/v1/import/fetch?url=" + encodeURIComponent(archiveURL);
        const resp = await fetch(proxyURL, { credentials: "same-origin" });

        if (!resp.ok) {
          const b = await resp.json().catch(function () {
            return {};
          });
          showError(
            "Could not fetch archive: " +
              ((b.error && b.error.message) || "HTTP " + resp.status),
          );
          setBusy(false, "migrate");
          setStatus("");

          return;
        }

        encryptedBytes = new Uint8Array(await resp.arrayBuffer());
      } catch (err) {
        showError("Fetch failed: " + err.message);
        setBusy(false, "migrate");
        setStatus("");

        return;
      }

      setStatus("decrypting archive…");

      try {
        decryptedBytes = await decryptArchive(privateKey, encryptedBytes);
      } catch (err) {
        showError(
          "Decryption failed: " +
            err.message +
            ". The recovery file must match the account this archive came from.",
        );
        setBusy(false, "migrate");
        setStatus("");

        return;
      }

      // Register with the archive's OWN key so the server's import
      // fingerprint-ownership check passes.
      setStatus("creating your account…");

      let pubArmored;
      try {
        pubArmored = publicKeyArmoredFromPrivate(privateKey);
      } catch (err) {
        showError("Could not derive public key: " + err.message);
        setBusy(false, "migrate");
        setStatus("");

        return;
      }

      let resp, body;
      try {
        resp = await fetch("/api/v1/users/register", {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf,
          },
          body: JSON.stringify({
            invite_token: inviteToken,
            local_part: localPart,
            armored_public_key: pubArmored,
          }),
        });
        body = await resp.json().catch(function () {
          return {};
        });
      } catch {
        showError(
          "Could not reach the server. Check your connection and try again.",
        );
        setBusy(false, "migrate");
        setStatus("");

        return;
      }

      if (!resp.ok) {
        showError(
          (body.error && body.error.message) ||
            "Registration failed (" + resp.status + ").",
        );
        setBusy(false, "migrate");
        setStatus("");

        return;
      }

      // Account created; session + CSRF cookies are set. From here a failure is
      // recoverable via the retry path rather than a fresh registration.
      registered = true;

      await runImport();
    });
  });
})();
