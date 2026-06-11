import { unlockPrivateKey, storeSessionKey, signChallenge } from "../crypto.js";

(function () {
  "use strict";

  if (location.pathname !== "/login") {
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
    const form = document.getElementById("login-form");
    if (!form) {
      return;
    }

    const section = form.closest("section");
    const errorEl = section.querySelector('.error[role="alert"]');
    const submitBtn = form.querySelector('button[type="submit"]');

    function nextURL() {
      const next = new URLSearchParams(window.location.search).get("next");

      // Only same-origin relative paths; reject protocol-relative //host and /\host.
      if (
        !next ||
        next.charAt(0) !== "/" ||
        next.charAt(1) === "/" ||
        next.charAt(1) === "\\"
      ) {
        return "/inbox";
      }

      return next;
    }

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.hidden = false;
    }

    function clearError() {
      errorEl.textContent = "";
      errorEl.hidden = true;
    }

    function setSubmitState(busy, label) {
      submitBtn.disabled = busy;
      submitBtn.textContent = label;
    }

    function fail(msg) {
      showError(msg);
      setSubmitState(false, "log in");
    }

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      clearError();

      const addressInput = form.querySelector('[name="address"]');
      const passphraseInput = form.querySelector('[name="passphrase"]');
      const fileInput = form.querySelector('[name="recovery_file"]');
      const csrf = form.querySelector('[name="_csrf"]').value;

      const address = addressInput.value.trim();
      const passphrase = passphraseInput.value;

      if (!address) {
        showError("Please enter your account address.");
        return;
      }

      if (!fileInput.files.length) {
        showError("Please select your recovery file (.asc).");
        return;
      }

      setSubmitState(true, "requesting challenge…");

      let challengeID, nonce;
      try {
        const resp = await fetch(
          "/api/v1/auth/challenge?" + new URLSearchParams({ address }),
          { credentials: "same-origin" },
        );
        const body = await resp.json();

        if (!resp.ok) {
          fail(body.message || "Could not obtain challenge.");
          return;
        }

        challengeID = body.challenge_id;
        nonce = body.nonce;
      } catch {
        fail(
          "Could not reach the server. Check your connection and try again.",
        );
        return;
      }

      setSubmitState(true, "unlocking key…");

      let privateKey;
      try {
        const armoredKey = await fileInput.files[0].text();
        privateKey = await unlockPrivateKey(armoredKey, passphrase);
      } catch {
        fail(
          "Could not unlock the recovery file — wrong passphrase or invalid file.",
        );
        return;
      }

      setSubmitState(true, "signing challenge…");

      let signedChallenge;
      try {
        signedChallenge = await signChallenge(privateKey, nonce);
      } catch (err) {
        fail("Signing failed: " + err.message);
        return;
      }

      setSubmitState(true, "logging in…");

      let resp, body;
      try {
        resp = await fetch("/api/v1/auth/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf,
          },
          body: JSON.stringify({
            address,
            challenge_id: challengeID,
            signed_challenge: signedChallenge,
          }),
          credentials: "same-origin",
        });
        body = await resp.json();
      } catch {
        fail(
          "Could not reach the server. Check your connection and try again.",
        );
        return;
      }

      if (!resp.ok) {
        fail(body.message || "Login failed.");
        return;
      }

      const fingerprint = body.public_key_fingerprint;
      if (fingerprint) {
        const importedFP = privateKey.getFingerprint().toUpperCase();

        if (importedFP !== fingerprint.toUpperCase()) {
          fail("The recovery file belongs to a different account.");
          return;
        }
      }

      try {
        await storeSessionKey(privateKey);
      } catch {
        /* non-fatal — session cookie is already set */
      }

      window.location.href = nextURL();
    });
  });
})();
