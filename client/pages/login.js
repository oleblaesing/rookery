/**
 * login.js — challenge/response login using the user's PGP private key.
 *
 * Flow:
 *   1. User enters their address and selects their recovery .asc file.
 *   2. On submit:
 *      a. GET /api/v1/auth/challenge?address=… → { challenge_id, nonce }
 *      b. Read and decrypt the recovery file with the supplied passphrase.
 *      c. Sign the nonce with the unlocked private key (detached PGP signature).
 *      d. POST /api/v1/auth/login with { address, challenge_id, signed_challenge }.
 *      e. On success: store the unlocked key in localStorage, navigate to inbox.
 *
 * The passphrase never leaves the browser. The server only ever sees the
 * address and a detached signature of a random nonce — no passphrase, no
 * passphrase hash, no private key material.
 *
 * On network failure or a bad response the error is shown inline and the
 * form is re-enabled for retry.
 */
import { unlockPrivateKey, storeSessionKey, signChallenge } from '../crypto.js';

(function () {
  'use strict';

  // Single-asset bundle: only run on this page (see client/index.js).
  if (location.pathname !== '/login') return;

  function ready(fn) {
    if (document.readyState !== 'loading') { fn(); return; }
    document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    const form = document.getElementById('login-form');
    if (!form) return;

    const section     = form.closest('section');
    const errorEl     = section.querySelector('.error[role="alert"]');
    const submitBtn   = form.querySelector('button[type="submit"]');

    function nextURL() {
      const next = new URLSearchParams(window.location.search).get('next');
      if (!next) return '/inbox';
      if (next.charAt(0) !== '/') return '/inbox';
      if (next.charAt(1) === '/' || next.charAt(1) === '\\') return '/inbox';
      return next;
    }

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.hidden = false;
    }

    function clearError() {
      errorEl.textContent = '';
      errorEl.hidden = true;
    }

    function setSubmitState(busy, label) {
      submitBtn.disabled = busy;
      submitBtn.textContent = label;
    }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearError();

      const addressInput    = form.querySelector('[name="address"]');
      const passphraseInput = form.querySelector('[name="passphrase"]');
      const fileInput       = form.querySelector('[name="recovery_file"]');
      const csrf            = form.querySelector('[name="_csrf"]').value;

      const address    = addressInput.value.trim();
      const passphrase = passphraseInput.value;

      if (!address) {
        showError('Please enter your account address.');
        return;
      }
      if (!fileInput.files.length) {
        showError('Please select your recovery file (.asc).');
        return;
      }

      setSubmitState(true, 'requesting challenge…');

      // Step 1: fetch a challenge nonce from the server.
      let challengeID, nonce;
      try {
        const resp = await fetch(
          '/api/v1/auth/challenge?' + new URLSearchParams({ address }),
          { credentials: 'same-origin' }
        );
        const body = await resp.json();
        if (!resp.ok) {
          showError(body.message || 'Could not obtain challenge.');
          setSubmitState(false, 'log in');
          return;
        }
        challengeID = body.challenge_id;
        nonce       = body.nonce;
      } catch {
        showError('Could not reach the server. Check your connection and try again.');
        setSubmitState(false, 'log in');
        return;
      }

      setSubmitState(true, 'unlocking key…');

      // Step 2: read and decrypt the recovery file.
      let privateKey;
      try {
        const armoredKey = await fileInput.files[0].text();
        privateKey = await unlockPrivateKey(armoredKey, passphrase);
      } catch {
        showError('Could not unlock the recovery file — wrong passphrase or invalid file.');
        setSubmitState(false, 'log in');
        return;
      }

      setSubmitState(true, 'signing challenge…');

      // Step 3: sign the nonce.
      let signedChallenge;
      try {
        signedChallenge = await signChallenge(privateKey, nonce);
      } catch (err) {
        showError('Signing failed: ' + err.message);
        setSubmitState(false, 'log in');
        return;
      }

      setSubmitState(true, 'logging in…');

      // Step 4: submit the signed challenge to the server.
      let resp, body;
      try {
        resp = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf,
          },
          body: JSON.stringify({ address, challenge_id: challengeID, signed_challenge: signedChallenge }),
          credentials: 'same-origin',
        });
        body = await resp.json();
      } catch {
        showError('Could not reach the server. Check your connection and try again.');
        setSubmitState(false, 'log in');
        return;
      }

      if (!resp.ok) {
        showError(body.message || 'Login failed.');
        setSubmitState(false, 'log in');
        return;
      }

      // Verify the key matches the account we just authenticated as.
      const fingerprint = body.public_key_fingerprint;
      if (fingerprint) {
        const importedFP = privateKey.getFingerprint().toUpperCase();
        if (importedFP !== fingerprint.toUpperCase()) {
          showError('The recovery file belongs to a different account.');
          setSubmitState(false, 'log in');
          return;
        }
      }

      // Step 5: cache the unlocked key for the session and navigate.
      try {
        await storeSessionKey(privateKey);
      } catch { /* non-fatal — session cookie is already set */ }

      window.location.href = nextURL();
    });
  });
})();
