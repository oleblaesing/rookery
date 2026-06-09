/**
 * register.js — client-side orchestration for the invite/registration page.
 *
 * Flow (single "create account" button):
 *   1. User fills in username.
 *   2. On submit:
 *      a. Generates an unencrypted Curve25519 keypair via RookeryCrypto.
 *      b. POSTs to /api/v1/users/register with the public key only.
 *      c. On success: stores the private key in localStorage via
 *         storeSessionKey() so the freshly-authenticated session can
 *         decrypt messages immediately, then redirects to /settings.
 *
 * No passphrase is collected here. The user sets a passphrase and exports
 * the encrypted recovery file on the settings page immediately after signup.
 * The private key never leaves the browser. The server receives only the
 * armored public key; it stores no passphrase and no passphrase hash.
 * Authentication after registration is PGP challenge/response — see login.js.
 *
 * The encrypted private key is exported from the settings page.
 * storeSessionKey() caches the unlocked key (AES-GCM wrapped) in localStorage
 * for the duration of the login session only.
 */

(function () {
  'use strict';

  // Single-asset bundle: only run on this page (see client/index.js).
  if (!location.pathname.startsWith('/invite/')) return;

  function ready(fn) {
    if (document.readyState !== 'loading') { fn(); return; }
    document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    const submitBtn      = document.getElementById('submit-btn');
    const statusDiv      = document.getElementById('keygen-status');
    const localPartInput = document.getElementById('local_part');
    const inviteInput    = document.querySelector('input[name="invite_token"]');
    const csrfInput      = document.querySelector('input[name="_csrf"]');
    const domainSuffix   = document.querySelector('.input-suffix');
    const form           = document.getElementById('register-form');

    if (!form || !submitBtn) return;

    function domain() {
      return domainSuffix ? domainSuffix.textContent.replace('@', '').trim() : '';
    }

    function setStatus(msg, type) {
      statusDiv.textContent = msg;
      statusDiv.className = 'keygen-status' + (type ? ' ' + type : '');
    }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      const localPart = localPartInput.value.trim();

      if (!localPart) {
        setStatus('Please enter a username.', 'error');
        return;
      }

      submitBtn.disabled = true;
      setStatus('generating keypair…', '');

      try {
        const { generateKeypair, readPrivateKey, storeSessionKey } = window.RookeryCrypto;
        const address = localPart + '@' + domain();

        // Generate an unencrypted keypair — the user will set a passphrase and
        // export the recovery file on the settings page after signup.
        const result = await generateKeypair(address, null);

        setStatus('registering…', '');

        // Register with the server.
        const csrfToken = csrfInput ? csrfInput.value : '';
        const resp = await fetch('/api/v1/users/register', {
          method:      'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token':  csrfToken,
          },
          body: JSON.stringify({
            invite_token:       inviteInput ? inviteInput.value : '',
            local_part:         localPart,
            armored_public_key: result.publicKeyArmored,
          }),
        });

        if (!resp.ok) {
          const body = await resp.json().catch(() => ({}));
          const msg  = (body && body.error && body.error.message) || ('Registration failed (' + resp.status + ').');
          setStatus(msg, 'error');
          submitBtn.disabled = false;
          return;
        }

        // The server has set the session cookie; we are now authenticated.
        // The private key from generateKeypair with no passphrase is already
        // unlocked — read it directly and put it in localStorage so the
        // current session can decrypt messages without a re-login.
        try {
          const unlocked = await readPrivateKey(result.privateKeyArmored);
          await storeSessionKey(unlocked);
        } catch (e) {
          // If this fails, the session cookie exists but localStorage is empty;
          // the read page would bounce us to /logout. Surface the error so the
          // user knows to log in again rather than silently navigating away.
          setStatus('Account created, but session setup failed: ' + e.message +
                    '. Please log in.', 'error');
          submitBtn.disabled = false;
          return;
        }

        // Success — navigate to settings to set a passphrase and export the
        // recovery file.
        window.location.href = '/settings';

      } catch (err) {
        setStatus('Error: ' + err.message, 'error');
        submitBtn.disabled = false;
      }
    });
  });
})();
