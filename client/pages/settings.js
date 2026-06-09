/**
 * settings.js — data & keys tab: recovery file export, full archive export,
 * and account deletion.
 *
 * Recovery file export: browser-side only. Re-encrypts the session key with a
 * passphrase and downloads a .asc file. The server is not involved.
 *
 * Full archive export: calls POST /api/v1/users/me/export, polls status every
 * 5 seconds, and notifies the user to check their inbox when ready.
 *
 * Import is not done here — it lives on the destination instance's logged-out
 * /migrate page (see migrate.js), which creates the account and ingests the
 * archive in one step.
 */

(function () {
  'use strict';

  // Single-asset bundle: only run on this page (see client/index.js).
  if (location.pathname !== '/settings') return;

  function ready(fn) {
    if (document.readyState !== 'loading') { fn(); return; }
    document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    const form    = document.getElementById('export-form');
    const btn     = document.getElementById('export-btn');
    const input   = document.getElementById('export-passphrase');
    const confirm = document.getElementById('export-passphrase-confirm');
    const errorEl = document.getElementById('export-error');

    if (!form || !input || !confirm) return;

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.style.display = '';
    }

    function clearError() {
      errorEl.textContent = '';
      errorEl.style.display = 'none';
    }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearError();

      const passphrase = input.value;

      if (passphrase !== confirm.value) {
        showError('Passphrases do not match.');
        confirm.focus();
        return;
      }

      btn.disabled = true;
      btn.textContent = 'exporting…';

      try {
        const { exportSessionKey } = window.RookeryCrypto;
        const { armoredKey, fingerprint } = await exportSessionKey(passphrase);

        const blob   = new Blob([armoredKey], { type: 'application/pgp-keys' });
        const url    = URL.createObjectURL(blob);
        const suffix = fingerprint ? fingerprint.slice(-8).toLowerCase() : 'key';

        const a      = document.createElement('a');
        a.href       = url;
        a.download   = 'rookery-recovery-' + suffix + '.asc';
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        input.value   = '';
        confirm.value = '';
      } catch (err) {
        showError('Export failed: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'export recovery file';
      }
    });
  });
})();

/**
 * Account deletion flow.
 *
 * 1. Validate the typed address matches the expected value (client-side).
 * 2. Read the recovery file and unlock it with the passphrase.
 * 3. POST /api/v1/users/me/deletion/challenge → { challenge_id, nonce }.
 * 4. Sign the nonce with the unlocked key.
 * 5. POST /api/v1/users/me/deletion with { challenge_id, signed_challenge, confirm_address }.
 * 6. On success: clear localStorage, navigate to /login?deleted=1.
 * 7. On failure: show an inline error.
 */
(function () {
  'use strict';

  // Single-asset bundle: only run on this page (see client/index.js).
  if (location.pathname !== '/settings') return;

  function ready(fn) {
    if (document.readyState !== 'loading') { fn(); return; }
    document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    const form    = document.getElementById('delete-account-form');
    const btn     = document.getElementById('delete-account-btn');
    const errorEl = document.getElementById('delete-account-error');

    if (!form || !window.RookeryCrypto) return;

    const { unlockPrivateKey, signChallenge } = window.RookeryCrypto;

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.style.display = '';
    }

    function clearError() {
      errorEl.textContent = '';
      errorEl.style.display = 'none';
    }

    function csrfToken() {
      const meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.getAttribute('content') : '';
    }

    function setBusy(label) {
      btn.disabled = true;
      btn.textContent = label;
    }

    function setReady() {
      btn.disabled = false;
      btn.textContent = 'delete account';
    }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearError();

      const confirmAddress = form.querySelector('[name="confirm_address"]').value.trim().toLowerCase();
      const passphrase     = form.querySelector('[name="passphrase"]').value;
      const fileInput      = form.querySelector('[name="recovery_file"]');

      // The server also checks this; client check gives immediate feedback.
      const expectedAddress = form.querySelector('[name="confirm_address"]').placeholder.toLowerCase();
      if (confirmAddress !== expectedAddress) {
        showError('Typed address does not match your primary address.');
        return;
      }

      if (!fileInput.files.length) {
        showError('Select your recovery file (.asc).');
        return;
      }

      setBusy('unlocking key…');

      let privateKey;
      try {
        const armoredKey = await fileInput.files[0].text();
        privateKey = await unlockPrivateKey(armoredKey, passphrase);
      } catch {
        showError('Could not unlock the recovery file — wrong passphrase or invalid file.');
        setReady();
        return;
      }

      setBusy('requesting challenge…');

      let challengeID, nonce;
      try {
        const resp = await fetch('/api/v1/users/me/deletion/challenge', {
          method: 'POST',
          headers: { 'X-CSRF-Token': csrfToken() },
          credentials: 'same-origin',
        });
        const body = await resp.json();
        if (!resp.ok) {
          showError(body.message || 'Could not obtain deletion challenge.');
          setReady();
          return;
        }
        challengeID = body.challenge_id;
        nonce       = body.nonce;
      } catch {
        showError('Could not reach the server. Check your connection and try again.');
        setReady();
        return;
      }

      setBusy('signing challenge…');

      let signedChallenge;
      try {
        signedChallenge = await signChallenge(privateKey, nonce);
      } catch (err) {
        showError('Signing failed: ' + err.message);
        setReady();
        return;
      }

      setBusy('deleting account…');

      try {
        const resp = await fetch('/api/v1/users/me/deletion', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken(),
          },
          body: JSON.stringify({
            challenge_id:     challengeID,
            signed_challenge: signedChallenge,
            confirm_address:  confirmAddress,
          }),
          credentials: 'same-origin',
        });
        const body = await resp.json();
        if (!resp.ok) {
          showError(body.message || 'Account deletion failed.');
          setReady();
          return;
        }
      } catch {
        showError('Could not reach the server. Check your connection and try again.');
        setReady();
        return;
      }

      // Clear the in-session key cache. The server has already destroyed the
      // session row; we clean up localStorage as a courtesy.
      try {
        localStorage.removeItem('rookery_session_key');
        localStorage.removeItem('rookery_session_key_wrap');
        localStorage.removeItem('rookery_session_key_fp');
      } catch { /* ignore */ }

      window.location.href = '/login?deleted=1';
    });
  });
}());

/**
 * Full archive export.
 *
 * Reads the optional new_instance field and POSTs it with the export request.
 * The server includes a migration link for that instance in the inbox notification.
 */
(function () {
  'use strict';

  // Single-asset bundle: only run on this page (see client/index.js).
  if (location.pathname !== '/settings') return;

  function ready(fn) {
    if (document.readyState !== 'loading') { fn(); return; }
    document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    const form        = document.getElementById('export-archive-form');
    const btn         = document.getElementById('export-archive-btn');
    const statusEl    = document.getElementById('export-archive-status');
    const newInstance = document.getElementById('export-new-instance');

    if (!form || !btn) return;

    function csrfToken() {
      const meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.getAttribute('content') : '';
    }

    function setStatus(msg) {
      statusEl.textContent = msg;
      statusEl.style.display = '';
    }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      btn.disabled = true;

      try {
        const body = newInstance && newInstance.value.trim()
          ? JSON.stringify({ new_instance: newInstance.value.trim() })
          : null;
        const resp = await fetch('/api/v1/users/me/export', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken(),
          },
          body,
          credentials: 'same-origin',
        });
        if (!resp.ok) {
          const data = await resp.json().catch(function () { return {}; });
          setStatus('Could not start export: ' + (data.error && data.error.message || 'unknown error'));
        } else {
          setStatus('Export started. You will receive an inbox message when the archive is ready.');
        }
      } catch (_e) {
        setStatus('Could not reach the server.');
        btn.disabled = false;
      }
    });
  });
}());
