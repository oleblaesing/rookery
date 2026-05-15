/**
 * settings.js — private key export on the settings page.
 *
 * The user enters a passphrase (and confirms it), then submits the form. The
 * script loads the session key from localStorage via
 * RookeryCrypto.exportSessionKey(), re-encrypts it with that passphrase using
 * OpenPGP.js's built-in s2k, and saves the resulting armored
 * private key as a .asc recovery file.
 *
 * An empty passphrase is valid — the key never leaves the user's machine, so
 * this is analogous to an unprotected SSH key.
 *
 * The passphrase never leaves this script; the server is not involved.
 */

(function () {
  'use strict';

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
