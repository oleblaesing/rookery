/**
 * migrate.js — logged-out cross-instance migration.
 *
 * Runs on /migrate (destination instance). The user supplies the recovery file
 * + passphrase for their OLD account, the archive URL from that account's
 * "archive is ready" message, an invite token for THIS instance, and a desired
 * username. The flow:
 *
 *   1. Unlock the recovery private key with the passphrase (browser only).
 *   2. Fetch the encrypted archive through the SSRF-safe proxy
 *      GET /api/v1/import/fetch?url=… (unauthenticated; the account doesn't
 *      exist yet).
 *   3. Decrypt the archive in the browser. Success proves the recovery key
 *      matches the key the archive was encrypted to — and therefore the
 *      manifest fingerprint the server checks on import.
 *   4. Register a new account here with the archive's own public key (derived
 *      from the private key): POST /api/v1/users/register. This sets the
 *      session + CSRF cookies (auto-login).
 *   5. Import the decrypted tar: POST /api/v1/users/me/import. The fingerprint
 *      ownership check passes because the account was just created with the
 *      archive's key.
 *   6. Cache the unlocked key for the session and navigate to /inbox.
 *
 * The private key never leaves the browser; the server only ever receives the
 * armored public key (register) and the plaintext tar (import).
 *
 * Ordering note: fetch + decrypt happen before register, so a bad
 * URL/passphrase/archive fails without consuming the invite. If register
 * succeeds but the import POST fails, the decrypted bytes are kept in memory
 * and the button becomes "retry import" so the user can finish without
 * re-registering (there is no settings-based import to fall back on).
 */
(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState !== 'loading') { fn(); return; }
    document.addEventListener('DOMContentLoaded', fn);
  }

  ready(function () {
    const form = document.getElementById('migrate-form');
    if (!form || !window.RookeryCrypto) return;

    const { unlockPrivateKey, decryptArchive, publicKeyArmoredFromPrivate, storeSessionKey } = window.RookeryCrypto;

    const section  = form.closest('section');
    const errorEl  = section.querySelector('.error[role="alert"]');
    const statusEl = document.getElementById('migrate-status');
    const btn      = document.getElementById('migrate-btn');

    // Carried across a possible retry once the account has been created.
    let privateKey     = null;
    let decryptedBytes = null;
    let registered     = false;

    function readCookie(name) {
      const escaped = name.replace(/([.*+?^${}()|[\]\\])/g, '\\$1');
      const m = document.cookie.match('(?:^|; )' + escaped + '=([^;]*)');
      return m ? decodeURIComponent(m[1]) : '';
    }

    function showError(msg) { errorEl.textContent = msg; errorEl.hidden = false; }
    function clearError() { errorEl.textContent = ''; errorEl.hidden = true; }
    function setStatus(msg) { statusEl.textContent = msg; }
    function setBusy(busy, label) { btn.disabled = busy; if (label) btn.textContent = label; }

    // Step 5–6: POST the already-decrypted tar to the authenticated import
    // endpoint, then cache the key and navigate. Reused by the retry path.
    async function runImport() {
      setBusy(true, 'importing…');
      setStatus('importing your mailbox…');

      let resp, body;
      try {
        resp = await fetch('/api/v1/users/me/import', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-CSRF-Token': readCookie('rookery_csrf'),
          },
          body: decryptedBytes,
          credentials: 'same-origin',
        });
        body = await resp.json().catch(function () { return {}; });
      } catch {
        showError('Could not reach the server. Your account was created — press "retry import" to finish.');
        setBusy(false, 'retry import');
        setStatus('');
        return;
      }

      if (!resp.ok) {
        showError('Import failed: ' + ((body.error && body.error.message) || 'unknown error') +
                  ' — press "retry import" to try again.');
        setBusy(false, 'retry import');
        setStatus('');
        return;
      }

      try {
        await storeSessionKey(privateKey);
      } catch { /* non-fatal — session cookie is already set */ }

      const msgs = body.imported_messages || 0;
      setStatus('imported ' + msgs + ' message(s). redirecting…');
      window.location.href = '/inbox';
    }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearError();

      // Retry path: account already exists and the tar is in memory.
      if (registered && decryptedBytes) {
        await runImport();
        return;
      }

      const inviteToken = form.querySelector('[name="invite_token"]').value.trim();
      const localPart   = form.querySelector('[name="local_part"]').value.trim();
      const archiveURL  = form.querySelector('[name="archive_url"]').value.trim();
      const fileInput   = form.querySelector('[name="recovery_file"]');
      const passphrase  = form.querySelector('[name="passphrase"]').value;
      const csrf        = form.querySelector('[name="_csrf"]').value;

      if (!inviteToken) { showError('Enter the invite token for this instance.'); return; }
      if (!localPart)   { showError('Choose a username for this instance.'); return; }
      if (!archiveURL)  { showError('Paste the archive URL from your old instance.'); return; }
      if (!fileInput.files.length) { showError('Select your recovery file (.asc).'); return; }

      // Step 1: unlock the recovery private key.
      setBusy(true, 'unlocking key…');
      setStatus('unlocking your key…');
      try {
        const armoredKey = await fileInput.files[0].text();
        privateKey = await unlockPrivateKey(armoredKey, passphrase);
      } catch {
        showError('Could not unlock the recovery file — wrong passphrase or invalid file.');
        setBusy(false, 'migrate');
        setStatus('');
        return;
      }

      // Step 2: fetch the encrypted archive through the SSRF-safe proxy.
      setStatus('fetching archive…');
      let encryptedBytes;
      try {
        const proxyURL = '/api/v1/import/fetch?url=' + encodeURIComponent(archiveURL);
        const resp = await fetch(proxyURL, { credentials: 'same-origin' });
        if (!resp.ok) {
          const b = await resp.json().catch(function () { return {}; });
          showError('Could not fetch archive: ' + ((b.error && b.error.message) || 'HTTP ' + resp.status));
          setBusy(false, 'migrate');
          setStatus('');
          return;
        }
        encryptedBytes = new Uint8Array(await resp.arrayBuffer());
      } catch (err) {
        showError('Fetch failed: ' + err.message);
        setBusy(false, 'migrate');
        setStatus('');
        return;
      }

      // Step 3: decrypt in the browser.
      setStatus('decrypting archive…');
      try {
        decryptedBytes = await decryptArchive(privateKey, encryptedBytes);
      } catch (err) {
        showError('Decryption failed: ' + err.message +
                  '. The recovery file must match the account this archive came from.');
        setBusy(false, 'migrate');
        setStatus('');
        return;
      }

      // Step 4: register a new account here with the archive's own key.
      setStatus('creating your account…');
      let pubArmored;
      try {
        pubArmored = publicKeyArmoredFromPrivate(privateKey);
      } catch (err) {
        showError('Could not derive public key: ' + err.message);
        setBusy(false, 'migrate');
        setStatus('');
        return;
      }

      let resp, body;
      try {
        resp = await fetch('/api/v1/users/register', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrf,
          },
          body: JSON.stringify({
            invite_token:       inviteToken,
            local_part:         localPart,
            armored_public_key: pubArmored,
          }),
        });
        body = await resp.json().catch(function () { return {}; });
      } catch {
        showError('Could not reach the server. Check your connection and try again.');
        setBusy(false, 'migrate');
        setStatus('');
        return;
      }

      if (!resp.ok) {
        showError((body.error && body.error.message) || ('Registration failed (' + resp.status + ').'));
        setBusy(false, 'migrate');
        setStatus('');
        return;
      }

      // Account created; session + CSRF cookies are set. From here a failure is
      // recoverable via the retry path rather than a fresh registration.
      registered = true;

      // Step 5–6: import and navigate.
      await runImport();
    });
  });
})();
