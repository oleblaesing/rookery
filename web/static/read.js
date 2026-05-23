/**
 * read.js — decryption and signature verification for the message read page.
 *
 * On page load:
 *   1. Reads the message ID and security_state from the data attributes on
 *      #message-body.
 *   2. If security_state is "plaintext": fetches /api/v1/messages/{id}/raw
 *      and renders the text body directly.
 *   3. If security_state is "pgp_encrypted" or "pgp_signed_plaintext":
 *      a. Checks the session key fingerprint in localStorage against the
 *         expected fingerprint for this account (data-key-fingerprint).
 *      b. If missing or mismatched: redirect to /logout for a clean re-login.
 *      c. Loads the session key and decrypts/verifies.
 *      d. Updates the security badge with the actual signature status.
 *
 * The decrypted body is rendered into #message-body as text (not innerHTML,
 * to prevent XSS).
 */

(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState !== 'loading') { fn(); return; }
    document.addEventListener('DOMContentLoaded', fn);
  }

  ready(async function () {
    const bodyDiv  = document.getElementById('message-body');
    const badgeEl  = document.getElementById('security-badge');
    const noticeEl = document.getElementById('decrypting-notice');

    if (!bodyDiv) return;

    const msgID          = bodyDiv.dataset.messageId;
    const secState       = bodyDiv.dataset.securityState;
    const keyFingerprint = bodyDiv.dataset.keyFingerprint;
    const senderKeyB64   = bodyDiv.dataset.senderKeyB64 || '';
    const senderKey      = senderKeyB64 ? atob(senderKeyB64) : null;
    const csrfToken      = document.querySelector('meta[name="csrf-token"]')?.content || '';

    async function fetchRaw() {
      const resp = await fetch('/api/v1/messages/' + msgID + '/raw', {
        headers: { 'X-CSRF-Token': csrfToken },
        credentials: 'same-origin',
      });
      if (!resp.ok) throw new Error('Failed to fetch message: ' + resp.status);
      return resp.text();
    }

    function renderBody(text) {
      const pre = document.createElement('pre');
      pre.className = 'message-body-text';
      pre.textContent = text;
      bodyDiv.replaceChildren(pre);
    }

    function updateBadge(status, securityState) {
      if (!badgeEl) return;
      if (securityState === 'pgp_encrypted') {
        const labels = {
          verified:    '🔒 PGP encrypted — signature verified',
          unknown_key: '🔒 PGP encrypted — signature unverified (key not known)',
          invalid:     '🔒 PGP encrypted — signature INVALID',
          none:        '🔒 PGP encrypted — unsigned',
        };
        badgeEl.textContent = labels[status] || '🔒 PGP encrypted';
        badgeEl.className = 'badge badge-encrypted';
      } else if (securityState === 'pgp_signed_plaintext') {
        const labels = {
          verified:    '✓ signed plaintext — signature verified',
          unknown_key: '✓ signed plaintext — signature unverified (key not known)',
          invalid:     '⚠ signed plaintext — signature INVALID',
          none:        'plaintext',
        };
        badgeEl.textContent = labels[status] || '✓ signed plaintext';
        badgeEl.className = 'badge badge-signed';
      }
    }

    function showError(msg) {
      if (noticeEl) {
        noticeEl.textContent = msg;
        noticeEl.className = 'error-notice';
      }
    }

    const { loadSessionKey, loadSessionFingerprint, decryptMessage } = window.RookeryCrypto;

    // --- Plaintext: fetch and render directly, no key needed ---
    if (secState === 'plaintext') {
      try {
        const raw = await fetchRaw();
        const { body } = await decryptMessage(raw, null);
        renderBody(body);
      } catch (err) {
        showError('Could not load message: ' + err.message);
      }
      return;
    }

    // --- PGP: verify the session key belongs to this account ---
    const sessionFP = loadSessionFingerprint();
    if (!sessionFP || (keyFingerprint && sessionFP.toUpperCase() !== keyFingerprint.toUpperCase())) {
      // No session key, or it belongs to a different account.
      // Force a clean re-login.
      window.location.replace('/logout');
      return;
    }

    const privateKey = await loadSessionKey();
    if (!privateKey) {
      window.location.replace('/logout');
      return;
    }

    try {
      if (noticeEl) noticeEl.textContent = 'decrypting…';
      const raw = await fetchRaw();
      const { body, signatureStatus } = await decryptMessage(raw, privateKey, senderKey);
      renderBody(body);
      updateBadge(signatureStatus, secState);
    } catch (err) {
      showError('Decryption failed: ' + err.message);
    }
  });
})();
