/**
 * rookery browser crypto module — Phase 1.
 *
 * Responsibilities:
 *   - In-browser PGP keypair generation (Curve25519 / ed25519+cv25519).
 *   - Mandatory recovery file export (encrypted private key as .asc).
 *   - PGP/MIME decryption + signature verification on the read page.
 *
 * This module is bundled by esbuild inside the Containerfile build (Stage 2).
 * It is never run directly by Node in production.
 *
 * Security properties (§11.1 / ADR-0010):
 *   - The PGP passphrase NEVER leaves this module.
 *   - The private key NEVER leaves this module in plaintext.
 *   - Only the public key (armored) is sent to the server.
 *   - At signup the private key is generated without a passphrase and stored
 *     in the session cache; the user sets a passphrase and exports the
 *     recovery file on the settings page immediately afterwards.
 *   - The server never receives or stores the private key.
 *
 * Dependencies:
 *   - openpgp (OpenPGP.js v6) — pinned in package.json; the only dependency.
 *
 * KDF note:
 *   OpenPGP.js encrypts the private key using its own string-to-key (s2k)
 *   function when a passphrase is supplied to generateKey / decryptKey.
 *   We do not need a separate KDF library; the protection is already
 *   applied by OpenPGP.js before the key is returned to us.
 *
 * Session key caching (auto-decrypt across all tabs, lifetime = until logout):
 *   After the first successful passphrase unlock, the unlocked private key
 *   bytes are wrapped with an AES-256-GCM key and stored in localStorage.
 *   All tabs on the same origin share the cache, so opening a new tab or
 *   window after login auto-decrypts without a passphrase prompt. The cache
 *   persists across page navigations and browser restarts; it is cleared on
 *   logout, and other tabs observe the removal via the "storage" event so
 *   they stop using the key immediately.
 *   The wrapping key is stored alongside the wrapped blob (same security
 *   boundary), so this does not add cryptographic protection against a
 *   same-origin XSS attack — the protection is ergonomic: the key is never
 *   stored in plaintext and is cleared on logout.
 *   localStorage keys: "rookery_swk" (hex AES key), "rookery_swb" (JSON
 *   {iv: hex, data: hex} wrapped key blob).
 */

import * as openpgp from 'openpgp';

export const ROOKERY_CRYPTO_VERSION = "0.1.0-phase2";

// --------------------------------------------------------------------------
// Key generation
// --------------------------------------------------------------------------

/**
 * generateKeypair(address, pgpPassphrase)
 *   → { privateKeyArmored, publicKeyArmored, fingerprint }
 *
 * Generates a Curve25519 keypair for the given address. OpenPGP.js encrypts
 * the private key with pgpPassphrase using its built-in s2k before returning
 * the armored string. The passphrase never leaves this function; the server
 * only receives publicKeyArmored.
 */
export async function generateKeypair(address, pgpPassphrase) {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ email: address }],
    passphrase: pgpPassphrase,
    format: 'armored',
  });
  const pk = await openpgp.readKey({ armoredKey: publicKey });
  const fingerprint = pk.getFingerprint().toUpperCase();
  return { privateKeyArmored: privateKey, publicKeyArmored: publicKey, fingerprint };
}

// --------------------------------------------------------------------------
// Private key unlock (passphrase → in-memory private key object)
// --------------------------------------------------------------------------

/**
 * unlockPrivateKey(encryptedPrivateKeyArmored, pgpPassphrase)
 *   → openpgp.PrivateKey
 *
 * Reads and decrypts the armored private key. Throws if the passphrase is
 * wrong. The returned key object is held in memory for the session; it is
 * never written to any persistent store in its decrypted form.
 *
 * Used during login (recovery file + passphrase → session key).
 */
export async function unlockPrivateKey(encryptedPrivateKeyArmored, pgpPassphrase) {
  const privateKey = await openpgp.readPrivateKey({ armoredKey: encryptedPrivateKeyArmored });
  return openpgp.decryptKey({ privateKey, passphrase: pgpPassphrase });
}

/**
 * readPrivateKey(armoredKey) → openpgp.PrivateKey
 *
 * Reads an armored private key that has no passphrase protection (i.e. as
 * returned by generateKeypair with a null/empty passphrase). The key is
 * already in a usable (decrypted) state; no decryptKey call is needed.
 *
 * Used during signup to store the freshly-generated key in the session cache
 * without a passphrase round-trip.
 */
export async function readPrivateKey(armoredKey) {
  return openpgp.readPrivateKey({ armoredKey });
}

// --------------------------------------------------------------------------
// Recovery file
// --------------------------------------------------------------------------

/**
 * buildRecoveryBlob(encryptedPrivateKeyArmored) → Blob
 *
 * Wraps the encrypted armored private key in a Blob suitable for export
 * as a .asc file. The content is the raw armored string — importable by gpg.
 */
export function buildRecoveryBlob(encryptedPrivateKeyArmored) {
  return new Blob([encryptedPrivateKeyArmored], { type: 'text/plain' });
}

// --------------------------------------------------------------------------
// Decryption (read page)
// --------------------------------------------------------------------------

/**
 * decryptMessage(rawRFC5322, privateKey, senderPublicKeyArmored?)
 *   → { body: string, signatureStatus: string }
 *
 * rawRFC5322: the raw RFC 5322 message bytes (fetched from
 *             /api/v1/messages/{id}/raw).
 * privateKey: the unlocked openpgp.PrivateKey object, or null for plaintext.
 * senderPublicKeyArmored: optional armored public key for signature verification.
 *
 * Returns:
 *   body            — decrypted plaintext body (or extracted body for
 *                     non-PGP messages)
 *   signatureStatus — "verified" | "unknown_key" | "invalid" | "none"
 */
export async function decryptMessage(rawRFC5322, privateKey, senderPublicKeyArmored = null) {
  const pgpBlock = extractPGPBlock(rawRFC5322);

  if (!pgpBlock || !privateKey) {
    const body = extractTextBody(rawRFC5322);
    return { body, signatureStatus: 'none' };
  }

  try {
    // First pass: decrypt to get the plaintext payload.
    const message = await openpgp.readMessage({ armoredMessage: pgpBlock });
    const { data, signatures } = await openpgp.decrypt({
      message,
      decryptionKeys: privateKey,
      expectSigned: false,
    });

    const body = extractDecryptedBody(data);

    if (!signatures || signatures.length === 0) {
      return { body, signatureStatus: 'none' };
    }

    if (!senderPublicKeyArmored) {
      return { body, signatureStatus: 'unknown_key' };
    }

    try {
      const senderKey = await openpgp.readKey({ armoredKey: senderPublicKeyArmored });
      const message2 = await openpgp.readMessage({ armoredMessage: pgpBlock });
      const { signatures: sigs2 } = await openpgp.decrypt({
        message: message2,
        decryptionKeys: privateKey,
        verificationKeys: senderKey,
        expectSigned: false,
      });
      await sigs2[0].verified;
      return { body, signatureStatus: 'verified' };
    } catch {
      return { body, signatureStatus: 'invalid' };
    }
  } catch (err) {
    throw new Error('Decryption failed: ' + err.message);
  }
}

// --------------------------------------------------------------------------
// Session key caching (auto-decrypt across all tabs, lifetime = login session)
// --------------------------------------------------------------------------

const SS_WRAP_KEY = 'rookery_swk';   // hex-encoded AES-256-GCM raw key
const SS_WRAP_BLOB = 'rookery_swb';  // JSON { iv: hex, data: hex }
const SS_FINGERPRINT = 'rookery_sfp'; // uppercase hex fingerprint of the session key

function hexEncode(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexDecode(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return out;
}

/**
 * storeSessionKey(privateKey)
 *
 * Wraps the unlocked OpenPGP PrivateKey object with an AES-256-GCM key and
 * stores both in localStorage. Persists until logout or explicit clearance.
 * Silently no-ops if localStorage or SubtleCrypto is unavailable.
 *
 * privateKey: an unlocked openpgp.PrivateKey (as returned by unlockPrivateKey).
 */
export async function storeSessionKey(privateKey) {
  try {
    const subtle = crypto.subtle;

    // Clear any previous session key first — guards against a stale entry from
    // a different account being used when switching users.
    clearSessionKey();

    // Export the OpenPGP private key to binary (non-armored).
    const keyBytes = privateKey.write(); // Uint8Array — OpenPGP.js internal

    // Generate a fresh random AES-256-GCM wrapping key.
    const wrapKey = await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,   // extractable so we can store it
      ['encrypt', 'decrypt']
    );

    // Encrypt the key bytes.
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      wrapKey,
      keyBytes
    );

    // Export wrapping key to raw bytes for storage.
    const rawWrapKey = await subtle.exportKey('raw', wrapKey);

    localStorage.setItem(SS_WRAP_KEY, hexEncode(rawWrapKey));
    localStorage.setItem(SS_WRAP_BLOB, JSON.stringify({
      iv:   hexEncode(iv),
      data: hexEncode(wrapped),
    }));
    localStorage.setItem(SS_FINGERPRINT, privateKey.getFingerprint().toUpperCase());
  } catch {
    // localStorage unavailable (private browsing restriction) or SubtleCrypto
    // missing — silently skip; the passphrase prompt will be shown next time.
  }
}

/**
 * loadSessionKey() → openpgp.PrivateKey | null
 *
 * Attempts to unwrap and reconstruct the private key from localStorage.
 * Returns null if nothing is stored, the data is malformed, or any crypto
 * operation fails (e.g. after storage was tampered with).
 */
export async function loadSessionKey() {
  try {
    const rawWrapKeyHex = localStorage.getItem(SS_WRAP_KEY);
    const blobJSON      = localStorage.getItem(SS_WRAP_BLOB);
    if (!rawWrapKeyHex || !blobJSON) return null;

    const { iv: ivHex, data: dataHex } = JSON.parse(blobJSON);

    const subtle = crypto.subtle;
    const wrapKey = await subtle.importKey(
      'raw',
      hexDecode(rawWrapKeyHex),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const keyBytes = await subtle.decrypt(
      { name: 'AES-GCM', iv: hexDecode(ivHex) },
      wrapKey,
      hexDecode(dataHex)
    );

    return openpgp.readPrivateKey({ binaryKey: new Uint8Array(keyBytes) });
  } catch {
    // Corrupt / stale session data — clear it so we fall back to the prompt.
    clearSessionKey();
    return null;
  }
}

/**
 * clearSessionKey()
 *
 * Removes the session key material from localStorage. Called on logout.
 */
/**
 * loadSessionFingerprint() → string | null
 *
 * Returns the fingerprint of the key currently stored in the session cache,
 * without performing the full AES-GCM unwrap. Used by the read page to verify
 * the cached key belongs to the current user before attempting decryption.
 */
export function loadSessionFingerprint() {
  try {
    return localStorage.getItem(SS_FINGERPRINT);
  } catch {
    return null;
  }
}

export function clearSessionKey() {
  try {
    localStorage.removeItem(SS_WRAP_KEY);
    localStorage.removeItem(SS_WRAP_BLOB);
    localStorage.removeItem(SS_FINGERPRINT);
  } catch { /* ignore */ }
}

/**
 * exportSessionKey(pgpPassphrase) → { armoredKey: string, fingerprint: string }
 *
 * Loads the session key from localStorage, re-encrypts it with the supplied
 * passphrase using OpenPGP.js's built-in s2k, and returns the armored private
 * key suitable for writing to a recovery file.
 *
 * Throws if no session key is present, if localStorage is unavailable, or if
 * the passphrase is missing.
 */
export async function exportSessionKey(pgpPassphrase) {
  // Empty passphrase is allowed — the private key never leaves the user's
  // machine, analogous to an unprotected SSH key. The user's choice.
  pgpPassphrase = pgpPassphrase ?? '';
  const privateKey = await loadSessionKey();
  if (!privateKey) throw new Error('no session key found — please log out and log in again');
  const fingerprint = privateKey.getFingerprint().toUpperCase();
  const encryptedKey = await openpgp.encryptKey({ privateKey, passphrase: pgpPassphrase });
  const armoredKey = encryptedKey.armor();
  return { armoredKey, fingerprint };
}

// --------------------------------------------------------------------------
// Challenge/response authentication
// --------------------------------------------------------------------------

/**
 * signChallenge(privateKey, nonce) → string (armored detached signature)
 *
 * Signs the nonce string with the user's unlocked private key using a
 * detached PGP signature. The server verifies this against the stored
 * public key to authenticate the login.
 *
 * privateKey: an unlocked openpgp.PrivateKey (as returned by unlockPrivateKey).
 * nonce:      the plain-text nonce string returned by GET /api/v1/auth/challenge.
 *
 * Returns the ASCII-armored detached signature string.
 */
export async function signChallenge(privateKey, nonce) {
  const message = await openpgp.createMessage({ text: nonce });
  return openpgp.sign({
    message,
    signingKeys: privateKey,
    detached: true,
    format: 'armored',
  });
}

// --------------------------------------------------------------------------
// Encryption (compose page)
// --------------------------------------------------------------------------

/**
 * encryptMessage(bodyText, recipientArmoredKeys, senderPublicKeyArmored, signingKey)
 *   → string (armored PGP MESSAGE block)
 *
 * Encrypts bodyText for all recipientArmoredKeys. If senderPublicKeyArmored is
 * non-empty the sender's public key is auto-attached as an application/pgp-keys
 * MIME part inside the encrypted payload so the recipient can harvest it.
 * If signingKey is provided (unlocked openpgp.PrivateKey) the message is also
 * signed. Returns the ASCII-armored PGP MESSAGE block suitable for wrapping in
 * a PGP/MIME multipart/encrypted structure.
 *
 * recipientArmoredKeys: string[]  — ASCII-armored public keys
 * senderPublicKeyArmored: string | null
 * signingKey: openpgp.PrivateKey | null
 */
export async function encryptMessage(bodyText, recipientArmoredKeys, senderPublicKeyArmored, signingKey) {
  const encryptionKeys = await Promise.all(
    recipientArmoredKeys.map(k => openpgp.readKey({ armoredKey: k }))
  );

  // Also encrypt to the sender so they can decrypt their own sent mail.
  // Key distribution uses WKD; no need to embed the key in the payload.
  if (signingKey) {
    encryptionKeys.push(signingKey.toPublic());
  }

  const message = await openpgp.createMessage({ text: bodyText });
  return openpgp.encrypt({
    message,
    encryptionKeys,
    signingKeys: signingKey || undefined,
    format: 'armored',
  });
}

function _randomHex(n) {
  return Array.from(crypto.getRandomValues(new Uint8Array(n)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

/**
 * extractDecryptedBody(decrypted) → string
 *
 * The decrypted PGP payload may be either:
 *   a) plain text  — when no sender key was attached
 *   b) multipart/mixed  — body part + application/pgp-keys part
 *
 * In case (b) we extract just the text/plain part body.
 */
function extractDecryptedBody(decrypted) {
  // Find Content-Type header in the decrypted payload.
  const ctMatch = decrypted.match(/^Content-Type:\s*multipart\/[^\s;]+;\s*boundary="([^"]+)"/im);
  if (!ctMatch) {
    // encryptMessage() emits bare text with no MIME wrapper, so only strip a
    // leading header block when the payload actually has one — otherwise a
    // blank line inside the body would be mistaken for the header/body
    // separator and the first paragraph would be silently dropped.
    return stripMimeHeadersIfPresent(decrypted);
  }

  const boundary = ctMatch[1];
  const parts = decrypted.split('--' + boundary);
  for (const part of parts) {
    if (!part || part.startsWith('--')) continue; // delimiter or epilogue
    if (!/Content-Type:\s*text\/plain/i.test(part)) continue;
    const sep = part.indexOf('\r\n\r\n');
    if (sep !== -1) return part.slice(sep + 4).replace(/\r\n$/, '');
    const sep2 = part.indexOf('\n\n');
    if (sep2 !== -1) return part.slice(sep2 + 2).replace(/\n$/, '');
  }

  return decrypted;
}

function stripMimeHeadersIfPresent(text) {
  const sepMatch = text.match(/\r?\n\r?\n/);
  if (!sepMatch) return text;
  const headerBlock = text.slice(0, sepMatch.index);
  const looksLikeHeaders = headerBlock.split(/\r?\n/).every(line =>
    /^[A-Za-z][A-Za-z0-9-]*:/.test(line) || /^[ \t]/.test(line)
  );
  if (!looksLikeHeaders) return text;
  return text.slice(sepMatch.index + sepMatch[0].length);
}

/**
 * extractPGPBlock(rawRFC5322) → string | null
 *
 * Looks for a "-----BEGIN PGP MESSAGE-----" block in the raw message bytes.
 * Sufficient for PGP/MIME (RFC 3156): the encrypted payload lives in an
 * application/octet-stream MIME part whose body is a PGP message block.
 */
function extractPGPBlock(raw) {
  const start = raw.indexOf('-----BEGIN PGP MESSAGE-----');
  if (start === -1) return null;
  const end = raw.indexOf('-----END PGP MESSAGE-----', start);
  if (end === -1) return null;
  return raw.slice(start, end + '-----END PGP MESSAGE-----'.length);
}

/**
 * extractTextBody(rawRFC5322) → string
 *
 * Parses the MIME structure and returns the text/plain body.
 * Handles multipart/signed, multipart/mixed, and simple text/plain messages.
 * Decodes quoted-printable and base64 transfer encodings.
 */
function extractTextBody(raw) {
  const { headers, body } = mimeSplit(raw);
  const text = mimeExtractText(headers, body);
  return text !== null ? text : body;
}

function mimeSplit(text) {
  const crlf = text.indexOf('\r\n\r\n');
  if (crlf !== -1) return { headers: text.slice(0, crlf), body: text.slice(crlf + 4) };
  const lf = text.indexOf('\n\n');
  if (lf !== -1) return { headers: text.slice(0, lf), body: text.slice(lf + 2) };
  return { headers: '', body: text };
}

function mimeHeader(headers, name) {
  const unfolded = headers.replace(/\r?\n[ \t]+/g, ' ');
  const lines = unfolded.split(/\r?\n/);
  const lower = name.toLowerCase();
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    if (line.slice(0, colon).trim().toLowerCase() === lower) {
      return line.slice(colon + 1).trim();
    }
  }
  return '';
}

function mimeBoundary(ct) {
  const m = ct.match(/;\s*boundary="([^"]+)"/i) || ct.match(/;\s*boundary=([^\s;]+)/i);
  return m ? m[1] : null;
}

function mimeMultipartParts(body, boundary) {
  const delim = '--' + boundary;
  const parts = [];
  const lines = body.split(/\r?\n/);
  let inPart = false;
  let partLines = [];

  for (const line of lines) {
    if (line === delim + '--' || line === delim + '-- ') break;
    if (line === delim || line === delim + ' ') {
      if (inPart && partLines.length > 0) {
        parts.push(partLines.join('\n'));
        partLines = [];
      }
      inPart = true;
      continue;
    }
    if (inPart) partLines.push(line);
  }
  if (inPart && partLines.length > 0) parts.push(partLines.join('\n'));
  return parts;
}

function mimeExtractText(headers, body) {
  const ct = mimeHeader(headers, 'Content-Type') || 'text/plain';
  const mediaType = ct.split(';')[0].trim().toLowerCase();

  if (mediaType === 'text/plain') {
    const enc = mimeHeader(headers, 'Content-Transfer-Encoding').toLowerCase().trim();
    return mimeDecodeBody(body.replace(/\r?\n$/, ''), enc);
  }

  if (mediaType.startsWith('multipart/')) {
    const boundary = mimeBoundary(ct);
    if (!boundary) return null;
    for (const part of mimeMultipartParts(body, boundary)) {
      const { headers: ph, body: pb } = mimeSplit(part);
      const pct = mimeHeader(ph, 'Content-Type') || 'text/plain';
      const pMedia = pct.split(';')[0].trim().toLowerCase();
      if (pMedia === 'application/pgp-signature' || pMedia === 'application/pgp-keys') continue;
      const result = mimeExtractText(ph, pb);
      if (result !== null) return result;
    }
  }

  return null;
}

function mimeDecodeBody(body, encoding) {
  if (encoding === 'quoted-printable') {
    const unfolded = body.replace(/=\r?\n/g, '');
    const bytes = [];
    let i = 0;
    while (i < unfolded.length) {
      if (unfolded[i] === '=' && i + 2 < unfolded.length && /[0-9A-Fa-f]{2}/.test(unfolded.slice(i + 1, i + 3))) {
        bytes.push(parseInt(unfolded.slice(i + 1, i + 3), 16));
        i += 3;
      } else {
        bytes.push(unfolded.charCodeAt(i));
        i++;
      }
    }
    return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
  }
  if (encoding === 'base64') {
    try {
      const b = atob(body.replace(/\s+/g, ''));
      const arr = new Uint8Array(b.length);
      for (let i = 0; i < b.length; i++) arr[i] = b.charCodeAt(i);
      return new TextDecoder('utf-8').decode(arr);
    } catch { return body; }
  }
  return body;
}
