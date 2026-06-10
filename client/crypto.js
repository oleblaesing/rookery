import * as openpgp from "openpgp";

export async function generateKeypair(address, pgpPassphrase) {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ email: address }],
    passphrase: pgpPassphrase,
    format: "armored",
  });

  const pk = await openpgp.readKey({ armoredKey: publicKey });
  const fingerprint = pk.getFingerprint().toUpperCase();

  return {
    privateKeyArmored: privateKey,
    publicKeyArmored: publicKey,
    fingerprint,
  };
}

export async function unlockPrivateKey(
  encryptedPrivateKeyArmored,
  pgpPassphrase,
) {
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: encryptedPrivateKeyArmored,
  });

  return openpgp.decryptKey({ privateKey, passphrase: pgpPassphrase });
}

export async function readPrivateKey(armoredKey) {
  return openpgp.readPrivateKey({ armoredKey });
}

export function publicKeyArmoredFromPrivate(privateKey) {
  return privateKey.toPublic().armor();
}

export function buildRecoveryBlob(encryptedPrivateKeyArmored) {
  return new Blob([encryptedPrivateKeyArmored], { type: "text/plain" });
}

export async function decryptMessage(
  rawRFC5322,
  privateKey,
  senderPublicKeyArmored = null,
) {
  const pgpBlock = extractPGPBlock(rawRFC5322);

  if (!pgpBlock || !privateKey) {
    const body = extractTextBody(rawRFC5322);

    return { body, signatureStatus: "none", attachments: [] };
  }

  try {
    const message = await openpgp.readMessage({ armoredMessage: pgpBlock });

    const { data, signatures } = await openpgp.decrypt({
      message,
      decryptionKeys: privateKey,
      expectSigned: false,
    });

    const body = extractDecryptedBody(data);
    const attachments = parseMIMEAttachments(data);

    if (!signatures || signatures.length === 0) {
      return { body, signatureStatus: "none", attachments };
    }

    if (!senderPublicKeyArmored) {
      return { body, signatureStatus: "unknown_key", attachments };
    }

    try {
      const senderKey = await openpgp.readKey({
        armoredKey: senderPublicKeyArmored,
      });

      const message2 = await openpgp.readMessage({ armoredMessage: pgpBlock });

      const { signatures: sigs2 } = await openpgp.decrypt({
        message: message2,
        decryptionKeys: privateKey,
        verificationKeys: senderKey,
        expectSigned: false,
      });

      await sigs2[0].verified;

      return { body, signatureStatus: "verified", attachments };
    } catch {
      return { body, signatureStatus: "invalid", attachments };
    }
  } catch (err) {
    throw new Error("Decryption failed: " + err.message);
  }
}

const SS_WRAP_KEY = "rookery_swk";
const SS_WRAP_BLOB = "rookery_swb";
const SS_FINGERPRINT = "rookery_sfp";

function hexEncode(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexDecode(hex) {
  const out = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }

  return out;
}

export async function storeSessionKey(privateKey) {
  try {
    const subtle = crypto.subtle;

    // Clear first so a failure below can't leave the previous user's key cached.
    clearSessionKey();

    const keyBytes = privateKey.write();

    const wrapKey = await subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const wrapped = await subtle.encrypt(
      { name: "AES-GCM", iv },
      wrapKey,
      keyBytes,
    );

    const rawWrapKey = await subtle.exportKey("raw", wrapKey);

    localStorage.setItem(SS_WRAP_KEY, hexEncode(rawWrapKey));
    localStorage.setItem(
      SS_WRAP_BLOB,
      JSON.stringify({
        iv: hexEncode(iv),
        data: hexEncode(wrapped),
      }),
    );
    localStorage.setItem(
      SS_FINGERPRINT,
      privateKey.getFingerprint().toUpperCase(),
    );
  } catch {
    // localStorage/SubtleCrypto unavailable (e.g. private browsing) — skip
    // caching and fall back to the passphrase prompt next time.
  }
}

export async function loadSessionKey() {
  try {
    const rawWrapKeyHex = localStorage.getItem(SS_WRAP_KEY);
    const blobJSON = localStorage.getItem(SS_WRAP_BLOB);

    if (!rawWrapKeyHex || !blobJSON) {
      return null;
    }

    const { iv: ivHex, data: dataHex } = JSON.parse(blobJSON);

    const subtle = crypto.subtle;
    const wrapKey = await subtle.importKey(
      "raw",
      hexDecode(rawWrapKeyHex),
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );

    const keyBytes = await subtle.decrypt(
      { name: "AES-GCM", iv: hexDecode(ivHex) },
      wrapKey,
      hexDecode(dataHex),
    );

    return openpgp.readPrivateKey({ binaryKey: new Uint8Array(keyBytes) });
  } catch {
    // Corrupt/stale/tampered data — clear it so we fall back to the prompt.
    clearSessionKey();

    return null;
  }
}

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
  } catch {
    //
  }
}

export async function exportSessionKey(pgpPassphraseParam) {
  // Empty passphrase is allowed — the key never leaves the user's machine,
  // analogous to an unprotected SSH key. Their choice.
  const pgpPassphrase = pgpPassphraseParam ?? "";
  const privateKey = await loadSessionKey();

  if (!privateKey) {
    throw new Error("no session key found — please log out and log in again");
  }

  const fingerprint = privateKey.getFingerprint().toUpperCase();
  const encryptedKey = await openpgp.encryptKey({
    privateKey,
    passphrase: pgpPassphrase,
  });
  const armoredKey = encryptedKey.armor();

  return { armoredKey, fingerprint };
}

export async function signChallenge(privateKey, nonce) {
  const message = await openpgp.createMessage({ text: nonce });

  return openpgp.sign({
    message,
    signingKeys: privateKey,
    detached: true,
    format: "armored",
  });
}

export async function encryptMessage(
  bodyText,
  recipientArmoredKeys,
  senderPublicKeyArmored,
  signingKey,
) {
  const encryptionKeys = await Promise.all(
    recipientArmoredKeys.map((k) => openpgp.readKey({ armoredKey: k })),
  );

  // Keeping a rookery key (no seipdv2 bit) in the set pins SEIPDv1 — else a
  // recipient advertising seipdv2 (e.g. ProtonMail) upgrades the ciphertext
  // past what rookery can decrypt. Also lets the sender self-decrypt.
  if (senderPublicKeyArmored) {
    const senderKey = await openpgp.readKey({
      armoredKey: senderPublicKeyArmored,
    });
    const senderFp = senderKey.getFingerprint();

    if (!encryptionKeys.some((k) => k.getFingerprint() === senderFp)) {
      encryptionKeys.push(senderKey);
    }
  } else if (signingKey) {
    encryptionKeys.push(signingKey.toPublic());
  }

  const message = await openpgp.createMessage({ text: bodyText });

  return openpgp.encrypt({
    message,
    encryptionKeys,
    signingKeys: signingKey || undefined,
    format: "armored",
  });
}

export async function decryptArchive(privateKey, encryptedBytes) {
  const message = await openpgp.readMessage({ binaryMessage: encryptedBytes });

  const { data } = await openpgp.decrypt({
    message,
    decryptionKeys: privateKey,
    format: "binary",
    expectSigned: false,
  });

  // OpenPGP.js returns either a Uint8Array or a ReadableStream depending on
  // input size and version; normalise the stream case to a single buffer.
  if (data instanceof Uint8Array) {
    return data;
  }

  const reader = data.getReader();
  const chunks = [];
  let totalLen = 0;

  for (;;) {
    const { done, value } = await reader.read();

    if (done) {
      break;
    }

    chunks.push(value);
    totalLen += value.length;
  }

  const out = new Uint8Array(totalLen);
  let offset = 0;

  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }

  return out;
}

function extractDecryptedBody(decrypted) {
  const { headers, body } = mimeSplit(decrypted);

  if (headers && mimeHeader(headers, "Content-Type")) {
    const result = mimeExtractText(headers, body);

    if (result !== null) {
      return result;
    }
  }

  return stripMimeHeadersIfPresent(decrypted);
}

// Only strip a leading header block when one is actually present — else a blank
// line inside bare body text (as encryptMessage emits) is mistaken for the
// header/body separator and the first paragraph is lost.
function stripMimeHeadersIfPresent(text) {
  const sepMatch = text.match(/\r?\n\r?\n/);

  if (!sepMatch) {
    return text;
  }

  const headerBlock = text.slice(0, sepMatch.index);
  const looksLikeHeaders = headerBlock
    .split(/\r?\n/)
    .every(
      (line) => /^[A-Za-z][A-Za-z0-9-]*:/.test(line) || /^[ \t]/.test(line),
    );

  if (!looksLikeHeaders) {
    return text;
  }

  return text.slice(sepMatch.index + sepMatch[0].length);
}

function extractPGPBlock(raw) {
  const start = raw.indexOf("-----BEGIN PGP MESSAGE-----");

  if (start === -1) {
    return null;
  }

  const end = raw.indexOf("-----END PGP MESSAGE-----", start);

  if (end === -1) {
    return null;
  }

  return raw.slice(start, end + "-----END PGP MESSAGE-----".length);
}

function extractTextBody(raw) {
  const { headers, body } = mimeSplit(raw);
  const text = mimeExtractText(headers, body);

  return text !== null ? text : body;
}

function mimeSplit(text) {
  const crlf = text.indexOf("\r\n\r\n");

  if (crlf !== -1) {
    return { headers: text.slice(0, crlf), body: text.slice(crlf + 4) };
  }

  const lf = text.indexOf("\n\n");

  if (lf !== -1) {
    return { headers: text.slice(0, lf), body: text.slice(lf + 2) };
  }

  return { headers: "", body: text };
}

function mimeHeader(headers, name) {
  const unfolded = headers.replace(/\r?\n[ \t]+/g, " ");
  const lines = unfolded.split(/\r?\n/);
  const lower = name.toLowerCase();

  for (const line of lines) {
    const colon = line.indexOf(":");

    if (colon === -1) {
      continue;
    }

    if (line.slice(0, colon).trim().toLowerCase() === lower) {
      return line.slice(colon + 1).trim();
    }
  }

  return "";
}

// The bare media type from a Content-Type/Disposition value, e.g.
// "text/plain; charset=utf-8" → "text/plain".
function mediaTypeOf(headerValue) {
  return headerValue.split(";")[0].trim().toLowerCase();
}

function mimeBoundary(ct) {
  // boundary="..." (quoted) or boundary=... (unquoted, up to ; or whitespace).
  const match =
    ct.match(/;\s*boundary="([^"]+)"/i) || ct.match(/;\s*boundary=([^\s;]+)/i);

  return match ? match[1] : null;
}

function mimeMultipartParts(body, boundary) {
  const delim = "--" + boundary;
  // RFC 2046 allows trailing whitespace on the boundary line.
  const isSeparator = (line) => line === delim || line === delim + " ";
  const isClosing = (line) => line === delim + "--" || line === delim + "-- ";

  const parts = [];
  // null until the first boundary; an array once we're inside a part.
  let current = null;

  const flush = () => {
    if (current && current.length > 0) {
      parts.push(current.join("\n"));
    }
  };

  for (const line of body.split(/\r?\n/)) {
    if (isClosing(line)) {
      break;
    }

    if (isSeparator(line)) {
      flush();
      current = [];
      continue;
    }

    if (current) {
      current.push(line);
    }
  }

  flush();

  return parts;
}

function mimeExtractText(headers, body) {
  const ct = mimeHeader(headers, "Content-Type") || "text/plain";
  const mediaType = mediaTypeOf(ct);

  if (mediaType === "text/plain") {
    const enc = mimeHeader(headers, "Content-Transfer-Encoding")
      .toLowerCase()
      .trim();

    return mimeDecodeBody(body.replace(/\r?\n$/, ""), enc);
  }

  if (mediaType.startsWith("multipart/")) {
    const boundary = mimeBoundary(ct);

    if (!boundary) {
      return null;
    }

    for (const part of mimeMultipartParts(body, boundary)) {
      const { headers: ph, body: pb } = mimeSplit(part);
      const pct = mimeHeader(ph, "Content-Type") || "text/plain";
      const pMedia = mediaTypeOf(pct);

      if (
        pMedia === "application/pgp-signature" ||
        pMedia === "application/pgp-keys"
      ) {
        continue;
      }

      const result = mimeExtractText(ph, pb);

      if (result !== null) {
        return result;
      }
    }
  }

  return null;
}

export function parseMIMEAttachments(mimeText) {
  if (!mimeText) {
    return [];
  }

  const { headers, body } = mimeSplit(mimeText);

  if (!headers) {
    return [];
  }

  const result = [];
  collectMIMEAttachments(headers, body, result);

  return result;
}

function collectMIMEAttachments(headers, body, result) {
  const ct = mimeHeader(headers, "Content-Type") || "text/plain";
  const mediaType = mediaTypeOf(ct);
  const disp = mimeHeader(headers, "Content-Disposition").trim();
  const dispType = mediaTypeOf(disp);

  if (
    mediaType === "application/pgp-signature" ||
    mediaType === "application/pgp-keys" ||
    mediaType === "application/pgp-encrypted"
  ) {
    return;
  }

  // text/plain without an attachment disposition is the body, not an attachment.
  if (mediaType === "text/plain" && dispType !== "attachment") {
    return;
  }

  if (mediaType.startsWith("multipart/")) {
    const boundary = mimeBoundary(ct);

    if (!boundary) {
      return;
    }

    for (const part of mimeMultipartParts(body, boundary)) {
      const { headers: ph, body: pb } = mimeSplit(part);

      collectMIMEAttachments(ph, pb, result);
    }

    return;
  }

  const dispHeader = mimeHeader(headers, "Content-Disposition");
  const enc = mimeHeader(headers, "Content-Transfer-Encoding")
    .toLowerCase()
    .trim();

  const filename = mimeDecodeWord(
    mimeParamValue(dispHeader, "filename") || mimeParamValue(ct, "name") || "",
  );

  const bytes = mimeDecodeBodyBytes(body.replace(/\r?\n$/, ""), enc);

  result.push({ filename, contentType: mediaType, bytes });
}

function mimeParamValue(header, param) {
  if (!header) {
    return "";
  }

  const lower = param.toLowerCase();

  const rfc2231 = new RegExp(lower + "\\*=([^;\\s]+)", "i");
  const m2231 = header.match(rfc2231);

  if (m2231) {
    try {
      const v = m2231[1];
      const apos = v.indexOf("''");

      if (apos !== -1) {
        return decodeURIComponent(v.slice(apos + 2));
      }
    } catch {
      //
    }
  }

  const mQuoted = header.match(new RegExp(lower + '="([^"]*)"', "i"));

  if (mQuoted) {
    return mQuoted[1];
  }

  const mUnquoted = header.match(new RegExp(lower + "=([^;\\s]+)", "i"));

  if (mUnquoted) {
    return mUnquoted[1];
  }

  return "";
}

// One byte per char from a binary string (each char code is a 0–255 byte).
function latin1ToBytes(binary) {
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function base64ToBytes(b64) {
  return latin1ToBytes(atob(b64));
}

// RFC 2047 "Q" encoding: underscores are spaces, =XX are hex-escaped bytes.
function qEncodedToBytes(text) {
  const binary = text
    .replace(/_/g, " ")
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16)),
    );

  return latin1ToBytes(binary);
}

// RFC 2047 encoded-word: =?charset?B|Q?text?=
function mimeDecodeWord(str) {
  const encodedWord = /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g;

  return str.replace(encodedWord, (_, charset, encoding, text) => {
    try {
      const bytes =
        encoding.toUpperCase() === "B"
          ? base64ToBytes(text)
          : qEncodedToBytes(text);

      return new TextDecoder(charset).decode(bytes);
    } catch {
      return str;
    }
  });
}

function mimeDecodeBodyBytes(body, encoding) {
  if (encoding === "base64") {
    try {
      return base64ToBytes(body.replace(/\s+/g, ""));
    } catch {
      return new Uint8Array(0);
    }
  }

  if (encoding === "quoted-printable") {
    const text = mimeDecodeBody(body, "quoted-printable");

    return new TextEncoder().encode(text);
  }

  return new TextEncoder().encode(body);
}

function mimeDecodeBody(body, encoding) {
  if (encoding === "quoted-printable") {
    // Drop soft line breaks (=<CRLF>), then turn =XX hex escapes into bytes.
    // A lone "=" not followed by two hex digits is left as a literal.
    const binary = body
      .replace(/=\r?\n/g, "")
      .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16)),
      );

    return new TextDecoder("utf-8").decode(latin1ToBytes(binary));
  }
  if (encoding === "base64") {
    try {
      const bytes = base64ToBytes(body.replace(/\s+/g, ""));

      return new TextDecoder("utf-8").decode(bytes);
    } catch {
      return body;
    }
  }

  return body;
}
