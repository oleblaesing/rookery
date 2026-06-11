import {
  loadSessionKey,
  loadSessionFingerprint,
  decryptMessage,
} from "../crypto.js";

(function () {
  "use strict";

  if (!/^\/messages\/[^/]+$/.test(location.pathname)) {
    return;
  }

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
      return;
    }

    document.addEventListener("DOMContentLoaded", fn);
  }

  ready(async function () {
    const bodyDiv = document.getElementById("message-body");
    const badgeEl = document.getElementById("security-badge");
    const noticeEl = document.getElementById("decrypting-notice");

    if (!bodyDiv) {
      return;
    }

    const msgID = bodyDiv.dataset.messageId;
    const secState = bodyDiv.dataset.securityState;
    const keyFingerprint = bodyDiv.dataset.keyFingerprint;
    const senderKeyB64 = bodyDiv.dataset.senderKeyB64 || "";
    const senderKey = senderKeyB64 ? atob(senderKeyB64) : null;
    const csrfToken =
      document.querySelector('meta[name="csrf-token"]')?.content || "";

    async function fetchRaw() {
      const resp = await fetch("/api/v1/messages/" + msgID + "/raw", {
        headers: { "X-CSRF-Token": csrfToken },
        credentials: "same-origin",
      });

      if (!resp.ok) {
        throw new Error("Failed to fetch message: " + resp.status);
      }

      return resp.text();
    }

    function renderBody(text) {
      const pre = document.createElement("pre");
      pre.className = "message-body-text";
      pre.textContent = text;
      bodyDiv.replaceChildren(pre);
    }

    // Revoke the object URLs we mint for attachment downloads when the page unloads.
    const blobURLs = [];
    window.addEventListener("beforeunload", function () {
      blobURLs.forEach(function (u) {
        URL.revokeObjectURL(u);
      });
    });

    // Only encrypted messages need client-side attachment rendering; plaintext
    // messages already have server-rendered download links, so an empty list
    // here leaves that section untouched.
    function renderAttachments(attachments) {
      const section = document.getElementById("attachment-list");

      if (!section) {
        return;
      }

      if (!attachments || attachments.length === 0) {
        return;
      }

      const ul =
        section.querySelector("#attachment-items") ||
        section.querySelector("ul");

      if (!ul) {
        return;
      }

      ul.innerHTML = "";
      attachments.forEach(function (att) {
        const blob = new Blob([att.bytes], {
          type: att.contentType || "application/octet-stream",
        });
        const url = URL.createObjectURL(blob);
        blobURLs.push(url);

        const a = document.createElement("a");
        a.href = url;
        a.download = att.filename || "attachment";
        a.textContent = att.filename || "attachment";
        a.className = "attachment-link";

        const li = document.createElement("li");
        li.className = "attachment-item";
        li.appendChild(a);
        ul.appendChild(li);
      });

      section.hidden = false;
    }

    function updateBadge(status, securityState) {
      if (!badgeEl) {
        return;
      }

      if (securityState === "pgp_encrypted") {
        const labels = {
          verified: "🔒 PGP encrypted — signature verified",
          unknown_key:
            "🔒 PGP encrypted — signature unverified (key not known)",
          invalid: "🔒 PGP encrypted — signature INVALID",
          none: "🔒 PGP encrypted — unsigned",
        };
        badgeEl.textContent = labels[status] || "🔒 PGP encrypted";
        badgeEl.className = "badge badge-encrypted";
      } else if (securityState === "pgp_signed_plaintext") {
        const labels = {
          verified: "🖋️ signed plaintext — signature verified",
          unknown_key:
            "🖋️ signed plaintext — signature unverified (key not known)",
          invalid: "⚠️ signed plaintext — signature INVALID",
          none: "⚠️ plaintext",
        };
        badgeEl.textContent = labels[status] || "🖋️ signed plaintext";
        badgeEl.className = "badge badge-signed";
      }
    }

    function showError(msg) {
      if (noticeEl) {
        noticeEl.textContent = msg;
        noticeEl.className = "error-notice";
      }
    }

    // Plaintext needs no key; attachments are already server-rendered.
    if (secState === "plaintext") {
      try {
        const raw = await fetchRaw();
        const { body } = await decryptMessage(raw, null);
        renderBody(body);
      } catch (err) {
        showError("Could not load message: " + err.message);
      }

      return;
    }

    // No session key, or it belongs to a different account: force a clean re-login.
    const sessionFP = loadSessionFingerprint();

    if (
      !sessionFP ||
      (keyFingerprint &&
        sessionFP.toUpperCase() !== keyFingerprint.toUpperCase())
    ) {
      window.location.replace("/logout");

      return;
    }

    const privateKey = await loadSessionKey();

    if (!privateKey) {
      window.location.replace("/logout");

      return;
    }

    try {
      if (noticeEl) {
        noticeEl.textContent = "decrypting…";
      }

      const raw = await fetchRaw();

      const { body, signatureStatus, attachments } = await decryptMessage(
        raw,
        privateKey,
        senderKey,
      );

      renderBody(body);
      updateBadge(signatureStatus, secState);
      renderAttachments(attachments);
    } catch (err) {
      showError("Decryption failed: " + err.message);
    }
  });
})();
