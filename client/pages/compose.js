import { loadSessionKey, encryptMessage } from "../crypto.js";

(function () {
  "use strict";

  // Single-asset bundle: only run on this page (see client/index.js).
  if (location.pathname !== "/compose") {
    return;
  }

  function ready(fn) {
    if (document.readyState !== "loading") {
      fn();
      return;
    }

    document.addEventListener("DOMContentLoaded", fn);
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');

    return meta ? meta.content : "";
  }

  function rfc2822Date(d) {
    const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const months = [
      "Jan",
      "Feb",
      "Mar",
      "Apr",
      "May",
      "Jun",
      "Jul",
      "Aug",
      "Sep",
      "Oct",
      "Nov",
      "Dec",
    ];
    const pad = (n) => (n < 10 ? "0" + n : "" + n);
    const tz = -d.getTimezoneOffset();
    const tzSign = tz >= 0 ? "+" : "-";
    const tzH = pad(Math.floor(Math.abs(tz) / 60));
    const tzM = pad(Math.abs(tz) % 60);

    return (
      days[d.getDay()] +
      ", " +
      d.getDate() +
      " " +
      months[d.getMonth()] +
      " " +
      d.getFullYear() +
      " " +
      pad(d.getHours()) +
      ":" +
      pad(d.getMinutes()) +
      ":" +
      pad(d.getSeconds()) +
      " " +
      tzSign +
      tzH +
      tzM
    );
  }

  function randomHex(n) {
    return Array.from(crypto.getRandomValues(new Uint8Array(n)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function generateBoundary() {
    return "rk-" + randomHex(12);
  }

  function generateMessageID(domain) {
    return "<" + randomHex(16) + "@" + domain + ">";
  }

  // OpenPGP.js armor and textarea input are LF-only; strict MIME parsers reject
  // mixed line endings, so collapse everything to CRLF.
  function normalizeCRLF(s) {
    return s.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n");
  }

  // btoa throws on non-ASCII, so widen through UTF-8 bytes first.
  function toBase64(str) {
    const bytes = new TextEncoder().encode(str);
    let binary = "";
    const len = bytes.length;

    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
  }

  // Spreading a whole file into fromCharCode at once overflows the call stack; chunk it.
  function uint8ToBase64(bytes) {
    const CHUNK = 0x8000;
    let binary = "";

    for (let i = 0; i < bytes.length; i += CHUNK) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }

    return btoa(binary);
  }

  function foldBase64(b64) {
    const lines = [];

    for (let i = 0; i < b64.length; i += 76) {
      lines.push(b64.slice(i, i + 76));
    }

    return lines.join("\r\n");
  }

  function encodeRFC2231(name) {
    return "utf-8''" + encodeURIComponent(name);
  }

  function formatBytes(n) {
    if (n < 1024) {
      return n + " B";
    }

    if (n < 1024 * 1024) {
      return (n / 1024).toFixed(1) + " KB";
    }

    return (n / (1024 * 1024)).toFixed(1) + " MB";
  }

  async function readAttachments(fileInput) {
    const files = Array.from(fileInput ? fileInput.files || [] : []);

    return Promise.all(
      files.map(async function (f) {
        const buf = await f.arrayBuffer();
        const b64 = uint8ToBase64(new Uint8Array(buf));

        return {
          name: f.name,
          type: f.type || "application/octet-stream",
          size: f.size,
          b64: b64,
        };
      }),
    );
  }

  const ASCII_PRINTABLE = /^[\x20-\x7E]*$/;

  function buildAttachmentPart(att) {
    const dispFilename = ASCII_PRINTABLE.test(att.name)
      ? 'filename="' + att.name + '"'
      : "filename*=" + encodeRFC2231(att.name);

    return (
      "Content-Type: " +
      att.type +
      "\r\n" +
      "Content-Disposition: attachment; " +
      dispFilename +
      "\r\n" +
      "Content-Transfer-Encoding: base64\r\n" +
      "\r\n" +
      foldBase64(att.b64)
    );
  }

  function buildPGPMIME(headers, pgpBlock) {
    const boundary = generateBoundary();
    const mimeHeaders = headers.concat([
      'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";',
      '\tboundary="' + boundary + '"',
    ]);
    const pgpBlockCRLF = normalizeCRLF(pgpBlock);

    const body = [
      "--" + boundary,
      "Content-Type: application/pgp-encrypted",
      "",
      "Version: 1",
      "",
      "--" + boundary,
      'Content-Type: application/octet-stream; name="encrypted.asc"',
      'Content-Disposition: inline; filename="encrypted.asc"',
      "",
      pgpBlockCRLF,
      "--" + boundary + "--",
    ].join("\r\n");

    return mimeHeaders.join("\r\n") + "\r\n\r\n" + body;
  }

  function buildPlaintextMessage(headers, body, attachments) {
    const normalized = normalizeCRLF(body);

    if (!attachments || attachments.length === 0) {
      const fullHeaders = headers.concat([
        "Content-Type: text/plain; charset=utf-8",
      ]);

      return fullHeaders.join("\r\n") + "\r\n\r\n" + normalized;
    }

    const boundary = generateBoundary();
    const fullHeaders = headers.concat([
      'Content-Type: multipart/mixed; boundary="' + boundary + '"',
    ]);
    let msg = fullHeaders.join("\r\n") + "\r\n\r\n";

    msg +=
      "--" +
      boundary +
      "\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n" +
      "Content-Transfer-Encoding: 8bit\r\n" +
      "\r\n" +
      normalized +
      "\r\n";

    attachments.forEach(function (att) {
      msg += "--" + boundary + "\r\n" + buildAttachmentPart(att) + "\r\n";
    });

    msg += "--" + boundary + "--\r\n";

    return msg;
  }

  // RFC 3156 §4: the encrypted payload is itself a MIME entity, so it needs its own
  // Content-Type. Without it ProtonMail and other strict clients reject the message —
  // as a decryption error, or "The MIMEType only allows 'text/html', or 'text/plain'"
  // when the user hits reply.
  //
  // senderKey, when present, is attached as an application/pgp-keys part so the
  // recipient's client can auto-harvest it for future encrypted replies. Any
  // attachments force the payload to multipart/mixed regardless of senderKey.
  function buildInnerMIME(body, senderKey, attachments) {
    const normalized = normalizeCRLF(body);
    const textPart =
      "Content-Type: text/plain; charset=utf-8\r\n" +
      "Content-Transfer-Encoding: 8bit\r\n" +
      "\r\n" +
      normalized;

    const hasKey = !!senderKey;
    const hasAtts = attachments && attachments.length > 0;

    if (!hasKey && !hasAtts) {
      return textPart;
    }

    const boundary = "rk-inner-" + randomHex(12);
    let result =
      'Content-Type: multipart/mixed; boundary="' +
      boundary +
      '"\r\n' +
      "\r\n" +
      "--" +
      boundary +
      "\r\n" +
      textPart +
      "\r\n";

    if (hasKey) {
      const keyNorm = normalizeCRLF(senderKey);
      result +=
        "--" +
        boundary +
        "\r\n" +
        "Content-Type: application/pgp-keys\r\n" +
        'Content-Disposition: attachment; filename="publickey.asc"\r\n' +
        "Content-Transfer-Encoding: 7bit\r\n" +
        "\r\n" +
        keyNorm +
        "\r\n";
    }

    (attachments || []).forEach(function (att) {
      result += "--" + boundary + "\r\n" + buildAttachmentPart(att) + "\r\n";
    });

    result += "--" + boundary + "--\r\n";

    return result;
  }

  ready(async function () {
    const form = document.getElementById("compose-form");

    if (!form) {
      return;
    }

    const fromAddress = form.dataset.from || "";
    let senderKey = "";

    if (form.dataset.senderKey) {
      try {
        senderKey = atob(form.dataset.senderKey);
      } catch (e) {
        console.error(
          "compose: data-sender-key is not valid base64; outgoing mail will not be signed",
          e,
        );
      }
    }

    const inReplyTo = form.dataset.inReplyTo || "";
    const references = form.dataset.references || "";
    const domain = fromAddress.includes("@")
      ? fromAddress.split("@")[1]
      : "localhost";

    const toInput = document.getElementById("compose-to");
    const keyHint = document.getElementById("key-status-hint");
    const statusEl = document.getElementById("compose-status");
    const sendBtn = document.getElementById("send-btn");
    const attachmentInput = document.getElementById("compose-attachments");
    const selectedFilesEl = document.getElementById("selected-files");

    if (attachmentInput && selectedFilesEl) {
      attachmentInput.addEventListener("change", function () {
        selectedFilesEl.innerHTML = "";
        Array.from(this.files || []).forEach(function (f) {
          const li = document.createElement("li");
          li.className = "selected-file";
          const name = document.createTextNode(f.name + " ");
          const size = document.createElement("span");
          size.className = "selected-file-size";
          size.textContent = "(" + formatBytes(f.size) + ")";
          li.appendChild(name);
          li.appendChild(size);
          selectedFilesEl.appendChild(li);
        });
      });
    }

    function fetchKeyStatus(address) {
      if (!address || !address.includes("@")) {
        if (keyHint) {
          keyHint.innerHTML = "";
        }

        return;
      }

      partials.swap(
        keyHint,
        "/partials/key-status?address=" + encodeURIComponent(address),
      );
    }

    const debouncedFetch = partials.debounce(fetchKeyStatus, 400);

    if (toInput) {
      toInput.addEventListener("input", function () {
        debouncedFetch(this.value.trim());
      });

      if (toInput.value.trim()) {
        fetchKeyStatus(toInput.value.trim());
      }
    }

    partials.onSubmit("#compose-form", async function (formData) {
      sendBtn.disabled = true;
      statusEl.textContent = "preparing…";

      const to = (formData.get("to") || "").trim();
      const subject = (formData.get("subject") || "").trim();
      const body = (formData.get("body") || "").trim();

      if (!to || !body) {
        statusEl.textContent = "To address and message body are required.";
        sendBtn.disabled = false;
        return;
      }

      const attachments = await readAttachments(attachmentInput);
      const totalAttachBytes = attachments.reduce(function (s, a) {
        return s + a.size;
      }, 0);
      const ATTACH_LIMIT = 20 * 1024 * 1024;

      if (totalAttachBytes > ATTACH_LIMIT) {
        statusEl.textContent =
          "Total attachment size (" +
          formatBytes(totalAttachBytes) +
          ") exceeds the 20 MB limit. Please remove some files.";
        sendBtn.disabled = false;
        return;
      }

      try {
        const baseHeaders = [
          "From: " + fromAddress,
          "To: " + to,
          "Subject: " + (subject || "(no subject)"),
          "Date: " + rfc2822Date(new Date()),
          "Message-ID: " + generateMessageID(domain),
          "MIME-Version: 1.0",
        ];

        if (inReplyTo) {
          baseHeaders.push("In-Reply-To: " + inReplyTo);
        }

        if (references) {
          baseHeaders.push("References: " + references);
        }

        const hintEl = keyHint ? keyHint.querySelector("[data-key-b64]") : null;
        const recipientKeyB64 = hintEl ? hintEl.dataset.keyB64 : null;

        let rawMessage;

        if (recipientKeyB64) {
          const attCount = attachments.length;
          statusEl.textContent =
            attCount > 0
              ? "encrypting (" +
                attCount +
                " attachment" +
                (attCount > 1 ? "s" : "") +
                ")…"
              : "encrypting…";
          const recipientKeyArmored = atob(recipientKeyB64);

          const privateKey = await loadSessionKey();

          const pgpBlock = await encryptMessage(
            buildInnerMIME(body, senderKey, attachments),
            [recipientKeyArmored],
            senderKey || null,
            privateKey || null,
          );

          rawMessage = buildPGPMIME(baseHeaders, pgpBlock);
        } else {
          statusEl.textContent = "sending (no key — plaintext)…";
          rawMessage = buildPlaintextMessage(baseHeaders, body, attachments);
        }

        const resp = await fetch("/api/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken(),
          },
          credentials: "same-origin",
          body: JSON.stringify({ message: toBase64(rawMessage), bcc: [] }),
        });

        if (resp.ok) {
          window.location.href = "/inbox?folder=sent";
        } else {
          const err = await resp
            .json()
            .catch(() => ({ message: "unknown error" }));
          statusEl.textContent = "Error: " + (err.message || resp.status);
          sendBtn.disabled = false;
        }
      } catch (err) {
        statusEl.textContent = "Error: " + err.message;
        sendBtn.disabled = false;
      }
    });
  });
})();
