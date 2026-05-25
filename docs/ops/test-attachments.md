# Attachment smoke test guide

End-to-end manual verification for the attachment feature added in Phase 4.
Run these checks against the dev stack (`./rookery start`).

## Prerequisites

```sh
./rookery start       # brings up rookery + postgres + mailpit at :8025
./rookery invite create  # get a signup URL, register at least one account
```

## 1. Compose encrypted message with attachments

1. Log in as a user who has their PGP key set up.
2. Go to `/compose`, enter a recipient who also has a registered key on the instance.
3. Click **attachments** → select a small file (≤ 10 KB) and a larger file (≤ 5 MB).
4. Verify the selected-files list updates with both filenames and sizes.
5. Hit **send**.
6. In mailpit (`http://localhost:8025`), open the raw message. Confirm the body is PGP-encrypted (`multipart/encrypted`) and the attachment content is not visible in plaintext.
7. Log in as the recipient account in a second tab, open the received message.
8. Confirm the attachment list appears below the decrypted body.
9. Click each attachment link — confirm the file downloads and the bytes match what was uploaded (compare checksums).

```sh
# Verify attachment bytes via gpg for a raw message copy:
# 1. Copy raw message bytes from mailpit
# 2. gpg --decrypt message.eml | gpg2mime | mpack -u > /tmp/parts
```

## 2. Compose plaintext message with attachment

1. Compose to a recipient with **no registered PGP key** (the key-status hint shows "no key — plaintext").
2. Attach a file.
3. Send.
4. In mailpit, open the raw message. Confirm `Content-Type: multipart/mixed` and the attachment is base64-encoded in plaintext.
5. Open the received message in the web UI. The attachment section shows a **server-rendered download link** (not a Blob URL).
6. Click the link — file downloads correctly.

Verify the attachments table:
```sh
./rookery psql -c "SELECT count(*) FROM message_attachments;"
# Should be > 0 for the plaintext message above and 0 for the encrypted one.
```

## 3. Size limit enforcement

1. Compose a message with a single file that is > 20 MB (e.g. `dd if=/dev/urandom of=/tmp/big.bin bs=1M count=22`).
2. Select the file. Hit **send**.
3. Confirm the status line shows "Total attachment size … exceeds the 20 MB limit" and the message is **not sent**.

## 4. Receive encrypted mail with attachment via `send-mail`

```sh
./rookery send-mail --encrypted --fetch-key alice@localhost
# inject a small plaintext file as the body; the tool wraps it in PGP/MIME.
```

Open the received message. Attachment list should populate after decryption.
Download and verify bytes.

## 5. Receive plaintext mail with attachment

Use mailpit's SMTP API or `swaks` to inject a multipart/mixed message:

```sh
swaks \
  --to alice@localhost \
  --from external@example.com \
  --server localhost:25 \
  --header 'MIME-Version: 1.0' \
  --header 'Content-Type: multipart/mixed; boundary=bound' \
  --body $'--bound\r\nContent-Type: text/plain\r\n\r\nHello\r\n--bound\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename="test.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--bound--'
```

1. Open alice's inbox — paperclip 📎 appears next to the message.
2. Open the message — attachment section shows "test.pdf" with a download link.
3. Click the link: `GET /api/v1/messages/{id}/attachments/0` → file downloads.

## 6. Inbox paperclip

Verify that:
- Messages with attachments show the 📎 icon in the inbox row.
- Messages without attachments show no icon.

## 7. Non-ASCII filename round-trip

1. Compose an encrypted message to a recipient with a key.
2. Attach a file named `résumé final.pdf` (rename it locally first if needed).
3. Send.
4. Open the received message, download the attachment.
5. Confirm the filename in the browser's download dialog is `résumé final.pdf`.

For plaintext, also verify the `Content-Disposition` header in the download response:
```sh
curl -sSI --cookie "rookery_session=..." \
  http://localhost:8080/api/v1/messages/{id}/attachments/0 \
  | grep -i content-disposition
# Should contain: filename*=UTF-8''r%C3%A9sum%C3%A9%20final.pdf
```

## 8. Error cases

| Scenario | Expected response |
|---|---|
| `GET /attachments/999` for a message that has only 1 attachment | 404 NOT_FOUND |
| `GET /attachments/0` for an encrypted message | 404 NOT_FOUND (decrypt in browser) |
| `GET /attachments/0` for a message owned by a different user | 404 NOT_FOUND |
| `POST /api/v1/messages` with raw message > 25 MB | 413 MESSAGE_TOO_LARGE |
