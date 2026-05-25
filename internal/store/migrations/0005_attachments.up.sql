-- message_attachments stores metadata for attachment parts extracted from
-- plaintext inbound messages at delivery time. Encrypted messages have no
-- rows here — the attachment list is reconstructed in the browser from the
-- raw RFC 5322 blob after PGP decryption (the server cannot see inside the
-- ciphertext).
--
-- Design: shape A.i (explicit table) was chosen over on-demand blob re-parse
-- because the download endpoint can locate a part by index without re-parsing
-- the full blob on each request, and the inbox has_attachments flag is already
-- set at inbound time so we walk the MIME tree anyway.
-- Trade-off: small INSERT overhead at inbound time for plaintext messages;
-- encrypted messages have zero rows and zero overhead.
--
-- part_index is the 0-based position among all attachment-eligible leaf parts
-- in the message, in depth-first traversal order. The download endpoint
-- re-walks the same tree to serve the part.
CREATE TABLE message_attachments (
    message_id   UUID    NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    part_index   INTEGER NOT NULL,
    filename     TEXT    NOT NULL DEFAULT '',
    content_type TEXT    NOT NULL DEFAULT 'application/octet-stream',
    size_bytes   BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY  (message_id, part_index)
);

CREATE INDEX idx_message_attachments_message_id ON message_attachments (message_id);
