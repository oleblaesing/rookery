-- Encrypted messages have no rows here — the browser reconstructs the list from
-- the raw blob after decryption (the server can't see inside the ciphertext).
-- An explicit table lets the download endpoint locate a part by index without
-- re-parsing the full blob per request.
-- part_index is the 0-based position among attachment-eligible leaf parts,
-- depth-first; the download endpoint re-walks the same tree to serve a part.
CREATE TABLE message_attachments (
    message_id   UUID    NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    part_index   INTEGER NOT NULL,
    filename     TEXT    NOT NULL DEFAULT '',
    content_type TEXT    NOT NULL DEFAULT 'application/octet-stream',
    size_bytes   BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY  (message_id, part_index)
);

CREATE INDEX idx_message_attachments_message_id ON message_attachments (message_id);
