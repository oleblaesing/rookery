-- Reverse migration 0008.

DROP INDEX IF EXISTS idx_outbound_queue_relay_client;

-- Relayed rows have no messages row; remove them before restoring NOT NULL.
DELETE FROM outbound_queue WHERE message_id IS NULL;

ALTER TABLE outbound_queue
    DROP COLUMN IF EXISTS relay_client_id,
    DROP COLUMN IF EXISTS mail_from,
    DROP COLUMN IF EXISTS blob_sha256,
    ALTER COLUMN message_id SET NOT NULL;

DROP TABLE IF EXISTS relay_clients;
