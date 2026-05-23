-- Reverse of migration 0003.
ALTER TABLE messages DROP COLUMN IF EXISTS message_id_header;
DROP TABLE IF EXISTS drafts;
DROP TABLE IF EXISTS outbound_queue;
DROP TABLE IF EXISTS dkim_keys;
