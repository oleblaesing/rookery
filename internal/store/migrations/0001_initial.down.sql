-- Rollback for migration 0001.
DROP TABLE IF EXISTS known_keys;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS invites;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS reserved_local_parts;
ALTER TABLE users DROP CONSTRAINT IF EXISTS fk_users_primary_address;
ALTER TABLE domains DROP CONSTRAINT IF EXISTS fk_domains_owner;
DROP TABLE IF EXISTS addresses;
DROP TABLE IF EXISTS user_keys;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS domains;
DROP EXTENSION IF EXISTS pgcrypto;
