-- Migration: Add TOTP support to sys_users and performance indexes on sys_token_blacklist
-- Run this against your existing database. For fresh Docker setups, include in schema init.

-- TOTP fields on sys_users
ALTER TABLE sys_users
  ADD COLUMN IF NOT EXISTS totp_secret  VARCHAR(64)  DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN      NOT NULL DEFAULT FALSE;

-- Performance indexes on sys_token_blacklist
CREATE INDEX IF NOT EXISTS idx_token_blacklist_token
  ON sys_token_blacklist(token);

CREATE INDEX IF NOT EXISTS idx_token_blacklist_expiry
  ON sys_token_blacklist(expires_at);
