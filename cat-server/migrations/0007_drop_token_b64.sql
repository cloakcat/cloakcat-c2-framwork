-- token_b64 was a legacy per-agent HMAC key used in v1; auth is now handled
-- entirely by SHARED_TOKEN + HKDF-derived keys.  The column is safe to drop.
ALTER TABLE agents DROP COLUMN IF EXISTS token_b64;
