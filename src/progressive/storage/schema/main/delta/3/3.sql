-- v3: Add device_id to access_tokens (if not already)

-- SQLite doesn't support ADD COLUMN IF NOT EXISTS, but our schema uses INSERT OR REPLACE
-- This migration is a no-op for fresh installs with v1 full schema
SELECT 1;
