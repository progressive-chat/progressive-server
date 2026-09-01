-- v4: Add version_checker table for tracking last update check

CREATE TABLE IF NOT EXISTS version_checker (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);

-- Insert initial value if not exists
INSERT OR IGNORE INTO version_checker (key, value) VALUES ('last_check_for_updates_id', 0);