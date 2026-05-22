-- v2: Add push_rules_enabled table for per-user push rule toggle state

CREATE TABLE IF NOT EXISTS push_rules_enabled (
    user_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    PRIMARY KEY (user_id, rule_id)
);
