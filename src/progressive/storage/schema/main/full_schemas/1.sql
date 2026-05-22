-- Progressive Server full schema v1
-- Matrix homeserver initial database schema

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    password_hash TEXT,
    creation_ts BIGINT NOT NULL,
    admin INTEGER DEFAULT 0,
    deactivated INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rooms (
    room_id TEXT PRIMARY KEY,
    is_public INTEGER DEFAULT 0,
    creator TEXT,
    room_version INTEGER DEFAULT 10,
    creation_ts BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    sender TEXT NOT NULL,
    content TEXT NOT NULL,
    state_key TEXT,
    depth BIGINT NOT NULL DEFAULT 0,
    origin_server_ts TEXT,
    outlier INTEGER DEFAULT 0,
    stream_ordering INTEGER
);

CREATE INDEX IF NOT EXISTS events_room_id ON events(room_id);
CREATE INDEX IF NOT EXISTS events_stream_ordering ON events(stream_ordering);
CREATE INDEX IF NOT EXISTS events_type ON events(type);

CREATE TABLE IF NOT EXISTS state_events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    PRIMARY KEY (room_id, type, state_key)
);

CREATE INDEX IF NOT EXISTS state_events_event ON state_events(event_id);

CREATE TABLE IF NOT EXISTS access_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    device_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS access_tokens_token ON access_tokens(token);

CREATE TABLE IF NOT EXISTS room_memberships (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    membership TEXT NOT NULL DEFAULT 'leave',
    sender TEXT NOT NULL,
    content TEXT,
    PRIMARY KEY (room_id, user_id)
);

CREATE TABLE IF NOT EXISTS event_auth (
    event_id TEXT NOT NULL,
    auth_id TEXT NOT NULL,
    PRIMARY KEY (event_id, auth_id)
);

CREATE TABLE IF NOT EXISTS event_edges (
    event_id TEXT NOT NULL,
    prev_event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    PRIMARY KEY (event_id, prev_event_id)
);

CREATE INDEX IF NOT EXISTS event_edges_prev ON event_edges(prev_event_id);

CREATE TABLE IF NOT EXISTS destinations (
    destination TEXT PRIMARY KEY,
    retry_interval BIGINT DEFAULT 0,
    retry_last_ts BIGINT,
    failure_ts BIGINT
);

CREATE TABLE IF NOT EXISTS push_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    priority_class INTEGER NOT NULL,
    conditions TEXT,
    actions TEXT NOT NULL,
    default_enabled INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS push_rules_user ON push_rules(user_id);
