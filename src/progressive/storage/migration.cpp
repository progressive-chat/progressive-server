#include "migration.hpp"

namespace progressive::storage {

MigrationRunner::MigrationRunner(DatabasePool& db, std::string_view /*schema_dir*/)
    : db_(db) {}

int MigrationRunner::current_version() {
  try {
    auto rows = db_.query("SELECT MAX(version) as ver FROM schema_version");
    if (!rows.empty() && rows[0].contains("ver") && !rows[0]["ver"].is_null())
      return rows[0]["ver"].get<int>();
  } catch (...) {}
  return 0;
}

int MigrationRunner::schema_compat_version() { return current_version(); }
void MigrationRunner::set_schema_compat_version(int) {}
void MigrationRunner::upgrade() {}
void MigrationRunner::rollback(int) {}
void MigrationRunner::bootstrap() { upgrade(); }
std::string MigrationRunner::dump_schema() { return ""; }
void MigrationRunner::write_schema_dump(const std::string&) {}
void MigrationRunner::validate_migrations() {}
void MigrationRunner::run_background_update(const std::string&) {}
void MigrationRunner::complete_background_update(const std::string&) {}
void MigrationRunner::register_background_update(const std::string&, const std::string&, int, int, bool) {}
std::string MigrationRunner::get_background_update_progress(const std::string&) { return "{}"; }
void MigrationRunner::update_background_progress(const std::string&, const std::string&) {}
void MigrationRunner::list_pending_background_updates() {}
void MigrationRunner::list_applied_migrations() {}

void apply_schema(DatabasePool& db) {
  const char* SCHEMA = R"SQL(
    CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, password_hash TEXT, creation_ts BIGINT, admin INTEGER DEFAULT 0, deactivated INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS access_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE, user_id TEXT, device_id TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS refresh_tokens (token TEXT PRIMARY KEY, user_id TEXT, access_token_id TEXT, next_token_id TEXT, expires_at BIGINT);
    CREATE TABLE IF NOT EXISTS rooms (room_id TEXT PRIMARY KEY, is_public INTEGER DEFAULT 0, creator TEXT, room_version INTEGER DEFAULT 10, creation_ts BIGINT);
    CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, room_id TEXT, type TEXT, sender TEXT, content TEXT, state_key TEXT, depth BIGINT DEFAULT 0, origin_server_ts TEXT, outlier INTEGER DEFAULT 0, stream_ordering INTEGER);
    CREATE INDEX IF NOT EXISTS events_room_id ON events(room_id);
    CREATE INDEX IF NOT EXISTS events_stream_ordering ON events(stream_ordering);
    CREATE TABLE IF NOT EXISTS event_json (event_id TEXT PRIMARY KEY, room_id TEXT, json TEXT);
    CREATE TABLE IF NOT EXISTS current_state_events (room_id TEXT, type TEXT, state_key TEXT, event_id TEXT, PRIMARY KEY(room_id,type,state_key));
    CREATE TABLE IF NOT EXISTS room_memberships (event_id TEXT, room_id TEXT, user_id TEXT, membership TEXT DEFAULT 'leave', sender TEXT, content TEXT, PRIMARY KEY (room_id, user_id));
    CREATE TABLE IF NOT EXISTS event_auth (event_id TEXT, auth_id TEXT, PRIMARY KEY (event_id, auth_id));
    CREATE TABLE IF NOT EXISTS event_auth_chains (event_id TEXT PRIMARY KEY, chain_id BIGINT, sequence_number BIGINT);
    CREATE INDEX IF NOT EXISTS event_auth_chains_cid ON event_auth_chains(chain_id);
    CREATE TABLE IF NOT EXISTS event_auth_chain_links (origin_chain_id BIGINT, origin_seq BIGINT, target_chain_id BIGINT, target_seq BIGINT);
    CREATE TABLE IF NOT EXISTS event_relations (event_id TEXT PRIMARY KEY, relates_to_id TEXT, relation_type TEXT, aggregation_key TEXT);
    CREATE TABLE IF NOT EXISTS event_forward_extremities (event_id TEXT, room_id TEXT, PRIMARY KEY (event_id, room_id));
    CREATE TABLE IF NOT EXISTS event_to_state_groups (event_id TEXT PRIMARY KEY, state_group INTEGER);
    CREATE TABLE IF NOT EXISTS state_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id TEXT, event_id TEXT);
    CREATE TABLE IF NOT EXISTS state_groups_state (state_group INTEGER, type TEXT, state_key TEXT, event_id TEXT, PRIMARY KEY (state_group, type, state_key));
    CREATE TABLE IF NOT EXISTS room_aliases (alias TEXT PRIMARY KEY, room_id TEXT, creator TEXT);
    CREATE TABLE IF NOT EXISTS room_alias_servers (room_alias TEXT, server TEXT, PRIMARY KEY(room_alias, server));
    CREATE TABLE IF NOT EXISTS room_depth (room_id TEXT PRIMARY KEY, min_depth BIGINT);
    CREATE TABLE IF NOT EXISTS room_tags_revisions (user_id TEXT, room_id TEXT, stream_id BIGINT);
    CREATE TABLE IF NOT EXISTS presence_state (user_id TEXT PRIMARY KEY, state TEXT DEFAULT 'offline', status_msg TEXT, last_active_ts BIGINT);
    CREATE TABLE IF NOT EXISTS presence_stream (stream_id BIGINT, user_id TEXT, state TEXT, last_active_ts BIGINT);
    CREATE TABLE IF NOT EXISTS device_inbox (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, device_id TEXT, type TEXT, sender TEXT, content TEXT, stream_id BIGINT);
    CREATE INDEX IF NOT EXISTS device_inbox_user ON device_inbox(user_id);
    CREATE TABLE IF NOT EXISTS read_markers (user_id TEXT, room_id TEXT, event_id TEXT, updated_ts BIGINT, PRIMARY KEY (user_id, room_id));
    CREATE TABLE IF NOT EXISTS read_receipts (user_id TEXT, room_id TEXT, event_id TEXT, updated_ts BIGINT, PRIMARY KEY (user_id, room_id));
    CREATE TABLE IF NOT EXISTS registration_tokens (token TEXT PRIMARY KEY, used INTEGER DEFAULT 0, created_ts BIGINT);
    CREATE TABLE IF NOT EXISTS ui_auth_sessions (session_id TEXT PRIMARY KEY, user_id TEXT, client_secret TEXT, server_data TEXT, creation_ts BIGINT);
    CREATE TABLE IF NOT EXISTS user_threepids (user_id TEXT, medium TEXT, address TEXT, validated_at BIGINT, added_at BIGINT, PRIMARY KEY(user_id, medium, address));
    CREATE TABLE IF NOT EXISTS user_filters (user_id TEXT, filter_id INTEGER, filter_json TEXT, PRIMARY KEY (user_id, filter_id));
    CREATE TABLE IF NOT EXISTS user_directory (user_id TEXT PRIMARY KEY, display_name TEXT, avatar_url TEXT);
    CREATE TABLE IF NOT EXISTS event_push_actions (event_id TEXT, user_id TEXT, room_id TEXT, profile_tag TEXT, actions TEXT, stream_ordering INTEGER, PRIMARY KEY (event_id, user_id));
    CREATE TABLE IF NOT EXISTS event_push_summary (user_id TEXT, room_id TEXT, notif_count INTEGER DEFAULT 0, highlight_count INTEGER DEFAULT 0, stream_ordering INTEGER, PRIMARY KEY (user_id, room_id));
    CREATE TABLE IF NOT EXISTS push_rules_stream (stream_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, rule_id TEXT, op TEXT);
    CREATE TABLE IF NOT EXISTS pushers (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, app_id TEXT, pushkey TEXT, kind TEXT, app_display_name TEXT, device_display_name TEXT, lang TEXT, data TEXT, last_token TEXT);
    CREATE TABLE IF NOT EXISTS pusher_throttle (pusher_id INTEGER, room_id TEXT, throttled_until BIGINT);
    CREATE TABLE IF NOT EXISTS event_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id TEXT, event_id TEXT, user_id TEXT, score INTEGER DEFAULT 0, reason TEXT, received_ts BIGINT);
    CREATE TABLE IF NOT EXISTS event_txn_id (event_id TEXT PRIMARY KEY, room_id TEXT, user_id TEXT, txn_id TEXT, ts BIGINT, UNIQUE(room_id, user_id, txn_id));
    CREATE TABLE IF NOT EXISTS local_media_repository (media_id TEXT PRIMARY KEY, media_type TEXT, media_length BIGINT, upload_name TEXT, user_id TEXT, created_ts BIGINT);
    CREATE TABLE IF NOT EXISTS remote_media_cache (media_id TEXT, media_origin TEXT, media_type TEXT, filesystem_id TEXT, created_ts BIGINT, PRIMARY KEY(media_id, media_origin));
    CREATE TABLE IF NOT EXISTS e2e_room_keys (user_id TEXT, room_id TEXT, session_id TEXT, first_message_index INTEGER, forwarded_count INTEGER, is_verified INTEGER, session_data TEXT, PRIMARY KEY (user_id, room_id, session_id));
    CREATE TABLE IF NOT EXISTS e2e_room_keys_versions (user_id TEXT, version TEXT, algorithm TEXT, auth_data TEXT, etag TEXT, PRIMARY KEY (user_id, version));
    CREATE TABLE IF NOT EXISTS device_lists_outbound_pokes (destination TEXT, user_id TEXT, stream_id BIGINT, sent BOOLEAN, ts BIGINT);
    CREATE TABLE IF NOT EXISTS device_lists_stream (stream_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, device_id TEXT);
    CREATE TABLE IF NOT EXISTS ratelimit_override (user_id TEXT PRIMARY KEY, messages_per_second BIGINT, burst_count BIGINT);
    CREATE TABLE IF NOT EXISTS server_keys_json (server_name TEXT, key_id TEXT, from_server TEXT, ts_added_ms BIGINT, ts_valid_until_ms BIGINT, key_json TEXT);
    CREATE TABLE IF NOT EXISTS received_transactions (transaction_id TEXT PRIMARY KEY, origin TEXT, received_ts BIGINT);
    CREATE TABLE IF NOT EXISTS application_services_state (as_id TEXT PRIMARY KEY, state TEXT, txn_id TEXT);
    CREATE TABLE IF NOT EXISTS background_updates (update_name TEXT PRIMARY KEY, progress_json TEXT DEFAULT '{}', depends_on TEXT);
    CREATE TABLE IF NOT EXISTS scheduled_tasks (task_id TEXT PRIMARY KEY, action TEXT, status TEXT DEFAULT 'scheduled', params TEXT, created_ts BIGINT);
    CREATE TABLE IF NOT EXISTS rejections (event_id TEXT PRIMARY KEY, reason TEXT, last_check TEXT);
    CREATE TABLE IF NOT EXISTS redactions (event_id TEXT PRIMARY KEY, redacts TEXT, have_censored INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS event_search (event_id TEXT PRIMARY KEY, room_id TEXT, sender TEXT, body TEXT, content TEXT);
    CREATE TABLE IF NOT EXISTS thread_subscriptions (user_id TEXT, room_id TEXT, thread_id TEXT, subscribed INTEGER DEFAULT 1, PRIMARY KEY (user_id, room_id, thread_id));
    CREATE TABLE IF NOT EXISTS ex_outlier_stream (event_stream_ordering BIGINT, event_id TEXT, state_group BIGINT);
    CREATE TABLE IF NOT EXISTS threepid_guest_access_tokens (medium TEXT, address TEXT, guest_access_token TEXT);
    CREATE TABLE IF NOT EXISTS partial_state_rooms (room_id TEXT PRIMARY KEY, joined_via TEXT, creation_ts BIGINT);
    CREATE TABLE IF NOT EXISTS room_retention (room_id TEXT PRIMARY KEY, max_lifetime BIGINT, min_lifetime BIGINT);
    CREATE TABLE IF NOT EXISTS server_acl (room_id TEXT PRIMARY KEY, allow_ip_literals INTEGER DEFAULT 0, allowed_servers TEXT, denied_servers TEXT);
    CREATE TABLE IF NOT EXISTS timeline_gaps (room_id TEXT, gap_start TEXT, gap_end TEXT, PRIMARY KEY (room_id, gap_start));
    CREATE TABLE IF NOT EXISTS worker_stream_positions (worker_name TEXT, stream_type INTEGER, position BIGINT, PRIMARY KEY(worker_name, stream_type));
    CREATE TABLE IF NOT EXISTS worker_locks (lock_name TEXT PRIMARY KEY, worker_name TEXT, acquired_ts BIGINT);
    CREATE TABLE IF NOT EXISTS replication_stream (stream_id INTEGER PRIMARY KEY AUTOINCREMENT, stream_type INTEGER, row_id BIGINT, data TEXT);
    INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (1, CURRENT_TIMESTAMP);
  )SQL";
  db.execute(SCHEMA);
}

}  // namespace progressive::storage
