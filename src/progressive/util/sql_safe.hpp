#pragma once
#include <set>
#include <string>
#include <string_view>

namespace progressive::sql {

inline bool is_safe_identifier(std::string_view name) {
  static const std::set<std::string_view> whitelist = {"users",
                                                       "events",
                                                       "rooms",
                                                       "access_tokens",
                                                       "room_memberships",
                                                       "event_json",
                                                       "state_events",
                                                       "event_auth",
                                                       "device_inbox",
                                                       "event_relations",
                                                       "event_push_actions",
                                                       "event_push_summary",
                                                       "state_groups",
                                                       "state_groups_state",
                                                       "event_forward_extremities",
                                                       "event_to_state_groups",
                                                       "ui_auth_sessions",
                                                       "presence_state",
                                                       "event_txn_id",
                                                       "server_acl",
                                                       "timeline_gaps",
                                                       "user_filters",
                                                       "e2e_room_keys",
                                                       "e2e_room_keys_versions",
                                                       "event_search",
                                                       "thread_subscriptions",
                                                       "event_auth_chains",
                                                       "event_auth_chain_links",
                                                       "partial_state_rooms",
                                                       "refresh_tokens",
                                                       "room_retention",
                                                       "background_updates",
                                                       "scheduled_tasks",
                                                       "profiles",
                                                       "account_data",
                                                       "room_account_data",
                                                       "pushers",
                                                       "event_reports",
                                                       "room_aliases",
                                                       "read_markers",
                                                       "read_receipts",
                                                       "registration_tokens",
                                                       "user_ips",
                                                       "open_id_tokens",
                                                       "room_tags",
                                                       "appservice_txns",
                                                       "blocked_rooms",
                                                       "user_external_ids",
                                                       "sticky_events",
                                                       "user_approvals",
                                                       "email_queue",
                                                       "sliding_sync_connections",
                                                       "sliding_sync_joined_rooms",
                                                       "experimental_features",
                                                       "threepid_tokens",
                                                       "rendezvous_sessions"};
  for (char c : name)
    if (c == ';' || c == '-' || c == '\'')
      return false;
  if (name.size() > 64)
    return false;
  return whitelist.find(name) != whitelist.end();
}

}  // namespace progressive::sql
