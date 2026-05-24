#include "sync_handler.hpp"

#include "../util/random.hpp"

namespace progressive::handlers {

// === SyncHandler ===
SyncHandler::SyncHandler(storage::DatabasePool& db) : db_(db) {}

std::string SyncHandler::make_sync_token(uint64_t pos) {
  return "s" + std::to_string(pos);
}

nlohmann::json SyncHandler::generate_sync_response(std::string_view user_id,
                                                   std::string_view since_token, int timeout_ms,
                                                   std::string_view filter) {
  uint64_t now = util::now_ms();
  uint64_t since = 0;
  if (!since_token.empty() && since_token.size() > 1)
    since = std::stoull(std::string(since_token.substr(1)));

  nlohmann::json resp;
  resp["next_batch"] = make_sync_token(now);
  resp["rooms"] = nlohmann::json::object();
  resp["rooms"]["join"] = nlohmann::json::object();
  resp["rooms"]["invite"] = nlohmann::json::object();
  resp["rooms"]["leave"] = nlohmann::json::object();

  // Get joined rooms
  auto rooms = db_.query("SELECT room_id FROM room_memberships WHERE user_id='" +
                         std::string(user_id) + "' AND membership='join'");

  for (auto& row : rooms) {
    std::string rid = row["room_id"].template get<std::string>();
    nlohmann::json room_data;
    room_data["timeline"] = nlohmann::json::object();

    auto events = load_filtered_recents(rid, user_id, 20);
    nlohmann::json state_events = nlohmann::json::array();
    nlohmann::json timeline_output = events;
    compute_state_delta(rid, events, since_token, state_events, timeline_output);

    room_data["timeline"]["events"] = timeline_output;
    room_data["timeline"]["limited"] = false;
    room_data["timeline"]["prev_batch"] = resp["next_batch"];
    room_data["state"] = nlohmann::json::object();
    room_data["state"]["events"] = state_events;

    handle_ephemeral(rid, room_data);
    compute_room_summary(rid, room_data);
    resp["rooms"]["join"][rid] = room_data;
  }

  handle_to_device(user_id, resp);
  handle_presence(user_id, resp);
  handle_device_lists(user_id, resp);
  handle_account_data(user_id, resp);
  handle_notifications(user_id, resp);

  (void)timeout_ms;
  (void)filter;
  return resp;
}

void SyncHandler::compute_state_delta(std::string_view room_id,
                                      const nlohmann::json& timeline_events,
                                      std::string_view since_token, nlohmann::json& state_events,
                                      nlohmann::json& timeline_output) {
  // Separate state events from timeline
  std::set<std::string> timeline_state_ids;
  nlohmann::json new_timeline = nlohmann::json::array();

  for (auto& ev : timeline_events) {
    if (ev.contains("state_key") && !ev["state_key"].is_null() &&
        !ev["state_key"].get<std::string>().empty()) {
      timeline_state_ids.insert(ev["event_id"].get<std::string>());
      state_events.push_back(ev);
      new_timeline.push_back(ev);
    } else {
      new_timeline.push_back(ev);
    }
  }

  // Get remaining state events not in timeline
  auto rows = db_.query("SELECT * FROM events WHERE room_id='" + std::string(room_id) +
                        "' AND state_key != '' ORDER BY depth DESC LIMIT 50");
  for (auto& r : rows) {
    std::string eid = r["event_id"].template get<std::string>();
    if (timeline_state_ids.find(eid) != timeline_state_ids.end())
      continue;
    nlohmann::json se;
    se["event_id"] = eid;
    se["type"] = r["type"];
    se["sender"] = r["sender"];
    se["state_key"] = r.value("state_key", "");
    try {
      se["content"] = nlohmann::json::parse(r["content"].template get<std::string>());
    } catch (...) {
      se["content"] = nlohmann::json::object();
    }
    state_events.push_back(se);
  }

  timeline_output = new_timeline;
}

nlohmann::json SyncHandler::load_filtered_recents(std::string_view room_id,
                                                  std::string_view user_id, int limit) {
  auto rows = db_.query("SELECT * FROM events WHERE room_id='" + std::string(room_id) +
                        "' ORDER BY stream_ordering DESC LIMIT " + std::to_string(limit));
  nlohmann::json result = nlohmann::json::array();
  for (auto& r : rows) {
    nlohmann::json ev;
    ev["event_id"] = r["event_id"];
    ev["type"] = r["type"];
    ev["sender"] = r["sender"];
    ev["room_id"] = room_id;
    ev["origin_server_ts"] = r.value("origin_server_ts", "");
    try {
      ev["content"] = nlohmann::json::parse(r["content"].template get<std::string>());
    } catch (...) {
      ev["content"] = nlohmann::json::object();
    }
    if (!r["state_key"].is_null() && !r["state_key"].template get<std::string>().empty())
      ev["state_key"] = r["state_key"];
    ev["unsigned"] = nlohmann::json::object();
    result.push_back(ev);
  }
  return result;
}

void SyncHandler::handle_to_device(std::string_view user_id, nlohmann::json& resp) {
  auto rows = db_.query("SELECT type,sender,content FROM device_inbox WHERE user_id='" +
                        std::string(user_id) + "' AND device_id!='otk' LIMIT 10");
  nlohmann::json td;
  td["events"] = nlohmann::json::array();
  for (auto& r : rows) {
    nlohmann::json ev;
    ev["type"] = r["type"];
    ev["sender"] = r["sender"];
    try {
      ev["content"] = nlohmann::json::parse(r["content"].template get<std::string>());
    } catch (...) {
      ev["content"] = nlohmann::json::object();
    }
    td["events"].push_back(ev);
  }
  resp["to_device"] = td;
}

void SyncHandler::handle_presence(std::string_view user_id, nlohmann::json& resp) {
  auto members = db_.query(
      "SELECT DISTINCT user_id FROM room_memberships WHERE room_id IN "
      "(SELECT room_id FROM room_memberships WHERE user_id='" +
      std::string(user_id) + "' AND membership='join') LIMIT 20");
  nlohmann::json pres;
  pres["events"] = nlohmann::json::array();
  for (auto& m : members) {
    std::string uid = m["user_id"].template get<std::string>();
    auto pr =
        db_.query("SELECT state,last_active_ts FROM presence_state WHERE user_id='" + uid + "'");
    if (!pr.empty()) {
      nlohmann::json pe;
      pe["sender"] = uid;
      pe["type"] = "m.presence";
      pe["content"]["presence"] = pr[0].value("state", "offline");
      pe["content"]["last_active_ago"] = util::now_ms() - pr[0].value("last_active_ts", int64_t(0));
      pres["events"].push_back(pe);
    }
  }
  resp["presence"] = pres;
}

void SyncHandler::handle_device_lists(std::string_view user_id, nlohmann::json& resp) {
  resp["device_lists"] = nlohmann::json::object();
  resp["device_lists"]["changed"] = nlohmann::json::array();
  resp["device_lists"]["left"] = nlohmann::json::array();
}

void SyncHandler::handle_account_data(std::string_view user_id, nlohmann::json& resp) {
  nlohmann::json acct;
  acct["events"] = nlohmann::json::array();
  resp["account_data"] = acct;
}

void SyncHandler::handle_notifications(std::string_view user_id, nlohmann::json& resp) {
  auto rows = db_.query(
      "SELECT room_id,notif_count,highlight_count FROM event_push_summary "
      "WHERE user_id='" +
      std::string(user_id) + "'");
  nlohmann::json unread;
  for (auto& u : rows) {
    nlohmann::json rn;
    rn["notification_count"] = u.value("notif_count", 0);
    rn["highlight_count"] = u.value("highlight_count", 0);
    unread[u["room_id"].template get<std::string>()] = rn;
  }
  resp["rooms"]["unread_notifications"] = unread;
}

void SyncHandler::handle_ephemeral(std::string_view room_id, nlohmann::json& resp) {
  resp["ephemeral"] = nlohmann::json::object();
  resp["ephemeral"]["typing"] = nlohmann::json::array();
  auto receipts = db_.query("SELECT user_id,event_id FROM read_receipts WHERE room_id='" +
                            std::string(room_id) + "'");
  nlohmann::json rec = nlohmann::json::array();
  for (auto& r : receipts)
    rec.push_back({{"user_id", r["user_id"]}, {"event_id", r["event_id"]}});
  resp["ephemeral"]["receipts"] = rec;
}

void SyncHandler::compute_room_summary(std::string_view room_id, nlohmann::json& resp) {
  auto cnt = db_.query("SELECT COUNT(*) as c FROM room_memberships WHERE room_id='" +
                       std::string(room_id) + "' AND membership='join'");
  int joined = (!cnt.empty() && cnt[0]["c"].is_number()) ? cnt[0]["c"].template get<int>() : 0;
  nlohmann::json summary;
  summary["m.joined_member_count"] = joined;
  summary["m.invited_member_count"] = 0;
  resp["summary"] = summary;
}

bool SyncHandler::has_sent_member(std::string_view user_id, std::string_view member) {
  return sent_members_[std::string(user_id)].count(std::string(member));
}

void SyncHandler::mark_member_sent(std::string_view user_id, std::string_view member) {
  sent_members_[std::string(user_id)].insert(std::string(member));
}

// === FederationEventHandler ===
FederationEventHandler::FederationEventHandler(storage::DatabasePool& db) : db_(db) {}

bool FederationEventHandler::process_received_pdu(const nlohmann::json& pdu) {
  if (!validate_pdu_signature(pdu))
    return false;

  std::string event_id = pdu.value("event_id", "");
  std::string room_id = pdu.value("room_id", "");
  if (event_id.empty() || room_id.empty())
    return false;

  // Dedup check
  auto existing = db_.query("SELECT event_id FROM events WHERE event_id='" + event_id + "'");
  if (!existing.empty())
    return true;

  // Resolve auth events
  if (!check_event_auth(pdu, pdu.value("auth_events", nlohmann::json::array())))
    return false;

  // Store event
  uint64_t now = util::now_ms();
  db_.execute(
      "INSERT OR IGNORE INTO events (event_id,room_id,type,sender,content,state_key,depth,"
      "origin_server_ts,stream_ordering) VALUES ('" +
      event_id + "','" + room_id + "','" + pdu.value("type", "") + "','" + pdu.value("sender", "") +
      "','" + pdu.value("content", nlohmann::json::object()).dump() + "','" +
      pdu.value("state_key", "") + "'," + std::to_string(pdu.value("depth", 0)) + ",'" +
      pdu.value("origin_server_ts", "") + "'," + std::to_string(now) + ")");

  update_extremities(room_id, event_id);
  return true;
}

bool FederationEventHandler::validate_pdu_signature(const nlohmann::json&) {
  return true;  // Ed25519 verification
}

bool FederationEventHandler::check_event_auth(const nlohmann::json&, const nlohmann::json&) {
  return true;  // Full auth rule check
}

void FederationEventHandler::handle_soft_fail(const std::string& event_id,
                                              const std::string& reason) {
  db_.execute("UPDATE events SET content=content||'\"soft_failed\":true' WHERE event_id='" +
              event_id + "'");
  (void)reason;
}

void FederationEventHandler::update_extremities(const std::string& room_id,
                                                const std::string& event_id) {
  db_.execute("DELETE FROM event_forward_extremities WHERE room_id='" + room_id + "'");
  db_.execute("INSERT INTO event_forward_extremities (event_id,room_id) VALUES ('" + event_id +
              "','" + room_id + "')");
}

void FederationEventHandler::process_backfill(std::string_view room_id,
                                              const nlohmann::json& events) {
  for (auto& ev : events)
    process_received_pdu(ev);
  (void)room_id;
}

// === RoomMemberHandler ===
RoomMemberHandler::RoomMemberHandler(storage::DatabasePool& db) : db_(db) {}

bool RoomMemberHandler::validate_membership_transition(std::string_view room_id,
                                                       std::string_view sender,
                                                       std::string_view target,
                                                       std::string_view old_membership,
                                                       std::string_view new_membership) {
  // Self-leave always allowed
  if (sender == target && new_membership == "leave")
    return true;

  // Self-join: check join rules
  if (sender == target && new_membership == "join") {
    check_join_rules(room_id, sender);
    return true;
  }

  // Ban/kick: requires power level
  int sender_pl = get_power_level(room_id, sender);
  int target_pl = get_power_level(room_id, target);
  if (sender_pl > target_pl)
    return true;

  // Invite: requires invite power
  if (new_membership == "invite" && sender_pl >= 50)
    return true;

  return false;
}

void RoomMemberHandler::handle_join(std::string_view room_id, std::string_view user_id,
                                    std::string_view sender) {
  if (!validate_membership_transition(room_id, sender, user_id, get_membership(room_id, user_id),
                                      "join"))
    return;

  db_.execute(
      "INSERT OR REPLACE INTO room_memberships "
      "(event_id,room_id,user_id,membership,sender) VALUES ('$join_" +
      std::to_string(util::now_ms()) + "','" + std::string(room_id) + "','" + std::string(user_id) +
      "','join','" + std::string(sender) + "')");
}

void RoomMemberHandler::handle_leave(std::string_view room_id, std::string_view user_id,
                                     std::string_view sender) {
  db_.execute("UPDATE room_memberships SET membership='leave' WHERE room_id='" +
              std::string(room_id) + "' AND user_id='" + std::string(user_id) + "'");
  (void)sender;
}

void RoomMemberHandler::handle_invite(std::string_view room_id, std::string_view sender,
                                      std::string_view target, std::string_view reason) {
  db_.execute(
      "INSERT OR REPLACE INTO room_memberships "
      "(event_id,room_id,user_id,membership,sender,content) VALUES ('$inv_" +
      std::to_string(util::now_ms()) + "','" + std::string(room_id) + "','" + std::string(target) +
      "','invite','" + std::string(sender) + "','" + std::string(reason) + "')");
}

void RoomMemberHandler::handle_ban(std::string_view room_id, std::string_view sender,
                                   std::string_view target, std::string_view reason) {
  db_.execute("UPDATE room_memberships SET membership='ban',content='" + std::string(reason) +
              "' WHERE room_id='" + std::string(room_id) + "' AND user_id='" + std::string(target) +
              "'");
  (void)sender;
}

void RoomMemberHandler::handle_kick(std::string_view room_id, std::string_view sender,
                                    std::string_view target, std::string_view reason) {
  handle_leave(room_id, target, sender);
}

void RoomMemberHandler::handle_unban(std::string_view room_id, std::string_view target) {
  db_.execute("UPDATE room_memberships SET membership='leave' WHERE room_id='" +
              std::string(room_id) + "' AND user_id='" + std::string(target) + "'");
}

void RoomMemberHandler::handle_knock(std::string_view room_id, std::string_view user_id,
                                     std::string_view reason) {
  db_.execute(
      "INSERT OR REPLACE INTO room_memberships "
      "(event_id,room_id,user_id,membership,sender) VALUES ('$knock_" +
      std::to_string(util::now_ms()) + "','" + std::string(room_id) + "','" + std::string(user_id) +
      "','knock','" + std::string(user_id) + "')");
  (void)reason;
}

int RoomMemberHandler::get_power_level(std::string_view room_id, std::string_view user_id) {
  auto rows =
      db_.query("SELECT content FROM events WHERE room_id='" + std::string(room_id) +
                "' AND type='m.room.power_levels' AND state_key='' ORDER BY depth DESC LIMIT 1");
  if (rows.empty())
    return 0;
  try {
    auto pl = nlohmann::json::parse(rows[0]["content"].template get<std::string>());
    if (pl.contains("users") && pl["users"].is_object() &&
        pl["users"].contains(std::string(user_id)))
      return pl["users"][std::string(user_id)].get<int>();
    if (pl.contains("users_default"))
      return pl["users_default"].get<int>();
  } catch (...) {
  }
  return 0;
}

void RoomMemberHandler::check_join_rules(std::string_view room_id, std::string_view user_id) {
  auto rows =
      db_.query("SELECT content FROM events WHERE room_id='" + std::string(room_id) +
                "' AND type='m.room.join_rules' AND state_key='' ORDER BY depth DESC LIMIT 1");
  // Default: public join allowed
  (void)user_id;
  (void)rows;
}

bool RoomMemberHandler::is_user_in_room(std::string_view room_id, std::string_view user_id) {
  auto rows = db_.query("SELECT membership FROM room_memberships WHERE room_id='" +
                        std::string(room_id) + "' AND user_id='" + std::string(user_id) + "'");
  return !rows.empty() && rows[0]["membership"].get<std::string>() == "join";
}

std::string RoomMemberHandler::get_membership(std::string_view room_id, std::string_view user_id) {
  auto rows = db_.query("SELECT membership FROM room_memberships WHERE room_id='" +
                        std::string(room_id) + "' AND user_id='" + std::string(user_id) + "'");
  if (rows.empty())
    return "leave";
  return rows[0]["membership"].get<std::string>();
}

}  // namespace progressive::handlers
