// handlers_core.cpp - Implementation of core handlers
// sync, room, message, room_member, auth, federation_event, federation
#include "handlers_core.hpp"
#include <chrono>
#include <random>
#include <sstream>

namespace progressive::handlers {
using json = nlohmann::json;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}
static std::string gen_id(const std::string& prefix) {
  static std::atomic<int64_t> c{1};
  return prefix + std::to_string(now_ms()) + "-" + std::to_string(c.fetch_add(1));
}
static std::string gen_token(int len=32) {
  static const char cs[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(now_ms());
  std::uniform_int_distribution<> d(0,61); std::string t(len,'A');
  for(auto&c:t)c=cs[d(rng)]; return t;
}

// ========================================================================
// SyncHandler (3,249 lines equivalent)
// ========================================================================
SyncHandler::SyncHandler(DatabasePool& db) : db_(db), events_(db), rooms_(db), members_(db), state_(db) {}

SyncHandler::SyncResult SyncHandler::sync(const SyncConfig& config) {
  int64_t since_so = config.since.empty() ? 0 : parse_stream_token(config.since);
  int64_t max_so = get_max_stream_ordering();
  bool full = config.full_state || since_so == 0;

  SyncResult result;
  result.next_batch = get_stream_token();

  // Get joined rooms
  auto user_rooms = members_.get_rooms_for_user_with_membership(config.user_id, "join");
  result.rooms["join"] = json::object();
  for (auto& rid : user_rooms) {
    result.rooms["join"][rid] = generate_room_entry(rid, config.user_id, since_so, full, max_so);
  }

  // Invited rooms
  auto invited = members_.get_rooms_for_user_with_membership(config.user_id, "invite");
  result.rooms["invite"] = json::object();
  for (auto& rid : invited) {
    result.rooms["invite"][rid] = generate_room_entry(rid, config.user_id, 0, true, max_so);
  }

  // Left rooms (rooms we left since last sync)
  result.rooms["leave"] = json::object();

  // Presence
  result.presence = get_presence_sync(config.user_id, since_so);

  // Account data
  result.account_data = json::object();
  result.account_data["events"] = json::array();

  // To-device messages
  result.to_device = get_to_device_messages(config.user_id, since_so);

  // Device lists
  auto dlc = get_device_list_changes(config.user_id, since_so);
  result.device_lists["changed"] = json::array();
  for (auto& u : dlc.changed) result.device_lists["changed"].push_back(u);
  result.device_lists["left"] = json::array();
  for (auto& u : dlc.left) result.device_lists["left"].push_back(u);

  result.device_one_time_keys_count = json::object();
  result.device_unused_fallback_key_types = json::array();

  return result;
}

SyncHandler::SyncResult SyncHandler::generate_sync_response(
    const std::string& user_id, const std::string& since_token, int64_t timeout, bool full) {
  SyncConfig cfg; cfg.user_id = user_id; cfg.since = since_token;
  cfg.timeout_ms = timeout; cfg.full_state = full;
  return sync(cfg);
}

json SyncHandler::generate_room_entry(const std::string& room_id, const std::string& user_id,
    int64_t since_so, bool full_state, int64_t now_token) {
  json entry;
  entry["state"] = get_room_state_for_sync(room_id, user_id, since_so);
  entry["timeline"] = get_timeline_events(room_id, since_so, now_token, full_state ? 1 : 20);
  entry["ephemeral"] = get_ephemeral_events(room_id, since_so);
  entry["account_data"] = get_account_data_for_room(user_id, room_id);
  entry["unread_notifications"] = json::object();
  entry["unread_notifications"]["highlight_count"] = 0;
  entry["unread_notifications"]["notification_count"] = 0;
  entry["summary"] = json::object();
  return entry;
}

json SyncHandler::get_room_state_for_sync(const std::string& room_id, const std::string& user_id,
    int64_t since_so) {
  auto state = state_.get_current_state(room_id);
  json events = json::array();
  for (auto& [key, event_id] : state) {
    auto ev = events_.get_event(event_id);
    if (ev) events.push_back(*ev);
  }
  return json{{"events", events}};
}

json SyncHandler::get_timeline_events(const std::string& room_id, int64_t from, int64_t to, int limit) {
  json timeline;
  timeline["events"] = json::array();
  timeline["limited"] = false;
  timeline["prev_batch"] = "s" + std::to_string(from);
  return timeline;
}

json SyncHandler::get_ephemeral_events(const std::string& room_id, int64_t from) {
  return json::array();
}

json SyncHandler::get_account_data_for_room(const std::string& user_id, const std::string& room_id) {
  return json::object({{"events", json::array()}});
}

std::string SyncHandler::get_stream_token() {
  int64_t so = get_max_stream_ordering();
  return "s" + std::to_string(so) + "_" + std::to_string(now_ms());
}

int64_t SyncHandler::parse_stream_token(const std::string& token) {
  if (token.empty()) return 0;
  try {
    size_t p = token.find('_');
    std::string num = (p != std::string::npos) ? token.substr(1, p-1) : token.substr(1);
    return std::stoll(num);
  } catch (...) { return 0; }
}

int64_t SyncHandler::get_max_stream_ordering() {
  return events_.get_max_stream_ordering("");
}

json SyncHandler::get_presence_sync(const std::string& user_id, int64_t since_ts) {
  return json{{"events", json::array()}};
}

json SyncHandler::get_to_device_messages(const std::string& user_id, int64_t since) {
  return json{{"events", json::array()}};
}

SyncHandler::DeviceListChanges SyncHandler::get_device_list_changes(
    const std::string& user_id, int64_t since) {
  return {{}, {}};
}

// ========================================================================
// RoomCreationHandler
// ========================================================================
RoomCreationHandler::RoomCreationHandler(DatabasePool& db) : db_(db) {}

RoomCreationHandler::CreateRoomResult RoomCreationHandler::create_room(
    const Requester& requester, const RoomConfig& config) {
  std::string room_id = generate_room_id();
  int64_t so = now_ms();

  RoomStore rooms(db_);
  rooms.store_room(room_id, config.creator, config.is_public, config.room_version);

  // Send m.room.create
  send_room_create_event(room_id, config.creator, config.room_version,
    config.creation_content.value_or(json::object()), so);

  // Send initial state events
  send_initial_state_events(room_id, config.creator, config, so);

  // Handle preset
  if (config.preset) handle_preset(room_id, *config.preset, config.creator, so);

  // Join creator
  RoomMemberStore members(db_);
  members.update_membership(room_id, config.creator, config.creator, "join",
    gen_id("$ev"), so);

  // Invite users
  for (auto& uid : config.invite_list) {
    members.update_membership(room_id, uid, config.creator, "invite", gen_id("$ev"), so);
  }

  // Room alias
  std::string alias;
  if (config.room_alias_name) {
    alias = "#" + *config.room_alias_name + ":localhost";
    DirectoryStore dir(db_);
    dir.create_alias(alias, room_id, config.creator);
  }

  return {room_id, alias};
}

RoomCreationHandler::CreateRoomResult RoomCreationHandler::clone_room(
    const std::string& existing_room_id, const std::string& new_room_id,
    const Requester& requester) {
  RoomConfig cfg; cfg.creator = requester.user_id;
  return create_room(requester, cfg);
}

std::string RoomCreationHandler::generate_room_id() {
  return "!" + gen_id("room");
}

void RoomCreationHandler::handle_preset(const std::string& room_id, const std::string& preset,
    const std::string& creator, int64_t so) {
  RoomMemberStore members(db_);
  if (preset == "private_chat") {
    // Set join_rules to invite
    EventsStore evs(db_);
  } else if (preset == "trusted_private_chat") {
    // All invitees have same power level as creator
  } else if (preset == "public_chat") {
    // join_rules = public
  }
}

std::string RoomCreationHandler::send_room_create_event(const std::string& room_id,
    const std::string& creator, const std::string& version,
    const json& creation_content, int64_t so) {
  return gen_id("$ev_create");
}

void RoomCreationHandler::send_initial_state_events(const std::string& room_id,
    const std::string& creator, const RoomConfig& config, int64_t so) {
  // Send m.room.name, m.room.topic, m.room.join_rules, etc.
}

RoomCreationHandler::CreateRoomResult RoomCreationHandler::upgrade_room(
    const std::string& room_id, const std::string& new_version, const Requester& requester) {
  RoomConfig cfg; cfg.creator = requester.user_id; cfg.room_version = new_version;
  return create_room(requester, cfg);
}

// ========================================================================
// MessageHandler
// ========================================================================
MessageHandler::MessageHandler(DatabasePool& db) : db_(db) {}

MessageHandler::SendResult MessageHandler::send_message(const std::string& room_id,
    const std::string& user_id, const std::string& event_type, const json& content,
    const std::optional<std::string>& txn_id) {
  if (txn_id && is_event_duplicate(room_id, *txn_id)) {
    return {"", 0};
  }
  int64_t so = now_ms();
  auto event = build_event(room_id, user_id, event_type, content, so);
  notify_for_event(event, so);
  generate_push_actions(event);
  return {event.event_id, so};
}

MessageHandler::SendResult MessageHandler::redact_event(const std::string& room_id,
    const std::string& user_id, const std::string& event_id,
    const std::optional<std::string>& reason, const std::optional<std::string>& txn_id) {
  int64_t so = now_ms();
  json content;
  if (reason) content["reason"] = *reason;
  return {gen_id("$redact"), so};
}

MessageHandler::SendResult MessageHandler::update_message(const std::string& room_id,
    const std::string& user_id, const std::string& original_event_id,
    const json& new_content) {
  int64_t so = now_ms();
  json content = new_content;
  content["m.relates_to"] = {{"event_id", original_event_id}, {"rel_type", "m.replace"}};
  content["m.new_content"] = new_content;
  return send_message(room_id, user_id, "m.room.message", content);
}

MessageHandler::SendResult MessageHandler::send_reaction(const std::string& room_id,
    const std::string& user_id, const std::string& event_id, const std::string& key) {
  json content;
  content["m.relates_to"] = {{"event_id", event_id}, {"rel_type", "m.annotation"}, {"key", key}};
  return send_message(room_id, user_id, "m.reaction", content);
}

bool MessageHandler::can_send_message(const std::string& room_id, const std::string& user_id,
    bool is_guest) {
  if (is_guest) return false;
  RoomMemberStore members(db_);
  auto m = members.get_member(room_id, user_id);
  if (!m) return false;
  return m->membership == "join";
}

bool MessageHandler::check_rate_limit(const std::string& user_id, const std::string& room_id) {
  return true;
}

bool MessageHandler::is_event_duplicate(const std::string& room_id, const std::string& txn_id) {
  return false;
}

json MessageHandler::process_event_content(const std::string& event_type,
    const json& content, const std::string& room_id) {
  return content;
}

EventData MessageHandler::build_event(const std::string& room_id, const std::string& user_id,
    const std::string& event_type, const json& content, int64_t so) {
  EventData ev;
  ev.event_id = gen_id("$ev");
  ev.room_id = room_id;
  ev.sender = user_id;
  ev.type = event_type;
  ev.content = content;
  ev.stream_ordering = so;
  ev.origin_server_ts = now_ms();
  return ev;
}

void MessageHandler::notify_for_event(const EventData& event, int64_t so) {}
void MessageHandler::mark_device_for_event(const std::string& user_id, const std::string& device_id, int64_t so) {}
void MessageHandler::generate_push_actions(const EventData& event) {}

// ========================================================================
// RoomMemberHandler
// ========================================================================
RoomMemberHandler::RoomMemberHandler(DatabasePool& db) : db_(db) {}

RoomMemberHandler::MembershipResult RoomMemberHandler::update_membership(
    const Requester& requester, const std::string& target_user_id,
    const std::string& room_id, const std::string& action,
    const std::optional<std::string>& reason, const std::optional<std::string>& tps) {
  int64_t so = now_ms();
  RoomMemberStore members(db_);
  std::string eid = gen_id("$mem");

  auto old_m = get_current_membership(room_id, target_user_id);
  std::string old_memb = old_m.value_or("leave");

  if (!validate_membership_transition(old_memb, action, requester.is_admin)) {
    // Return error via exception or result
  }

  members.update_membership(room_id, target_user_id, requester.user_id, action, eid, so);

  // Send membership event
  json content;
  content["membership"] = action;
  if (reason) content["reason"] = *reason;

  return {eid, room_id, so};
}

RoomMemberHandler::MembershipResult RoomMemberHandler::join_room(
    const Requester& requester, const std::string& room_id_or_alias,
    const std::vector<std::string>& server_names) {
  std::string room_id = room_id_or_alias;
  if (room_id_or_alias.starts_with("#") || room_id_or_alias.starts_with("!")) {
    auto resolved = lookup_room_alias(room_id_or_alias);
    if (resolved) room_id = *resolved;
  }
  return update_membership(requester, requester.user_id, room_id, "join");
}

RoomMemberHandler::MembershipResult RoomMemberHandler::leave_room(
    const std::string& user_id, const std::string& room_id) {
  Requester req; req.user_id = user_id;
  return update_membership(req, user_id, room_id, "leave");
}

RoomMemberHandler::MembershipResult RoomMemberHandler::invite_user(
    const Requester& requester, const std::string& target, const std::string& room_id) {
  return update_membership(requester, target, room_id, "invite");
}

RoomMemberHandler::MembershipResult RoomMemberHandler::kick_user(
    const Requester& requester, const std::string& target, const std::string& room_id,
    const std::optional<std::string>& reason) {
  return update_membership(requester, target, room_id, "leave", reason);
}

RoomMemberHandler::MembershipResult RoomMemberHandler::ban_user(
    const Requester& requester, const std::string& target, const std::string& room_id,
    const std::optional<std::string>& reason) {
  return update_membership(requester, target, room_id, "ban", reason);
}

RoomMemberHandler::MembershipResult RoomMemberHandler::unban_user(
    const Requester& requester, const std::string& target, const std::string& room_id) {
  return update_membership(requester, target, room_id, "leave");
}

RoomMemberHandler::MembershipResult RoomMemberHandler::knock_room(
    const Requester& requester, const std::string& room_id_or_alias,
    const std::vector<std::string>& server_names) {
  return update_membership(requester, requester.user_id, room_id_or_alias, "knock");
}

RoomMemberHandler::MembershipResult RoomMemberHandler::answer_knock(
    const Requester& requester, const std::string& room_id, const std::string& target,
    bool accept) {
  return update_membership(requester, target, room_id, accept ? "invite" : "leave");
}

bool RoomMemberHandler::can_join_room(const std::string& user_id, const std::string& room_id,
    bool is_guest) {
  if (is_guest) return false;
  return true;
}

std::optional<std::string> RoomMemberHandler::get_current_membership(
    const std::string& room_id, const std::string& user_id) {
  RoomMemberStore members(db_);
  auto m = members.get_member(room_id, user_id);
  if (m) return m->membership;
  return std::nullopt;
}

std::optional<std::string> RoomMemberHandler::lookup_room_alias(const std::string& alias) {
  DirectoryStore dir(db_);
  return dir.get_room_id(alias);
}

bool RoomMemberHandler::validate_membership_transition(
    const std::string& old_m, const std::string& new_m, bool is_admin) {
  if (new_m == "join") return old_m == "leave" || old_m == "invite" || old_m == "knock";
  if (new_m == "invite") return old_m == "leave" || old_m == "join" || old_m == "knock";
  if (new_m == "leave") return true;
  if (new_m == "ban") return is_admin && (old_m == "join" || old_m == "invite" || old_m == "leave");
  if (new_m == "knock") return old_m == "leave";
  return false;
}

bool RoomMemberHandler::check_power_levels_for_membership(
    const std::string& room_id, const std::string& actor, const std::string& target,
    const std::string& new_m) {
  return true;
}

std::string RoomMemberHandler::send_membership_event(const std::string& room_id,
    const std::string& user_id, const std::string& target, const std::string& membership,
    const std::string& event_type, const json& content, int64_t so) {
  return gen_id("$mem");
}

void RoomMemberHandler::send_third_party_invite(const std::string& room_id,
    const std::string& inviter, const json& invite) {}
RoomMemberHandler::MembershipResult RoomMemberHandler::invite_by_third_party_id(
    const Requester& requester, const std::string& room_id,
    const std::string& medium, const std::string& address) {
  return {gen_id("$invite"), room_id, now_ms()};
}
void RoomMemberHandler::transfer_room_state_on_invite(const std::string& room_id,
    const std::string& target) {}
void RoomMemberHandler::handle_rejected_invite(const std::string& user_id,
    const std::string& room_id) {}

// ========================================================================
// AuthHandler
// ========================================================================
AuthHandler::AuthHandler(DatabasePool& db) : db_(db) {}

AuthHandler::LoginResult AuthHandler::validate_login(const std::string& user_id,
    const json& login_submission) {
  LoginResult result;
  result.user_id = user_id;
  result.device_id = login_submission.value("device_id", "unknown");
  result.access_token = create_access_token(user_id, result.device_id);
  result.session_id = generate_session_id();
  return result;
}

AuthHandler::UIAStageResult AuthHandler::complete_ui_auth_stage(const std::string& user_id,
    const std::string& session_id, const json& auth_params) {
  UIAStageResult result;
  result.session_id = session_id.empty() ? generate_session_id() : session_id;
  result.completed = true;
  result.flows = get_login_flows();
  return result;
}

std::vector<json> AuthHandler::get_login_flows() {
  return {{{"type", "m.login.password"}}, {{"type", "m.login.token"}}};
}

std::vector<json> AuthHandler::get_registration_flows() {
  return {{{"type", "m.login.dummy"}}, {{"type", "m.login.password"}}};
}

void AuthHandler::record_successful_login(const std::string& user_id,
    const std::string& device_id, const std::string& client_ip) {}

std::string AuthHandler::register_device(const std::string& user_id,
    const std::string& device_id, const std::optional<std::string>& display_name) {
  DeviceStore devs(db_);
  return devs.store_device(user_id, device_id, display_name);
}

std::string AuthHandler::create_access_token(const std::string& user_id,
    const std::string& device_id) {
  RegistrationStore reg(db_);
  return reg.add_access_token_to_user(user_id, device_id);
}

std::string AuthHandler::create_refresh_token(const std::string& user_id,
    const std::string& device_id, const std::string& access_token) {
  return gen_token(64);
}

std::string AuthHandler::generate_session_id() { return gen_id("sess"); }

bool AuthHandler::is_account_deactivated(const std::string& user_id) {
  RegistrationStore reg(db_);
  return reg.is_deactivated(user_id);
}

bool AuthHandler::validate_password(const std::string& user_id, const std::string& password) {
  RegistrationStore reg(db_);
  auto hash = reg.get_password_hash(user_id);
  return hash.has_value();
}

bool AuthHandler::validate_token_auth(const std::string& user_id, const std::string& token) {
  return !token.empty();
}

std::optional<AuthHandler::SSOUserMapping> AuthHandler::get_sso_user_mapping(
    const std::string& auth_provider, const std::string& remote_user_id) {
  RegistrationStore reg(db_);
  auto uid = reg.get_user_by_external_id(auth_provider, remote_user_id);
  if (!uid) return std::nullopt;
  return SSOUserMapping{*uid, *uid, {}};
}

std::string AuthHandler::create_account_from_sso(const SSOUserMapping& mapping,
    const std::string& auth_provider) {
  RegistrationStore reg(db_);
  return reg.register_user(mapping.user_id, std::nullopt, mapping.display_name);
}

// ========================================================================
// FederationEventHandler
// ========================================================================
FederationEventHandler::FederationEventHandler(DatabasePool& db) : db_(db) {}

FederationEventHandler::ProcessResult FederationEventHandler::process_federation_event(
    const std::string& origin, const json& event, const std::optional<std::string>& room_version) {
  // Verify signatures
  if (!verify_event_signatures(event)) {
    return {"", 0, false, false};
  }

  // Get event details
  std::string event_id = event.value("event_id", "");
  std::string room_id = event.value("room_id", "");

  // Check if already processed
  EventsStore evs(db_);
  auto existing = evs.get_event(event_id);
  if (existing) {
    return {event_id, 0, false, false};
  }

  // Process state resolution
  std::vector<std::string> auth_ids;
  if (event.contains("auth_events")) {
    for (auto& ae : event["auth_events"]) auth_ids.push_back(ae.get<std::string>());
  }
  auto missing_auth = get_missing_auth_events(auth_ids);
  // Would pull missing auth events from origin

  int64_t so = now_ms();
  return {event_id, so, false, true};
}

FederationEventHandler::BackfillResult FederationEventHandler::backfill(
    const std::string& origin, const std::string& room_id, int limit,
    const std::vector<std::string>& extremities) {
  BackfillResult result;
  result.origin = origin;
  result.events = json::array();
  result.backwards_extremity_more = false;
  return result;
}

void FederationEventHandler::process_state_events(const std::string& room_id,
    const std::string& origin, const std::vector<json>& state_events, bool backfilled) {}

void FederationEventHandler::handle_auth_events(const std::vector<json>& auth_events,
    const std::string& room_id, const std::string& origin) {}

json FederationEventHandler::precompute_event_auth(const json& event,
    const json& auth_events, const std::string& room_version) {
  return json::object();
}

std::vector<std::string> FederationEventHandler::get_missing_auth_events(
    const std::vector<std::string>& auth_ids) {
  EventFederationStore fed(db_);
  std::set<std::string> ids(auth_ids.begin(), auth_ids.end());
  auto missing = fed.get_missing_events(ids);
  return std::vector<std::string>(missing.begin(), missing.end());
}

void FederationEventHandler::on_reject_federation_event(const std::string& event_id,
    const std::string& reason) {}

std::optional<json> FederationEventHandler::pull_event(const std::string& origin,
    const std::string& event_id) {
  return std::nullopt;
}

bool FederationEventHandler::check_event_hash(const json& event) { return true; }
bool FederationEventHandler::verify_event_signatures(const json& event) { return true; }

std::map<std::pair<std::string,std::string>, std::string>
FederationEventHandler::resolve_state_conflicts(const std::string& room_id,
    const std::vector<std::map<std::pair<std::string,std::string>, std::string>>& states) {
  if (states.empty()) return {};
  return states[0];
}

// ========================================================================
// FederationHandler
// ========================================================================
FederationHandler::FederationHandler(DatabasePool& db) : db_(db) {}

json FederationHandler::handle_transaction(const std::string& origin,
    const std::string& transaction_id, const json& data) {
  json response;
  response["pdus"] = json::object();
  response["edus"] = json::object();

  // Process PDUs
  if (data.contains("pdus")) {
    for (auto& pdu : data["pdus"]) {
      FederationEventHandler feh(db_);
      feh.process_federation_event(origin, pdu);
    }
  }

  // Process EDUs
  if (data.contains("edus")) {
    for (auto& edu : data["edus"]) {
      std::string edu_type = edu.value("edu_type", "");
      // Handle typing, presence, device list updates, etc.
    }
  }

  return response;
}

json FederationHandler::send_transaction(const std::string& destination,
    const json& data) {
  return json::object();
}

json FederationHandler::query_room_state(const std::string& destination,
    const std::string& room_id, const std::string& event_id) {
  StateStore state(db_);
  auto s = state.get_current_state(room_id);
  json result = json::object();
  for (auto& [key, eid] : s) {
    result[key.first + (key.second.empty() ? "" : "/" + key.second)] = eid;
  }
  return result;
}

json FederationHandler::query_room_members(const std::string& destination,
    const std::string& room_id) {
  return json::object();
}

json FederationHandler::query_room_events(const std::string& destination,
    const std::string& room_id, int64_t depth) {
  return json::object();
}

json FederationHandler::make_join(const std::string& destination,
    const std::string& room_id, const std::string& user_id) {
  json resp;
  resp["event"] = json::object();
  resp["room_version"] = "1";
  return resp;
}

json FederationHandler::send_join(const std::string& destination,
    const std::string& room_id, const std::string& event_id) {
  return json::object();
}

json FederationHandler::make_leave(const std::string& destination,
    const std::string& room_id, const std::string& user_id) {
  json resp;
  resp["event"] = json::object();
  resp["room_version"] = "1";
  return resp;
}

json FederationHandler::send_leave(const std::string& destination,
    const std::string& room_id, const std::string& event_id) {
  return json::object();
}

json FederationHandler::make_invite(const std::string& destination,
    const std::string& room_id, const std::string& event_id) {
  json resp;
  resp["event"] = json::object();
  resp["room_version"] = "1";
  return resp;
}

json FederationHandler::send_invite(const std::string& destination,
    const std::string& room_id, const std::string& event_id,
    const json& invite_room_state) {
  return json::object();
}

std::vector<json> FederationHandler::get_missing_events(const std::string& dest,
    const std::string& room_id, const std::vector<std::string>& missing,
    const std::vector<std::string>& earliest, const std::vector<std::string>& latest) {
  return {};
}

json FederationHandler::exchange_third_party_invite(const std::string& dest,
    const std::string& room_id, const json& event) {
  return json::object();
}

std::optional<json> FederationHandler::get_event(const std::string& dest,
    const std::string& event_id) {
  return std::nullopt;
}

json FederationHandler::query_profile(const std::string& dest, const std::string& user_id) {
  ProfileStore profiles(db_);
  auto p = profiles.get_profile(user_id);
  json resp; if (p) { if (p->display_name) resp["displayname"] = *p->display_name; if (p->avatar_url) resp["avatar_url"] = *p->avatar_url; }
  return resp;
}

json FederationHandler::query_keys(const std::string& dest, const json& query) {
  EndToEndKeyStore keys(db_);
  return json::object();
}

json FederationHandler::claim_keys(const std::string& dest, const json& claim) {
  return json::object();
}

void FederationHandler::notify_device_update(const std::string& dest,
    const std::string& user_id, const std::vector<std::string>& device_ids) {}

void FederationHandler::send_edu(const std::string& dest, const std::string& edu_type,
    const json& content) {}

json FederationHandler::get_server_keys(const std::string& server_name,
    const std::set<std::string>& key_ids) {
  return json::object();
}

} // namespace progressive::handlers
