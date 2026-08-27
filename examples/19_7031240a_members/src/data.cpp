#include "data.hpp"

#include "crypto.hpp"
#include "utils.hpp"

#include <algorithm>
#include <iostream>
#include <cstdio>

// utils::generate_keypair via update_and_fetch("keypair") semantics.
static std::string load_or_generate_keypair(sled::Db& storage) {
  if (auto existing = storage.get_root("keypair")) return *existing;
  const std::string seed = crypto::ed25519_generate_seed();
  storage.insert_root("keypair", seed);
  return seed;
}

Data::Data(const std::filesystem::path& dir)
    : db_storage_(sled::Db::open(dir)), db_(database::Database::open(&db_storage_)) {
  hostname_ = db_storage_.get_root("hostname").value_or("localhost");
  keypair_ = load_or_generate_keypair(db_storage_);
}

Data Data::load_or_create(const std::filesystem::path& dir) { return Data(dir); }

void Data::set_hostname(const std::string& hostname) {
  hostname_ = hostname;
  db_storage_.insert_root("hostname", hostname);
}

const std::string& Data::hostname() const { return hostname_; }

const std::string& Data::keypair() const { return keypair_; }

// NEW in 7031240a: state events of one type (prefix scan over
// 'd'+room+0xff+type+0xff+state_key).
std::vector<std::string> Data::room_state_type(const std::string& room_id,
                                               const std::string& type) const {
  std::vector<std::string> pdus;
  std::string prefix;
  prefix.push_back('d');
  prefix += room_id;
  prefix.push_back(static_cast<char>(0xff));
  prefix += type;
  for (const auto& [key, value] : db_.roomstateid_pdu.scan_prefix(prefix)) {
    pdus.push_back(value);
  }
  return pdus;
}

std::vector<std::pair<std::string, std::string>> Data::debug_userid_roomids() const {
  return db_.userid_roomids.iter_all();
}

std::vector<std::pair<std::string, std::string>> Data::debug_userid_leftroomids() const {
  return db_.userid_leftroomids.iter_all();
}

bool Data::user_exists(const std::string& user_id) const {
  return db_.userid_password.contains_key(user_id);
}

void Data::user_add(const std::string& user_id, const std::string& hash) {
  db_.userid_password.insert(user_id, hash);
}

// NEW in abcce95d.
std::vector<std::string> Data::users_all() const {
  std::vector<std::string> users;
  for (const auto& [key, value] : db_.userid_password.iter_all()) {
    users.push_back(key);  // keys are the user ids
  }
  return users;
}

std::optional<std::string> Data::user_from_token(const std::string& token) const {
  return db_.token_userid.get(token);
}

std::optional<std::string> Data::password_hash_get(const std::string& user_id) const {
  return db_.userid_password.get(user_id);
}

// --- displayname (4cc0a070) -----------------------------------------------------

std::optional<std::string> Data::displayname_get(const std::string& user_id) const {
  return db_.userid_displayname.get(user_id);
}

bool Data::displayname_set(const std::string& user_id,
                           const std::string& displayname) {
  db_.userid_displayname.insert(user_id, displayname);

  // Broadcast the rename: a fresh m.room.member join event per joined room.
  for (const auto& room_id : rooms_joined(user_id)) {
    nlohmann::json event = {
        {"type", "m.room.member"},
        {"content",
         {{"membership", "join"}, {"displayname", displayname}}},
        {"event_id", "$thiswillbefilledinlater"},
        {"origin_server_ts", utils::millis_since_unix_epoch()},
        {"room_id", room_id},
        {"sender", user_id},
        {"state_key", user_id},
        {"unsigned", nlohmann::json::object()},
    };
    const std::string event_id = crypto::reference_hash(event);
    event["event_id"] = event_id;
    return pdu_append(event_id, room_id, std::move(event));
  }
}

void Data::displayname_remove(const std::string& user_id) {
  db_.userid_displayname.erase(user_id);
}

void Data::device_add(const std::string& user_id, const std::string& device_id) {
  bool already = false;
  for (const auto& [k, v] : db_.userid_deviceids.get_iter(user_id)) {
    if (v == device_id) already = true;
  }
  if (!already) db_.userid_deviceids.add(user_id, device_id);
}

void Data::token_replace(const std::string& user_id, const std::string& device_id,
                         const std::string& token) {
  // Key layout changed in abcce95d: user_id + 0xff + device_id.
  const std::string key = user_id + "\xff" + device_id;

  // Remove old token
  if (const auto old_token = db_.userdeviceid_token.get(key)) {
    db_.token_userid.erase(*old_token);
    // It will be removed from userdeviceid_token by the insert below.
  }

  // Assign token to (user, device)
  db_.userdeviceid_token.insert(key, token);

  // Assign token to user
  db_.token_userid.insert(token, user_id);
}

// --- membership ----------------------------------------------------------------

bool Data::room_join(const std::string& room_id, const std::string& user_id) {
  db_.roomid_userids.add(room_id, user_id);
  db_.userid_roomids.add(user_id, room_id);

  // NEW in 4cc0a070: the join member event carries the displayname.
  nlohmann::json content = {{"membership", "join"}};
  if (auto displayname = displayname_get(user_id))
    content["displayname"] = *displayname;

  nlohmann::json event = {
      {"type", "m.room.member"},
      {"content", std::move(content)},
      {"event_id", "$thiswillbefilledinlater"},
      {"origin_server_ts", utils::millis_since_unix_epoch()},
      {"room_id", room_id},
      {"sender", user_id},
      {"state_key", user_id},
      {"unsigned", nlohmann::json::object()},
  };
  const std::string event_id = crypto::reference_hash(event);
  event["event_id"] = event_id;
  return pdu_append(event_id, room_id, std::move(event));
}

size_t Data::room_users(const std::string& room_id) const {
  return db_.roomid_userids.get_iter(room_id).size();
}

std::vector<std::string> Data::rooms_joined(const std::string& user_id) const {
  std::vector<std::string> rooms;
  for (const auto& [key, value] : db_.userid_roomids.get_iter(user_id)) {
    rooms.push_back(value);
  }
  return rooms;
}

bool Data::room_leave(const std::string& room_id, const std::string& user_id) {
  // Remove membership entries (inverse lookups via remove_value).
  for (const auto& [k, v] : db_.roomid_userids.get_iter(room_id))
    if (v == user_id) db_.roomid_userids.remove_value(room_id, user_id);
  db_.userid_roomids.remove_value(user_id, room_id);
  db_.userid_leftroomids.add(user_id, room_id);

  nlohmann::json event = {
      {"type", "m.room.member"},
      {"content", {{"membership", "leave"}}},
      {"event_id", "$thiswillbefilledinlater"},
      {"origin_server_ts", utils::millis_since_unix_epoch()},
      {"room_id", room_id},
      {"sender", user_id},
      {"state_key", user_id},
      {"unsigned", nlohmann::json::object()},
  };
  const std::string event_id = crypto::reference_hash(event);
  event["event_id"] = event_id;
  return pdu_append(event_id, room_id, std::move(event));
}

void Data::room_forget(const std::string& room_id, const std::string& user_id) {
  db_.userid_leftroomids.remove_value(user_id, room_id);
}

/// NEW in b106d139: database/users.rs remove_device, adapted to our token-
/// keyed lookup. Removes the device entry and its access token.
bool Data::remove_device_by_token(const std::string& token) {
  const auto user_id = db_.token_userid.get(token);
  if (!user_id) return false;

  // Find which of the user's devices holds this token.
  for (const auto& [k, device_id] : db_.userid_deviceids.get_iter(*user_id)) {
    const std::string key = *user_id + '\xff' + device_id;
    if (db_.userdeviceid_token.get(key).value_or("") == token) {
      // Remove tokens
      db_.userdeviceid_token.erase(key);
      db_.token_userid.erase(token);
      // Remove the device from the user's device list
      db_.userid_deviceids.remove_value(*user_id, device_id);
      return true;
    }
  }
  // Token maps to a user but no device entry matches — stale token.
  db_.token_userid.erase(token);
  return true;  // treated as logged out either way
}

// --- NEW in b6c0e9bf: access control -------------------------------------------

bool Data::is_joined(const std::string& user_id, const std::string& room_id) const {
  for (const auto& [k, v] : db_.roomid_userids.get_iter(room_id))
    if (v == user_id) return true;
  return false;
}

std::optional<std::string> Data::membership_of(const std::string& room_id,
                                               const std::string& user_id) const {
  std::string key;
  key.push_back('d');
  key += room_id;
  key.push_back(static_cast<char>(0xff));
  key += "m.room.member";
  key.push_back(static_cast<char>(0xff));
  key += user_id;
  auto text = db_.roomstateid_pdu.get(key);
  if (!text) return std::nullopt;
  return nlohmann::json::parse(*text)["content"].value("membership", "leave");
}

void Data::update_membership(const std::string& room_id,
                             const std::string& user_id,
                             const std::string& membership) {
  if (membership == "join") {
    bool already = is_joined(user_id, room_id);
    if (!already) db_.roomid_userids.add(room_id, user_id);
    db_.userid_inviteroomids.remove_value(user_id, room_id);
  } else if (membership == "invite") {
    db_.userid_inviteroomids.add(user_id, room_id);
  } else {  // leave / ban
    db_.userid_leftroomids.add(user_id, room_id);
    db_.userid_inviteroomids.remove_value(user_id, room_id);
    db_.roomid_userids.remove_value(room_id, user_id);
    db_.userid_roomids.remove_value(user_id, room_id);
  }
}

// --- PDU graph ------------------------------------------------------------------

std::optional<std::string> Data::pdu_get(const std::string& event_id) const {
  const auto pdu_id = db_.eventid_pduid.get(event_id);
  if (!pdu_id) return std::nullopt;
  return db_.pduid_pdus.get(*pdu_id);
}

std::vector<std::string> Data::pdu_leaves_replace(const std::string& room_id,
                                                  const std::string& event_id) {
  std::vector<std::string> event_ids;
  for (const auto& [key, value] : db_.roomid_pduleaves.get_iter(room_id)) {
    event_ids.push_back(value);
  }
  db_.roomid_pduleaves.clear(room_id);
  db_.roomid_pduleaves.add(room_id, event_id);
  return event_ids;
}

bool Data::pdu_append(const std::string& event_id, const std::string& room_id,
                      nlohmann::json event) {
  const std::vector<std::string> prev_events =
      pdu_leaves_replace(room_id, event_id);

  // --- NEW in b6c0e9bf: state-event access control ---------------------------
  const std::string sender = event.value("sender", "");
  using json = nlohmann::json;
  const bool has_state_key = event.contains("state_key");

  auto get_state = [&](const std::string& type,
                       const std::string& sk) -> std::optional<json> {
    std::string key;
    key.push_back('d');
    key += room_id;
    key.push_back(static_cast<char>(0xff));
    key += type;
    key.push_back(static_cast<char>(0xff));
    key += sk;
    auto text = db_.roomstateid_pdu.get(key);
    if (!text) return std::nullopt;
    return json::parse(*text, nullptr, false);
  };

  long sender_power_val = 0;

  if (has_state_key) {
    json pl = {
        {"ban", 50}, {"events_default", 0}, {"invite", 50},
        {"kick", 50}, {"redact", 50}, {"state_default", 0},
        {"users", json::object()}, {"users_default", 0},
    };
    if (auto pl_ev = get_state("m.room.power_levels", ""))
      pl = pl_ev->value("content", pl);

    auto user_power = [&](const std::string& uid) -> std::optional<long> {
      auto users_it = pl.find("users");
      if (users_it != pl.end()) {
        if (auto u = users_it->find(uid); u != users_it->end())
          return static_cast<long>(u->get<long long>());
      }
      return std::nullopt;
    };
    const long users_default =
        static_cast<long>(pl.value("users_default", (long long)0));
    const long invite_level = static_cast<long>(pl.value("invite", (long long)50));
    const long kick_level = static_cast<long>(pl.value("kick", (long long)50));
    const long ban_level = static_cast<long>(pl.value("ban", (long long)50));
    const long state_default = static_cast<long>(pl.value("state_default", (long long)0));

    const std::string type = event.value("type", "");
    const std::string state_key = event.value("state_key", "");
    const std::string sender_membership =
        membership_of(room_id, sender).value_or("leave");
    auto sp = user_power(sender);
    if (!sp && sender_membership == "join") sp = users_default;
    sender_power_val = sp.value_or(0);

    bool authorized = false;
    std::fprintf(stderr, "[auth] %s sk=%s sender=%s sm=%s sp=%ld pl=%s\n",
                 type.c_str(), state_key.c_str(), sender.c_str(),
                 sender_membership.c_str(), sender_power_val, pl.dump().c_str());

    if (type == "m.room.member") {
      const std::string target_user = state_key;
      const std::string current =
          membership_of(room_id, target_user).value_or("leave");
      const std::string target_membership =
          event["content"].value("membership", "");
      auto tp = user_power(target_user);
      if (!tp && target_membership == "join") tp = users_default;
      const long target_power = tp.value_or(0);

      std::string join_rule = "public";
      if (auto jr = get_state("m.room.join_rules", ""))
        join_rule = jr->value("content", json::object()).value("join_rule", "public");

      std::fprintf(stderr, "[auth-member] target=%s current=%s tm=%s tp=%ld jr=%s\n",
                   target_user.c_str(), current.c_str(), target_membership.c_str(),
                   target_power, join_rule.c_str());
      if (target_membership == "join") {
        if (sender != target_user) authorized = false;
        else if (current == "ban") authorized = false;
        else if (join_rule == "invite" && (current == "join" || current == "invite"))
          authorized = true;
        else if (join_rule == "public")
          authorized = true;
      } else if (target_membership == "invite") {
        if (sender_membership != "join") authorized = false;
        else if (current == "join" || current == "ban") authorized = false;
        else authorized = sender_power_val >= invite_level;
      } else if (target_membership == "leave") {
        if (sender == target_user)
          authorized = (current == "join" || current == "invite");
        else if (sender_membership != "join") authorized = false;
        else if (current == "ban" && sender_power_val < ban_level) authorized = false;
        else
          authorized =
              sender_power_val >= kick_level && target_power < sender_power_val;
      } else if (target_membership == "ban") {
        if (sender_membership != "join") authorized = false;
        else authorized = sender_power_val >= ban_level && target_power < sender_power_val;
      }
    } else if (type == "m.room.create") {
      authorized = prev_events.empty();
    } else if (sender_membership == "join") {
      authorized = sender_power_val >= state_default;
    }

    if (!authorized) {
      std::cerr << "[debug] event not authorized\n";
      return false;
    }
  } else if (!is_joined(sender, room_id)) {
    std::cerr << "[debug] event not authorized (not joined)\n";
    return false;
  }

  uint64_t depth = 0;
  for (const auto& prev : prev_events) {
    if (const auto text = pdu_get(prev)) {
      depth = std::max(
          depth,
          static_cast<uint64_t>(nlohmann::json::parse(*text).value("depth", 0ull)));
    }
  }
  depth += 1;

  event["prev_events"] = prev_events;
  event["origin"] = hostname_;
  event["depth"] = depth;
  event["auth_events"] = nlohmann::json::array({"$auth_eventid"});  // still TODO upstream

  // NEW in 4cc0a070: state events carry unsigned.prev_content with the old
  // content (upstream notes: TODO optimize — loads the whole room state).
  if (event.contains("state_key")) {
    for (const auto& state_text : room_state(room_id)) {
      auto prev = nlohmann::json::parse(state_text, nullptr, false);
      if (!prev.is_discarded() && prev.value("type", "") == event.value("type", "") &&
          prev.value("state_key", "") == event.value("state_key", "")) {
        event["unsigned"]["prev_content"] = prev.value("content", nlohmann::json::object());
        break;
      }
    }
  }

  // NEW in b0d9ccdb: ruma_signatures::hash_and_sign_event — the "AAAA..."
  // hashes and fake "signature" become a real content hash and Ed25519 sig.
  crypto::hash_and_sign_event(hostname_, keypair_, event);

  const std::string index_bytes =
      db_.pduid_pdus.update_and_fetch("n" + room_id, utils::increment);
  const uint64_t index = utils::u64_from_bytes(index_bytes);

  std::string pdu_id;
  pdu_id.push_back('d');
  pdu_id += room_id;
  pdu_id.push_back('#');
  pdu_id += std::to_string(index);

  const std::string pdu_json = event.dump();
  std::printf("[debug] %s\n", pdu_json.c_str());
  db_.pduid_pdus.insert(pdu_id, pdu_json);
  db_.eventid_pduid.insert(event_id, pdu_id);

  // NEW in abcce95d: state events also land in roomstateid_pdu under
  // 'd' + room + 0xff + type + 0xff + state_key.
  if (event.contains("state_key")) {
    std::string state_key;
    state_key.push_back('d');
    state_key += room_id;
    state_key.push_back(static_cast<char>(0xff));
    state_key += event.value("type", "");
    state_key.push_back(static_cast<char>(0xff));
    state_key += event.value("state_key", "");
    db_.roomstateid_pdu.insert(state_key, pdu_json);
  }

  // b6c0e9bf: membership tree updates happen here, post-authorization.
  if (event.value("type", "") == "m.room.member") {
    update_membership(room_id, event.value("state_key", ""),
                      event["content"].value("membership", ""));
  }

  return true;
}

std::vector<std::string> Data::pdus_all() const {
  std::vector<std::string> pdus;
  for (const auto& [key, value] : db_.pduid_pdus.iter_all()) {
    if (key.rfind("d", 0) == 0) pdus.push_back(value);
  }
  return pdus;
}

// NEW in 23cb550d: walk backwards from 'until' while inside the room prefix.
std::vector<std::string> Data::pdus_until(const std::string& room_id,
                                          uint64_t until) const {
  std::vector<std::string> pdus;
  std::string prefix;
  prefix.push_back('d');
  prefix += room_id;
  prefix.push_back('#');  // matches stored 'd'+room+'#'+index keys

  std::string current = prefix + std::to_string(until);

  while (true) {
    const auto prev = db_.pduid_pdus.get_lt(current);
    if (!prev) { std::fprintf(stderr, "[dbg] get_lt none\n"); break; }
    if (prev->first.rfind(prefix, 0) != 0) {
      std::fprintf(stderr, "[dbg] prefix mismatch: %s\n", prev->first.c_str());
      break;
    }
    current = prev->first;
    pdus.push_back(prev->second);
  }
  return pdus;
}

uint64_t Data::last_pdu_index(const std::string& room_id) const {
  if (const auto v = db_.pduid_pdus.get("n" + room_id))
    return utils::u64_from_bytes(*v);
  return 0;
}

// --- NEW in 821c608c: media repository -----------------------------------------

void Data::media_create(const std::string& mxc, const std::optional<std::string>& filename,
                        const std::string& content_type, const std::string& file) {
  db_.media.create(mxc, filename, content_type, file);
}

std::optional<database::Media::File> Data::media_get(const std::string& mxc) const {
  return db_.media.get(mxc);
}

bool Data::room_pdu_first(const std::string& room_id, uint64_t pdu_index) const {
  std::string pdu_id;
  pdu_id.push_back('d');
  pdu_id += room_id;
  pdu_id.push_back('#');
  pdu_id += std::to_string(pdu_index);
  return !db_.pduid_pdus.get_lt(pdu_id).has_value();
}

// NEW (folded prerequisite): per-room timeline after `since` (a pdu index).
std::vector<std::string> Data::pdus_since(const std::string& room_id,
                                          uint64_t since) const {
  std::vector<std::string> pdus;
  std::string current = "d" + room_id + "#" + std::to_string(since);
  while (true) {
    const auto next = db_.pduid_pdus.get_gt(current);
    if (!next || next->first.rfind("d" + room_id + "#", 0) != 0) break;
    current = next->first;
    pdus.push_back(next->second);
  }
  return pdus;
}

// --- NEW in abcce95d: invites & state -------------------------------------------

std::vector<std::string> Data::room_state(const std::string& room_id) const {
  std::vector<std::string> state;
  std::string prefix;
  prefix.push_back('d');
  prefix += room_id;
  prefix.push_back(static_cast<char>(0xff));
  for (const auto& [key, value] : db_.roomstateid_pdu.scan_prefix(prefix)) {
    state.push_back(value);
  }
  return state;
}

bool Data::room_invite(const std::string& sender, const std::string& room_id,
                       const std::string& user_id) {
  // m.room.member invite state event, appended like any other pdu.
  nlohmann::json event = {
      {"type", "m.room.member"},
      {"content", {{"membership", "invite"}}},
      {"event_id", "$thiswillbefilledinlater"},
      {"origin_server_ts", utils::millis_since_unix_epoch()},
      {"room_id", room_id},
      {"sender", sender},
      {"state_key", user_id},
      {"unsigned", nlohmann::json::object()},
  };
  const std::string event_id = crypto::reference_hash(event);
  event["event_id"] = event_id;
  pdu_append(event_id, room_id, std::move(event));

  db_.userid_inviteroomids.add(user_id, room_id);
}

std::vector<std::string> Data::rooms_invited(const std::string& user_id) const {
  std::vector<std::string> rooms;
  for (const auto& [key, value] : db_.userid_inviteroomids.get_iter(user_id)) {
    rooms.push_back(value);
  }
  return rooms;
}
