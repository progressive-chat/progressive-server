#include "data.hpp"

#include "crypto.hpp"
#include "utils.hpp"

#include <algorithm>
#include <cstdio>

// utils::generate_keypair via update_and_fetch("keypair") semantics.
static std::string load_or_generate_keypair(sled::Db& storage) {
  if (auto existing = storage.get_root("keypair")) return *existing;
  const std::string seed = crypto::ed25519_generate_seed();
  storage.insert_root("keypair", seed);
  return seed;
}

Data::Data(const std::filesystem::path& dir)
    : db_storage_(sled::Db::open(dir)), db_(stubdb::Database::open(&db_storage_)) {
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

void Data::room_join(const std::string& room_id, const std::string& user_id) {
  db_.roomid_userids.add(room_id, user_id);
  db_.userid_roomids.add(user_id, room_id);
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

void Data::pdu_append(const std::string& event_id, const std::string& room_id,
                      nlohmann::json event) {
  const std::vector<std::string> prev_events =
      pdu_leaves_replace(room_id, event_id);

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

  // Folded prerequisite: membership PDUs maintain roomid_userids.
  if (event.value("type", "") == "m.room.member") {
    const auto membership = event["content"].value("membership", "");
    const auto& target = event.value("state_key", "");
    if (membership == "join") {
      bool already = false;
      for (const auto& [k, v] : db_.roomid_userids.get_iter(room_id))
        if (v == target) already = true;
      if (!already && !target.empty()) {
        db_.roomid_userids.add(room_id, target);
        db_.userid_roomids.add(target, room_id);
      }
    }
  }
}

std::vector<std::string> Data::pdus_all() const {
  std::vector<std::string> pdus;
  for (const auto& [key, value] : db_.pduid_pdus.iter_all()) {
    if (key.rfind("d", 0) == 0) pdus.push_back(value);
  }
  return pdus;
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

void Data::room_invite(const std::string& sender, const std::string& room_id,
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
