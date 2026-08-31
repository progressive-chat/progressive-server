#include "data.hpp"

#include "crypto.hpp"
#include "utils.hpp"

#include <algorithm>
#include <iostream>
#include <cstdio>
#include <cstring>

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

  // NEW in 9db1f5a13c-era: seed admin users from the CONDUIT_ADMINS env var
  // (comma/space separated list of full user IDs). Mirrors Conduit's `admins`
  // server config so the admin API has at least one bootstrap administrator.
  const char* env = std::getenv("CONDUIT_ADMINS");
  if (env) {
    std::string s(env);
    size_t start = 0;
    while (start < s.size()) {
      while (start < s.size() && (s[start] == ',' || s[start] == ' ')) ++start;
      size_t end = start;
      while (end < s.size() && s[end] != ',' && s[end] != ' ') ++end;
      if (end > start) admin_add(s.substr(start, end - start));
      start = end;
    }
  }

  // NEW in 66a14ac: media.unauthenticated_access_permitted (default true, which
  // preserves the previous behaviour). Set the env var to "false" to freeze
  // unauthenticated media access for subsequently uploaded content.
  const char* media_unauth = std::getenv("CONDUIT_MEDIA_UNAUTHENTICATED_ACCESS_PERMITTED");
  if (media_unauth && std::string(media_unauth) == "false") {
    media_unauthenticated_access_permitted_ = false;
  }

  // NEW in c3fb1b0: media retention policies. Conduit reads these from
  // conduit.toml `[[global.media.retention]]`; we read a JSON array of
  // {scope?, accessed_ms?, created_ms?, space_bytes?} from the env (the
  // "humantime"/"bytesize" config strings are adapted to plain ms/bytes).
  const char* retention_env = std::getenv("CONDUIT_MEDIA_RETENTION");
  if (retention_env && *retention_env) {
    try {
      const nlohmann::json j = nlohmann::json::parse(retention_env);
      if (j.is_array()) {
        for (const auto& item : j) {
          database::RetentionPolicy p;
          if (item.contains("scope") && item["scope"].is_string())
            p.scope = item["scope"].get<std::string>();
          if (item.contains("accessed_ms") && item["accessed_ms"].is_number())
            p.accessed_ms = item["accessed_ms"].get<uint64_t>();
          if (item.contains("created_ms") && item["created_ms"].is_number())
            p.created_ms = item["created_ms"].get<uint64_t>();
          if (item.contains("space_bytes") && item["space_bytes"].is_number())
            p.space_bytes = item["space_bytes"].get<uint64_t>();
          media_retention_.push_back(p);
        }
      }
    } catch (...) {
      media_retention_.clear();
    }
  }
}

Data Data::load_or_create(const std::filesystem::path& dir) { return Data(dir); }

void Data::set_hostname(const std::string& hostname) {
  hostname_ = hostname;
  admin_alias_ = "#admins:" + hostname;  // NEW in 144d548
  db_storage_.insert_root("hostname", hostname);
}

const std::string& Data::hostname() const { return hostname_; }

const std::string& Data::admin_alias() const { return admin_alias_; }

void Data::set_well_known_client(const std::string& v) {
  well_known_client_override_ = v;
}
void Data::set_well_known_server(const std::string& v) {
  well_known_server_override_ = v;
}

std::string Data::well_known_client() const {
  if (!well_known_client_override_.empty()) return well_known_client_override_;
  return "https://" + hostname_;
}

std::string Data::well_known_server() const {
  if (!well_known_server_override_.empty()) return well_known_server_override_;
  const std::string& h = hostname_;
  if (h.find(':') != std::string::npos) return h;  // already has a port
  return h + ":443";
}

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

bool Data::is_deactivated(const std::string& user_id) const {
  auto pw = db_.userid_password.get(user_id);
  return pw.has_value() && pw->empty();
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

std::optional<std::string> Data::device_from_token(const std::string& token) const {
  auto user = db_.token_userid.get(token);
  if (!user) return std::nullopt;
  for (const auto& [k, device] : db_.userid_deviceids.get_iter(*user)) {
    const std::string key = *user + "\xff" + device;
    if (db_.userdeviceid_token.get(key) == token) return device;
  }
  return std::nullopt;
}

void Data::device_last_seen_update(const std::string& user_id, const std::string& device_id) {
  const std::string key = user_id + static_cast<char>(0xff) + device_id;
  const uint64_t now = utils::millis_since_unix_epoch();
  db_.userdeviceid_lastseen.insert(key, std::to_string(now));
  device_last_seen_cache_[{user_id, device_id}] = now;
}

std::optional<uint64_t> Data::device_last_seen_get(const std::string& user_id,
                                                   const std::string& device_id) const {
  const auto it = device_last_seen_cache_.find({user_id, device_id});
  if (it != device_last_seen_cache_.end()) return it->second;
  auto raw = db_.userdeviceid_lastseen.get(user_id + static_cast<char>(0xff) + device_id);
  if (!raw) return std::nullopt;
  try {
    return std::stoull(*raw);
  } catch (...) {
    return std::nullopt;
  }
}

void Data::add_txnid(const std::string& user_id, const std::string& device_id,
                     const std::string& txn_id, const std::string& data) {
  db_.userdevicetxnid_response.insert(
      user_id + "\xff" + device_id + "\xff" + txn_id, data);
}

std::optional<std::string> Data::existing_txnid(const std::string& user_id,
                                               const std::string& device_id,
                                               const std::string& txn_id) const {
  return db_.userdevicetxnid_response.get(user_id + "\xff" + device_id + "\xff" + txn_id);
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
  return true;
}

// --- NEW in 21af83e: state-cache knock tracking -------------------------------

void Data::mark_as_knocked(const std::string& user_id, const std::string& room_id,
                            const std::string& knock_event_json) {
  const std::string userroom_key = user_id + '\xff' + room_id;
  const std::string roomuser_key = room_id + '\xff' + user_id;
  db_.userroomid_knockstate.insert(userroom_key, knock_event_json);
  // Increment knock count (big-endian counter, like Conduit's next_count).
  uint64_t count = 0;
  if (auto existing = db_.roomuserid_knockcount.get(roomuser_key))
    count = utils::u64_from_bytes(*existing);
  ++count;
  db_.roomuserid_knockcount.insert(roomuser_key, utils::u64_to_bytes(count));
  // A knock clears any prior "left" membership marker for this user in the room.
  db_.userid_leftroomids.remove_value(user_id, room_id);
}

std::optional<uint64_t> Data::get_knock_count(const std::string& room_id,
                                              const std::string& user_id) const {
  const std::string key = room_id + '\xff' + user_id;
  if (auto bytes = db_.roomuserid_knockcount.get(key))
    return utils::u64_from_bytes(*bytes);
  return std::nullopt;
}

std::vector<std::pair<std::string, std::string>> Data::rooms_knocked(
    const std::string& user_id) const {
  std::vector<std::pair<std::string, std::string>> out;
  for (const auto& [key, value] : db_.userroomid_knockstate.scan_prefix(user_id + '\xff')) {
    // key = user_id + 0xff + room_id
    const std::string room_id = key.substr(user_id.size() + 1);
    out.emplace_back(room_id, value);
  }
  return out;
}

std::optional<std::string> Data::knock_state(const std::string& user_id,
                                             const std::string& room_id) const {
  const std::string key = user_id + '\xff' + room_id;
  if (auto v = db_.userroomid_knockstate.get(key)) return *v;
  return std::nullopt;
}

bool Data::is_knocked(const std::string& user_id, const std::string& room_id) const {
  return db_.userroomid_knockstate.contains_key(user_id + '\xff' + room_id);
}

void Data::displayname_remove(const std::string& user_id) {
  db_.userid_displayname.erase(user_id);
}

// --- admin (9db1f5a13c-era) ----------------------------------------------------

void Data::admin_add(const std::string& user_id) {
  db_.admin_users.insert(user_id, "");
}

bool Data::user_is_admin(const std::string& user_id) const {
  return db_.admin_users.get(user_id).has_value();
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

  // NEW in 21af83e: joining clears any prior knock state for this room.
  db_.userroomid_knockstate.erase(user_id + '\xff' + room_id);
  db_.roomuserid_knockcount.erase(room_id + '\xff' + user_id);


  // NEW in df55e8ed: remember that this user has once joined (used to carry
  // account data / membership across a room upgrade's predecessor).
  db_.roomuseroncejoinedids.insert(room_id + "ÿ" + user_id, "");

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

bool Data::room_leave(const std::string& room_id, const std::string& user_id,
                      const std::string& reason) {
  // Remove membership entries (inverse lookups via remove_value).
  for (const auto& [k, v] : db_.roomid_userids.get_iter(room_id))
    if (v == user_id) db_.roomid_userids.remove_value(room_id, user_id);
  db_.userid_roomids.remove_value(user_id, room_id);
  db_.userid_leftroomids.add(user_id, room_id);

  // NEW in 82b7cf6261: carry the client-supplied reason (if any) into the
  // leave member event, mirroring Conduit's populate_membership_template which
  // preserves provided content instead of overwriting it.
  nlohmann::json content = {{"membership", "leave"}};
  if (!reason.empty()) content["reason"] = reason;

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

void Data::room_forget(const std::string& room_id, const std::string& user_id) {
  db_.userid_leftroomids.remove_value(user_id, room_id);
}

bool Data::room_knock(const std::string& room_id, const std::string& user_id,
                      const std::string& reason) {
  // NEW in 21af83e: a knock is an m.room.member state event with
  // membership "knock"; it does not add the user to the joined set.
  nlohmann::json content = {{"membership", "knock"}};
  if (!reason.empty()) content["reason"] = reason;
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
  const bool ok = pdu_append(event_id, room_id, std::move(event));
  if (ok) {
    // NEW in 21af83e: also record knock state in the state cache so the knock
    // can be surfaced in /sync and resolved by an admin invite.
    nlohmann::json stored = {
        {"type", "m.room.member"},
        {"state_key", user_id},
        {"content", {{"membership", "knock"}, {"reason", reason}}},
        {"event_id", event_id},
        {"room_id", room_id},
        {"sender", user_id},
    };
    mark_as_knocked(user_id, room_id, stored.dump());
  }
  return ok;
}

/// NEW in b106d139: database/users.rs remove_device, adapted to our token-
/// keyed lookup. Removes the device entry and its access token.
void Data::remove_device(const std::string& user_id, const std::string& device_id) {
  const std::string key = user_id + '\xff' + device_id;
  if (const auto old_token = db_.userdeviceid_token.get(key)) {
    db_.token_userid.erase(*old_token);
  }
  db_.userdeviceid_token.erase(key);

  // Remove to-device events (TODO upstream too) and one-time keys.

  // Remove from the device list
  std::vector<std::string> devices;
  for (const auto& [k, v] : db_.userid_deviceids.get_iter(user_id)) devices.push_back(v);
  devices.erase(std::remove(devices.begin(), devices.end(), device_id), devices.end());
  for (const auto& d : devices) {} // list rebuilt below
  db_.userid_deviceids.clear(user_id);
  for (const auto& d : devices) db_.userid_deviceids.add(user_id, d);
}

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

// --- NEW in d8badaf: membership reason-aware kick/ban/unban -------------------

std::optional<nlohmann::json> Data::get_member_content(
    const std::string& room_id, const std::string& user_id) const {
  std::string key;
  key.push_back('d');
  key += room_id;
  key.push_back(static_cast<char>(0xff));
  key += "m.room.member";
  key.push_back(static_cast<char>(0xff));
  key += user_id;
  auto text = db_.roomstateid_pdu.get(key);
  if (!text) return std::nullopt;
  auto ev = nlohmann::json::parse(*text, nullptr, false);
  if (ev.is_discarded()) return std::nullopt;
  return ev.value("content", nlohmann::json::object());
}

namespace {
// Build a m.room.member event issued by `sender` targeting `target`.
nlohmann::json make_member_event(const std::string& sender,
                                 const std::string& room_id,
                                 const std::string& target,
                                 nlohmann::json content) {
  nlohmann::json event = {
      {"type", "m.room.member"},
      {"content", std::move(content)},
      {"event_id", "$thiswillbefilledinlater"},
      {"origin_server_ts", utils::millis_since_unix_epoch()},
      {"room_id", room_id},
      {"sender", sender},
      {"state_key", target},
      {"unsigned", nlohmann::json::object()},
  };
  const std::string event_id = crypto::reference_hash(event);
  event["event_id"] = event_id;
  return event;
}
}  // namespace

bool Data::room_kick(const std::string& sender, const std::string& room_id,
                     const std::string& target, const std::string& reason) {
  auto content = get_member_content(room_id, target);
  // d8badaf: if already left with an unchanged reason, don't emit a new event.
  if (content && (*content).value("membership", "") == "leave" &&
      (*content).value("reason", "") == reason) {
    return true;
  }
  nlohmann::json c = {{"membership", "leave"}};
  if (!reason.empty()) c["reason"] = reason;
  if (content) {
    for (const char* f : {"displayname", "avatar_url"})
      if (auto it = content->find(f); it != content->end()) c[f] = *it;
  }
  nlohmann::json ev = make_member_event(sender, room_id, target, std::move(c));
  bool ok = pdu_append(ev.value("event_id", ""), room_id, std::move(ev));
  if (ok) update_membership(room_id, target, "leave");
  return ok;
}

bool Data::room_ban(const std::string& sender, const std::string& room_id,
                    const std::string& target, const std::string& reason) {
  auto content = get_member_content(room_id, target);
  // d8badaf: if already banned with an unchanged reason, don't emit a new event.
  if (content && (*content).value("membership", "") == "ban" &&
      (*content).value("reason", "") == reason) {
    return true;
  }
  nlohmann::json c = {{"membership", "ban"}};
  if (!reason.empty()) c["reason"] = reason;
  if (content) {
    for (const char* f : {"displayname", "avatar_url", "blurhash"})
      if (auto it = content->find(f); it != content->end()) c[f] = *it;
  }
  nlohmann::json ev = make_member_event(sender, room_id, target, std::move(c));
  bool ok = pdu_append(ev.value("event_id", ""), room_id, std::move(ev));
  if (ok) update_membership(room_id, target, "ban");
  return ok;
}

bool Data::room_unban(const std::string& sender, const std::string& room_id,
                      const std::string& target, const std::string& reason) {
  auto content = get_member_content(room_id, target);
  // d8badaf: if already left with an unchanged reason, don't emit a new event.
  if (content && (*content).value("membership", "") == "leave" &&
      (*content).value("reason", "") == reason) {
    return true;
  }
  nlohmann::json c = {{"membership", "leave"}};
  if (!reason.empty()) c["reason"] = reason;
  if (content) {
    for (const char* f : {"displayname", "avatar_url"})
      if (auto it = content->find(f); it != content->end()) c[f] = *it;
  }
  nlohmann::json ev = make_member_event(sender, room_id, target, std::move(c));
  bool ok = pdu_append(ev.value("event_id", ""), room_id, std::move(ev));
  if (ok) update_membership(room_id, target, "leave");
  return ok;
}

/// NEW in 67a1f21f: hash and set the user's password (Argon2id).
bool Data::set_password(const std::string& user_id, const std::string& password) {
  auto hash = utils::calculate_hash(password);
  if (!hash) return false;
  db_.userid_password.insert(user_id, *hash);
  return true;
}

std::vector<std::string> Data::all_device_ids(const std::string& user_id) const {
  std::vector<std::string> out;
  for (const auto& [k, v] : db_.userid_deviceids.get_iter(user_id)) out.push_back(v);
  return out;
}

// --- NEW in 42d8e88-backfill: E2E key storage (upload_keys / get_keys) -------
void Data::add_device_keys(const std::string& user_id, const std::string& device_id,
                           const nlohmann::json& keys) {
  db_.userdeviceid_devicekey.insert(user_id + '\xff' + device_id, keys.dump());
}

std::optional<nlohmann::json> Data::get_device_keys(const std::string& user_id,
                                                    const std::string& device_id) const {
  auto v = db_.userdeviceid_devicekey.get(user_id + '\xff' + device_id);
  if (!v) return std::nullopt;
  return nlohmann::json::parse(*v, nullptr, false);
}

void Data::add_one_time_key(const std::string& user_id, const std::string& device_id,
                            const std::string& key_id, const nlohmann::json& key) {
  db_.userdeviceid_onetimekey.insert(
      user_id + '\xff' + device_id + '\xff' + key_id, key.dump());
}

void Data::remove_one_time_key(const std::string& user_id, const std::string& device_id,
                               const std::string& key_id) {
  db_.userdeviceid_onetimekey.erase(user_id + '\xff' + device_id + '\xff' + key_id);
}

std::map<std::string, nlohmann::json> Data::get_one_time_keys(
    const std::string& user_id, const std::string& device_id) const {
  std::map<std::string, nlohmann::json> out;
  const std::string prefix = user_id + '\xff' + device_id + '\xff';
  for (const auto& [key, value] : db_.userdeviceid_onetimekey.scan_prefix(prefix)) {
    // key = user + 0xff + device + 0xff + key_id  -> recover key_id
    std::string key_id = key.substr(prefix.size());
    out[key_id] = nlohmann::json::parse(value, nullptr, false);
  }
  return out;
}

int Data::count_one_time_keys(const std::string& user_id,
                              const std::string& device_id) const {
  const std::string prefix = user_id + '\xff' + device_id + '\xff';
  return static_cast<int>(db_.userdeviceid_onetimekey.scan_prefix(prefix).size());
}

// --- NEW in dc5abd6-backfill: appservice registration storage ----------------
void Data::appservice_register(const std::string& id, const std::string& url,
                               const std::string& hs_token,
                               const std::string& sender) {
  nlohmann::json reg = nlohmann::json::object();
  reg["id"] = id;
  reg["url"] = url;
  reg["hs_token"] = hs_token;
  reg["sender"] = sender;
  db_.appserviceid_registration.insert(id, reg.dump());
  db_.appservice_token_id.insert(hs_token, id);
}

std::optional<nlohmann::json> Data::appservice_by_id(const std::string& id) const {
  auto v = db_.appserviceid_registration.get(id);
  if (!v) return std::nullopt;
  return nlohmann::json::parse(*v, nullptr, false);
}

std::optional<std::string> Data::appservice_id_from_token(
    const std::string& token) const {
  return db_.appservice_token_id.get(token);
}


/// NEW in b8193984: deactivate account — remove all devices, blank password.
void Data::deactivate_account(const std::string& user_id) {
  for (const auto& device_id : all_device_ids(user_id)) {
    remove_device(user_id, device_id);
  }
  // Empty password marks the account as deactivated (upstream convention).
  db_.userid_password.insert(user_id, "");
}

std::optional<std::string> Data::token_for_device(const std::string& user_id,
                                                   const std::string& device_id) const {
  return db_.userdeviceid_token.get(user_id + '\xff' + device_id);
}

// --- NEW in a888c7cb16: OpenID tokens ----------------------------------------

static constexpr uint64_t kOpenidTokenTtl = 3600;  // seconds (Conduit default)

std::pair<std::string, uint64_t> Data::create_openid_token(
    const std::string& user_id) {
  // token -> (expires_at, user_id)
  const std::string token = utils::random_string(24);
  const uint64_t expires_in = kOpenidTokenTtl;
  const uint64_t expires_at =
      utils::millis_since_unix_epoch() + expires_in * 1000;

  std::string value;
  value.append(reinterpret_cast<const char*>(&expires_at), sizeof(expires_at));
  value += user_id;
  db_.openidtoken_userid.insert(token, value);
  return {token, expires_in};
}

std::optional<std::string> Data::find_from_openid_token(const std::string& token) {
  const auto value = db_.openidtoken_userid.get(token);
  if (!value) return std::nullopt;
  if (value->size() < sizeof(uint64_t)) return std::nullopt;
  uint64_t expires_at = 0;
  std::memcpy(&expires_at, value->data(), sizeof(uint64_t));
  if (expires_at < utils::millis_since_unix_epoch()) {
    db_.openidtoken_userid.erase(token);
    return std::nullopt;
  }
  return value->substr(sizeof(uint64_t));
}


// --- NEW in 3aa0c8ed / 9c26e22a: aliases & visibility --------------------------

void Data::set_alias(const std::string& alias, const std::string& room_id,
                     const std::string& user_id) {
  db_.alias_creator.insert(alias, user_id);  // NEW in 144d548 (first, no stuck alias)
  db_.alias_roomid.insert(alias, room_id);
  std::string aliasid = room_id;
  const std::string index_bytes =
      db_.pduid_pdus.update_and_fetch("n" + room_id + "#aliases", utils::increment);
  aliasid += static_cast<char>(0xff);
  aliasid += utils::u64_from_bytes(index_bytes);
  aliasid += alias;
  (void)index_bytes;
  // Store alias under a unique per-room key; value is the alias itself.
  std::string key;
  key += room_id;
  const auto idx = db_.pduid_pdus.get("n" + room_id + "#aliases");
  key.push_back(static_cast<char>(0xff));
  key += idx.value_or(std::string(8, '\0'));
  db_.aliasid_alias.insert(key, alias);
}

void Data::remove_alias(const std::string& alias,
                        [[maybe_unused]] const std::string& user_id) {
  db_.alias_roomid.erase(alias);
  db_.alias_creator.erase(alias);  // NEW in 144d548
  for (const auto& [key, val] : db_.aliasid_alias.iter_all())
    if (val == alias) db_.aliasid_alias.erase(key);
}

std::optional<std::string> Data::id_from_alias(const std::string& alias) const {
  return db_.alias_roomid.get(alias);
}

std::optional<std::string> Data::who_created_alias(const std::string& alias) const {
  return db_.alias_creator.get(alias);  // NEW in 144d548
}

std::vector<std::string> Data::room_aliases(const std::string& room_id) const {
  std::vector<std::string> out;
  for (const auto& [k, v] : db_.aliasid_alias.iter_all())
    if (k.rfind(room_id, 0) == 0 || k.rfind("#", 0) == 0) out.push_back(v);
  return out;
}

void Data::set_public(const std::string& room_id, bool is_public) {
  if (is_public)
    db_.publicroomids.insert(room_id, "");
  else
    db_.publicroomids.erase(room_id);
}

bool Data::is_public(const std::string& room_id) const {
  return db_.publicroomids.contains_key(room_id);
}


std::vector<std::string> Data::room_useroncejoined(const std::string& room_id) const {
  std::vector<std::string> out;
  const std::string prefix = room_id + "ÿ";
  for (const auto& [key, value] : db_.roomuseroncejoinedids.iter_all()) {
    if (key.rfind(prefix, 0) == 0) {
      const std::string user_id = key.substr(prefix.size());
      if (!user_id.empty()) out.push_back(user_id);
    }
  }
  return out;
}

bool Data::once_joined(const std::string& user_id, const std::string& room_id) const {
  return db_.roomuseroncejoinedids.contains_key(room_id + "ÿ" + user_id);
}

std::optional<nlohmann::json> Data::room_state_get(const std::string& room_id,
                                                  const std::string& type,
                                                  const std::string& state_key) const {
  for (const auto& pdu_text : room_state(room_id)) {
    auto pdu = nlohmann::json::parse(pdu_text);
    if (pdu.value("type", "") == type && pdu.value("state_key", "") == state_key)
      return pdu["content"];
  }
  return std::nullopt;
}

std::vector<std::string> Data::public_rooms() const {
  std::vector<std::string> out;
  for (const auto& [key, value] : db_.publicroomids.iter_all())
    out.push_back(key);
  return out;
}

// --- PDU graph ------------------------------------------------------------------

std::optional<std::string> Data::pdu_get(const std::string& event_id) const {
  const auto pdu_id = db_.eventid_pduid.get(event_id);
  if (!pdu_id) return std::nullopt;
  return db_.pduid_pdus.get(*pdu_id);
}

// NEW in 18bf6774: replace a PDU with the redacted form (rooms.rs
// redact_pdu). The event JSON is rewritten in place via eventid_pduid lookup.
void Data::redact_pdu(const std::string& event_id) {
  const auto pdu_id = db_.eventid_pduid.get(event_id);
  if (!pdu_id) return;

  nlohmann::json pdu = nlohmann::json::parse(*db_.pduid_pdus.get(*pdu_id));

  // PduEvent::redact(): clear unsigned, strip content per event type.
  pdu["unsigned"] = nlohmann::json::object();
  static const std::map<std::string, std::vector<std::string>> kAllowed = {
      {"m.room.member", {"membership"}},
      {"m.room.create", {"creator"}},
      {"m.room.join_rules", {"join_rule"}},
      {"m.room.power_levels",
       {"ban", "events", "events_default", "kick", "redact",
        "state_default", "users", "users_default"}},
      {"m.room.history_visibility", {"history_visibility"}},
  };
  const std::string type = pdu.value("type", "");
  auto rule = kAllowed.find(type);
  nlohmann::json new_content = nlohmann::json::object();
  if (rule != kAllowed.end() && pdu.contains("content")) {
    for (const auto& key : rule->second)
      if (pdu["content"].contains(key)) new_content[key] = pdu["content"][key];
  }
  pdu["content"] = std::move(new_content);

  db_.pduid_pdus.insert(*pdu_id, pdu.dump());
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
      } else if (target_membership == "knock") {
        // NEW in 21af83e: a user may only knock for themselves, and only in a
        // room whose join rule permits knocking.
        if (sender != target_user) authorized = false;
        else if (join_rule != "knock") authorized = false;
        else authorized = true;
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
  // Compute the auth-event chain from the room's current state (Matrix spec):
  // m.room.create, m.room.power_levels, m.room.join_rules, the sender's own
  // m.room.member, and — for m.room.member events — the target's membership.
  {
    nlohmann::json auth_events = nlohmann::json::array();
    const std::string ev_type = event.value("type", "");
    const std::string ev_sender = event.value("sender", "");
    const std::string ev_state_key = event.value("state_key", "");
    for (const auto& state_text : room_state(room_id)) {
      auto st = nlohmann::json::parse(state_text, nullptr, false);
      if (st.is_discarded()) continue;
      const std::string t = st.value("type", "");
      const std::string sk = st.value("state_key", "");
      bool is_auth = false;
      if (t == "m.room.create" || t == "m.room.power_levels" ||
          t == "m.room.join_rules") {
        is_auth = true;
      } else if (t == "m.room.member") {
        if (sk == ev_sender) is_auth = true;
        if (ev_type == "m.room.member" && sk == ev_state_key) is_auth = true;
      }
      if (is_auth) {
        const std::string aid = st.value("event_id", "");
        if (!aid.empty()) auth_events.push_back(aid);
      }
    }
    event["auth_events"] = std::move(auth_events);
  }

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

bool Data::room_exists(const std::string& room_id) const {
  return db_.pduid_pdus.get("n" + room_id).has_value();
}

// NEW in f7816b11d: participating servers of a room (federation).
void Data::add_room_server(const std::string& room_id, const std::string& server) {
  std::string key = room_id;
  key.push_back(static_cast<char>(0xff));
  key += server;
  db_.roomserverids.insert(key, "");
}

std::vector<std::string> Data::room_servers(const std::string& room_id) const {
  std::vector<std::string> out;
  std::string prefix = room_id;
  prefix.push_back(static_cast<char>(0xff));
  for (const auto& [k, v] : db_.roomserverids.scan_prefix(prefix))
    out.push_back(k.substr(room_id.size() + 1));
  return out;
}

// --- NEW in 821c608c: media repository -----------------------------------------

void Data::media_create(const std::string& server_name, const std::string& media_id,
                        const std::optional<std::string>& filename,
                        const std::optional<std::string>& content_type, const std::string& file,
                        const std::optional<std::string>& user_id) {
  db_.media.create(server_name, media_id, filename, content_type, file,
                   media_unauthenticated_access_permitted_, user_id);
}

std::optional<database::Media::File> Data::media_get(const std::string& server_name,
                                                     const std::string& media_id,
                                                     bool authenticated) {
  return db_.media.get(server_name, media_id, authenticated);
}

bool Data::media_remove(const std::string& server_name, const std::string& media_id, bool force) {
  return db_.media.remove(server_name, media_id, force);
}

size_t Data::media_remove_by_user(const std::string& server_name, const std::string& user_id,
                                  bool force, const std::optional<uint64_t>& after_ms) {
  return db_.media.remove_by_user(server_name, user_id, force, after_ms);
}

size_t Data::media_remove_by_server(const std::string& server_name, bool force,
                                    const std::optional<uint64_t>& after_ms) {
  return db_.media.remove_by_server(server_name, force, after_ms);
}

bool Data::media_is_blocked(const std::string& server_name, const std::string& media_id) const {
  return db_.media.is_blocked(server_name, media_id);
}

void Data::media_block(const std::string& server_name, const std::string& media_id,
                       const std::string& reason) {
  db_.media.block(server_name, media_id, reason, utils::millis_since_unix_epoch() / 1000);
}

size_t Data::media_block_by_user(const std::string& server_name, const std::string& user_id,
                                 const std::string& reason,
                                 const std::optional<uint64_t>& after_secs) {
  return db_.media.block_by_user(server_name, user_id, reason,
                                 utils::millis_since_unix_epoch() / 1000, after_secs);
}

bool Data::media_unblock(const std::string& server_name, const std::string& media_id) {
  return db_.media.unblock(server_name, media_id);
}

std::vector<database::Media::BlockedMediaInfo> Data::media_list_blocked() const {
  return db_.media.list_blocked();
}

size_t Data::media_cleanup_time_retention() {
  return db_.media.cleanup_time_retention(media_retention_);
}

size_t Data::media_clear_required_space(bool thumbnail, uint64_t new_size) {
  return db_.media.clear_required_space(media_retention_, thumbnail, new_size);
}

const std::vector<database::RetentionPolicy>& Data::media_retention() const {
  return media_retention_;
}

std::optional<database::Media::MediaQuery> Data::media_query(
    const std::string& server_name, const std::string& media_id) const {
  return db_.media.media_query(server_name, media_id);
}

std::vector<database::Media::MediaListItem> Data::media_list(
    const std::optional<std::string>& server_name,
    const std::optional<std::string>& user_id,
    const std::optional<std::string>& content_type,
    const std::optional<uint64_t>& before_ms,
    const std::optional<uint64_t>& after_ms) const {
  return db_.media.media_list(server_name, user_id, content_type, before_ms, after_ms);
}

uint64_t Data::media_cleanup_interval_ms() const {
  // Conduit cleans every 1/10th of the shortest retention time, clamped to
  // [60s, 24h]. Compute from the accessed/created policies.
  uint64_t shortest = ~0ull;
  for (const auto& p : media_retention_) {
    if (p.accessed_ms) shortest = std::min(shortest, *p.accessed_ms);
    if (p.created_ms) shortest = std::min(shortest, *p.created_ms);
  }
  uint64_t interval = shortest == ~0ull ? 24ull * 3600 * 1000 : shortest / 10;
  interval = std::max<uint64_t>(60000, std::min<uint64_t>(interval, 24ull * 3600 * 1000));
  return interval;
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

// NEW in 12a8c9ba: federation helpers -----------------------------------------
std::vector<nlohmann::json> Data::federation_full_state(const std::string& room_id) const {
  // Derive current state from the room's PDUs directly (latest event wins per
  // (type, state_key)), rather than relying on room_state which is only populated
  // by pdu_append's auth-gated path.
  std::map<std::string, nlohmann::json> latest;
  for (const auto& text : pdus_since(room_id, 0)) {
    nlohmann::json p;
    try { p = nlohmann::json::parse(text); } catch (...) { continue; }
    if (!p.contains("type") || !p.contains("state_key")) continue;
    std::string k = p["type"].get<std::string>() + std::string(1, '\xff') +
                    p["state_key"].get<std::string>();
    latest[k] = std::move(p);
  }
  std::vector<nlohmann::json> out;
  for (auto& kv : latest) out.push_back(std::move(kv.second));
  return out;
}

std::vector<nlohmann::json> Data::federation_auth_chain(
    const std::string& room_id, const std::vector<std::string>& event_ids) const {
  std::vector<nlohmann::json> out;
  std::set<std::string> seen;
  std::vector<std::string> queue = event_ids;
  while (!queue.empty()) {
    std::string id = queue.back();
    queue.pop_back();
    if (seen.count(id)) continue;
    seen.insert(id);
    auto t = pdu_get(id);
    if (!t) continue;
    nlohmann::json p;
    try { p = nlohmann::json::parse(*t); } catch (...) { continue; }
    out.push_back(p);
    if (p.contains("auth_events") && p["auth_events"].is_array()) {
      for (auto& a : p["auth_events"]) {
        std::string aid;
        if (a.is_string()) aid = a.get<std::string>();
        else if (a.is_array() && a.size())
          aid = a[0].is_string() ? a[0].get<std::string>() : std::string();
        if (!aid.empty()) queue.push_back(aid);
      }
    }
  }
  return out;
}

std::vector<nlohmann::json> Data::federation_pdus_of_room(const std::string& room_id) const {
  std::vector<nlohmann::json> out;
  for (const auto& text : pdus_since(room_id, 0)) {
    try { out.push_back(nlohmann::json::parse(text)); } catch (...) {}
  }
  return out;
}


bool Data::room_invite(const std::string& sender, const std::string& room_id,
                       const std::string& user_id, const std::string& reason) {
  // m.room.member invite state event, appended like any other pdu.
  // NEW in 346913268f: preserve a client-supplied invite reason (and any
  // provided content) instead of overwriting it with a fixed content, mirroring
  // Conduit's populate_membership_template which keeps provided fields.
  nlohmann::json content = {{"membership", "invite"}};
  if (!reason.empty()) content["reason"] = reason;

  nlohmann::json event = {
      {"type", "m.room.member"},
      {"content", std::move(content)},
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

  // NEW in 21af83e: resolving a knock (by invite) clears the knock state.
  db_.userroomid_knockstate.erase(user_id + '\xff' + room_id);
  db_.roomuserid_knockcount.erase(room_id + '\xff' + user_id);

  db_.userid_inviteroomids.add(user_id, room_id);
  return true;
}

std::vector<std::string> Data::rooms_invited(const std::string& user_id) const {
  std::vector<std::string> rooms;
  for (const auto& [key, value] : db_.userid_inviteroomids.get_iter(user_id)) {
    rooms.push_back(value);
  }
  return rooms;
}

// --- NEW in 3f4cb753: key backup store (folded base + remaining endpoints) ---

std::string Data::backup_create(const std::string& user_id,
                                const nlohmann::json& algorithm) {
  std::string version = utils::random_string(24);
  std::string k = user_id + '\xff' + version;
  db_.backupid_algorithm.insert(k, algorithm.dump());
  db_.backupid_etag.insert(k, "0");
  db_.backup_latest.insert(user_id, version);
  return version;
}

std::optional<std::string> Data::backup_latest(const std::string& user_id) const {
  auto v = db_.backup_latest.get(user_id);
  if (v) return *v;
  return std::nullopt;
}

std::optional<nlohmann::json> Data::backup_get(const std::string& user_id,
                                               const std::string& version) const {
  std::string k = user_id + '\xff' + version;
  auto a = db_.backupid_algorithm.get(k);
  if (!a) return std::nullopt;
  nlohmann::json algorithm = nlohmann::json::parse(*a, nullptr, false);
  return nlohmann::json{
      {"algorithm", algorithm},
      {"count", backup_count(user_id, version)},
      {"etag", backup_etag(user_id, version)},
      {"version", version},
  };
}

void Data::backup_update(const std::string& user_id, const std::string& version,
                         const nlohmann::json& algorithm) {
  std::string k = user_id + '\xff' + version;
  db_.backupid_algorithm.insert(k, algorithm.dump());
}

std::string Data::backup_add_key(const std::string& user_id, const std::string& version,
                                 const std::string& room_id, const std::string& session_id,
                                 const nlohmann::json& key_data) {
  std::string k = user_id + '\xff' + version + '\xff' + room_id + '\xff' + session_id;
  db_.backupkeyid_backup.insert(k, key_data.dump());
  std::string ek = user_id + '\xff' + version;
  std::string etag = backup_etag(user_id, version);
  long cur = 0;
  try {
    cur = std::stol(etag);
  } catch (...) {
  }
  std::string next = std::to_string(cur + 1);
  db_.backupid_etag.insert(ek, next);
  return next;
}

size_t Data::backup_count(const std::string& user_id, const std::string& version) const {
  std::string prefix = user_id + '\xff' + version + '\xff';
  return db_.backupkeyid_backup.scan_prefix(prefix).size();
}

std::string Data::backup_etag(const std::string& user_id, const std::string& version) const {
  std::string k = user_id + '\xff' + version;
  auto v = db_.backupid_etag.get(k);
  return v ? *v : "0";
}

nlohmann::json Data::backup_get_keys(const std::string& user_id,
                                     const std::string& version) const {
  std::string prefix = user_id + '\xff' + version + '\xff';
  nlohmann::json rooms = nlohmann::json::object();
  for (const auto& [key, value] : db_.backupkeyid_backup.scan_prefix(prefix)) {
    size_t p1 = key.rfind('\xff');
    std::string session_id = key.substr(p1 + 1);
    std::string rest = key.substr(0, p1);
    size_t p2 = rest.rfind('\xff');
    std::string room_id = rest.substr(p2 + 1);
    nlohmann::json key_data = nlohmann::json::parse(value, nullptr, false);
    if (!rooms.contains(room_id)) rooms[room_id] = nlohmann::json::object();
    rooms[room_id][session_id] = key_data;
  }
  return rooms;
}

void Data::backup_delete(const std::string& user_id, const std::string& version) {
  std::string k = user_id + '\xff' + version;
  db_.backupid_algorithm.erase(k);
  db_.backupid_etag.erase(k);
  db_.backup_latest.erase(user_id);
  std::string prefix = k + '\xff';
  for (const auto& [key, value] : db_.backupkeyid_backup.scan_prefix(prefix)) {
    db_.backupkeyid_backup.erase(key);
  }
}

nlohmann::json Data::backup_get_room(const std::string& user_id, const std::string& version,
                                    const std::string& room_id) const {
  std::string prefix = user_id + '\xff' + version + '\xff' + room_id + '\xff';
  nlohmann::json sessions = nlohmann::json::object();
  for (const auto& [key, value] : db_.backupkeyid_backup.scan_prefix(prefix)) {
    size_t p = key.rfind('\xff');
    std::string session_id = key.substr(p + 1);
    sessions[session_id] = nlohmann::json::parse(value, nullptr, false);
  }
  return sessions;
}

std::optional<nlohmann::json> Data::backup_get_session(const std::string& user_id,
                                                      const std::string& version,
                                                      const std::string& room_id,
                                                      const std::string& session_id) const {
  std::string k = user_id + '\xff' + version + '\xff' + room_id + '\xff' + session_id;
  auto v = db_.backupkeyid_backup.get(k);
  if (!v) return std::nullopt;
  return nlohmann::json::parse(*v, nullptr, false);
}

void Data::backup_delete_all_keys(const std::string& user_id, const std::string& version) {
  std::string prefix = user_id + '\xff' + version + '\xff';
  for (const auto& [key, value] : db_.backupkeyid_backup.scan_prefix(prefix)) {
    db_.backupkeyid_backup.erase(key);
  }
}

void Data::backup_delete_room_keys(const std::string& user_id, const std::string& version,
                                   const std::string& room_id) {
  std::string prefix = user_id + '\xff' + version + '\xff' + room_id + '\xff';
  for (const auto& [key, value] : db_.backupkeyid_backup.scan_prefix(prefix)) {
    db_.backupkeyid_backup.erase(key);
  }
}

void Data::backup_delete_room_key(const std::string& user_id, const std::string& version,
                                 const std::string& room_id, const std::string& session_id) {
  std::string k = user_id + '\xff' + version + '\xff' + room_id + '\xff' + session_id;
  db_.backupkeyid_backup.erase(k);
}

// NEW in b5e3185: room version rules (MSC4289/4291)
const Data::RoomVersionRules Data::DEFAULT_ROOM_VERSION_RULES = {
    "1",  // version
    true,  // explicitly_privilege_room_creators
    false, // additional_room_creators
    false  // use_room_create_sender
};

Data::RoomVersionRules Data::get_room_version_rules(const std::string& version) {
  // For now, only room version "1" is supported.
  // Future versions can be added here.
  if (version == "1") {
    return DEFAULT_ROOM_VERSION_RULES;
  }
  // Unknown version -> default to legacy behavior
  return DEFAULT_ROOM_VERSION_RULES;
}
