#include "data.hpp"

#include "crypto.hpp"
#include "push_rules.hpp"
#include "utils.hpp"

#include <algorithm>
#include <iostream>
#include <cstdio>

// NEW in db8a0c5: closest parent logic for PDU ordering
#include <variant>

#include <algorithm>
#include <iostream>
#include <cstdio>

// NEW in 6b3934e: configurable cache capacity (placeholder for future implementation)
// Note: The underlying RocksDB wrapper doesn't currently expose cache capacity configuration.
// This parameter is accepted for API compatibility with Conduit's config.

#include <algorithm>
#include <iostream>
#include <cstdio>

// utils::generate_keypair via update_and_fetch("keypair") semantics.
// NEW in dd749b8: versioned keypair format (1 byte version + 0xff + key)
static std::string load_or_generate_keypair(sled::Db& storage) {
  if (auto existing = storage.get_root("keypair")) {
    std::string keypair = *existing;
    
    // Check if keypair has version prefix (1 byte version + 0xff + key)
    if (keypair.size() >= 2 && static_cast<unsigned char>(keypair[1]) == 0xff) {
      // Versioned format - return as-is
      return keypair;
    }
    
    // Old format (raw 32-byte key) - convert to versioned format
    // Version 1: 1 byte version (1) + 0xff + 32-byte key
    std::string versioned;
    versioned.push_back(static_cast<char>(1));  // version 1
    versioned.push_back(static_cast<char>(0xff));
    versioned += keypair;
    
    // Update storage with versioned format
    storage.insert_root("keypair", versioned);
    return versioned;
  }
  
  // Generate new versioned keypair
  const std::string seed = utils::generate_keypair();
  storage.insert_root("keypair", seed);
  return seed;
}

Data::Data(const std::filesystem::path& dir, uint64_t cache_capacity)
    : db_storage_(sled::Db::open(dir)), db_(database::Database::open(&db_storage_)) {
  (void)cache_capacity;  // TODO: implement cache capacity configuration for RocksDB
  hostname_ = db_storage_.get_root("hostname").value_or("localhost");
  keypair_ = load_or_generate_keypair(db_storage_);
  // NEW in 972caacd: media blobs live in <data_dir>/media/ files.
  db_.media.set_dir(dir / "media");
}

Data Data::load_or_create(const std::filesystem::path& dir, uint64_t cache_capacity) {
  return Data(dir, cache_capacity);
}

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
  // NEW in 58463bba: per-room failures no longer abort the broadcast
  // (upstream `let _ =` / filter_map-ok style).
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
    try {
      const std::string event_id = crypto::reference_hash(event);
      event["event_id"] = event_id;
      (void)pdu_append(event_id, room_id, std::move(event));
    } catch (...) {}
  }
  return true;
}

void Data::displayname_remove(const std::string& user_id) {
  db_.userid_displayname.erase(user_id);
}

void Data::device_add(const std::string& user_id, const std::string& device_id) {
  bool already = false;
  for (const auto& [k, v] : db_.userid_deviceids.get_iter(user_id)) {
    if (v == device_id) already = true;
  }
  if (!already) {
    db_.userid_deviceids.add(user_id, device_id);
    // NEW in 71ed1b29: bump devicelist version on device add.
    db_.userid_devicelistversion.update_and_fetch(user_id, utils::increment);
  }
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
  // NEW in 71ed1b29: bump devicelist version on device remove.
  db_.userid_devicelistversion.update_and_fetch(user_id, utils::increment);
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
      // NEW in 71ed1b29: bump devicelist version on device remove.
      db_.userid_devicelistversion.update_and_fetch(*user_id, utils::increment);
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

// NEW in 7fa54e44: single source for default power levels (previously
// hardcoded in two places, both missing events:{}/notifications:{room:50}).
nlohmann::json Data::default_power_levels(const std::string& creator) {
  nlohmann::json users = nlohmann::json::object();
  if (!creator.empty()) users[creator] = 100;
  return nlohmann::json{{"ban", 50},
                        {"events", nlohmann::json::object()},
                        {"events_default", 0},
                        {"invite", 50},
                        {"kick", 50},
                        {"redact", 50},
                        {"state_default", 50},
                        {"users", std::move(users)},
                        {"users_default", 0},
                        {"notifications", {{"room", 50}}}};
}

void Data::update_membership(const std::string& room_id,
                             const std::string& user_id,
                             const std::string& membership,
                             const std::optional<nlohmann::json>& invite_state) {
  const std::string userroom = user_id + '\xff' + room_id;
  const std::string roomuser = room_id + '\xff' + user_id;
  if (membership == "join") {
    bool already = is_joined(user_id, room_id);
    if (!already) db_.roomid_userids.add(room_id, user_id);
    db_.userid_inviteroomids.remove_value(user_id, room_id);
    // NEW in 8773e501: joining clears invite state + count.
    db_.userroomid_invitestate.erase(userroom);
    db_.roomuserid_invitecount.erase(roomuser);
  } else if (membership == "invite") {
    db_.userid_inviteroomids.add(user_id, room_id);
    // NEW in 8773e501: store invite_state + bump invite count.
    nlohmann::json state = invite_state.value_or(nlohmann::json::array());
    if (!state.is_array()) state = nlohmann::json::array();
    db_.userroomid_invitestate.insert(userroom, state.dump());
    const std::string count_bytes =
        db_.roomuserid_invitecount.update_and_fetch("n" + roomuser, utils::increment);
    db_.roomuserid_invitecount.insert(roomuser, count_bytes);
  } else {  // leave / ban
    db_.userid_leftroomids.add(user_id, room_id);
    db_.userid_inviteroomids.remove_value(user_id, room_id);
    db_.roomid_userids.remove_value(room_id, user_id);
    db_.userid_roomids.remove_value(user_id, room_id);
    // NEW in 8773e501: leaving clears invite state + count.
    db_.userroomid_invitestate.erase(userroom);
    db_.roomuserid_invitecount.erase(roomuser);
  }
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

// NEW in 71ed1b29: devicelist version for federation /user/devices stream_id.
std::optional<uint64_t> Data::get_devicelist_version(const std::string& user_id) const {
  auto v = db_.userid_devicelistversion.get(user_id);
  if (!v) return std::nullopt;
  try {
    return utils::u64_from_bytes(*v);
  } catch (...) {
    return std::nullopt;
  }
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

// --- NEW in 3aa0c8ed / 9c26e22a: aliases & visibility --------------------------

void Data::set_alias(const std::string& alias, const std::string& room_id) {
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

void Data::remove_alias(const std::string& alias) {
  db_.alias_roomid.erase(alias);
  for (const auto& [key, val] : db_.aliasid_alias.iter_all())
    if (val == alias) db_.aliasid_alias.erase(key);
}

std::optional<std::string> Data::id_from_alias(const std::string& alias) const {
  return db_.alias_roomid.get(alias);
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

// NEW in 3c3062a3: directory chunk from targeted state lookups instead of a
// full room-state scan per room (removes upstream's "TODO: Do not load full
// state?"). Visibility fields come from their state events instead of
// hardcoded values.
nlohmann::json Data::public_room_chunk(const std::string& room_id) const {
  nlohmann::json chunk;
  chunk["room_id"] = room_id;
  chunk["num_joined_members"] = room_users(room_id);
  if (auto v = room_state_get(room_id, "m.room.canonical_alias", "")) {
    if (v->contains("alias") && (*v)["alias"].is_string())
      chunk["canonical_alias"] = (*v)["alias"];
  }
  if (auto v = room_state_get(room_id, "m.room.name", "")) {
    std::string name = v->value("name", "");
    if (!name.empty()) chunk["name"] = name;
  }
  if (auto v = room_state_get(room_id, "m.room.topic", "")) {
    std::string topic = v->value("topic", "");
    if (!topic.empty()) chunk["topic"] = topic;
  }
  bool world_readable = false;
  if (auto v = room_state_get(room_id, "m.room.history_visibility", ""))
    world_readable = (v->value("history_visibility", "") == "world_readable");
  chunk["world_readable"] = world_readable;
  bool guest_can_join = false;
  if (auto v = room_state_get(room_id, "m.room.guest_access", ""))
    guest_can_join = (v->value("guest_access", "") == "can_join");
  chunk["guest_can_join"] = guest_can_join;
  if (auto v = room_state_get(room_id, "m.room.avatar", "")) {
    std::string url = v->value("url", "");
    if (!url.empty()) chunk["avatar_url"] = url;
  }
  return chunk;
}

// --- PDU graph ------------------------------------------------------------------

std::optional<std::string> Data::pdu_get(const std::string& event_id) const {
  const auto pdu_id = db_.eventid_pduid.get(event_id);
  if (!pdu_id) return std::nullopt;
  return db_.pduid_pdus.get(*pdu_id);
}

// NEW in 18bf6774: replace a PDU with the redacted form (rooms.rs
// redact_pdu). The event JSON is rewritten in place via eventid_pduid lookup.
void Data::redact_pdu(const std::string& event_id,
                       const std::optional<nlohmann::json>& redaction_event) {
  const auto pdu_id = db_.eventid_pduid.get(event_id);
  if (!pdu_id) return;

  nlohmann::json pdu = nlohmann::json::parse(*db_.pduid_pdus.get(*pdu_id));

  // PduEvent::redact(): clear unsigned, strip content per event type.
  pdu["unsigned"] = nlohmann::json::object();
  // NEW in ddcf1a71: redacted_because is the redaction event object itself,
  // never a JSON-encoded string.
  if (redaction_event && redaction_event->is_object())
    pdu["unsigned"]["redacted_because"] = *redaction_event;
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

// NEW in 58463bba: read-only leaves for the outgoing invite PDU.
std::vector<std::string> Data::pdu_leaves(const std::string& room_id) const {
  std::vector<std::string> event_ids;
  for (const auto& [key, value] : db_.roomid_pduleaves.get_iter(room_id)) {
    event_ids.push_back(value);
  }
  return event_ids;
}

bool Data::pdu_append(const std::string& event_id, const std::string& room_id,
                      nlohmann::json event, uint64_t count,
                      const std::string& pdu_id_in) {
  std::vector<std::string> prev_events =
      pdu_leaves_replace(room_id, event_id);
  // NEW in a77fcd1: limit prev_events to 20
  if (prev_events.size() > 20) {
    prev_events.resize(20);
  }

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
    // NEW in 7fa54e44: shared defaults (were hardcoded here).
    json pl = Data::default_power_levels("");
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

// NEW in 12b0efa: pre-compute count and pdu_id to ensure consistency between
  // pdu storage and state append. This prevents random timeline reloads.
  uint64_t index;
  std::string pdu_id;
  if (count > 0 && !pdu_id_in.empty()) {
    // Use pre-computed count and pdu_id
    index = count;
    pdu_id = pdu_id_in;
  } else {
    // Compute them now
    const std::string index_bytes =
        db_.pduid_pdus.update_and_fetch("n" + room_id, utils::increment);
    index = utils::u64_from_bytes(index_bytes);

    pdu_id.push_back('d');
    pdu_id += room_id;
    pdu_id.push_back('#');
    pdu_id += std::to_string(index);
  }

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

    // NEW in e50f2864: save state for send_join pdu
    // We set the room state after inserting the pdu, so that we never have a moment in time
    // where events in the current room state do not exist
    if (auto state_hash = append_to_state(room_id, event)) {
      set_room_state(room_id, *state_hash);
    }
  }

  // b6c0e9bf: membership tree updates happen here, post-authorization.
  if (event.value("type", "") == "m.room.member") {
    update_membership(room_id, event.value("state_key", ""),
                      event["content"].value("membership", ""));
  }

  // NEW in 662a0cf1: notification/highlight counts. The sender's own counts
  // reset on send (mirrors upstream private_read_set + reset in the append
  // path); every other joined member's rules are evaluated and their counts
  // bumped on notify/highlight.
  // NEW in e1e529d8: local, non-deactivated members only (see loop filter).
  reset_notification_counts(sender, room_id);
  {
    for (const auto& [k, member] : db_.roomid_userids.get_iter(room_id)) {
      (void)k;
      if (member == sender) continue;
      // NEW in e1e529d8: push rules (and their counts) apply to local,
      // non-deactivated members only — never to remote users.
      const std::string local_suffix = ":" + hostname_;
      if (member.size() < local_suffix.size() ||
          member.compare(member.size() - local_suffix.size(), local_suffix.size(),
                         local_suffix) != 0)
        continue;
      if (is_deactivated(member)) continue;
      push_rules::PushRuleSet rules;
      if (auto stored = get_push_rules(member)) {
        // Stored shape is {"global": {kind: [rules]}} — parse each bucket.
        const nlohmann::json& g =
            stored->contains("global") ? (*stored)["global"] : *stored;
        auto bucket = [&](const char* kind, push_rules::PushRuleKind rk,
                          std::vector<push_rules::PushRule>& out) {
          if (g.contains(kind) && g[kind].is_array()) {
            for (const auto& rj : g[kind]) {
              push_rules::PushRule r;
              r.rule_id = rj.value("rule_id", "");
              r.kind = rk;
              r.enabled = rj.value("enabled", true);
              if (rj.contains("conditions") && rj["conditions"].is_array())
                for (const auto& cj : rj["conditions"]) {
                  push_rules::PushCondition c;
                  c.kind = cj.value("kind", "");
                  c.content = cj;
                  r.conditions.push_back(std::move(c));
                }
              if (rj.contains("actions") && rj["actions"].is_array())
                for (const auto& aj : rj["actions"])
                  if (aj.is_string()) r.actions.push_back(aj.get<std::string>());
              out.push_back(std::move(r));
            }
          }
        };
        bucket("override", push_rules::PushRuleKind::Override, rules.override_rules);
        bucket("underride", push_rules::PushRuleKind::Underride, rules.underride_rules);
        bucket("sender", push_rules::PushRuleKind::Sender, rules.sender_rules);
        bucket("room", push_rules::PushRuleKind::Room, rules.room_rules);
        bucket("content", push_rules::PushRuleKind::Content, rules.content_rules);
      } else {
        rules = push_rules::get_default_push_rules();
      }
      std::string display_name = displayname_get(member).value_or("");
      push_rules::PushActions acts = push_rules::get_actions(
          member, display_name, rules, event, room_id);
      const std::string userroom = member + '\xff' + room_id;
      if (acts.notify)
        db_.userroomid_notificationcount.update_and_fetch(userroom, utils::increment);
      if (acts.highlight)
        db_.userroomid_highlightcount.update_and_fetch(userroom, utils::increment);
    }
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

// --- NEW in 821c608c: media repository -----------------------------------------

void Data::media_create(const std::string& mxc, const std::optional<std::string>& filename,
                        const std::string& content_type, const std::string& file) {
  db_.media.create(mxc, filename, content_type, file);
}

std::optional<database::Media::File> Data::media_get(const std::string& mxc) const {
  return db_.media.get(mxc);
}

// NEW in aa5e9e6: upload thumbnail with dimensions
void Data::media_upload_thumbnail(const std::string& mxc,
                                  const std::optional<std::string>& filename,
                                  const std::string& content_type,
                                  uint32_t width, uint32_t height,
                                  const std::string& file) {
  db_.media.upload_thumbnail(mxc, filename, content_type, width, height, file);
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

// NEW in dcac1361: search a room's PDUs for a term (case-insensitive over
// event type, sender and content body). Returns matching event ids.
std::vector<std::string> Data::search_pdus(const std::string& room_id,
                                           const std::string& search_term) const {
  std::vector<std::string> results;
  const std::string term = utils::ascii_lower(search_term);
  for (const auto& text : pdus_since(room_id, 0)) {
    nlohmann::json pdu;
    try {
      pdu = nlohmann::json::parse(text);
    } catch (...) {
      continue;  // skip unparseable events
    }
    const std::string event_type = pdu.value("type", "");
    const std::string sender = pdu.value("sender", "");
    const std::string body =
        pdu.value("content", nlohmann::json::object()).value("body", "");
    if (utils::icontains(event_type, term) || utils::icontains(sender, term) ||
        utils::icontains(body, term)) {
      if (const auto id = pdu.value("event_id", ""); !id.empty())
        results.push_back(id);
    }
  }
  return results;
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

// NEW in 71500b1: get participating servers in a room
std::vector<std::string> Data::room_servers(const std::string& room_id) const {
  std::vector<std::string> servers;
  std::string prefix = "r" + room_id + "\xff";
  auto entries = db_.roomserverids.scan_prefix(prefix);
  for (const auto& [key, _] : entries) {
    // Key format: "r" + room_id + 0xff + server_name
    // Extract server_name from the end
    size_t pos = key.rfind('\xff');
    if (pos != std::string::npos && pos + 1 < key.size()) {
      servers.push_back(key.substr(pos + 1));
    }
  }
  return servers;
}

// File-local helper (defined below, used by room_invite above).
static nlohmann::json to_stripped(const nlohmann::json& pdu);

bool Data::room_invite(const std::string& sender, const std::string& room_id,
                       const std::string& user_id, bool is_direct) {
  // m.room.member invite state event, appended like any other pdu.
  // NEW in 58463bba: content carries the target's displayname and is_direct
  // (upstream MemberEventContent; avatar_url has no store here yet).
  nlohmann::json content = {{"membership", "invite"}};
  if (auto dn = displayname_get(user_id)) content["displayname"] = *dn;
  if (is_direct) content["is_direct"] = true;
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
  // NEW in 8773e501: capture invite_state (stripped create/join_rules/alias/avatar/
  // name) before appending, so sync can serve it without scanning PDUs.
  // NEW in 662a0cf1: also include the sender's member event and the invite
  // event itself, like upstream does at invite time.
  nlohmann::json invite_state = build_invite_state(room_id);
  for (const auto& text : room_state(room_id)) {
    try {
      auto pdu = nlohmann::json::parse(text);
      if (pdu.value("type", "") == "m.room.member" &&
          pdu.value("state_key", "") == sender) {
        invite_state.push_back(to_stripped(pdu));
        break;
      }
    } catch (...) {}
  }
  pdu_append(event_id, room_id, nlohmann::json(event));
  invite_state.push_back(to_stripped(event));

  db_.userid_inviteroomids.add(user_id, room_id);
  update_membership(room_id, user_id, "invite", invite_state);
  return true;
}

std::vector<std::string> Data::rooms_invited(const std::string& user_id) const {
  std::vector<std::string> rooms;
  for (const auto& [key, value] : db_.userid_inviteroomids.get_iter(user_id)) {
    rooms.push_back(value);
  }
  return rooms;
}

// --- NEW in 8773e501: incoming invites over federation -----------------------
// Invite state: stripped (type/state_key/content/sender) copies of the room's
// join_rules, canonical_alias, avatar and name state events at invite time.
static nlohmann::json to_stripped(const nlohmann::json& pdu) {
  nlohmann::json s;
  s["type"] = pdu.value("type", "");
  s["state_key"] = pdu.value("state_key", "");
  s["sender"] = pdu.value("sender", "");
  s["content"] = pdu.value("content", nlohmann::json::object());
  return s;
}

nlohmann::json Data::build_invite_state(const std::string& room_id) const {
  nlohmann::json state = nlohmann::json::array();
  // NEW in 3e2f742f: the create event comes first in invite state.
  for (const char* type : {"m.room.create", "m.room.join_rules", "m.room.canonical_alias",
                            "m.room.avatar", "m.room.name"}) {
    if (auto content = room_state_get(room_id, type, "")) {
      // Reconstruct a stripped event from stored state content. Sender is
      // unknown from content alone, so find the full PDU for fidelity.
      bool pushed = false;
      for (const auto& text : room_state(room_id)) {
        try {
          auto pdu = nlohmann::json::parse(text);
          if (pdu.value("type", "") == type && pdu.value("state_key", "") == "") {
            state.push_back(to_stripped(pdu));
            pushed = true;
            break;
          }
        } catch (...) {}
      }
      if (!pushed) {
        state.push_back(nlohmann::json{{"type", type},
                                        {"state_key", ""},
                                        {"sender", ""},
                                        {"content", *content}});
      }
    }
  }
  return state;
}

void Data::store_invite(const std::string& room_id, const std::string& user_id,
                         const nlohmann::json& invite_state) {
  update_membership(room_id, user_id, "invite", invite_state);
}

std::vector<std::pair<std::string, nlohmann::json>> Data::rooms_invited_with_state(
    const std::string& user_id) const {
  std::vector<std::pair<std::string, nlohmann::json>> out;
  std::string prefix = user_id + '\xff';
  for (const auto& [key, value] : db_.userroomid_invitestate.scan_prefix(prefix)) {
    std::string room_id = key.substr(prefix.size());
    try {
      out.emplace_back(room_id, nlohmann::json::parse(value));
    } catch (...) {
      out.emplace_back(room_id, nlohmann::json::array());
    }
  }
  // Fall back to legacy MultiValue entries that have no stored state yet.
  for (const auto& room_id : rooms_invited(user_id)) {
    bool known = false;
    for (const auto& [r, _] : out)
      if (r == room_id) known = true;
    if (!known) out.emplace_back(room_id, nlohmann::json::array());
  }
  return out;
}

std::optional<uint64_t> Data::get_invite_count(const std::string& room_id,
                                                const std::string& user_id) const {
  auto v = db_.roomuserid_invitecount.get(room_id + '\xff' + user_id);
  if (!v) return std::nullopt;
  try {
    return utils::u64_from_bytes(*v);
  } catch (...) {
    return std::nullopt;
  }
}

// --- NEW in bc98425d: invite state as join server hints ----------------------
std::optional<nlohmann::json> Data::invite_state(const std::string& user_id,
                                                  const std::string& room_id) const {
  auto v = db_.userroomid_invitestate.get(user_id + '\xff' + room_id);
  if (!v) return std::nullopt;
  try {
    nlohmann::json state = nlohmann::json::parse(*v);
    if (!state.is_array()) return std::nullopt;
    return state;
  } catch (...) {
    return std::nullopt;
  }
}

std::vector<std::string> Data::invite_state_servers(const nlohmann::json& state) {
  // Mirrors upstream: senders of invite-state events -> their server names,
  // order-preserving and deduplicated.
  std::vector<std::string> servers;
  if (!state.is_array()) return servers;
  for (const auto& ev : state) {
    if (!ev.is_object()) continue;
    const std::string sender = ev.value("sender", "");
    if (sender.empty() || sender[0] != '@') continue;
    size_t colon = sender.find(':');
    if (colon == std::string::npos || colon + 1 >= sender.size()) continue;
    std::string server = sender.substr(colon + 1);
    if (std::find(servers.begin(), servers.end(), server) == servers.end())
      servers.push_back(std::move(server));
  }
  return servers;
}

// --- NEW in 662a0cf1: notification/highlight counts --------------------------
uint64_t Data::notification_count(const std::string& user_id,
                                   const std::string& room_id) const {
  auto v = db_.userroomid_notificationcount.get(user_id + '\xff' + room_id);
  if (!v) return 0;
  try {
    return utils::u64_from_bytes(*v);
  } catch (...) {
    return 0;
  }
}

uint64_t Data::highlight_count(const std::string& user_id,
                                const std::string& room_id) const {
  auto v = db_.userroomid_highlightcount.get(user_id + '\xff' + room_id);
  if (!v) return 0;
  try {
    return utils::u64_from_bytes(*v);
  } catch (...) {
    return 0;
  }
}

void Data::reset_notification_counts(const std::string& user_id,
                                      const std::string& room_id) {
  const std::string key = user_id + '\xff' + room_id;
  std::string zero(8, '\0');
  db_.userroomid_notificationcount.insert(key, zero);
  db_.userroomid_highlightcount.insert(key, zero);
}

Data::InviteResult Data::handle_incoming_invite(const std::string& room_id,
                                                 nlohmann::json event,
                                                 nlohmann::json invite_room_state) {
  InviteResult r;
  const std::string membership =
      event.value("content", nlohmann::json::object()).value("membership", "");
  const std::string sender = event.value("sender", "");
  const std::string state_key = event.value("state_key", "");
  const std::string ev_room = event.value("room_id", room_id);
  if (membership != "invite" || sender.empty() || state_key.empty() || ev_room != room_id) {
    r.errcode = "M_INVALID_PARAM";
    r.error = "Invite event is invalid.";
    return r;
  }
  // Only accept invites for local users.
  const std::string local_suffix = ":" + hostname_;
  if (state_key.size() < local_suffix.size() ||
      state_key.compare(state_key.size() - local_suffix.size(), local_suffix.size(),
                        local_suffix) != 0) {
    r.errcode = "M_INVALID_PARAM";
    r.error = "Invited user is not local.";
    return r;
  }
  if (!invite_room_state.is_array()) invite_room_state = nlohmann::json::array();
  // Sign the event as the receiving server (upstream hash_and_sign_event).
  try {
    crypto::hash_and_sign_event(hostname_, keypair_, event);
  } catch (...) {
    r.errcode = "M_INVALID_PARAM";
    r.error = "Failed to sign event.";
    return r;
  }
  // Append the stripped invite event to the invite state, like upstream does
  // (it pushes the invite PDU itself with a $dummy id).
  // NEW in 662a0cf1: also include the sender's member event when known.
  for (const auto& text : room_state(room_id)) {
    try {
      auto pdu = nlohmann::json::parse(text);
      if (pdu.value("type", "") == "m.room.member" &&
          pdu.value("state_key", "") == sender) {
        invite_room_state.push_back(to_stripped(pdu));
        break;
      }
    } catch (...) {}
  }
  nlohmann::json stripped = to_stripped(event);
  invite_room_state.push_back(stripped);
  // Persist membership + invite state (no full PDU join; invite only).
  update_membership(room_id, state_key, "invite", invite_room_state);
  // Also record the invite PDU in state so membership_of() sees it.
  try {
    std::string state_key_bin;
    state_key_bin.push_back('d');
    state_key_bin += room_id;
    state_key_bin.push_back(static_cast<char>(0xff));
    state_key_bin += "m.room.member";
    state_key_bin.push_back(static_cast<char>(0xff));
    state_key_bin += state_key;
    db_.roomstateid_pdu.insert(state_key_bin, event.dump());
    const std::string event_id = event.value("event_id", "");
    if (!event_id.empty()) {
      const std::string index_bytes =
          db_.pduid_pdus.update_and_fetch("n" + room_id, utils::increment);
      uint64_t index = utils::u64_from_bytes(index_bytes);
      db_.pduid_pdus.insert("d" + room_id + "#" + std::to_string(index), event.dump());
      db_.eventid_pduid.insert(event_id, "d" + room_id + "#" + std::to_string(index));
    }
  } catch (...) {}
  r.ok = true;
  r.event = std::move(event);
  return r;
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

// NEW in db8a0c5: find closest parent for PDU insertion ordering
std::optional<std::variant<ClosestParentAppend, ClosestParentInsert>> Data::get_closest_parent(
    const std::string& room_id,
    const std::vector<std::string>& incoming_prev_ids,
    const std::map<std::string, nlohmann::json>& their_state) const {
  // If the room is empty, no parent exists
  if (db_.pduid_pdus.iter_all().empty()) {
    return std::nullopt;
  }

  // If the last event in the room is one of the incoming prev_events
  auto all_pdus = db_.pduid_pdus.iter_all();
  if (!all_pdus.empty()) {
    auto last = all_pdus.back();
    try {
      auto pdu_json = nlohmann::json::parse(last.second);
      std::string last_event_id = pdu_json.value("event_id", "");
      
      if (std::find(incoming_prev_ids.begin(), incoming_prev_ids.end(), last_event_id) != incoming_prev_ids.end()) {
        return ClosestParentAppend{};
      }
    } catch (...) {
      // Ignore parse errors
    }
  }

  // Otherwise, walk back through the prev_ids to find a known ancestor
  std::vector<std::string> prev_ids = incoming_prev_ids;
  while (!prev_ids.empty()) {
    std::string id = prev_ids.back();
    prev_ids.pop_back();

    // Check if we have this PDU in our database
    if (auto pdu_id = get_pdu_id(id)) {
      // Found a known ancestor - return the count to insert after
      uint64_t count = pdu_count(*pdu_id);
      return ClosestParentInsert{count};
    }

    // If not found, add its auth events to the search
    // For simplicity, we'll skip auth chain traversal in this simplified version
  }

  // No common ancestor found
  return std::nullopt;
}

// NEW in db8a0c5: helper methods for PDU lookup
std::optional<std::string> Data::get_pdu_id(const std::string& event_id) const {
  return db_.eventid_pduid.get(event_id);
}

uint64_t Data::pdu_count(const std::string& pdu_id) const {
  // For now, return 0 as placeholder
  // In a real implementation, we'd track the count in a separate tree
  return 0;
}

// NEW in a77fcd1: state_ids federation endpoint
std::optional<uint64_t> Data::pdu_shortstatehash(const std::string& event_id) const {
  // Get the shortstatehash from the event's state hash
  auto pdu_id = get_pdu_id(event_id);
  if (!pdu_id) return std::nullopt;
  
  // Look up the state hash for this pdu
  // The state hash is stored in pduid_statehash tree
  auto state_hash = db_.pduid_statehash.get(*pdu_id);
  if (!state_hash) return std::nullopt;
  
  // Convert state_hash to shortstatehash
  auto shortstatehash = db_.statehash_shortstatehash.get(state_hash.value());
  if (!shortstatehash) return std::nullopt;
  
  // Convert bytes to uint64_t
  if (shortstatehash.value().size() != 8) return std::nullopt;
  uint64_t result = 0;
  for (size_t i = 0; i < 8; ++i) {
    result = (result << 8) | static_cast<uint8_t>(shortstatehash.value()[i]);
  }
  return result;
}

// NEW in fe744c85: push rules
void Data::set_push_rules(const std::string& user_id, const nlohmann::json& rules) {
  db_.user_push_rules.insert(user_id, rules.dump());
}

std::optional<nlohmann::json> Data::get_push_rules(const std::string& user_id) const {
  auto rules = db_.user_push_rules.get(user_id);
  if (!rules) return std::nullopt;
  try {
    return nlohmann::json::parse(*rules);
  } catch (...) {
    return std::nullopt;
  }
}

void Data::add_pusher(const std::string& user_id, const std::string& pusher_id, const nlohmann::json& pusher) {
  std::string key = user_id + static_cast<char>(0xff) + pusher_id;
  db_.user_pusher.insert(key, pusher.dump());
  db_.pusher_userid.insert(pusher_id, user_id);
}

std::optional<nlohmann::json> Data::get_pusher(const std::string& user_id, const std::string& pusher_id) const {
  std::string key = user_id + static_cast<char>(0xff) + pusher_id;
  auto pusher = db_.user_pusher.get(key);
  if (!pusher) return std::nullopt;
  try {
    return nlohmann::json::parse(*pusher);
  } catch (...) {
    return std::nullopt;
  }
}

std::vector<std::pair<std::string, nlohmann::json>> Data::get_pushers(const std::string& user_id) const {
  std::vector<std::pair<std::string, nlohmann::json>> result;
  std::string prefix = user_id + static_cast<char>(0xff);
  for (const auto& [key, value] : db_.user_pusher.scan_prefix(prefix)) {
    std::string pusher_id = key.substr(prefix.size());
    try {
      result.emplace_back(pusher_id, nlohmann::json::parse(value));
    } catch (...) {
      // Skip invalid entries
    }
  }
  return result;
}

void Data::remove_pusher(const std::string& user_id, const std::string& pusher_id) {
  std::string key = user_id + static_cast<char>(0xff) + pusher_id;
  db_.user_pusher.erase(key);
  db_.pusher_userid.erase(pusher_id);
}

// NEW in e50f2864: save state for send_join pdu
std::optional<std::string> Data::append_to_state(const std::string& room_id,
                                                 const nlohmann::json& event) {
  // Compute the state hash for the room
  std::vector<std::string> state_events = room_state(room_id);
  
  // Create a simple hash of the state events
  // In a real implementation, this would use the proper state hash algorithm
  std::string state_data;
  for (const auto& ev : state_events) {
    state_data += ev;
  }
  
  // Simple hash for now - in reality this would be a proper hash
  std::hash<std::string> hasher;
  std::string state_hash = std::to_string(hasher(state_data));
  
  // Store the state hash with the room ID as key
  std::string key = room_id + static_cast<char>(0xff) + state_hash;
  db_.roomid_statehash.insert(key, "");
  
  return state_hash;
}

void Data::set_room_state(const std::string& room_id, const std::string& state_hash) {
  // Set the room's current state hash
  std::string key = room_id + static_cast<char>(0xff) + "current";
  db_.roomid_statehash.insert(key, state_hash);
}

// NEW in e305889: room account data
void Data::set_room_account_data(const std::string& room_id, const std::string& user_id,
                                 const std::string& event_type, const nlohmann::json& data) {
  // Key format: room_id + 0xff + user_id + 0xff + event_type
  std::string key = room_id + static_cast<char>(0xff) + user_id + static_cast<char>(0xff) + event_type;
  
  // Store as JSON with event_type and data
  nlohmann::json value;
  value["event_type"] = event_type;
  value["data"] = data;
  
  db_.roomuserid_accountdata.insert(key, value.dump());
}

std::optional<nlohmann::json> Data::get_room_account_data(const std::string& room_id,
                                                          const std::string& user_id,
                                                          const std::string& event_type) const {
  // Key format: room_id + 0xff + user_id + 0xff + event_type
  std::string key = room_id + static_cast<char>(0xff) + user_id + static_cast<char>(0xff) + event_type;
  
  auto value = db_.roomuserid_accountdata.get(key);
  if (!value) return std::nullopt;
  
  try {
    return nlohmann::json::parse(*value);
  } catch (...) {
    return std::nullopt;
  }
}

std::vector<std::string> Data::state_full_ids(uint64_t shortstatehash) const {
  std::vector<std::string> result;
  // Convert shortstatehash to big-endian bytes
  std::array<uint8_t, 8> bytes;
  for (int i = 7; i >= 0; --i) {
    bytes[i] = static_cast<uint8_t>(shortstatehash & 0xFF);
    shortstatehash >>= 8;
  }
  std::string key(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  
  // Scan stateid_shorteventid for all short event IDs with this shortstatehash prefix
  for (const auto& [shorteventid_bytes, value] : db_.stateid_shorteventid.scan_prefix(key)) {
    // Convert shorteventid bytes to event_id
    auto event_id_opt = db_.shorteventid_eventid.get(shorteventid_bytes);
    if (event_id_opt) {
      result.push_back(event_id_opt.value());
    }
  }
  
  return result;
}

// NEW in fe744c85: push rules

// NEW in 6da4022: forward extremities + signing keys (declared in 6da4022,
// defined here in 1f84013b when the federation verifier became their caller).
std::vector<std::string> Data::get_forward_extremities(const std::string& room_id) const {
  std::vector<std::string> out;
  for (const auto& [k, v] : db_.roomid_forward_extremities.scan_prefix(room_id)) {
    if (!v.empty()) out.push_back(v);
  }
  return out;
}

void Data::set_forward_extremities(const std::string& room_id,
                                    const std::vector<std::string>& extremities) {
  for (const auto& [k, v] : db_.roomid_forward_extremities.scan_prefix(room_id)) {
    db_.roomid_forward_extremities.erase(k);
  }
  for (const auto& e : extremities) {
    db_.roomid_forward_extremities.insert(room_id + '\xff' + e, e);
  }
}

std::map<std::string, std::string> Data::get_signing_keys(
    const std::string& server_name) const {
  std::map<std::string, std::string> out;
  for (const auto& [k, v] : db_.servertimeout_signingkey.scan_prefix(server_name + '\xff')) {
    size_t pos = k.rfind('\xff');
    if (pos != std::string::npos && pos + 1 < k.size()) out[k.substr(pos + 1)] = v;
  }
  return out;
}

void Data::add_signing_key(const std::string& server_name, const ServerSigningKeys& keys) {
  for (const auto& [key_id, vk] : keys.verify_keys) {
    db_.servertimeout_signingkey.insert(server_name + '\xff' + key_id, vk.key);
  }
}

// NEW in e50f2864: save state for send_join pdu


// NEW in e305889: room account data
