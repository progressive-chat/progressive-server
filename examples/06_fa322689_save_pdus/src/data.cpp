#include "data.hpp"

#include "utils.hpp"

#include <algorithm>
#include <cstdio>

Data::Data(sled::Db db)
    : hostname_(db.get_root("hostname").value_or("localhost")), db_(std::move(db)) {}

Data Data::load_or_create(const std::filesystem::path& dir) {
  return Data(sled::Db::open(dir));
}

void Data::set_hostname(const std::string& hostname) {
  hostname_ = hostname;
  db_.insert_root("hostname", hostname);
}

const std::string& Data::hostname() const { return hostname_; }

bool Data::user_exists(const std::string& user_id) const {
  return db_.userid_password.contains_key(user_id);
}

void Data::user_add(const std::string& user_id, const std::optional<std::string>& password) {
  db_.userid_password.insert(user_id, password.value_or(""));
}

std::optional<std::string> Data::user_from_token(const std::string& token) const {
  return db_.token_userid.get(token);
}

std::optional<std::string> Data::password_get(const std::string& user_id) const {
  return db_.userid_password.get(user_id);
}

namespace {
std::vector<std::string> devices_of(const stubdb::MultiValue& mv,
                                    const std::string& user_id) {
  std::vector<std::string> devices;
  for (const auto& [key, value] : mv.get_iter(user_id)) devices.push_back(value);
  return devices;
}
}  // namespace

void Data::device_add(const std::string& user_id, const std::string& device_id) {
  auto devices = devices_of(db_.userid_deviceids, user_id);
  if (std::find(devices.begin(), devices.end(), device_id) != devices.end()) return;
  db_.userid_deviceids.add(user_id, device_id);
}

void Data::token_replace(const std::string& user_id, const std::string& device_id,
                         const std::string& token) {
  const auto devices = devices_of(db_.userid_deviceids, user_id);
  if (std::find(devices.begin(), devices.end(), device_id) == devices.end()) {
    std::fprintf(stderr, "[assert] device %s does not belong to %s\n", device_id.c_str(),
                 user_id.c_str());
    return;
  }

  if (const auto old_token = db_.deviceid_token.get(device_id)) {
    db_.token_userid.erase(*old_token);
  }
  db_.deviceid_token.insert(device_id, token);
  db_.token_userid.insert(token, user_id);
}

std::optional<std::string> Data::pdu_get(const std::string& event_id) const {
  const auto pdu_id = db_.eventid_pduid.get(event_id);
  if (!pdu_id) return std::nullopt;
  return db_.pduid_pdus.get(*pdu_id);  // "eventid_pduid in db is valid"
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
  // prev_events are the leaves of the current graph; replace them with us.
  const std::vector<std::string> prev_events =
      pdu_leaves_replace(room_id, event_id);

  // Our depth is the maximum depth of prev_events + 1.
  uint64_t depth = 0;
  for (const auto& prev : prev_events) {
    if (const auto text = pdu_get(prev)) {
      depth = std::max(depth, json(*text).value("depth", 0ull));
    }
  }
  depth += 1;

  event["prev_events"] = prev_events;
  event["origin"] = hostname_;
  event["depth"] = depth;
  event["auth_events"] = json::array({"$auth_eventid"});            // TODO upstream
  event["hashes"] = std::string(64, 'A');                           // TODO upstream
  event["signatures"] = "signature";                                // TODO upstream

  // The new value will need a new index. We store the last used index in 'n' + room.
  const std::string index_bytes =
      db_.pduid_pdus.update_and_fetch("n" + room_id, utils::increment);
  const uint64_t index = utils::u64_from_bytes(index_bytes);

  std::string pdu_id;
  pdu_id.push_back('d');
  pdu_id += room_id;
  pdu_id.push_back('#');  // delimiter: rooms sharing prefixes stay separate
  pdu_id += std::to_string(index);

  const std::string pdu_json = event.dump();  // canonical: sorted keys
  std::printf("[debug] %s\n", pdu_json.c_str());
  db_.pduid_pdus.insert(pdu_id, pdu_json);
  db_.eventid_pduid.insert(event_id, pdu_id);
}

std::vector<std::string> Data::pdus_all() const {
  std::vector<std::string> pdus;
  for (const auto& [key, value] : db_.pduid_pdus.iter_all()) {
    if (key.rfind("d", 0) == 0) pdus.push_back(value);  // skip 'n' counters
  }
  return pdus;
}
