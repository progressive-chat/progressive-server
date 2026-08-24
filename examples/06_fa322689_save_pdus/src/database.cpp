#include "database.hpp"

#include "utils.hpp"

#include <cstdio>
#include <stdexcept>

namespace stubdb {

std::string MultiValue::data_prefix(const std::string& id) {
  std::string key;
  key.push_back('d');
  key += id;
  key.push_back(static_cast<char>(0xff));  // ids sharing a prefix stay separate
  return key;
}

std::vector<std::pair<std::string, std::string>> MultiValue::get_iter(
    const std::string& id) const {
  return tree_.scan_prefix(data_prefix(id));
}

void MultiValue::clear(const std::string& id) {
  for (const auto& [key, value] : get_iter(id)) {
    tree_.erase(key);
  }
}

void MultiValue::add(const std::string& id, const std::string& value) {
  // The new value will need a new index. We store the last used index in 'n' + id.
  const std::string count_key = "n" + id;
  const std::string index = tree_.update_and_fetch(count_key, [](const auto& old) {
    uint64_t number = old ? utils::u64_from_bytes(*old) : 0;
    ++number;
    std::string bytes(8, '\0');
    for (int i = 0; i < 8; ++i) {
      bytes[static_cast<size_t>(i)] =
          static_cast<char>((number >> ((7 - i) * 8)) & 0xFF);
    }
    return bytes;
  });

  std::string key = data_prefix(id);
  key += utils::u64_from_bytes(index);
  tree_.insert(key, value);
}

Database::Database(sled::Tree up, MultiValue ud, sled::Tree dt, sled::Tree tu,
                   sled::Tree pp, MultiValue rl, sled::Tree ep)
    : userid_password(std::move(up)),
      userid_deviceids(std::move(ud)),
      deviceid_token(std::move(dt)),
      token_userid(std::move(tu)),
      pduid_pdus(std::move(pp)),
      roomid_pduleaves(std::move(rl)),
      eventid_pduid(std::move(ep)) {}

Database Database::open(sled::Db* db) {
  return Database(db->open_tree("userid_password"),
                  MultiValue(db->open_tree("userid_deviceids")),
                  db->open_tree("deviceid_token"),
                  db->open_tree("token_userid"),
                  db->open_tree("pduid_pdus"),
                  MultiValue(db->open_tree("roomid_pduleaves")),
                  db->open_tree("eventid_pduid"));
}

}  // namespace stubdb
