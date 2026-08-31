#include "database.hpp"

#include "utils.hpp"

#include <cstdio>

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
  for (const auto& [key, value] : get_iter(id)) tree_.erase(key);
}

// NEW in abcce95d.
void MultiValue::remove_value(const std::string& id, const std::string& value) {
  for (const auto& [key, v] : get_iter(id)) {
    if (v == value) {
      tree_.erase(key);
      return;
    }
  }
}

void MultiValue::add(const std::string& id, const std::string& value) {
  // The new value will need a new index. We store the last used index in 'n' + id.
  const std::string count_key = "n" + id;
  const std::string index = tree_.update_and_fetch(count_key, utils::increment);

  std::string key = data_prefix(id);
  key += utils::u64_from_bytes(index);
  tree_.insert(key, value);
}

Database::Database(sled::Tree up, MultiValue ud, sled::Tree ut, sled::Tree tu,
                   sled::Tree pp, MultiValue rl, sled::Tree ep,
                   sled::Tree rs, MultiValue ru, MultiValue ur,
                   MultiValue ui)
    : userid_password(std::move(up)),
      userid_deviceids(std::move(ud)),
      userdeviceid_token(std::move(ut)),
      token_userid(std::move(tu)),
      pduid_pdus(std::move(pp)),
      roomid_pduleaves(std::move(rl)),
      eventid_pduid(std::move(ep)),
      roomstateid_pdu(std::move(rs)),
      roomid_userids(std::move(ru)),
      userid_roomids(std::move(ur)),
      userid_inviteroomids(std::move(ui)) {}

Database Database::open(sled::Db* db) {
  return Database(db->open_tree("userid_password"),
                  MultiValue(db->open_tree("userid_deviceids")),
                  db->open_tree("userdeviceid_token"),
                  db->open_tree("token_userid"),
                  db->open_tree("pduid_pdus"),
                  MultiValue(db->open_tree("roomid_pduleaves")),
                  db->open_tree("eventid_pduid"),
                  db->open_tree("roomstateid_pdu"),
                  MultiValue(db->open_tree("roomid_userids")),
                  MultiValue(db->open_tree("userid_roomids")),
                  MultiValue(db->open_tree("userid_inviteroomids")));
}

}  // namespace stubdb
