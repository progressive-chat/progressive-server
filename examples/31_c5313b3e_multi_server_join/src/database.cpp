#include "database.hpp"

#include "utils.hpp"

#include <cstdio>

namespace database {

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
                   MultiValue ui, sled::Tree dn, MultiValue ul,
                   sled::Tree mf, sled::Tree ua,
                   sled::Tree ar, sled::Tree aa, sled::Tree pr,
                    sled::Tree ro,
                    sled::Tree ti,
                    sled::Tree ba, sled::Tree be, sled::Tree bb, sled::Tree bl)
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
      userid_inviteroomids(std::move(ui)),
      userid_displayname(std::move(dn)),
      userid_leftroomids(std::move(ul)),
      media(std::move(mf)),
      uiaa(std::move(ua)),
      alias_roomid(std::move(ar)),
      aliasid_alias(std::move(aa)),
      publicroomids(std::move(pr)),
      roomuseroncejoinedids(std::move(ro)),
      userdevicetxnid_response(std::move(ti)),
      backupid_algorithm(std::move(ba)),
      backupid_etag(std::move(be)),
      backupkeyid_backup(std::move(bb)),
      backup_latest(std::move(bl)) {}

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
                  MultiValue(db->open_tree("userid_inviteroomids")),
                  db->open_tree("userid_displayname"),
                  MultiValue(db->open_tree("userid_leftroomids")),
                  db->open_tree("mediaid_file"),
                  db->open_tree("userdeviceid_uiaainfo"),
                  db->open_tree("alias_roomid"),
                  db->open_tree("aliasid_alias"),
                  db->open_tree("publicroomids"),
                  db->open_tree("roomuseroncejoinedids"),
                  db->open_tree("userdevicetxnid_response"),
                  db->open_tree("backupid_algorithm"),
                  db->open_tree("backupid_etag"),
                  db->open_tree("backupkeyid_backup"),
                  db->open_tree("backup_latest"));
}

}  // namespace database
