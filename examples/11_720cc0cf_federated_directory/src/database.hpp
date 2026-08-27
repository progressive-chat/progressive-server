// database.hpp — translation of Conduit commit fa322689's src/database.rs
//
// Named trees as fields of one struct + MultiValue ("one id -> many values"
// on a KV tree: 'd'+id+0xff data keys, 'n'+id big-endian counter).
#pragma once

#include "sled.hpp"

#include <string>
#include <utility>
#include <vector>

namespace database {

class MultiValue {
 public:
  explicit MultiValue(sled::Tree tree) : tree_(std::move(tree)) {}

  std::vector<std::pair<std::string, std::string>> get_iter(
      const std::string& id) const;
  void clear(const std::string& id);
  // NEW in abcce95d: remove the entry whose VALUE matches (inverse lookup).
  void remove_value(const std::string& id, const std::string& value);
  void add(const std::string& id, const std::string& value);
  std::vector<std::pair<std::string, std::string>> iter_all() const {
    return tree_.iter_all();
  }

 private:
  static std::string data_prefix(const std::string& id);  // 'd' + id + 0xff
  sled::Tree tree_;
};

class Database {
 public:
  static Database open(sled::Db* db);

  sled::Tree userid_password;
  MultiValue userid_deviceids;
  sled::Tree userdeviceid_token;   // was deviceid_token; key = user + 0xff + device
  sled::Tree token_userid;
  sled::Tree pduid_pdus;
  MultiValue roomid_pduleaves;
  sled::Tree eventid_pduid;
  sled::Tree roomstateid_pdu;      // NEW: 'd'+room+0xff+type+0xff+state_key -> pdu
  MultiValue roomid_userids;       // NEW (folded prerequisite): room membership
  MultiValue userid_roomids;       // NEW
  MultiValue userid_inviteroomids; // NEW in abcce95d

 private:
  Database(sled::Tree up, MultiValue ud, sled::Tree ut, sled::Tree tu,
           sled::Tree pp, MultiValue rl, sled::Tree ep,
           sled::Tree rs, MultiValue ru, MultiValue ur,
           MultiValue ui);
};

}  // namespace database
