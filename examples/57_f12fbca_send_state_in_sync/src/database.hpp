// database.hpp — translation of Conduit commit fa322689's src/database.rs
//
// Named trees as fields of one struct + MultiValue ("one id -> many values"
// on a KV tree: 'd'+id+0xff data keys, 'n'+id big-endian counter).
#pragma once

#include "sled.hpp"
#include "media.hpp"
#include "uiaa.hpp"

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
  // NEW in f12fbca: state resolution sled trees
  sled::Tree stateid_pduid;         // StateId = StateHash + (EventType, StateKey) -> pdu
  sled::Tree pduid_statehash;      // PDU id -> StateHash
  sled::Tree roomid_statehash;     // room_id -> latest StateHash
  sled::Tree userid_displayname;   // folded prerequisite (profile endpoints)
  MultiValue roomid_userids;       // NEW (folded prerequisite): room membership
  MultiValue userid_roomids;       // NEW
  MultiValue userid_inviteroomids; // NEW in abcce95d
  MultiValue userid_leftroomids;   // NEW in 23cb550d (folded leave flow)
  sled::Tree alias_roomid;         // NEW in 9c26e22a: alias -> room_id
  sled::Tree roomuseroncejoinedids;  // NEW in df55e8ed: room+user ever joined
  // NEW in 3f4cb753: key backup store (folded base + remaining endpoints)
  sled::Tree backupid_algorithm;   // user + 0xff + version -> algorithm json
  sled::Tree backupid_etag;        // user + 0xff + version -> etag (counter)
  sled::Tree backupkeyid_backup;   // user+0xff+version+0xff+room+0xff+session -> key_data json
  sled::Tree backup_latest;        // user -> latest version (folded base helper)
  sled::Tree userdevicetxnid_response;  // NEW in 4954df3c: txnid -> response bytes
  sled::Tree aliasid_alias;        // NEW in 3aa0c8ed: room+idx -> alias
sled::Tree publicroomids;        // NEW in 3aa0c8ed: public rooms
    sled::Tree roomserverids;       // NEW in 71500b1: room -> servers
    Media media;                     // NEW in 821c608c: media repository
  Uiaa uiaa;                       // NEW in c85d363d: UIAA sessions

 private:
  Database(sled::Tree up, MultiValue ud, sled::Tree ut, sled::Tree tu,
           sled::Tree pp, MultiValue rl, sled::Tree ep,
           sled::Tree rs, MultiValue ru, MultiValue ur,
           MultiValue ui, sled::Tree dn, MultiValue ul,
           sled::Tree mf, sled::Tree ua,
           sled::Tree ar, sled::Tree aa, sled::Tree pr,
           sled::Tree rs2,
           sled::Tree ro,
           sled::Tree ti,
           sled::Tree ba, sled::Tree be, sled::Tree bb, sled::Tree bl,
           // NEW in f12fbca: state resolution trees
           sled::Tree sp, sled::Tree ps, sled::Tree rsh);
};

}  // namespace database
