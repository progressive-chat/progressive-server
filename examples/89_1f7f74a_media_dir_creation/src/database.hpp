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
  sled::Tree userid_displayname;   // folded prerequisite (profile endpoints)
  MultiValue roomid_userids;       // NEW (folded prerequisite): room membership
  MultiValue userid_roomids;       // NEW
  MultiValue userid_inviteroomids; // NEW in abcce95d
  MultiValue userid_leftroomids;   // NEW in 23cb550d (folded leave flow)
  sled::Tree alias_roomid;         // NEW in 9c26e22a: alias -> room_id
  sled::Tree alias_creator;        // NEW in 144d548: alias -> creator user_id
  sled::Tree roomuseroncejoinedids;  // NEW in df55e8ed: room+user ever joined
  // NEW in 3f4cb753: key backup store (folded base + remaining endpoints)
  sled::Tree backupid_algorithm;   // user + 0xff + version -> algorithm json
  sled::Tree backupid_etag;        // user + 0xff + version -> etag (counter)
  sled::Tree backupkeyid_backup;   // user+0xff+version+0xff+room+0xff+session -> key_data json
  sled::Tree backup_latest;        // user -> latest version (folded base helper)
  sled::Tree userdevicetxnid_response;  // NEW in 4954df3c: txnid -> response bytes
  sled::Tree aliasid_alias;        // NEW in 3aa0c8ed: room+idx -> alias
  sled::Tree publicroomids;        // NEW in 3aa0c8ed: public rooms
  sled::Tree roomserverids;        // NEW in f7816b11d: room+0xff+server -> present
  Media media;                     // NEW in 821c608c: media repository
                                   // (70d7f77: mediaid_file + mediaid_meta;
                                   //  594fe5f: + blocked_servername_mediaid + blocked_filehash)
  Uiaa uiaa;                       // NEW in c85d363d: UIAA sessions
  sled::Tree openidtoken_userid;   // NEW in a888c7cb16: OpenID token -> (expires_at, user_id)
  sled::Tree admin_users;        // NEW in 9db1f5a13c-era: admin user_id -> ""
  // NEW in 21af83e: knock state / count — mirror Conduit's userroomid_knockstate
  // and roomuserid_knockcount trees.
  sled::Tree userroomid_knockstate;  // user+0xff+room -> knock m.room.member event json
  sled::Tree roomuserid_knockcount;  // room+0xff+user -> count (for sync since)
  // NEW in 42d8e88-backfill: E2E key storage for upload_keys / get_keys.
  // (Conduit already had these before 42d8e88; our translation skipped the
  // whole keys subsystem, so we backfill it now to host the 42d8e88 change.)
  sled::Tree userdeviceid_devicekey;   // user + 0xff + device -> device keys json
  sled::Tree userdeviceid_onetimekey;  // user + 0xff + device + 0xff + key_id -> key json
  sled::Tree userdeviceid_lastseen;  // NEW in 09e1713: user + 0xff + device -> last-seen ms
  // NEW in dc5abd6-backfill: appservice registration storage (pinging + future
  // appservice features). Conduit configures appservices via a yaml file; we
  // store them in the DB (seeded through an admin command) so the ping route
  // can authenticate and reach the appservice's URL.
  sled::Tree appserviceid_registration;  // id -> json {url, sender, hs_token}
  sled::Tree appservice_token_id;        // hs_token -> id

  private:
  Database(sled::Tree up, MultiValue ud, sled::Tree ut, sled::Tree tu,
           sled::Tree pp, MultiValue rl, sled::Tree ep,
           sled::Tree rs, MultiValue ru, MultiValue ur,
           MultiValue ui, sled::Tree dn, MultiValue ul,
            sled::Tree mf, sled::Tree mf_meta, sled::Tree mf_blocked, sled::Tree mf_blocked_hash,
            sled::Tree ua,
           sled::Tree ar, sled::Tree ac, sled::Tree aa, sled::Tree pr,
            sled::Tree ro,
            sled::Tree ti,
            sled::Tree ba, sled::Tree be, sled::Tree bb, sled::Tree bl,
           sled::Tree rs2, sled::Tree ot, sled::Tree au,
            sled::Tree userroomid_knockstate, sled::Tree roomuserid_knockcount,
            sled::Tree userdeviceid_devicekey, sled::Tree userdeviceid_onetimekey,
            sled::Tree userdeviceid_lastseen,
            sled::Tree appserviceid_registration, sled::Tree appservice_token_id);
};

}  // namespace database
