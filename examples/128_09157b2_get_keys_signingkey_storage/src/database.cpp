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
                   sled::Tree ps,
                   sled::Tree rs, MultiValue ru, MultiValue ur,
                   MultiValue ui, sled::Tree dn, MultiValue ul,
                   sled::Tree mf, sled::Tree ua,
                   sled::Tree ar, sled::Tree aa, sled::Tree pr,
                   sled::Tree rs2,
                   sled::Tree ro,
                   sled::Tree ti,
                   sled::Tree ba, sled::Tree be, sled::Tree bb, sled::Tree bl,
                   // NEW in 100307c: Short ID system
                   sled::Tree ssh, sled::Tree es, sled::Tree se,
                   sled::Tree sk, sled::Tree sr, sled::Tree ss,
                   sled::Tree ss2, sled::Tree rs3,
                   // NEW in 6da4022: forward extremities and signing keys
                   sled::Tree fe, sled::Tree ssk,
                   // NEW in 44425a9: stateid_eventid
                   sled::Tree se2,
                   // NEW in 100307c: stateid_shorteventid
                   sled::Tree sse,
                   // NEW in e50f2864: room state hash
                   sled::Tree rsh,
                   // NEW in e50f2864: room account data
                   sled::Tree rua, sled::Tree uda,
                   // NEW in fe744c85: push rules
                   sled::Tree upr, sled::Tree up2, sled::Tree pu,
                   // NEW in 8773e501: incoming invites over federation
                   sled::Tree uis, sled::Tree ric,
                   // NEW in 662a0cf1: notification/highlight counts
                   sled::Tree unc, sled::Tree uhc,
// NEW in 71ed1b29: devicelist version
                    sled::Tree udv,
                    // NEW in cf94b8e7: uiaa request store (user+device+session -> request JSON)
                    sled::Tree uir,
                    // NEW in 2479389: latest presence event per (user, room)
                    sled::Tree urp,
                    // NEW in 8f27e61: read receipts + server->room index + EDU counts
                    sled::Tree rrr, sled::Tree sri, sled::Tree sec)
     : userid_password(std::move(up)),
      userid_deviceids(std::move(ud)),
      userdeviceid_token(std::move(ut)),
      token_userid(std::move(tu)),
      pduid_pdus(std::move(pp)),
      roomid_pduleaves(std::move(rl)),
      eventid_pduid(std::move(ep)),
      pduid_statehash(std::move(ps)),
      roomstateid_pdu(std::move(rs)),
      roomid_userids(std::move(ru)),
      userid_roomids(std::move(ur)),
      userid_inviteroomids(std::move(ui)),
      userid_displayname(std::move(dn)),
      userid_leftroomids(std::move(ul)),
      media(std::move(mf)),
      uiaa(std::move(ua), std::move(uir)),
      alias_roomid(std::move(ar)),
      aliasid_alias(std::move(aa)),
      publicroomids(std::move(pr)),
      roomserverids(std::move(rs2)),
      roomuseroncejoinedids(std::move(ro)),
      userdevicetxnid_response(std::move(ti)),
      backupid_algorithm(std::move(ba)),
      backupid_etag(std::move(be)),
      backupkeyid_backup(std::move(bb)),
      backup_latest(std::move(bl)),
      // NEW in 100307c: Short ID system
      statehash_shortstatehash(std::move(ssh)),
      eventid_shorteventid(std::move(es)),
      shorteventid_eventid(std::move(se)),
      statekey_shortstatekey(std::move(sk)),
      statehash_shortstatehash_rev(std::move(sr)),
      shorteventid_shortstatehash(std::move(ss)),
      shortstatehash_shorteventid(std::move(ss2)),
      roomid_shortstatehash(std::move(rs3)),
      // NEW in 6da4022: forward extremities and signing keys
      roomid_forward_extremities(std::move(fe)),
      server_signingkeys(std::move(ssk)),
      // NEW in 44425a9: stateid_eventid
      stateid_eventid(std::move(se2)),
      // NEW in 100307c: stateid_shorteventid
      stateid_shorteventid(std::move(sse)),
      // NEW in e50f2864: room state hash
      roomid_statehash(std::move(rsh)),
      // NEW in e50f2864: room account data
      roomuserid_accountdata(std::move(rua)),
      userid_accountdata(std::move(uda)),
      // NEW in fe744c85: push rules
      user_push_rules(std::move(upr)),
      user_pusher(std::move(up2)),
      pusher_userid(std::move(pu)),
      // NEW in 8773e501: incoming invites over federation
      userroomid_invitestate(std::move(uis)),
      roomuserid_invitecount(std::move(ric)),
      // NEW in 662a0cf1: notification/highlight counts
      userroomid_notificationcount(std::move(unc)),
      userroomid_highlightcount(std::move(uhc)),
      // NEW in 71ed1b29: devicelist version
      userid_devicelistversion(std::move(udv)),
      // NEW in cf94b8e7: uiaa request store (user+device+session -> request JSON)
      userdevicesessionid_uiaarequest(std::move(uir)),
      // NEW in 2479389: latest presence event per (user, room)
      userroomid_presence(std::move(urp)),
      // NEW in 8f27e61: read receipts + server->room index + EDU counts
      readreceiptid_readreceipt(std::move(rrr)),
      serverroomids(std::move(sri)),
      servername_educount(std::move(sec)),
      pdu_cache(1000) {}

Database Database::open(sled::Db* db) {
  return Database(db->open_tree("userid_password"),
                  MultiValue(db->open_tree("userid_deviceids")),
                  db->open_tree("userdeviceid_token"),
                  db->open_tree("token_userid"),
                  db->open_tree("pduid_pdus"),
                  MultiValue(db->open_tree("roomid_pduleaves")),
                  db->open_tree("eventid_pduid"),
                  db->open_tree("pduid_statehash"),
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
                  db->open_tree("roomserverids"),
                  db->open_tree("roomuseroncejoinedids"),
                  db->open_tree("userdevicetxnid_response"),
                  db->open_tree("backupid_algorithm"),
                  db->open_tree("backupid_etag"),
                  db->open_tree("backupkeyid_backup"),
                  db->open_tree("backup_latest"),
                  // NEW in 100307c: Short ID system
                  db->open_tree("statehash_shortstatehash"),
                  db->open_tree("eventid_shorteventid"),
                  db->open_tree("shorteventid_eventid"),
                  db->open_tree("statekey_shortstatekey"),
                  db->open_tree("statehash_shortstatehash_rev"),
                  db->open_tree("shorteventid_shortstatehash"),
                  db->open_tree("shortstatehash_shorteventid"),
                  db->open_tree("roomid_shortstatehash"),
                  // NEW in 6da4022: forward extremities and signing keys
                  db->open_tree("roomid_forward_extremities"),
                  db->open_tree("server_signingkeys"),
                  // NEW in 44425a9: stateid_eventid
                  db->open_tree("stateid_eventid"),
                  // NEW in 100307c: stateid_shorteventid
                  db->open_tree("stateid_shorteventid"),
                  // NEW in e50f2864: room state hash
                  db->open_tree("roomid_statehash"),
                  // NEW in e50f2864: room account data
                  db->open_tree("roomuserid_accountdata"),
                  db->open_tree("userid_accountdata"),
                  // NEW in fe744c85: push rules
                  db->open_tree("user_push_rules"),
                  db->open_tree("user_pusher"),
                  db->open_tree("pusher_userid"),
                  // NEW in 8773e501: incoming invites over federation
                  db->open_tree("userroomid_invitestate"),
                  db->open_tree("roomuserid_invitecount"),
                  // NEW in 662a0cf1: notification/highlight counts
                  db->open_tree("userroomid_notificationcount"),
                  db->open_tree("userroomid_highlightcount"),
                  // NEW in 71ed1b29: devicelist version
                  db->open_tree("userid_devicelistversion"),
                  // NEW in cf94b8e7: uiaa request store (user+device+session -> request JSON)
                  db->open_tree("userdevicesessionid_uiaarequest"),
                  // NEW in 2479389: latest presence event per (user, room)
                  db->open_tree("userroomid_presence"),
                  // NEW in 8f27e61: read receipts + server->room index + EDU counts
                  db->open_tree("readreceiptid_readreceipt"),
                  db->open_tree("serverroomids"),
                  db->open_tree("servername_educount"));
}

}  // namespace database
