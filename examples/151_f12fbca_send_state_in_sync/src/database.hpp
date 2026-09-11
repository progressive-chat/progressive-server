// database.hpp — translation of Conduit commit fa322689's src/database.rs
//
// Named trees as fields of one struct + MultiValue ("one id -> many values"
// on a KV tree: 'd'+id+0xff data keys, 'n'+id big-endian counter).
#pragma once

#include "sled.hpp"
#include <unordered_map>
#include <list>
#include "media.hpp"
#include "uiaa.hpp"

#include <string>
#include <utility>
#include <vector>

namespace database {

// Simple LRU cache implementation for PDU caching
template <typename Key, typename Value>
class LRUCache {
public:
    explicit LRUCache(size_t capacity) : capacity_(capacity) {}

    std::optional<Value> get(const Key& key) {
        auto it = cache_.find(key);
        if (it == cache_.end()) return std::nullopt;
        lru_.splice(lru_.begin(), lru_, it->second.second);
        return it->second.first;
    }

    void put(const Key& key, Value value) {
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            it->second.first = std::move(value);
            lru_.splice(lru_.begin(), lru_, it->second.second);
        } else {
            if (cache_.size() >= capacity_) {
                cache_.erase(lru_.back());
                lru_.pop_back();
            }
            lru_.push_front(key);
            cache_[key] = {std::move(value), lru_.begin()};
        }
    }

    void clear() {
        cache_.clear();
        lru_.clear();
    }

    size_t size() const { return cache_.size(); }

private:
    size_t capacity_;
    std::list<Key> lru_;
    std::unordered_map<Key, std::pair<Value, typename std::list<Key>::iterator>> cache_;
};

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
  // NEW in 71ed1b29: devicelist version (user -> BE u64), bumped on add/remove
  sled::Tree userid_devicelistversion;
  sled::Tree pduid_pdus;
  MultiValue roomid_pduleaves;
  sled::Tree eventid_pduid;
  sled::Tree pduid_statehash;      // pduid -> state_hash
  sled::Tree roomstateid_pdu;      // NEW: 'd'+room+0xff+type+0xff+state_key -> pdu
  sled::Tree userid_displayname;   // folded prerequisite (profile endpoints)
  MultiValue roomid_userids;       // NEW (folded prerequisite): room membership
  MultiValue userid_roomids;       // NEW
  MultiValue userid_inviteroomids; // NEW in abcce95d
  // NEW in 8773e501: incoming invites over federation (replaces bare
  // userroomid_invited/roomuserid_invited with state + count).
  sled::Tree userroomid_invitestate;  // user+0xff+room -> invite_state JSON array
  sled::Tree roomuserid_invitecount;  // room+0xff+user -> BE u64 invite count
  // NEW in 662a0cf1: efficient notification/highlight counts (bumped on PDU
  // append per push-rule evaluation, reset on read).
  sled::Tree userroomid_notificationcount;  // user+0xff+room -> BE u64
  sled::Tree userroomid_highlightcount;     // user+0xff+room -> BE u64
  MultiValue userid_leftroomids;   // NEW in 23cb550d (folded leave flow)
  sled::Tree alias_roomid;         // NEW in 9c26e22a: alias -> room_id
  sled::Tree roomuseroncejoinedids;  // NEW in df55e8ed: room+user ever joined
  // NEW in 3f4cb753: key backup store (folded base + remaining endpoints)
  sled::Tree backupid_algorithm;   // user + 0xff + version -> algorithm json
  sled::Tree backupid_etag;        // user + 0xff + version -> etag (counter)
  sled::Tree backupkeyid_backup;   // user+0xff+version+0xff+room+0xff+session -> key_data json
  sled::Tree backup_latest;        // user -> latest version (folded base helper)
  // NEW in e305889: room account data
  sled::Tree roomuserid_accountdata;    // room+user+type -> data
  sled::Tree userid_accountdata;        // user+type -> data (global)

  // NEW in fe744c85: push rules
  sled::Tree user_push_rules;         // user -> push rules json
  sled::Tree user_pusher;             // user -> pusher json
  sled::Tree pusher_userid;           // pusher_id -> user_id

  sled::Tree userdevicetxnid_response;  // NEW in 4954df3c: txnid -> response bytes
  sled::Tree aliasid_alias;        // NEW in 3aa0c8ed: room+idx -> alias
  sled::Tree publicroomids;        // NEW in 3aa0c8ed: public rooms
  sled::Tree roomserverids;        // NEW in 71500b1: room -> servers
  // NEW in 2479389: latest presence event per (user, room); upstream keys a
  // count-stamped presenceid_presence tree plus userid_lastpresenceupdate,
  // this port keeps only the latest event per room.
  sled::Tree userroomid_presence;  // user+0xff+room -> presence event JSON
  // NEW in 8f27e61: read receipts (folded prerequisite: /receipt) and the
  // server->room index used to pick EDU recipients.
  // readreceiptid_readreceipt = room+0xff+count(BE u64)+0xff+user -> m.receipt JSON
  sled::Tree readreceiptid_readreceipt;
  sled::Tree serverroomids;        // NEW in 8f27e61: server+0xff+room -> ""
  sled::Tree servername_educount;  // NEW in 8f27e61: server -> last EDU count
  Media media;                     // NEW in 821c608c: media repository
  // NEW in cf94b8e7: uiaa works like in synapse — stores the original
  // JSON request for each session (user+device+session -> request JSON)
  sled::Tree userdevicesessionid_uiaarequest;
  Uiaa uiaa;                       // NEW in c85d363d: UIAA sessions

  // NEW in 100307c: Short ID system for state storage optimization
  // State hashes -> short state hashes (u64)
  sled::Tree statehash_shortstatehash;
  // Event IDs -> short event IDs
  sled::Tree eventid_shorteventid;
  // Short event IDs -> Event IDs
  sled::Tree shorteventid_eventid;
  // State keys -> short state keys (u64)
  sled::Tree statekey_shortstatekey;
  // State hashes -> short state hashes (reverse mapping)
  sled::Tree statehash_shortstatehash_rev;
  // Short event IDs -> short state hashes
  sled::Tree shorteventid_shortstatehash;
  // Short state hashes -> short event IDs
  sled::Tree shortstatehash_shorteventid;
  // Room ID -> short state hash
  sled::Tree roomid_shortstatehash;

  // NEW in 100307c (part of Short ID system): stateid -> shorteventid
  sled::Tree stateid_shorteventid;

  // NEW in 6da4022: forward extremities and signing keys
  // Forward extremities for rooms (RoomId -> EventId)
  sled::Tree roomid_forward_extremities;
  // NEW in 09157b2: merged per-server signing-key document (replaces the
  // timeout-keyed rows): ServerName -> ServerSigningKeys JSON
  // {verify_keys: {key_id: {key}}, old_verify_keys: {...}}.
  sled::Tree server_signingkeys;

  // NEW in 44425a9: stateid_pduid renamed to stateid_eventid
  sled::Tree stateid_eventid;
  // NEW in e50f2864: room state hash
  // NEW in 05821d6f: PDU cache (LRU for get_pdu)
  mutable LRUCache<std::string, std::string> pdu_cache;
  sled::Tree roomid_statehash;

 private:
  Database(sled::Tree up, MultiValue ud, sled::Tree ut, sled::Tree tu,
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
  // NEW in 05821d6f: PDU cache (LRU for get_pdu)
           sled::Tree rsh,
           // NEW in e50f2864: room account data
           sled::Tree rua, sled::Tree uda,
           // NEW in fe744c85: push rules
           sled::Tree upr, sled::Tree up2, sled::Tree pu,
           // NEW in 8773e501: incoming invites over federation
           // user+room -> invite_state JSON (stripped state events)
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
             sled::Tree rrr, sled::Tree sri, sled::Tree sec);
};

}  // namespace database
