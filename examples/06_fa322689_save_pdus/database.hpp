// database.hpp — stand-in for the sled::Db used by Conduit up to 34a53ce2
//
// Rust original:
//
//   let db = sled::open(
//       ProjectDirs::from("xyz", "koesters", "matrixserver")
//           .unwrap()
//           .data_dir(),
//   ).unwrap();
//   ...
//   let users = db.open_tree("username_password").unwrap();
//   users.contains_key(user_id.to_string())
//   users.insert(user_id.to_string(), &*password)
//
// sled is an LSM-tree embedded KV store (the same family as RocksDB, which
// conduwuit/tuwunel later adopted). This stub keeps the exact same API shape —
// open a directory, open named trees, get/insert/contains_key — but backs it
// with std::map plus one flat file per tree. Same contract, visible internals.
//
// NEW in 34a53ce2: sled's default tree (the root, no name) is now used — Data
// stores the hostname there. Modeled as get_root()/insert_root() backed by a
// "_root.kv" file.

#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace stubdb {

class Tree {
 public:
  bool contains_key(const std::string& key) const;
  void insert(const std::string& key, const std::string& value);
  std::optional<std::string> get(const std::string& key) const;
  void erase(const std::string& key);

  // NEW in fa322689 (the sled iteration surface Data now relies on):
  std::vector<std::pair<std::string, std::string>> scan_prefix(
      const std::string& prefix) const;                       // sled scan_prefix
  std::optional<std::pair<std::string, std::string>> get_gt(  // sled get_gt
      const std::string& key) const;
  // sled update_and_fetch: apply fn to current value (or empty), store result.
  std::string update_and_fetch(
      const std::string& key,
      const std::function<std::string(const std::optional<std::string>&)>& fn);
  // Full dump for Database::debug().
  std::vector<std::pair<std::string, std::string>> iter_all() const;

 private:
  friend class Db;
  explicit Tree(std::map<std::string, std::string>* map,
                std::function<void()> on_change)
      : map_(map), on_change_(std::move(on_change)) {}
  std::map<std::string, std::string>* map_;
  std::function<void()> on_change_;  // sled fsyncs its WAL here instead
};

class Db {
 public:
  // sled::open(dir): loads existing trees from <dir>/<name>.kv.
  static Db open(const std::filesystem::path& dir);

  // db.open_tree("name"): creates or loads the tree; persists on mutation.
  // const + mutable: sled's open_tree takes &self (interior mutability).
  Tree open_tree(const std::string& name) const;

  // NEW in 34a53ce2: the default (root) tree, where Data keeps the hostname.
  void insert_root(const std::string& key, const std::string& value);
  std::optional<std::string> get_root(const std::string& key) const;

 private:
  mutable std::map<std::string, std::map<std::string, std::string>> trees_;
  mutable std::map<std::string, std::string> root_;
  std::filesystem::path dir_;

  void load_tree(const std::string& name) const;
  void flush_tree(const std::string& name) const;
};

// --- NEW in fa322689: database.rs translated ---------------------------------
//
// Upstream grew a Database struct with named trees as FIELDS, plus a MultiValue
// wrapper implementing "one id -> many values" on top of a KV tree:
//
//   pub struct MultiValue(sled::Tree);
//   impl MultiValue {
//       fn get_iter(&self, id: &[u8])   // scan_prefix('d' + id + 0xff)
//       fn clear(&self, id: &[u8])      // remove everything under the prefix
//       fn add(&self, id: &[u8], value) // 'n'+id counter -> 'd'+id+0xff+index
//   }
//
//   pub struct Database {
//       pub userid_password: sled::Tree,
//       pub userid_deviceids: MultiValue,
//       pub deviceid_token: sled::Tree,
//       pub token_userid: sled::Tree,
//       pub pduid_pdus: sled::Tree,
//       pub roomid_pduleaves: MultiValue,
//       pub eventid_pduid: sled::Tree,
//   }

class MultiValue {
 public:
  explicit MultiValue(Tree tree) : tree_(std::move(tree)) {}

  std::vector<std::pair<std::string, std::string>> get_iter(
      const std::string& id) const;  // values under one id
  void clear(const std::string& id);
  // Append a value: allocates index from the 'n'+id counter.
  void add(const std::string& id, const std::string& value);
  std::vector<std::pair<std::string, std::string>> iter_all() const {
    return tree_.iter_all();
  }

 private:
  static std::string data_prefix(const std::string& id);  // 'd' + id + 0xff
  Tree tree_;
};

class Database {
 public:
  static Database open(class Db* db);

  stubdb::Tree userid_password;
  stubdb::MultiValue userid_deviceids;
  stubdb::Tree deviceid_token;
  stubdb::Tree token_userid;
  stubdb::Tree pduid_pdus;
  stubdb::MultiValue roomid_pduleaves;
  stubdb::Tree eventid_pduid;

  // Dump every tree — the debug!() endpoint upstream.
  void debug() const;

 private:
  Database(stubdb::Tree up, stubdb::MultiValue ud, stubdb::Tree dt,
           stubdb::Tree tu, stubdb::Tree pp, stubdb::MultiValue rl,
           stubdb::Tree ep)
      : userid_password(std::move(up)),
        userid_deviceids(std::move(ud)),
        deviceid_token(std::move(dt)),
        token_userid(std::move(tu)),
        pduid_pdus(std::move(pp)),
        roomid_pduleaves(std::move(rl)),
        eventid_pduid(std::move(ep)) {}
};

}  // namespace stubdb
