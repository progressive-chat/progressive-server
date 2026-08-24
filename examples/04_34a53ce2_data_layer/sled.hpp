// sled.hpp — the sled API Conduit used, backed by RocksDB.
//
// Conduit (Feb 2020) stored everything in sled, an embedded LSM KV store.
// This project's lineage later switched to RocksDB (conduwuit did the real
// migration; tuwunel ships RocksDB-only), so our translation speaks the
// sled API the original code was written against, implemented on RocksDB
// column families:
//
//   sled::Db::open(dir)            -> rocksdb::DB with lazy column families
//   db.open_tree("name")           -> column family "name"
//   tree.get/insert/remove         -> Get/Put/Delete
//   scan_prefix / get_gt           -> Iterator seeks
//   update_and_fetch               -> Get + Put
//   db.insert("hostname", ...)     -> default column family (sled's root)
//
// Durability: RocksDB WAL is enabled by default, matching sled's fsync
// semantics closely enough for this exercise.

#pragma once

#include <rocksdb/db.h>

#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace sled {

class Db;

class Tree {
 public:
  std::optional<std::string> get(const std::string& key) const;
  void insert(const std::string& key, const std::string& value);
  bool contains_key(const std::string& key) const;
  void erase(const std::string& key);

  std::vector<std::pair<std::string, std::string>> scan_prefix(
      const std::string& prefix) const;
  std::optional<std::pair<std::string, std::string>> get_gt(
      const std::string& key) const;
  std::string update_and_fetch(
      const std::string& key,
      const std::function<std::string(const std::optional<std::string>&)>& fn);
  std::vector<std::pair<std::string, std::string>> iter_all() const;

 private:
  friend class Db;
  Tree(rocksdb::DB* db, rocksdb::ColumnFamilyHandle* cf)
      : db_(db), cf_(cf) {}
  rocksdb::DB* db_;
  rocksdb::ColumnFamilyHandle* cf_;
};

class Db {
 public:
  static Db open(const std::filesystem::path& dir);

  // Non-copyable (owns raw handles); movable not needed here.
  Db(const Db&) = delete;
  Db& operator=(const Db&) = delete;
  Db(Db&& other) noexcept;
  Db& operator=(Db&&) = delete;
  ~Db();

  Tree open_tree(const std::string& name);

  // sled's unnamed root tree.
  void insert_root(const std::string& key, const std::string& value);
  std::optional<std::string> get_root(const std::string& key) const;

 private:
  explicit Db(rocksdb::DB* db) : db_(db) {}

  rocksdb::DB* db_;
  std::map<std::string, rocksdb::ColumnFamilyHandle*> cfs_;
};

}  // namespace sled
