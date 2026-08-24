// database.hpp — stand-in for Conduit commit c2c18b46's sled::Db
//
// Rust original:
//
//   let db = sled::open(
//       ProjectDirs::from("xyz", "koesters", "matrixserver")
//           .unwrap()
//           .data_dir(),
//   ).unwrap();
//   ...
//   let users = db.open_tree("users").unwrap();
//   users.contains_key(user_id.to_string())
//   users.insert(user_id.to_string(), &*password)
//
// sled is an LSM-tree embedded KV store (the same family as RocksDB, which
// conduwuit/tuwunel later adopted). This stub keeps the exact same API shape —
// open a directory, open named trees, get/insert/contains_key — but backs it
// with std::map plus one flat file per tree. Same contract, visible internals.

#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>

namespace stubdb {

class Tree {
 public:
  bool contains_key(const std::string& key) const;
  void insert(const std::string& key, const std::string& value);
  std::optional<std::string> get(const std::string& key) const;

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

  // db.open_tree("users"): creates or loads the tree; persists on mutation.
  Tree open_tree(const std::string& name);

 private:
  std::map<std::string, std::map<std::string, std::string>> trees_;
  std::filesystem::path dir_;

  void load_tree(const std::string& name);
  void flush_tree(const std::string& name);
};

}  // namespace stubdb
