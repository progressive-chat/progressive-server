#include "sled.hpp"

#include <memory>
#include <stdexcept>

#include <rocksdb/table.h>
#include <rocksdb/cache.h>

namespace sled {

std::optional<std::string> Tree::get(const std::string& key) const {
  std::string value;
  const rocksdb::Status status =
      db_->Get(rocksdb::ReadOptions(), cf_, key, &value);
  if (status.IsNotFound()) return std::nullopt;
  if (!status.ok()) throw std::runtime_error("sled get: " + status.ToString());
  return value;
}

void Tree::insert(const std::string& key, const std::string& value) {
  const rocksdb::Status status =
      db_->Put(rocksdb::WriteOptions(), cf_, key, value);
  if (!status.ok()) throw std::runtime_error("sled put: " + status.ToString());
}

bool Tree::contains_key(const std::string& key) const {
  // sled contains_key: existence check without copying the value.
  std::string value;
  const rocksdb::Status status =
      db_->Get(rocksdb::ReadOptions(), cf_, key, &value);
  return status.ok();
}

void Tree::erase(const std::string& key) {
  db_->Delete(rocksdb::WriteOptions(), cf_, key);
}

std::vector<std::pair<std::string, std::string>> Tree::scan_prefix(
    const std::string& prefix) const {
  // Iterate from Seek(prefix), stop at first key that no longer matches.
  // (Conduit's MultiValue uses 0xff as its separator byte, so a strict
  // upper-bound trick would be subtly wrong here.)
  std::vector<std::pair<std::string, std::string>> out;
  rocksdb::Iterator* it = db_->NewIterator(rocksdb::ReadOptions(), cf_);
  for (it->Seek(prefix); it->Valid() && it->key().starts_with(prefix);
       it->Next()) {
    out.emplace_back(it->key().ToString(), it->value().ToString());
  }
  delete it;
  return out;
}

std::optional<std::pair<std::string, std::string>> Tree::get_gt(
    const std::string& key) const {
  rocksdb::Iterator* it = db_->NewIterator(rocksdb::ReadOptions(), cf_);
  it->Seek(key);  // positions AT key when present
  if (it->Valid() && it->key().ToString() == key) it->Next();
  if (!it->Valid()) {
    delete it;
    return std::nullopt;
  }
  auto result = std::make_pair(it->key().ToString(), it->value().ToString());
  delete it;
  return result;
}

// NEW in 23cb550d: sled's get_lt — first entry strictly less than key.
std::optional<std::pair<std::string, std::string>> Tree::get_lt(
    const std::string& key) const {
  rocksdb::Iterator* it = db_->NewIterator(rocksdb::ReadOptions(), cf_);
  it->SeekForPrev(key);
  if (it->Valid() && it->key().ToString() == key) it->Prev();
  if (!it->Valid()) {
    delete it;
    return std::nullopt;
  }
  auto result = std::make_pair(it->key().ToString(), it->value().ToString());
  delete it;
  return result;
}

std::string Tree::update_and_fetch(
    const std::string& key,
    const std::function<std::string(const std::optional<std::string>&)>& fn) {
  const std::string new_value = fn(get(key));
  insert(key, new_value);
  return new_value;
}

std::vector<std::pair<std::string, std::string>> Tree::iter_all() const {
  std::vector<std::pair<std::string, std::string>> out;
  rocksdb::Iterator* it = db_->NewIterator(rocksdb::ReadOptions(), cf_);
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    out.emplace_back(it->key().ToString(), it->value().ToString());
  }
  delete it;
  return out;
}

Db Db::open(const std::filesystem::path& dir, uint64_t cache_capacity) {
  std::filesystem::create_directories(dir);

  // Reopening must describe every existing column family, so list them first.
  std::vector<std::string> existing;
  const rocksdb::Status listed =
      rocksdb::DB::ListColumnFamilies(rocksdb::DBOptions(), dir.string(), &existing);
  if (!listed.ok()) existing.clear();  // fresh database
  if (existing.empty()) existing.push_back(rocksdb::kDefaultColumnFamilyName);

  // Create shared block cache for all column families
  std::shared_ptr<rocksdb::Cache> block_cache = rocksdb::NewLRUCache(cache_capacity);

  std::vector<rocksdb::ColumnFamilyDescriptor> descriptors;
  for (const std::string& name : existing) {
    rocksdb::ColumnFamilyOptions cf_options;
    // Configure block cache based on cache_capacity
    rocksdb::BlockBasedTableOptions table_options;
    table_options.block_cache = block_cache;
    cf_options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_options));
    descriptors.emplace_back(name, cf_options);
  }

  rocksdb::DBOptions db_options;
  db_options.create_if_missing = true;

  std::unique_ptr<rocksdb::DB> db_ptr;
  std::vector<rocksdb::ColumnFamilyHandle*> handles;
  const rocksdb::Status status = rocksdb::DB::Open(
      db_options, dir.string(), descriptors, &handles, &db_ptr);
  if (!status.ok()) throw std::runtime_error("rocksdb open: " + status.ToString());
  rocksdb::DB* raw = db_ptr.release();

  Db db(raw);
  for (size_t i = 0; i < handles.size(); ++i) {
    db.cfs_[handles[i]->GetName()] = handles[i];
  }
  return db;
}

Db::Db(Db&& other) noexcept
    : db_(other.db_), cfs_(std::move(other.cfs_)) {
  other.db_ = nullptr;
}

Db::~Db() {
  if (db_ == nullptr) return;
  for (auto& [name, handle] : cfs_) {
    if (name != rocksdb::kDefaultColumnFamilyName) db_->DestroyColumnFamilyHandle(handle);
  }
  delete db_;
}

Tree Db::open_tree(const std::string& name) const {
  if (const auto it = cfs_.find(name); it != cfs_.end()) {
    return Tree(db_, it->second);
  }

  rocksdb::ColumnFamilyHandle* handle = nullptr;
  const rocksdb::Status status = db_->CreateColumnFamily(
      rocksdb::ColumnFamilyOptions(), name, &handle);
  if (!status.ok()) throw std::runtime_error("open_tree: " + status.ToString());
  cfs_[name] = handle;
  return Tree(db_, handle);
}

void Db::insert_root(const std::string& key, const std::string& value) {
  db_->Put(rocksdb::WriteOptions(),
           db_->DefaultColumnFamily(), key, value);
}

std::optional<std::string> Db::get_root(const std::string& key) const {
  std::string value;
  const rocksdb::Status status =
      db_->Get(rocksdb::ReadOptions(), db_->DefaultColumnFamily(), key, &value);
  if (status.IsNotFound()) return std::nullopt;
  if (!status.ok()) throw std::runtime_error("root get: " + status.ToString());
  return value;
}

}  // namespace sled
