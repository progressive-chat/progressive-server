#include "database.hpp"

#include <fstream>
#include <stdexcept>

namespace stubdb {

namespace {

// One tree = one file of "key\tvalue" lines, with minimal escaping. Real sled
// stores log-structured SSTables; the wire format is an implementation detail
// the API deliberately hides.
std::string escape(std::string_view s) {
  std::string out;
  for (const char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '\t': out += "\\t"; break;
      case '\n': out += "\\n"; break;
      default: out.push_back(c);
    }
  }
  return out;
}

std::string unescape(const std::string& s) {
  std::string out;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\\' && i + 1 < s.size()) {
      switch (s[++i]) {
        case 't': out.push_back('\t'); break;
        case 'n': out.push_back('\n'); break;
        default: out.push_back(s[i]); break;
      }
    } else {
      out.push_back(s[i]);
    }
  }
  return out;
}

}  // namespace

bool Tree::contains_key(const std::string& key) const {
  return map_->count(key) > 0;
}

void Tree::insert(const std::string& key, const std::string& value) {
  (*map_)[key] = value;
  if (on_change_) on_change_();
}

std::optional<std::string> Tree::get(const std::string& key) const {
  const auto it = map_->find(key);
  if (it == map_->end()) return std::nullopt;
  return it->second;
}

Db Db::open(const std::filesystem::path& dir) {
  std::filesystem::create_directories(dir);  // like sled creating its dir
  Db db;
  db.dir_ = dir;

  // Discover existing trees by scanning *.kv files.
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (!entry.is_regular_file() || entry.path().extension() != ".kv") continue;
    db.load_tree(entry.path().stem().string());
  }
  return db;
}

Tree Db::open_tree(const std::string& name) {
  if (!trees_.count(name)) load_tree(name);
  return Tree(&trees_[name], [this, name] { flush_tree(name); });
}

void Db::load_tree(const std::string& name) {
  auto& map = trees_[name];
  std::ifstream file(dir_ / (name + ".kv"));
  if (!file) return;

  std::string line;
  while (std::getline(file, line)) {
    const size_t tab = line.find('\t');
    if (tab == std::string::npos) continue;
    map[unescape(line.substr(0, tab))] = unescape(line.substr(tab + 1));
  }
}

void Db::flush_tree(const std::string& name) {
  // Called on every mutation via Tree — fine at stub scale, exactly what LSM
  // compaction exists to avoid in real deployments.
  std::ofstream file(dir_ / (name + ".kv"), std::ios::trunc);
  for (const auto& [key, value] : trees_.at(name)) {
    file << escape(key) << '\t' << escape(value) << '\n';
  }
}

}  // namespace stubdb
