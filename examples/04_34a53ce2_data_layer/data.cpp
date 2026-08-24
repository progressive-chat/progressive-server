#include "data.hpp"

Data Data::load_or_create(const std::filesystem::path& dir) {
  return Data(stubdb::Db::open(dir));
}

// self.0.insert("hostname", hostname) — sled's default (root) tree.
void Data::set_hostname(const std::string& hostname) {
  db_.insert_root("hostname", hostname);
}

std::string Data::hostname() const {
  // Rust: .unwrap().unwrap() — panics if unset; main() sets it every boot.
  const auto value = db_.get_root("hostname");
  return value.value_or("localhost");
}

bool Data::user_exists(const std::string& user_id) const {
  return db_.open_tree("username_password").contains_key(user_id);  // renamed from "users"
}

void Data::user_add(const std::string& user_id,
                    const std::optional<std::string>& password) {
  db_.open_tree("username_password").insert(user_id, password.value_or(""));
}
