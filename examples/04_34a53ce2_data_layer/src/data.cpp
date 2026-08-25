#include "data.hpp"

Data Data::load_or_create(const std::filesystem::path& dir) {
  return Data(sled::Db::open(dir));
}

void Data::set_hostname(const std::string& hostname) {
  db_.insert_root("hostname", hostname);  // sled default tree
}

std::string Data::hostname() const {
  return db_.get_root("hostname").value_or("localhost");
}

bool Data::user_exists(const std::string& user_id) const {
  return db_.open_tree("username_password").contains_key(user_id);
}

void Data::user_add(const std::string& user_id,
                    const std::optional<std::string>& password) {
  db_.open_tree("username_password").insert(user_id, password.value_or(""));
}

Data::Data(sled::Db db) : db_(std::move(db)) {}
