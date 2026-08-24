#include "data.hpp"

#include "utils.hpp"

#include <algorithm>
#include <cstdio>

namespace {

// Tree names as constants, exactly like the Rust commit.
const std::string kUserIdPassword = "userid_password";
const std::string kUserIdDeviceIds = "userid_deviceids";
const std::string kDeviceIdToken = "deviceid_token";
const std::string kTokenUserId = "token_userid";

}  // namespace

Data Data::load_or_create(const std::filesystem::path& dir) {
  return Data(stubdb::Db::open(dir));
}

void Data::set_hostname(const std::string& hostname) {
  db_.insert_root("hostname", hostname);
}

std::string Data::hostname() const { return db_.get_root("hostname").value_or("localhost"); }

bool Data::user_exists(const std::string& user_id) const {
  return db_.open_tree(kUserIdPassword).contains_key(user_id);
}

void Data::user_add(const std::string& user_id, const std::optional<std::string>& password) {
  db_.open_tree(kUserIdPassword).insert(user_id, password.value_or(""));
}

std::optional<std::string> Data::user_from_token(const std::string& token) const {
  return db_.open_tree(kTokenUserId).get(token);
}

std::optional<std::string> Data::password_get(const std::string& user_id) const {
  return db_.open_tree(kUserIdPassword).get(user_id);
}

void Data::device_add(const std::string& user_id, const std::string& device_id) {
  // The user's devices live in ONE value, NUL-joined (utils::vec_to_bytes).
  stubdb::Tree tree = db_.open_tree(kUserIdDeviceIds);
  std::vector<std::string> devices =
      utils::bytes_to_vec(tree.get(user_id).value_or(""));
  if (std::find(devices.begin(), devices.end(), device_id) == devices.end()) {
    devices.push_back(device_id);
    tree.insert(user_id, utils::vec_to_bytes(devices));
  }
}

void Data::token_replace(const std::string& user_id, const std::string& device_id,
                         const std::string& token) {
  // debug_assert!(...device belongs to user...) — debug-only upstream; we
  // check unconditionally since it costs nothing at stub scale.
  const stubdb::Tree devices_tree = db_.open_tree(kUserIdDeviceIds);
  const auto devices =
      utils::bytes_to_vec(devices_tree.get(user_id).value_or(""));
  if (std::find(devices.begin(), devices.end(), device_id) == devices.end()) {
    std::fprintf(stderr, "[assert] device %s does not belong to %s\n", device_id.c_str(),
                 user_id.c_str());
    return;
  }

  // Remove old token
  stubdb::Tree device_token = db_.open_tree(kDeviceIdToken);
  stubdb::Tree token_user = db_.open_tree(kTokenUserId);
  if (const auto old_token = device_token.get(device_id)) {
    token_user.erase(*old_token);
    // It will be removed from DEVICEID_TOKEN by the insert below.
  }

  // Assign token to device_id
  device_token.insert(device_id, token);

  // Assign token to user
  token_user.insert(token, user_id);
}
