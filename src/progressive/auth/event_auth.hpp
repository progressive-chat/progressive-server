#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "../state/room_version.hpp"
#include "../storage/database.hpp"

namespace progressive::auth {

struct AuthCheckResult {
  bool allowed = false;
  std::string errcode;
  std::string error;
};

class EventAuthorizer {
public:
  explicit EventAuthorizer(storage::DatabasePool& db);

  AuthCheckResult can_send_event(std::string_view room_id, std::string_view user_id,
                                 std::string_view event_type, bool is_state);

  AuthCheckResult can_redact_event(std::string_view room_id, std::string_view user_id,
                                   std::string_view redactee_sender);

  int get_user_power_level(std::string_view room_id, std::string_view user_id);

  int get_event_power_level(std::string_view room_id, std::string_view event_type, bool is_state);

private:
  storage::DatabasePool& db_;
};

}  // namespace progressive::auth
