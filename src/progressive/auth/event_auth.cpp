#include "event_auth.hpp"

#include <nlohmann/json.hpp>

namespace progressive::auth {

static const int DEFAULT_POWER_LEVEL = 50;
static const int EVENTS_DEFAULT = 0;
static const int STATE_DEFAULT = 50;
static const int REDACT_DEFAULT = 50;

EventAuthorizer::EventAuthorizer(storage::DatabasePool& db) : db_(db) {}

int EventAuthorizer::get_user_power_level(std::string_view room_id, std::string_view user_id) {
  auto rows = db_.query("SELECT content FROM events WHERE room_id='" + std::string(room_id) +
                        "' AND type='m.room.power_levels' AND state_key='' "
                        "ORDER BY depth DESC LIMIT 1");
  if (rows.empty() || rows[0]["content"].is_null())
    return 0;

  try {
    auto pl = nlohmann::json::parse(rows[0]["content"].get<std::string>());
    if (pl.contains("users") && pl["users"].is_object() &&
        pl["users"].contains(std::string(user_id)))
      return pl["users"][std::string(user_id)].get<int>();
    if (pl.contains("users_default"))
      return pl["users_default"].get<int>();
  } catch (...) {
  }
  return 0;
}

int EventAuthorizer::get_event_power_level(std::string_view room_id, std::string_view event_type,
                                           bool is_state) {
  auto rows = db_.query("SELECT content FROM events WHERE room_id='" + std::string(room_id) +
                        "' AND type='m.room.power_levels' AND state_key='' "
                        "ORDER BY depth DESC LIMIT 1");
  if (rows.empty() || rows[0]["content"].is_null())
    return is_state ? STATE_DEFAULT : EVENTS_DEFAULT;

  try {
    auto pl = nlohmann::json::parse(rows[0]["content"].get<std::string>());
    if (pl.contains("events") && pl["events"].is_object() &&
        pl["events"].contains(std::string(event_type)))
      return pl["events"][std::string(event_type)].get<int>();

    // Check state_default
    if (is_state && pl.contains("state_default"))
      return pl["state_default"].get<int>();
    return pl.value("events_default", EVENTS_DEFAULT);
  } catch (...) {
  }
  return is_state ? STATE_DEFAULT : EVENTS_DEFAULT;
}

AuthCheckResult EventAuthorizer::can_send_event(std::string_view room_id, std::string_view user_id,
                                                std::string_view event_type, bool is_state) {
  AuthCheckResult result;

  // Check membership
  auto rows = db_.query("SELECT membership FROM room_memberships WHERE room_id='" +
                        std::string(room_id) + "' AND user_id='" + std::string(user_id) + "'");
  if (rows.empty() || rows[0]["membership"].is_null()) {
    result.errcode = "M_FORBIDDEN";
    result.error = "Not in room";
    return result;
  }
  auto membership = rows[0]["membership"].get<std::string>();
  if (membership != "join") {
    result.errcode = "M_FORBIDDEN";
    result.error = "Not joined to room";
    return result;
  }

  // Check power levels
  int user_pl = get_user_power_level(room_id, user_id);
  int required = get_event_power_level(room_id, event_type, is_state);
  if (user_pl < required) {
    result.errcode = "M_FORBIDDEN";
    result.error = "Insufficient power level. Required: " + std::to_string(required) +
                   ", have: " + std::to_string(user_pl);
    return result;
  }

  result.allowed = true;
  return result;
}

AuthCheckResult EventAuthorizer::can_redact_event(std::string_view room_id,
                                                  std::string_view user_id,
                                                  std::string_view redactee_sender) {
  AuthCheckResult result;

  // If redacting own event, allowed
  if (user_id == redactee_sender) {
    result.allowed = true;
    return result;
  }

  int user_pl = get_user_power_level(room_id, user_id);

  auto rows = db_.query("SELECT content FROM events WHERE room_id='" + std::string(room_id) +
                        "' AND type='m.room.power_levels' AND state_key='' "
                        "ORDER BY depth DESC LIMIT 1");
  int redact_req = REDACT_DEFAULT;
  if (!rows.empty() && !rows[0]["content"].is_null()) {
    try {
      auto pl = nlohmann::json::parse(rows[0]["content"].get<std::string>());
      redact_req = pl.value("redact", REDACT_DEFAULT);
    } catch (...) {
    }
  }

  if (user_pl < redact_req) {
    result.errcode = "M_FORBIDDEN";
    result.error = "Insufficient power level for redaction";
    return result;
  }

  result.allowed = true;
  return result;
}

}  // namespace progressive::auth
