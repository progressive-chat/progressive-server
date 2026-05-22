#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <map>
#include <optional>
#include <cstdint>
#include "../types/matrix_id.hpp"

namespace progressive::events {

enum class RoomVersion : uint8_t {
  V1 = 1, V2 = 2, V3 = 3, V4 = 4, V5 = 5, V6 = 6,
  V7 = 7, V8 = 8, V9 = 9, V10 = 10, V11 = 11,
};

struct EventContent {
  nlohmann::json body;
  std::string msgtype;

  static EventContent from_json(const nlohmann::json& j) {
    EventContent c;
    c.body = j;
    c.msgtype = j.value("msgtype", std::string{});
    return c;
  }
};

struct UnsignedData {
  uint64_t age_ts = 0;
  std::optional<nlohmann::json> redacted_because;

  nlohmann::json to_json() const;
  static UnsignedData from_json(const nlohmann::json& j);
};

struct Signatures {
  std::map<std::string, std::map<std::string, std::string>> sigs;

  nlohmann::json to_json() const;
  static Signatures from_json(const nlohmann::json& j);
  void add(std::string_view origin, std::string_view key_id, std::string_view signature);
};

class Event {
public:
  EventID event_id;
  std::string type;
  std::string sender;
  RoomID room_id;
  nlohmann::json content;
  int64_t depth = 0;
  std::vector<std::string> prev_events;
  std::vector<std::string> auth_events;
  std::string origin_server_ts;
  std::optional<std::string> state_key;
  UnsignedData unsigned_;
  Signatures signatures;
  RoomVersion room_version = RoomVersion::V10;

  Event()
    : event_id("_", "_")
    , room_id("_", "_")
  {}

  nlohmann::json to_json() const;
  static Event from_json(const nlohmann::json& j);

  bool is_state() const { return state_key.has_value(); }
  std::string state_key_str() const { return state_key.value_or(""); }
};

}
