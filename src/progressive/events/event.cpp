#include "event.hpp"
#include "../util/time.hpp"

namespace progressive::events {

nlohmann::json UnsignedData::to_json() const {
  nlohmann::json j = nlohmann::json::object();
  if (age_ts) j["age_ts"] = age_ts;
  if (redacted_because) j["redacted_because"] = *redacted_because;
  return j;
}

UnsignedData UnsignedData::from_json(const nlohmann::json& j) {
  UnsignedData u;
  u.age_ts = j.value("age_ts", uint64_t(0));
  if (j.contains("redacted_because"))
    u.redacted_because = j["redacted_because"];
  return u;
}

nlohmann::json Signatures::to_json() const {
  nlohmann::json j;
  for (auto& [origin, keys] : sigs) {
    nlohmann::json kv;
    for (auto& [kid, sig] : keys) kv[kid] = sig;
    j[origin] = kv;
  }
  return j;
}

Signatures Signatures::from_json(const nlohmann::json& j) {
  Signatures s;
  for (auto& [origin, keys] : j.items()) {
    for (auto& [kid, sig] : keys.items()) {
      s.sigs[origin][kid] = sig.get<std::string>();
    }
  }
  return s;
}

void Signatures::add(std::string_view origin, std::string_view key_id, std::string_view signature) {
  sigs[std::string(origin)][std::string(key_id)] = std::string(signature);
}

nlohmann::json Event::to_json() const {
  nlohmann::json j;
  j["event_id"] = event_id.to_string();
  j["type"] = type;
  j["sender"] = sender;
  j["room_id"] = room_id.to_string();
  j["content"] = content;
  j["depth"] = depth;
  j["prev_events"] = prev_events;
  j["auth_events"] = auth_events;
  j["origin_server_ts"] = origin_server_ts;
  j["unsigned"] = unsigned_.to_json();
  j["signatures"] = signatures.to_json();
  if (state_key) j["state_key"] = *state_key;
  return j;
}

Event Event::from_json(const nlohmann::json& j) {
  Event ev;
  ev.event_id = EventID::from_string(j.at("event_id").get<std::string>());
  ev.type = j.at("type").get<std::string>();
  ev.sender = j.at("sender").get<std::string>();
  ev.room_id = RoomID::from_string(j.at("room_id").get<std::string>());
  ev.content = j.at("content");
  ev.depth = j.value("depth", int64_t(0));
  for (auto& pe : j.value("prev_events", nlohmann::json::array()))
    ev.prev_events.push_back(pe.get<std::string>());
  for (auto& ae : j.value("auth_events", nlohmann::json::array()))
    ev.auth_events.push_back(ae.get<std::string>());
  ev.origin_server_ts = j.value("origin_server_ts", std::string{});
  if (j.contains("state_key")) ev.state_key = j["state_key"].get<std::string>();
  if (j.contains("unsigned")) ev.unsigned_ = UnsignedData::from_json(j["unsigned"]);
  if (j.contains("signatures")) ev.signatures = Signatures::from_json(j["signatures"]);
  return ev;
}

}
