#pragma once
#include <boost/beast/http.hpp>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "../http/router.hpp"
#include "../storage/database.hpp"
#include "../types/matrix_id.hpp"

namespace progressive::federation {

struct FederationRequest {
  std::string origin;
  std::string method;
  std::string uri;
  std::string content;
};

struct PDU {
  std::string event_id;
  std::string room_id;
  std::string type;
  std::string sender;
  nlohmann::json content;
  int64_t depth = 0;
  std::vector<std::string> prev_events;
  std::vector<std::string> auth_events;
  std::string origin;
  std::string origin_server_ts;
  std::optional<std::string> state_key;
  nlohmann::json signatures;

  static PDU from_json(const nlohmann::json& j);
  nlohmann::json to_json() const;
};

struct EDU {
  std::string type;
  nlohmann::json content;
};

struct Transaction {
  std::string origin;
  uint64_t origin_server_ts = 0;
  std::vector<PDU> pdus;
  std::vector<EDU> edus;
};

void register_federation_routes(storage::DatabasePool& db, progressive::http::Router& router,
                                std::string_view server_name);

}  // namespace progressive::federation
