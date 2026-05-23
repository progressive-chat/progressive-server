#pragma once
#include <boost/beast/http.hpp>
#include <cstdint>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace boost_http = boost::beast::http;

namespace progressive::federation {

struct FederationAuth {
  std::string origin;
  std::string key_id;
  std::string signature;
  std::string destination;
  bool verified = false;

  static FederationAuth parse(std::string_view header);
  bool verify(std::string_view method, std::string_view uri, std::string_view body,
              std::string_view destination_server);
};

struct KeyCache {
  std::map<std::string, nlohmann::json> keys;

  std::optional<std::vector<uint8_t>> get_pubkey(std::string_view server, std::string_view key_id);
  void store_keys(std::string_view server, const nlohmann::json& key_data);
};

boost_http::response<boost_http::string_body> make_federation_error(boost_http::status status,
                                                                    std::string_view errcode,
                                                                    std::string_view error);

}  // namespace progressive::federation
