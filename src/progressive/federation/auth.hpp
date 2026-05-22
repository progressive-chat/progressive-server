#pragma once
#include <boost/beast/http.hpp>
#include <cstdint>
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
  bool verified = false;

  static FederationAuth parse(std::string_view header);
  bool verify(std::string_view body, std::string_view server_name);
};

boost_http::response<boost_http::string_body> make_federation_error(boost_http::status status,
                                                                    std::string_view errcode,
                                                                    std::string_view error);

}  // namespace progressive::federation
