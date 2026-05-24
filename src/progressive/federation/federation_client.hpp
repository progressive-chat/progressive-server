#pragma once
#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace boost_http = boost::beast::http;

namespace progressive::federation {

using FederationCallback = std::function<void(bool success, nlohmann::json response)>;

class FederationHttpClient {
public:
  explicit FederationHttpClient(boost::asio::io_context& ioc);

  void get(std::string_view server, std::string_view path, FederationCallback cb);
  void post(std::string_view server, std::string_view path, const nlohmann::json& body,
            FederationCallback cb);
  void put(std::string_view server, std::string_view path, const nlohmann::json& body,
           FederationCallback cb);

private:
  void do_request(std::string_view server, std::string_view path, std::string_view method,
                  std::string body, FederationCallback cb);
  boost::asio::io_context& ioc_;
};

}  // namespace progressive::federation
