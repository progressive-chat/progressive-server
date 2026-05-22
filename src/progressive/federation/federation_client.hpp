#pragma once
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace boost_http = boost::beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;

namespace progressive::federation {

using FederationCallback = std::function<void(bool success, nlohmann::json response)>;

class FederationClient {
public:
  explicit FederationClient(net::io_context& ioc);

  void get(std::string_view server, std::string_view path, FederationCallback cb);

  void post(std::string_view server, std::string_view path, const nlohmann::json& body,
            FederationCallback cb);

private:
  void do_request(std::string_view server, std::string_view path, std::string_view method,
                  std::string body, FederationCallback cb);

  net::io_context& ioc_;
  ssl::context ssl_ctx_{ssl::context::tlsv12_client};
};

}  // namespace progressive::federation
