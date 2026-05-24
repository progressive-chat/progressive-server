#include "federation_client.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <iostream>

namespace progressive::federation {

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

FederationHttpClient::FederationHttpClient(net::io_context& ioc) : ioc_(ioc) {}

void FederationHttpClient::get(std::string_view server, std::string_view path,
                               FederationCallback cb) {
  do_request(server, path, "GET", "", std::move(cb));
}

void FederationHttpClient::post(std::string_view server, std::string_view path,
                                const nlohmann::json& body, FederationCallback cb) {
  do_request(server, path, "POST", body.dump(), std::move(cb));
}

void FederationHttpClient::put(std::string_view server, std::string_view path,
                               const nlohmann::json& body, FederationCallback cb) {
  do_request(server, path, "PUT", body.dump(), std::move(cb));
}

void FederationHttpClient::do_request(std::string_view server, std::string_view path,
                                      std::string_view method, std::string body,
                                      FederationCallback cb) {
  auto resolver = std::make_shared<tcp::resolver>(ioc_);
  auto socket = std::make_shared<tcp::socket>(ioc_);
  auto req = std::make_shared<http::request<http::string_body>>();

  std::string method_str(method);
  if (method_str == "GET")
    req->method(http::verb::get);
  else if (method_str == "POST")
    req->method(http::verb::post);
  else if (method_str == "PUT")
    req->method(http::verb::put);

  req->set(http::field::host, std::string(server));
  req->set(http::field::user_agent, "Progressive/0.1.0");
  req->set(http::field::content_type, "application/json");
  req->target(std::string(path));
  req->body() = std::move(body);
  req->prepare_payload();

  std::string sv(server);
  auto colon = sv.find(':');
  std::string host = (colon != std::string::npos) ? sv.substr(0, colon) : sv;
  std::string port = (colon != std::string::npos) ? sv.substr(colon + 1) : "8448";

  resolver->async_resolve(
      host, port,
      [resolver, socket, req, cb = std::move(cb)](beast::error_code ec,
                                                  tcp::resolver::results_type results) mutable {
        if (ec) {
          if (cb)
            cb(false, {});
          return;
        }
        net::async_connect(
            *socket, results,
            [socket, req, cb = std::move(cb)](beast::error_code ec, tcp::endpoint) mutable {
              if (ec) {
                if (cb)
                  cb(false, {});
                return;
              }
              http::async_write(
                  *socket, *req,
                  [socket, req, cb = std::move(cb)](beast::error_code ec, std::size_t) mutable {
                    if (ec) {
                      if (cb)
                        cb(false, {});
                      return;
                    }
                    auto res = std::make_shared<http::response<http::string_body>>();
                    auto buffer = std::make_shared<beast::flat_buffer>();
                    http::async_read(*socket, *buffer, *res,
                                     [socket, res, cb = std::move(cb)](beast::error_code ec,
                                                                       std::size_t) mutable {
                                       if (cb) {
                                         try {
                                           auto j = nlohmann::json::parse(res->body());
                                           cb(!ec, j);
                                         } catch (...) {
                                           cb(false, {});
                                         }
                                       }
                                     });
                  });
            });
      });
}

}  // namespace progressive::federation
