#include "gateway.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <iostream>

namespace progressive::push {

PushGateway::PushGateway(boost::asio::io_context& ioc, std::string_view fcm_key,
                         std::string_view apns_cert)
    : ioc_(ioc), fcm_key_(fcm_key), apns_cert_(apns_cert) {}

void PushGateway::send_notification(std::string_view device_token, std::string_view title,
                                    std::string_view body, int badge) {
  nlohmann::json payload;
  payload["notification"] = {{"title", title}, {"body", body}};
  payload["data"] = {{"badge", std::to_string(badge)}};
  send_fcm(device_token, payload);
}

void PushGateway::send_fcm(std::string_view token, const nlohmann::json& payload) {
  if (fcm_key_.empty())
    return;
  namespace beast = boost::beast;
  namespace http = beast::http;
  namespace net = boost::asio;

  auto socket = std::make_shared<net::ip::tcp::socket>(ioc_);
  auto resolver = std::make_shared<net::ip::tcp::resolver>(ioc_);

  resolver->async_resolve("fcm.googleapis.com", "443", [](boost::system::error_code, auto) {
    // In production: TLS connect + HTTP POST to /fcm/send
    // with Authorization: key= and Content-Type: application/json
  });

  nlohmann::json fcm_payload;
  fcm_payload["to"] = std::string(token);
  fcm_payload["notification"] = payload["notification"];
  std::cout << "[push] FCM notification to " << token << "\n";
}

void PushGateway::send_apns(std::string_view token, std::string_view payload) {
  if (apns_cert_.empty())
    return;
  // In production: TLS connect to api.push.apple.com with certificate
  std::cout << "[push] APNs notification to " << token << "\n";
}

}  // namespace progressive::push
