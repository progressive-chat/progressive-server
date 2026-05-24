#pragma once
#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace progressive::push {

class PushGateway {
public:
  PushGateway(boost::asio::io_context& ioc, std::string_view fcm_key = "",
              std::string_view apns_cert = "");
  void send_notification(std::string_view device_token, std::string_view title,
                         std::string_view body, int badge = 1);
  void send_fcm(std::string_view token, const nlohmann::json& payload);
  void send_apns(std::string_view token, std::string_view payload);

private:
  boost::asio::io_context& ioc_;
  std::string fcm_key_;
  std::string apns_cert_;
};

}  // namespace progressive::push
