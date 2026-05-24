#pragma once
#include <boost/asio/io_context.hpp>
#include <map>
#include <nlohmann/json.hpp>
#include <queue>
#include <string>
#include <string_view>

#include "../storage/database.hpp"

namespace progressive::federation {

struct FedDestination {
  std::string server;
  int64_t retry_interval = 60000;  // 1 min initial
  int64_t last_attempt = 0;
  int failures = 0;
};

class FederationSender {
public:
  FederationSender(storage::DatabasePool& db, boost::asio::io_context& ioc,
                   std::string_view server_name);

  void send_event(const std::string& event_id, const std::string& room_id);
  void process_queue();

private:
  void send_to_destination(const std::string& dest, const nlohmann::json& txn);
  int64_t backoff(const FedDestination& d) const;

  storage::DatabasePool& db_;
  boost::asio::io_context& ioc_;
  std::string server_name_;
  std::map<std::string, FedDestination, std::less<>> destinations_;
};

}  // namespace progressive::federation
