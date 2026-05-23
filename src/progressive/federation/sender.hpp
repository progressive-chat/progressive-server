#pragma once
#include <boost/asio/io_context.hpp>
#include <map>
#include <nlohmann/json.hpp>
#include <queue>
#include <string>
#include <string_view>

#include "../storage/database.hpp"

namespace progressive::federation {

class FederationSender {
public:
  FederationSender(storage::DatabasePool& db, boost::asio::io_context& ioc,
                   std::string_view server_name);

  void send_event(const std::string& event_id, const std::string& room_id);
  void process_queue();

private:
  struct Destination {
    std::string retry_interval;
    int64_t retry_last_ts = 0;
    std::queue<std::string> pending_events;
  };

  storage::DatabasePool& db_;
  boost::asio::io_context& ioc_;
  std::string server_name_;
  std::map<std::string, Destination> destinations_;
};

}  // namespace progressive::federation
