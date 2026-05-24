#include "sender.hpp"

#include <algorithm>
#include <iostream>

#include "../util/time.hpp"
#include "federation_client.hpp"
#include "federation_server.hpp"

namespace progressive::federation {

FederationSender::FederationSender(storage::DatabasePool& db, boost::asio::io_context& ioc,
                                   std::string_view server_name)
    : db_(db), ioc_(ioc), server_name_(server_name) {}

int64_t FederationSender::backoff(const FedDestination& d) const {
  return d.retry_interval * (1LL << std::min(d.failures, 5));  // max 32x
}

void FederationSender::send_event(const std::string& event_id, const std::string& room_id) {
  auto rows = db_.query("SELECT sender FROM events WHERE event_id='" + event_id + "'");
  if (rows.empty())
    return;
  auto sender = rows[0]["sender"].get<std::string>();
  auto colon = sender.find(':');
  if (colon == std::string::npos)
    return;
  auto dest = sender.substr(colon + 1);
  if (dest == server_name_)
    return;

  auto& dd = destinations_[dest];
  dd.server = dest;
  int64_t now = util::now_ms();
  if (now - dd.last_attempt < backoff(dd))
    return;  // skip if in backoff
  dd.last_attempt = now;

  // Build transaction
  Transaction txn;
  txn.origin = server_name_;
  txn.origin_server_ts = now;
  txn.pdus.push_back(PDU{});  // placeholder — real PDU from DB

  nlohmann::json txn_json;
  txn_json["origin"] = txn.origin;
  txn_json["origin_server_ts"] = txn.origin_server_ts;
  txn_json["pdus"] = nlohmann::json::array();

  send_to_destination(dest, txn_json);
  dd.failures = 0;  // reset on success
}

void FederationSender::send_to_destination(const std::string& dest, const nlohmann::json& txn) {
  auto txn_id = "txn_" + std::to_string(util::now_ms());
  std::cout << "[fed_send] PUT /_matrix/federation/v1/send/" << txn_id << " to " << dest << "\n";
}

void FederationSender::process_queue() {
  // Periodic processing of pending events
}

}  // namespace progressive::federation
