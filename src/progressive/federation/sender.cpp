#include "sender.hpp"

#include <algorithm>
#include <iostream>

#include "../util/time.hpp"
#include "federation_server.hpp"

namespace progressive::federation {

FederationSender::FederationSender(storage::DatabasePool& db, boost::asio::io_context& ioc,
                                   std::string_view server_name)
    : db_(db), ioc_(ioc), server_name_(server_name) {}

void FederationSender::send_event(const std::string& event_id, const std::string& room_id) {
  auto rows = db_.query("SELECT sender,room_id FROM events WHERE event_id='" + event_id + "'");
  if (rows.empty())
    return;

  auto sender = rows[0]["sender"].get<std::string>();
  auto colon = sender.find(':');
  if (colon == std::string::npos)
    return;

  auto dest = sender.substr(colon + 1);
  if (dest == server_name_)
    return;  // local, skip

  destinations_[dest].pending_events.push(event_id);
  std::cout << "[fed_send] queued " << event_id << " for " << dest << "\n";
}

void FederationSender::process_queue() {
  for (auto& [dest, dq] : destinations_) {
    if (dq.pending_events.empty())
      continue;

    // Build transaction
    Transaction txn;
    txn.origin = server_name_;
    txn.origin_server_ts = util::now_ms();

    // Pop up to 50 events per destination
    for (int i = 0; i < 50 && !dq.pending_events.empty(); i++) {
      auto eid = dq.pending_events.front();
      dq.pending_events.pop();

      auto rows = db_.query("SELECT * FROM events WHERE event_id='" + eid + "'");
      if (!rows.empty() && !rows[0]["event_id"].is_null()) {
        auto& ev = rows[0];
        PDU pdu;
        pdu.event_id = ev["event_id"].get<std::string>();
        pdu.room_id = ev["room_id"].get<std::string>();
        pdu.type = ev["type"].get<std::string>();
        pdu.sender = ev["sender"].get<std::string>();
        try {
          pdu.content = nlohmann::json::parse(ev["content"].get<std::string>());
        } catch (...) {
        }
        pdu.depth = ev.value("depth", int64_t(0));
        pdu.origin = server_name_;
        pdu.origin_server_ts = ev.value("origin_server_ts", "");
        if (!ev["state_key"].is_null() && !ev["state_key"].get<std::string>().empty())
          pdu.state_key = ev["state_key"].get<std::string>();
        txn.pdus.push_back(pdu);
      }
    }

    if (!txn.pdus.empty()) {
      nlohmann::json txn_json;
      txn_json["origin"] = txn.origin;
      txn_json["origin_server_ts"] = txn.origin_server_ts;
      txn_json["pdus"] = nlohmann::json::array();
      for (auto& pdu : txn.pdus)
        txn_json["pdus"].push_back(pdu.to_json());

      std::cout << "[fed_send] sending " << txn.pdus.size() << " pdus to " << dest << "\n";

      // Actually send via HTTP federation client
      send_to_destination(dest, txn_json);
    }
  }
}

void FederationSender::send_to_destination(const std::string& dest, const nlohmann::json& txn) {
  // In production: async HTTP PUT to https://{dest}/_matrix/federation/v1/send/{txnId}
  // with X-Matrix authorization header signed by our ed25519 key
  std::string txn_id = "txn_" + std::to_string(util::now_ms());
  std::cout << "[fed_send] PUT /_matrix/federation/v1/send/" << txn_id << " to " << dest << "\n";
  // Real HTTP call stub — full async TLS in production
}

}  // namespace progressive::federation
