#include "server.hpp"

#include <boost/asio/signal_set.hpp>
#include <iostream>
#include <thread>

#include "../crypto/signing.hpp"
#include "../federation/auth.hpp"
#include "../federation/federation_server.hpp"
#include "../media/media.hpp"
#include "../rest/client/endpoints.hpp"
#include "../rest/key/v2/server_key.hpp"
#include "../storage/migration.hpp"

namespace progressive::server {

Server::Server(config::Config cfg) : config_(std::move(cfg)) {}

Server::~Server() {
  stop();
}

void Server::setup() {
  std::string conn = "sqlite://progressive.db";
  if (!config_.database.databases.empty()) {
    auto& dbcfg = config_.database.databases[0];
    if (dbcfg.name.starts_with("pg") || dbcfg.name.starts_with("post")) {
      conn = "postgresql://";
      if (auto it = dbcfg.args.find("user"); it != dbcfg.args.end())
        conn += it->second;
      if (auto it = dbcfg.args.find("password"); it != dbcfg.args.end())
        conn += ":" + it->second;
      if (auto it = dbcfg.args.find("host"); it != dbcfg.args.end())
        conn += "@" + it->second;
      if (auto it = dbcfg.args.find("database"); it != dbcfg.args.end())
        conn += "/" + it->second;
    }
  }
  db_ = storage::DatabasePool::create(conn);

  // Apply database schema via migration system
  storage::apply_schema(*db_);

  // Stream ordering monotonicity check
  auto max_stream = db_->query("SELECT MAX(stream_ordering) as mx FROM events");
  int64_t max_val = 0;
  if (!max_stream.empty() && !max_stream[0]["mx"].is_null())
    max_val = max_stream[0]["mx"].template get<int64_t>();
  std::cout << "[progressive] max stream ordering: " << max_val << "\n";

  // Set SQLite statement timeout (60s)
  db_->execute("PRAGMA busy_timeout = 60000");

  // Register REST routes
  rest::client::register_routes(*this, router_);

  // Register federation routes
  federation::register_federation_routes(*db_, router_, config_.server.server_name);

  // Register key server routes — with real ed25519 key
  signing_key_ = crypto::generate_ed25519_keypair();
  federation::register_key_routes(signing_key_, router_, config_.server.server_name);

  std::cout << "[progressive] signing key: " << signing_key_.key_id() << " ("
            << signing_key_.public_key_b64().substr(0, 12) << "...)\n";

  // Register media routes
  auto auth_obj = auth::Auth(*db_);
  media::register_routes(router_, auth_obj, "/tmp/media", config_.server.server_name);

  // Federation sender for outbound transactions
  fed_sender_ =
      std::make_unique<federation::FederationSender>(*db_, ioc_, config_.server.server_name);

  // IRC server on port 6667
  irc_server_ = std::make_unique<irc::IrcServer>(ioc_, 6667, config_.server.server_name, *db_);
  irc_server_->start();

  // XMPP server on port 5222
  xmpp_server_ = std::make_unique<xmpp::XmppServer>(ioc_, 5222, config_.server.server_name, *db_);
  xmpp_server_->start();

  // Start HTTP server on the first listener
  if (!config_.server.listeners.empty()) {
    auto& listener = config_.server.listeners[0];
    http_server_ =
        std::make_unique<http::HttpServer>(ioc_, listener.bind_address, listener.port, listener.tls,
                                           listener.tls_cert_path, listener.tls_key_path);

    http_server_->set_handler([this](boost_http::request<boost_http::string_body>&& req) {
      static std::map<std::string, int, std::less<>> ip_counts;
      static std::mutex ip_mutex;
      auto ip_addr = std::string(req["X-Forwarded-For"]);
      if (ip_addr.empty())
        ip_addr = "127.0.0.1";

      int count = 0;
      {
        std::lock_guard lock(ip_mutex);
        ip_counts[std::string(ip_addr)]++;
        count = ip_counts[std::string(ip_addr)];
      }

      if (count > 100) {
        boost_http::response<boost_http::string_body> res{boost_http::status::too_many_requests,
                                                          11};
        progressive::http::set_json(
            res, R"({"errcode":"M_LIMIT_EXCEEDED","error":"Too many requests"})");
        res.set("X-RateLimit-Limit", "100");
        res.set("X-RateLimit-Remaining", "0");
        progressive::http::set_cors(res);
        return res;
      }

      auto response = router_.route(std::move(req));
      response.set("X-RateLimit-Limit", "100");
      response.set("X-RateLimit-Remaining", std::to_string(std::max(0, 100 - count)));
      return response;
    });
  }

  std::cout << "[progressive] server '" << config_.server.server_name << "' setup complete\n";
  std::cout << "[progressive] database: " << db_->driver_name() << "\n";
}

void Server::start() {
  running_ = true;
  if (http_server_) {
    http_server_->start();
  }
  std::cout << "[progressive] server '" << config_.server.server_name << "' started\n";
  for (auto& listener : config_.server.listeners) {
    std::cout << "[progressive] listening on " << listener.bind_address << ":" << listener.port
              << " (" << listener.type << ")\n";
  }
}

void Server::stop() {
  if (!running_)
    return;
  running_ = false;
  std::cout << "[progressive] draining connections...\n";
  // Allow 3 seconds for in-flight requests to complete
  auto work = boost::asio::make_work_guard(ioc_);
  boost::asio::steady_timer timer(ioc_, std::chrono::seconds(3));
  timer.async_wait([this, work = std::move(work)](boost::system::error_code) { ioc_.stop(); });
  std::cout << "[progressive] server stopped\n";
}

void Server::run() {
  setup();
  start();

  boost::asio::signal_set signals(ioc_, SIGINT, SIGTERM);
  signals.async_wait([this](boost::system::error_code, int) { stop(); });

  ioc_.run();
}

}  // namespace progressive::server
