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

  // Start HTTP server on the first listener
  if (!config_.server.listeners.empty()) {
    auto& listener = config_.server.listeners[0];
    http_server_ =
        std::make_unique<http::HttpServer>(ioc_, listener.bind_address, listener.port, listener.tls,
                                           listener.tls_cert_path, listener.tls_key_path);

    http_server_->set_handler([this](boost_http::request<boost_http::string_body>&& req) {
      // Simple rate limit: track request count per IP in a map
      static std::map<std::string, int, std::less<>> ip_counts;
      static std::mutex ip_mutex;

      auto ip_addr = std::string(req["X-Forwarded-For"]);
      if (ip_addr.empty())
        ip_addr = "127.0.0.1";

      {
        std::lock_guard lock(ip_mutex);
        ip_counts[std::string(ip_addr)]++;
        int count = ip_counts[std::string(ip_addr)];
        if (count > 100) {
          boost_http::response<boost_http::string_body> res{boost_http::status::too_many_requests,
                                                            11};
          progressive::http::set_json(
              res, R"({"errcode":"M_LIMIT_EXCEEDED","error":"Too many requests"})");
          progressive::http::set_cors(res);
          return res;
        }
      }

      return router_.route(std::move(req));
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
