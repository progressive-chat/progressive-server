#include "server.hpp"

#include <boost/asio/signal_set.hpp>
#include <iostream>
#include <thread>

#include "../crypto/signing.hpp"
#include "../federation/auth.hpp"
#include "../federation/federation_server.hpp"
#include "../rest/client/endpoints.hpp"
#include "../rest/key/v2/server_key.hpp"

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

  db_->execute(R"(
    CREATE TABLE IF NOT EXISTS schema_version (
      version INTEGER PRIMARY KEY,
      applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      password_hash TEXT,
      creation_ts BIGINT NOT NULL,
      admin INTEGER DEFAULT 0,
      deactivated INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS rooms (
      room_id TEXT PRIMARY KEY,
      is_public INTEGER DEFAULT 0,
      creator TEXT,
      room_version INTEGER DEFAULT 10,
      creation_ts BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
      event_id TEXT PRIMARY KEY,
      room_id TEXT NOT NULL,
      type TEXT NOT NULL,
      sender TEXT NOT NULL,
      content TEXT NOT NULL,
      state_key TEXT,
      depth BIGINT NOT NULL DEFAULT 0,
      origin_server_ts TEXT,
      outlier INTEGER DEFAULT 0,
      stream_ordering INTEGER
    );
    CREATE INDEX IF NOT EXISTS events_room_id ON events(room_id);
    CREATE INDEX IF NOT EXISTS events_stream_ordering ON events(stream_ordering);
    CREATE INDEX IF NOT EXISTS events_type ON events(type);
    CREATE TABLE IF NOT EXISTS state_events (
      event_id TEXT NOT NULL,
      room_id TEXT NOT NULL,
      type TEXT NOT NULL,
      state_key TEXT NOT NULL,
      PRIMARY KEY (room_id, type, state_key)
    );
    CREATE INDEX IF NOT EXISTS state_events_event ON state_events(event_id);
    CREATE TABLE IF NOT EXISTS access_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL UNIQUE,
      user_id TEXT NOT NULL,
      device_id TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS access_tokens_token ON access_tokens(token);
    CREATE TABLE IF NOT EXISTS room_memberships (
      event_id TEXT NOT NULL,
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      membership TEXT NOT NULL DEFAULT 'leave',
      sender TEXT NOT NULL,
      content TEXT,
      PRIMARY KEY (room_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS event_auth (
      event_id TEXT NOT NULL,
      auth_id TEXT NOT NULL,
      PRIMARY KEY (event_id, auth_id)
    );
    CREATE TABLE IF NOT EXISTS destinations (
      destination TEXT PRIMARY KEY,
      retry_interval BIGINT DEFAULT 0,
      retry_last_ts BIGINT,
      failure_ts BIGINT
    );
  )");

  // Register REST routes
  rest::client::register_routes(*this, router_);

  // Register federation routes
  federation::register_federation_routes(*db_, router_, config_.server.server_name);

  // Register key server routes
  auto signing_key = crypto::SigningKey("v0", {});
  federation::register_key_routes(signing_key, router_, config_.server.server_name);

  // Start HTTP server on the first listener
  if (!config_.server.listeners.empty()) {
    auto& listener = config_.server.listeners[0];
    http_server_ = std::make_unique<http::HttpServer>(ioc_, listener.bind_address, listener.port);

    http_server_->set_handler([this](boost_http::request<boost_http::string_body>&& req) {
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
  ioc_.stop();
  std::cout << "[progressive] server stopped\n";
}

void Server::run() {
  setup();
  start();

  net::signal_set signals(ioc_, SIGINT, SIGTERM);
  signals.async_wait([this](boost::system::error_code, int) { stop(); });

  ioc_.run();
}

}  // namespace progressive::server
