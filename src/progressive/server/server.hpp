#pragma once
#include <boost/asio/io_context.hpp>
#include <memory>
#include <string>
#include <string_view>

#include "../config/config.hpp"
#include "../crypto/signing.hpp"
#include "../http/router.hpp"
#include "../http/server.hpp"
#include "../ratelimit/ratelimit.hpp"
#include "../storage/database.hpp"

namespace progressive::server {

class Server {
public:
  explicit Server(config::Config cfg);
  ~Server();

  void setup();
  void start();
  void stop();
  void run();

  config::Config& config() { return config_; }
  storage::DatabasePool& db() { return *db_; }
  boost::asio::io_context& io() { return ioc_; }
  crypto::Ed25519Keypair& signing_key() { return signing_key_; }
  ratelimit::RateLimiter& rate_limiter() { return rate_limiter_; }

private:
  config::Config config_;
  boost::asio::io_context ioc_;
  std::unique_ptr<storage::DatabasePool> db_;
  std::unique_ptr<http::HttpServer> http_server_;
  http::Router router_;
  crypto::Ed25519Keypair signing_key_;
  ratelimit::RateLimiter rate_limiter_{50.0, 100.0};
  bool running_ = false;
};

}  // namespace progressive::server
