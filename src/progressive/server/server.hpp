#pragma once
#include <string>
#include <string_view>
#include <memory>
#include <boost/asio/io_context.hpp>
#include "../config/config.hpp"
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

private:
  config::Config config_;
  boost::asio::io_context ioc_;
  std::unique_ptr<storage::DatabasePool> db_;
  bool running_ = false;
};

}
