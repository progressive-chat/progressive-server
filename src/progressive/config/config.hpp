#pragma once
#include <filesystem>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace progressive::config {

struct ListenerConfig {
  uint16_t port = 8008;
  std::string bind_address = "127.0.0.1";
  std::string type = "http";  // http, https, unix
  bool tls = false;
  std::string resource;  // client, federation
  std::string tls_cert_path;
  std::string tls_key_path;
};

struct ServerConfigSection {
  std::string server_name;
  std::vector<ListenerConfig> listeners;
  std::optional<std::string> public_baseurl;
};

struct DatabaseConfigSection {
  struct Database {
    std::string name = "psycopg2";
    std::map<std::string, std::string> args;

    std::string connection_string() const;
  };
  std::vector<Database> databases;
};

struct Config {
  ServerConfigSection server;
  DatabaseConfigSection database;
  std::optional<std::string> config_path;

  static Config load(std::string_view path);
  void validate() const;
};

}  // namespace progressive::config
