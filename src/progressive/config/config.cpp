#include "config.hpp"
#include <fstream>
#include <stdexcept>

namespace progressive::config {

Config Config::load(std::string_view path) {
  std::ifstream f{std::string(path)};
  if (!f) throw std::runtime_error("cannot open config file: " + std::string(path));

  nlohmann::json j = nlohmann::json::parse(f);
  Config cfg;
  cfg.config_path = std::string(path);

  if (j.contains("server_name"))
    cfg.server.server_name = j["server_name"].get<std::string>();

  if (j.contains("listeners")) {
    for (auto& l : j["listeners"]) {
      ListenerConfig lc;
      lc.port = l.value("port", 8008);
      lc.bind_address = l.value("bind_addresses", std::vector<std::string>{"127.0.0.1"})[0];
      lc.type = l.value("type", std::string{"http"});
      lc.tls = l.value("tls", false);
      cfg.server.listeners.push_back(lc);
    }
  }

  if (j.contains("public_baseurl"))
    cfg.server.public_baseurl = j["public_baseurl"].get<std::string>();

  if (j.contains("database")) {
    auto& db = j["database"];
    DatabaseConfigSection::Database d;
    d.name = db.value("name", std::string{"psycopg2"});
    if (db.contains("args")) {
      for (auto& [k, v] : db["args"].items()) {
        d.args[k] = v.get<std::string>();
      }
    }
    cfg.database.databases.push_back(d);
  }

  cfg.validate();
  return cfg;
}

void Config::validate() const {
  if (server.server_name.empty())
    throw std::runtime_error("server_name is required");
  if (server.listeners.empty())
    throw std::runtime_error("at least one listener is required");
}

}
