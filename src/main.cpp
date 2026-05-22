#include <iostream>
#include <string_view>
#include <vector>

#include "progressive/config/config.hpp"
#include "progressive/crypto/signing.hpp"
#include "progressive/server/server.hpp"
#include "progressive/types/matrix_id.hpp"
#include "progressive/util/random.hpp"

namespace {

void print_banner() {
  std::cout << R"(
  ██████╗ ██████╗  ██████╗  ██████╗ ██████╗ ███████╗███████╗███████╗██╗██╗   ██╗███████╗
  ██╔══██╗██╔══██╗██╔═══██╗██╔════╝ ██╔══██╗██╔════╝██╔════╝██╔════╝██║██║   ██║██╔════╝
  ██████╔╝██████╔╝██║   ██║██║  ███╗██████╔╝█████╗  ███████╗███████╗██║██║   ██║█████╗
  ██╔═══╝ ██╔══██╗██║   ██║██║   ██║██╔══██╗██╔══╝  ╚════██║╚════██║██║╚██╗ ██╔╝██╔══╝
  ██║     ██║  ██║╚██████╔╝╚██████╔╝██║  ██║███████╗███████║███████║██║ ╚████╔╝ ███████╗
  ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝

     Progressive Server v0.1.0 — The Matrix protocol, in C++
  )" << std::endl;
}

void print_help() {
  std::cout << "Usage: progressive-server [options]\n\n"
            << "Options:\n"
            << "  -c, --config PATH   Path to config file (default: homeserver.yaml)\n"
            << "  -h, --help          Show this help\n"
            << "  -v, --version       Show version\n"
            << "  --generate-config   Generate a default config and print it\n"
            << "  --generate-keys     Generate signing keys and print them\n";
}

int generate_config() {
  std::cout << R"(# Progressive Server configuration
server_name: "localhost"
public_baseurl: "http://localhost:8008/"
listeners:
  - port: 8008
    bind_addresses: ["127.0.0.1"]
    type: http
  - port: 8448
    bind_addresses: ["127.0.0.1"]
    type: http

database:
  name: sqlite3
  args:
    database: ":memory:"

log_config: "/dev/stdout"
)" << std::endl;
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  std::string config_path = "homeserver.yaml";

  for (int i = 1; i < argc; i++) {
    std::string_view arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      print_help();
      return 0;
    }
    if (arg == "-v" || arg == "--version") {
      std::cout << "progressive-server 0.1.0\n";
      return 0;
    }
    if (arg == "--generate-config") {
      return generate_config();
    }
    if (arg == "--generate-keys") {
      auto key = progressive::crypto::generate_signing_key();
      std::cout << "signing_key: \"" << key.value("key", "") << "\"\n";
      return 0;
    }
    if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
      config_path = argv[++i];
      continue;
    }
  }

  print_banner();

  try {
    auto cfg = progressive::config::Config::load(config_path);
    progressive::server::Server server(std::move(cfg));
    server.run();
  } catch (const std::exception& e) {
    std::cerr << "Fatal: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
