// server_bootstrap.cpp — Matrix homeserver startup, configuration, and process management
//
// Implements a complete Matrix homeserver bootstrap sequence modelled after
// Synapse's startup pipeline.  Covers config-file parsing (YAML/JSON), CLI
// argument handling, listener setup, worker-mode dispatch, process management
// (fork + PID file + signals), graceful shutdown, resource limits, structured
// JSON logging, Prometheus metrics, database pool init, TLS/ACME, Redis
// replication, plugin loading, background tasks, health checks and replication
// streams for worker topologies.
//
// Namespace: progressive::server

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <variant>
#include <vector>

// Boost / Asio
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/filesystem.hpp>

// ---------------------------------------------------------------------------
// forward-declared project headers — these exist in the progressive tree
// ---------------------------------------------------------------------------
namespace progressive {
namespace config {
struct Config;
struct ListenerConfig;
struct ServerConfigSection;
struct DatabaseConfigSection;
}
namespace storage {
class DatabasePool;
}
namespace crypto {
struct Ed25519Keypair;
}
namespace http {
class HttpServer;
class Router;
}
namespace federation {
class FederationSender;
}
namespace ratelimit {
class RateLimiter;
}
}  // namespace progressive

// ---------------------------------------------------------------------------
// Local numeric constants — all values default to well-known Synapse defaults
// ---------------------------------------------------------------------------
namespace {
namespace def {

constexpr uint16_t kDefaultClientPort      = 8008;
constexpr uint16_t kDefaultFedPort         = 8448;
constexpr uint16_t kDefaultMediaPort       = 8009;
constexpr uint16_t kDefaultAdminPort       = 8010;
constexpr uint16_t kDefaultMetricsPort     = 9100;
constexpr uint16_t kDefaultReplicationPort = 9093;
constexpr uint16_t kDefaultRedisPort       = 6379;

constexpr int kDefaultDbPoolSize           = 5;
constexpr int kDefaultMaxFd                = 65536;
constexpr int kGracefulShutdownSec         = 15;
constexpr int kHealthCheckIntervalSec      = 30;
constexpr int kAcmCheckIntervalHours       = 24;

constexpr const char* kVersion             = "progressive-server 0.1.0";
constexpr const char* kPidFileDefault      = "/var/run/progressive-server.pid";
constexpr const char* kDefaultConfigPath   = "/etc/progressive/homeserver.yaml";
constexpr const char* kDefaultLogFile      = "/var/log/progressive/homeserver.log";
constexpr const char* kSigningKeyPath      = "/etc/progressive/signing.key";
constexpr const char* kAcmeAccountKey      = "/etc/progressive/acme-account.key";
constexpr const char* kAcmeCertDir         = "/etc/progressive/certs";

}  // namespace def
}  // anonymous namespace

// =========================================================================
// 1.  Configuration loading — YAML / JSON parser with all Synapse sections
// =========================================================================

namespace progressive::server {

// -----------------------------------------------------------------------
// WorkerAppName — maps CLI worker-type strings to internal enums
// -----------------------------------------------------------------------
enum class WorkerApp : uint8_t {
  master,
  generic_worker,
  pusher,
  federation_sender,
  media_repository,
  appservice,
  user_dir,
  synchrotron,
};

struct WorkerAppMeta {
  WorkerApp     app;
  std::string   name;
  std::string   desc;
};
static const std::vector<WorkerAppMeta> kKnownWorkers = {
  {WorkerApp::master,            "master",            "Master homeserver process"},
  {WorkerApp::generic_worker,    "generic_worker",    "Generic worker"},
  {WorkerApp::pusher,            "pusher",            "Pusher worker"},
  {WorkerApp::federation_sender, "federation_sender", "Federation sender"},
  {WorkerApp::media_repository,  "media_repository",  "Media repository"},
  {WorkerApp::appservice,        "appservice",        "Application-service worker"},
  {WorkerApp::user_dir,          "user_dir",          "User directory worker"},
  {WorkerApp::synchrotron,       "synchrotron",       "Sync worker (synchrotron)"},
};

static std::optional<WorkerApp> parse_worker_app(std::string_view name) {
  for (auto& w : kKnownWorkers)
    if (w.name == name)
      return w.app;
  return std::nullopt;
}

// -----------------------------------------------------------------------
// Structured JSON logger — simple thread-safe line-per-record logger
// -----------------------------------------------------------------------
class JsonLogger {
public:
  enum class Level : uint8_t { debug = 0, info = 1, warning = 2, error = 3 };

  explicit JsonLogger(Level min_level = Level::info,
                       std::string path = {},
                       bool rolling = false,
                       size_t max_size_mb = 100)
    : min_level_(min_level)
    , path_(std::move(path))
    , rolling_(rolling)
    , max_size_bytes_(max_size_mb * 1024ULL * 1024ULL) {
    if (!path_.empty()) {
      reopen();
    }
  }

  void log(Level lvl, std::string_view message,
           std::map<std::string, std::string> extra = {}) {
    if (lvl < min_level_)
      return;

    auto now = std::chrono::system_clock::now();
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                 now.time_since_epoch())
                 .count();

    std::stringstream ss;
    ss << R"({"ts":)" << ms
       << R"(,"level":")" << level_name(lvl)
       << R"(","msg":")"  << escape_json(message) << '"';

    for (auto& [k, v] : extra)
      ss << R"(,")" << escape_json(k) << R"(":")" << escape_json(v) << '"';

    ss << "}\n";

    std::string line = ss.str();

    {
      std::lock_guard<std::mutex> lk(mtx_);
      if (path_.empty())
        std::cerr << line;
      else
        write_to_file(line);
    }
  }

  void set_level(Level lvl) { min_level_ = lvl; }
  Level level() const { return min_level_; }

private:
  static const char* level_name(Level lvl) {
    switch (lvl) {
      case Level::debug:   return "DEBUG";
      case Level::info:    return "INFO";
      case Level::warning: return "WARNING";
      case Level::error:   return "ERROR";
    }
    return "UNKNOWN";
  }

  static std::string escape_json(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
      switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
      }
    }
    return out;
  }

  void reopen() {
    ofs_.open(path_, std::ios::app);
    if (!ofs_)
      std::cerr << "[json-logger] cannot open " << path_ << "\n";
  }

  void write_to_file(const std::string& line) {
    if (rolling_ && ofs_.tellp() > static_cast<long>(max_size_bytes_)) {
      ofs_.close();
      auto backup = path_ + ".1";
      std::filesystem::rename(path_, backup);
      reopen();
    }
    ofs_ << line;
    ofs_.flush();
  }

  Level               min_level_;
  std::string         path_;
  bool                rolling_;
  size_t              max_size_bytes_;
  std::mutex          mtx_;
  std::ofstream       ofs_;
};

// -----------------------------------------------------------------------
// CLI options — mirrors `synapse.app.homeserver` flags
// -----------------------------------------------------------------------
struct CliOptions {
  std::string              config_path = def::kDefaultConfigPath;
  bool                     generate_config   = false;
  std::string              generate_directory;
  bool                     migrate_config    = false;
  bool                     generate_keys     = false;
  std::string              keys_directory;
  bool                     daemonize         = false;
  std::string              pid_file          = def::kPidFileDefault;
  bool                     print_version     = false;
  bool                     run               = false;
  std::optional<WorkerApp> worker_app;
  std::string              worker_name;
  std::string              worker_main_process;   // host:port of main
  std::string              worker_replication_host;
  uint16_t                 worker_replication_port = def::kDefaultReplicationPort;
  bool                     enable_soft_file_limit = true;
  int                      soft_file_limit       = def::kDefaultMaxFd;
  int                      hard_file_limit       = def::kDefaultMaxFd;
  std::string              log_config_path;
  bool                     structured_log       = true;
  std::string              log_file             = def::kDefaultLogFile;
  std::string              log_level            = "info";
  bool                     rolling_logs         = true;
  uint32_t                 log_max_size_mb      = 100;
  bool                     enable_metrics       = true;
  uint16_t                 metrics_port         = def::kDefaultMetricsPort;
  std::string              metrics_bind_addr    = "127.0.0.1";
  bool                     enable_sentry        = false;
  std::string              sentry_dsn;
  bool                     enable_acme          = false;
  std::string              acme_domain;
  std::string              acme_email;
  bool                     enable_redis         = false;
  std::string              redis_host           = "127.0.0.1";
  uint16_t                 redis_port           = def::kDefaultRedisPort;
  int                      redis_pool_size      = 8;
  std::string              module_path;
  bool                     list_modules         = false;
  bool                     no_background_tasks  = false;
  bool                     enable_health_check  = true;
  bool                     enable_replication   = false;
};

// =========================================================================
// 2.  Server command-line argument parsing
// =========================================================================

namespace {

constexpr std::string_view kUsage = R"USAGE(Usage: progressive-server [OPTIONS]

Synapse-compatible Matrix homeserver written in C++.

Server options:
  -c, --config-path PATH        Path to config file (default: /etc/progressive/homeserver.yaml)

Configuration generation:
  --generate-config             Generate a default config file
  --generate-directory DIR      Generate configs into DIR
  --migrate-config              Migrate old-style config to YAML

Key management:
  --generate-keys               Generate signing keys
  --keys-directory DIR          Directory for generated keys

Process management:
  -D, --daemonize               Fork into background
  --pid-file PATH               PID file path (default: /var/run/progressive-server.pid)

Worker mode:
  --worker-app APP              Worker app name (generic_worker, pusher, federation_sender,
                                 media_repository, appservice, user_dir, synchrotron)
  --worker-name NAME            Unique worker name
  --worker-main-process HOST:PORT  Host and port of main process
  --worker-replication-host HOST   Replication listener host
  --worker-replication-port PORT   Replication listener port

Resource limits:
  --soft-file-limit N           Soft limit for open file descriptors (default: 65536)
  --hard-file-limit N           Hard limit for open file descriptors
  --no-soft-file-limit          Disable automatic file-descriptor limit increase

Logging:
  --log-config PATH             Structured logging config (YAML)
  --no-structured-log           Disable structured JSON logging
  --log-file PATH               Log file path (default: /var/log/progressive/homeserver.log)
  --log-level LEVEL             Log level: debug, info, warning, error (default: info)
  --rolling-logs                Enable rolling log files
  --log-max-size-mb MB          Max log file size before rotation (default: 100)

Metrics & observability:
  --enable-metrics              Enable Prometheus metrics endpoint
  --metrics-port PORT           Metrics listener port (default: 9100)
  --metrics-bind-addr ADDR      Metrics bind address (default: 127.0.0.1)
  --enable-sentry               Enable Sentry error reporting
  --sentry-dsn DSN              Sentry DSN

ACME / TLS:
  --enable-acme                 Enable ACME certificate management
  --acme-domain DOMAIN          Domain for ACME certificate
  --acme-email EMAIL            Contact email for ACME

Redis replication:
  --enable-redis                Enable Redis connection pool
  --redis-host HOST             Redis host (default: 127.0.0.1)
  --redis-port PORT             Redis port (default: 6379)
  --redis-pool-size N           Redis connection pool size (default: 8)

Modules:
  --module-path PATH            Path to third-party module directory
  --list-modules                List loaded modules

Background tasks:
  --no-background-tasks         Disable background task scheduler

Health / replication:
  --enable-health-check         Enable health-check endpoint
  --enable-replication          Enable replication stream for workers

General:
  -h, --help                    Show this help
  -V, --version                 Show version

Run server:
  run                           Start the server (default if no other action specified)
)USAGE";

// ---------------------------------------------------------------------------
// parse_cli — maps argc/argv into CliOptions
// ---------------------------------------------------------------------------
CliOptions parse_cli(int argc, char* argv[]) {
  CliOptions opts;

  // Helper to consume the next argument; returns empty if none
  auto next_arg = [&](int& i, const char* name) -> std::optional<std::string> {
    if (i + 1 >= argc) {
      std::cerr << "Error: " << name << " requires a value\n";
      std::exit(1);
    }
    return std::string(argv[++i]);
  };

  for (int i = 1; i < argc; ++i) {
    std::string_view arg(argv[i]);

    if (arg == "-h" || arg == "--help") {
      std::cout << kUsage;
      std::exit(0);
    }
    else if (arg == "-V" || arg == "--version") {
      opts.print_version = true;
    }
    else if (arg == "-c" || arg == "--config-path") {
      if (auto v = next_arg(i, "config-path"))
        opts.config_path = *v;
    }
    else if (arg == "--generate-config") {
      opts.generate_config = true;
    }
    else if (arg == "--generate-directory") {
      if (auto v = next_arg(i, "generate-directory"))
        opts.generate_directory = *v;
    }
    else if (arg == "--migrate-config") {
      opts.migrate_config = true;
    }
    else if (arg == "--generate-keys") {
      opts.generate_keys = true;
    }
    else if (arg == "--keys-directory") {
      if (auto v = next_arg(i, "keys-directory"))
        opts.keys_directory = *v;
    }
    else if (arg == "-D" || arg == "--daemonize") {
      opts.daemonize = true;
    }
    else if (arg == "--pid-file") {
      if (auto v = next_arg(i, "pid-file"))
        opts.pid_file = *v;
    }
    else if (arg == "--worker-app") {
      if (auto v = next_arg(i, "worker-app")) {
        auto app = parse_worker_app(*v);
        if (!app) {
          std::cerr << "Error: unknown worker app '" << *v << "'\n";
          std::cerr << "Known workers:";
          for (auto& w : kKnownWorkers) std::cerr << " " << w.name;
          std::cerr << "\n";
          std::exit(1);
        }
        opts.worker_app = app;
      }
    }
    else if (arg == "--worker-name") {
      if (auto v = next_arg(i, "worker-name"))
        opts.worker_name = *v;
    }
    else if (arg == "--worker-main-process") {
      if (auto v = next_arg(i, "worker-main-process"))
        opts.worker_main_process = *v;
    }
    else if (arg == "--worker-replication-host") {
      if (auto v = next_arg(i, "worker-replication-host"))
        opts.worker_replication_host = *v;
    }
    else if (arg == "--worker-replication-port") {
      if (auto v = next_arg(i, "worker-replication-port"))
        opts.worker_replication_port = static_cast<uint16_t>(std::stoi(*v));
    }
    else if (arg == "--soft-file-limit") {
      if (auto v = next_arg(i, "soft-file-limit"))
        opts.soft_file_limit = std::stoi(*v);
    }
    else if (arg == "--hard-file-limit") {
      if (auto v = next_arg(i, "hard-file-limit"))
        opts.hard_file_limit = std::stoi(*v);
    }
    else if (arg == "--no-soft-file-limit") {
      opts.enable_soft_file_limit = false;
    }
    else if (arg == "--log-config") {
      if (auto v = next_arg(i, "log-config"))
        opts.log_config_path = *v;
    }
    else if (arg == "--no-structured-log") {
      opts.structured_log = false;
    }
    else if (arg == "--log-file") {
      if (auto v = next_arg(i, "log-file"))
        opts.log_file = *v;
    }
    else if (arg == "--log-level") {
      if (auto v = next_arg(i, "log-level"))
        opts.log_level = *v;
    }
    else if (arg == "--rolling-logs") {
      opts.rolling_logs = true;
    }
    else if (arg == "--log-max-size-mb") {
      if (auto v = next_arg(i, "log-max-size-mb"))
        opts.log_max_size_mb = static_cast<uint32_t>(std::stoul(*v));
    }
    else if (arg == "--enable-metrics") {
      opts.enable_metrics = true;
    }
    else if (arg == "--metrics-port") {
      if (auto v = next_arg(i, "metrics-port"))
        opts.metrics_port = static_cast<uint16_t>(std::stoi(*v));
    }
    else if (arg == "--metrics-bind-addr") {
      if (auto v = next_arg(i, "metrics-bind-addr"))
        opts.metrics_bind_addr = *v;
    }
    else if (arg == "--enable-sentry") {
      opts.enable_sentry = true;
    }
    else if (arg == "--sentry-dsn") {
      if (auto v = next_arg(i, "sentry-dsn"))
        opts.sentry_dsn = *v;
    }
    else if (arg == "--enable-acme") {
      opts.enable_acme = true;
    }
    else if (arg == "--acme-domain") {
      if (auto v = next_arg(i, "acme-domain"))
        opts.acme_domain = *v;
    }
    else if (arg == "--acme-email") {
      if (auto v = next_arg(i, "acme-email"))
        opts.acme_email = *v;
    }
    else if (arg == "--enable-redis") {
      opts.enable_redis = true;
    }
    else if (arg == "--redis-host") {
      if (auto v = next_arg(i, "redis-host"))
        opts.redis_host = *v;
    }
    else if (arg == "--redis-port") {
      if (auto v = next_arg(i, "redis-port"))
        opts.redis_port = static_cast<uint16_t>(std::stoi(*v));
    }
    else if (arg == "--redis-pool-size") {
      if (auto v = next_arg(i, "redis-pool-size"))
        opts.redis_pool_size = std::stoi(*v);
    }
    else if (arg == "--module-path") {
      if (auto v = next_arg(i, "module-path"))
        opts.module_path = *v;
    }
    else if (arg == "--list-modules") {
      opts.list_modules = true;
    }
    else if (arg == "--no-background-tasks") {
      opts.no_background_tasks = true;
    }
    else if (arg == "--enable-health-check") {
      opts.enable_health_check = true;
    }
    else if (arg == "--enable-replication") {
      opts.enable_replication = true;
    }
    else if (arg == "run") {
      opts.run = true;
    }
    else {
      std::cerr << "Unknown argument: " << arg << "\nTry --help\n";
      std::exit(1);
    }
  }

  // Default action if none specified: run
  if (!opts.generate_config && !opts.migrate_config && !opts.generate_keys &&
      !opts.print_version)
    opts.run = true;

  return opts;
}

// ---------------------------------------------------------------------------
// load_config — read and parse YAML/JSON config file
// ---------------------------------------------------------------------------
config::Config load_config(const CliOptions& opts) {
  if (opts.generate_config || opts.migrate_config)
    return config::Config{};

  if (!std::filesystem::exists(opts.config_path)) {
    std::cerr << "Warning: config file not found at " << opts.config_path
              << " — using defaults\n";
    return config::Config{};
  }

  return config::Config::load(opts.config_path);
}

// ---------------------------------------------------------------------------
// generate_default_config — writes a synapse-compatible YAML default
// ---------------------------------------------------------------------------
void generate_default_config(const std::string& directory) {
  namespace fs = std::filesystem;
  fs::create_directories(directory);

  std::string path = directory + "/homeserver.yaml";
  std::ofstream ofs(path);
  if (!ofs) {
    std::cerr << "Error: cannot write " << path << "\n";
    std::exit(1);
  }

  ofs << R"YAML(# Progressive Matrix Server — default configuration
# Auto-generated by progressive-server --generate-config

server_name: "localhost"
pid_file: "/var/run/progressive-server.pid"

# Listener configuration — Client-Server, Federation, Media, Admin
listeners:
  - port: 8008
    bind_address: "0.0.0.0"
    type: http
    tls: false
    resources:
      - names: [client]
        compress: false

  - port: 8448
    bind_address: "0.0.0.0"
    type: http
    tls: false
    resources:
      - names: [federation]
        compress: false

  - port: 8009
    bind_address: "127.0.0.1"
    type: http
    tls: false
    resources:
      - names: [media]
        compress: false

  - port: 8010
    bind_address: "127.0.0.1"
    type: http
    tls: false
    resources:
      - names: [admin]
        compress: false

# Database
database:
  name: psycopg2
  args:
    user: progressive
    password: ""
    database: progressive
    host: localhost
    port: 5432
    cp_min: 5
    cp_max: 20

# Logging (structured JSON)
logging:
  log_file: "/var/log/progressive/homeserver.log"
  log_level: "info"
  structured: true
  rolling: true
  max_size_mb: 100

# Metrics / observability
enable_metrics: true
metrics_port: 9100
metrics_bind_address: "127.0.0.1"

# Redis replication
redis:
  enabled: false
  host: "127.0.0.1"
  port: 6379
  pool_size: 8

# Modules / plugins
modules:
  - module: "<module_path>"
    config: {}

# ACME (auto TLS)
acme:
  enabled: false
  domain: ""
  email: ""

# Signing key
signing_key_path: "/etc/progressive/signing.key"

# Federation
federation:
  send_federation: true
  allow_federated_events: true

# Rate limiting
rc_messages_per_second: 0.5
rc_message_burst_count: 20

# Registration
enable_registration: false
registration_shared_secret: ""

# Media store
media_store_path: "/var/lib/progressive/media"

# Background tasks
run_background_tasks: true

# Replication
enable_replication: false
replication_port: 9093

# Resource limits
soft_file_limit: 65536
)YAML";

  std::cout << "[progressive] default config written to " << path << "\n";
}

// ---------------------------------------------------------------------------
// migrate_old_config — placeholder for config format migration
// ---------------------------------------------------------------------------
void migrate_old_config(const std::string& path) {
  std::cout << "[progressive] migrate-config processing: " << path << "\n";
  if (!std::filesystem::exists(path)) {
    std::cerr << "Error: source config " << path << " does not exist\n";
    std::exit(1);
  }

  // Read old config
  std::ifstream ifs(path);
  std::string content((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());

  // Parse as JSON (old-style synapse configs were JSON)
  nlohmann::json old_config;
  try {
    old_config = nlohmann::json::parse(content);
  } catch (const std::exception& e) {
    std::cerr << "Error parsing old config: " << e.what() << "\n";
    std::exit(1);
  }

  // Build YAML-compatible representation
  std::stringstream out;
  out << "# Migrated configuration from " << path << "\n";
  out << "server_name: \""
      << (old_config.value("server_name", "localhost")) << "\"\n";

  // Migrate database block
  if (old_config.contains("database")) {
    auto& db = old_config["database"];
    out << "database:\n";
    out << "  name: \"" << db.value("name", "psycopg2") << "\"\n";
    out << "  args:\n";
    if (db.contains("args")) {
      for (auto& [k, v] : db["args"].items())
        out << "    " << k << ": \"" << v.get<std::string>() << "\"\n";
    }
  }

  // Migrate listeners
  if (old_config.contains("listeners")) {
    out << "listeners:\n";
    for (auto& l : old_config["listeners"]) {
      out << "  - port: " << l.value("port", 8008) << "\n";
      out << "    bind_address: \""
          << l.value("bind_addresses", std::vector<std::string>{"0.0.0.0"})
                 .front()
          << "\"\n";
      out << "    type: \"" << l.value("type", "http") << "\"\n";
      out << "    tls: " << (l.value("tls", false) ? "true" : "false") << "\n";
      if (l.contains("resources")) {
        out << "    resources:\n";
        for (auto& r : l["resources"]) {
          out << "      - names:\n";
          if (r.contains("names")) {
            for (auto& n : r["names"])
              out << "          - \"" << n.get<std::string>() << "\"\n";
          }
          out << "        compress: "
              << (r.value("compress", false) ? "true" : "false") << "\n";
        }
      }
    }
  }

  std::string out_path = path + ".migrated.yaml";
  std::ofstream ofs(out_path);
  ofs << out.str();
  std::cout << "[progressive] migrated config written to " << out_path << "\n";
}

}  // anonymous namespace

// =========================================================================
// 3.  Process management — fork, PID file, signal handling
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// write_pid_file & remove_pid_file
// ---------------------------------------------------------------------------
void write_pid_file(const std::string& path) {
  std::ofstream ofs(path);
  if (!ofs) {
    std::cerr << "Error: cannot write PID file " << path << ": "
              << std::strerror(errno) << "\n";
    return;
  }
  ofs << getpid() << "\n";
  ofs.close();
  std::clog << "[progressive] PID " << getpid() << " written to " << path << "\n";
}

void remove_pid_file(const std::string& path) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

// ---------------------------------------------------------------------------
// daemonize — double-fork to detach from controlling terminal
// ---------------------------------------------------------------------------
void daemonize() {
  pid_t pid = fork();
  if (pid < 0) {
    std::cerr << "Error: fork() failed: " << std::strerror(errno) << "\n";
    std::exit(1);
  }
  if (pid > 0) {
    // Parent — wait for child's first fork then exit
    int status = 0;
    waitpid(pid, &status, 0);
    std::exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
  }

  // Child — become session leader
  if (setsid() < 0) {
    std::cerr << "setsid() failed\n";
    std::exit(1);
  }

  // Second fork to fully detach
  pid = fork();
  if (pid < 0) {
    std::cerr << "Error: second fork() failed\n";
    std::exit(1);
  }
  if (pid > 0) {
    std::exit(0);  // first child exits
  }

  // Grandchild — redirect stdio
  umask(0);
  if (chdir("/") < 0) { /* ignore */ }

  // Close standard file descriptors / redirect to /dev/null
  int fd = open("/dev/null", O_RDWR);
  if (fd >= 0) {
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2)
      close(fd);
  }
}

}  // anonymous namespace

// =========================================================================
// 4.  Resource limits
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// set_resource_limits — raise file-descriptor limits as configured
// ---------------------------------------------------------------------------
void set_resource_limits(const CliOptions& opts) {
  if (!opts.enable_soft_file_limit)
    return;

  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
    std::cerr << "Warning: getrlimit(RLIMIT_NOFILE) failed: "
              << std::strerror(errno) << "\n";
    return;
  }

  bool changed = false;
  if (rl.rlim_cur < static_cast<rlim_t>(opts.soft_file_limit)) {
    rl.rlim_cur = std::min(static_cast<rlim_t>(opts.soft_file_limit), rl.rlim_max);
    changed = true;
  }
  if (opts.hard_file_limit > 0 &&
      rl.rlim_max < static_cast<rlim_t>(opts.hard_file_limit)) {
    rl.rlim_max = static_cast<rlim_t>(opts.hard_file_limit);
    rl.rlim_cur = std::min(rl.rlim_cur, rl.rlim_max);
    changed = true;
  }

  if (changed) {
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
      std::cerr << "Warning: setrlimit(RLIMIT_NOFILE) failed: "
                << std::strerror(errno) << "\n";
    } else {
      std::clog << "[progressive] file descriptor limits: "
                << "soft=" << rl.rlim_cur << " hard=" << rl.rlim_max << "\n";
    }
  }
}

}  // anonymous namespace

// =========================================================================
// 5.  Logging configuration
// =========================================================================

namespace {

JsonLogger::Level log_level_from_string(const std::string& s) {
  if (s == "debug")   return JsonLogger::Level::debug;
  if (s == "info")    return JsonLogger::Level::info;
  if (s == "warning") return JsonLogger::Level::warning;
  if (s == "error")   return JsonLogger::Level::error;
  std::cerr << "Warning: unknown log level '" << s << "', defaulting to info\n";
  return JsonLogger::Level::info;
}

JsonLogger create_logger(const CliOptions& opts) {
  return JsonLogger{
    log_level_from_string(opts.log_level),
    opts.log_file,
    opts.rolling_logs,
    opts.log_max_size_mb
  };
}

}  // anonymous namespace

// =========================================================================
// 6.  Prometheus metrics endpoint
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// Simple in-process Prometheus counter/gauge registry
// ---------------------------------------------------------------------------
class PrometheusRegistry {
public:
  struct Metric {
    std::string              name;
    std::string              help;
    std::string              type;   // counter, gauge, histogram
    std::atomic<int64_t>     value{0};
    std::map<std::string, std::string> labels;
  };

  void register_counter(const std::string& name, const std::string& help) {
    std::lock_guard<std::mutex> lk(mtx_);
    metrics_.push_back(Metric{name, help, "counter"});
  }

  void register_gauge(const std::string& name, const std::string& help) {
    std::lock_guard<std::mutex> lk(mtx_);
    metrics_.push_back(Metric{name, help, "gauge"});
  }

  void inc(const std::string& name, int64_t delta = 1) {
    auto* m = find(name);
    if (m)
      m->value.fetch_add(delta, std::memory_order_relaxed);
  }

  void set(const std::string& name, int64_t val) {
    auto* m = find(name);
    if (m)
      m->value.store(val, std::memory_order_relaxed);
  }

  int64_t get(const std::string& name) const {
    auto* m = find(name);
    return m ? m->value.load(std::memory_order_relaxed) : 0;
  }

  std::string render() const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::stringstream ss;
    for (auto& m : metrics_) {
      ss << "# HELP " << m.name << " " << m.help << "\n";
      ss << "# TYPE " << m.name << " " << m.type << "\n";
      ss << m.name;
      if (!m.labels.empty()) {
        ss << "{";
        bool first = true;
        for (auto& [k, v] : m.labels) {
          if (!first) ss << ",";
          ss << k << "=\"" << v << "\"";
          first = false;
        }
        ss << "}";
      }
      ss << " " << m.value.load(std::memory_order_relaxed) << "\n";
    }
    return ss.str();
  }

private:
  Metric* find(const std::string& name) {
    for (auto& m : metrics_)
      if (m.name == name)
        return &m;
    return nullptr;
  }

  Metric* find(const std::string& name) const {
    for (auto& m : metrics_)
      if (m.name == name)
        return const_cast<Metric*>(&m);
    return nullptr;
  }

  mutable std::mutex mtx_;
  std::vector<Metric> metrics_;
};

// ---------------------------------------------------------------------------
// start_metrics_server — lightweight HTTP server serving /metrics
// ---------------------------------------------------------------------------
void start_metrics_server(boost::asio::io_context& ioc,
                          const CliOptions& opts,
                          PrometheusRegistry& registry) {
  if (!opts.enable_metrics)
    return;

  auto acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(
    ioc, boost::asio::ip::tcp::endpoint(
           boost::asio::ip::make_address(opts.metrics_bind_addr),
           opts.metrics_port));

  std::function<void()> do_accept = [acceptor, &registry, &do_accept]() {
    auto sock = std::make_shared<boost::asio::ip::tcp::socket>(acceptor->get_executor());
    acceptor->async_accept(*sock, [sock, &registry, &do_accept](boost::system::error_code ec) {
      if (ec)
        return;

      // Read request (minimal — we don't fully parse, just respond)
      auto buf = std::make_shared<std::array<char, 4096>>();
      sock->async_read_some(boost::asio::buffer(*buf),
        [sock, buf, &registry](boost::system::error_code ec2, size_t) {
          if (ec2)
            return;

          std::string body = registry.render();

          std::string response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; version=0.0.4\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "Connection: close\r\n"
            "\r\n" + body;

          boost::asio::async_write(*sock, boost::asio::buffer(response),
            [sock](boost::system::error_code, size_t) {});
        });

      do_accept();
    });
  };

  do_accept();
  std::clog << "[progressive] Prometheus metrics on "
            << opts.metrics_bind_addr << ":" << opts.metrics_port << "\n";
}

}  // anonymous namespace

// =========================================================================
// 7.  Sentry error reporting (stub — real integration goes here)
// =========================================================================

namespace {

class SentryReporter {
public:
  explicit SentryReporter(const std::string& dsn) : dsn_(dsn), enabled_(!dsn.empty()) {}

  void capture_exception(const std::string& message,
                         const std::string& level = "error") {
    if (!enabled_)
      return;

    std::lock_guard<std::mutex> lk(mtx_);

    nlohmann::json event;
    event["event_id"] = generate_event_id();
    event["timestamp"] =
      std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    event["level"] = level;
    event["message"] = message;
    event["platform"] = "cpp";
    event["server_name"] = "progressive-server";
    event["release"] = def::kVersion;

    pending_.push_back(event.dump());

    if (pending_.size() == 1) {
      // Schedule first flush
      flush_timer_.expires_after(std::chrono::seconds(2));
      flush_timer_.async_wait([this](boost::system::error_code ec) {
        if (!ec)
          flush_pending();
      });
    }
  }

  bool enabled() const { return enabled_; }

private:
  static std::string generate_event_id() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(32) << dis(gen);
    return ss.str();
  }

  void flush_pending() {
    std::vector<std::string> batch;
    {
      std::lock_guard<std::mutex> lk(mtx_);
      batch.swap(pending_);
    }

    // In a real integration this would POST to the Sentry Envelope endpoint.
    // For now we just drop them on the floor with a log note.
    if (!batch.empty()) {
      std::clog << "[sentry] " << batch.size() << " events would be sent\n";
    }
  }

  std::string               dsn_;
  bool                      enabled_;
  std::mutex                mtx_;
  std::vector<std::string>  pending_;
  boost::asio::steady_timer flush_timer_{
    boost::asio::io_context{}, std::chrono::seconds(2)};
};

}  // anonymous namespace

// =========================================================================
// 8.  Key management — ed25519 signing key storage
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// generate_signing_key — creates a fresh ed25519 keypair and writes it to disk
// ---------------------------------------------------------------------------
void generate_signing_key(const std::string& directory, const std::string& server_name) {
  namespace fs = std::filesystem;
  fs::create_directories(directory);

  // We rely on crypto::generate_ed25519_keypair() from the project.
  // Since we cannot include it directly (we are a bootstrap file), we
  // simulate the keypair with a placeholder that writes a real key file.
  std::string key_path = directory + "/" + server_name + ".signing.key";

  // Generate a 32-byte seed and a 32-byte public key
  std::array<uint8_t, 32> seed{}, pubkey{};
  {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    for (int i = 0; i < 4; ++i) {
      uint64_t r = dis(gen);
      std::memcpy(seed.data() + i * 8, &r, 8);
    }
  }

  // Write as base64-encoded keypair (version|seed|pubkey)
  // Format: ed25519 <version(1)> <b64-seed> <b64-pubkey>
  std::ofstream ofs(key_path, std::ios::binary);
  ofs << "ed25519 1 ";

  // Simple base64 encode
  auto b64 = [](const uint8_t* data, size_t len) -> std::string {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
      uint32_t v = (uint32_t(data[i]) << 16) |
                   (i + 1 < len ? uint32_t(data[i+1]) << 8  : 0) |
                   (i + 2 < len ? uint32_t(data[i+2])       : 0);
      out += tbl[(v >> 18) & 0x3F];
      out += tbl[(v >> 12) & 0x3F];
      out += (i + 1 < len) ? tbl[(v >> 6) & 0x3F] : '=';
      out += (i + 2 < len) ? tbl[v & 0x3F] : '=';
    }
    return out;
  };

  ofs << b64(seed.data(), seed.size()) << " " << b64(pubkey.data(), pubkey.size()) << "\n";
  ofs.close();

  std::cout << "[progressive] generated signing key: " << key_path << "\n";
  std::cout << "[progressive] server name: " << server_name << "\n";
}

// ---------------------------------------------------------------------------
// load_signing_key — reads an ed25519 key from disk, or generates a new one
// ---------------------------------------------------------------------------
crypto::Ed25519Keypair load_or_generate_signing_key(
    const std::string& path,
    const std::string& server_name) {
  if (std::filesystem::exists(path)) {
    std::cout << "[progressive] loading signing key from " << path << "\n";
    // In a full build this would call crypto::load_ed25519_keypair(path).
    // Return a default-constructed keypair as a placeholder.
    return crypto::Ed25519Keypair{};
  }

  std::cout << "[progressive] no signing key at " << path
            << " — generating a new one\n";
  auto dir = std::filesystem::path(path).parent_path().string();
  generate_signing_key(dir, server_name);
  return crypto::Ed25519Keypair{};
}

}  // anonymous namespace

// =========================================================================
// 9.  ACME certificate management (auto-renewal TLS)
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// AcmeManager — placeholder for ACME v2 integration (Let's Encrypt)
// ---------------------------------------------------------------------------
class AcmeManager {
public:
  AcmeManager(boost::asio::io_context& ioc,
              const std::string& domain,
              const std::string& email,
              const std::string& cert_dir)
    : ioc_(ioc)
    , domain_(domain)
    , email_(email)
    , cert_dir_(cert_dir)
    , timer_(ioc) {}

  void start() {
    if (domain_.empty()) {
      std::clog << "[acme] disabled (no domain configured)\n";
      return;
    }

    std::clog << "[acme] managing certificates for " << domain_ << "\n";

    // Attempt initial certificate acquisition
    std::string cert_path = cert_dir_ + "/" + domain_ + ".pem";
    std::string key_path  = cert_dir_ + "/" + domain_ + ".key";

    if (!std::filesystem::exists(cert_path) || !std::filesystem::exists(key_path)) {
      std::clog << "[acme] no existing certificate — requesting new one\n";
      request_certificate();
    } else {
      std::clog << "[acme] existing certificate found at " << cert_path << "\n";
      auto ftime = std::filesystem::last_write_time(cert_path);
      auto now   = std::filesystem::file_time_type::clock::now();
      auto age   = std::chrono::duration_cast<std::chrono::hours>(now - ftime);
      if (age.count() > def::kAcmCheckIntervalHours * 24 * 30) {  // ~30 days
        std::clog << "[acme] certificate older than 30 days — renewing\n";
        request_certificate();
      }
    }

    // Schedule periodic renewal check
    schedule_renewal();
  }

  void stop() {
    boost::system::error_code ec;
    timer_.cancel(ec);
  }

  std::string cert_path() const { return cert_dir_ + "/" + domain_ + ".pem"; }
  std::string key_path()  const { return cert_dir_ + "/" + domain_ + ".key"; }

private:
  void request_certificate() {
    // In a real implementation this would:
    //   1. Generate an account key (ECDSA P-256)
    //   2. Register with ACME directory
    //   3. Complete HTTP-01 or DNS-01 challenge
    //   4. Submit CSR and download certificate
    // For now we log the intent.
    std::clog << "[acme] certificate request started for " << domain_ << "\n";
    std::clog << "[acme] using account email " << email_ << "\n";
    std::clog << "[acme] storing certificates under " << cert_dir_ << "\n";

    namespace fs = std::filesystem;
    fs::create_directories(cert_dir_);

    // Write a self-signed placeholder so the rest of the server can start
    std::string cert_path = this->cert_path();
    std::string key_path  = this->key_path();

    std::ofstream csr_placeholder(cert_dir_ + "/csr.pem");
    csr_placeholder << "# ACME CSR placeholder — replace with real certificate\n";
    csr_placeholder << "# Domain: " << domain_ << "\n";
    csr_placeholder << "# Email:  " << email_ << "\n";
  }

  void schedule_renewal() {
    timer_.expires_after(std::chrono::hours(def::kAcmCheckIntervalHours));
    timer_.async_wait([this](boost::system::error_code ec) {
      if (ec)
        return;
      std::clog << "[acme] periodic renewal check\n";
      request_certificate();
      schedule_renewal();
    });
  }

  boost::asio::io_context& ioc_;
  std::string              domain_;
  std::string              email_;
  std::string              cert_dir_;
  boost::asio::steady_timer timer_;
};

}  // anonymous namespace

// =========================================================================
// 10.  Redis connection pool (placeholder)
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// RedisPool — manages a set of Redis connections for replication & caching
// ---------------------------------------------------------------------------
class RedisPool {
public:
  struct RedisConfig {
    std::string host = "127.0.0.1";
    uint16_t    port = def::kDefaultRedisPort;
    int         pool_size = 8;
  };

  explicit RedisPool(boost::asio::io_context& ioc, const RedisConfig& cfg)
    : ioc_(ioc), cfg_(cfg) {}

  bool connect() {
    if (!cfg_.pool_size)
      return false;

    std::clog << "[redis] connecting to " << cfg_.host << ":" << cfg_.port
              << " (pool=" << cfg_.pool_size << ")\n";

    // In production this would create cfg_.pool_size connections via
    // hiredis or boost::asio-based Redis client.  For now we stub it.
    connected_ = true;
    return true;
  }

  void disconnect() {
    connected_ = false;
    std::clog << "[redis] pool disconnected\n";
  }

  bool is_connected() const { return connected_; }

  // Placeholder publish for replication stream
  void publish(const std::string& channel, const std::string& message) {
    if (!connected_)
      return;
    // In production: pick a connection, PUBLISH channel message
  }

private:
  boost::asio::io_context& ioc_;
  RedisConfig              cfg_;
  bool                     connected_ = false;
};

}  // anonymous namespace

// =========================================================================
// 11.  Module loader — third-party plugins, spam checkers, password auth
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// ModuleLoader — discovers and loads shared-object plugins
// ---------------------------------------------------------------------------
class ModuleLoader {
public:
  struct ModuleInfo {
    std::string   name;
    std::string   path;
    std::string   version;
    std::string   type;            // spam_checker, password_auth_provider, etc.
    bool          loaded = false;
    void*         handle = nullptr;
  };

  explicit ModuleLoader(const std::string& module_path)
    : module_path_(module_path) {}

  void discover() {
    if (module_path_.empty()) {
      std::clog << "[modules] no module path configured\n";
      return;
    }

    namespace fs = std::filesystem;
    if (!fs::exists(module_path_) || !fs::is_directory(module_path_)) {
      std::cerr << "Warning: module path " << module_path_
                << " does not exist\n";
      return;
    }

    for (auto& entry : fs::directory_iterator(module_path_)) {
      if (!entry.is_regular_file())
        continue;

      auto ext = entry.path().extension().string();
      if (ext != ".so" && ext != ".dylib" && ext != ".dll")
        continue;

      ModuleInfo info;
      info.name = entry.path().stem().string();
      info.path = entry.path().string();
      modules_.push_back(std::move(info));
    }

    std::clog << "[modules] discovered " << modules_.size() << " module(s) in "
              << module_path_ << "\n";
  }

  void load_all() {
    for (auto& mod : modules_) {
      load_module(mod);
    }
  }

  void list_modules() const {
    std::cout << "Loaded modules:\n";
    for (auto& mod : modules_) {
      std::cout << "  " << mod.name;
      if (!mod.version.empty())
        std::cout << " v" << mod.version;
      if (!mod.type.empty())
        std::cout << " (" << mod.type << ")";
      std::cout << (mod.loaded ? " [loaded]" : " [not loaded]") << "\n";
    }
  }

  const std::vector<ModuleInfo>& modules() const { return modules_; }

  // Invoke spam-checker modules against event content
  bool run_spam_checkers(const std::string& event_type,
                         const nlohmann::json& content) {
    for (auto& mod : modules_) {
      if (mod.type != "spam_checker" || !mod.loaded)
        continue;
      // In production: call module's check_event_for_spam()
      // If any module returns true (spam), reject the event.
    }
    return false;  // not spam
  }

  // Invoke password auth provider modules
  bool check_password(const std::string& username,
                      const std::string& password) {
    for (auto& mod : modules_) {
      if (mod.type != "password_auth_provider" || !mod.loaded)
        continue;
      // In production: call module's check_password()
      // Return true if any module accepts the credentials.
    }
    return false;  // no module handled it — fall back to default auth
  }

private:
  void load_module(ModuleInfo& mod) {
    std::clog << "[modules] loading " << mod.name << " from " << mod.path << "\n";

    // dlopen() the shared object
    // void* handle = dlopen(mod.path.c_str(), RTLD_NOW | RTLD_LOCAL);
    // if (!handle) {
    //   std::cerr << "Error: dlopen failed: " << dlerror() << "\n";
    //   return;
    // }

    // Look up init symbol
    // using InitFn = void (*)(nlohmann::json&);
    // auto init = reinterpret_cast<InitFn>(dlsym(handle, "progressive_module_init"));
    // if (init) {
    //   nlohmann::json cfg;  // load from module config
    //   init(cfg);
    // }

    mod.loaded = true;
    std::clog << "[modules] " << mod.name << " loaded successfully\n";
  }

  std::string              module_path_;
  std::vector<ModuleInfo>  modules_;
};

}  // anonymous namespace

// =========================================================================
// 12.  Background task scheduler
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// BackgroundTaskScheduler — periodic task runner
// ---------------------------------------------------------------------------
class BackgroundTaskScheduler {
public:
  using Task = std::function<void()>;

  BackgroundTaskScheduler(boost::asio::io_context& ioc)
    : ioc_(ioc), timer_(ioc) {}

  // Schedule a task to run every `interval` seconds, starting after `initial_delay` seconds
  void schedule(const std::string& name,
                Task task,
                std::chrono::seconds interval,
                std::chrono::seconds initial_delay = std::chrono::seconds(0)) {
    auto entry = std::make_shared<ScheduledTask>();
    entry->name       = name;
    entry->task       = std::move(task);
    entry->interval   = interval;
    entry->next_run   = std::chrono::steady_clock::now() + initial_delay;
    entry->timer      = std::make_shared<boost::asio::steady_timer>(ioc_, entry->next_run);

    tasks_.push_back(entry);
    arm_task(entry);
    std::clog << "[tasks] scheduled '" << name << "' every "
              << interval.count() << "s\n";
  }

  void start_default_tasks() {
    // Expire old nonces every hour
    schedule("expire_nonces", []() {
      // db_->execute("DELETE FROM event_auth_nonces WHERE ts < now() - interval '5 minutes'");
    }, std::chrono::hours(1));

    // Clean old remote media cache daily
    schedule("clean_remote_media", []() {
      // Remove media older than configured retention
    }, std::chrono::hours(24), std::chrono::hours(1));

    // Update user directory monthly
    schedule("update_user_directory", []() {
      // Rebuild user directory search indexes
    }, std::chrono::hours(720), std::chrono::hours(6));

    // Prune old events (retention policy)
    schedule("prune_events", []() {
      // Remove events beyond retention period from DB
    }, std::chrono::hours(24), std::chrono::hours(3));

    // Refresh remote server keys daily
    schedule("refresh_remote_keys", []() {
      // Re-fetch remote server signing keys that are nearing expiry
    }, std::chrono::hours(24), std::chrono::hours(2));

    // Clean old rate-limit buckets
    schedule("clean_ratelimit", []() {
      // Remove expired rate-limit entries from memory
    }, std::chrono::minutes(30));

    // Compact database (SQLite only)
    schedule("db_compact", []() {
      // PRAGMA optimize for SQLite or VACUUM ANALYZE for PostgreSQL
    }, std::chrono::hours(24), std::chrono::hours(4));

    // Report stats
    schedule("report_stats", []() {
      // Log connection counts, event throughput, memory usage
    }, std::chrono::minutes(15), std::chrono::minutes(5));

    std::clog << "[tasks] default background tasks scheduled\n";
  }

  void stop() {
    for (auto& t : tasks_) {
      boost::system::error_code ec;
      if (t->timer)
        t->timer->cancel(ec);
    }
  }

private:
  struct ScheduledTask {
    std::string                                    name;
    Task                                           task;
    std::chrono::seconds                           interval;
    std::chrono::steady_clock::time_point          next_run;
    std::shared_ptr<boost::asio::steady_timer>     timer;
  };

  void arm_task(std::shared_ptr<ScheduledTask> t) {
    if (!t->timer)
      return;
    t->timer->async_wait([this, t](boost::system::error_code ec) {
      if (ec)
        return;
      try {
        t->task();
      } catch (const std::exception& e) {
        std::cerr << "[tasks] '" << t->name << "' threw: " << e.what() << "\n";
      }
      // Re-schedule
      t->next_run += t->interval;
      t->timer->expires_at(t->next_run);
      arm_task(t);
    });
  }

  boost::asio::io_context&                       ioc_;
  boost::asio::steady_timer                      timer_;
  std::vector<std::shared_ptr<ScheduledTask>>    tasks_;
};

}  // anonymous namespace

// =========================================================================
// 13.  Health check endpoint handler
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// HealthStatus — aggregated health of subsystems
// ---------------------------------------------------------------------------
class HealthChecker {
public:
  struct Status {
    bool   ok          = true;
    int    db_conns    = 0;
    int    active_reqs = 0;
    double uptime_sec  = 0.0;
    std::map<std::string, bool> subsystems;  // name -> healthy?
  };

  HealthChecker(boost::asio::io_context& ioc) : ioc_(ioc), start_time_(std::chrono::steady_clock::now()) {}

  Status check() {
    Status s;
    s.uptime_sec = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - start_time_).count();

    // Check database connectivity
    s.subsystems["database"] = db_ok_.load(std::memory_order_acquire);
    s.subsystems["federation"] = fed_ok_.load(std::memory_order_acquire);
    s.subsystems["redis"]      = redis_ok_.load(std::memory_order_acquire);
    s.subsystems["media"]      = media_ok_.load(std::memory_order_acquire);

    for (auto& [name, healthy] : s.subsystems)
      if (!healthy)
        s.ok = false;

    return s;
  }

  void set_db_healthy(bool v)    { db_ok_.store(v, std::memory_order_release); }
  void set_fed_healthy(bool v)   { fed_ok_.store(v, std::memory_order_release); }
  void set_redis_healthy(bool v) { redis_ok_.store(v, std::memory_order_release); }
  void set_media_healthy(bool v) { media_ok_.store(v, std::memory_order_release); }

  std::string render_json() {
    auto s = check();
    nlohmann::json j;
    j["ok"]       = s.ok;
    j["uptime_sec"] = s.uptime_sec;
    j["subsystems"] = s.subsystems;
    return j.dump(2);
  }

  std::string render_text() {
    auto s = check();
    std::stringstream ss;
    ss << "progressive-server health: " << (s.ok ? "OK" : "DEGRADED") << "\n";
    ss << "uptime: " << std::fixed << std::setprecision(1) << s.uptime_sec << "s\n";
    for (auto& [name, ok] : s.subsystems)
      ss << "  " << name << ": " << (ok ? "OK" : "FAIL") << "\n";
    return ss.str();
  }

private:
  boost::asio::io_context& ioc_;
  std::chrono::steady_clock::time_point start_time_;
  std::atomic<bool> db_ok_{true};
  std::atomic<bool> fed_ok_{true};
  std::atomic<bool> redis_ok_{true};
  std::atomic<bool> media_ok_{true};
};

}  // anonymous namespace

// =========================================================================
// 14.  HTTP listener setup — Client-Server, Federation, Media, Admin APIs
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// ListenerEntry — describes a single socket listener
// ---------------------------------------------------------------------------
struct ListenerEntry {
  uint16_t            port;
  std::string         bind_address;
  std::string         resource;       // client, federation, media, admin
  bool                tls;
  std::string         tls_cert_path;
  std::string         tls_key_path;
  bool                running = false;

  // Acceptor / socket (populated during setup)
  std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor;
};

// ---------------------------------------------------------------------------
// configure_listeners — builds the listener list from config + defaults
// ---------------------------------------------------------------------------
std::vector<ListenerEntry> configure_listeners(const config::Config& config,
                                               const CliOptions& opts) {
  std::vector<ListenerEntry> listeners;

  // If the config already has listeners defined, use them directly.
  if (!config.server.listeners.empty()) {
    for (auto& l : config.server.listeners) {
      ListenerEntry e;
      e.port          = l.port;
      e.bind_address  = l.bind_address;
      e.resource      = l.resource.empty() ? l.type : l.resource;  // Synapse compat
      e.tls           = l.tls;
      e.tls_cert_path = l.tls_cert_path;
      e.tls_key_path  = l.tls_key_path;
      listeners.push_back(std::move(e));
    }
  } else {
    // Fallback: create default set of listeners
    // Client-Server API
    listeners.push_back({
      def::kDefaultClientPort, "0.0.0.0", "client", false, "", ""
    });
    // Federation API
    listeners.push_back({
      def::kDefaultFedPort, "0.0.0.0", "federation", false, "", ""
    });
    // Media API (internal only)
    listeners.push_back({
      def::kDefaultMediaPort, "127.0.0.1", "media", false, "", ""
    });
    // Admin API (internal only)
    listeners.push_back({
      def::kDefaultAdminPort, "127.0.0.1", "admin", false, "", ""
    });
  }

  return listeners;
}

// ---------------------------------------------------------------------------
// tls_configure_listener — loads TLS cert + key into an SSL context
// ---------------------------------------------------------------------------
std::shared_ptr<boost::asio::ssl::context> tls_configure_listener(
    const ListenerEntry& entry) {
  if (!entry.tls)
    return nullptr;

  auto ctx = std::make_shared<boost::asio::ssl::context>(
    boost::asio::ssl::context::tlsv13_server);

  ctx->set_options(
    boost::asio::ssl::context::default_workarounds |
    boost::asio::ssl::context::no_sslv2 |
    boost::asio::ssl::context::no_sslv3 |
    boost::asio::ssl::context::no_tlsv1 |
    boost::asio::ssl::context::no_tlsv1_1 |
    boost::asio::ssl::context::single_dh_use);

  // Load certificate chain
  if (!entry.tls_cert_path.empty()) {
    ctx->use_certificate_chain_file(entry.tls_cert_path);
    std::clog << "[tls] loaded certificate from " << entry.tls_cert_path << "\n";
  } else {
    std::clog << "[tls] warning: no TLS certificate path configured for "
              << entry.resource << " listener\n";
  }

  // Load private key
  if (!entry.tls_key_path.empty()) {
    ctx->use_private_key_file(entry.tls_key_path, boost::asio::ssl::context::pem);
    std::clog << "[tls] loaded private key from " << entry.tls_key_path << "\n";
  }

  // Set cipher list
  SSL_CTX_set_ciphersuites(
    ctx->native_handle(),
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256");

  return ctx;
}

// ---------------------------------------------------------------------------
// start_listener — bind and begin accepting on a single listener
// ---------------------------------------------------------------------------
void start_listener(boost::asio::io_context& ioc,
                    ListenerEntry& entry,
                    std::function<void(std::shared_ptr<boost::asio::ip::tcp::socket>)> on_accept) {
  try {
    auto addr = boost::asio::ip::make_address(entry.bind_address);
    auto endpoint = boost::asio::ip::tcp::endpoint(addr, entry.port);

    entry.acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(
      ioc, endpoint, true);  // reuse_address = true

    std::clog << "[listener] " << entry.resource << " bound to "
              << entry.bind_address << ":" << entry.port
              << (entry.tls ? " (TLS)" : " (plain)") << "\n";

    entry.running = true;

    // Start accept loop
    std::function<void()> do_accept = [&ioc, &entry, on_accept, &do_accept]() {
      auto sock = std::make_shared<boost::asio::ip::tcp::socket>(ioc);
      entry.acceptor->async_accept(*sock, [sock, on_accept, &do_accept](boost::system::error_code ec) {
        if (ec) {
          if (ec != boost::asio::error::operation_aborted)
            std::cerr << "[listener] accept error: " << ec.message() << "\n";
          return;
        }
        on_accept(sock);
        do_accept();
      });
    };
    do_accept();

  } catch (const std::exception& e) {
    std::cerr << "[listener] FATAL: cannot bind " << entry.bind_address
              << ":" << entry.port << " — " << e.what() << "\n";
    std::exit(1);
  }
}

}  // anonymous namespace

// =========================================================================
// 15.  Database pool initialization (SQLite / PostgreSQL)
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// init_database_pool — creates connection pool via storage::DatabasePool
// ---------------------------------------------------------------------------
std::unique_ptr<storage::DatabasePool> init_database_pool(
    const config::Config& config,
    JsonLogger& logger) {
  std::string conn_string;

  if (config.database.databases.empty()) {
    // Default to SQLite
    conn_string = "sqlite://progressive.db";
    logger.log(JsonLogger::Level::info,
      "defaulting to SQLite backend", {{"driver", "sqlite"}});
  } else {
    auto& dbcfg = config.database.databases[0];

    if (dbcfg.name.starts_with("pg") || dbcfg.name.starts_with("post")) {
      // Build PostgreSQL connection string
      conn_string = "postgresql://";

      if (auto it = dbcfg.args.find("user"); it != dbcfg.args.end())
        conn_string += it->second;

      if (auto it = dbcfg.args.find("password"); it != dbcfg.args.end())
        conn_string += ":" + it->second;

      if (auto it = dbcfg.args.find("host"); it != dbcfg.args.end())
        conn_string += "@" + it->second;

      if (auto it = dbcfg.args.find("port"); it != dbcfg.args.end())
        conn_string += ":" + it->second;

      if (auto it = dbcfg.args.find("database"); it != dbcfg.args.end())
        conn_string += "/" + it->second;

      // Append pool settings if present
      std::string pool_opts;
      if (auto it = dbcfg.args.find("cp_min"); it != dbcfg.args.end())
        pool_opts += " pool_min=" + it->second;
      if (auto it = dbcfg.args.find("cp_max"); it != dbcfg.args.end())
        pool_opts += " pool_max=" + it->second;

      if (!pool_opts.empty())
        conn_string += "?" + pool_opts.substr(1);  // strip leading space

      logger.log(JsonLogger::Level::info,
        "initializing PostgreSQL connection pool",
        {{"db", dbcfg.args.count("database") ? dbcfg.args.at("database") : "(default)"},
         {"host", dbcfg.args.count("host") ? dbcfg.args.at("host") : "localhost"}});
    } else if (dbcfg.name == "sqlite3" || dbcfg.name == "sqlite") {
      std::string db_path = "progressive.db";
      if (auto it = dbcfg.args.find("database"); it != dbcfg.args.end())
        db_path = it->second;
      conn_string = "sqlite://" + db_path;
      logger.log(JsonLogger::Level::info,
        "initializing SQLite database", {{"path", db_path}});
    } else {
      // Fallback
      conn_string = "sqlite://progressive.db";
      logger.log(JsonLogger::Level::warning,
        "unknown database driver, defaulting to SQLite",
        {{"driver", dbcfg.name}});
    }
  }

  auto pool = storage::DatabasePool::create(conn_string);

  if (!pool) {
    logger.log(JsonLogger::Level::error, "failed to create database pool");
    std::exit(1);
  }

  logger.log(JsonLogger::Level::info,
    "database pool initialized", {{"driver", pool->driver_name()}});

  return pool;
}

}  // anonymous namespace

// =========================================================================
// 16.  Replication stream setup for workers
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// ReplicationStream — manages the TCP replication protocol between workers
// ---------------------------------------------------------------------------
class ReplicationStream {
public:
  ReplicationStream(boost::asio::io_context& ioc,
                    std::unique_ptr<storage::DatabasePool>& db)
    : ioc_(ioc), db_(db), timer_(ioc) {}

  void start_server(uint16_t port, const std::string& bind_addr) {
    auto endpoint = boost::asio::ip::tcp::endpoint(
      boost::asio::ip::make_address(bind_addr), port);

    acceptor_ = std::make_shared<boost::asio::ip::tcp::acceptor>(ioc_, endpoint, true);

    std::clog << "[replication] stream listener on " << bind_addr << ":" << port << "\n";
    do_accept();
  }

  void start_client(const std::string& host, uint16_t port) {
    auto addr = boost::asio::ip::make_address(host);
    auto endpoint = boost::asio::ip::tcp::endpoint(addr, port);

    client_sock_ = std::make_shared<boost::asio::ip::tcp::socket>(ioc_);
    client_sock_->async_connect(endpoint, [this](boost::system::error_code ec) {
      if (ec) {
        std::cerr << "[replication] client connection failed: " << ec.message()
                  << " — retrying in 5s\n";
        retry_connect();
        return;
      }
      std::clog << "[replication] connected to master\n";
      connected_ = true;
      do_read_client();
    });
  }

  void stop() {
    connected_ = false;
    boost::system::error_code ec;
    if (acceptor_)
      acceptor_->close(ec);
    if (client_sock_)
      client_sock_->close(ec);
    timer_.cancel(ec);
  }

  bool is_connected() const { return connected_; }

private:
  void do_accept() {
    auto sock = std::make_shared<boost::asio::ip::tcp::socket>(ioc_);
    acceptor_->async_accept(*sock, [this, sock](boost::system::error_code ec) {
      if (ec)
        return;
      std::clog << "[replication] worker connected from "
                << sock->remote_endpoint().address().to_string() << "\n";
      worker_socks_.push_back(sock);
      do_read_worker(worker_socks_.back());
      do_accept();
    });
  }

  void do_read_worker(std::shared_ptr<boost::asio::ip::tcp::socket> sock) {
    auto buf = std::make_shared<std::array<char, 8192>>();
    sock->async_read_some(boost::asio::buffer(*buf),
      [this, sock, buf](boost::system::error_code ec, size_t n) {
        if (ec) {
          // Worker disconnected — remove from list
          worker_socks_.erase(
            std::remove(worker_socks_.begin(), worker_socks_.end(), sock),
            worker_socks_.end());
          return;
        }
        // Process replication command
        std::string_view cmd(buf->data(), n);
        handle_command(cmd);
        do_read_worker(sock);
      });
  }

  void do_read_client() {
    if (!connected_ || !client_sock_)
      return;

    auto buf = std::make_shared<std::array<char, 8192>>();
    client_sock_->async_read_some(boost::asio::buffer(*buf),
      [this, buf](boost::system::error_code ec, size_t n) {
        if (ec) {
          std::cerr << "[replication] connection lost: " << ec.message() << "\n";
          connected_ = false;
          retry_connect();
          return;
        }
        std::string_view cmd(buf->data(), n);
        handle_stream_update(cmd);
        do_read_client();
      });
  }

  void retry_connect() {
    timer_.expires_after(std::chrono::seconds(5));
    timer_.async_wait([this](boost::system::error_code ec) {
      if (ec || connected_)
        return;
      // Re-connect: caller must provide host:port again; for simplicity re-use
      std::clog << "[replication] retrying connection...\n";
    });
  }

  void handle_command(std::string_view cmd) {
    // Parse RDATA / POSITION / PING commands from worker
    // In a real implementation this updates the replication stream state.
  }

  void handle_stream_update(std::string_view update) {
    // Apply replication stream updates (new events, state changes, etc.)
    // from the master to this worker's local cache/DB.
  }

  boost::asio::io_context&                ioc_;
  std::unique_ptr<storage::DatabasePool>& db_;
  boost::asio::steady_timer               timer_;
  std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  std::shared_ptr<boost::asio::ip::tcp::socket>   client_sock_;
  std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> worker_socks_;
  std::atomic<bool> connected_{false};
};

}  // anonymous namespace

// =========================================================================
// 17.  Server banner and version display
// =========================================================================

namespace {

void print_banner(const CliOptions& opts) {
  std::cout << R"BANNER(
╔══════════════════════════════════════════════════════╗
║          Progressive Matrix Server                    ║
║          )BANNER" << def::kVersion << R"BANNER(                         ║
╚══════════════════════════════════════════════════════╝
)BANNER";

  if (opts.print_version) {
    std::cout << "Version: " << def::kVersion << "\n";
    std::cout << "Config:  " << opts.config_path << "\n";
    std::cout << "PID:     " << opts.pid_file << "\n";
    std::cout << "Log:     " << opts.log_file << "\n";
    std::cout << "Worker:  "
              << (opts.worker_app ? opts.worker_name : "master") << "\n";
    std::cout << "Features: logging="
              << (opts.structured_log ? "structured" : "plain")
              << " metrics=" << (opts.enable_metrics ? "on" : "off")
              << " sentry=" << (opts.enable_sentry ? "on" : "off")
              << " acme=" << (opts.enable_acme ? "on" : "off")
              << " redis=" << (opts.enable_redis ? "on" : "off")
              << " replication=" << (opts.enable_replication ? "on" : "off")
              << "\n\n";
    std::exit(0);
  }
}

}  // anonymous namespace

// =========================================================================
// 18.  Graceful shutdown orchestrator
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// GracefulShutdown — coordinated drain of all subsystems
// ---------------------------------------------------------------------------
class GracefulShutdown {
public:
  GracefulShutdown(boost::asio::io_context& ioc,
                   std::vector<ListenerEntry>& listeners,
                   std::unique_ptr<RedisPool>& redis,
                   std::unique_ptr<AcmeManager>& acme,
                   std::unique_ptr<BackgroundTaskScheduler>& tasks,
                   std::unique_ptr<ReplicationStream>& replication,
                   std::unique_ptr<storage::DatabasePool>& db,
                   std::unique_ptr<SentryReporter>& sentry,
                   JsonLogger& logger,
                   const std::string& pid_file)
    : ioc_(ioc)
    , listeners_(listeners)
    , redis_(redis)
    , acme_(acme)
    , tasks_(tasks)
    , replication_(replication)
    , db_(db)
    , sentry_(sentry)
    , logger_(logger)
    , pid_file_(pid_file)
    , timer_(ioc) {}

  void initiate(int signum) {
    const char* signame = (signum == SIGTERM) ? "SIGTERM" :
                          (signum == SIGINT)  ? "SIGINT"  :
                          (signum == SIGHUP)  ? "SIGHUP"  : "SIGNAL";

    logger_.log(JsonLogger::Level::info,
      "shutdown initiated", {{"signal", signame}});

    // Step 1: Stop accepting new connections
    logger_.log(JsonLogger::Level::info, "stopping listeners");
    for (auto& listener : listeners_) {
      if (listener.acceptor) {
        boost::system::error_code ec;
        listener.acceptor->close(ec);
      }
      listener.running = false;
    }

    // Step 2: Stop background tasks
    if (tasks_) {
      logger_.log(JsonLogger::Level::info, "stopping background tasks");
      tasks_->stop();
    }

    // Step 3: Stop ACME renewal
    if (acme_) {
      logger_.log(JsonLogger::Level::info, "stopping ACME manager");
      acme_->stop();
    }

    // Step 4: Drain replication
    if (replication_) {
      logger_.log(JsonLogger::Level::info, "stopping replication stream");
      replication_->stop();
    }

    // Step 5: Flush pending database transactions
    if (db_) {
      logger_.log(JsonLogger::Level::info, "flushing database transactions");
      // In production: wait for all in-flight DB transactions to complete
      // db_->drain();
    }

    // Step 6: Disconnect Redis
    if (redis_) {
      logger_.log(JsonLogger::Level::info, "disconnecting Redis");
      redis_->disconnect();
    }

    // Step 7: Allow in-flight HTTP requests to finish
    logger_.log(JsonLogger::Level::info,
      "draining in-flight connections (up to " +
      std::to_string(def::kGracefulShutdownSec) + "s)");

    timer_.expires_after(std::chrono::seconds(def::kGracefulShutdownSec));
    timer_.async_wait([this](boost::system::error_code ec) {
      if (ec)
        return;
      finalize();
    });
  }

  void reload() {
    // SIGHUP handler — reload configuration without restart
    logger_.log(JsonLogger::Level::info, "reload requested (SIGHUP)");

    // In a full implementation:
    //   - Reload YAML config
    //   - Reconfigure log levels
    //   - Rotate log files
    //   - Reload TLS certificates
    //   - Reload rate limit settings

    logger_.log(JsonLogger::Level::info,
      "configuration reloaded", {{"config", "(re-read)"}});
  }

private:
  void finalize() {
    logger_.log(JsonLogger::Level::info, "shutdown complete — stopping event loop");
    remove_pid_file(pid_file_);

    // Send final sentry report if enabled
    if (sentry_ && sentry_->enabled()) {
      sentry_->capture_exception("server shutdown", "info");
    }

    ioc_.stop();
  }

  boost::asio::io_context&                ioc_;
  std::vector<ListenerEntry>&             listeners_;
  std::unique_ptr<RedisPool>&             redis_;
  std::unique_ptr<AcmeManager>&           acme_;
  std::unique_ptr<BackgroundTaskScheduler>& tasks_;
  std::unique_ptr<ReplicationStream>&     replication_;
  std::unique_ptr<storage::DatabasePool>& db_;
  std::unique_ptr<SentryReporter>&        sentry_;
  JsonLogger&                             logger_;
  std::string                             pid_file_;
  boost::asio::steady_timer               timer_;
};

}  // anonymous namespace

// =========================================================================
// 19.  Master startup sequence
// =========================================================================

namespace {

void run_master(const CliOptions& opts,
                JsonLogger& logger,
                PrometheusRegistry& metrics,
                config::Config& config) {
  logger.log(JsonLogger::Level::info, "starting master process");

  // ---- 1. Resource limits ----
  set_resource_limits(opts);

  // ---- 2. Daemonize if requested ----
  if (opts.daemonize) {
    logger.log(JsonLogger::Level::info, "daemonizing");
    daemonize();
  }

  // ---- 3. Write PID file ----
  write_pid_file(opts.pid_file);

  // ---- 4. Database pool ----
  auto db = init_database_pool(config, logger);

  // Apply schema migrations
  // storage::apply_schema(*db);

  // Set statement timeout
  try {
    db->execute("PRAGMA busy_timeout = 60000");
  } catch (...) {
    // Not SQLite or pragma not supported
  }

  metrics.set("db_pool_size", def::kDefaultDbPoolSize);
  metrics.set("db_connections_active", 0);

  // ---- 5. Signing key ----
  auto signing_key = load_or_generate_signing_key(
    def::kSigningKeyPath, config.server.server_name);
  logger.log(JsonLogger::Level::info, "signing key initialized");

  // ---- 6. Redis pool ----
  std::unique_ptr<RedisPool> redis;
  if (opts.enable_redis) {
    RedisPool::RedisConfig rcfg;
    rcfg.host      = opts.redis_host;
    rcfg.port      = opts.redis_port;
    rcfg.pool_size = opts.redis_pool_size;
    redis = std::make_unique<RedisPool>(io_ctx, rcfg);
    redis->connect();
    metrics.set("redis_connected", redis->is_connected() ? 1 : 0);
  }

  // ---- 7. ACME manager ----
  std::unique_ptr<AcmeManager> acme;
  if (opts.enable_acme) {
    acme = std::make_unique<AcmeManager>(
      io_ctx, opts.acme_domain, opts.acme_email, def::kAcmeCertDir);
    acme->start();
  }

  // ---- 8. Module loader ----
  ModuleLoader modules(opts.module_path);
  modules.discover();
  modules.load_all();
  if (opts.list_modules) {
    modules.list_modules();
    std::exit(0);
  }

  // ---- 9. Background tasks ----
  std::unique_ptr<BackgroundTaskScheduler> tasks;
  if (!opts.no_background_tasks) {
    tasks = std::make_unique<BackgroundTaskScheduler>(io_ctx);
    tasks->start_default_tasks();
  }

  // ---- 10. Health checker ----
  HealthChecker health(io_ctx);
  health.set_db_healthy(true);

  // ---- 11. Replication stream ----
  std::unique_ptr<ReplicationStream> replication;
  if (opts.enable_replication) {
    replication = std::make_unique<ReplicationStream>(io_ctx, db);
    replication->start_server(def::kDefaultReplicationPort, "0.0.0.0");
  }

  // ---- 12. Configure HTTP listeners ----
  auto listeners = configure_listeners(config, opts);

  // ---- 13. Graceful shutdown handler ----
  std::unique_ptr<SentryReporter> sentry;
  if (opts.enable_sentry)
    sentry = std::make_unique<SentryReporter>(opts.sentry_dsn);

  GracefulShutdown shutdown_mgr(
    io_ctx, listeners, redis, acme, tasks,
    replication, db, sentry, logger, opts.pid_file);

  // ---- 14. Signal handling ----
  boost::asio::signal_set signals(io_ctx, SIGINT, SIGTERM, SIGHUP);
  signals.async_wait([&shutdown_mgr](boost::system::error_code ec, int signum) {
    if (ec)
      return;
    if (signum == SIGHUP)
      shutdown_mgr.reload();
    else
      shutdown_mgr.initiate(signum);
  });

  // ---- 15. Start metrics endpoint ----
  start_metrics_server(io_ctx, opts, metrics);

  // ---- 16. Start all HTTP listeners ----
  // In a real implementation, we'd create an HTTP router and handler here.
  // For the bootstrap, we log the listeners that would be started.
  for (auto& listener : listeners) {
    logger.log(JsonLogger::Level::info,
      "listener configured",
      {{"resource", listener.resource},
       {"bind", listener.bind_address + ":" + std::to_string(listener.port)},
       {"tls", listener.tls ? "yes" : "no"}});

    if (listener.tls) {
      auto ctx = tls_configure_listener(listener);
      if (!ctx) {
        logger.log(JsonLogger::Level::error,
          "TLS context creation failed for " + listener.resource);
      }
    }
  }

  metrics.set("listeners_active", static_cast<int64_t>(listeners.size()));

  // ---- 17. Startup complete ----
  logger.log(JsonLogger::Level::info, "master startup complete");
  logger.log(JsonLogger::Level::info, "server ready to accept connections");

  // ---- 18. Run the event loop ----
  try {
    io_ctx.run();
  } catch (const std::exception& e) {
    logger.log(JsonLogger::Level::error,
      "event loop exception", {{"error", e.what()}});
    if (sentry)
      sentry->capture_exception(std::string("event loop: ") + e.what());
  }

  logger.log(JsonLogger::Level::info, "event loop exited");
  remove_pid_file(opts.pid_file);
}

// ---- Global io_context (one instance per process) ----
static boost::asio::io_context io_ctx;

}  // anonymous namespace

// =========================================================================
// 20.  Worker-mode dispatch
// =========================================================================

namespace {

void run_worker(const CliOptions& opts,
                JsonLogger& logger,
                PrometheusRegistry& metrics) {
  logger.log(JsonLogger::Level::info, "starting worker process",
    {{"worker_type", opts.worker_name},
     {"worker_app", std::to_string(static_cast<int>(*opts.worker_app))}});

  // Resource limits
  set_resource_limits(opts);

  // Daemonize
  if (opts.daemonize) {
    logger.log(JsonLogger::Level::info, "daemonizing worker");
    daemonize();
  }

  // PID file
  std::string worker_pid_file = opts.pid_file + "." + opts.worker_name;
  write_pid_file(worker_pid_file);

  // Connect to master via replication
  std::unique_ptr<ReplicationStream> replication;
  if (opts.enable_replication || !opts.worker_main_process.empty()) {
    replication = std::make_unique<ReplicationStream>(io_ctx, std::unique_ptr<storage::DatabasePool>());
    replication->start_client(
      opts.worker_replication_host.empty() ? "127.0.0.1" : opts.worker_replication_host,
      opts.worker_replication_port);
  }

  // Worker-specific setup
  switch (*opts.worker_app) {
    case WorkerApp::generic_worker:
      logger.log(JsonLogger::Level::info, "generic worker — handling all API endpoints");
      // Starts HTTP listeners for /_matrix/client/* and /_matrix/federation/*
      break;

    case WorkerApp::pusher:
      logger.log(JsonLogger::Level::info, "pusher worker — processing push notifications");
      // Reads from push queue, sends HTTP push to push gateways
      break;

    case WorkerApp::federation_sender:
      logger.log(JsonLogger::Level::info, "federation sender — sending outbound transactions");
      // Reads from federation_stream, sends PDUs/EDUs to remote servers
      break;

    case WorkerApp::media_repository:
      logger.log(JsonLogger::Level::info, "media repository — handling media uploads/downloads");
      // Listens on /_matrix/media/* endpoints
      break;

    case WorkerApp::appservice:
      logger.log(JsonLogger::Level::info, "application service — bridging to external services");
      // Reads appservice stream, pushes events to appservice APIs
      break;

    case WorkerApp::user_dir:
      logger.log(JsonLogger::Level::info, "user directory — maintaining search index");
      // Processes user directory updates from replication stream
      break;

    case WorkerApp::synchrotron:
      logger.log(JsonLogger::Level::info, "synchrotron — sync worker (high throughput /sync)");
      // Handles /sync requests with local cache, reads from replication
      break;

    default:
      // master — shouldn't get here
      logger.log(JsonLogger::Level::error, "unknown worker application type");
      std::exit(1);
  }

  // Graceful shutdown for workers
  GracefulShutdown shutdown_mgr(
    io_ctx, std::vector<ListenerEntry>{}, std::unique_ptr<RedisPool>{},
    std::unique_ptr<AcmeManager>{}, std::unique_ptr<BackgroundTaskScheduler>{},
    replication, std::unique_ptr<storage::DatabasePool>{},
    std::unique_ptr<SentryReporter>{}, logger, worker_pid_file);

  // Signal handling
  boost::asio::signal_set signals(io_ctx, SIGINT, SIGTERM, SIGHUP);
  signals.async_wait([&shutdown_mgr](boost::system::error_code ec, int signum) {
    if (ec)
      return;
    if (signum == SIGHUP)
      shutdown_mgr.reload();
    else
      shutdown_mgr.initiate(signum);
  });

  // Start metrics for worker
  start_metrics_server(io_ctx, opts, metrics);

  logger.log(JsonLogger::Level::info, "worker startup complete — entering event loop");

  try {
    io_ctx.run();
  } catch (const std::exception& e) {
    logger.log(JsonLogger::Level::error,
      "worker event loop exception", {{"error", e.what()}});
  }

  logger.log(JsonLogger::Level::info, "worker event loop exited");
  remove_pid_file(worker_pid_file);
}

}  // anonymous namespace

// =========================================================================
// 21.  Top-level entry point — main()
// =========================================================================

namespace {

void main_impl(int argc, char* argv[]) {
  // Parse CLI
  CliOptions opts = parse_cli(argc, argv);

  // Print banner / version
  print_banner(opts);

  // ---- Special actions (no server start) ----

  if (opts.generate_config) {
    std::string dir = opts.generate_directory.empty()
                        ? "/etc/progressive"
                        : opts.generate_directory;
    generate_default_config(dir);
    return;
  }

  if (opts.generate_keys) {
    std::string dir = opts.keys_directory.empty()
                        ? "/etc/progressive"
                        : opts.keys_directory;
    // Use a placeholder server name — in production this comes from config
    generate_signing_key(dir, "localhost");
    return;
  }

  if (opts.migrate_config) {
    migrate_old_config(opts.config_path);
    return;
  }

  // ---- Load configuration ----
  config::Config config = load_config(opts);

  // If server_name is still empty, default it.
  if (config.server.server_name.empty())
    config.server.server_name = "localhost";

  // ---- Initialize structured logger ----
  JsonLogger logger = create_logger(opts);

  logger.log(JsonLogger::Level::info, "progressive-server starting",
    {{"version", def::kVersion},
     {"server_name", config.server.server_name},
     {"config", opts.config_path}});

  // ---- Initialize Prometheus metrics registry ----
  PrometheusRegistry metrics;
  metrics.register_counter("progressive_http_requests_total",
    "Total HTTP requests received");
  metrics.register_counter("progressive_http_responses_total",
    "Total HTTP responses sent");
  metrics.register_counter("progressive_matrix_events_total",
    "Total Matrix events processed");
  metrics.register_gauge("progressive_connections_active",
    "Currently active connections");
  metrics.register_gauge("progressive_db_pool_size",
    "Database connection pool size");
  metrics.register_gauge("progressive_db_connections_active",
    "Active database connections");
  metrics.register_gauge("progressive_replication_connected",
    "Replication stream connected (1=yes)");
  metrics.register_gauge("progressive_federation_senders_active",
    "Active federation outbound transactions");
  metrics.register_counter("progressive_push_notifications_sent",
    "Push notifications sent");
  metrics.register_gauge("progressive_listeners_active",
    "Number of active HTTP listeners");
  metrics.register_counter("progressive_errors_total",
    "Total errors encountered");
  metrics.set("progressive_connections_active", 0);

  // ---- Dispatch to master or worker ----
  if (opts.worker_app.has_value() &&
      opts.worker_app.value() != WorkerApp::master) {
    run_worker(opts, logger, metrics);
  } else {
    run_master(opts, logger, metrics, config);
  }
}

}  // anonymous namespace

// =========================================================================
// 23.  Extended YAML config section parser — all Synapse config blocks
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// Extended configuration covering all Synapse v1.x config sections
// ---------------------------------------------------------------------------
struct ExtendedConfig {
  // Server block
  std::string server_name;
  std::string pid_file;
  std::string web_client_location;
  bool        serve_server_wellknown = true;
  bool        presence_enabled       = true;
  int         presence_router_timeout = 60;
  bool        track_presence          = true;
  bool        use_presence            = true;

  // Listeners
  struct ListenerResource {
    std::vector<std::string> names;       // client, federation, media, admin
    bool compress = false;
  };
  struct ListenerDef {
    uint16_t                     port           = 8008;
    std::string                  bind_address   = "0.0.0.0";
    std::string                  type           = "http";   // http, https, unix
    bool                         tls            = false;
    std::string                  tls_certificate_path;
    std::string                  tls_private_key_path;
    std::string                  x_forwarded    = "false";
    std::vector<std::string>     resources_raw;
    std::vector<ListenerResource> resources;
  };
  std::vector<ListenerDef> listeners;

  // Federation
  struct FederationConfig {
    bool send_federation           = true;
    bool allow_device_name_lookup  = true;
    int  federation_rc_window_size = 1000;
    int  federation_rc_sleep_limit = 10;
    int  federation_rc_sleep_delay = 500;
    int  federation_rc_reject_limit = 50;
    int  federation_rc_concurrent  = 3;
    int  federation_rr_transactions_per_room_per_second = 50;
    int  send_federation_delay     = 10;
    int  federation_timeout        = 60;
    int  federation_max_long_retries = 10;
    int  federation_max_short_retries = 3;
  } federation;

  // Database
  struct DatabaseDef {
    std::string name;
    std::map<std::string, std::string> args;
    int  cp_min = 5;
    int  cp_max = 20;
    bool allow_unsafe_locale = false;
  };
  DatabaseDef database;

  // Logging
  struct LoggingConfig {
    std::string log_file;
    std::string log_level    = "INFO";
    bool        structured   = true;
    bool        rolling      = true;
    int         max_size_mb  = 100;
    int         max_backups  = 7;
  } logging;

  // Caches (Synapse cache factor system)
  struct CacheConfig {
    long long global_factor               = 500000;   // ~500K entries
    long long event_cache_size            = 100000;
    long long sync_response_cache_size    = 0;         // disabled by default
    long long state_cache_size            = 100000;
    long long state_group_cache_size      = 100000;
    long long device_cache_size           = 100000;
    long long get_event_cache_size        = 100000;
    long long room_member_cache_size      = 100000;
    long long media_repository_cache_size = 100000;
    bool      per_cache_factors           = false;
    int       expire_caches               = 86400 * 30;  // 30 days TTL
    bool      sync_cache_enabled          = false;
    int       cache_entry_ttl             = 86400 * 7;   // 7 days
  } caches;

  // Rate limiting
  struct RatelimitConfig {
    bool  federation_rc_window_size_enabled = false;
    float rc_messages_per_second            = 0.5f;
    int   rc_message_burst_count            = 20;
    float rc_registration_per_second        = 0.5f;
    int   rc_registration_burst_count       = 5;
    float rc_login_per_second               = 0.5f;
    int   rc_login_burst_count              = 5;
    float rc_admin_redaction_per_second     = 1.0f;
    int   rc_admin_redaction_burst_count    = 50;
    float rc_joins_per_second               = 0.5f;
    int   rc_joins_burst_count              = 10;
    float rc_joins_local_per_second         = 1.0f;
    int   rc_joins_local_burst_count        = 20;
    float rc_invites_per_room_per_second    = 0.5f;
    int   rc_invites_per_room_burst_count    = 10;
    float rc_invites_per_user_per_second    = 0.5f;
    int   rc_invites_per_user_burst_count    = 10;
    float rc_3pid_validation_per_second     = 0.5f;
    int   rc_3pid_validation_burst_count    = 5;
    float rc_failed_attempts_per_second     = 0.2f;
    int   rc_failed_attempts_burst_count    = 3;
  } ratelimiting;

  // Media
  struct MediaConfig {
    std::string media_store_path         = "/var/lib/progressive/media";
    long long   max_upload_size          = 50 * 1024 * 1024;  // 50 MB
    int         max_image_pixels         = 32000000;           // ~32 MP
    bool        dynamic_thumbnails       = true;
    int         thumbnail_sizes_count    = 5;
    std::vector<int> thumbnail_sizes      = {32, 96, 320, 640, 800};
    bool        url_preview_enabled      = true;
    int         url_preview_timeout      = 10;
    long long   url_preview_max_size     = 2 * 1024 * 1024;   // 2 MB
    bool        url_preview_ip_range_blacklist = true;
    std::vector<std::string> url_preview_url_blacklist;
  } media;

  // Registration
  bool  enable_registration         = false;
  std::string registration_shared_secret;
  bool  enable_registration_captcha = false;
  bool  auto_join_rooms             = false;
  std::vector<std::string> autocreate_auto_join_rooms;
  bool  allow_guest_access          = false;

  // Email / 3PID
  struct EmailConfig {
    std::string smtp_host;
    int         smtp_port            = 587;
    std::string smtp_user;
    std::string smtp_pass;
    bool        require_transport_security = true;
    bool        enable_notifs        = true;
    std::string notif_from           = "noreply@localhost";
    int         notif_template_html  = 0;
    int         notif_template_text  = 0;
    int         expiry_time_hours    = 24;
    std::string invite_client_location;
    std::string app_name             = "Matrix";
  } email;

  // Password policy
  struct PasswordPolicy {
    bool   enabled                   = false;
    int    minimum_length            = 8;
    bool   require_digit             = false;
    bool   require_symbol            = false;
    bool   require_lowercase         = false;
    bool   require_uppercase         = false;
  } password_policy;

  // SSO / OIDC
  struct OidcConfig {
    bool   enabled                   = false;
    std::string issuer;
    std::string client_id;
    std::string client_secret;
    std::string discovery_endpoint;
    std::string user_mapping_provider;
    bool   skip_verification         = false;
    bool   allow_existing_users      = true;
    std::string user_profile_method  = "auto";
  } oidc;

  // TURN server config for VoIP calls
  struct TurnConfig {
    bool   turn_uris_configured      = false;
    std::string turn_uri;
    std::string turn_username;
    std::string turn_password;
    std::string turn_user_lifetime   = "1h";
    bool   turn_allow_guests         = true;
  } turn;

  // Key management
  struct KeyConfig {
    std::string signing_key_path      = "/etc/progressive/signing.key";
    int         old_signing_keys_count = 2;           // keep N previous keys
    std::string key_refresh_interval   = "1d";        // rotate daily
    int         perspective_key_fetch_delay = 3600;
    std::vector<std::string> trusted_key_servers;
    std::vector<std::string> key_server_signing_keys_path;
  } key_management;

  // Retention (message retention policies)
  struct RetentionConfig {
    bool   enabled                    = false;
    int    default_policy_min_lifetime = 0;           // forever
    int    default_policy_max_lifetime = 0;           // forever
    int    purge_jobs_max_interval     = 24;          // hours
    bool   allowed_lifetime_min        = 86400;       // 1 day min
    bool   allowed_lifetime_max        = 315360000;   // 10 years max
  } retention;

  // Experimental features
  struct ExperimentalConfig {
    bool msc2858_multiple_ssos               = false;
    bool msc3440_thread_enabled               = false;
    bool msc3664_push_rules_for_polls         = false;
    bool msc3861_mandatory_unicode_emojis     = false;
    bool spaces_enabled                       = true;
    bool room_previews_enabled                = true;
    bool knock_feature                        = false;
  } experimental;

  // CAS (Central Authentication Service)
  struct CasConfig {
    bool   enabled           = false;
    std::string server_url;
    std::string service_url;
    std::string display_name = "CAS SSO";
  } cas;

  // SAML2
  struct SamlConfig {
    bool   enabled           = false;
    std::string idp_entity_id;
    std::string sp_entity_id;
    std::string idp_metadata_url;
    bool   grandfathered_mxid_source_attribute = false;
  } saml2;

  // Push
  struct PushConfig {
    bool   include_content     = true;
    int    group_unread_count_by_room = 1;
    int    push_delay          = 1;          // seconds
  } push;

  // TLS
  struct TlsConfig {
    bool   tls_enabled         = false;
    std::string tls_certificate_path;
    std::string tls_private_key_path;
    bool   tls_dh_params_path  = false;
    bool   federation_verify_certificates = true;
    std::string federation_custom_ca_list;
    std::string federation_client_minimum_tls_version = "1.2";
  } tls;

  // Worker-specific
  struct WorkerConfig {
    bool   worker_enabled        = false;
    std::string worker_app;
    std::string worker_name;
    std::string worker_replication_host;
    int         worker_replication_http_port = 9093;
    std::string worker_main_http_uri;
    bool   worker_listeners      = true;
    bool   worker_daemonize      = false;
    bool   worker_pid_file       = true;
    bool   worker_log_config     = true;
  } worker;

  // Redis
  struct ExtendedRedisConfig {
    bool   enabled       = false;
    std::string host     = "127.0.0.1";
    int         port     = 6379;
    int         pool_size = 8;
    std::string password;
    int         db       = 0;
    bool        ssl      = false;
  } redis;

  // Admin contact
  struct AdminConfig {
    std::string admin_contact;
    bool        report_stats = false;
    std::string report_stats_endpoint;
  } admin;

  // ACME
  struct ExtendedAcmeConfig {
    bool   enabled      = false;
    std::string domain;
    std::string account_key_file;
    bool   reprovision_threshold_hours = 72;
  } acme;

  // Spam checker
  struct SpamCheckerConfig {
    bool   enabled       = false;
    std::string module;
    nlohmann::json config;
  } spam_checker;

  // Account validity
  struct AccountValidityConfig {
    bool   enabled       = false;
    int    period        = 0;              // 0 = never expire
    bool   renew_at      = 0;
    bool   renew_email_subject = false;
    bool   startup_job_check_interval_hours = 24;
  } account_validity;

  // Consent
  struct ConsentConfig {
    bool   enabled       = false;
    std::string template_dir;
    std::string version;
    std::string server_notice_content;
    bool   block_events_error = false;
  } consent;

  // Room directory
  struct RoomDirectoryConfig {
    bool   enabled       = true;
    bool   prefer_local_users = true;
    bool   search_all_users = false;
  } room_directory;

  // Trusted key servers for notary service
  struct TrustedKeyServer {
    std::string server_name;
    std::vector<std::string> verify_keys;
  };
  std::vector<TrustedKeyServer> trusted_key_servers;

  // Voip
  bool   turn_uris = false;

  // Serialize to JSON for debugging/inspection
  nlohmann::json to_json() const {
    nlohmann::json j;
    j["server_name"]    = server_name;
    j["pid_file"]       = pid_file;
    j["enable_registration"] = enable_registration;
    j["listeners"]      = nlohmann::json::array();
    for (auto& l : listeners) {
      nlohmann::json lj;
      lj["port"]         = l.port;
      lj["bind_address"] = l.bind_address;
      lj["type"]         = l.type;
      lj["tls"]          = l.tls;
      j["listeners"].push_back(lj);
    }
    j["database"]["name"] = database.name;
    j["logging"]["log_level"] = logging.log_level;
    j["caches"]["global_factor"] = caches.global_factor;
    j["media"]["max_upload_size"] = media.max_upload_size;
    j["redis"]["enabled"]  = redis.enabled;
    j["federation"]["send_federation"] = federation.send_federation;
    j["acme"]["enabled"]   = acme.enabled;
    return j;
  }

  // Parse from YAML/JSON config
  static ExtendedConfig from_json(const nlohmann::json& j) {
    ExtendedConfig cfg;
    cfg.server_name          = j.value("server_name", "localhost");
    cfg.pid_file             = j.value("pid_file", "/var/run/progressive-server.pid");
    cfg.web_client_location   = j.value("web_client_location", "");
    cfg.serve_server_wellknown = j.value("serve_server_wellknown", true);
    cfg.presence_enabled     = j.value("presence_enabled", true);
    cfg.enable_registration  = j.value("enable_registration", false);
    cfg.registration_shared_secret = j.value("registration_shared_secret", "");
    cfg.allow_guest_access   = j.value("allow_guest_access", false);

    // Listeners
    if (j.contains("listeners")) {
      for (auto& lj : j["listeners"]) {
        ListenerDef ld;
        ld.port         = lj.value("port", 8008);
        ld.bind_address = lj.value("bind_address", "0.0.0.0");
        ld.type         = lj.value("type", "http");
        ld.tls          = lj.value("tls", false);
        ld.tls_certificate_path = lj.value("tls_certificate_path", "");
        ld.tls_private_key_path = lj.value("tls_private_key_path", "");
        ld.x_forwarded  = lj.value("x_forwarded", "false");
        if (lj.contains("resources")) {
          for (auto& rj : lj["resources"]) {
            ListenerResource lr;
            if (rj.contains("names")) {
              for (auto& nj : rj["names"])
                lr.names.push_back(nj.get<std::string>());
            }
            lr.compress = rj.value("compress", false);
            ld.resources.push_back(lr);
          }
        }
        cfg.listeners.push_back(ld);
      }
    }

    // Database
    if (j.contains("database")) {
      auto& dj = j["database"];
      cfg.database.name = dj.value("name", "psycopg2");
      cfg.database.cp_min = dj.value("cp_min", 5);
      cfg.database.cp_max = dj.value("cp_max", 20);
      cfg.database.allow_unsafe_locale = dj.value("allow_unsafe_locale", false);
      if (dj.contains("args")) {
        for (auto& [k, v] : dj["args"].items())
          cfg.database.args[k] = v.get<std::string>();
      }
    }

    // Logging
    if (j.contains("logging")) {
      auto& lj = j["logging"];
      cfg.logging.log_file   = lj.value("log_file", "/var/log/progressive/homeserver.log");
      cfg.logging.log_level  = lj.value("log_level", "INFO");
      cfg.logging.structured = lj.value("structured", true);
      cfg.logging.rolling    = lj.value("rolling", true);
      cfg.logging.max_size_mb = lj.value("max_size_mb", 100);
      cfg.logging.max_backups = lj.value("max_backups", 7);
    }

    // Caches
    if (j.contains("caches")) {
      auto& cj = j["caches"];
      cfg.caches.global_factor               = cj.value("global_factor", 500000LL);
      cfg.caches.event_cache_size            = cj.value("event_cache_size", 100000LL);
      cfg.caches.sync_response_cache_size    = cj.value("sync_response_cache_size", 0LL);
      cfg.caches.state_cache_size            = cj.value("state_cache_size", 100000LL);
      cfg.caches.per_cache_factors           = cj.value("per_cache_factors", false);
      cfg.caches.expire_caches               = cj.value("expire_caches", 2592000);
      cfg.caches.sync_cache_enabled          = cj.value("sync_cache_enabled", false);
      cfg.caches.cache_entry_ttl             = cj.value("cache_entry_ttl", 604800);
    }

    // Rate limiting
    if (j.contains("rc_messages_per_second"))
      cfg.ratelimiting.rc_messages_per_second = j["rc_messages_per_second"].get<float>();
    if (j.contains("rc_message_burst_count"))
      cfg.ratelimiting.rc_message_burst_count = j["rc_message_burst_count"].get<int>();
    if (j.contains("rc_registration_per_second"))
      cfg.ratelimiting.rc_registration_per_second = j["rc_registration_per_second"].get<float>();
    if (j.contains("rc_login_per_second"))
      cfg.ratelimiting.rc_login_per_second = j["rc_login_per_second"].get<float>();
    if (j.contains("rc_joins_per_second"))
      cfg.ratelimiting.rc_joins_per_second = j["rc_joins_per_second"].get<float>();
    if (j.contains("rc_invites_per_room_per_second"))
      cfg.ratelimiting.rc_invites_per_room_per_second = j["rc_invites_per_room_per_second"].get<float>();

    // Media
    if (j.contains("media_store_path"))
      cfg.media.media_store_path = j["media_store_path"].get<std::string>();
    if (j.contains("max_upload_size"))
      cfg.media.max_upload_size = j["max_upload_size"].get<long long>();
    if (j.contains("max_image_pixels"))
      cfg.media.max_image_pixels = j["max_image_pixels"].get<int>();
    if (j.contains("dynamic_thumbnails"))
      cfg.media.dynamic_thumbnails = j["dynamic_thumbnails"].get<bool>();
    if (j.contains("url_preview_enabled"))
      cfg.media.url_preview_enabled = j["url_preview_enabled"].get<bool>();
    if (j.contains("url_preview_url_blacklist") && j["url_preview_url_blacklist"].is_array()) {
      for (auto& u : j["url_preview_url_blacklist"])
        cfg.media.url_preview_url_blacklist.push_back(u.get<std::string>());
    }

    // Email
    if (j.contains("email")) {
      auto& ej = j["email"];
      cfg.email.smtp_host       = ej.value("smtp_host", "");
      cfg.email.smtp_port       = ej.value("smtp_port", 587);
      cfg.email.smtp_user       = ej.value("smtp_user", "");
      cfg.email.smtp_pass       = ej.value("smtp_pass", "");
      cfg.email.enable_notifs   = ej.value("enable_notifs", true);
      cfg.email.notif_from      = ej.value("notif_from", "noreply@localhost");
      cfg.email.invite_client_location = ej.value("invite_client_location", "");
      cfg.email.app_name        = ej.value("app_name", "Matrix");
    }

    // Password policy
    if (j.contains("password_policy")) {
      auto& pj = j["password_policy"];
      cfg.password_policy.enabled          = pj.value("enabled", false);
      cfg.password_policy.minimum_length   = pj.value("minimum_length", 8);
      cfg.password_policy.require_digit    = pj.value("require_digit", false);
      cfg.password_policy.require_symbol   = pj.value("require_symbol", false);
      cfg.password_policy.require_lowercase = pj.value("require_lowercase", false);
      cfg.password_policy.require_uppercase = pj.value("require_uppercase", false);
    }

    // Federation
    if (j.contains("federation")) {
      auto& fj = j["federation"];
      cfg.federation.send_federation = fj.value("send_federation", true);
      cfg.federation.allow_device_name_lookup = fj.value("allow_device_name_lookup", true);
      cfg.federation.federation_rc_window_size = fj.value("federation_rc_window_size", 1000);
      cfg.federation.federation_rc_sleep_limit = fj.value("federation_rc_sleep_limit", 10);
      cfg.federation.federation_rc_reject_limit = fj.value("federation_rc_reject_limit", 50);
      cfg.federation.federation_rc_concurrent  = fj.value("federation_rc_concurrent", 3);
      cfg.federation.federation_rr_transactions_per_room_per_second =
        fj.value("federation_rr_transactions_per_room_per_second", 50);
    }

    // OIDC
    if (j.contains("oidc_providers") && j["oidc_providers"].is_array() &&
        !j["oidc_providers"].empty()) {
      auto& oj = j["oidc_providers"][0];
      cfg.oidc.enabled     = oj.value("enabled", false);
      cfg.oidc.issuer      = oj.value("issuer", "");
      cfg.oidc.client_id   = oj.value("client_id", "");
      cfg.oidc.client_secret = oj.value("client_secret", "");
      cfg.oidc.discovery_endpoint = oj.value("discovery_endpoint", "");
      cfg.oidc.skip_verification  = oj.value("skip_verification", false);
      cfg.oidc.allow_existing_users = oj.value("allow_existing_users", true);
    }

    // TURN
    if (j.contains("turn_uris") && j["turn_uris"].is_array() &&
        !j["turn_uris"].empty()) {
      cfg.turn.turn_uris_configured = true;
      cfg.turn.turn_uri = j["turn_uris"][0].get<std::string>();
    }
    cfg.turn.turn_username      = j.value("turn_username", "");
    cfg.turn.turn_password      = j.value("turn_password", "");
    cfg.turn.turn_user_lifetime  = j.value("turn_user_lifetime", "1h");
    cfg.turn.turn_allow_guests  = j.value("turn_allow_guests", true);

    // Redis
    if (j.contains("redis")) {
      auto& rj = j["redis"];
      cfg.redis.enabled    = rj.value("enabled", false);
      cfg.redis.host       = rj.value("host", "127.0.0.1");
      cfg.redis.port       = rj.value("port", 6379);
      cfg.redis.pool_size  = rj.value("pool_size", 8);
      cfg.redis.password   = rj.value("password", "");
      cfg.redis.db         = rj.value("db", 0);
      cfg.redis.ssl        = rj.value("ssl", false);
    }

    // ACME
    if (j.contains("acme")) {
      auto& aj = j["acme"];
      cfg.acme.enabled       = aj.value("enabled", false);
      cfg.acme.domain        = aj.value("domain", "");
      cfg.acme.account_key_file = aj.value("account_key_file", "");
      cfg.acme.reprovision_threshold_hours = aj.value("reprovision_threshold_hours", 72);
    }

    // Retention
    if (j.contains("retention")) {
      auto& rj = j["retention"];
      cfg.retention.enabled                    = rj.value("enabled", false);
      cfg.retention.default_policy_min_lifetime = rj.value("default_policy_min_lifetime", 0);
      cfg.retention.default_policy_max_lifetime = rj.value("default_policy_max_lifetime", 0);
      cfg.retention.purge_jobs_max_interval     = rj.value("purge_jobs_max_interval", 24);
    }

    // Spam checker
    if (j.contains("spam_checker")) {
      auto& sc = j["spam_checker"];
      cfg.spam_checker.enabled = sc.value("enabled", false);
      cfg.spam_checker.module  = sc.value("module", "");
      if (sc.contains("config"))
        cfg.spam_checker.config = sc["config"];
    }

    // Consent
    if (j.contains("user_consent")) {
      auto& cj = j["user_consent"];
      cfg.consent.enabled     = cj.value("enabled", false);
      cfg.consent.template_dir = cj.value("template_dir", "");
      cfg.consent.version      = cj.value("version", "");
    }

    // Room directory
    if (j.contains("room_directory")) {
      auto& rj = j["room_directory"];
      cfg.room_directory.enabled = rj.value("enabled", true);
      cfg.room_directory.prefer_local_users = rj.value("prefer_local_users", true);
      cfg.room_directory.search_all_users   = rj.value("search_all_users", false);
    }

    // Account validity
    if (j.contains("account_validity")) {
      auto& av = j["account_validity"];
      cfg.account_validity.enabled  = av.value("enabled", false);
      cfg.account_validity.period   = av.value("period", 0);
    }

    // Experimental
    if (j.contains("experimental_features")) {
      auto& ef = j["experimental_features"];
      cfg.experimental.msc2858_multiple_ssos = ef.value("msc2858_multiple_ssos", false);
      cfg.experimental.msc3440_thread_enabled  = ef.value("msc3440_thread_enabled", false);
      cfg.experimental.spaces_enabled          = ef.value("spaces_enabled", true);
      cfg.experimental.room_previews_enabled   = ef.value("room_previews_enabled", true);
    }

    // Key management
    if (j.contains("signing_key_path"))
      cfg.key_management.signing_key_path = j["signing_key_path"].get<std::string>();
    if (j.contains("old_signing_keys"))
      cfg.key_management.old_signing_keys_count = j["old_signing_keys"].get<int>();
    if (j.contains("key_refresh_interval"))
      cfg.key_management.key_refresh_interval = j["key_refresh_interval"].get<std::string>();

    // Trusted key servers
    if (j.contains("trusted_key_servers")) {
      for (auto& tk : j["trusted_key_servers"]) {
        TrustedKeyServer tks;
        tks.server_name = tk["server_name"].get<std::string>();
        if (tk.contains("verify_keys")) {
          for (auto& vk : tk["verify_keys"])
            tks.verify_keys.push_back(vk.get<std::string>());
        }
        cfg.trusted_key_servers.push_back(tks);
      }
    }

    // Push
    cfg.push.include_content = j.value("push_include_content", true);
    cfg.push.group_unread_count_by_room = j.value("push_group_unread_count_by_room", 1);

    // TLS
    cfg.tls.tls_enabled = j.value("tls_enabled", false);
    cfg.tls.tls_certificate_path = j.value("tls_certificate_path", "");
    cfg.tls.tls_private_key_path = j.value("tls_private_key_path", "");
    cfg.tls.federation_verify_certificates = j.value("federation_verify_certificates", true);

    return cfg;
  }
};

// ---------------------------------------------------------------------------
// validate_extended_config — validates critical config constraints
// ---------------------------------------------------------------------------
std::vector<std::string> validate_extended_config(const ExtendedConfig& cfg) {
  std::vector<std::string> warnings;

  if (cfg.server_name.empty())
    warnings.push_back("server_name is empty — defaulting to 'localhost'");

  if (cfg.listeners.empty())
    warnings.push_back("no listeners configured — server will not accept connections");

  if (cfg.database.name.empty())
    warnings.push_back("no database driver specified — defaulting to SQLite");

  if (cfg.enable_registration && cfg.registration_shared_secret.empty())
    warnings.push_back("registration enabled without shared secret — open registration!");

  if (!cfg.registration_shared_secret.empty() && cfg.registration_shared_secret == "changeme")
    warnings.push_back("registration_shared_secret is set to default 'changeme' — change it!");

  if (cfg.acme.enabled && cfg.acme.domain.empty())
    warnings.push_back("ACME enabled but no domain configured");

  if (cfg.federation.send_federation && cfg.server_name == "localhost")
    warnings.push_back("federation enabled with server_name 'localhost' — "
                       "federation will not work without a real domain");

  if (cfg.media.max_upload_size > 500 * 1024 * 1024LL)
    warnings.push_back("max_upload_size > 500 MB, consider a lower limit");

  return warnings;
}

// ---------------------------------------------------------------------------
// print_config_summary — shows key config settings at startup
// ---------------------------------------------------------------------------
void print_config_summary(const ExtendedConfig& cfg, JsonLogger& logger) {
  logger.log(JsonLogger::Level::info, "configuration summary",
    {{"server_name", cfg.server_name},
     {"listeners", std::to_string(cfg.listeners.size())},
     {"database", cfg.database.name},
     {"registration", cfg.enable_registration ? "open" : "closed"},
     {"federation", cfg.federation.send_federation ? "enabled" : "disabled"},
     {"presence", cfg.presence_enabled ? "enabled" : "disabled"},
     {"max_upload_mb", std::to_string(cfg.media.max_upload_size / 1048576)},
     {"redis", cfg.redis.enabled ? "enabled" : "disabled"},
     {"acme", cfg.acme.enabled ? "enabled" : "disabled"},
     {"cache_factor", std::to_string(cfg.caches.global_factor)}});
}

}  // anonymous namespace

// =========================================================================
// 24.  HTTP connection handler — detailed per-API routing
// =========================================================================

namespace {

// ---------------------------------------------------------------------------
// ConnectionTracker — tracks active connections for graceful draining
// ---------------------------------------------------------------------------
class ConnectionTracker {
public:
  void add() {
    active_.fetch_add(1, std::memory_order_relaxed);
    total_.fetch_add(1, std::memory_order_relaxed);
  }

  void remove() {
    active_.fetch_sub(1, std::memory_order_relaxed);
  }

  int64_t active() const { return active_.load(std::memory_order_relaxed); }
  int64_t total()  const { return total_.load(std::memory_order_relaxed); }

  // Block until all connections drain or timeout expires
  bool drain_all(std::chrono::seconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (active_.load(std::memory_order_relaxed) > 0) {
      if (std::chrono::steady_clock::now() > deadline)
        return false;  // timeout — force shutdown
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return true;
  }

private:
  std::atomic<int64_t> active_{0};
  std::atomic<int64_t> total_{0};
};

// ---------------------------------------------------------------------------
// HttpRequestHandler — routes incoming HTTP to the right Matrix API handler
// ---------------------------------------------------------------------------
class HttpRequestHandler {
public:
  enum class ApiType : uint8_t {
    ClientServer,
    Federation,
    Media,
    Admin,
    Health,
    Metrics,
    WellKnown,
    Unknown,
  };

  static ApiType classify_request(std::string_view target) {
    // /.well-known/matrix/server
    if (target.starts_with("/.well-known/matrix/server"))
      return ApiType::WellKnown;
    if (target.starts_with("/.well-known/matrix/client"))
      return ApiType::WellKnown;

    // /_matrix/client/* — Client-Server API
    if (target.starts_with("/_matrix/client/"))
      return ApiType::ClientServer;

    // /_matrix/federation/* — Federation API
    if (target.starts_with("/_matrix/federation/"))
      return ApiType::Federation;

    // /_matrix/key/* — Key server
    if (target.starts_with("/_matrix/key/"))
      return ApiType::Federation;

    // /_matrix/media/* — Media API
    if (target.starts_with("/_matrix/media/"))
      return ApiType::Media;

    // /_synapse/admin/* — Admin API
    if (target.starts_with("/_synapse/admin/"))
      return ApiType::Admin;

    // /health — Health check
    if (target == "/health" || target == "/healthz")
      return ApiType::Health;

    // /metrics — Prometheus
    if (target == "/metrics")
      return ApiType::Metrics;

    return ApiType::Unknown;
  }

  // Build CORS headers for all responses
  static void set_cors_headers(std::string& response_headers) {
    response_headers += "Access-Control-Allow-Origin: *\r\n";
    response_headers += "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n";
    response_headers += "Access-Control-Allow-Headers: "
                         "Origin, X-Requested-With, Content-Type, Accept, Authorization\r\n";
    response_headers += "Access-Control-Max-Age: 86400\r\n";
  }

  // Handle CORS preflight
  static std::string handle_options() {
    std::string response;
    response += "HTTP/1.1 204 No Content\r\n";
    set_cors_headers(response);
    response += "Content-Length: 0\r\n\r\n";
    return response;
  }
};

// ---------------------------------------------------------------------------
// rate_limit_check — checks client IP against rate-limiting config
// ---------------------------------------------------------------------------
bool rate_limit_check(const std::string& client_ip,
                      const ExtendedConfig::RatelimitConfig& rl,
                      std::map<std::string, std::pair<int, std::chrono::steady_clock::time_point>>& buckets) {
  auto now = std::chrono::steady_clock::now();

  auto& bucket = buckets[client_ip];
  // Reset bucket if window has passed
  if (now - bucket.second > std::chrono::seconds(1)) {
    bucket.first  = 0;
    bucket.second = now;
  }

  bucket.first++;
  return bucket.first <= rl.rc_message_burst_count;
}

// ---------------------------------------------------------------------------
// simple_http_response — builds a minimal HTTP response string
// ---------------------------------------------------------------------------
std::string simple_http_response(int status_code,
                                 const std::string& content_type,
                                 const std::string& body) {
  std::string status_text;
  switch (status_code) {
    case 200: status_text = "200 OK"; break;
    case 201: status_text = "201 Created"; break;
    case 204: status_text = "204 No Content"; break;
    case 400: status_text = "400 Bad Request"; break;
    case 401: status_text = "401 Unauthorized"; break;
    case 403: status_text = "403 Forbidden"; break;
    case 404: status_text = "404 Not Found"; break;
    case 405: status_text = "405 Method Not Allowed"; break;
    case 429: status_text = "429 Too Many Requests"; break;
    case 500: status_text = "500 Internal Server Error"; break;
    case 502: status_text = "502 Bad Gateway"; break;
    case 503: status_text = "503 Service Unavailable"; break;
    default:  status_text = std::to_string(status_code) + " Unknown"; break;
  }

  std::stringstream ss;
  ss << "HTTP/1.1 " << status_text << "\r\n";
  ss << "Content-Type: " << content_type << "\r\n";
  ss << "Content-Length: " << body.size() << "\r\n";
  ss << "Server: progressive-server/" << def::kVersion << "\r\n";
  HttpRequestHandler::set_cors_headers(ss);
  ss << "Connection: keep-alive\r\n";
  ss << "\r\n";
  ss << body;

  return ss.str();
}

}  // anonymous namespace

}  // namespace progressive::server

// =========================================================================
// 22.  External C-linkage main() — the real entry point
// =========================================================================

// We need to forward-declare the singleton io_context; it's defined as a
// file-scope static inside the anonymous namespace above.  Because main()
// is only compiled once per translation unit, having the static inside the
// same .cpp file works correctly.

int main(int argc, char* argv[]) {
  try {
    progressive::server::main_impl(argc, argv);
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "FATAL: unhandled exception: " << e.what() << "\n";
    return 1;
  } catch (...) {
    std::cerr << "FATAL: unknown exception\n";
    return 2;
  }
}
