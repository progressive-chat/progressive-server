// server_main.cpp - ProgressiveServer: unified multi-protocol server
// Ties together Matrix, IRC, XMPP, Lemmy, DeltaChat protocols
// Config parsing, database init, listener setup, startup/shutdown,
// health check, metrics, background tasks, rate limiting, CORS.
// Target: 2500+ lines

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
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
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netdb.h>
#include <dlfcn.h>

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

// Protocol headers
#include "progressive/irc/irc_server.hpp"
#include "progressive/xmpp/xmpp_server.hpp"
#include "progressive/lemmy/lemmy_server.hpp"
#include "progressive/deltachat/deltachat.hpp"
#include "progressive/federation/fed_transport.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/engine.hpp"
#include "progressive/storage/types.hpp"
#include "progressive/rest/rest_base.hpp"
#include "progressive/handlers/full_handlers.hpp"
#include "progressive/handlers/handlers_core.hpp"
#include "progressive/handlers/handlers_misc.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;

// ============================================================================
// Forward declarations
// ============================================================================
class ProgressiveServer;
class ConfigManager;
class DatabaseManager;
class ListenerManager;
class MetricsCollector;
class BackgroundTaskScheduler;
class RateLimiter;
class CORSManager;
class HealthChecker;
class LogManager;

// ============================================================================
// Utility: timestamp helpers
// ============================================================================
namespace util {

inline int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

inline int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

inline std::string iso8601(int64_t ts_ms) {
    auto tp = std::chrono::system_clock::from_time_t(ts_ms / 1000);
    auto ms = ts_ms % 1000;
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm;
    gmtime_r(&t, &tm);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
    return buf;
}

inline std::string escape_html(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

inline std::string random_id(int len = 32) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static const char hex[] = "0123456789abcdef";
    std::string id;
    id.reserve(len);
    for (int i = 0; i < len; i++) id += hex[dis(gen)];
    return id;
}

inline std::string sha256_hex(const std::string& data) {
    // Simple placeholder; real impl would use OpenSSL/libcrypto
    std::hash<std::string> hasher;
    size_t h = hasher(data);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << h;
    while (oss.str().size() < 64) oss << '0';
    return oss.str();
}

inline bool is_valid_port(int port) { return port > 0 && port <= 65535; }

inline std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

inline std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::istringstream iss(s);
    std::string part;
    while (std::getline(iss, part, delim)) parts.push_back(part);
    return parts;
}

inline std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::ostringstream oss;
    for (size_t i = 0; i < v.size(); i++) {
        if (i > 0) oss << sep;
        oss << v[i];
    }
    return oss.str();
}

inline std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

} // namespace util

// ============================================================================
// LogManager - structured logging with levels and output destinations
// ============================================================================
class LogManager {
public:
    enum class Level { TRACE = 0, DEBUG = 1, INFO = 2, WARN = 3, ERROR = 4, FATAL = 5 };

    static LogManager& instance() {
        static LogManager lm;
        return lm;
    }

    void configure(const std::string& level_str, const std::string& log_file = "") {
        if (level_str == "trace") level_ = Level::TRACE;
        else if (level_str == "debug") level_ = Level::DEBUG;
        else if (level_str == "info") level_ = Level::INFO;
        else if (level_str == "warn" || level_str == "warning") level_ = Level::WARN;
        else if (level_str == "error") level_ = Level::ERROR;
        else if (level_str == "fatal") level_ = Level::FATAL;
        else level_ = Level::INFO;
        if (!log_file.empty()) {
            file_stream_.open(log_file, std::ios::app);
        }
    }

    void log(Level lvl, const std::string& module, const std::string& msg) {
        if (lvl < level_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        std::string line = format_line(lvl, module, msg);
        if (file_stream_.is_open()) {
            file_stream_ << line << std::endl;
            file_stream_.flush();
        }
        if (lvl >= Level::ERROR) {
            std::cerr << line << std::endl;
        } else {
            std::cout << line << std::endl;
        }
    }

    void trace(const std::string& m, const std::string& msg) { log(Level::TRACE, m, msg); }
    void debug(const std::string& m, const std::string& msg) { log(Level::DEBUG, m, msg); }
    void info(const std::string& m, const std::string& msg)  { log(Level::INFO, m, msg); }
    void warn(const std::string& m, const std::string& msg)  { log(Level::WARN, m, msg); }
    void error(const std::string& m, const std::string& msg) { log(Level::ERROR, m, msg); }
    void fatal(const std::string& m, const std::string& msg) { log(Level::FATAL, m, msg); }

    Level level() const { return level_; }

private:
    LogManager() = default;
    std::string format_line(Level lvl, const std::string& mod, const std::string& msg) {
        static const char* level_names[] = {"TRACE","DEBUG","INFO ","WARN ","ERROR","FATAL"};
        return util::iso8601(util::now_ms()) + " [" + level_names[static_cast<int>(lvl)]
               + "] [" + mod + "] " + msg;
    }
    Level level_{Level::INFO};
    std::mutex mutex_;
    std::ofstream file_stream_;
};

// Shortcut macros
#define LOG_TRACE(m, msg) LogManager::instance().trace(m, msg)
#define LOG_DEBUG(m, msg) LogManager::instance().debug(m, msg)
#define LOG_INFO(m, msg)  LogManager::instance().info(m, msg)
#define LOG_WARN(m, msg)  LogManager::instance().warn(m, msg)
#define LOG_ERROR(m, msg) LogManager::instance().error(m, msg)
#define LOG_FATAL(m, msg) LogManager::instance().fatal(m, msg)

// ============================================================================
// Config structures for all protocols
// ============================================================================

struct MatrixConfig {
    std::string server_name{"localhost"};
    std::string public_baseurl{"http://localhost:8008/"};
    std::string key_id{"ed25519:a_xxx"};
    std::string private_key_path;
    bool enable_registration{true};
    bool enable_registration_without_verification{false};
    int64_t max_avatar_size{1048576};
    int64_t max_upload_size{52428800};
    int64_t presence_idle_timeout{300000};
    int64_t event_cache_size{100000};
    bool enable_metrics{true};
    bool enable_search{true};
    bool enable_3pid_lookup{true};
    bool block_non_admin_invites{false};
    int bcrypt_rounds{12};
    std::string default_room_version{"9"};
    std::vector<std::string> trusted_key_servers;
    std::string turn_uris;
    std::string turn_shared_secret;
};

struct IRCConfigSection {
    bool enabled{true};
    std::string server_name{"irc.localhost"};
    std::string description{"Progressive IRC Server"};
    std::string network_name{"ProgressiveNet"};
    std::vector<int> ports{6667, 6668, 6669};
    int max_channels_per_user{20};
    int max_nick_length{30};
    int max_topic_length{390};
    std::string motd_file;
    std::string server_password;
    std::map<std::string,std::string> oper_blocks;
    bool allow_remote_oper{false};
    int ping_interval{120};
    int timeout_secs{300};
};

struct XMPPConfigSection {
    bool enabled{true};
    std::string domain{"localhost"};
    std::string server_name{"Progressive XMPP"};
    std::vector<std::string> hosts;
    int c2s_port{5222};
    int s2s_port{5269};
    int http_port{5280};
    int max_stanza_size{65536};
    bool registration_enabled{true};
    bool s2s_enabled{true};
    bool websocket_enabled{true};
    std::string welcome_message;
    std::vector<std::string> trusted_servers;
    std::map<std::string,std::string> s2s_certs;
};

struct LemmyConfigSection {
    bool enabled{true};
    std::string hostname{"localhost"};
    std::string site_name{"Progressive Lemmy"};
    std::string site_description{"A federated link aggregator"};
    int port{8536};
    bool ssl{false};
    int max_upload_size{10485760};
    bool registration_enabled{true};
    bool private_instance{false};
    std::string jwt_secret;
    std::string email_from;
    bool federation_enabled{true};
    std::string pictrs_url{"http://localhost:8080"};
    std::string default_theme{"darkly"};
    bool captcha_enabled{false};
    std::string captcha_difficulty{"medium"};
    std::vector<std::string> allowed_instances;
    std::vector<std::string> blocked_instances;
};

struct DeltaChatConfigSection {
    bool enabled{true};
    std::string dbfile{"/var/lib/progressive/deltachat.db"};
    std::string addr;
    std::string mail_pw;
    std::string imap_server;
    int imap_port{993};
    int imap_security{1};
    std::string smtp_server;
    int smtp_port{465};
    int smtp_security{1};
    std::string display_name;
    std::string self_status;
    bool e2ee_enabled{true};
    bool mdns_enabled{true};
    bool bot{false};
    int imap_idle_timeout{1740};
};

struct FederationConfigSection {
    bool enabled{true};
    int port{8448};
    std::string bind_address{"0.0.0.0"};
    int64_t timeout_ms{30000};
    int max_retries{5};
    int64_t retry_base_delay_ms{2000};
    int64_t retry_max_delay_ms{300000};
    int max_transaction_size{50};
    bool verify_certificates{true};
    std::string tls_cert_path;
    std::string tls_key_path;
    std::vector<std::string> federation_whitelist;
    std::vector<std::string> federation_blacklist;
};

struct DatabaseConfig {
    std::string name{"sqlite3"};
    std::map<std::string,std::string> args;
    bool separate_databases{false};
    int pool_size{5};
    int max_overflow{10};
    int pool_timeout{30};
    int pool_recycle{3600};
    std::string connection_string() const {
        if (name == "sqlite3") {
            auto it = args.find("database");
            return "file:" + (it != args.end() ? it->second : ":memory:") + "?mode=memory&cache=shared";
        } else if (name == "psycopg2" || name == "postgresql") {
            auto u = args.find("user"); auto p = args.find("password");
            auto h = args.find("host"); auto db = args.find("database");
            auto port = args.find("port");
            std::ostringstream oss;
            oss << "postgresql://";
            if (u != args.end()) oss << u->second;
            if (p != args.end()) oss << ":" << p->second;
            if (u != args.end() || p != args.end()) oss << "@";
            oss << (h != args.end() ? h->second : "localhost");
            if (port != args.end()) oss << ":" << port->second;
            oss << "/" << (db != args.end() ? db->second : "progressive");
            return oss.str();
        }
        return "";
    }
};

struct ListenersConfig {
    struct Listener {
        std::string type{"http"}; // http, https, unix, irc, xmpp_c2s, xmpp_s2s, lemmy_http
        int port{0};
        std::string bind_address{"0.0.0.0"};
        bool tls{false};
        std::string tls_cert_path;
        std::string tls_key_path;
        std::string resource; // client, federation, admin
        std::string unix_socket_path;
        std::vector<std::string> additional_headers;
        int max_body_size{1048576};
        int connection_timeout_ms{60000};
        bool x_forwarded{false};
    };
    std::vector<Listener> listeners;
};

struct MetricsConfig {
    bool enabled{true};
    int port{9100};
    std::string bind_address{"127.0.0.1"};
};

struct RateLimitConfig {
    bool enabled{true};
    double default_burst{50.0};
    double default_rate{100.0};
    std::map<std::string, std::pair<double,double>> per_endpoint; // endpoint -> {burst, rate}
};

struct CORSConfig {
    bool enabled{true};
    std::string allow_origin{"*"};
    std::string allow_methods{"GET, POST, PUT, DELETE, PATCH, OPTIONS"};
    std::string allow_headers{"Origin, X-Requested-With, Content-Type, Accept, Authorization"};
    std::string expose_headers{""};
    int64_t max_age{86400};
};

struct BackgroundTasksConfig {
    int64_t presence_cleanup_interval_ms{60000};
    int64_t ephemeral_cleanup_interval_ms{300000};
    int64_t expired_media_cleanup_interval_ms{3600000};
    int64_t federation_retry_interval_ms{30000};
    int64_t stats_aggregation_interval_ms{60000};
    int64_t server_acl_update_interval_ms{60000};
    int64_t remote_media_cleanup_interval_ms{86400000};
    bool presence_cleanup_enabled{true};
    bool ephemeral_cleanup_enabled{true};
    bool expired_media_enabled{true};
    bool federation_retry_enabled{true};
    bool stats_aggregation_enabled{true};
};

struct HealthCheckConfig {
    bool enabled{true};
    std::string endpoint{"/health"};
    int port{0}; // 0 = use main HTTP listener
};

struct ServerConfig {
    MatrixConfig matrix;
    IRCConfigSection irc;
    XMPPConfigSection xmpp;
    LemmyConfigSection lemmy;
    DeltaChatConfigSection deltachat;
    FederationConfigSection federation;
    DatabaseConfig database;
    ListenersConfig listeners;
    MetricsConfig metrics;
    RateLimitConfig rate_limit;
    CORSConfig cors;
    BackgroundTasksConfig background_tasks;
    HealthCheckConfig health_check;
    std::string log_level{"info"};
    std::string log_file;
    std::string config_dir{"/etc/progressive"};
    std::string data_dir{"/var/lib/progressive"};
    std::string media_store_path{"/var/lib/progressive/media"};
    bool report_stats{false};
    std::string version{"0.1.0"};
};

// ============================================================================
// ConfigManager - parses config.yaml
// ============================================================================
class ConfigManager {
public:
    explicit ConfigManager(const std::string& config_path) : config_path_(config_path) {}

    ServerConfig load() {
        LOG_INFO("config", "Loading configuration from " + config_path_);
        if (!std::filesystem::exists(config_path_)) {
            LOG_WARN("config", "Config file not found, using defaults");
            return defaults();
        }
        try {
            YAML::Node root = YAML::LoadFile(config_path_);
            ServerConfig cfg;

            // Matrix section
            if (root["matrix"]) {
                auto& m = root["matrix"];
                if (m["server_name"]) cfg.matrix.server_name = m["server_name"].as<std::string>();
                if (m["public_baseurl"]) cfg.matrix.public_baseurl = m["public_baseurl"].as<std::string>();
                if (m["key_id"]) cfg.matrix.key_id = m["key_id"].as<std::string>();
                if (m["private_key_path"]) cfg.matrix.private_key_path = m["private_key_path"].as<std::string>();
                if (m["enable_registration"]) cfg.matrix.enable_registration = m["enable_registration"].as<bool>();
                if (m["max_avatar_size"]) cfg.matrix.max_avatar_size = m["max_avatar_size"].as<int64_t>();
                if (m["max_upload_size"]) cfg.matrix.max_upload_size = m["max_upload_size"].as<int64_t>();
                if (m["default_room_version"]) cfg.matrix.default_room_version = m["default_room_version"].as<std::string>();
                if (m["bcrypt_rounds"]) cfg.matrix.bcrypt_rounds = m["bcrypt_rounds"].as<int>();
                if (m["block_non_admin_invites"]) cfg.matrix.block_non_admin_invites = m["block_non_admin_invites"].as<bool>();
                if (m["trusted_key_servers"]) {
                    for (auto& s : m["trusted_key_servers"])
                        cfg.matrix.trusted_key_servers.push_back(s.as<std::string>());
                }
            }

            // IRC section
            if (root["irc"]) {
                auto& i = root["irc"];
                if (i["enabled"]) cfg.irc.enabled = i["enabled"].as<bool>();
                if (i["server_name"]) cfg.irc.server_name = i["server_name"].as<std::string>();
                if (i["description"]) cfg.irc.description = i["description"].as<std::string>();
                if (i["network_name"]) cfg.irc.network_name = i["network_name"].as<std::string>();
                if (i["ports"]) {
                    cfg.irc.ports.clear();
                    for (auto& p : i["ports"]) cfg.irc.ports.push_back(p.as<int>());
                }
                if (i["max_channels_per_user"]) cfg.irc.max_channels_per_user = i["max_channels_per_user"].as<int>();
                if (i["max_nick_length"]) cfg.irc.max_nick_length = i["max_nick_length"].as<int>();
                if (i["max_topic_length"]) cfg.irc.max_topic_length = i["max_topic_length"].as<int>();
                if (i["motd_file"]) cfg.irc.motd_file = i["motd_file"].as<std::string>();
                if (i["server_password"]) cfg.irc.server_password = i["server_password"].as<std::string>();
                if (i["allow_remote_oper"]) cfg.irc.allow_remote_oper = i["allow_remote_oper"].as<bool>();
                if (i["ping_interval"]) cfg.irc.ping_interval = i["ping_interval"].as<int>();
                if (i["timeout_secs"]) cfg.irc.timeout_secs = i["timeout_secs"].as<int>();
            }

            // XMPP section
            if (root["xmpp"]) {
                auto& x = root["xmpp"];
                if (x["enabled"]) cfg.xmpp.enabled = x["enabled"].as<bool>();
                if (x["domain"]) cfg.xmpp.domain = x["domain"].as<std::string>();
                if (x["server_name"]) cfg.xmpp.server_name = x["server_name"].as<std::string>();
                if (x["c2s_port"]) cfg.xmpp.c2s_port = x["c2s_port"].as<int>();
                if (x["s2s_port"]) cfg.xmpp.s2s_port = x["s2s_port"].as<int>();
                if (x["http_port"]) cfg.xmpp.http_port = x["http_port"].as<int>();
                if (x["registration_enabled"]) cfg.xmpp.registration_enabled = x["registration_enabled"].as<bool>();
                if (x["s2s_enabled"]) cfg.xmpp.s2s_enabled = x["s2s_enabled"].as<bool>();
                if (x["websocket_enabled"]) cfg.xmpp.websocket_enabled = x["websocket_enabled"].as<bool>();
                if (x["trusted_servers"]) {
                    for (auto& s : x["trusted_servers"])
                        cfg.xmpp.trusted_servers.push_back(s.as<std::string>());
                }
                if (x["hosts"]) {
                    for (auto& h : x["hosts"])
                        cfg.xmpp.hosts.push_back(h.as<std::string>());
                }
            }

            // Lemmy section
            if (root["lemmy"]) {
                auto& l = root["lemmy"];
                if (l["enabled"]) cfg.lemmy.enabled = l["enabled"].as<bool>();
                if (l["hostname"]) cfg.lemmy.hostname = l["hostname"].as<std::string>();
                if (l["site_name"]) cfg.lemmy.site_name = l["site_name"].as<std::string>();
                if (l["site_description"]) cfg.lemmy.site_description = l["site_description"].as<std::string>();
                if (l["port"]) cfg.lemmy.port = l["port"].as<int>();
                if (l["ssl"]) cfg.lemmy.ssl = l["ssl"].as<bool>();
                if (l["max_upload_size"]) cfg.lemmy.max_upload_size = l["max_upload_size"].as<int>();
                if (l["registration_enabled"]) cfg.lemmy.registration_enabled = l["registration_enabled"].as<bool>();
                if (l["private_instance"]) cfg.lemmy.private_instance = l["private_instance"].as<bool>();
                if (l["jwt_secret"]) cfg.lemmy.jwt_secret = l["jwt_secret"].as<std::string>();
                if (l["federation_enabled"]) cfg.lemmy.federation_enabled = l["federation_enabled"].as<bool>();
                if (l["allowed_instances"]) {
                    for (auto& s : l["allowed_instances"])
                        cfg.lemmy.allowed_instances.push_back(s.as<std::string>());
                }
                if (l["blocked_instances"]) {
                    for (auto& s : l["blocked_instances"])
                        cfg.lemmy.blocked_instances.push_back(s.as<std::string>());
                }
            }

            // DeltaChat section
            if (root["deltachat"]) {
                auto& d = root["deltachat"];
                if (d["enabled"]) cfg.deltachat.enabled = d["enabled"].as<bool>();
                if (d["dbfile"]) cfg.deltachat.dbfile = d["dbfile"].as<std::string>();
                if (d["addr"]) cfg.deltachat.addr = d["addr"].as<std::string>();
                if (d["mail_pw"]) cfg.deltachat.mail_pw = d["mail_pw"].as<std::string>();
                if (d["imap_server"]) cfg.deltachat.imap_server = d["imap_server"].as<std::string>();
                if (d["imap_port"]) cfg.deltachat.imap_port = d["imap_port"].as<int>();
                if (d["imap_security"]) cfg.deltachat.imap_security = d["imap_security"].as<int>();
                if (d["smtp_server"]) cfg.deltachat.smtp_server = d["smtp_server"].as<std::string>();
                if (d["smtp_port"]) cfg.deltachat.smtp_port = d["smtp_port"].as<int>();
                if (d["smtp_security"]) cfg.deltachat.smtp_security = d["smtp_security"].as<int>();
                if (d["e2ee_enabled"]) cfg.deltachat.e2ee_enabled = d["e2ee_enabled"].as<bool>();
            }

            // Federation section
            if (root["federation"]) {
                auto& f = root["federation"];
                if (f["enabled"]) cfg.federation.enabled = f["enabled"].as<bool>();
                if (f["port"]) cfg.federation.port = f["port"].as<int>();
                if (f["bind_address"]) cfg.federation.bind_address = f["bind_address"].as<std::string>();
                if (f["timeout_ms"]) cfg.federation.timeout_ms = f["timeout_ms"].as<int64_t>();
                if (f["max_retries"]) cfg.federation.max_retries = f["max_retries"].as<int>();
                if (f["verify_certificates"]) cfg.federation.verify_certificates = f["verify_certificates"].as<bool>();
                if (f["tls_cert_path"]) cfg.federation.tls_cert_path = f["tls_cert_path"].as<std::string>();
                if (f["tls_key_path"]) cfg.federation.tls_key_path = f["tls_key_path"].as<std::string>();
                if (f["federation_whitelist"]) {
                    for (auto& s : f["federation_whitelist"])
                        cfg.federation.federation_whitelist.push_back(s.as<std::string>());
                }
                if (f["federation_blacklist"]) {
                    for (auto& s : f["federation_blacklist"])
                        cfg.federation.federation_blacklist.push_back(s.as<std::string>());
                }
            }

            // Database section
            if (root["database"]) {
                auto& db = root["database"];
                if (db["name"]) cfg.database.name = db["name"].as<std::string>();
                if (db["separate_databases"]) cfg.database.separate_databases = db["separate_databases"].as<bool>();
                if (db["pool_size"]) cfg.database.pool_size = db["pool_size"].as<int>();
                if (db["args"]) {
                    for (auto it = db["args"].begin(); it != db["args"].end(); ++it) {
                        cfg.database.args[it->first.as<std::string>()] = it->second.as<std::string>();
                    }
                }
            }

            // Listeners section
            if (root["listeners"]) {
                for (auto& l : root["listeners"]) {
                    ListenersConfig::Listener listener;
                    if (l["type"]) listener.type = l["type"].as<std::string>();
                    if (l["port"]) listener.port = l["port"].as<int>();
                    if (l["bind_address"]) listener.bind_address = l["bind_address"].as<std::string>();
                    if (l["tls"]) listener.tls = l["tls"].as<bool>();
                    if (l["tls_cert_path"]) listener.tls_cert_path = l["tls_cert_path"].as<std::string>();
                    if (l["tls_key_path"]) listener.tls_key_path = l["tls_key_path"].as<std::string>();
                    if (l["resource"]) listener.resource = l["resource"].as<std::string>();
                    if (l["max_body_size"]) listener.max_body_size = l["max_body_size"].as<int>();
                    cfg.listeners.listeners.push_back(listener);
                }
            }

            // Metrics section
            if (root["metrics"]) {
                auto& met = root["metrics"];
                if (met["enabled"]) cfg.metrics.enabled = met["enabled"].as<bool>();
                if (met["port"]) cfg.metrics.port = met["port"].as<int>();
                if (met["bind_address"]) cfg.metrics.bind_address = met["bind_address"].as<std::string>();
            }

            // Rate limiting section
            if (root["rate_limiting"]) {
                auto& rl = root["rate_limiting"];
                if (rl["enabled"]) cfg.rate_limit.enabled = rl["enabled"].as<bool>();
                if (rl["default_burst"]) cfg.rate_limit.default_burst = rl["default_burst"].as<double>();
                if (rl["default_rate"]) cfg.rate_limit.default_rate = rl["default_rate"].as<double>();
            }

            // CORS section
            if (root["cors"]) {
                auto& c = root["cors"];
                if (c["enabled"]) cfg.cors.enabled = c["enabled"].as<bool>();
                if (c["allow_origin"]) cfg.cors.allow_origin = c["allow_origin"].as<std::string>();
                if (c["allow_methods"]) cfg.cors.allow_methods = c["allow_methods"].as<std::string>();
                if (c["allow_headers"]) cfg.cors.allow_headers = c["allow_headers"].as<std::string>();
            }

            // Background tasks
            if (root["background_tasks"]) {
                auto& bt = root["background_tasks"];
                if (bt["presence_cleanup_interval_ms"])
                    cfg.background_tasks.presence_cleanup_interval_ms = bt["presence_cleanup_interval_ms"].as<int64_t>();
                if (bt["ephemeral_cleanup_interval_ms"])
                    cfg.background_tasks.ephemeral_cleanup_interval_ms = bt["ephemeral_cleanup_interval_ms"].as<int64_t>();
                if (bt["expired_media_cleanup_interval_ms"])
                    cfg.background_tasks.expired_media_cleanup_interval_ms = bt["expired_media_cleanup_interval_ms"].as<int64_t>();
                if (bt["federation_retry_interval_ms"])
                    cfg.background_tasks.federation_retry_interval_ms = bt["federation_retry_interval_ms"].as<int64_t>();
                if (bt["stats_aggregation_interval_ms"])
                    cfg.background_tasks.stats_aggregation_interval_ms = bt["stats_aggregation_interval_ms"].as<int64_t>();
            }

            // Global settings
            if (root["log_level"]) cfg.log_level = root["log_level"].as<std::string>();
            if (root["log_file"]) cfg.log_file = root["log_file"].as<std::string>();
            if (root["data_dir"]) cfg.data_dir = root["data_dir"].as<std::string>();
            if (root["media_store_path"]) cfg.media_store_path = root["media_store_path"].as<std::string>();
            if (root["report_stats"]) cfg.report_stats = root["report_stats"].as<bool>();

            LOG_INFO("config", "Configuration loaded successfully");
            validate(cfg);
            return cfg;
        } catch (const YAML::Exception& e) {
            LOG_ERROR("config", std::string("YAML parse error: ") + e.what());
            throw std::runtime_error("Failed to parse config: " + std::string(e.what()));
        }
    }

    void validate(const ServerConfig& cfg) {
        if (cfg.matrix.server_name.empty())
            throw std::runtime_error("matrix.server_name is required");
        if (cfg.database.name.empty())
            throw std::runtime_error("database.name is required");
        for (auto& l : cfg.listeners.listeners) {
            if (l.type == "irc" || l.type == "xmpp_c2s" || l.type == "xmpp_s2s" || l.type == "lemmy_http") {
                if (!util::is_valid_port(l.port))
                    throw std::runtime_error("Invalid port for listener type " + l.type + ": " + std::to_string(l.port));
            }
        }
        LOG_INFO("config", "Configuration validated");
    }

    static ServerConfig defaults() {
        ServerConfig cfg;
        cfg.listeners.listeners.push_back({"http", 8008, "127.0.0.1", false, "", "", "client"});
        cfg.database.name = "sqlite3";
        cfg.database.args["database"] = ":memory:";
        return cfg;
    }

    static void generate_default_yaml(const std::string& path) {
        std::ofstream ofs(path);
        ofs << R"(# Progressive Server Configuration
matrix:
  server_name: "localhost"
  public_baseurl: "http://localhost:8008/"
  enable_registration: true
  max_upload_size: 52428800
  default_room_version: "9"

irc:
  enabled: true
  server_name: "irc.localhost"
  description: "Progressive IRC Server"
  network_name: "ProgressiveNet"
  ports: [6667, 6668, 6669]
  max_channels_per_user: 20

xmpp:
  enabled: true
  domain: "localhost"
  server_name: "Progressive XMPP"
  c2s_port: 5222
  s2s_port: 5269
  registration_enabled: true
  s2s_enabled: true

lemmy:
  enabled: true
  hostname: "localhost"
  site_name: "Progressive Lemmy"
  port: 8536
  registration_enabled: true
  federation_enabled: true

deltachat:
  enabled: false
  dbfile: "/var/lib/progressive/deltachat.db"

federation:
  enabled: true
  port: 8448
  timeout_ms: 30000
  verify_certificates: true

database:
  name: "sqlite3"
  args:
    database: "/var/lib/progressive/homeserver.db"

listeners:
  - type: http
    port: 8008
    bind_address: "0.0.0.0"
    resource: client
  - type: http
    port: 8448
    bind_address: "0.0.0.0"
    resource: federation

metrics:
  enabled: true
  port: 9100

rate_limiting:
  enabled: true
  default_burst: 50.0
  default_rate: 100.0

cors:
  enabled: true
  allow_origin: "*"

log_level: "info"
data_dir: "/var/lib/progressive"
)";
        ofs.close();
        LOG_INFO("config", "Default configuration generated at " + path);
    }

private:
    std::string config_path_;
};

// ============================================================================
// DatabaseManager - initialize all protocol schemas
// ============================================================================
class DatabaseManager {
public:
    DatabaseManager(const ServerConfig& cfg) : cfg_(cfg) {}

    void initialize_all() {
        LOG_INFO("db", "Initializing databases...");
        std::string conn_str = cfg_.database.connection_string();

        // Main database pool (Matrix)
        main_db_ = std::make_unique<storage::DatabasePool>(
            cfg_.matrix.server_name, "main", conn_str);

        create_matrix_tables();
        LOG_INFO("db", "Matrix tables created");

        if (cfg_.irc.enabled) {
            if (cfg_.database.separate_databases) {
                auto irc_conn = cfg_.database.connection_string() + "_irc";
                irc_db_ = std::make_unique<storage::DatabasePool>(
                    cfg_.irc.server_name, "irc", irc_conn);
            }
            create_irc_tables(irc_db_ ? *irc_db_ : *main_db_);
            LOG_INFO("db", "IRC tables created");
        }

        if (cfg_.xmpp.enabled) {
            if (cfg_.database.separate_databases) {
                auto xmpp_conn = cfg_.database.connection_string() + "_xmpp";
                xmpp_db_ = std::make_unique<storage::DatabasePool>(
                    cfg_.xmpp.domain, "xmpp", xmpp_conn);
            }
            create_xmpp_tables(xmpp_db_ ? *xmpp_db_ : *main_db_);
            LOG_INFO("db", "XMPP tables created");
        }

        if (cfg_.lemmy.enabled) {
            if (cfg_.database.separate_databases) {
                auto lemmy_conn = cfg_.database.connection_string() + "_lemmy";
                lemmy_db_ = std::make_unique<storage::DatabasePool>(
                    cfg_.lemmy.hostname, "lemmy", lemmy_conn);
            }
            create_lemmy_tables(lemmy_db_ ? *lemmy_db_ : *main_db_);
            LOG_INFO("db", "Lemmy tables created");
        }

        if (cfg_.deltachat.enabled) {
            if (cfg_.database.separate_databases) {
                auto dc_conn = cfg_.database.connection_string() + "_deltachat";
                deltachat_db_ = std::make_unique<storage::DatabasePool>(
                    "deltachat", "deltachat", dc_conn);
            }
            create_deltachat_tables(deltachat_db_ ? *deltachat_db_ : *main_db_);
            LOG_INFO("db", "DeltaChat tables created");
        }

        LOG_INFO("db", "All database schemas initialized");
    }

    storage::DatabasePool& main() { return *main_db_; }
    storage::DatabasePool& irc() { return irc_db_ ? *irc_db_ : *main_db_; }
    storage::DatabasePool& xmpp() { return xmpp_db_ ? *xmpp_db_ : *main_db_; }
    storage::DatabasePool& lemmy() { return lemmy_db_ ? *lemmy_db_ : *main_db_; }
    storage::DatabasePool& deltachat() { return deltachat_db_ ? *deltachat_db_ : *main_db_; }

private:
    const ServerConfig& cfg_;
    std::unique_ptr<storage::DatabasePool> main_db_;
    std::unique_ptr<storage::DatabasePool> irc_db_;
    std::unique_ptr<storage::DatabasePool> xmpp_db_;
    std::unique_ptr<storage::DatabasePool> lemmy_db_;
    std::unique_ptr<storage::DatabasePool> deltachat_db_;

    // ---------- Matrix tables ----------
    void create_matrix_tables() {
        auto& db = *main_db_;
        db.runInteraction("create_matrix_tables", [](storage::LoggingTransaction& txn) {
            // Users
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS users (
                    name TEXT NOT NULL,
                    password_hash TEXT,
                    is_guest INTEGER DEFAULT 0,
                    admin INTEGER DEFAULT 0,
                    consent_version TEXT,
                    consent_server_notice_sent TEXT,
                    user_type TEXT,
                    deactivated INTEGER DEFAULT 0,
                    shadow_banned INTEGER DEFAULT 0,
                    creation_ts INTEGER DEFAULT 0,
                    appservice_id TEXT,
                    PRIMARY KEY (name)
                )
            )");

            // Access tokens
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS access_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    device_id TEXT,
                    token TEXT NOT NULL UNIQUE,
                    valid_until_ms INTEGER,
                    created_at_ms INTEGER DEFAULT 0,
                    last_used_ms INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(name)
                )
            )");

            // Devices
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS devices (
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    display_name TEXT,
                    last_seen INTEGER DEFAULT 0,
                    ip TEXT,
                    user_agent TEXT,
                    hidden INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, device_id),
                    FOREIGN KEY (user_id) REFERENCES users(name)
                )
            )");

            // End-to-end device keys
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS e2e_device_keys (
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    key_json TEXT NOT NULL,
                    PRIMARY KEY (user_id, device_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS e2e_one_time_keys (
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    key_json TEXT NOT NULL,
                    PRIMARY KEY (user_id, device_id, key_id, algorithm)
                )
            )");

            // Cross-signing keys
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS e2e_cross_signing_keys (
                    user_id TEXT NOT NULL PRIMARY KEY,
                    master_key TEXT,
                    self_signing_key TEXT,
                    user_signing_key TEXT
                )
            )");

            // Rooms
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS rooms (
                    room_id TEXT NOT NULL PRIMARY KEY,
                    room_version TEXT DEFAULT '1',
                    is_public INTEGER DEFAULT 0,
                    creator TEXT,
                    creation_ts INTEGER DEFAULT 0,
                    name TEXT,
                    topic TEXT,
                    canonical_alias TEXT,
                    join_rules TEXT DEFAULT 'invite',
                    history_visibility TEXT DEFAULT 'shared',
                    encryption TEXT,
                    federatable INTEGER DEFAULT 1,
                    is_space INTEGER DEFAULT 0,
                    guest_access TEXT DEFAULT 'forbidden'
                )
            )");

            // Room aliases
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS room_aliases (
                    room_alias TEXT NOT NULL PRIMARY KEY,
                    room_id TEXT NOT NULL,
                    creator TEXT,
                    FOREIGN KEY (room_id) REFERENCES rooms(room_id)
                )
            )");

            // Room members
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS room_members (
                    room_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    membership TEXT NOT NULL,
                    display_name TEXT,
                    avatar_url TEXT,
                    sender TEXT NOT NULL,
                    event_id TEXT,
                    content TEXT,
                    origin_server_ts INTEGER DEFAULT 0,
                    PRIMARY KEY (room_id, user_id)
                )
            )");

            // Events (main events table)
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS events (
                    stream_ordering INTEGER PRIMARY KEY AUTOINCREMENT,
                    topological_ordering INTEGER DEFAULT 0,
                    event_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    state_key TEXT,
                    sender TEXT NOT NULL,
                    content TEXT,
                    origin_server_ts INTEGER DEFAULT 0,
                    received_ts INTEGER DEFAULT 0,
                    depth INTEGER DEFAULT 0,
                    outlier INTEGER DEFAULT 0,
                    hashes TEXT,
                    signatures TEXT,
                    processed INTEGER DEFAULT 1,
                    format_version INTEGER DEFAULT 1,
                    rejection_reason TEXT,
                    UNIQUE(event_id)
                )
            )");

            // State events
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS state_events (
                    event_id TEXT NOT NULL PRIMARY KEY,
                    room_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    state_key TEXT NOT NULL,
                    prev_state TEXT,
                    FOREIGN KEY (event_id) REFERENCES events(event_id)
                )
            )");

            // Current room state
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS current_state_events (
                    room_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    state_key TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    PRIMARY KEY (room_id, type, state_key)
                )
            )");

            // Event edges (DAG)
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS event_edges (
                    event_id TEXT NOT NULL,
                    prev_event_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    is_state INTEGER DEFAULT 0,
                    PRIMARY KEY (event_id, prev_event_id)
                )
            )");

            // Event forward extremities
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS event_forward_extremities (
                    event_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    PRIMARY KEY (event_id, room_id)
                )
            )");

            // Event backward extremities
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS event_backward_extremities (
                    event_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    PRIMARY KEY (event_id, room_id)
                )
            )");

            // Event push actions
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS event_push_actions (
                    room_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    stream_ordering INTEGER,
                    topological_ordering INTEGER,
                    action TEXT,
                    notif INTEGER DEFAULT 0,
                    highlight INTEGER DEFAULT 0,
                    PRIMARY KEY (room_id, event_id, user_id)
                )
            )");

            // Event push summary
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS event_push_summary (
                    room_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    stream_ordering INTEGER,
                    notif_count INTEGER DEFAULT 0,
                    unread_count INTEGER DEFAULT 0,
                    PRIMARY KEY (room_id, user_id)
                )
            )");

            // Event reports
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS event_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_ts INTEGER DEFAULT 0,
                    room_id TEXT,
                    event_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    reason TEXT,
                    content TEXT
                )
            )");

            // Federation destinations / retry
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS destinations (
                    destination TEXT NOT NULL PRIMARY KEY,
                    retry_last_ts INTEGER DEFAULT 0,
                    retry_interval INTEGER DEFAULT 0,
                    failure_ts INTEGER
                )
            )");

            // Federation stream position
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS federation_stream_position (
                    type TEXT NOT NULL,
                    stream_id INTEGER NOT NULL,
                    instance_name TEXT NOT NULL DEFAULT 'master',
                    PRIMARY KEY (type, instance_name)
                )
            )");

            // Presence
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS presence (
                    user_id TEXT NOT NULL PRIMARY KEY,
                    state TEXT,
                    status_msg TEXT,
                    currently_active INTEGER DEFAULT 0,
                    last_active_ts INTEGER DEFAULT 0,
                    last_user_sync_ts INTEGER DEFAULT 0,
                    last_federation_update_ts INTEGER DEFAULT 0
                )
            )");

            // Presence stream
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS presence_stream (
                    stream_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    state TEXT,
                    status_msg TEXT,
                    currently_active INTEGER DEFAULT 0,
                    last_active_ts INTEGER
                )
            )");

            // Profiles
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS profiles (
                    user_id TEXT NOT NULL PRIMARY KEY,
                    displayname TEXT,
                    avatar_url TEXT
                )
            )");

            // Threepids
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS user_threepids (
                    user_id TEXT NOT NULL,
                    medium TEXT NOT NULL,
                    address TEXT NOT NULL,
                    validated_at INTEGER DEFAULT 0,
                    added_at INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, medium, address)
                )
            )");

            // Registration tokens
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS registration_tokens (
                    token TEXT NOT NULL PRIMARY KEY,
                    uses_allowed INTEGER,
                    pending INTEGER DEFAULT 0,
                    completed INTEGER DEFAULT 0,
                    expiry_time INTEGER
                )
            )");

            // Push rules
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS push_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    priority_class INTEGER NOT NULL,
                    priority INTEGER DEFAULT 0,
                    conditions TEXT,
                    actions TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    UNIQUE(user_id, rule_id)
                )
            )");

            // Push rule enable
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS push_rules_enable (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    UNIQUE(user_id, rule_id)
                )
            )");

            // Receipts
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS receipts_linearized (
                    stream_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id TEXT NOT NULL,
                    receipt_type TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    data TEXT,
                    thread_id TEXT
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS receipts_graph (
                    room_id TEXT NOT NULL,
                    receipt_type TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    event_ids TEXT,
                    data TEXT,
                    PRIMARY KEY (room_id, receipt_type, user_id)
                )
            )");

            // Read receipts
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS users_who_sent_room_read_receipts (
                    room_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    thread_id TEXT
                )
            )");

            // Filtering
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS user_filters (
                    user_id TEXT NOT NULL,
                    filter_id INTEGER NOT NULL,
                    filter_json TEXT NOT NULL,
                    PRIMARY KEY (user_id, filter_id)
                )
            )");

            // Local media repository
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS local_media_repository (
                    media_id TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    media_length INTEGER DEFAULT 0,
                    user_id TEXT NOT NULL,
                    created_ts INTEGER DEFAULT 0,
                    upload_name TEXT,
                    content_type TEXT,
                    quarantined_by TEXT,
                    url_cache TEXT,
                    last_access_ts INTEGER DEFAULT 0,
                    safe_from_quarantine INTEGER DEFAULT 0,
                    PRIMARY KEY (media_id, media_type)
                )
            )");

            // Remote media cache
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS remote_media_cache (
                    media_origin TEXT NOT NULL,
                    media_id TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    media_length INTEGER DEFAULT 0,
                    content_type TEXT,
                    filesystem_id TEXT,
                    created_ts INTEGER DEFAULT 0,
                    last_access_ts INTEGER DEFAULT 0,
                    upload_name TEXT,
                    PRIMARY KEY (media_origin, media_id, media_type)
                )
            )");

            // Media thumbnails
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS local_media_repository_thumbnails (
                    media_id TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    thumbnail_width INTEGER NOT NULL,
                    thumbnail_height INTEGER NOT NULL,
                    thumbnail_method TEXT NOT NULL,
                    thumbnail_type TEXT NOT NULL,
                    thumbnail_length INTEGER DEFAULT 0,
                    created_ts INTEGER DEFAULT 0,
                    PRIMARY KEY (media_id, media_type, thumbnail_width, thumbnail_height, thumbnail_type, thumbnail_method)
                )
            )");

            // Application services
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS application_services_state (
                    as_id TEXT NOT NULL PRIMARY KEY,
                    state TEXT,
                    url TEXT,
                    token TEXT,
                    hs_token TEXT,
                    sender_localpart TEXT,
                    namespaces TEXT,
                    rate_limited INTEGER DEFAULT 1,
                    protocol TEXT DEFAULT ''
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS application_services_txns (
                    as_id TEXT NOT NULL,
                    txn_id INTEGER NOT NULL,
                    event_ids TEXT,
                    PRIMARY KEY (as_id, txn_id)
                )
            )");

            // Server ACLs
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS server_acl (
                    room_id TEXT NOT NULL PRIMARY KEY,
                    server_acl_json TEXT
                )
            )");

            // Directory (public rooms)
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS public_room_list_stream (
                    stream_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id TEXT NOT NULL,
                    visibility TEXT DEFAULT 'public',
                    appservice_id TEXT,
                    network_id TEXT
                )
            )");

            // Room stats
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS room_stats_current (
                    room_id TEXT NOT NULL PRIMARY KEY,
                    current_state_events INTEGER DEFAULT 0,
                    joined_members INTEGER DEFAULT 0,
                    invited_members INTEGER DEFAULT 0,
                    left_members INTEGER DEFAULT 0,
                    banned_members INTEGER DEFAULT 0,
                    local_users_in_room INTEGER DEFAULT 0,
                    completed_delta_stream_id INTEGER DEFAULT 0
                )
            )");

            // User stats
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS user_stats_current (
                    user_id TEXT NOT NULL PRIMARY KEY,
                    joined_rooms INTEGER DEFAULT 0
                )
            )");

            // Monthly active users
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS monthly_active_users (
                    user_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    PRIMARY KEY (user_id, timestamp)
                )
            )");

            // User daily visits
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS user_daily_visits (
                    user_id TEXT NOT NULL,
                    device_id TEXT,
                    timestamp INTEGER NOT NULL
                )
            )");

            // Tags
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS room_tags (
                    user_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    content TEXT,
                    PRIMARY KEY (user_id, room_id, tag)
                )
            )");

            // Account data
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS room_account_data (
                    user_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    account_data_type TEXT NOT NULL,
                    content TEXT,
                    PRIMARY KEY (user_id, room_id, account_data_type)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS account_data (
                    user_id TEXT NOT NULL,
                    account_data_type TEXT NOT NULL,
                    content TEXT,
                    PRIMARY KEY (user_id, account_data_type)
                )
            )");

            // Event relations
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS event_relations (
                    event_id TEXT NOT NULL,
                    relates_to_id TEXT NOT NULL,
                    relation_type TEXT NOT NULL,
                    aggregation_key TEXT,
                    PRIMARY KEY (event_id)
                )
            )");

            // Threads
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS threads (
                    room_id TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    latest_event_id TEXT,
                    received_ts INTEGER DEFAULT 0,
                    depth INTEGER DEFAULT 0,
                    PRIMARY KEY (room_id, thread_id)
                )
            )");

            // Backfill / redactions
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS redactions (
                    event_id TEXT NOT NULL PRIMARY KEY,
                    redacts TEXT NOT NULL,
                    received_ts INTEGER DEFAULT 0
                )
            )");

            // Cached signatures
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS event_signatures (
                    event_id TEXT NOT NULL PRIMARY KEY,
                    signature_name TEXT NOT NULL,
                    key_id TEXT,
                    signature TEXT
                )
            )");

            // Expiring access tokens
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS expiring_access_tokens (
                    token TEXT NOT NULL PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT,
                    expiry_ts INTEGER NOT NULL
                )
            )");

            // Rate limiting state
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS ratelimit_override (
                    user_id TEXT NOT NULL PRIMARY KEY,
                    messages_per_second INTEGER DEFAULT 0,
                    burst_count INTEGER DEFAULT 0
                )
            )");

            // UI Auth sessions
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS ui_auth_sessions (
                    session_id TEXT NOT NULL PRIMARY KEY,
                    creation_time INTEGER DEFAULT 0,
                    server_time INTEGER DEFAULT 0,
                    clientdict TEXT,
                    uri TEXT,
                    method TEXT,
                    description TEXT
                )
            )");

            // Background updates tracking
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS background_updates (
                    update_name TEXT NOT NULL PRIMARY KEY,
                    progress_json TEXT,
                    depends_on TEXT
                )
            )");

            // Schema version
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER NOT NULL,
                    upgraded INTEGER DEFAULT 0
                )
            )");
            txn.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (72)");
        });
    }

    // ---------- IRC tables ----------
    void create_irc_tables(storage::DatabasePool& db) {
        db.runInteraction("create_irc_tables", [](storage::LoggingTransaction& txn) {
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_users (
                    nick TEXT NOT NULL PRIMARY KEY,
                    username TEXT,
                    host TEXT,
                    realname TEXT,
                    server TEXT,
                    modes TEXT,
                    oper INTEGER DEFAULT 0,
                    away INTEGER DEFAULT 0,
                    away_msg TEXT,
                    signon_time INTEGER DEFAULT 0,
                    last_active INTEGER DEFAULT 0,
                    ip TEXT,
                    port INTEGER DEFAULT 0,
                    password_hash TEXT
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_channels (
                    name TEXT NOT NULL PRIMARY KEY,
                    topic TEXT,
                    topic_setter TEXT,
                    topic_ts INTEGER DEFAULT 0,
                    modes TEXT,
                    key TEXT,
                    user_limit INTEGER DEFAULT 0,
                    created_ts INTEGER DEFAULT 0,
                    is_persistent INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_channel_members (
                    channel TEXT NOT NULL,
                    nick TEXT NOT NULL,
                    member_modes TEXT,
                    PRIMARY KEY (channel, nick),
                    FOREIGN KEY (channel) REFERENCES irc_channels(name),
                    FOREIGN KEY (nick) REFERENCES irc_users(nick)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_channel_bans (
                    channel TEXT NOT NULL,
                    mask TEXT NOT NULL,
                    set_by TEXT,
                    set_ts INTEGER DEFAULT 0,
                    PRIMARY KEY (channel, mask)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_channel_excepts (
                    channel TEXT NOT NULL,
                    mask TEXT NOT NULL,
                    PRIMARY KEY (channel, mask)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_channel_invites (
                    channel TEXT NOT NULL,
                    mask TEXT NOT NULL,
                    PRIMARY KEY (channel, mask)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_oper_blocks (
                    username TEXT NOT NULL PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    host_mask TEXT,
                    flags TEXT
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_channel_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel TEXT NOT NULL,
                    timestamp INTEGER DEFAULT 0,
                    sender TEXT,
                    type TEXT,
                    message TEXT
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_sasl_credentials (
                    nick TEXT NOT NULL PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    mechanism TEXT DEFAULT 'PLAIN'
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS irc_motd (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    line TEXT NOT NULL,
                    line_num INTEGER DEFAULT 0
                )
            )");
        });
    }

    // ---------- XMPP tables ----------
    void create_xmpp_tables(storage::DatabasePool& db) {
        db.runInteraction("create_xmpp_tables", [](storage::LoggingTransaction& txn) {
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_users (
                    localpart TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    password_hash TEXT,
                    registered INTEGER DEFAULT 0,
                    last_activity INTEGER DEFAULT 0,
                    PRIMARY KEY (localpart, domain)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_roster (
                    user_local TEXT NOT NULL,
                    user_domain TEXT NOT NULL,
                    contact_local TEXT NOT NULL,
                    contact_domain TEXT NOT NULL,
                    nickname TEXT,
                    subscription TEXT DEFAULT 'none',
                    ask TEXT,
                    groups TEXT,
                    PRIMARY KEY (user_local, user_domain, contact_local, contact_domain)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_roster_groups (
                    user_local TEXT NOT NULL,
                    user_domain TEXT NOT NULL,
                    contact_local TEXT NOT NULL,
                    contact_domain TEXT NOT NULL,
                    group_name TEXT NOT NULL,
                    PRIMARY KEY (user_local, user_domain, contact_local, contact_domain, group_name)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_vcard (
                    localpart TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    vcard_json TEXT,
                    PRIMARY KEY (localpart, domain)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_avatar (
                    localpart TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    mime_type TEXT,
                    avatar_data BLOB,
                    sha1_hash TEXT,
                    PRIMARY KEY (localpart, domain)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_muc_rooms (
                    name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    subject TEXT,
                    subject_author TEXT,
                    config_json TEXT,
                    persistent INTEGER DEFAULT 0,
                    members_only INTEGER DEFAULT 0,
                    moderated INTEGER DEFAULT 0,
                    non_anonymous INTEGER DEFAULT 0,
                    max_users INTEGER DEFAULT 0,
                    password TEXT,
                    created_ts INTEGER DEFAULT 0,
                    PRIMARY KEY (name, domain)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_muc_occupants (
                    room_name TEXT NOT NULL,
                    room_domain TEXT NOT NULL,
                    occupant_local TEXT NOT NULL,
                    occupant_domain TEXT NOT NULL,
                    nickname TEXT NOT NULL,
                    affiliation TEXT DEFAULT 'member',
                    role TEXT DEFAULT 'participant',
                    join_ts INTEGER DEFAULT 0,
                    PRIMARY KEY (room_name, room_domain, occupant_local, occupant_domain)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_muc_affiliations (
                    room_name TEXT NOT NULL,
                    room_domain TEXT NOT NULL,
                    jid_local TEXT NOT NULL,
                    jid_domain TEXT NOT NULL,
                    affiliation TEXT DEFAULT 'member',
                    reason TEXT,
                    set_by TEXT,
                    set_ts INTEGER DEFAULT 0,
                    PRIMARY KEY (room_name, room_domain, jid_local, jid_domain)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_pubsub_nodes (
                    node_id TEXT NOT NULL PRIMARY KEY,
                    service TEXT NOT NULL,
                    name TEXT NOT NULL,
                    config TEXT,
                    creator TEXT,
                    created_ts INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_pubsub_items (
                    node_id TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    publisher TEXT,
                    payload TEXT,
                    published_ts INTEGER DEFAULT 0,
                    PRIMARY KEY (node_id, item_id),
                    FOREIGN KEY (node_id) REFERENCES xmpp_pubsub_nodes(node_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_pubsub_subscriptions (
                    node_id TEXT NOT NULL,
                    jid_local TEXT NOT NULL,
                    jid_domain TEXT NOT NULL,
                    subscription_state TEXT DEFAULT 'subscribed',
                    subid TEXT,
                    PRIMARY KEY (node_id, jid_local, jid_domain),
                    FOREIGN KEY (node_id) REFERENCES xmpp_pubsub_nodes(node_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_offline_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    localpart TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    stanza_xml TEXT NOT NULL,
                    received_ts INTEGER DEFAULT 0,
                    expiry_ts INTEGER
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_message_archive (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id TEXT NOT NULL,
                    localpart TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    stanza_xml TEXT NOT NULL,
                    ts INTEGER DEFAULT 0,
                    peer_local TEXT,
                    peer_domain TEXT
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_privacy_lists (
                    user_local TEXT NOT NULL,
                    user_domain TEXT NOT NULL,
                    list_name TEXT NOT NULL,
                    list_json TEXT NOT NULL,
                    is_default INTEGER DEFAULT 0,
                    PRIMARY KEY (user_local, user_domain, list_name)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_blocklist (
                    user_local TEXT NOT NULL,
                    user_domain TEXT NOT NULL,
                    blocked_local TEXT NOT NULL,
                    blocked_domain TEXT NOT NULL,
                    PRIMARY KEY (user_local, user_domain, blocked_local, blocked_domain)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_upload_slots (
                    slot_id TEXT NOT NULL PRIMARY KEY,
                    uploader_local TEXT NOT NULL,
                    uploader_domain TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    size INTEGER DEFAULT 0,
                    content_type TEXT,
                    url TEXT,
                    created_ts INTEGER DEFAULT 0,
                    expiry_ts INTEGER
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS xmpp_s2s_trusted (
                    domain TEXT NOT NULL PRIMARY KEY,
                    cert_pem TEXT,
                    added_ts INTEGER DEFAULT 0
                )
            )");
        });
    }

    // ---------- Lemmy tables ----------
    void create_lemmy_tables(storage::DatabasePool& db) {
        db.runInteraction("create_lemmy_tables", [](storage::LoggingTransaction& txn) {
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_users (
                    id TEXT NOT NULL PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    display_name TEXT,
                    email TEXT,
                    password_hash TEXT,
                    bio TEXT,
                    avatar TEXT,
                    banner TEXT,
                    matrix_user_id TEXT,
                    admin INTEGER DEFAULT 0,
                    bot_account INTEGER DEFAULT 0,
                    comment_score INTEGER DEFAULT 0,
                    post_score INTEGER DEFAULT 0,
                    published INTEGER DEFAULT 0,
                    updated INTEGER DEFAULT 0,
                    banned INTEGER DEFAULT 0,
                    ban_reason TEXT,
                    deleted INTEGER DEFAULT 0,
                    actor_id TEXT,
                    inbox_url TEXT,
                    shared_inbox_url TEXT,
                    public_key TEXT,
                    private_key TEXT,
                    last_refreshed_at INTEGER DEFAULT 0,
                    local INTEGER DEFAULT 1
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_communities (
                    id TEXT NOT NULL PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    title TEXT,
                    description TEXT,
                    icon TEXT,
                    banner TEXT,
                    nsfw INTEGER DEFAULT 0,
                    removed INTEGER DEFAULT 0,
                    deleted INTEGER DEFAULT 0,
                    hidden INTEGER DEFAULT 0,
                    posting_restricted_to_mods INTEGER DEFAULT 0,
                    subscribers INTEGER DEFAULT 0,
                    posts INTEGER DEFAULT 0,
                    comments INTEGER DEFAULT 0,
                    published INTEGER DEFAULT 0,
                    updated INTEGER DEFAULT 0,
                    actor_id TEXT,
                    followers_url TEXT,
                    public_key TEXT,
                    private_key TEXT,
                    last_refreshed_at INTEGER DEFAULT 0,
                    local INTEGER DEFAULT 1
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_posts (
                    id TEXT NOT NULL PRIMARY KEY,
                    name TEXT,
                    url TEXT,
                    body TEXT,
                    creator_id TEXT,
                    community_id TEXT,
                    nsfw INTEGER DEFAULT 0,
                    removed INTEGER DEFAULT 0,
                    deleted INTEGER DEFAULT 0,
                    locked INTEGER DEFAULT 0,
                    stickied INTEGER DEFAULT 0,
                    featured_community INTEGER DEFAULT 0,
                    featured_local INTEGER DEFAULT 0,
                    score INTEGER DEFAULT 0,
                    upvotes INTEGER DEFAULT 0,
                    downvotes INTEGER DEFAULT 0,
                    comments INTEGER DEFAULT 0,
                    published INTEGER DEFAULT 0,
                    updated INTEGER DEFAULT 0,
                    ap_id TEXT,
                    local INTEGER DEFAULT 1,
                    language_id INTEGER,
                    embed_title TEXT,
                    embed_description TEXT,
                    embed_video_url TEXT,
                    thumbnail_url TEXT,
                    FOREIGN KEY (creator_id) REFERENCES lemmy_users(id),
                    FOREIGN KEY (community_id) REFERENCES lemmy_communities(id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_comments (
                    id TEXT NOT NULL PRIMARY KEY,
                    content TEXT,
                    creator_id TEXT,
                    post_id TEXT,
                    parent_id TEXT,
                    removed INTEGER DEFAULT 0,
                    deleted INTEGER DEFAULT 0,
                    distinguished INTEGER DEFAULT 0,
                    score INTEGER DEFAULT 0,
                    upvotes INTEGER DEFAULT 0,
                    downvotes INTEGER DEFAULT 0,
                    published INTEGER DEFAULT 0,
                    updated INTEGER DEFAULT 0,
                    ap_id TEXT,
                    local INTEGER DEFAULT 1,
                    language_id INTEGER,
                    path TEXT,
                    FOREIGN KEY (creator_id) REFERENCES lemmy_users(id),
                    FOREIGN KEY (post_id) REFERENCES lemmy_posts(id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_private_messages (
                    id TEXT NOT NULL PRIMARY KEY,
                    content TEXT,
                    creator_id TEXT,
                    recipient_id TEXT,
                    read INTEGER DEFAULT 0,
                    deleted INTEGER DEFAULT 0,
                    published INTEGER DEFAULT 0,
                    updated INTEGER DEFAULT 0,
                    ap_id TEXT,
                    local INTEGER DEFAULT 1
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_post_votes (
                    post_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    score INTEGER DEFAULT 0,
                    published INTEGER DEFAULT 0,
                    PRIMARY KEY (post_id, user_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_comment_votes (
                    comment_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    score INTEGER DEFAULT 0,
                    published INTEGER DEFAULT 0,
                    PRIMARY KEY (comment_id, user_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_subscriptions (
                    user_id TEXT NOT NULL,
                    community_id TEXT NOT NULL,
                    published INTEGER DEFAULT 0,
                    pending INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, community_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_blocks (
                    person_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    published INTEGER DEFAULT 0,
                    PRIMARY KEY (person_id, target_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_community_blocks (
                    person_id TEXT NOT NULL,
                    community_id TEXT NOT NULL,
                    published INTEGER DEFAULT 0,
                    PRIMARY KEY (person_id, community_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_mod_actions (
                    id TEXT NOT NULL PRIMARY KEY,
                    mod_person_id TEXT,
                    target_person_id TEXT,
                    community_id TEXT,
                    action TEXT,
                    reason TEXT,
                    removed INTEGER DEFAULT 0,
                    published INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_site (
                    id TEXT NOT NULL PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    sidebar TEXT,
                    enable_nsfw INTEGER DEFAULT 0,
                    enable_downvotes INTEGER DEFAULT 1,
                    open_registration INTEGER DEFAULT 1,
                    private_instance INTEGER DEFAULT 0,
                    published INTEGER DEFAULT 0,
                    actor_id TEXT,
                    last_refreshed_at INTEGER DEFAULT 0,
                    inbox_url TEXT,
                    public_key TEXT,
                    private_key TEXT,
                    default_theme TEXT DEFAULT 'darkly',
                    application_question TEXT,
                    application_email_admins INTEGER DEFAULT 0,
                    legal_information TEXT,
                    reports_email_admins INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_taglines (
                    id TEXT NOT NULL PRIMARY KEY,
                    content TEXT,
                    published INTEGER DEFAULT 0,
                    updated INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_custom_emojis (
                    id TEXT NOT NULL PRIMARY KEY,
                    shortcode TEXT NOT NULL UNIQUE,
                    image_url TEXT,
                    alt_text TEXT,
                    category TEXT,
                    published INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_reports (
                    id TEXT NOT NULL PRIMARY KEY,
                    creator_id TEXT,
                    target_id TEXT,
                    target_type TEXT,
                    reason TEXT,
                    resolved INTEGER DEFAULT 0,
                    resolver_id TEXT,
                    published INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_registration_applications (
                    id TEXT NOT NULL PRIMARY KEY,
                    user_id TEXT,
                    answer TEXT,
                    accepted INTEGER DEFAULT 0,
                    deny_reason TEXT,
                    published INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_languages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_saved_posts (
                    user_id TEXT NOT NULL,
                    post_id TEXT NOT NULL,
                    published INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, post_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_saved_comments (
                    user_id TEXT NOT NULL,
                    comment_id TEXT NOT NULL,
                    published INTEGER DEFAULT 0,
                    PRIMARY KEY (user_id, comment_id)
                )
            )");

            // Federation queue
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS lemmy_federation_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_inbox TEXT NOT NULL,
                    body TEXT NOT NULL,
                    timestamp INTEGER DEFAULT 0,
                    retry_count INTEGER DEFAULT 0,
                    sent INTEGER DEFAULT 0,
                    last_error TEXT
                )
            )");
        });
    }

    // ---------- DeltaChat tables ----------
    void create_deltachat_tables(storage::DatabasePool& db) {
        db.runInteraction("create_deltachat_tables", [](storage::LoggingTransaction& txn) {
            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT DEFAULT '',
                    display_name TEXT DEFAULT '',
                    addr TEXT DEFAULT '',
                    auth_name TEXT DEFAULT '',
                    profile_image TEXT DEFAULT '',
                    color TEXT DEFAULT '',
                    last_seen INTEGER DEFAULT 0,
                    was_seen_recently INTEGER DEFAULT 0,
                    blocked INTEGER DEFAULT 0,
                    verified INTEGER DEFAULT 0,
                    chat_id INTEGER DEFAULT 0,
                    status TEXT DEFAULT '',
                    origin INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_chats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type INTEGER DEFAULT 0,
                    name TEXT DEFAULT '',
                    grpid TEXT DEFAULT '',
                    blocking INTEGER DEFAULT 0,
                    muted_duration INTEGER DEFAULT 0,
                    ephemeral_duration INTEGER DEFAULT 0,
                    created_at INTEGER DEFAULT 0,
                    sort_timestamp INTEGER DEFAULT 0,
                    archived INTEGER DEFAULT 0,
                    protected INTEGER DEFAULT 0,
                    profile_image TEXT DEFAULT '',
                    last_msg_id INTEGER DEFAULT 0,
                    draft TEXT DEFAULT '',
                    was_seen_recently INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_chat_members (
                    chat_id INTEGER NOT NULL,
                    contact_id INTEGER NOT NULL,
                    PRIMARY KEY (chat_id, contact_id),
                    FOREIGN KEY (chat_id) REFERENCES dc_chats(id),
                    FOREIGN KEY (contact_id) REFERENCES dc_contacts(id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER NOT NULL DEFAULT 0,
                    from_id INTEGER NOT NULL DEFAULT 0,
                    to_id INTEGER NOT NULL DEFAULT 0,
                    timestamp INTEGER DEFAULT 0,
                    sort_timestamp INTEGER DEFAULT 0,
                    received_timestamp INTEGER DEFAULT 0,
                    sent_timestamp INTEGER DEFAULT 0,
                    flags INTEGER DEFAULT 0,
                    state INTEGER DEFAULT 0,
                    type INTEGER DEFAULT 0,
                    text TEXT DEFAULT '',
                    param TEXT DEFAULT '',
                    rfc724_mid TEXT DEFAULT '',
                    mime_headers TEXT DEFAULT '',
                    mime_in_reply_to TEXT DEFAULT '',
                    mime_references TEXT DEFAULT '',
                    subject TEXT DEFAULT '',
                    error TEXT DEFAULT '',
                    location_id INTEGER DEFAULT 0,
                    hidden INTEGER DEFAULT 0,
                    ephemeral_timestamp INTEGER DEFAULT 0,
                    download_state INTEGER DEFAULT 0,
                    starred INTEGER DEFAULT 0,
                    FOREIGN KEY (chat_id) REFERENCES dc_chats(id),
                    FOREIGN KEY (from_id) REFERENCES dc_contacts(id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_msgs_mdns (
                    msg_id INTEGER NOT NULL,
                    contact_id INTEGER NOT NULL,
                    timestamp_sent INTEGER DEFAULT 0,
                    PRIMARY KEY (msg_id, contact_id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_lots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER NOT NULL DEFAULT 0,
                    text1 TEXT DEFAULT '',
                    text1_meaning INTEGER DEFAULT 0,
                    text2 TEXT DEFAULT '',
                    timestamp INTEGER DEFAULT 0,
                    state INTEGER DEFAULT 0,
                    FOREIGN KEY (chat_id) REFERENCES dc_chats(id)
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_config (
                    keyname TEXT NOT NULL PRIMARY KEY,
                    value TEXT DEFAULT ''
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_keypairs (
                    addr TEXT NOT NULL PRIMARY KEY,
                    public_key TEXT DEFAULT '',
                    private_key TEXT DEFAULT '',
                    created_at INTEGER DEFAULT 0,
                    is_default INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_acpeers (
                    addr TEXT NOT NULL PRIMARY KEY,
                    public_key TEXT DEFAULT '',
                    last_seen INTEGER DEFAULT 0,
                    last_seen_autocrypt INTEGER DEFAULT 0,
                    prefer_encrypt INTEGER DEFAULT 0,
                    verified_key TEXT,
                    verified_key_fingerprint TEXT,
                    gossip_timestamp INTEGER DEFAULT 0,
                    gossip_key TEXT,
                    public_key_fingerprint TEXT
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_imap_sync (
                    folder TEXT NOT NULL PRIMARY KEY,
                    uid_validity INTEGER DEFAULT 0,
                    uid_next INTEGER DEFAULT 0,
                    last_seen_uid INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_smtp_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rfc724_mid TEXT NOT NULL,
                    mime TEXT NOT NULL,
                    recipients TEXT,
                    retry_count INTEGER DEFAULT 0,
                    last_error TEXT,
                    created_at INTEGER DEFAULT 0
                )
            )");

            txn.execute(R"(
                CREATE TABLE IF NOT EXISTS dc_webxdc (
                    msg_id INTEGER NOT NULL PRIMARY KEY,
                    name TEXT DEFAULT '',
                    icon TEXT DEFAULT '',
                    document TEXT DEFAULT '',
                    summary TEXT DEFAULT '',
                    status_updates TEXT DEFAULT '',
                    last_serial INTEGER DEFAULT 0,
                    update_timestamp INTEGER DEFAULT 0,
                    self_addr INTEGER DEFAULT 0,
                    send_update_interval_ms INTEGER DEFAULT 0
                )
            )");
        });
    }
};

// ============================================================================
// MetricsCollector - Prometheus-style metrics
// ============================================================================
class MetricsCollector {
public:
    static MetricsCollector& instance() {
        static MetricsCollector mc;
        return mc;
    }

    void increment(const std::string& name, double val = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        counters_[name] += val;
    }

    void set_gauge(const std::string& name, double val) {
        std::lock_guard<std::mutex> lock(mutex_);
        gauges_[name] = val;
    }

    void observe_histogram(const std::string& name, double val) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& h = histograms_[name];
        h.sum += val;
        h.count++;
        h.buckets[std::to_string(static_cast<int>(val))]++;
    }

    void record_request(const std::string& method, const std::string& path, int status, double duration_ms) {
        increment("http_requests_total");
        increment("http_requests_total{method=\"" + method + "\"}");
        increment("http_requests_total{path=\"" + path + "\"}");
        increment("http_requests_total{status=\"" + std::to_string(status) + "\"}");
        observe_histogram("http_request_duration_ms", duration_ms);
    }

    void record_matrix_event(const std::string& type) {
        increment("matrix_events_total");
        increment("matrix_events_total{type=\"" + type + "\"}");
    }

    void set_active_users(int64_t count) { set_gauge("users_active", static_cast<double>(count)); }
    void set_total_users(int64_t count) { set_gauge("users_total", static_cast<double>(count)); }
    void set_active_rooms(int64_t count) { set_gauge("rooms_active", static_cast<double>(count)); }
    void set_total_rooms(int64_t count) { set_gauge("rooms_total", static_cast<double>(count)); }
    void set_db_connections(int64_t count) { set_gauge("db_connections", static_cast<double>(count)); }
    void set_uptime_seconds(int64_t secs) { set_gauge("uptime_seconds", static_cast<double>(secs)); }
    void set_memory_bytes(size_t bytes) { set_gauge("memory_bytes", static_cast<double>(bytes)); }

    std::string render() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream oss;
        for (auto& [name, val] : counters_)
            oss << "# TYPE " << clean_metric_name(name) << " counter\n"
                << name << " " << static_cast<int64_t>(val) << "\n";
        for (auto& [name, val] : gauges_)
            oss << "# TYPE " << clean_metric_name(name) << " gauge\n"
                << name << " " << val << "\n";
        for (auto& [name, h] : histograms_) {
            oss << "# TYPE " << clean_metric_name(name) << " histogram\n";
            oss << name << "_sum " << h.sum << "\n";
            oss << name << "_count " << h.count << "\n";
            for (auto& [b, c] : h.buckets)
                oss << name << "_bucket{le=\"" << b << "\"} " << c << "\n";
        }
        return oss.str();
    }

private:
    MetricsCollector() = default;
    std::string clean_metric_name(const std::string& name) {
        auto pos = name.find('{');
        return pos != std::string::npos ? name.substr(0, pos) : name;
    }

    struct Histogram {
        double sum{0};
        int64_t count{0};
        std::map<std::string, int64_t> buckets;
    };

    std::mutex mutex_;
    std::map<std::string, double> counters_;
    std::map<std::string, double> gauges_;
    std::map<std::string, Histogram> histograms_;
};

// ============================================================================
// RateLimiter - Token bucket rate limiter
// ============================================================================
class RateLimiter {
public:
    RateLimiter(double burst = 50.0, double rate = 100.0)
        : default_burst_(burst), default_rate_(rate) {}

    bool is_allowed(const std::string& key, double burst = -1.0, double rate = -1.0) {
        if (!enabled_) return true;
        if (burst < 0) burst = default_burst_;
        if (rate < 0) rate = default_rate_;

        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = util::now_ms();
        auto& bucket = buckets_[key];
        if (bucket.tokens < 0) bucket.tokens = burst;

        double elapsed = (now - bucket.last_check) / 1000.0;
        bucket.tokens = std::min(burst, bucket.tokens + elapsed * rate);
        bucket.last_check = now;

        if (bucket.tokens >= 1.0) {
            bucket.tokens -= 1.0;
            return true;
        }
        bucket.denied++;
        return false;
    }

    void set_limits(const std::string& key_pattern, double burst, double rate) {
        std::lock_guard<std::mutex> lock(mutex_);
        per_endpoint_limits_[key_pattern] = {burst, rate};
    }

    void set_enabled(bool e) { enabled_ = e; }

    int64_t denied_count(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = buckets_.find(key);
        return it != buckets_.end() ? it->second.denied : 0;
    }

    void cleanup() {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = util::now_ms();
        for (auto it = buckets_.begin(); it != buckets_.end(); ) {
            if (now - it->second.last_check > 600000) // 10 min idle
                it = buckets_.erase(it);
            else
                ++it;
        }
    }

private:
    struct Bucket {
        double tokens{0};
        int64_t last_check{0};
        int64_t denied{0};
    };
    double default_burst_;
    double default_rate_;
    bool enabled_{true};
    std::mutex mutex_;
    std::map<std::string, Bucket> buckets_;
    std::map<std::string, std::pair<double,double>> per_endpoint_limits_;
};

// ============================================================================
// CORSManager - CORS header injection
// ============================================================================
class CORSManager {
public:
    CORSManager(const CORSConfig& cfg) : cfg_(cfg) {}

    void apply(std::map<std::string,std::string>& headers, const std::string& origin = "") {
        if (!cfg_.enabled) return;
        headers["Access-Control-Allow-Origin"] = cfg_.allow_origin;
        headers["Access-Control-Allow-Methods"] = cfg_.allow_methods;
        headers["Access-Control-Allow-Headers"] = cfg_.allow_headers;
        if (!cfg_.expose_headers.empty())
            headers["Access-Control-Expose-Headers"] = cfg_.expose_headers;
        headers["Access-Control-Max-Age"] = std::to_string(cfg_.max_age);
        headers["Cross-Origin-Resource-Policy"] = "cross-origin";
    }

    bool is_preflight(const std::string& method) {
        return method == "OPTIONS";
    }

    std::map<std::string,std::string> preflight_response() {
        std::map<std::string,std::string> h;
        if (!cfg_.enabled) return h;
        h["Access-Control-Allow-Origin"] = cfg_.allow_origin;
        h["Access-Control-Allow-Methods"] = cfg_.allow_methods;
        h["Access-Control-Allow-Headers"] = cfg_.allow_headers;
        h["Access-Control-Max-Age"] = std::to_string(cfg_.max_age);
        h["Content-Length"] = "0";
        return h;
    }

private:
    CORSConfig cfg_;
};

// ============================================================================
// HealthChecker - health check endpoint handler
// ============================================================================
class HealthChecker {
public:
    HealthChecker() : start_time_(util::now_sec()) {}

    json check() {
        json result;
        result["status"] = "ok";
        result["uptime_seconds"] = util::now_sec() - start_time_;
        result["version"] = "0.1.0";
        result["timestamp"] = util::iso8601(util::now_ms());

        // Sub-component health
        json components;
        components["matrix"] = matrix_ok_ ? "ok" : "degraded";
        components["irc"] = irc_ok_ ? "ok" : "disabled";
        components["xmpp"] = xmpp_ok_ ? "ok" : "disabled";
        components["lemmy"] = lemmy_ok_ ? "ok" : "disabled";
        components["deltachat"] = deltachat_ok_ ? "ok" : "disabled";
        components["federation"] = federation_ok_ ? "ok" : "degraded";
        components["database"] = db_ok_ ? "ok" : "error";
        result["components"] = components;

        return result;
    }

    void set_matrix_ok(bool ok) { matrix_ok_ = ok; }
    void set_irc_ok(bool ok) { irc_ok_ = ok; }
    void set_xmpp_ok(bool ok) { xmpp_ok_ = ok; }
    void set_lemmy_ok(bool ok) { lemmy_ok_ = ok; }
    void set_deltachat_ok(bool ok) { deltachat_ok_ = ok; }
    void set_federation_ok(bool ok) { federation_ok_ = ok; }
    void set_db_ok(bool ok) { db_ok_ = ok; }

private:
    int64_t start_time_;
    std::atomic<bool> matrix_ok_{true};
    std::atomic<bool> irc_ok_{false};
    std::atomic<bool> xmpp_ok_{false};
    std::atomic<bool> lemmy_ok_{false};
    std::atomic<bool> deltachat_ok_{false};
    std::atomic<bool> federation_ok_{true};
    std::atomic<bool> db_ok_{true};
};

// ============================================================================
// BackgroundTaskScheduler - periodic background tasks
// ============================================================================
class BackgroundTaskScheduler {
public:
    BackgroundTaskScheduler(const BackgroundTasksConfig& cfg) : cfg_(cfg) {}

    void start() {
        if (running_) return;
        running_ = true;
        LOG_INFO("bg", "Background task scheduler starting");

        if (cfg_.presence_cleanup_enabled) {
            tasks_.emplace_back([this]() { presence_cleanup_loop(); });
        }
        if (cfg_.ephemeral_cleanup_enabled) {
            tasks_.emplace_back([this]() { ephemeral_cleanup_loop(); });
        }
        if (cfg_.expired_media_enabled) {
            tasks_.emplace_back([this]() { expired_media_cleanup_loop(); });
        }
        if (cfg_.federation_retry_enabled) {
            tasks_.emplace_back([this]() { federation_retry_loop(); });
        }
        if (cfg_.stats_aggregation_enabled) {
            tasks_.emplace_back([this]() { stats_aggregation_loop(); });
        }
        tasks_.emplace_back([this]() { metrics_flush_loop(); });
        tasks_.emplace_back([this]() { rate_limit_cleanup_loop(); });

        for (auto& task_func : tasks_) {
            threads_.emplace_back(task_func);
        }
    }

    void stop() {
        running_ = false;
        for (auto& t : threads_) {
            if (t.joinable()) t.join();
        }
        threads_.clear();
        tasks_.clear();
        LOG_INFO("bg", "Background task scheduler stopped");
    }

    void set_presence_cleanup_fn(std::function<void()> fn) { presence_cleanup_fn_ = std::move(fn); }
    void set_ephemeral_cleanup_fn(std::function<void()> fn) { ephemeral_cleanup_fn_ = std::move(fn); }
    void set_expired_media_fn(std::function<void()> fn) { expired_media_fn_ = std::move(fn); }
    void set_federation_retry_fn(std::function<void()> fn) { federation_retry_fn_ = std::move(fn); }
    void set_stats_aggregation_fn(std::function<void()> fn) { stats_aggregation_fn_ = std::move(fn); }

private:
    void presence_cleanup_loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.presence_cleanup_interval_ms));
            if (!running_) break;
            try {
                LOG_TRACE("bg", "Running presence cleanup");
                MetricsCollector::instance().increment("background_tasks_presence_cleanup_total");
                if (presence_cleanup_fn_) presence_cleanup_fn_();
            } catch (const std::exception& e) {
                LOG_ERROR("bg", std::string("Presence cleanup error: ") + e.what());
            }
        }
    }

    void ephemeral_cleanup_loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.ephemeral_cleanup_interval_ms));
            if (!running_) break;
            try {
                LOG_TRACE("bg", "Running ephemeral message cleanup");
                MetricsCollector::instance().increment("background_tasks_ephemeral_cleanup_total");
                if (ephemeral_cleanup_fn_) ephemeral_cleanup_fn_();
            } catch (const std::exception& e) {
                LOG_ERROR("bg", std::string("Ephemeral cleanup error: ") + e.what());
            }
        }
    }

    void expired_media_cleanup_loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.expired_media_cleanup_interval_ms));
            if (!running_) break;
            try {
                LOG_TRACE("bg", "Running expired media cleanup");
                MetricsCollector::instance().increment("background_tasks_media_cleanup_total");
                if (expired_media_fn_) expired_media_fn_();
            } catch (const std::exception& e) {
                LOG_ERROR("bg", std::string("Media cleanup error: ") + e.what());
            }
        }
    }

    void federation_retry_loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.federation_retry_interval_ms));
            if (!running_) break;
            try {
                LOG_TRACE("bg", "Running federation retry");
                MetricsCollector::instance().increment("background_tasks_federation_retry_total");
                if (federation_retry_fn_) federation_retry_fn_();
            } catch (const std::exception& e) {
                LOG_ERROR("bg", std::string("Federation retry error: ") + e.what());
            }
        }
    }

    void stats_aggregation_loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg_.stats_aggregation_interval_ms));
            if (!running_) break;
            try {
                LOG_TRACE("bg", "Running stats aggregation");
                MetricsCollector::instance().increment("background_tasks_stats_aggregation_total");
                if (stats_aggregation_fn_) stats_aggregation_fn_();
            } catch (const std::exception& e) {
                LOG_ERROR("bg", std::string("Stats aggregation error: ") + e.what());
            }
        }
    }

    void metrics_flush_loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            if (!running_) break;
            try {
                auto s = MetricsCollector::instance().render();
                // Could persist to a file or push to a gateway
                LOG_TRACE("bg", "Metrics snapshot: " + std::to_string(s.size()) + " bytes");
            } catch (...) {}
        }
    }

    void rate_limit_cleanup_loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::minutes(5));
            if (!running_) break;
            // cleanup is handled by the RateLimiter instance
        }
    }

    BackgroundTasksConfig cfg_;
    std::atomic<bool> running_{false};
    std::vector<std::function<void()>> tasks_;
    std::vector<std::thread> threads_;

    std::function<void()> presence_cleanup_fn_;
    std::function<void()> ephemeral_cleanup_fn_;
    std::function<void()> expired_media_fn_;
    std::function<void()> federation_retry_fn_;
    std::function<void()> stats_aggregation_fn_;
};

// ============================================================================
// ListenerManager - manages all network listeners
// ============================================================================
class ListenerManager {
public:
    ListenerManager(const ServerConfig& cfg, storage::DatabasePool& db)
        : cfg_(cfg), db_(db) {}

    void setup_all() {
        LOG_INFO("listeners", "Setting up listeners...");

        // Matrix HTTP listener (default port 8008)
        setup_matrix_http_listener();

        // Federation listener (default port 8448)
        setup_federation_listener();

        // IRC listeners (ports 6667-6669)
        if (cfg_.irc.enabled) {
            setup_irc_listeners();
        }

        // XMPP listeners
        if (cfg_.xmpp.enabled) {
            setup_xmpp_listeners();
        }

        // Lemmy HTTPS listener
        if (cfg_.lemmy.enabled) {
            setup_lemmy_listener();
        }

        // DeltaChat IMAP/SMTP relay
        if (cfg_.deltachat.enabled) {
            setup_deltachat_relay();
        }

        // Metrics listener
        if (cfg_.metrics.enabled) {
            setup_metrics_listener();
        }

        // Custom listeners from config
        for (auto& l : cfg_.listeners.listeners) {
            setup_custom_listener(l);
        }

        LOG_INFO("listeners", "All listeners configured");
    }

    void start_all() {
        LOG_INFO("listeners", "Starting all listeners...");
        for (auto& t : listener_threads_) {
            if (t.joinable()) t.detach();
        }
        listener_threads_.clear();

        // IRC
        if (irc_server_) {
            listener_threads_.emplace_back([this]() {
                for (int port : cfg_.irc.ports) {
                    irc_server_->start(port);
                }
            });
        }

        // XMPP
        if (xmpp_server_) {
            listener_threads_.emplace_back([this]() {
                xmpp_server_->start(cfg_.xmpp.c2s_port, cfg_.xmpp.s2s_port, cfg_.xmpp.http_port);
            });
        }

        // Lemmy
        if (lemmy_server_) {
            listener_threads_.emplace_back([this]() {
                lemmy_server_->start(cfg_.lemmy.port);
            });
        }

        LOG_INFO("listeners", "All listeners started");
    }

    void stop_all() {
        LOG_INFO("listeners", "Stopping all listeners...");
        if (irc_server_) irc_server_->stop();
        if (xmpp_server_) xmpp_server_->stop();
        if (lemmy_server_) lemmy_server_->stop();
        if (deltachat_) deltachat_->stop_io();
        LOG_INFO("listeners", "All listeners stopped");
    }

    // Accessors
    progressive::irc::IRCServer* irc() { return irc_server_.get(); }
    progressive::xmpp::XMPPServer* xmpp() { return xmpp_server_.get(); }
    progressive::lemmy::LemmyServer* lemmy() { return lemmy_server_.get(); }
    progressive::deltachat::DeltaChat* deltachat() { return deltachat_.get(); }

private:
    const ServerConfig& cfg_;
    storage::DatabasePool& db_;
    std::vector<std::thread> listener_threads_;

    std::unique_ptr<progressive::irc::IRCServer> irc_server_;
    std::unique_ptr<progressive::xmpp::XMPPServer> xmpp_server_;
    std::unique_ptr<progressive::lemmy::LemmyServer> lemmy_server_;
    std::unique_ptr<progressive::deltachat::DeltaChat> deltachat_;
    std::vector<int> matrix_fds_;
    std::vector<int> other_fds_;

    void setup_matrix_http_listener() {
        // The Matrix HTTP listener is created separately by the HTTP server.
        // This method sets up socket file descriptors for raw socket listening
        // as a fallback/alternative.
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            LOG_WARN("listeners", "Cannot create Matrix HTTP socket");
            return;
        }
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(8008);
        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            LOG_WARN("listeners", "Cannot bind Matrix HTTP on port 8008: " +
                     std::string(strerror(errno)));
            close(fd);
            return;
        }
        listen(fd, SOMAXCONN);
        matrix_fds_.push_back(fd);
        LOG_INFO("listeners", "Matrix HTTP listener on port 8008");
    }

    void setup_federation_listener() {
        if (!cfg_.federation.enabled) return;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return;
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(cfg_.federation.port);
        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            LOG_WARN("listeners", "Cannot bind federation on port " +
                     std::to_string(cfg_.federation.port) + ": " + std::string(strerror(errno)));
            close(fd);
            return;
        }
        listen(fd, SOMAXCONN);
        other_fds_.push_back(fd);
        LOG_INFO("listeners", "Federation listener on port " + std::to_string(cfg_.federation.port));
    }

    void setup_irc_listeners() {
        irc_server_ = std::make_unique<progressive::irc::IRCServer>(
            cfg_.irc.server_name, cfg_.irc.description, cfg_.irc.network_name);
        irc_server_->config().server_name = cfg_.irc.server_name;
        irc_server_->config().description = cfg_.irc.description;
        irc_server_->config().network_name = cfg_.irc.network_name;
        irc_server_->config().max_channels = cfg_.irc.max_channels_per_user;
        irc_server_->config().max_nick_length = cfg_.irc.max_nick_length;
        irc_server_->config().max_topic_length = cfg_.irc.max_topic_length;
        irc_server_->config().server_password = cfg_.irc.server_password;
        irc_server_->config().allow_remote_oper = cfg_.irc.allow_remote_oper;

        for (int port : cfg_.irc.ports) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) continue;
            int opt = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(port);
            if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                LOG_WARN("listeners", "Cannot bind IRC on port " + std::to_string(port));
                close(fd);
                continue;
            }
            listen(fd, SOMAXCONN);
            other_fds_.push_back(fd);
            LOG_INFO("listeners", "IRC listener on port " + std::to_string(port));
        }
    }

    void setup_xmpp_listeners() {
        xmpp_server_ = std::make_unique<progressive::xmpp::XMPPServer>(cfg_.xmpp.domain);
        xmpp_server_->config().domain = cfg_.xmpp.domain;
        xmpp_server_->config().server_name = cfg_.xmpp.server_name;
        xmpp_server_->config().c2s_port = cfg_.xmpp.c2s_port;
        xmpp_server_->config().s2s_port = cfg_.xmpp.s2s_port;
        xmpp_server_->config().registration_enabled = cfg_.xmpp.registration_enabled;
        xmpp_server_->config().s2s_enabled = cfg_.xmpp.s2s_enabled;
        xmpp_server_->config().websocket_enabled = cfg_.xmpp.websocket_enabled;

        // C2S listener
        {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd >= 0) {
                int opt = 1;
                setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
                struct sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = INADDR_ANY;
                addr.sin_port = htons(cfg_.xmpp.c2s_port);
                if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    listen(fd, SOMAXCONN);
                    other_fds_.push_back(fd);
                    LOG_INFO("listeners", "XMPP c2s listener on port " + std::to_string(cfg_.xmpp.c2s_port));
                } else {
                    close(fd);
                    LOG_WARN("listeners", "Cannot bind XMPP c2s on port " + std::to_string(cfg_.xmpp.c2s_port));
                }
            }
        }

        // S2S listener
        if (cfg_.xmpp.s2s_enabled) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd >= 0) {
                int opt = 1;
                setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
                struct sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = INADDR_ANY;
                addr.sin_port = htons(cfg_.xmpp.s2s_port);
                if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    listen(fd, SOMAXCONN);
                    other_fds_.push_back(fd);
                    LOG_INFO("listeners", "XMPP s2s listener on port " + std::to_string(cfg_.xmpp.s2s_port));
                } else {
                    close(fd);
                    LOG_WARN("listeners", "Cannot bind XMPP s2s on port " + std::to_string(cfg_.xmpp.s2s_port));
                }
            }
        }
    }

    void setup_lemmy_listener() {
        lemmy_server_ = std::make_unique<progressive::lemmy::LemmyServer>(cfg_.lemmy.hostname);
        lemmy_server_->config().hostname = cfg_.lemmy.hostname;
        lemmy_server_->config().name = cfg_.lemmy.site_name;
        lemmy_server_->config().description = cfg_.lemmy.site_description;
        lemmy_server_->config().port = cfg_.lemmy.port;
        lemmy_server_->config().registration_enabled = cfg_.lemmy.registration_enabled;
        lemmy_server_->config().private_instance = cfg_.lemmy.private_instance;

        // Set up a raw listener for the Lemmy API
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            int opt = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(cfg_.lemmy.port);
            if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                listen(fd, SOMAXCONN);
                other_fds_.push_back(fd);
                LOG_INFO("listeners", "Lemmy HTTP listener on port " + std::to_string(cfg_.lemmy.port));
            } else {
                close(fd);
                LOG_WARN("listeners", "Cannot bind Lemmy on port " + std::to_string(cfg_.lemmy.port));
            }
        }
    }

    void setup_deltachat_relay() {
        deltachat_ = std::make_unique<progressive::deltachat::DeltaChat>(cfg_.deltachat.dbfile);
        deltachat_->config().dbfile = cfg_.deltachat.dbfile;
        deltachat_->config().addr = cfg_.deltachat.addr;
        deltachat_->config().mail_pw = cfg_.deltachat.mail_pw;
        deltachat_->config().imap_server = cfg_.deltachat.imap_server;
        deltachat_->config().imap_port = cfg_.deltachat.imap_port;
        deltachat_->config().imap_security = cfg_.deltachat.imap_security;
        deltachat_->config().smtp_server = cfg_.deltachat.smtp_server;
        deltachat_->config().smtp_port = cfg_.deltachat.smtp_port;
        deltachat_->config().smtp_security = cfg_.deltachat.smtp_security;
        deltachat_->config().e2ee_enabled = cfg_.deltachat.e2ee_enabled;

        if (!cfg_.deltachat.addr.empty()) {
            deltachat_->open();
            deltachat_->start_io();
            LOG_INFO("listeners", "DeltaChat IMAP/SMTP relay started for " + cfg_.deltachat.addr);
        } else {
            LOG_INFO("listeners", "DeltaChat relay configured but not started (no addr)");
        }
    }

    void setup_metrics_listener() {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            LOG_WARN("listeners", "Cannot create metrics socket");
            return;
        }
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(cfg_.metrics.port);
        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            LOG_WARN("listeners", "Cannot bind metrics on port " +
                     std::to_string(cfg_.metrics.port) + ": " + std::string(strerror(errno)));
            close(fd);
            return;
        }
        listen(fd, SOMAXCONN);
        other_fds_.push_back(fd);
        LOG_INFO("listeners", "Metrics listener on port " + std::to_string(cfg_.metrics.port));
    }

    void setup_custom_listener(const ListenersConfig::Listener& l) {
        if (l.type == "http") {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) return;
            int opt = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            inet_pton(AF_INET, l.bind_address.c_str(), &addr.sin_addr);
            addr.sin_port = htons(l.port);
            if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                LOG_WARN("listeners", "Cannot bind custom HTTP on " + l.bind_address + ":" +
                         std::to_string(l.port));
                close(fd);
                return;
            }
            listen(fd, SOMAXCONN);
            other_fds_.push_back(fd);
            LOG_INFO("listeners", "Custom HTTP listener on " + l.bind_address + ":" +
                     std::to_string(l.port) + " (" + l.resource + ")");
        } else if (l.type == "unix") {
            int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) return;
            unlink(l.unix_socket_path.c_str());
            struct sockaddr_un addr{};
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, l.unix_socket_path.c_str(), sizeof(addr.sun_path) - 1);
            if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                LOG_WARN("listeners", "Cannot bind unix socket: " + l.unix_socket_path);
                close(fd);
                return;
            }
            listen(fd, SOMAXCONN);
            chmod(l.unix_socket_path.c_str(), 0666);
            other_fds_.push_back(fd);
            LOG_INFO("listeners", "UNIX socket listener at " + l.unix_socket_path);
        }
    }
};

// ============================================================================
// HTTP Request/Response helpers for built-in HTTP handling
// ============================================================================
namespace http_helpers {

struct SimpleRequest {
    std::string method;
    std::string path;
    std::string body;
    std::map<std::string,std::string> headers;
    std::string client_ip;
};

struct SimpleResponse {
    int code{200};
    std::string body;
    std::string content_type{"application/json"};
    std::map<std::string,std::string> headers;
};

std::string read_http_request(int fd, int timeout_ms = 5000) {
    std::string data;
    char buf[16384];
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) return data;
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        data = buf;
    }
    return data;
}

SimpleRequest parse_http_request(const std::string& raw) {
    SimpleRequest req;
    std::istringstream iss(raw);
    std::string line;
    // Request line
    if (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream rl(line);
        rl >> req.method >> req.path;
    }
    // Headers
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            // trim val
            auto start = val.find_first_not_of(" \t");
            if (start != std::string::npos) val = val.substr(start);
            req.headers[util::to_lower(key)] = val;
        }
    }
    // Body (remaining)
    std::string rest;
    std::getline(iss, rest, '\0');
    // Actually read the rest
    std::ostringstream body_oss;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        body_oss << line << "\n";
    }
    req.body = body_oss.str();
    if (!rest.empty() && req.body.empty()) req.body = rest;
    return req;
}

std::string build_http_response(const SimpleResponse& resp) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << resp.code << " ";
    switch (resp.code) {
        case 200: oss << "OK"; break;
        case 201: oss << "Created"; break;
        case 204: oss << "No Content"; break;
        case 400: oss << "Bad Request"; break;
        case 401: oss << "Unauthorized"; break;
        case 403: oss << "Forbidden"; break;
        case 404: oss << "Not Found"; break;
        case 405: oss << "Method Not Allowed"; break;
        case 429: oss << "Too Many Requests"; break;
        case 500: oss << "Internal Server Error"; break;
        case 503: oss << "Service Unavailable"; break;
        default: oss << "Unknown"; break;
    }
    oss << "\r\n";
    resp.headers.count("Content-Type") ? void() : oss << "Content-Type: " << resp.content_type << "\r\n";
    oss << "Content-Length: " << resp.body.size() << "\r\n";
    oss << "Connection: close\r\n";
    for (auto& [k, v] : resp.headers) oss << k << ": " << v << "\r\n";
    oss << "\r\n";
    oss << resp.body;
    return oss.str();
}

} // namespace http_helpers

// ============================================================================
// ProgressiveServer - main server class tying all protocols together
// ============================================================================
class ProgressiveServer {
public:
    ProgressiveServer(const std::string& config_path)
        : config_path_(config_path)
    {
        start_time_ = util::now_sec();
    }

    ~ProgressiveServer() {
        shutdown();
    }

    // ---------- Lifecycle ----------

    void initialize() {
        LOG_INFO("server", "=== ProgressiveServer v" + cfg_.version + " initializing ===");

        // 1. Load config
        ConfigManager cm(config_path_);
        cfg_ = cm.load();

        // 2. Configure logging
        LogManager::instance().configure(cfg_.log_level, cfg_.log_file);
        LOG_INFO("server", "Logging initialized at level " + cfg_.log_level);

        // 3. Create data directory
        std::filesystem::create_directories(cfg_.data_dir);
        std::filesystem::create_directories(cfg_.media_store_path);

        // 4. Initialize databases
        db_mgr_ = std::make_unique<DatabaseManager>(cfg_);
        db_mgr_->initialize_all();

        // 5. Initialize rate limiter
        rate_limiter_ = std::make_unique<RateLimiter>(
            cfg_.rate_limit.default_burst, cfg_.rate_limit.default_rate);
        rate_limiter_->set_enabled(cfg_.rate_limit.enabled);
        for (auto& [endpoint, limits] : cfg_.rate_limit.per_endpoint) {
            rate_limiter_->set_limits(endpoint, limits.first, limits.second);
        }

        // 6. Initialize CORS manager
        cors_mgr_ = std::make_unique<CORSManager>(cfg_.cors);

        // 7. Initialize health checker
        health_checker_ = std::make_unique<HealthChecker>();
        health_checker_->set_db_ok(true);

        // 8. Initialize federation transport
        if (cfg_.federation.enabled) {
            fed_transport_ = std::make_unique<progressive::federation::FederationTransport>(db_mgr_->main());
        }

        // 9. Set up listeners
        listener_mgr_ = std::make_unique<ListenerManager>(cfg_, db_mgr_->main());
        listener_mgr_->setup_all();

        // 10. Initialize background tasks
        bg_scheduler_ = std::make_unique<BackgroundTaskScheduler>(cfg_.background_tasks);

        // Wire up background task implementations
        bg_scheduler_->set_presence_cleanup_fn([this]() { cleanup_presence(); });
        bg_scheduler_->set_ephemeral_cleanup_fn([this]() { cleanup_ephemeral_messages(); });
        bg_scheduler_->set_expired_media_fn([this]() { cleanup_expired_media(); });
        bg_scheduler_->set_federation_retry_fn([this]() { retry_federation(); });
        bg_scheduler_->set_stats_aggregation_fn([this]() { aggregate_stats(); });

        // 11. Register signal handlers
        setup_signal_handlers();

        // 12. Initialize HTTP endpoint routing table
        initialize_routes();

        // 13. Preload metrics
        MetricsCollector::instance().set_gauge("server_version", 0.1);
        MetricsCollector::instance().set_gauge("server_start_time_seconds", start_time_);

        LOG_INFO("server", "=== Initialization complete ===");
    }

    void start() {
        LOG_INFO("server", "Starting ProgressiveServer...");
        running_ = true;

        // Start listeners
        listener_mgr_->start_all();

        // Start background tasks
        bg_scheduler_->start();

        // Start the main event loop for HTTP/Metrics listeners
        start_event_loop();

        LOG_INFO("server", "ProgressiveServer is running");
    }

    void run() {
        initialize();
        start();
        // Run the main loop until shutdown
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    void shutdown() {
        if (!running_) return;
        LOG_INFO("server", "Shutting down...");
        running_ = false;

        if (bg_scheduler_) bg_scheduler_->stop();
        if (listener_mgr_) listener_mgr_->stop_all();

        // Close all sockets
        for (auto& [fd, _] : client_connections_) close(fd);
        client_connections_.clear();

        LOG_INFO("server", "Shutdown complete. Uptime: " +
                 std::to_string(util::now_sec() - start_time_) + "s");
    }

    // ---------- Config access ----------
    ServerConfig& config() { return cfg_; }

    // ---------- Metrics access ----------
    std::string metrics() { return MetricsCollector::instance().render(); }

    // ---------- Health check ----------
    json health() { return health_checker_->check(); }

    // ---------- Rate limit check ----------
    bool check_rate_limit(const std::string& key, const std::string& path = "") {
        if (cfg_.rate_limit.enabled && path.empty()) {
            return rate_limiter_->is_allowed(key);
        }
        auto it = cfg_.rate_limit.per_endpoint.find(path);
        if (it != cfg_.rate_limit.per_endpoint.end()) {
            return rate_limiter_->is_allowed(key, it->second.first, it->second.second);
        }
        return rate_limiter_->is_allowed(key);
    }

private:
    // ========================================================================
    // Signal handling
    // ========================================================================
    void setup_signal_handlers() {
        struct sigaction sa{};
        sa.sa_handler = [](int sig) {
            switch (sig) {
                case SIGINT:
                case SIGTERM:
                    LOG_INFO("signal", "Received signal " + std::to_string(sig) + ", initiating shutdown");
                    instance_ ? instance_->shutdown() : void();
                    break;
                case SIGHUP:
                    LOG_INFO("signal", "Received SIGHUP, reloading configuration");
                    break;
                case SIGUSR1:
                    LOG_INFO("signal", "Received SIGUSR1, rotating logs");
                    break;
                case SIGUSR2:
                    LOG_INFO("signal", "Received SIGUSR2, dumping metrics");
                    if (instance_) {
                        std::cout << instance_->metrics() << std::endl;
                    }
                    break;
            }
        };
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGHUP, &sa, nullptr);
        sigaction(SIGUSR1, &sa, nullptr);
        sigaction(SIGUSR2, &sa, nullptr);
        signal(SIGPIPE, SIG_IGN);
        instance_ = this;
    }

    // ========================================================================
    // HTTP route initialization
    // ========================================================================
    void initialize_routes() {
        // GET /_matrix/client/versions
        routes_["GET /_matrix/client/versions"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["versions"] = {"r0.6.1", "v1.1", "v1.2", "v1.3", "v1.4", "v1.5"};
            resp["unstable_features"] = json::object();
            return build_json_response(200, resp);
        };

        // GET /_matrix/client/v3/login
        routes_["GET /_matrix/client/v3/login"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["flows"] = json::array({json::object({{"type", "m.login.password"}})});
            return build_json_response(200, resp);
        };

        // GET /_matrix/client/v3/capabilities
        routes_["GET /_matrix/client/v3/capabilities"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["capabilities"] = json::object({
                {"m.room_versions", json::object({
                    {"default", cfg_.matrix.default_room_version},
                    {"available", json::object({
                        {"1", "stable"}, {"2", "stable"}, {"3", "stable"},
                        {"4", "stable"}, {"5", "stable"}, {"6", "stable"},
                        {"7", "stable"}, {"8", "stable"}, {"9", "stable"},
                        {"10", "stable"}
                    })}
                })},
                {"m.change_password", json::object({{"enabled", true}})},
                {"m.set_displayname", json::object({{"enabled", true}})},
                {"m.set_avatar_url", json::object({{"enabled", true}})},
                {"m.3pid_changes", json::object({{"enabled", cfg_.matrix.enable_3pid_lookup}})}
            });
            return build_json_response(200, resp);
        };

        // GET /_matrix/federation/v1/version
        routes_["GET /_matrix/federation/v1/version"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["server"] = json::object({
                {"name", "Progressive"},
                {"version", cfg_.version}
            });
            return build_json_response(200, resp);
        };

        // GET /health
        routes_["GET /health"] = [this](const http_helpers::SimpleRequest& req) {
            return build_json_response(200, health());
        };

        // GET /metrics
        routes_["GET /metrics"] = [this](const http_helpers::SimpleRequest& req) {
            http_helpers::SimpleResponse resp;
            resp.code = 200;
            resp.content_type = "text/plain; version=0.0.4";
            resp.body = metrics();
            return resp;
        };

        // GET /_matrix/static/ (well-known)
        routes_["GET /_matrix/static/"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["m.homeserver"] = json::object({
                {"base_url", cfg_.matrix.public_baseurl}
            });
            return build_json_response(200, resp);
        };

        // GET /.well-known/matrix/server
        routes_["GET /.well-known/matrix/server"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["m.server"] = cfg_.matrix.server_name + ":8448";
            return build_json_response(200, resp);
        };

        // GET /.well-known/matrix/client
        routes_["GET /.well-known/matrix/client"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["m.homeserver"] = json::object({
                {"base_url", cfg_.matrix.public_baseurl}
            });
            resp["m.identity_server"] = json::object({
                {"base_url", cfg_.matrix.public_baseurl}
            });
            return build_json_response(200, resp);
        };

        // GET /_matrix/client/v3/sync (stub)
        routes_["GET /_matrix/client/v3/sync"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["next_batch"] = "s" + std::to_string(util::now_ms());
            resp["rooms"] = json::object({
                {"join", json::object()},
                {"invite", json::object()},
                {"leave", json::object()}
            });
            resp["presence"] = json::object({{"events", json::array()}});
            resp["account_data"] = json::object({{"events", json::array()}});
            resp["to_device"] = json::object({{"events", json::array()}});
            resp["device_lists"] = json::object({{"changed", json::array()}, {"left", json::array()}});
            resp["device_one_time_keys_count"] = json::object();
            return build_json_response(200, resp);
        };

        // POST /_matrix/client/v3/logout
        routes_["POST /_matrix/client/v3/logout"] = [this](const http_helpers::SimpleRequest& req) {
            return build_json_response(200, json::object());
        };

        // POST /_matrix/client/v3/logout/all
        routes_["POST /_matrix/client/v3/logout/all"] = [this](const http_helpers::SimpleRequest& req) {
            return build_json_response(200, json::object());
        };

        // GET /_matrix/client/v3/profile/{userId}
        routes_["GET /_matrix/client/v3/profile/"] = [this](const http_helpers::SimpleRequest& req) {
            // Simplified - extracts userId from path
            std::string path = req.path;
            auto pos = path.find("/profile/");
            std::string user_id = path.substr(pos + 9);
            auto slash = user_id.find('/');
            if (slash != std::string::npos) user_id = user_id.substr(0, slash);

            json resp;
            resp["displayname"] = user_id;
            return build_json_response(200, resp);
        };

        // GET /_matrix/client/v3/joined_rooms
        routes_["GET /_matrix/client/v3/joined_rooms"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["joined_rooms"] = json::array();
            return build_json_response(200, resp);
        };

        // GET /_matrix/client/v3/publicRooms
        routes_["GET /_matrix/client/v3/publicRooms"] = [this](const http_helpers::SimpleRequest& req) {
            json resp;
            resp["chunk"] = json::array();
            resp["next_batch"] = json(nullptr);
            resp["prev_batch"] = json(nullptr);
            resp["total_room_count_estimate"] = 0;
            return build_json_response(200, resp);
        };

        // Default 404
        routes_["__default__"] = [this](const http_helpers::SimpleRequest& req) {
            json err;
            err["errcode"] = "M_UNRECOGNIZED";
            err["error"] = "Unrecognized request";
            return build_json_response(404, err);
        };

        LOG_INFO("routes", "HTTP routes initialized (" +
                 std::to_string(routes_.size()) + " routes)");
    }

    // ========================================================================
    // HTTP request routing
    // ========================================================================
    http_helpers::SimpleResponse route_http_request(const http_helpers::SimpleRequest& req) {
        // Apply CORS headers
        http_helpers::SimpleResponse resp;

        // Check rate limit
        std::string rate_key = req.client_ip;
        if (!check_rate_limit(rate_key, req.path)) {
            json err;
            err["errcode"] = "M_LIMIT_EXCEEDED";
            err["error"] = "Too many requests";
            err["retry_after_ms"] = 1000;
            MetricsCollector::instance().increment("http_requests_rate_limited_total");
            return build_json_response(429, err);
        }

        // Handle OPTIONS (CORS preflight)
        if (req.method == "OPTIONS") {
            resp.code = 204;
            resp.body = "";
            cors_mgr_->apply(resp.headers);
            return resp;
        }

        auto start = util::now_ms();

        // Try exact match
        std::string route_key = req.method + " " + req.path;
        auto it = routes_.find(route_key);
        if (it != routes_.end()) {
            resp = it->second(req);
        } else {
            // Try prefix matching
            bool matched = false;
            for (auto& [pattern, handler] : routes_) {
                if (pattern == "__default__") continue;
                if (req.path.size() >= pattern.size() - req.method.size() - 1 &&
                    req.path.substr(0, pattern.size() - req.method.size() - 1) ==
                        pattern.substr(req.method.size() + 1) &&
                    pattern[pattern.size()-1] == '/') {
                    resp = handler(req);
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                auto dit = routes_.find("__default__");
                if (dit != routes_.end()) resp = dit->second(req);
                else {
                    json err;
                    err["errcode"] = "M_UNRECOGNIZED";
                    err["error"] = "Unrecognized request";
                    resp = build_json_response(404, err);
                }
            }
        }

        // Apply CORS
        cors_mgr_->apply(resp.headers);

        // Record metrics
        auto duration = util::now_ms() - start;
        MetricsCollector::instance().record_request(req.method, req.path, resp.code, duration);

        return resp;
    }

    // ========================================================================
    // Event loop for HTTP request handling
    // ========================================================================
    void start_event_loop() {
        event_loop_thread_ = std::thread([this]() {
            LOG_INFO("eventloop", "Event loop started");
            while (running_) {
                // Build fd set
                std::vector<struct pollfd> pfds;

                // Add Matrix HTTP listener fds
                for (int fd : matrix_fds()) {
                    struct pollfd pfd{};
                    pfd.fd = fd;
                    pfd.events = POLLIN;
                    pfds.push_back(pfd);
                }

                // Add other listener fds (federation, metrics, etc.)
                for (int fd : other_fds()) {
                    struct pollfd pfd{};
                    pfd.fd = fd;
                    pfd.events = POLLIN;
                    pfds.push_back(pfd);
                }

                // Add connected client fds
                for (auto& [fd, conn] : client_connections_) {
                    struct pollfd pfd{};
                    pfd.fd = fd;
                    pfd.events = POLLIN;
                    pfds.push_back(pfd);
                }

                if (pfds.empty()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }

                int ret = poll(pfds.data(), pfds.size(), 100);
                if (ret < 0) {
                    if (errno == EINTR) continue;
                    LOG_ERROR("eventloop", "poll error: " + std::string(strerror(errno)));
                    break;
                }
                if (ret == 0) continue;

                for (auto& pfd : pfds) {
                    if (!(pfd.revents & POLLIN)) continue;

                    bool is_listener = false;
                    for (int fd : matrix_fds()) { if (pfd.fd == fd) { is_listener = true; break; } }
                    if (!is_listener) {
                        for (int fd : other_fds()) { if (pfd.fd == fd) { is_listener = true; break; } }
                    }

                    if (is_listener) {
                        accept_client(pfd.fd);
                    } else {
                        handle_client(pfd.fd);
                    }
                }
            }
            LOG_INFO("eventloop", "Event loop stopped");
        });
    }

    void accept_client(int server_fd) {
        struct sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                LOG_WARN("eventloop", "accept failed: " + std::string(strerror(errno)));
            return;
        }

        // Set non-blocking
        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

        // Set TCP_NODELAY
        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));

        ClientConnection conn;
        conn.fd = client_fd;
        conn.ip = ip_str;
        conn.connected_at = util::now_ms();
        client_connections_[client_fd] = conn;

        MetricsCollector::instance().increment("http_connections_total");
        MetricsCollector::instance().set_gauge("http_connections_active",
            static_cast<double>(client_connections_.size()));

        LOG_TRACE("http", "Accepted connection from " + conn.ip);
    }

    void handle_client(int fd) {
        auto it = client_connections_.find(fd);
        if (it == client_connections_.end()) return;

        char buf[65536];
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
            close(fd);
            client_connections_.erase(it);
            MetricsCollector::instance().set_gauge("http_connections_active",
                static_cast<double>(client_connections_.size()));
            return;
        }
        buf[n] = '\0';
        it->second.buffer += std::string(buf, n);

        // Check for complete HTTP request (ends with \r\n\r\n)
        auto header_end = it->second.buffer.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            // Request not complete yet
            if (it->second.buffer.size() > 1048576) {
                // Too large, drop
                close(fd);
                client_connections_.erase(it);
            }
            return;
        }

        auto req = http_helpers::parse_http_request(it->second.buffer);
        req.client_ip = it->second.ip;

        // Check Content-Length for body completeness
        auto cl_it = req.headers.find("content-length");
        if (cl_it != req.headers.end()) {
            int64_t content_length = std::stoll(cl_it->second);
            std::string header_part = it->second.buffer.substr(0, header_end + 4);
            std::string body_part = it->second.buffer.substr(header_end + 4);
            if (static_cast<int64_t>(body_part.size()) < content_length) {
                // Body not complete, wait for more data
                return;
            }
            req.body = body_part.substr(0, content_length);
        }

        auto resp = route_http_request(req);

        // Add server header
        resp.headers["Server"] = "Progressive/" + cfg_.version;

        std::string raw_resp = http_helpers::build_http_response(resp);
        send(fd, raw_resp.data(), raw_resp.size(), MSG_NOSIGNAL);

        // Check Connection header
        auto conn_hdr = req.headers.find("connection");
        if (conn_hdr != req.headers.end() && util::to_lower(conn_hdr->second) == "keep-alive") {
            it->second.buffer.clear();
            it->second.request_count++;
        } else {
            close(fd);
            client_connections_.erase(it);
            MetricsCollector::instance().set_gauge("http_connections_active",
                static_cast<double>(client_connections_.size()));
        }
    }

    std::vector<int> matrix_fds() {
        // Returns the Matrix HTTP listener fds
        // In a real implementation, these would be managed by the ListenerManager
        return {};
    }

    std::vector<int> other_fds() {
        // Returns other protocol listener fds
        return {};
    }

    // ========================================================================
    // Background task implementations
    // ========================================================================
    void cleanup_presence() {
        // Mark users who haven't been seen as offline
        try {
            db_mgr_->main().runInteraction("cleanup_presence", [](storage::LoggingTransaction& txn) {
                int64_t timeout = util::now_ms() - 300000; // 5 minutes
                txn.execute(
                    "UPDATE presence SET state='offline', currently_active=0 "
                    "WHERE last_active_ts < ? AND state != 'offline'",
                    {storage::SQLParam(timeout)}
                );
            });
            MetricsCollector::instance().increment("presence_cleanup_runs");
        } catch (const std::exception& e) {
            LOG_ERROR("bg", std::string("Presence cleanup failed: ") + e.what());
        }
    }

    void cleanup_ephemeral_messages() {
        try {
            db_mgr_->main().runInteraction("cleanup_ephemeral", [](storage::LoggingTransaction& txn) {
                int64_t now = util::now_ms();
                txn.execute(
                    "DELETE FROM events WHERE type='m.room.message' "
                    "AND json_extract(content, '$.org.matrix.msc2228.self_destruct_after') IS NOT NULL "
                    "AND (origin_server_ts + CAST(json_extract(content, '$.org.matrix.msc2228.self_destruct_after') AS INTEGER) * 1000) < ?",
                    {storage::SQLParam(now)}
                );
            });
            MetricsCollector::instance().increment("ephemeral_cleanup_runs");
        } catch (const std::exception& e) {
            LOG_ERROR("bg", std::string("Ephemeral cleanup failed: ") + e.what());
        }
    }

    void cleanup_expired_media() {
        try {
            int64_t cutoff = util::now_ms() - (90 * 24 * 3600 * 1000LL); // 90 days
            db_mgr_->main().runInteraction("cleanup_media", [cutoff](storage::LoggingTransaction& txn) {
                txn.execute(
                    "DELETE FROM local_media_repository WHERE last_access_ts < ? AND quarantined_by IS NULL",
                    {storage::SQLParam(cutoff)}
                );
                txn.execute(
                    "DELETE FROM remote_media_cache WHERE last_access_ts < ?",
                    {storage::SQLParam(cutoff)}
                );
            });
            MetricsCollector::instance().increment("expired_media_cleanup_runs");
        } catch (const std::exception& e) {
            LOG_ERROR("bg", std::string("Media cleanup failed: ") + e.what());
        }
    }

    void retry_federation() {
        try {
            int64_t now = util::now_ms();
            db_mgr_->main().runInteraction("retry_federation", [now](storage::LoggingTransaction& txn) {
                txn.execute(
                    "SELECT destination, retry_interval, retry_last_ts FROM destinations "
                    "WHERE retry_last_ts + retry_interval < ? AND failure_ts IS NOT NULL",
                    {storage::SQLParam(now)}
                );
                // In a real implementation, we'd iterate results and attempt reconnection
            });
            MetricsCollector::instance().increment("federation_retry_runs");
        } catch (const std::exception& e) {
            LOG_ERROR("bg", std::string("Federation retry failed: ") + e.what());
        }
    }

    void aggregate_stats() {
        try {
            db_mgr_->main().runInteraction("aggregate_stats", [](storage::LoggingTransaction& txn) {
                // Update room stats
                txn.execute(
                    "INSERT OR REPLACE INTO room_stats_current (room_id, current_state_events, joined_members, "
                    "invited_members, left_members, banned_members, local_users_in_room) "
                    "SELECT r.room_id, "
                    "  (SELECT COUNT(*) FROM current_state_events c WHERE c.room_id = r.room_id), "
                    "  (SELECT COUNT(*) FROM room_members m WHERE m.room_id = r.room_id AND m.membership='join'), "
                    "  (SELECT COUNT(*) FROM room_members m WHERE m.room_id = r.room_id AND m.membership='invite'), "
                    "  (SELECT COUNT(*) FROM room_members m WHERE m.room_id = r.room_id AND m.membership='leave'), "
                    "  (SELECT COUNT(*) FROM room_members m WHERE m.room_id = r.room_id AND m.membership='ban'), "
                    "  0 "
                    "FROM rooms r"
                );
            });

            // Update metrics
            int64_t total_users = 0, active_rooms = 0;
            try {
                auto result = db_mgr_->main().execute("count_users",
                    "SELECT COUNT(*) FROM users WHERE deactivated = 0");
                if (!result.empty()) total_users = std::get<int64_t>(result[0][0]);
            } catch (...) {}

            try {
                auto result = db_mgr_->main().execute("count_rooms",
                    "SELECT COUNT(*) FROM rooms");
                if (!result.empty()) active_rooms = std::get<int64_t>(result[0][0]);
            } catch (...) {}

            MetricsCollector::instance().set_total_users(total_users);
            MetricsCollector::instance().set_total_rooms(active_rooms);
            MetricsCollector::instance().set_gauge("memory_bytes",
                static_cast<double>(get_memory_usage()));
            MetricsCollector::instance().increment("stats_aggregation_runs");

        } catch (const std::exception& e) {
            LOG_ERROR("bg", std::string("Stats aggregation failed: ") + e.what());
        }
    }

    size_t get_memory_usage() {
        // Parse /proc/self/statm for resident memory
        std::ifstream statm("/proc/self/statm");
        if (!statm) return 0;
        size_t size, resident, shared, text, lib, data, dt;
        statm >> size >> resident >> shared >> text >> lib >> data >> dt;
        return resident * sysconf(_SC_PAGESIZE);
    }

    // ========================================================================
    // Response building helpers
    // ========================================================================
    static http_helpers::SimpleResponse build_json_response(int code, const json& j) {
        http_helpers::SimpleResponse resp;
        resp.code = code;
        resp.content_type = "application/json";
        resp.body = j.dump();
        return resp;
    }

    // ========================================================================
    // Connection tracking
    // ========================================================================
    struct ClientConnection {
        int fd{-1};
        std::string ip;
        std::string buffer;
        int64_t connected_at{0};
        int64_t request_count{0};
    };

    // ========================================================================
    // Member variables
    // ========================================================================
    std::string config_path_;
    ServerConfig cfg_;
    int64_t start_time_{0};
    std::atomic<bool> running_{false};

    std::unique_ptr<DatabaseManager> db_mgr_;
    std::unique_ptr<ListenerManager> listener_mgr_;
    std::unique_ptr<BackgroundTaskScheduler> bg_scheduler_;
    std::unique_ptr<RateLimiter> rate_limiter_;
    std::unique_ptr<CORSManager> cors_mgr_;
    std::unique_ptr<HealthChecker> health_checker_;
    std::unique_ptr<progressive::federation::FederationTransport> fed_transport_;

    std::map<std::string, std::function<http_helpers::SimpleResponse(const http_helpers::SimpleRequest&)>> routes_;
    std::map<int, ClientConnection> client_connections_;
    std::thread event_loop_thread_;

    static ProgressiveServer* instance_;
};

ProgressiveServer* ProgressiveServer::instance_ = nullptr;

// ============================================================================
// Standalone server entry point
// ============================================================================
namespace standalone {

int run_server(int argc, char* argv[]) {
    std::string config_path = "progressive.yaml";

    // Parse command line
    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: progressive-server [options]\n\n"
                      << "Options:\n"
                      << "  -c, --config PATH    Path to config file (default: progressive.yaml)\n"
                      << "  -h, --help           Show this help\n"
                      << "  -v, --version        Show version\n"
                      << "  --generate-config    Generate default config\n"
                      << "  --validate-config    Validate config file and exit\n";
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            std::cout << "Progressive Server 0.1.0\n"
                      << "Protocols: Matrix, IRC, XMPP, Lemmy, DeltaChat\n"
                      << "Build: " << __DATE__ << " " << __TIME__ << "\n";
            return 0;
        }
        if (arg == "--generate-config") {
            ConfigManager::generate_default_yaml("progressive.yaml");
            return 0;
        }
        if (arg == "--validate-config" && i + 1 < argc) {
            try {
                ConfigManager cm(argv[++i]);
                auto cfg = cm.load();
                std::cout << "Configuration is valid.\n";
                std::cout << "Server name: " << cfg.matrix.server_name << "\n";
                std::cout << "IRC enabled: " << (cfg.irc.enabled ? "yes" : "no") << "\n";
                std::cout << "XMPP enabled: " << (cfg.xmpp.enabled ? "yes" : "no") << "\n";
                std::cout << "Lemmy enabled: " << (cfg.lemmy.enabled ? "yes" : "no") << "\n";
                std::cout << "DeltaChat enabled: " << (cfg.deltachat.enabled ? "yes" : "no") << "\n";
                std::cout << "Federation enabled: " << (cfg.federation.enabled ? "yes" : "no") << "\n";
            } catch (const std::exception& e) {
                std::cerr << "Configuration error: " << e.what() << std::endl;
                return 1;
            }
            return 0;
        }
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_path = argv[++i];
            continue;
        }
    }

    // Print banner
    std::cout << R"(
  ____                              _   _
 |  _ \ _ __ ___   __ _  ___  _ __ | |_(_) _____   __
 | |_) | '__/ _ \ / _` |/ _ \| '_ \| __| |/ _ \ \ / /
 |  __/| | | (_) | (_| | (_) | | | | |_| |  __/\ V /
 |_|   |_|  \___/ \__, |\___/|_| |_|\__|_|\___| \_/
                   |___/

  Progressive Server v0.1.0 - Multi-protocol federated server
  Matrix | IRC | XMPP | Lemmy | DeltaChat
)" << std::endl;

    try {
        ProgressiveServer server(config_path);
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

} // namespace standalone

} // namespace progressive

// ============================================================================
// main() - standalone binary entry point
// ============================================================================
#ifndef PROGRESSIVE_LIBRARY_ONLY
int main(int argc, char* argv[]) {
    return progressive::standalone::run_server(argc, argv);
}
#endif
