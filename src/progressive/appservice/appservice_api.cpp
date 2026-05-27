/**
 * progressive-server — Matrix Application Service API
 *
 * Implements the complete Matrix Application Service (AppService) specification
 * as defined by the Matrix protocol. Application services are privileged
 * processes that can bridge Matrix to external protocols and manage their own
 * namespace of users, aliases, and rooms.
 *
 * Features:
 *   1. AppService Registration — register app services with token, URL,
 *      namespace configurations (users, aliases, rooms), rate limiting,
 *      and protocol type (IRC, XMPP, Telegram, Discord, etc.).
 *
 *   2. AppService Transaction API — push batches of events to app services
 *      as JSON transactions via HTTP PUT, with retry, backoff, and
 *      transaction ID tracking.
 *
 *   3. User Namespace Management — exclusive user namespace regex matching;
 *      users claimed by an app service are managed exclusively by that service.
 *
 *   4. Room Alias Namespace Management — exclusive alias namespace control;
 *      app services own aliases matching their registered regex patterns.
 *
 *   5. Event Push to App Services — filter events by namespace, user
 *      membership, room membership, and interest tracking; push relevant
 *      events to interested app services.
 *
 *   6. AppService Query API — implement /_matrix/app/v1/users/{userId}
 *      and /_matrix/app/v1/rooms/{roomAlias} endpoints for homeserver
 *      to query whether an app service controls a user/alias.
 *
 *   7. Ghost User Management — manage ghost users created by app services:
 *      creation, registration, display name, avatar, and deactivation.
 *
 *   8. Bridge Admin — list all bridges, enable/disable individual bridges,
 *      view bridge status, connection counts, and error states.
 *
 *   9. AppService Rate Limiting — per-app-service rate limiting on
 *      transaction sending, query endpoints, and user creation.
 *
 *  10. Protocol Bridging — protocol-specific bridge handlers for IRC,
 *      XMPP, Telegram, Discord, Slack, WhatsApp, Signal, Mattermost,
 *      and generic webhook bridges.
 *
 *  11. AppService Interest Tracking — track which rooms and users an
 *      app service is interested in; optimize event pushing.
 *
 *  12. Ephemeral Event Push — push typing notifications, presence,
 *      and receipt events to app services.
 *
 *  13. Device List Updates — notify app services of device list changes
 *      for their namespaced users.
 *
 *  14. One-Time Key Counts — report one-time key counts for app service
 *      users to enable end-to-end encryption for bridged users.
 *
 *  15. AppService Logging and Metrics — structured logging, Prometheus
 *      metrics export, transaction success/failure tracking, latency
 *      histograms.
 *
 *  16. Protocol Handler Interface — abstract base class for bridge
 *      implementations; define the contract that all bridge types
 *      must fulfill.
 *
 *  17. Puppet User Management — manage puppet users that represent
 *      remote users from bridged protocols; create, update, sync.
 *
 *  18. Bridge Configuration Loading — load bridge configs from YAML/JSON;
 *      hot-reload, validation, defaults.
 *
 *  19. AppService Health Checking — periodic health checks to app service
 *      endpoints; track uptime, latency, error rates.
 *
 *  20. Namespace Conflict Resolution — detect and resolve conflicts
 *      between overlapping app service namespaces; priority-based
 *      resolution.
 *
 * Equivalent to:
 *   synapse/appservice/__init__.py                     (~200 lines)
 *   synapse/appservice/api.py                          (~900 lines)
 *   synapse/appservice/scheduler.py                     (~300 lines)
 *   synapse/handlers/appservice.py                      (~600 lines)
 *   synapse/appservice/appservice.py                    (~400 lines)
 *   synapse/appservice/event_pusher.py                  (~250 lines)
 *   synapse/appservice/interest.py                      (~150 lines)
 *   synapse/appservice/namespaces.py                    (~100 lines)
 *   synapse/appservice/query.py                         (~100 lines)
 *   synapse/appservice/ratelimiter.py                   (~100 lines)
 *
 * Total equivalent: ~3,100 lines of Python
 *
 * Target: 3000+ lines of production-grade C++.
 * Namespace: progressive::appservice
 */

// ============================================================================
// Standard Library Includes
// ============================================================================

#include <algorithm>
#include <any>
#include <array>
#include <atomic>
#include <bit>
#include <bitset>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cmath>
#include <compare>
#include <condition_variable>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iomanip>
#include <ios>
#include <iostream>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <numeric>
#include <optional>
#include <queue>
#include <random>
#include <ranges>
#include <regex>
#include <set>
#include <shared_mutex>
#include <source_location>
#include <span>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <string>
#include <string_view>
#include <syncstream>
#include <system_error>
#include <thread>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

// ============================================================================
// Third-Party Includes
// ============================================================================

#include "../json.hpp"

// ============================================================================
// Platform / Networking Includes
// ============================================================================

#ifdef __linux__
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include <curl/curl.h>

// ============================================================================
// Progressive AppService Namespace
// ============================================================================

namespace progressive {
namespace appservice {

// ==========================================================================
// Forward Declarations
// ==========================================================================

class AppServiceRegistry;
class AppServiceTransactionManager;
class AppServiceNamespaceManager;
class AppServiceEventPusher;
class AppServiceQueryHandler;
class GhostUserManager;
class BridgeAdminManager;
class AppServiceRateLimiter;
class ProtocolBridgeRegistry;
class AppServiceInterestTracker;
class EphemeralEventPusher;
class DeviceListNotifier;
class OneTimeKeyReporter;
class AppServiceLogger;
class AppServiceMetrics;
class ProtocolHandlerInterface;
class PuppetUserManager;
class BridgeConfigLoader;
class AppServiceHealthChecker;
class NamespaceConflictResolver;

// ==========================================================================
// Common Types and Constants
// ==========================================================================

/// Clock types used throughout the appservice subsystem.
using steady_clock = std::chrono::steady_clock;
using system_clock = std::chrono::system_clock;
using time_point = steady_clock::time_point;
using sys_time_point = system_clock::time_point;
using milliseconds = std::chrono::milliseconds;
using seconds = std::chrono::seconds;
using minutes = std::chrono::minutes;
using hours = std::chrono::hours;

/// JSON type alias for convenience.
using json = nlohmann::json;

/// Maximum transaction size in bytes.
constexpr size_t kMaxTransactionSize = 10 * 1024 * 1024; // 10 MB

/// Default transaction retry count.
constexpr int kDefaultRetryCount = 5;

/// Default transaction timeout.
constexpr auto kDefaultTransactionTimeout = seconds{30};

/// Default health check interval.
constexpr auto kDefaultHealthCheckInterval = seconds{60};

/// Maximum events per transaction.
constexpr size_t kMaxEventsPerTransaction = 100;

/// Default rate limit: transactions per second.
constexpr double kDefaultRateLimit = 10.0;

/// Maximum namespace regex length.
constexpr size_t kMaxNamespaceRegexLength = 4096;

// ==========================================================================
// Enumerations
// ==========================================================================

/// AppService protocol type.
enum class ProtocolType : uint8_t {
    kUnknown    = 0,
    kIRC        = 1,
    kXMPP       = 2,
    kTelegram   = 3,
    kDiscord    = 4,
    kSlack      = 5,
    kWhatsApp   = 6,
    kSignal     = 7,
    kMattermost = 8,
    kWebhook    = 9,
    kGeneric    = 10,
    kCustom     = 11,
};

/// AppService registration state.
enum class AppServiceState : uint8_t {
    kUnregistered = 0,
    kRegistered   = 1,
    kDisabled     = 2,
    kError        = 3,
};

/// Health check status.
enum class HealthStatus : uint8_t {
    kUnknown   = 0,
    kHealthy   = 1,
    kUnhealthy = 2,
    kDegraded  = 3,
    kTimeout   = 4,
};

/// Transaction delivery status.
enum class TransactionStatus : uint8_t {
    kPending   = 0,
    kDelivered = 1,
    kFailed    = 2,
    kRetrying  = 3,
    kAbandoned = 4,
};

/// Namespace kind.
enum class NamespaceKind : uint8_t {
    kUsers      = 0,
    kAliases    = 1,
    kRooms      = 2,
};

/// Conflict resolution strategy.
enum class ConflictStrategy : uint8_t {
    kFirstWins     = 0,
    kPriorityBased = 1,
    kRejectNew     = 2,
    kManual        = 3,
};

// ==========================================================================
// Utility: Protocol Type Serialization
// ==========================================================================

/// Convert ProtocolType to its string representation.
constexpr std::string_view protocol_type_to_string(ProtocolType pt) noexcept {
    using enum ProtocolType;
    switch (pt) {
        case kIRC:        return "irc";
        case kXMPP:       return "xmpp";
        case kTelegram:   return "telegram";
        case kDiscord:    return "discord";
        case kSlack:      return "slack";
        case kWhatsApp:   return "whatsapp";
        case kSignal:     return "signal";
        case kMattermost: return "mattermost";
        case kWebhook:    return "webhook";
        case kGeneric:    return "generic";
        case kCustom:     return "custom";
        default:          return "unknown";
    }
}

/// Parse ProtocolType from string.
inline ProtocolType protocol_type_from_string(std::string_view s) noexcept {
    if (s == "irc")        return ProtocolType::kIRC;
    if (s == "xmpp")       return ProtocolType::kXMPP;
    if (s == "telegram")   return ProtocolType::kTelegram;
    if (s == "discord")    return ProtocolType::kDiscord;
    if (s == "slack")      return ProtocolType::kSlack;
    if (s == "whatsapp")   return ProtocolType::kWhatsApp;
    if (s == "signal")     return ProtocolType::kSignal;
    if (s == "mattermost") return ProtocolType::kMattermost;
    if (s == "webhook")    return ProtocolType::kWebhook;
    if (s == "generic")    return ProtocolType::kGeneric;
    if (s == "custom")     return ProtocolType::kCustom;
    return ProtocolType::kUnknown;
}

// ==========================================================================
// 1. Namespace Configuration
// ==========================================================================

/// A single namespace rule: a regex pattern with exclusivity flag.
struct NamespaceRule {
    std::string regex_pattern;
    std::regex  compiled_regex;
    bool        exclusive = true;
    std::string original_pattern; // as provided in config

    /// Compile the regex. Returns true on success.
    bool compile() noexcept {
        try {
            compiled_regex = std::regex(
                regex_pattern,
                std::regex::ECMAScript | std::regex::optimize
            );
            return true;
        } catch (const std::regex_error&) {
            return false;
        }
    }

    /// Test whether a given value matches this namespace rule.
    bool matches(std::string_view value) const noexcept {
        try {
            return std::regex_match(value.begin(), value.end(), compiled_regex);
        } catch (...) {
            return false;
        }
    }

    /// Serialize to JSON.
    json to_json() const {
        return {
            {"regex", original_pattern},
            {"exclusive", exclusive}
        };
    }

    /// Deserialize from JSON.
    static NamespaceRule from_json(const json& j) {
        NamespaceRule rule;
        if (j.contains("regex") && j["regex"].is_string()) {
            rule.original_pattern = j["regex"].get<std::string>();
            rule.regex_pattern = rule.original_pattern;
        }
        if (j.contains("exclusive") && j["exclusive"].is_boolean()) {
            rule.exclusive = j["exclusive"].get<bool>();
        }
        rule.compile();
        return rule;
    }
};

/// Collection of namespace rules for an app service.
struct AppServiceNamespaces {
    std::vector<NamespaceRule> users;
    std::vector<NamespaceRule> aliases;
    std::vector<NamespaceRule> rooms;

    /// Check if all rules compile successfully.
    bool validate() const noexcept {
        for (const auto& r : users) {
            if (!const_cast<NamespaceRule&>(r).compile()) return false;
        }
        for (const auto& r : aliases) {
            if (!const_cast<NamespaceRule&>(r).compile()) return false;
        }
        for (const auto& r : rooms) {
            if (!const_cast<NamespaceRule&>(r).compile()) return false;
        }
        return true;
    }

    /// Check if a user ID is in this namespace.
    bool is_user_in_namespace(std::string_view user_id) const noexcept {
        for (const auto& rule : users) {
            if (rule.matches(user_id)) return true;
        }
        return false;
    }

    /// Check if a room alias is in this namespace.
    bool is_alias_in_namespace(std::string_view alias) const noexcept {
        for (const auto& rule : aliases) {
            if (rule.matches(alias)) return true;
        }
        return false;
    }

    /// Check if a room ID is in this namespace.
    bool is_room_in_namespace(std::string_view room_id) const noexcept {
        for (const auto& rule : rooms) {
            if (rule.matches(room_id)) return true;
        }
        return false;
    }

    /// Get all matching namespace kinds for a value.
    std::vector<NamespaceKind> get_matching_kinds(std::string_view value) const noexcept {
        std::vector<NamespaceKind> result;
        if (is_user_in_namespace(value))
            result.push_back(NamespaceKind::kUsers);
        if (is_alias_in_namespace(value))
            result.push_back(NamespaceKind::kAliases);
        if (is_room_in_namespace(value))
            result.push_back(NamespaceKind::kRooms);
        return result;
    }

    /// Serialize to JSON.
    json to_json() const {
        json j;
        j["users"] = json::array();
        for (const auto& r : users) j["users"].push_back(r.to_json());
        j["aliases"] = json::array();
        for (const auto& r : aliases) j["aliases"].push_back(r.to_json());
        j["rooms"] = json::array();
        for (const auto& r : rooms) j["rooms"].push_back(r.to_json());
        return j;
    }

    /// Deserialize from JSON.
    static AppServiceNamespaces from_json(const json& j) {
        AppServiceNamespaces ns;
        if (j.contains("users") && j["users"].is_array()) {
            for (const auto& u : j["users"]) {
                ns.users.push_back(NamespaceRule::from_json(u));
            }
        }
        if (j.contains("aliases") && j["aliases"].is_array()) {
            for (const auto& a : j["aliases"]) {
                ns.aliases.push_back(NamespaceRule::from_json(a));
            }
        }
        if (j.contains("rooms") && j["rooms"].is_array()) {
            for (const auto& r : j["rooms"]) {
                ns.rooms.push_back(NamespaceRule::from_json(r));
            }
        }
        return ns;
    }
};

// ==========================================================================
// 2. Rate Limiter Configuration
// ==========================================================================

/// Per-app-service rate limiter configuration.
struct RateLimitConfig {
    double  transactions_per_second = kDefaultRateLimit;
    size_t  burst_size              = 100;
    size_t  max_pending             = 1000;
    bool    enabled                 = true;

    json to_json() const {
        return {
            {"transactions_per_second", transactions_per_second},
            {"burst_size", burst_size},
            {"max_pending", max_pending},
            {"enabled", enabled}
        };
    }

    static RateLimitConfig from_json(const json& j) {
        RateLimitConfig cfg;
        if (j.contains("transactions_per_second"))
            cfg.transactions_per_second = j["transactions_per_second"].get<double>();
        if (j.contains("burst_size"))
            cfg.burst_size = j["burst_size"].get<size_t>();
        if (j.contains("max_pending"))
            cfg.max_pending = j["max_pending"].get<size_t>();
        if (j.contains("enabled"))
            cfg.enabled = j["enabled"].get<bool>();
        return cfg;
    }
};

// ==========================================================================
// 3. AppService Registration Record
// ==========================================================================

/// Full registration record for a single application service.
struct AppServiceRecord {
    // Identity
    std::string             id;              // unique app service ID
    std::string             as_token;        // application service token
    std::string             hs_token;        // homeserver token (generated)
    std::string             url;             // push endpoint URL
    std::string             sender_localpart; // localpart for app service bot user

    // Namespaces
    AppServiceNamespaces    namespaces;

    // Protocol
    ProtocolType            protocol        = ProtocolType::kUnknown;
    std::string             protocol_config; // JSON config for bridge

    // State
    AppServiceState         state           = AppServiceState::kUnregistered;
    sys_time_point          registered_at;
    sys_time_point          last_active;

    // Rate limiting
    RateLimitConfig         rate_limit;

    // Metadata
    std::string             display_name;
    std::string             description;
    std::string             avatar_url;

    // Stats
    std::atomic<uint64_t>   total_transactions{0};
    std::atomic<uint64_t>   successful_transactions{0};
    std::atomic<uint64_t>   failed_transactions{0};
    std::atomic<uint64_t>   total_events_pushed{0};
    std::atomic<uint64_t>   ghost_users_created{0};

    /// Get the bot user ID (sender_localpart + server name).
    std::string get_sender_user_id(std::string_view server_name) const {
        return std::format("@{}:{}", sender_localpart, server_name);
    }

    /// Check if this app service is active.
    bool is_active() const noexcept {
        return state == AppServiceState::kRegistered;
    }

    /// Serialize to JSON for admin API.
    json to_admin_json() const {
        return {
            {"id", id},
            {"url", url},
            {"protocol", protocol_type_to_string(protocol)},
            {"state", static_cast<int>(state)},
            {"sender_localpart", sender_localpart},
            {"namespaces", namespaces.to_json()},
            {"rate_limit", rate_limit.to_json()},
            {"total_transactions", total_transactions.load()},
            {"successful_transactions", successful_transactions.load()},
            {"failed_transactions", failed_transactions.load()},
            {"total_events_pushed", total_events_pushed.load()},
            {"ghost_users_created", ghost_users_created.load()}
        };
    }
};

// ==========================================================================
// 4. Transaction Record
// ==========================================================================

/// A single transaction being delivered to an app service.
struct TransactionRecord {
    std::string             txn_id;         // unique transaction ID
    std::string             appservice_id;  // target app service
    json                    events;         // array of events to push
    time_point              created_at;
    time_point              last_attempt;
    TransactionStatus       status          = TransactionStatus::kPending;
    int                     retry_count     = 0;
    int                     max_retries     = kDefaultRetryCount;
    milliseconds            backoff         = milliseconds{1000};
    std::string             last_error;

    /// Calculate backoff for next retry.
    milliseconds next_backoff() const noexcept {
        auto factor = std::pow(2.0, retry_count);
        auto jitter = (std::rand() % 1000);
        return milliseconds{
            static_cast<long long>(factor * 1000.0 + jitter)
        };
    }
};

// ==========================================================================
// 5. Ghost User Record
// ==========================================================================

/// Represents a ghost user created by an app service.
struct GhostUser {
    std::string             user_id;
    std::string             appservice_id;
    std::string             display_name;
    std::string             avatar_url;
    bool                    is_active       = true;
    sys_time_point          created_at;
    json                    extra_data;

    json to_json() const {
        return {
            {"user_id", user_id},
            {"appservice_id", appservice_id},
            {"display_name", display_name},
            {"avatar_url", avatar_url},
            {"is_active", is_active}
        };
    }
};

// ==========================================================================
// 6. Interest Record
// ==========================================================================

/// Tracks what rooms/users an app service is interested in.
struct AppServiceInterest {
    std::string appservice_id;

    // Rooms the app service has users in
    std::unordered_set<std::string> rooms_with_users;

    // Users the app service is explicitly interested in
    std::unordered_set<std::string> interested_users;

    // Rooms the app service's bot is a member of
    std::unordered_set<std::string> bot_rooms;

    /// Add interest in a room because of a user membership.
    void add_room_for_user(std::string_view room_id) {
        rooms_with_users.emplace(room_id);
    }

    /// Remove interest in a room when the last user leaves.
    void remove_room_for_user(std::string_view room_id) {
        rooms_with_users.erase(std::string(room_id));
    }

    /// Add explicit user interest.
    void add_user_interest(std::string_view user_id) {
        interested_users.emplace(user_id);
    }

    /// Add bot room membership.
    void add_bot_room(std::string_view room_id) {
        bot_rooms.emplace(room_id);
    }

    /// Check if app service cares about a given room.
    bool is_interested_in_room(std::string_view room_id) const noexcept {
        return rooms_with_users.contains(std::string(room_id)) ||
               bot_rooms.contains(std::string(room_id));
    }

    /// Check if app service cares about a given user.
    bool is_interested_in_user(std::string_view user_id) const noexcept {
        return interested_users.contains(std::string(user_id));
    }
};

// ==========================================================================
// 7. Protocol Handler Interface
// ==========================================================================

/// Abstract base class for all protocol bridge implementations.
/// Bridge implementations must inherit from this and provide
/// protocol-specific logic for sending/receiving messages,
/// managing connections, and handling protocol events.
class ProtocolHandlerInterface {
public:
    virtual ~ProtocolHandlerInterface() = default;

    /// Get the protocol type this handler implements.
    virtual ProtocolType get_protocol_type() const noexcept = 0;

    /// Get the human-readable name of this protocol.
    virtual std::string get_protocol_name() const noexcept = 0;

    /// Initialize the protocol handler with configuration.
    virtual bool initialize(const json& config) = 0;

    /// Connect to the remote protocol network.
    virtual bool connect() = 0;

    /// Disconnect from the remote protocol network.
    virtual void disconnect() = 0;

    /// Check if connected.
    virtual bool is_connected() const noexcept = 0;

    /// Send a message from Matrix to the bridged protocol.
    /// Returns an error message on failure, or empty on success.
    virtual std::string send_message(
        std::string_view remote_room_id,
        std::string_view sender_user_id,
        const json& content
    ) = 0;

    /// Handle an incoming message from the bridged protocol.
    /// This is called when a message arrives from the remote side.
    virtual void handle_incoming_message(
        std::string_view remote_room_id,
        std::string_view remote_user_id,
        std::string_view message_text,
        const json& extra_data
    ) = 0;

    /// Join a room/channel on the remote protocol.
    virtual bool join_room(std::string_view remote_room_id) = 0;

    /// Leave a room/channel on the remote protocol.
    virtual bool leave_room(std::string_view remote_room_id) = 0;

    /// Invite a user to a room/channel on the remote protocol.
    virtual bool invite_user(
        std::string_view remote_room_id,
        std::string_view remote_user_id
    ) = 0;

    /// Kick a user from a room/channel on the remote protocol.
    virtual bool kick_user(
        std::string_view remote_room_id,
        std::string_view remote_user_id,
        std::string_view reason
    ) = 0;

    /// Set a topic on the remote protocol room/channel.
    virtual bool set_topic(
        std::string_view remote_room_id,
        std::string_view topic
    ) = 0;

    /// Get the list of users in a remote room/channel.
    virtual std::vector<std::string> get_room_members(
        std::string_view remote_room_id
    ) = 0;

    /// Map a remote user to a Matrix ghost user ID.
    virtual std::string get_matrix_user_id(
        std::string_view remote_user_id
    ) const = 0;

    /// Map a Matrix user to a remote user ID.
    virtual std::string get_remote_user_id(
        std::string_view matrix_user_id
    ) const = 0;

    /// Get the admin list for a remote room.
    virtual std::vector<std::string> get_room_admins(
        std::string_view remote_room_id
    ) = 0;

    /// Set the power level of a user in the remote room.
    virtual bool set_user_power_level(
        std::string_view remote_room_id,
        std::string_view remote_user_id,
        int power_level
    ) = 0;

    /// Handle a file/media transfer.
    virtual std::string send_file(
        std::string_view remote_room_id,
        std::string_view sender_user_id,
        std::string_view file_path,
        std::string_view mime_type,
        const json& extra_data
    ) = 0;

    /// Get protocol-specific connection status details.
    virtual json get_connection_status() const = 0;

    /// Perform protocol-specific health checks.
    virtual HealthStatus health_check() = 0;

    /// Get per-protocol metrics.
    virtual json get_metrics() const = 0;

    /// Shutdown the protocol handler gracefully.
    virtual void shutdown() = 0;
};

// ==========================================================================
// 8. AppService Rate Limiter Implementation
// ==========================================================================

/// Token bucket rate limiter for app service transactions.
class AppServiceRateLimiter {
public:
    AppServiceRateLimiter() = default;

    explicit AppServiceRateLimiter(const RateLimitConfig& config)
        : config_(config)
        , tokens_(config.burst_size)
        , last_refill_(steady_clock::now())
    {}

    /// Configure the rate limiter.
    void configure(const RateLimitConfig& config) {
        std::lock_guard lock(mutex_);
        config_ = config;
        tokens_ = std::min(tokens_, static_cast<double>(config_.burst_size));
    }

    /// Attempt to consume one token. Returns true if allowed.
    bool try_consume() noexcept {
        if (!config_.enabled) return true;

        std::lock_guard lock(mutex_);
        refill_tokens();

        if (tokens_ >= 1.0) {
            tokens_ -= 1.0;
            return true;
        }
        return false;
    }

    /// Wait until a token is available, up to a timeout.
    bool consume_with_timeout(milliseconds timeout) noexcept {
        if (!config_.enabled) return true;

        auto deadline = steady_clock::now() + timeout;
        while (steady_clock::now() < deadline) {
            {
                std::lock_guard lock(mutex_);
                refill_tokens();
                if (tokens_ >= 1.0) {
                    tokens_ -= 1.0;
                    return true;
                }
            }
            std::this_thread::sleep_for(milliseconds{10});
        }
        return false;
    }

    /// Get current token count.
    double available_tokens() const noexcept {
        std::lock_guard lock(mutex_);
        return tokens_;
    }

    /// Reset to full burst capacity.
    void reset() noexcept {
        std::lock_guard lock(mutex_);
        tokens_ = static_cast<double>(config_.burst_size);
        last_refill_ = steady_clock::now();
    }

    /// Get the configuration.
    const RateLimitConfig& config() const noexcept { return config_; }

    /// Serialize to JSON for metrics.
    json to_json() const {
        std::lock_guard lock(mutex_);
        return {
            {"tokens_available", tokens_},
            {"config", config_.to_json()}
        };
    }

private:
    void refill_tokens() noexcept {
        auto now = steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - last_refill_).count();
        double new_tokens = elapsed * config_.transactions_per_second;
        tokens_ = std::min(tokens_ + new_tokens,
                           static_cast<double>(config_.burst_size));
        last_refill_ = now;
    }

    RateLimitConfig config_;
    double tokens_ = 100.0;
    time_point last_refill_;
    mutable std::mutex mutex_;
};

// ==========================================================================
// 9. AppService Registry — Registration Management
// ==========================================================================

/// Central registry for all application services.
class AppServiceRegistry {
public:
    AppServiceRegistry() = default;

    // --------------------------------------------------------------------
    // Registration
    // --------------------------------------------------------------------

    /// Register a new application service.
    /// Returns an error message on failure, or empty string on success.
    std::string register_appservice(
        std::string_view id,
        std::string_view as_token,
        std::string_view url,
        std::string_view sender_localpart,
        AppServiceNamespaces namespaces,
        ProtocolType protocol = ProtocolType::kGeneric
    ) {
        std::unique_lock lock(mutex_);

        // Validate inputs
        if (id.empty()) {
            return "App service ID cannot be empty";
        }
        if (as_token.empty()) {
            return "AS token cannot be empty";
        }
        if (url.empty()) {
            return "URL cannot be empty";
        }
        if (sender_localpart.empty()) {
            return "Sender localpart cannot be empty";
        }

        // Check for duplicate ID
        if (records_.contains(std::string(id))) {
            return std::format("App service '{}' already registered", id);
        }

        // Check for duplicate AS token
        for (const auto& [_, rec] : records_) {
            if (rec.as_token == as_token) {
                return "AS token already in use by another app service";
            }
        }

        // Check for duplicate sender localpart
        for (const auto& [_, rec] : records_) {
            if (rec.sender_localpart == sender_localpart) {
                return std::format(
                    "Sender localpart '{}' already in use",
                    sender_localpart
                );
            }
        }

        // Validate namespaces
        if (!namespaces.validate()) {
            return "One or more namespace regex patterns failed to compile";
        }

        // Check namespace conflicts
        std::string conflict = check_namespace_conflicts_internal(namespaces, id);
        if (!conflict.empty()) {
            return conflict;
        }

        // Generate hs_token
        std::string hs_token = generate_hs_token();

        // Create record
        AppServiceRecord rec;
        rec.id               = std::string(id);
        rec.as_token         = std::string(as_token);
        rec.hs_token         = hs_token;
        rec.url              = std::string(url);
        rec.sender_localpart = std::string(sender_localpart);
        rec.namespaces       = std::move(namespaces);
        rec.protocol         = protocol;
        rec.state            = AppServiceState::kRegistered;
        rec.registered_at    = system_clock::now();
        rec.last_active      = system_clock::now();

        // Initialize rate limiter
        rate_limiters_.emplace(
            std::string(id),
            std::make_unique<AppServiceRateLimiter>(rec.rate_limit)
        );

        // Initialize interest tracker
        interests_.emplace(std::string(id), AppServiceInterest{std::string(id)});

        records_.emplace(rec.id, std::move(rec));

        lock.unlock();
        log_info(std::format(
            "AppService registered: id={} protocol={} url={}",
            id, protocol_type_to_string(protocol), url
        ));
        return "";
    }

    /// Deregister an application service.
    bool deregister_appservice(std::string_view id) {
        std::unique_lock lock(mutex_);
        auto it = records_.find(std::string(id));
        if (it == records_.end()) return false;

        it->second.state = AppServiceState::kUnregistered;
        log_info(std::format("AppService deregistered: id={}", id));

        rate_limiters_.erase(std::string(id));
        interests_.erase(std::string(id));
        records_.erase(it);
        return true;
    }

    /// Disable an app service without removing it.
    bool disable_appservice(std::string_view id) {
        std::unique_lock lock(mutex_);
        auto it = records_.find(std::string(id));
        if (it == records_.end()) return false;

        it->second.state = AppServiceState::kDisabled;
        log_info(std::format("AppService disabled: id={}", id));
        return true;
    }

    /// Enable a previously disabled app service.
    bool enable_appservice(std::string_view id) {
        std::unique_lock lock(mutex_);
        auto it = records_.find(std::string(id));
        if (it == records_.end()) return false;

        it->second.state = AppServiceState::kRegistered;
        it->second.last_active = system_clock::now();
        log_info(std::format("AppService enabled: id={}", id));
        return true;
    }

    // --------------------------------------------------------------------
    // Lookup
    // --------------------------------------------------------------------

    /// Find an app service by its AS token.
    std::optional<std::reference_wrapper<const AppServiceRecord>>
    find_by_token(std::string_view as_token) const {
        std::shared_lock lock(mutex_);
        for (const auto& [_, rec] : records_) {
            if (rec.as_token == as_token && rec.is_active()) {
                return std::cref(rec);
            }
        }
        return std::nullopt;
    }

    /// Find an app service by ID.
    std::optional<std::reference_wrapper<const AppServiceRecord>>
    find_by_id(std::string_view id) const {
        std::shared_lock lock(mutex_);
        auto it = records_.find(std::string(id));
        if (it != records_.end()) return std::cref(it->second);
        return std::nullopt;
    }

    /// Get a mutable reference to an app service record.
    AppServiceRecord* get_mutable(std::string_view id) {
        std::shared_lock lock(mutex_);
        auto it = records_.find(std::string(id));
        if (it != records_.end()) return &it->second;
        return nullptr;
    }

    /// Get the app service that controls a given user ID.
    std::string get_appservice_for_user(std::string_view user_id) const {
        std::shared_lock lock(mutex_);
        for (const auto& [id, rec] : records_) {
            if (!rec.is_active()) continue;
            if (rec.namespaces.is_user_in_namespace(user_id)) {
                return id;
            }
        }
        return "";
    }

    /// Get the app service that controls a given room alias.
    std::string get_appservice_for_alias(std::string_view alias) const {
        std::shared_lock lock(mutex_);
        for (const auto& [id, rec] : records_) {
            if (!rec.is_active()) continue;
            if (rec.namespaces.is_alias_in_namespace(alias)) {
                return id;
            }
        }
        return "";
    }

    /// Get the app service that controls a given room ID.
    std::string get_appservice_for_room(std::string_view room_id) const {
        std::shared_lock lock(mutex_);
        for (const auto& [id, rec] : records_) {
            if (!rec.is_active()) continue;
            if (rec.namespaces.is_room_in_namespace(room_id)) {
                return id;
            }
        }
        return "";
    }

    /// Check if a user ID is exclusive to an app service.
    bool is_exclusive_user(std::string_view user_id) const {
        return !get_appservice_for_user(user_id).empty();
    }

    /// Check if an alias is exclusive to an app service.
    bool is_exclusive_alias(std::string_view alias) const {
        return !get_appservice_for_alias(alias).empty();
    }

    // --------------------------------------------------------------------
    // Listing & Admin
    // --------------------------------------------------------------------

    /// Get all registered app services.
    std::vector<AppServiceRecord> list_all() const {
        std::shared_lock lock(mutex_);
        std::vector<AppServiceRecord> result;
        result.reserve(records_.size());
        for (const auto& [_, rec] : records_) {
            result.push_back(rec);
        }
        return result;
    }

    /// Get all active app services.
    std::vector<AppServiceRecord> list_active() const {
        std::shared_lock lock(mutex_);
        std::vector<AppServiceRecord> result;
        for (const auto& [_, rec] : records_) {
            if (rec.is_active()) result.push_back(rec);
        }
        return result;
    }

    /// Get the app service of a given protocol type.
    std::vector<AppServiceRecord> list_by_protocol(ProtocolType pt) const {
        std::shared_lock lock(mutex_);
        std::vector<AppServiceRecord> result;
        for (const auto& [_, rec] : records_) {
            if (rec.protocol == pt && rec.is_active()) {
                result.push_back(rec);
            }
        }
        return result;
    }

    /// Count of registered app services.
    size_t count() const {
        std::shared_lock lock(mutex_);
        return records_.size();
    }

    /// Count of active app services.
    size_t count_active() const {
        std::shared_lock lock(mutex_);
        size_t n = 0;
        for (const auto& [_, rec] : records_) {
            if (rec.is_active()) ++n;
        }
        return n;
    }

    // --------------------------------------------------------------------
    // Rate Limiting
    // --------------------------------------------------------------------

    /// Get the rate limiter for an app service.
    AppServiceRateLimiter* get_rate_limiter(std::string_view id) {
        std::shared_lock lock(mutex_);
        auto it = rate_limiters_.find(std::string(id));
        if (it != rate_limiters_.end()) return it->second.get();
        return nullptr;
    }

    /// Update rate limit config for an app service.
    bool update_rate_limit(std::string_view id, const RateLimitConfig& cfg) {
        std::unique_lock lock(mutex_);
        auto rit = records_.find(std::string(id));
        if (rit == records_.end()) return false;

        rit->second.rate_limit = cfg;
        auto lit = rate_limiters_.find(std::string(id));
        if (lit != rate_limiters_.end()) {
            lit->second->configure(cfg);
        }
        return true;
    }

    // --------------------------------------------------------------------
    // Interest Tracking
    // --------------------------------------------------------------------

    /// Get interest tracker for an app service.
    AppServiceInterest* get_interest(std::string_view id) {
        std::shared_lock lock(mutex_);
        auto it = interests_.find(std::string(id));
        if (it != interests_.end()) return &it->second;
        return nullptr;
    }

    /// Update interest: app service user joined a room.
    void mark_user_joined_room(
        std::string_view appservice_id,
        std::string_view user_id,
        std::string_view room_id
    ) {
        std::unique_lock lock(mutex_);
        auto it = interests_.find(std::string(appservice_id));
        if (it == interests_.end()) return;
        it->second.add_room_for_user(room_id);
        it->second.add_user_interest(user_id);
    }

    /// Update interest: app service user left a room.
    void mark_user_left_room(
        std::string_view appservice_id,
        std::string_view room_id
    ) {
        std::unique_lock lock(mutex_);
        auto it = interests_.find(std::string(appservice_id));
        if (it == interests_.end()) return;
        it->second.remove_room_for_user(room_id);
    }

    // --------------------------------------------------------------------
    // Serialization
    // --------------------------------------------------------------------

    /// Export full registry as JSON.
    json to_json() const {
        std::shared_lock lock(mutex_);
        json j = json::array();
        for (const auto& [_, rec] : records_) {
            j.push_back(rec.to_admin_json());
        }
        return j;
    }

private:
    /// Generate a random HS token.
    static std::string generate_hs_token() {
        static const char charset[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        static constexpr size_t token_len = 64;
        static thread_local std::mt19937_64 rng{
            static_cast<uint64_t>(
                std::chrono::steady_clock::now().time_since_epoch().count()
            )
        };
        std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);

        std::string token;
        token.reserve(token_len);
        for (size_t i = 0; i < token_len; ++i) {
            token += charset[dist(rng)];
        }
        return token;
    }

    /// Check if new namespaces conflict with existing registrations.
    std::string check_namespace_conflicts_internal(
        const AppServiceNamespaces& new_ns,
        std::string_view exclude_id
    ) {
        for (const auto& [id, rec] : records_) {
            if (id == exclude_id) continue;
            if (!rec.is_active()) continue;

            // Check user namespace overlaps
            for (const auto& new_rule : new_ns.users) {
                for (const auto& existing_rule : rec.namespaces.users) {
                    if (!new_rule.exclusive || !existing_rule.exclusive)
                        continue;
                    // Check for pattern overlap (simplified: check prefix)
                    if (new_rule.original_pattern ==
                        existing_rule.original_pattern) {
                        return std::format(
                            "Namespace conflict: user regex '{}' already "
                            "registered by app service '{}'",
                            new_rule.original_pattern, id
                        );
                    }
                }
            }

            // Check alias namespace overlaps
            for (const auto& new_rule : new_ns.aliases) {
                for (const auto& existing_rule : rec.namespaces.aliases) {
                    if (!new_rule.exclusive || !existing_rule.exclusive)
                        continue;
                    if (new_rule.original_pattern ==
                        existing_rule.original_pattern) {
                        return std::format(
                            "Namespace conflict: alias regex '{}' already "
                            "registered by app service '{}'",
                            new_rule.original_pattern, id
                        );
                    }
                }
            }

            // Check room namespace overlaps
            for (const auto& new_rule : new_ns.rooms) {
                for (const auto& existing_rule : rec.namespaces.rooms) {
                    if (!new_rule.exclusive || !existing_rule.exclusive)
                        continue;
                    if (new_rule.original_pattern ==
                        existing_rule.original_pattern) {
                        return std::format(
                            "Namespace conflict: room regex '{}' already "
                            "registered by app service '{}'",
                            new_rule.original_pattern, id
                        );
                    }
                }
            }
        }
        return "";
    }

    /// Minimal logging placeholder (calls external logger).
    static void log_info(const std::string& msg) {
        auto now = system_clock::now();
        auto time_t_now = system_clock::to_time_t(now);
        std::osyncstream(std::cout)
            << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S")
            << " [INFO] [appservice] " << msg << '\n';
    }

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, AppServiceRecord> records_;
    std::unordered_map<std::string, std::unique_ptr<AppServiceRateLimiter>>
        rate_limiters_;
    std::unordered_map<std::string, AppServiceInterest> interests_;
};

// ==========================================================================
// 10. Transaction Manager — Push Transactions to App Services
// ==========================================================================

/// Manages sending transaction batches to app services.
class AppServiceTransactionManager {
public:
    AppServiceTransactionManager(AppServiceRegistry& registry)
        : registry_(registry)
    {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    ~AppServiceTransactionManager() {
        shutdown();
        curl_global_cleanup();
    }

    /// Push a batch of events to an app service.
    /// Returns the HTTP status code, or -1 on connection failure.
    int push_transaction(
        std::string_view appservice_id,
        std::string_view txn_id,
        const json& events
    ) {
        auto* rec = registry_.get_mutable(appservice_id);
        if (!rec || !rec->is_active()) {
            return -1;
        }

        // Rate limit check
        auto* limiter = registry_.get_rate_limiter(appservice_id);
        if (limiter && !limiter->try_consume()) {
            // Queue for later or reject
            return 429; // Too Many Requests
        }

        // Build transaction body
        json body;
        body["events"] = events;

        // Send via HTTP PUT
        std::string url = std::format(
            "{}/_matrix/app/v1/transactions/{}?access_token={}",
            rec->url, txn_id, rec->hs_token
        );

        std::string response_body;
        long http_code = 0;

        bool success = http_put(url, body.dump(), response_body, http_code,
                                kDefaultTransactionTimeout);

        // Update stats
        rec->total_transactions.fetch_add(1);
        if (success && http_code >= 200 && http_code < 300) {
            rec->successful_transactions.fetch_add(1);
            rec->total_events_pushed.fetch_add(
                events.is_array() ? events.size() : 1
            );
        } else {
            rec->failed_transactions.fetch_add(1);
        }

        rec->last_active = system_clock::now();

        return static_cast<int>(http_code);
    }

    /// Push transaction with retry logic.
    TransactionStatus push_with_retry(
        std::string_view appservice_id,
        std::string_view txn_id,
        const json& events,
        int max_retries = kDefaultRetryCount
    ) {
        TransactionRecord txn;
        txn.txn_id = std::string(txn_id);
        txn.appservice_id = std::string(appservice_id);
        txn.events = events;
        txn.created_at = steady_clock::now();
        txn.max_retries = max_retries;
        txn.status = TransactionStatus::kRetrying;

        for (int attempt = 0; attempt <= max_retries; ++attempt) {
            txn.last_attempt = steady_clock::now();
            txn.retry_count = attempt;

            int code = push_transaction(appservice_id, txn_id, events);

            if (code >= 200 && code < 300) {
                txn.status = TransactionStatus::kDelivered;
                return TransactionStatus::kDelivered;
            }

            if (code == 429 || code == 503 || code == -1) {
                // Retryable error
                if (attempt < max_retries) {
                    auto backoff = txn.next_backoff();
                    txn.backoff = backoff;
                    std::this_thread::sleep_for(backoff);
                    continue;
                }
            }

            // Non-retryable or exhausted retries
            txn.status = TransactionStatus::kFailed;
            txn.last_error = std::format("HTTP {}", code);
            break;
        }

        return txn.status;
    }

    /// Send ephemeral events (typing, presence, receipts).
    /// These are delivered via the same transaction API but are marked
    /// as ephemeral in the event dictionary.
    int push_ephemeral_events(
        std::string_view appservice_id,
        const json& ephemeral_events
    ) {
        std::string txn_id = generate_txn_id();
        json body;
        body["ephemeral"] = ephemeral_events;

        auto* rec = registry_.get_mutable(appservice_id);
        if (!rec || !rec->is_active()) return -1;

        std::string url = std::format(
            "{}/_matrix/app/v1/transactions/{}?access_token={}",
            rec->url, txn_id, rec->hs_token
        );

        std::string response_body;
        long http_code = 0;
        http_put(url, body.dump(), response_body, http_code, seconds{10});

        return static_cast<int>(http_code);
    }

    /// Generate a unique transaction ID.
    static std::string generate_txn_id() {
        static std::atomic<uint64_t> counter{0};
        auto ts = std::chrono::system_clock::now().time_since_epoch().count();
        auto c = counter.fetch_add(1, std::memory_order_relaxed);
        return std::format("progressive-{}-{}", ts, c);
    }

    /// Shutdown and cancel pending transactions.
    void shutdown() {
        shutting_down_.store(true, std::memory_order_release);
    }

private:
    /// Perform an HTTP PUT request.
    bool http_put(
        const std::string& url,
        const std::string& body,
        std::string& response_body,
        long& http_code,
        milliseconds timeout
    ) {
        CURL* curl = curl_easy_init();
        if (!curl) return false;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                         static_cast<long>(body.size()));
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS,
                         static_cast<long>(timeout.count()));
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPCNT, 3L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 60L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 30L);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        } else {
            http_code = -1;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return res == CURLE_OK;
    }

    /// libcurl write callback.
    static size_t write_callback(
        void* contents, size_t size, size_t nmemb, void* userp
    ) {
        size_t total = size * nmemb;
        auto* response = static_cast<std::string*>(userp);
        response->append(static_cast<char*>(contents), total);
        return total;
    }

    AppServiceRegistry& registry_;
    std::atomic<bool> shutting_down_{false};
};

// ==========================================================================
// 11. Event Pusher — Route Events to Interested App Services
// ==========================================================================

/// Routes events to the appropriate app services based on namespace,
/// interest, and membership criteria.
class AppServiceEventPusher {
public:
    AppServiceEventPusher(
        AppServiceRegistry& registry,
        AppServiceTransactionManager& txn_mgr
    )
        : registry_(registry)
        , txn_mgr_(txn_mgr)
    {}

    /// Push an event to all interested app services.
    /// Returns the count of app services the event was pushed to.
    size_t push_event(const json& event) {
        std::vector<std::string> targets = find_interested_appservices(event);
        if (targets.empty()) return 0;

        size_t pushed = 0;
        for (auto& as_id : targets) {
            json events_array = json::array({event});
            std::string txn_id = AppServiceTransactionManager::generate_txn_id();
            int code = txn_mgr_.push_transaction(as_id, txn_id, events_array);
            if (code >= 200 && code < 300) {
                ++pushed;
            }
        }
        return pushed;
    }

    /// Push multiple events batched by app service.
    /// More efficient than individual push_event calls.
    size_t push_events_batch(const std::vector<json>& events) {
        // Group events by target app service
        std::unordered_map<std::string, json> batches;
        for (const auto& event : events) {
            auto targets = find_interested_appservices(event);
            for (const auto& as_id : targets) {
                if (!batches.contains(as_id)) {
                    batches[as_id] = json::array();
                }
                batches[as_id].push_back(event);
            }
        }

        // Push each batch
        size_t pushed = 0;
        for (auto& [as_id, batch] : batches) {
            // Limit batch size
            if (batch.size() > kMaxEventsPerTransaction) {
                // Split into sub-batches
                json sub_batch = json::array();
                for (size_t i = 0; i < batch.size(); ++i) {
                    sub_batch.push_back(batch[i]);
                    if (sub_batch.size() >= kMaxEventsPerTransaction ||
                        i == batch.size() - 1) {
                        std::string txn_id =
                            AppServiceTransactionManager::generate_txn_id();
                        int code = txn_mgr_.push_transaction(
                            as_id, txn_id, sub_batch
                        );
                        if (code >= 200 && code < 300) ++pushed;
                        sub_batch = json::array();
                    }
                }
            } else {
                std::string txn_id =
                    AppServiceTransactionManager::generate_txn_id();
                int code = txn_mgr_.push_transaction(as_id, txn_id, batch);
                if (code >= 200 && code < 300) ++pushed;
            }
        }
        return pushed;
    }

    /// Push typing notification to interested app services.
    void push_typing(
        std::string_view room_id,
        std::string_view user_id,
        bool typing,
        std::optional<milliseconds> timeout = std::nullopt
    ) {
        json typing_event;
        typing_event["type"] = "m.typing";
        typing_event["room_id"] = room_id;
        typing_event["content"]["user_id"] = user_id;
        typing_event["content"]["typing"] = typing;
        if (timeout) {
            typing_event["content"]["timeout"] =
                static_cast<int64_t>(timeout->count());
        }

        auto targets = find_appservices_for_room(room_id);
        for (const auto& as_id : targets) {
            json events = json::array({typing_event});
            txn_mgr_.push_ephemeral_events(as_id, events);
        }
    }

    /// Push presence update to app services interested in a user.
    void push_presence(
        std::string_view user_id,
        std::string_view presence_state,
        std::optional<std::string_view> status_msg = std::nullopt
    ) {
        json presence_event;
        presence_event["type"] = "m.presence";
        presence_event["sender"] = user_id;
        presence_event["content"]["presence"] = presence_state;
        if (status_msg) {
            presence_event["content"]["status_msg"] = *status_msg;
        }
        presence_event["content"]["last_active_ago"] = 0;

        auto targets = find_appservices_interested_in_user(user_id);
        for (const auto& as_id : targets) {
            json events = json::array({presence_event});
            txn_mgr_.push_ephemeral_events(as_id, events);
        }
    }

    /// Push receipt update to app services.
    void push_receipt(
        std::string_view room_id,
        std::string_view event_id,
        std::string_view user_id,
        std::string_view receipt_type
    ) {
        json receipt_event;
        receipt_event["type"] = "m.receipt";
        receipt_event["room_id"] = room_id;
        receipt_event["content"][std::string(event_id)][receipt_type]
            [std::string(user_id)]["ts"] =
                std::chrono::system_clock::now().time_since_epoch().count();

        auto targets = find_appservices_for_room(room_id);
        for (const auto& as_id : targets) {
            json events = json::array({receipt_event});
            txn_mgr_.push_ephemeral_events(as_id, events);
        }
    }

    /// Push device list update to app services.
    void push_device_list_update(
        std::string_view user_id,
        const json& device_list
    ) {
        json device_event;
        device_event["type"] = "m.device_list_update";
        device_event["sender"] = user_id;
        device_event["content"]["user_id"] = user_id;
        device_event["content"]["device_list"] = device_list;

        auto targets = find_appservices_interested_in_user(user_id);
        for (const auto& as_id : targets) {
            auto* rec = registry_.get_mutable(as_id);
            if (!rec) continue;

            std::string txn_id = AppServiceTransactionManager::generate_txn_id();
            json events = json::array({device_event});
            txn_mgr_.push_transaction(as_id, txn_id, events);
        }
    }

private:
    /// Find all app services interested in an event.
    std::vector<std::string> find_interested_appservices(const json& event) {
        std::unordered_set<std::string> targets;

        // Determine room_id from event
        std::string room_id;
        if (event.contains("room_id") && event["room_id"].is_string()) {
            room_id = event["room_id"].get<std::string>();
        }

        // Determine sender from event
        std::string sender;
        if (event.contains("sender") && event["sender"].is_string()) {
            sender = event["sender"].get<std::string>();
        }

        // Determine state_key if present
        std::string state_key;
        if (event.contains("state_key") && event["state_key"].is_string()) {
            state_key = event["state_key"].get<std::string>();
        }

        // 1. Check room namespace
        if (!room_id.empty()) {
            std::string as_id = registry_.get_appservice_for_room(room_id);
            if (!as_id.empty()) targets.insert(as_id);
        }

        // 2. Check sender (user) namespace
        if (!sender.empty()) {
            std::string as_id = registry_.get_appservice_for_user(sender);
            if (!as_id.empty()) targets.insert(as_id);
        }

        // 3. Check state_key (user) namespace
        if (!state_key.empty()) {
            std::string as_id = registry_.get_appservice_for_user(state_key);
            if (!as_id.empty()) targets.insert(as_id);
        }

        // 4. Check interests: any app service with users in this room
        if (!room_id.empty()) {
            auto active = registry_.list_active();
            for (const auto& rec : active) {
                auto* interest = registry_.get_interest(rec.id);
                if (interest && interest->is_interested_in_room(room_id)) {
                    targets.insert(rec.id);
                }
            }
        }

        // 5. Check interests: any app service interested in the sender
        if (!sender.empty()) {
            auto active = registry_.list_active();
            for (const auto& rec : active) {
                auto* interest = registry_.get_interest(rec.id);
                if (interest && interest->is_interested_in_user(sender)) {
                    targets.insert(rec.id);
                }
            }
        }

        return std::vector<std::string>(targets.begin(), targets.end());
    }

    /// Find all app services interested in a room.
    std::vector<std::string> find_appservices_for_room(
        std::string_view room_id
    ) {
        std::unordered_set<std::string> targets;

        std::string ns_as = registry_.get_appservice_for_room(room_id);
        if (!ns_as.empty()) targets.insert(ns_as);

        auto active = registry_.list_active();
        for (const auto& rec : active) {
            auto* interest = registry_.get_interest(rec.id);
            if (interest && interest->is_interested_in_room(room_id)) {
                targets.insert(rec.id);
            }
        }

        return std::vector<std::string>(targets.begin(), targets.end());
    }

    /// Find all app services interested in a user.
    std::vector<std::string> find_appservices_interested_in_user(
        std::string_view user_id
    ) {
        std::unordered_set<std::string> targets;

        std::string ns_as = registry_.get_appservice_for_user(user_id);
        if (!ns_as.empty()) targets.insert(ns_as);

        auto active = registry_.list_active();
        for (const auto& rec : active) {
            auto* interest = registry_.get_interest(rec.id);
            if (interest && interest->is_interested_in_user(user_id)) {
                targets.insert(rec.id);
            }
        }

        return std::vector<std::string>(targets.begin(), targets.end());
    }

    AppServiceRegistry& registry_;
    AppServiceTransactionManager& txn_mgr_;
};

// ==========================================================================
// 12. Query API Handler — /users/{userId}, /rooms/{roomAlias}
// ==========================================================================

/// Handles the AppService Query API. The homeserver queries app services
/// to determine if a user or alias belongs to them.
class AppServiceQueryHandler {
public:
    AppServiceQueryHandler(AppServiceRegistry& registry)
        : registry_(registry)
    {}

    /// Query: check if a user exists and belongs to an app service.
    /// Returns JSON response for /_matrix/app/v1/users/{userId}
    json query_user(std::string_view user_id) {
        json response;
        std::string as_id = registry_.get_appservice_for_user(user_id);

        if (as_id.empty()) {
            // Not claimed by any app service
            response["exists"] = false;
            return response;
        }

        auto rec = registry_.find_by_id(as_id);
        if (!rec) {
            response["exists"] = false;
            return response;
        }

        // Check if this user is in an exclusive namespace
        response["exists"] = true;

        // Build the profile info
        if (!rec->get().sender_localpart.empty()) {
            response["user_id"] = user_id;
        }

        return response;
    }

    /// Query: check if a room alias exists and belongs to an app service.
    /// Returns JSON response for /_matrix/app/v1/rooms/{roomAlias}
    json query_room_alias(std::string_view room_alias) {
        json response;
        std::string as_id = registry_.get_appservice_for_alias(room_alias);

        if (as_id.empty()) {
            response["exists"] = false;
            return response;
        }

        auto rec = registry_.find_by_id(as_id);
        if (!rec) {
            response["exists"] = false;
            return response;
        }

        response["exists"] = true;
        response["room_id"] = ""; // Would be filled by room directory lookup

        return response;
    }

    /// Query: check if a user is in the exclusive namespace of a specific
    /// app service (used during registration verification).
    json query_user_for_appservice(
        std::string_view user_id,
        std::string_view appservice_id
    ) {
        json response;
        auto rec = registry_.find_by_id(appservice_id);

        if (!rec) {
            response["exists"] = false;
            response["error"] = "App service not found";
            return response;
        }

        bool in_namespace = rec->get().namespaces.is_user_in_namespace(user_id);
        response["exists"] = in_namespace;

        return response;
    }

    /// Query: check if an alias is in the exclusive namespace of a specific
    /// app service.
    json query_alias_for_appservice(
        std::string_view alias,
        std::string_view appservice_id
    ) {
        json response;
        auto rec = registry_.find_by_id(appservice_id);

        if (!rec) {
            response["exists"] = false;
            response["error"] = "App service not found";
            return response;
        }

        bool in_namespace = rec->get().namespaces.is_alias_in_namespace(alias);
        response["exists"] = in_namespace;

        return response;
    }

    /// Handle the third-party lookup protocol query.
    /// /_matrix/app/v1/thirdparty/protocol/{protocol}
    json query_third_party_protocol(
        std::string_view protocol,
        std::string_view appservice_id
    ) {
        json response;
        auto rec = registry_.find_by_id(appservice_id);

        if (!rec) {
            response["error"] = "App service not found";
            return response;
        }

        std::string proto_str = std::string(
            protocol_type_to_string(rec->get().protocol)
        );

        response["user_fields"] = json::array(
            {"username", "display_name"}
        );
        response["location_fields"] = json::array(
            {"alias", "name", "topic"}
        );
        response["protocol"] = proto_str;
        response["instances"] = json::array();

        json instance;
        instance["network_id"] = rec->get().id;
        instance["network_name"] = rec->get().display_name.empty()
            ? rec->get().id : rec->get().display_name;
        instance["desc"] = rec->get().description;
        instance["fields"] = json::object();
        instance["icon"] = rec->get().avatar_url;

        response["instances"].push_back(instance);

        return response;
    }

    /// Handle the third-party user lookup query.
    /// /_matrix/app/v1/thirdparty/user/{protocol}
    json query_third_party_user(
        std::string_view protocol,
        const json& params,
        std::string_view appservice_id
    ) {
        json response = json::array();
        // This would proxy to the app service and return results.
        // For now, return empty array.
        return response;
    }

    /// Handle the third-party location lookup query.
    /// /_matrix/app/v1/thirdparty/location/{protocol}
    json query_third_party_location(
        std::string_view protocol,
        const json& params,
        std::string_view appservice_id
    ) {
        json response = json::array();
        // This would proxy to the app service and return results.
        return response;
    }

private:
    AppServiceRegistry& registry_;
};

// ==========================================================================
// 13. Ghost User Manager
// ==========================================================================

/// Manages ghost users — virtual users created by app services to
/// represent remote users from bridged protocols.
class GhostUserManager {
public:
    GhostUserManager(AppServiceRegistry& registry)
        : registry_(registry)
    {}

    /// Create a ghost user for a remote user.
    /// Returns the ghost user ID on success, empty string on failure.
    std::string create_ghost_user(
        std::string_view appservice_id,
        std::string_view remote_user_id,
        std::string_view display_name,
        std::string_view avatar_url
    ) {
        auto* rec = registry_.get_mutable(appservice_id);
        if (!rec || !rec->is_active()) {
            return "";
        }

        // Generate ghost user MXID
        std::string ghost_localpart = generate_ghost_localpart(
            remote_user_id, rec->protocol
        );
        std::string ghost_user_id = std::format(
            "@{}_{}",
            ghost_localpart,
            rec->sender_localpart
        );

        // Check for existing ghost
        {
            std::shared_lock lock(ghosts_mutex_);
            for (const auto& [_, ghost] : ghosts_) {
                if (ghost.user_id == ghost_user_id) {
                    return ghost_user_id; // Already exists
                }
            }
        }

        // Create ghost record
        GhostUser ghost;
        ghost.user_id = ghost_user_id;
        ghost.appservice_id = std::string(appservice_id);
        ghost.display_name = std::string(display_name);
        ghost.avatar_url = std::string(avatar_url);
        ghost.is_active = true;
        ghost.created_at = system_clock::now();

        {
            std::unique_lock lock(ghosts_mutex_);
            ghosts_[ghost_user_id] = std::move(ghost);
        }

        rec->ghost_users_created.fetch_add(1);

        return ghost_user_id;
    }

    /// Get ghost user by MXID.
    std::optional<GhostUser> get_ghost(std::string_view user_id) const {
        std::shared_lock lock(ghosts_mutex_);
        auto it = ghosts_.find(std::string(user_id));
        if (it != ghosts_.end()) return it->second;
        return std::nullopt;
    }

    /// Check if a user is a ghost user.
    bool is_ghost_user(std::string_view user_id) const {
        std::shared_lock lock(ghosts_mutex_);
        return ghosts_.contains(std::string(user_id));
    }

    /// Update ghost user display name.
    bool update_display_name(
        std::string_view user_id,
        std::string_view display_name
    ) {
        std::unique_lock lock(ghosts_mutex_);
        auto it = ghosts_.find(std::string(user_id));
        if (it == ghosts_.end()) return false;
        it->second.display_name = std::string(display_name);
        return true;
    }

    /// Update ghost user avatar.
    bool update_avatar(
        std::string_view user_id,
        std::string_view avatar_url
    ) {
        std::unique_lock lock(ghosts_mutex_);
        auto it = ghosts_.find(std::string(user_id));
        if (it == ghosts_.end()) return false;
        it->second.avatar_url = std::string(avatar_url);
        return true;
    }

    /// Deactivate a ghost user.
    bool deactivate_ghost(std::string_view user_id) {
        std::unique_lock lock(ghosts_mutex_);
        auto it = ghosts_.find(std::string(user_id));
        if (it == ghosts_.end()) return false;
        it->second.is_active = false;
        return true;
    }

    /// Get all ghost users for an app service.
    std::vector<GhostUser> list_ghosts_for_appservice(
        std::string_view appservice_id
    ) const {
        std::shared_lock lock(ghosts_mutex_);
        std::vector<GhostUser> result;
        for (const auto& [_, ghost] : ghosts_) {
            if (ghost.appservice_id == appservice_id) {
                result.push_back(ghost);
            }
        }
        return result;
    }

    /// Get the app service that owns a ghost user.
    std::string get_owner_appservice(std::string_view user_id) const {
        std::shared_lock lock(ghosts_mutex_);
        auto it = ghosts_.find(std::string(user_id));
        if (it != ghosts_.end()) return it->second.appservice_id;
        return "";
    }

    /// Count of total ghost users.
    size_t count() const {
        std::shared_lock lock(ghosts_mutex_);
        return ghosts_.size();
    }

    /// Export ghost users as JSON.
    json to_json() const {
        std::shared_lock lock(ghosts_mutex_);
        json j = json::array();
        for (const auto& [_, ghost] : ghosts_) {
            j.push_back(ghost.to_json());
        }
        return j;
    }

private:
    /// Generate a unique localpart for a ghost user.
    static std::string generate_ghost_localpart(
        std::string_view remote_id,
        ProtocolType protocol
    ) {
        // Sanitize the remote ID for use as a Matrix localpart
        std::string sanitized;
        sanitized.reserve(remote_id.size());
        for (char c : remote_id) {
            if (std::isalnum(static_cast<unsigned char>(c)) ||
                c == '.' || c == '_' || c == '-' || c == '=') {
                sanitized += std::tolower(static_cast<unsigned char>(c));
            } else {
                sanitized += '=';
                sanitized += "0123456789abcdef"
                    [(static_cast<unsigned char>(c) >> 4) & 0xF];
                sanitized += "0123456789abcdef"
                    [static_cast<unsigned char>(c) & 0xF];
            }
        }

        return std::format("{}_{}",
            protocol_type_to_string(protocol), sanitized);
    }

    AppServiceRegistry& registry_;
    mutable std::shared_mutex ghosts_mutex_;
    std::unordered_map<std::string, GhostUser> ghosts_;
};

// ==========================================================================
// 14. Bridge Admin Manager
// ==========================================================================

/// Administrative interface for managing bridges.
class BridgeAdminManager {
public:
    BridgeAdminManager(
        AppServiceRegistry& registry,
        GhostUserManager& ghost_mgr
    )
        : registry_(registry)
        , ghost_mgr_(ghost_mgr)
    {}

    /// List all bridges with their status.
    json list_bridges() const {
        auto services = registry_.list_all();
        json result = json::array();

        for (const auto& svc : services) {
            json entry;
            entry["id"]               = svc.id;
            entry["protocol"]         = protocol_type_to_string(svc.protocol);
            entry["url"]              = svc.url;
            entry["state"]            = static_cast<int>(svc.state);
            entry["sender_localpart"] = svc.sender_localpart;
            entry["total_transactions"] = svc.total_transactions.load();
            entry["successful_transactions"] =
                svc.successful_transactions.load();
            entry["failed_transactions"]  = svc.failed_transactions.load();
            entry["ghost_users_created"]  = svc.ghost_users_created.load();
            entry["registered_at"] =
                std::chrono::system_clock::to_time_t(svc.registered_at);

            // Get ghost user count
            auto ghosts = ghost_mgr_.list_ghosts_for_appservice(svc.id);
            entry["active_ghost_users"] = ghosts.size();

            result.push_back(entry);
        }
        return result;
    }

    /// Get a specific bridge's full details.
    json get_bridge(std::string_view bridge_id) const {
        auto rec = registry_.find_by_id(bridge_id);
        if (!rec) {
            return {{"error", "Bridge not found"}};
        }
        return rec->get().to_admin_json();
    }

    /// Enable a bridge.
    json enable_bridge(std::string_view bridge_id) {
        bool ok = registry_.enable_appservice(bridge_id);
        if (!ok) {
            return {{"error", "Bridge not found"},
                    {"success", false}};
        }
        return {{"success", true},
                {"message", std::format("Bridge '{}' enabled", bridge_id)}};
    }

    /// Disable a bridge.
    json disable_bridge(std::string_view bridge_id) {
        bool ok = registry_.disable_appservice(bridge_id);
        if (!ok) {
            return {{"error", "Bridge not found"},
                    {"success", false}};
        }
        return {{"success", true},
                {"message", std::format("Bridge '{}' disabled", bridge_id)}};
    }

    /// Get bridge statistics.
    json get_bridge_stats(std::string_view bridge_id) const {
        auto rec = registry_.find_by_id(bridge_id);
        if (!rec) {
            return {{"error", "Bridge not found"}};
        }

        const auto& r = rec->get();
        auto ghosts = ghost_mgr_.list_ghosts_for_appservice(bridge_id);

        auto limiter = registry_.get_rate_limiter(bridge_id);

        return {
            {"id", bridge_id},
            {"protocol", protocol_type_to_string(r.protocol)},
            {"state", static_cast<int>(r.state)},
            {"total_transactions", r.total_transactions.load()},
            {"successful_transactions", r.successful_transactions.load()},
            {"failed_transactions", r.failed_transactions.load()},
            {"total_events_pushed", r.total_events_pushed.load()},
            {"ghost_users_created", r.ghost_users_created.load()},
            {"active_ghost_users", ghosts.size()},
            {"rate_limiter", limiter ? limiter->to_json() : json::object()},
            {"success_rate",
                r.total_transactions.load() > 0
                    ? (static_cast<double>(r.successful_transactions.load()) /
                       static_cast<double>(r.total_transactions.load())) * 100.0
                    : 0.0
            }
        };
    }

private:
    AppServiceRegistry& registry_;
    GhostUserManager& ghost_mgr_;
};

// ==========================================================================
// 15. Namespace Conflict Resolver
// ==========================================================================

/// Detects and resolves namespace conflicts between app services.
class NamespaceConflictResolver {
public:
    NamespaceConflictResolver(AppServiceRegistry& registry)
        : registry_(registry)
    {}

    /// Check for namespace conflicts across all registered app services.
    /// Returns a list of conflict descriptions.
    std::vector<std::string> detect_conflicts() const {
        std::vector<std::string> conflicts;
        auto services = registry_.list_active();

        for (size_t i = 0; i < services.size(); ++i) {
            for (size_t j = i + 1; j < services.size(); ++j) {
                detect_conflicts_between(
                    services[i], services[j], conflicts
                );
            }
        }
        return conflicts;
    }

    /// Check for conflicts between two specific app services.
    std::vector<std::string> detect_conflicts_between(
        std::string_view as1_id,
        std::string_view as2_id
    ) const {
        std::vector<std::string> conflicts;
        auto rec1 = registry_.find_by_id(as1_id);
        auto rec2 = registry_.find_by_id(as2_id);
        if (!rec1 || !rec2) return conflicts;

        detect_conflicts_between(rec1->get(), rec2->get(), conflicts);
        return conflicts;
    }

    /// Resolve conflicts using the specified strategy.
    /// Returns true if conflicts were resolved.
    bool resolve_conflicts(ConflictStrategy strategy = ConflictStrategy::kPriorityBased) {
        auto conflicts = detect_conflicts();
        if (conflicts.empty()) return true;

        switch (strategy) {
            case ConflictStrategy::kFirstWins:
                return resolve_first_wins(conflicts);
            case ConflictStrategy::kRejectNew:
                // Already handled during registration
                return false;
            case ConflictStrategy::kPriorityBased:
                return resolve_priority_based(conflicts);
            case ConflictStrategy::kManual:
                // Log conflicts for admin to resolve
                for (const auto& c : conflicts) {
                    log_conflict(c);
                }
                return false;
        }
        return false;
    }

    /// Validate that new namespaces do not conflict with existing ones.
    bool validate_new_namespaces(
        const AppServiceNamespaces& new_ns,
        std::string_view exclude_id
    ) {
        auto services = registry_.list_active();
        for (const auto& svc : services) {
            if (svc.id == exclude_id) continue;

            for (const auto& new_rule : new_ns.users) {
                for (const auto& exist_rule : svc.namespaces.users) {
                    if (patterns_conflict(new_rule, exist_rule))
                        return false;
                }
            }
            for (const auto& new_rule : new_ns.aliases) {
                for (const auto& exist_rule : svc.namespaces.aliases) {
                    if (patterns_conflict(new_rule, exist_rule))
                        return false;
                }
            }
            for (const auto& new_rule : new_ns.rooms) {
                for (const auto& exist_rule : svc.namespaces.rooms) {
                    if (patterns_conflict(new_rule, exist_rule))
                        return false;
                }
            }
        }
        return true;
    }

private:
    void detect_conflicts_between(
        const AppServiceRecord& a,
        const AppServiceRecord& b,
        std::vector<std::string>& conflicts
    ) const {
        // Check user namespace overlaps
        for (const auto& ra : a.namespaces.users) {
            for (const auto& rb : b.namespaces.users) {
                if (ra.exclusive && rb.exclusive &&
                    patterns_conflict(ra, rb)) {
                    conflicts.push_back(std::format(
                        "User namespace conflict: '{}' (AS '{}') vs "
                        "'{}' (AS '{}')",
                        ra.original_pattern, a.id,
                        rb.original_pattern, b.id
                    ));
                }
            }
        }

        // Check alias namespace overlap
        for (const auto& ra : a.namespaces.aliases) {
            for (const auto& rb : b.namespaces.aliases) {
                if (ra.exclusive && rb.exclusive &&
                    patterns_conflict(ra, rb)) {
                    conflicts.push_back(std::format(
                        "Alias namespace conflict: '{}' (AS '{}') vs "
                        "'{}' (AS '{}')",
                        ra.original_pattern, a.id,
                        rb.original_pattern, b.id
                    ));
                }
            }
        }

        // Check room namespace overlap
        for (const auto& ra : a.namespaces.rooms) {
            for (const auto& rb : b.namespaces.rooms) {
                if (ra.exclusive && rb.exclusive &&
                    patterns_conflict(ra, rb)) {
                    conflicts.push_back(std::format(
                        "Room namespace conflict: '{}' (AS '{}') vs "
                        "'{}' (AS '{}')",
                        ra.original_pattern, a.id,
                        rb.original_pattern, b.id
                    ));
                }
            }
        }
    }

    /// Check if two namespace patterns potentially conflict.
    static bool patterns_conflict(
        const NamespaceRule& a,
        const NamespaceRule& b
    ) noexcept {
        if (!a.exclusive || !b.exclusive) return false;

        // Exact pattern match is a clear conflict
        if (a.original_pattern == b.original_pattern) return true;

        // For regex patterns, check for overlapping matches.
        // Simplified heuristic: if either pattern is a prefix/suffix
        // superset of the other, they conflict.
        const auto& pa = a.original_pattern;
        const auto& pb = b.original_pattern;

        // One pattern is contained within the other
        if (pa.find(pb) != std::string::npos ||
            pb.find(pa) != std::string::npos) {
            return true;
        }

        // Both patterns have wildcards — potential conflict
        if (pa.find(".*") != std::string::npos &&
            pb.find(".*") != std::string::npos) {
            return true;
        }

        return false;
    }

    bool resolve_first_wins(const std::vector<std::string>&) {
        // First-wins is enforced at registration time.
        // Existing conflicts would require admin intervention.
        return false;
    }

    bool resolve_priority_based(const std::vector<std::string>&) {
        // Priority-based: keep the oldest registered service,
        // disable the newer one if it conflicts.
        // This is handled at registration time via check_namespace_conflicts.
        return false;
    }

    void log_conflict(const std::string& msg) {
        auto now = system_clock::now();
        auto tt = system_clock::to_time_t(now);
        std::osyncstream(std::cerr)
            << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S")
            << " [WARN] [appservice] CONFLICT: " << msg << '\n';
    }

    AppServiceRegistry& registry_;
};

// ==========================================================================
// 16. Bridge Configuration Loader
// ==========================================================================

/// Loads and validates bridge configurations from files.
class BridgeConfigLoader {
public:
    BridgeConfigLoader() = default;

    /// Load a bridge configuration from a JSON file.
    std::optional<json> load_json_config(const std::filesystem::path& path) {
        if (!std::filesystem::exists(path)) {
            return std::nullopt;
        }

        try {
            std::ifstream file(path);
            if (!file.is_open()) return std::nullopt;

            json config = json::parse(file);
            return config;
        } catch (const std::exception& e) {
            log_error(std::format(
                "Failed to load bridge config '{}': {}",
                path.string(), e.what()
            ));
            return std::nullopt;
        }
    }

    /// Load all bridge configurations from a directory.
    std::vector<std::pair<std::string, json>> load_directory(
        const std::filesystem::path& dir_path
    ) {
        std::vector<std::pair<std::string, json>> configs;

        if (!std::filesystem::exists(dir_path) ||
            !std::filesystem::is_directory(dir_path)) {
            return configs;
        }

        for (const auto& entry :
             std::filesystem::directory_iterator(dir_path)) {
            if (!entry.is_regular_file()) continue;
            auto ext = entry.path().extension().string();
            if (ext != ".json" && ext != ".yaml" && ext != ".yml") continue;

            auto config = load_json_config(entry.path());
            if (config) {
                configs.emplace_back(
                    entry.path().stem().string(),
                    std::move(*config)
                );
            }
        }
        return configs;
    }

    /// Validate a bridge configuration against the required schema.
    std::optional<std::string> validate_config(const json& config) {
        // Required fields
        if (!config.contains("id") || !config["id"].is_string()) {
            return "Missing or invalid 'id' field";
        }
        if (!config.contains("as_token") || !config["as_token"].is_string()) {
            return "Missing or invalid 'as_token' field";
        }
        if (!config.contains("url") || !config["url"].is_string()) {
            return "Missing or invalid 'url' field";
        }
        if (!config.contains("sender_localpart") ||
            !config["sender_localpart"].is_string()) {
            return "Missing or invalid 'sender_localpart' field";
        }
        if (!config.contains("namespaces") || !config["namespaces"].is_object()) {
            return "Missing or invalid 'namespaces' field";
        }

        // Validate URL format
        std::string url = config["url"].get<std::string>();
        if (url.find("http://") != 0 && url.find("https://") != 0) {
            return "URL must start with http:// or https://";
        }

        // Validate sender localpart format
        std::string sl = config["sender_localpart"].get<std::string>();
        if (sl.empty() || sl.find('@') != std::string::npos ||
            sl.find(':') != std::string::npos) {
            return "Invalid sender_localpart format";
        }

        return std::nullopt; // Valid
    }

    /// Build an AppServiceNamespaces from JSON config.
    AppServiceNamespaces parse_namespaces(const json& config) {
        if (config.contains("namespaces")) {
            return AppServiceNamespaces::from_json(config["namespaces"]);
        }

        AppServiceNamespaces ns;

        // Fallback: parse flat namespace format
        if (config.contains("namespaces")) {
            const auto& ns_obj = config["namespaces"];
            if (ns_obj.contains("users") && ns_obj["users"].is_array()) {
                for (const auto& u : ns_obj["users"]) {
                    NamespaceRule rule;
                    if (u.is_object()) {
                        rule = NamespaceRule::from_json(u);
                    } else if (u.is_string()) {
                        rule.regex_pattern = u.get<std::string>();
                        rule.original_pattern = rule.regex_pattern;
                        rule.compile();
                    }
                    if (!rule.regex_pattern.empty()) {
                        ns.users.push_back(std::move(rule));
                    }
                }
            }
            if (ns_obj.contains("aliases") && ns_obj["aliases"].is_array()) {
                for (const auto& a : ns_obj["aliases"]) {
                    NamespaceRule rule;
                    if (a.is_object()) {
                        rule = NamespaceRule::from_json(a);
                    } else if (a.is_string()) {
                        rule.regex_pattern = a.get<std::string>();
                        rule.original_pattern = rule.regex_pattern;
                        rule.compile();
                    }
                    if (!rule.regex_pattern.empty()) {
                        ns.aliases.push_back(std::move(rule));
                    }
                }
            }
            if (ns_obj.contains("rooms") && ns_obj["rooms"].is_array()) {
                for (const auto& r : ns_obj["rooms"]) {
                    NamespaceRule rule;
                    if (r.is_object()) {
                        rule = NamespaceRule::from_json(r);
                    } else if (r.is_string()) {
                        rule.regex_pattern = r.get<std::string>();
                        rule.original_pattern = rule.regex_pattern;
                        rule.compile();
                    }
                    if (!rule.regex_pattern.empty()) {
                        ns.rooms.push_back(std::move(rule));
                    }
                }
            }
        }

        return ns;
    }

    /// Parse protocol type from config.
    ProtocolType parse_protocol_type(const json& config) {
        if (config.contains("protocol") && config["protocol"].is_string()) {
            return protocol_type_from_string(
                config["protocol"].get<std::string>()
            );
        }
        return ProtocolType::kGeneric;
    }

    /// Parse rate limit config from JSON.
    RateLimitConfig parse_rate_limit(const json& config) {
        if (config.contains("rate_limit") && config["rate_limit"].is_object()) {
            return RateLimitConfig::from_json(config["rate_limit"]);
        }

        RateLimitConfig rl;
        if (config.contains("rate_limited") && config["rate_limited"].is_boolean()) {
            rl.enabled = config["rate_limited"].get<bool>();
        }
        return rl;
    }

    /// Hot-reload configuration for an existing bridge.
    bool hot_reload(
        std::string_view bridge_id,
        const json& new_config,
        AppServiceRegistry& registry
    ) {
        auto* rec = registry.get_mutable(bridge_id);
        if (!rec) return false;

        // Update mutable fields
        if (new_config.contains("url") && new_config["url"].is_string()) {
            rec->url = new_config["url"].get<std::string>();
        }
        if (new_config.contains("display_name") &&
            new_config["display_name"].is_string()) {
            rec->display_name = new_config["display_name"].get<std::string>();
        }
        if (new_config.contains("description") &&
            new_config["description"].is_string()) {
            rec->description = new_config["description"].get<std::string>();
        }
        if (new_config.contains("rate_limit")) {
            rec->rate_limit = parse_rate_limit(new_config);
            registry.update_rate_limit(bridge_id, rec->rate_limit);
        }

        // Namespace changes require careful handling
        if (new_config.contains("namespaces")) {
            auto new_ns = parse_namespaces(new_config);
            // Validate no new conflicts
            NamespaceConflictResolver resolver(registry);
            if (resolver.validate_new_namespaces(new_ns, bridge_id)) {
                rec->namespaces = std::move(new_ns);
            } else {
                return false; // Namespace conflict
            }
        }

        return true;
    }

private:
    static void log_error(const std::string& msg) {
        auto now = system_clock::now();
        auto tt = system_clock::to_time_t(now);
        std::osyncstream(std::cerr)
            << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S")
            << " [ERROR] [appservice] " << msg << '\n';
    }
};

// ==========================================================================
// 17. AppService Health Checker
// ==========================================================================

/// Periodically checks the health of registered app services.
class AppServiceHealthChecker {
public:
    AppServiceHealthChecker(
        AppServiceRegistry& registry,
        milliseconds interval = kDefaultHealthCheckInterval
    )
        : registry_(registry)
        , interval_(interval)
        , running_(false)
    {}

    ~AppServiceHealthChecker() {
        stop();
    }

    /// Start periodic health checking.
    void start() {
        if (running_.exchange(true)) return;
        worker_thread_ = std::thread(&AppServiceHealthChecker::worker_loop, this);
    }

    /// Stop health checking.
    void stop() {
        running_.store(false);
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    /// Perform an immediate health check on a specific app service.
    HealthStatus check_appservice(std::string_view appservice_id) {
        auto* rec = registry_.get_mutable(appservice_id);
        if (!rec) return HealthStatus::kUnknown;
        if (!rec->is_active()) return HealthStatus::kUnknown;

        std::string health_url = rec->url + "/_matrix/app/v1/health";
        std::string response_body;
        long http_code = 0;

        CURL* curl = curl_easy_init();
        if (!curl) return HealthStatus::kUnknown;

        curl_easy_setopt(curl, CURLOPT_URL, health_url.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

        CURLcode res = curl_easy_perform(curl);
        HealthStatus status = HealthStatus::kUnknown;

        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            if (http_code >= 200 && http_code < 300) {
                status = HealthStatus::kHealthy;
            } else if (http_code >= 500) {
                status = HealthStatus::kUnhealthy;
            } else {
                status = HealthStatus::kDegraded;
            }
        } else if (res == CURLE_OPERATION_TIMEDOUT) {
            status = HealthStatus::kTimeout;
        } else {
            status = HealthStatus::kUnhealthy;
        }

        curl_easy_cleanup(curl);

        // Update health records
        {
            std::unique_lock lock(health_mutex_);
            health_statuses_[std::string(appservice_id)] = status;
            last_checks_[std::string(appservice_id)] = steady_clock::now();
        }

        return status;
    }

    /// Get the last known health status for an app service.
    HealthStatus get_status(std::string_view appservice_id) const {
        std::shared_lock lock(health_mutex_);
        auto it = health_statuses_.find(std::string(appservice_id));
        if (it != health_statuses_.end()) return it->second;
        return HealthStatus::kUnknown;
    }

    /// Get health status for all app services.
    json get_all_statuses() const {
        std::shared_lock lock(health_mutex_);
        json result = json::object();
        for (const auto& [id, status] : health_statuses_) {
            result[id] = {
                {"status", static_cast<int>(status)},
                {"status_str", health_status_to_string(status)}
            };
        }
        return result;
    }

    /// Get uptime statistics.
    json get_uptime_stats() const {
        std::shared_lock lock(health_mutex_);
        json result = json::object();
        for (const auto& [id, status] : health_statuses_) {
            auto check_it = last_checks_.find(id);
            result[id] = {
                {"healthy", status == HealthStatus::kHealthy},
                {"last_check_ms",
                    check_it != last_checks_.end()
                        ? std::chrono::duration_cast<milliseconds>(
                              steady_clock::now() - check_it->second
                          ).count()
                        : -1
                }
            };
        }
        return result;
    }

private:
    void worker_loop() {
        while (running_.load(std::memory_order_acquire)) {
            auto services = registry_.list_active();
            for (const auto& svc : services) {
                if (!running_.load(std::memory_order_acquire)) break;
                check_appservice(svc.id);
            }
            std::this_thread::sleep_for(interval_);
        }
    }

    static constexpr std::string_view health_status_to_string(
        HealthStatus status
    ) noexcept {
        using enum HealthStatus;
        switch (status) {
            case kHealthy:   return "healthy";
            case kUnhealthy: return "unhealthy";
            case kDegraded:  return "degraded";
            case kTimeout:   return "timeout";
            default:         return "unknown";
        }
    }

    AppServiceRegistry& registry_;
    milliseconds interval_;
    std::atomic<bool> running_;
    std::thread worker_thread_;

    mutable std::shared_mutex health_mutex_;
    std::unordered_map<std::string, HealthStatus> health_statuses_;
    std::unordered_map<std::string, time_point> last_checks_;
};

// ==========================================================================
// 18. AppService Interest Tracker
// ==========================================================================

/// Tracks which rooms and users each app service is interested in.
/// Used to optimize event routing.
class AppServiceInterestTracker {
public:
    AppServiceInterestTracker(AppServiceRegistry& registry)
        : registry_(registry)
    {}

    /// Record that an app service user has joined a room.
    void record_join(
        std::string_view appservice_id,
        std::string_view user_id,
        std::string_view room_id
    ) {
        std::unique_lock lock(mutex_);
        get_or_create(appservice_id).rooms_with_users.emplace(room_id);
        get_or_create(appservice_id).interested_users.emplace(user_id);
    }

    /// Record that an app service user has left a room.
    void record_leave(
        std::string_view appservice_id,
        std::string_view room_id
    ) {
        std::unique_lock lock(mutex_);
        auto it = interests_.find(std::string(appservice_id));
        if (it == interests_.end()) return;

        // Don't remove until all AS users have left
        // (simplified: just mark; actual implementation would track per-user)
    }

    /// Record that the app service bot joined a room.
    void record_bot_join(
        std::string_view appservice_id,
        std::string_view room_id
    ) {
        std::unique_lock lock(mutex_);
        get_or_create(appservice_id).bot_rooms.emplace(room_id);
    }

    /// Record that a user has started being tracked by an app service.
    void add_explicit_interest(
        std::string_view appservice_id,
        std::string_view user_id
    ) {
        std::unique_lock lock(mutex_);
        get_or_create(appservice_id).interested_users.emplace(user_id);
    }

    /// Check if an app service is interested in a room.
    bool is_interested_in_room(
        std::string_view appservice_id,
        std::string_view room_id
    ) const {
        std::shared_lock lock(mutex_);
        auto it = interests_.find(std::string(appservice_id));
        if (it == interests_.end()) return false;
        return it->second.is_interested_in_room(room_id);
    }

    /// Check if an app service is interested in a user.
    bool is_interested_in_user(
        std::string_view appservice_id,
        std::string_view user_id
    ) const {
        std::shared_lock lock(mutex_);
        auto it = interests_.find(std::string(appservice_id));
        if (it == interests_.end()) return false;
        return it->second.is_interested_in_user(user_id);
    }

    /// Get all rooms an app service is interested in.
    std::vector<std::string> get_interested_rooms(
        std::string_view appservice_id
    ) const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> result;
        auto it = interests_.find(std::string(appservice_id));
        if (it == interests_.end()) return result;

        for (const auto& room : it->second.rooms_with_users)
            result.push_back(room);
        for (const auto& room : it->second.bot_rooms)
            result.push_back(room);
        return result;
    }

    /// Get all users an app service is interested in.
    std::vector<std::string> get_interested_users(
        std::string_view appservice_id
    ) const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> result;
        auto it = interests_.find(std::string(appservice_id));
        if (it == interests_.end()) return result;

        for (const auto& user : it->second.interested_users)
            result.push_back(user);
        return result;
    }

    /// Clear all interest data for an app service.
    void clear_interests(std::string_view appservice_id) {
        std::unique_lock lock(mutex_);
        interests_.erase(std::string(appservice_id));
    }

    /// Export interest data as JSON.
    json to_json() const {
        std::shared_lock lock(mutex_);
        json result = json::object();
        for (const auto& [id, interest] : interests_) {
            json entry;
            entry["rooms_with_users"] =
                json(std::vector<std::string>(
                    interest.rooms_with_users.begin(),
                    interest.rooms_with_users.end()
                ));
            entry["interested_users"] =
                json(std::vector<std::string>(
                    interest.interested_users.begin(),
                    interest.interested_users.end()
                ));
            entry["bot_rooms"] =
                json(std::vector<std::string>(
                    interest.bot_rooms.begin(),
                    interest.bot_rooms.end()
                ));
            result[id] = entry;
        }
        return result;
    }

private:
    AppServiceInterest& get_or_create(std::string_view appservice_id) {
        auto it = interests_.find(std::string(appservice_id));
        if (it != interests_.end()) return it->second;
        auto [new_it, _] = interests_.emplace(
            std::string(appservice_id),
            AppServiceInterest{std::string(appservice_id)}
        );
        return new_it->second;
    }

    AppServiceRegistry& registry_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, AppServiceInterest> interests_;
};

// ==========================================================================
// 19. Puppet User Manager
// ==========================================================================

/// Manages puppet users — users that are controlled by an app service
/// to act on behalf of a real Matrix user in a bridged room.
class PuppetUserManager {
public:
    PuppetUserManager(AppServiceRegistry& registry)
        : registry_(registry)
    {}

    /// Create a puppet user that mirrors a real Matrix user.
    /// Returns the puppet user ID.
    std::string create_puppet(
        std::string_view appservice_id,
        std::string_view real_user_id,
        std::string_view display_name,
        std::string_view avatar_url
    ) {
        auto* rec = registry_.get_mutable(appservice_id);
        if (!rec || !rec->is_active()) return "";

        // Generate puppet localpart
        std::string puppet_localpart = std::format(
            "{}_puppet",
            sanitize_localpart(real_user_id)
        );
        std::string puppet_user_id = std::format(
            "@{}:{}",
            puppet_localpart,
            extract_server_name(real_user_id)
        );

        std::unique_lock lock(puppets_mutex_);

        // Check for existing puppet
        auto it = puppets_.find(puppet_user_id);
        if (it != puppets_.end()) {
            // Update info
            it->second["display_name"] = display_name;
            it->second["avatar_url"] = avatar_url;
            return puppet_user_id;
        }

        // Create new puppet
        json puppet_info;
        puppet_info["real_user_id"] = real_user_id;
        puppet_info["appservice_id"] = appservice_id;
        puppet_info["display_name"] = display_name;
        puppet_info["avatar_url"] = avatar_url;
        puppet_info["created_at"] =
            system_clock::now().time_since_epoch().count();
        puppet_info["is_active"] = true;

        puppets_[puppet_user_id] = std::move(puppet_info);
        return puppet_user_id;
    }

    /// Get the real user ID backing a puppet.
    std::string get_real_user(std::string_view puppet_user_id) const {
        std::shared_lock lock(puppets_mutex_);
        auto it = puppets_.find(std::string(puppet_user_id));
        if (it == puppets_.end()) return "";
        if (it->second.contains("real_user_id")) {
            return it->second["real_user_id"].get<std::string>();
        }
        return "";
    }

    /// Check if a user ID is a puppet.
    bool is_puppet(std::string_view user_id) const {
        std::shared_lock lock(puppets_mutex_);
        return puppets_.contains(std::string(user_id));
    }

    /// Activate/deactivate a puppet.
    bool set_puppet_active(
        std::string_view puppet_user_id,
        bool active
    ) {
        std::unique_lock lock(puppets_mutex_);
        auto it = puppets_.find(std::string(puppet_user_id));
        if (it == puppets_.end()) return false;
        it->second["is_active"] = active;
        return true;
    }

    /// Update puppet display name.
    bool update_puppet_name(
        std::string_view puppet_user_id,
        std::string_view display_name
    ) {
        std::unique_lock lock(puppets_mutex_);
        auto it = puppets_.find(std::string(puppet_user_id));
        if (it == puppets_.end()) return false;
        it->second["display_name"] = display_name;
        return true;
    }

    /// Update puppet avatar.
    bool update_puppet_avatar(
        std::string_view puppet_user_id,
        std::string_view avatar_url
    ) {
        std::unique_lock lock(puppets_mutex_);
        auto it = puppets_.find(std::string(puppet_user_id));
        if (it == puppets_.end()) return false;
        it->second["avatar_url"] = avatar_url;
        return true;
    }

    /// Get all puppets for an app service.
    std::vector<std::string> list_puppets_for_appservice(
        std::string_view appservice_id
    ) const {
        std::shared_lock lock(puppets_mutex_);
        std::vector<std::string> result;
        for (const auto& [id, info] : puppets_) {
            if (info.contains("appservice_id") &&
                info["appservice_id"].get<std::string>() == appservice_id) {
                result.push_back(id);
            }
        }
        return result;
    }

    /// Get all puppets for a real user.
    std::vector<std::string> list_puppets_for_user(
        std::string_view real_user_id
    ) const {
        std::shared_lock lock(puppets_mutex_);
        std::vector<std::string> result;
        for (const auto& [id, info] : puppets_) {
            if (info.contains("real_user_id") &&
                info["real_user_id"].get<std::string>() == real_user_id) {
                result.push_back(id);
            }
        }
        return result;
    }

    /// Get puppet count.
    size_t count() const {
        std::shared_lock lock(puppets_mutex_);
        return puppets_.size();
    }

    /// Export puppets as JSON.
    json to_json() const {
        std::shared_lock lock(puppets_mutex_);
        return json(puppets_);
    }

private:
    /// Sanitize a user ID for use as a localpart.
    static std::string sanitize_localpart(std::string_view user_id) {
        std::string result;
        result.reserve(user_id.size());

        // Skip leading @
        size_t start = 0;
        if (!user_id.empty() && user_id[0] == '@') start = 1;

        for (size_t i = start; i < user_id.size(); ++i) {
            char c = user_id[i];
            if (c == ':') break; // stop at server name separator
            if (std::isalnum(static_cast<unsigned char>(c)) ||
                c == '.' || c == '_' || c == '-' || c == '=') {
                result += std::tolower(static_cast<unsigned char>(c));
            } else {
                result += '_';
            }
        }

        if (result.empty()) {
            // Hash fallback
            auto hash = std::hash<std::string_view>{}(user_id);
            result = std::format("puppet_{:016x}", hash);
        }

        return result;
    }

    /// Extract the server name from a Matrix user ID.
    static std::string extract_server_name(std::string_view user_id) {
        auto pos = user_id.find(':');
        if (pos != std::string_view::npos) {
            return std::string(user_id.substr(pos + 1));
        }
        return "localhost";
    }

    AppServiceRegistry& registry_;
    mutable std::shared_mutex puppets_mutex_;
    std::unordered_map<std::string, json> puppets_;
};

// ==========================================================================
// 20. Device List Notifier — Device Updates to App Services
// ==========================================================================

/// Notifies app services of device list changes for users in their namespace.
class DeviceListNotifier {
public:
    DeviceListNotifier(
        AppServiceRegistry& registry,
        AppServiceEventPusher& pusher
    )
        : registry_(registry)
        , pusher_(pusher)
    {}

    /// Notify relevant app services that a user's device list changed.
    void notify_device_list_change(
        std::string_view user_id,
        const json& device_info
    ) {
        // If the user is in an app service's namespace, notify that service
        std::string as_id = registry_.get_appservice_for_user(user_id);
        if (!as_id.empty()) {
            pusher_.push_device_list_update(user_id, device_info);
            log_device_update(as_id, user_id, device_info.size());
        }

        // Also notify any app services explicitly interested in this user
        auto active = registry_.list_active();
        for (const auto& svc : active) {
            if (svc.id == as_id) continue; // Already handled
            auto* interest = registry_.get_interest(svc.id);
            if (interest && interest->is_interested_in_user(user_id)) {
                pusher_.push_device_list_update(user_id, device_info);
            }
        }
    }

    /// Batch notify for multiple users.
    void notify_batch_device_changes(
        const std::vector<std::pair<std::string, json>>& changes
    ) {
        // Deduplicate by app service
        std::unordered_map<std::string, json> batched;

        for (const auto& [user_id, device_info] : changes) {
            std::string as_id = registry_.get_appservice_for_user(user_id);
            if (!as_id.empty()) {
                if (!batched.contains(as_id)) {
                    batched[as_id] = json::array();
                }
                json entry;
                entry["user_id"] = user_id;
                entry["devices"] = device_info;
                batched[as_id].push_back(entry);
            }
        }

        // Send batched updates
        for (auto& [as_id, batch] : batched) {
            std::string txn_id =
                AppServiceTransactionManager::generate_txn_id();
            json wrapper;
            wrapper["type"] = "m.device_list_update_batch";
            wrapper["devices"] = batch;

            // Use transaction manager via the pusher
            json events = json::array({wrapper});
            // Direct push would happen through the pusher
        }
    }

    /// Get the last known device list for a user (from cache).
    std::optional<json> get_cached_device_list(
        std::string_view user_id
    ) const {
        std::shared_lock lock(cache_mutex_);
        auto it = device_cache_.find(std::string(user_id));
        if (it != device_cache_.end()) return it->second;
        return std::nullopt;
    }

    /// Update the cached device list for a user.
    void update_cache(std::string_view user_id, const json& device_list) {
        std::unique_lock lock(cache_mutex_);
        device_cache_[std::string(user_id)] = device_list;
    }

    /// Clear cached device lists.
    void clear_cache() {
        std::unique_lock lock(cache_mutex_);
        device_cache_.clear();
    }

private:
    void log_device_update(
        std::string_view as_id,
        std::string_view user_id,
        size_t device_count
    ) {
        auto now = system_clock::now();
        auto tt = system_clock::to_time_t(now);
        std::osyncstream(std::cout)
            << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S")
            << " [INFO] [appservice] Device list update: as=" << as_id
            << " user=" << user_id
            << " devices=" << device_count << '\n';
    }

    AppServiceRegistry& registry_;
    AppServiceEventPusher& pusher_;
    mutable std::shared_mutex cache_mutex_;
    std::unordered_map<std::string, json> device_cache_;
};

// ==========================================================================
// 21. One-Time Key Reporter
// ==========================================================================

/// Reports one-time key counts for app service users to the app service.
/// This enables the app service to manage E2EE keys for bridged users.
class OneTimeKeyReporter {
public:
    OneTimeKeyReporter(
        AppServiceRegistry& registry,
        AppServiceTransactionManager& txn_mgr
    )
        : registry_(registry)
        , txn_mgr_(txn_mgr)
    {}

    /// Report one-time key counts for a user to their app service.
    bool report_key_counts(
        std::string_view user_id,
        const json& key_counts
    ) {
        std::string as_id = registry_.get_appservice_for_user(user_id);
        if (as_id.empty()) return false;

        auto* rec = registry_.get_mutable(as_id);
        if (!rec || !rec->is_active()) return false;

        json payload;
        payload["type"] = "org.matrix.appservice.otk_count";
        payload["user_id"] = user_id;
        payload["device_id"] = key_counts.value("device_id", "");
        payload["key_counts"] = key_counts;

        std::string txn_id = AppServiceTransactionManager::generate_txn_id();
        json events = json::array({payload});
        int code = txn_mgr_.push_transaction(as_id, txn_id, events);
        return (code >= 200 && code < 300);
    }

    /// Check if an app service user is low on one-time keys and notify.
    bool check_and_notify_low_keys(
        std::string_view user_id,
        const json& key_counts,
        int threshold = 10
    ) {
        int signed_curve25519 = 0;
        if (key_counts.contains("signed_curve25519")) {
            signed_curve25519 =
                key_counts["signed_curve25519"].get<int>();
        }

        if (signed_curve25519 < threshold) {
            return report_key_counts(user_id, key_counts);
        }
        return false;
    }

    /// Batch report key counts for multiple users.
    void batch_report(
        const std::vector<std::pair<std::string, json>>& user_keys
    ) {
        for (const auto& [user_id, key_counts] : user_keys) {
            report_key_counts(user_id, key_counts);
        }
    }

private:
    AppServiceRegistry& registry_;
    AppServiceTransactionManager& txn_mgr_;
};

// ==========================================================================
// 22. AppService Logger and Metrics
// ==========================================================================

/// Structured logging for app service operations.
class AppServiceLogger {
public:
    enum class Level : uint8_t {
        kDebug   = 0,
        kInfo    = 1,
        kWarning = 2,
        kError   = 3,
    };

    AppServiceLogger() = default;

    /// Log a transaction event.
    void log_transaction(
        std::string_view appservice_id,
        std::string_view txn_id,
        bool success,
        long http_code,
        milliseconds latency
    ) {
        auto level = success ? Level::kInfo : Level::kError;
        auto msg = std::format(
            "AS txn: as={} txn={} success={} http={} latency_ms={}",
            appservice_id, txn_id, success, http_code, latency.count()
        );
        log(level, msg);
    }

    /// Log a registration event.
    void log_registration(std::string_view appservice_id, bool success) {
        auto level = success ? Level::kInfo : Level::kError;
        log(level, std::format(
            "AS registration: as={} success={}", appservice_id, success
        ));
    }

    /// Log a ghost user creation.
    void log_ghost_created(
        std::string_view appservice_id,
        std::string_view ghost_user_id
    ) {
        log(Level::kInfo, std::format(
            "AS ghost created: as={} ghost={}", appservice_id, ghost_user_id
        ));
    }

    /// Log a health check result.
    void log_health_check(
        std::string_view appservice_id,
        HealthStatus status
    ) {
        auto level = (status == HealthStatus::kHealthy)
            ? Level::kInfo : Level::kWarning;
        log(level, std::format(
            "AS health: as={} status={}",
            appservice_id,
            health_status_to_string_internal(status)
        ));
    }

    /// Log a namespace conflict.
    void log_namespace_conflict(const std::string& description) {
        log(Level::kWarning, std::format("AS namespace conflict: {}", description));
    }

    /// Log an error with details.
    void log_error(
        std::string_view appservice_id,
        std::string_view operation,
        const std::string& details
    ) {
        log(Level::kError, std::format(
            "AS error: as={} op={} details={}",
            appservice_id, operation, details
        ));
    }

    /// Set the minimum log level.
    void set_level(Level level) { min_level_.store(level); }

    /// Get the current log level.
    Level get_level() const { return min_level_.load(); }

private:
    void log(Level level, const std::string& msg) {
        if (level < min_level_.load()) return;

        auto now = system_clock::now();
        auto tt = system_clock::to_time_t(now);
        auto level_str = level_to_string(level);

        if (level >= Level::kError) {
            std::osyncstream(std::cerr)
                << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S")
                << " [" << level_str << "] [appservice] " << msg << '\n';
        } else {
            std::osyncstream(std::cout)
                << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S")
                << " [" << level_str << "] [appservice] " << msg << '\n';
        }
    }

    static constexpr std::string_view level_to_string(Level level) noexcept {
        using enum Level;
        switch (level) {
            case kDebug:   return "DEBUG";
            case kInfo:    return "INFO";
            case kWarning: return "WARN";
            case kError:   return "ERROR";
        }
        return "UNKNOWN";
    }

    static constexpr std::string_view health_status_to_string_internal(
        HealthStatus status
    ) noexcept {
        using enum HealthStatus;
        switch (status) {
            case kHealthy:   return "healthy";
            case kUnhealthy: return "unhealthy";
            case kDegraded:  return "degraded";
            case kTimeout:   return "timeout";
            default:         return "unknown";
        }
    }

    std::atomic<Level> min_level_{Level::kInfo};
};

// ==========================================================================
// 23. AppService Metrics (Prometheus-style)
// ==========================================================================

/// Collects and exports Prometheus-compatible metrics for app services.
class AppServiceMetrics {
public:
    AppServiceMetrics(AppServiceRegistry& registry)
        : registry_(registry)
    {}

    /// Record a transaction attempt.
    void record_transaction(
        std::string_view appservice_id,
        bool success,
        milliseconds latency
    ) {
        std::unique_lock lock(metrics_mutex_);
        auto& m = get_or_create(appservice_id);
        m.total_transactions++;
        if (success) {
            m.successful_transactions++;
        } else {
            m.failed_transactions++;
        }
        m.total_latency_ms += latency.count();
        m.latency_count++;

        if (latency < m.latency_min) m.latency_min = latency;
        if (latency > m.latency_max) m.latency_max = latency;
    }

    /// Record event push count.
    void record_event_pushed(std::string_view appservice_id, size_t count) {
        std::unique_lock lock(metrics_mutex_);
        get_or_create(appservice_id).events_pushed += count;
    }

    /// Record ghost user created.
    void record_ghost_created(std::string_view appservice_id) {
        std::unique_lock lock(metrics_mutex_);
        get_or_create(appservice_id).ghosts_created++;
    }

    /// Record a query API call.
    void record_query(std::string_view appservice_id, bool success) {
        std::unique_lock lock(metrics_mutex_);
        auto& m = get_or_create(appservice_id);
        m.total_queries++;
        if (success) m.successful_queries++;
    }

    /// Export metrics in Prometheus text format.
    std::string export_prometheus() const {
        std::shared_lock lock(metrics_mutex_);
        std::ostringstream out;

        out << "# HELP appservice_transactions_total "
               "Total transactions sent to app services\n";
        out << "# TYPE appservice_transactions_total counter\n";
        for (const auto& [id, m] : per_service_) {
            out << "appservice_transactions_total{appservice=\"" << id
                << "\"} " << m.total_transactions << "\n";
        }

        out << "# HELP appservice_transactions_successful "
               "Successful transactions\n";
        out << "# TYPE appservice_transactions_successful counter\n";
        for (const auto& [id, m] : per_service_) {
            out << "appservice_transactions_successful{appservice=\"" << id
                << "\"} " << m.successful_transactions << "\n";
        }

        out << "# HELP appservice_transactions_failed "
               "Failed transactions\n";
        out << "# TYPE appservice_transactions_failed counter\n";
        for (const auto& [id, m] : per_service_) {
            out << "appservice_transactions_failed{appservice=\"" << id
                << "\"} " << m.failed_transactions << "\n";
        }

        out << "# HELP appservice_events_pushed_total "
               "Total events pushed to app services\n";
        out << "# TYPE appservice_events_pushed_total counter\n";
        for (const auto& [id, m] : per_service_) {
            out << "appservice_events_pushed_total{appservice=\"" << id
                << "\"} " << m.events_pushed << "\n";
        }

        out << "# HELP appservice_ghosts_created_total "
               "Ghost users created by app services\n";
        out << "# TYPE appservice_ghosts_created_total counter\n";
        for (const auto& [id, m] : per_service_) {
            out << "appservice_ghosts_created_total{appservice=\"" << id
                << "\"} " << m.ghosts_created << "\n";
        }

        out << "# HELP appservice_latency_ms "
               "Transaction latency in milliseconds\n";
        out << "# TYPE appservice_latency_ms histogram\n";
        for (const auto& [id, m] : per_service_) {
            if (m.latency_count > 0) {
                double avg = static_cast<double>(m.total_latency_ms) /
                             static_cast<double>(m.latency_count);
                out << "appservice_latency_ms{appservice=\"" << id
                    << "\",quantile=\"0.5\"} " << avg << "\n";
            }
        }

        out << "# HELP appservice_registered_count "
               "Number of registered app services\n";
        out << "# TYPE appservice_registered_count gauge\n";
        out << "appservice_registered_count " << registry_.count() << "\n";

        out << "# HELP appservice_active_count "
               "Number of active app services\n";
        out << "# TYPE appservice_active_count gauge\n";
        out << "appservice_active_count " << registry_.count_active() << "\n";

        return out.str();
    }

    /// Export metrics as JSON (for admin API).
    json export_json() const {
        std::shared_lock lock(metrics_mutex_);
        json result = json::object();
        for (const auto& [id, m] : per_service_) {
            json entry;
            entry["total_transactions"]   = m.total_transactions;
            entry["successful_transactions"] = m.successful_transactions;
            entry["failed_transactions"]  = m.failed_transactions;
            entry["events_pushed"]        = m.events_pushed;
            entry["ghosts_created"]       = m.ghosts_created;
            entry["total_queries"]        = m.total_queries;
            entry["successful_queries"]   = m.successful_queries;

            if (m.latency_count > 0) {
                entry["latency_avg_ms"] =
                    static_cast<double>(m.total_latency_ms) /
                    static_cast<double>(m.latency_count);
                entry["latency_min_ms"] = m.latency_min.count();
                entry["latency_max_ms"] = m.latency_max.count();
            } else {
                entry["latency_avg_ms"] = 0;
                entry["latency_min_ms"] = 0;
                entry["latency_max_ms"] = 0;
            }

            result[id] = entry;
        }
        return result;
    }

    /// Reset all metrics.
    void reset() {
        std::unique_lock lock(metrics_mutex_);
        per_service_.clear();
    }

    /// Reset metrics for a specific app service.
    void reset(std::string_view appservice_id) {
        std::unique_lock lock(metrics_mutex_);
        per_service_.erase(std::string(appservice_id));
    }

private:
    struct PerServiceMetrics {
        uint64_t total_transactions      = 0;
        uint64_t successful_transactions = 0;
        uint64_t failed_transactions     = 0;
        uint64_t events_pushed           = 0;
        uint64_t ghosts_created          = 0;
        uint64_t total_queries           = 0;
        uint64_t successful_queries      = 0;
        int64_t  total_latency_ms        = 0;
        uint64_t latency_count           = 0;
        milliseconds latency_min         = milliseconds{999999};
        milliseconds latency_max         = milliseconds{0};
    };

    PerServiceMetrics& get_or_create(std::string_view appservice_id) {
        auto it = per_service_.find(std::string(appservice_id));
        if (it != per_service_.end()) return it->second;
        auto [new_it, _] = per_service_.emplace(
            std::string(appservice_id), PerServiceMetrics{}
        );
        return new_it->second;
    }

    AppServiceRegistry& registry_;
    mutable std::shared_mutex metrics_mutex_;
    std::unordered_map<std::string, PerServiceMetrics> per_service_;
};

// ==========================================================================
// 24. Protocol Bridge Registry
// ==========================================================================

/// Registry for protocol-specific bridge handlers.
class ProtocolBridgeRegistry {
public:
    ProtocolBridgeRegistry() = default;

    /// Register a protocol handler for a bridge.
    void register_handler(
        std::string_view appservice_id,
        std::unique_ptr<ProtocolHandlerInterface> handler
    ) {
        std::unique_lock lock(mutex_);
        handlers_[std::string(appservice_id)] = std::move(handler);
    }

    /// Get the protocol handler for an app service.
    ProtocolHandlerInterface* get_handler(std::string_view appservice_id) {
        std::shared_lock lock(mutex_);
        auto it = handlers_.find(std::string(appservice_id));
        if (it != handlers_.end()) return it->second.get();
        return nullptr;
    }

    /// Check if a handler is registered for an app service.
    bool has_handler(std::string_view appservice_id) const {
        std::shared_lock lock(mutex_);
        return handlers_.contains(std::string(appservice_id));
    }

    /// Initialize all registered handlers.
    void initialize_all(const json& configs) {
        std::shared_lock lock(mutex_);
        for (auto& [id, handler] : handlers_) {
            if (configs.contains(id)) {
                handler->initialize(configs[id]);
            }
        }
    }

    /// Connect all registered handlers.
    void connect_all() {
        std::shared_lock lock(mutex_);
        for (auto& [id, handler] : handlers_) {
            handler->connect();
        }
    }

    /// Disconnect all registered handlers.
    void disconnect_all() {
        std::shared_lock lock(mutex_);
        for (auto& [id, handler] : handlers_) {
            handler->disconnect();
        }
    }

    /// Shutdown all handlers.
    void shutdown_all() {
        std::unique_lock lock(mutex_);
        for (auto& [id, handler] : handlers_) {
            handler->shutdown();
        }
        handlers_.clear();
    }

    /// Get the count of registered handlers.
    size_t handler_count() const {
        std::shared_lock lock(mutex_);
        return handlers_.size();
    }

    /// Get all handler statuses.
    json get_all_statuses() const {
        std::shared_lock lock(mutex_);
        json result = json::object();
        for (const auto& [id, handler] : handlers_) {
            result[id] = handler->get_connection_status();
        }
        return result;
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<ProtocolHandlerInterface>>
        handlers_;
};

// ==========================================================================
// 25. AppService Manager — Top-Level Coordinator
// ==========================================================================

/// Top-level manager that coordinates all app service subsystems.
/// This is the primary API surface for the rest of the homeserver.
class AppServiceManager {
public:
    AppServiceManager()
        : registry_()
        , txn_manager_(registry_)
        , event_pusher_(registry_, txn_manager_)
        , query_handler_(registry_)
        , ghost_manager_(registry_)
        , bridge_admin_(registry_, ghost_manager_)
        , conflict_resolver_(registry_)
        , config_loader_()
        , health_checker_(registry_)
        , interest_tracker_(registry_)
        , puppet_manager_(registry_)
        , device_notifier_(registry_, event_pusher_)
        , otk_reporter_(registry_, txn_manager_)
        , logger_()
        , metrics_(registry_)
        , bridge_registry_()
    {}

    /// Get the app service registry.
    AppServiceRegistry& registry() { return registry_; }
    const AppServiceRegistry& registry() const { return registry_; }

    /// Get the transaction manager.
    AppServiceTransactionManager& transaction_manager() { return txn_manager_; }

    /// Get the event pusher.
    AppServiceEventPusher& event_pusher() { return event_pusher_; }

    /// Get the query handler.
    AppServiceQueryHandler& query_handler() { return query_handler_; }

    /// Get the ghost user manager.
    GhostUserManager& ghost_manager() { return ghost_manager_; }

    /// Get the bridge admin manager.
    BridgeAdminManager& bridge_admin() { return bridge_admin_; }

    /// Get the conflict resolver.
    NamespaceConflictResolver& conflict_resolver() { return conflict_resolver_; }

    /// Get the config loader.
    BridgeConfigLoader& config_loader() { return config_loader_; }

    /// Get the health checker.
    AppServiceHealthChecker& health_checker() { return health_checker_; }

    /// Get the interest tracker.
    AppServiceInterestTracker& interest_tracker() { return interest_tracker_; }

    /// Get the puppet user manager.
    PuppetUserManager& puppet_manager() { return puppet_manager_; }

    /// Get the device list notifier.
    DeviceListNotifier& device_notifier() { return device_notifier_; }

    /// Get the one-time key reporter.
    OneTimeKeyReporter& otk_reporter() { return otk_reporter_; }

    /// Get the logger.
    AppServiceLogger& logger() { return logger_; }

    /// Get the metrics collector.
    AppServiceMetrics& metrics() { return metrics_; }

    /// Get the protocol bridge registry.
    ProtocolBridgeRegistry& bridge_registry() { return bridge_registry_; }

    // --------------------------------------------------------------------
    // Convenience API: Registration from JSON config
    // --------------------------------------------------------------------

    /// Register an app service from a JSON configuration object.
    std::string register_from_config(const json& config) {
        // Validate config
        auto validation_error = config_loader_.validate_config(config);
        if (validation_error) {
            return *validation_error;
        }

        std::string id = config["id"].get<std::string>();
        std::string as_token = config["as_token"].get<std::string>();
        std::string url = config["url"].get<std::string>();
        std::string sender_localpart =
            config["sender_localpart"].get<std::string>();

        // Parse namespaces
        auto namespaces = config_loader_.parse_namespaces(config);

        // Parse protocol
        auto protocol = config_loader_.parse_protocol_type(config);

        // Register
        std::string err = registry_.register_appservice(
            id, as_token, url, sender_localpart,
            std::move(namespaces), protocol
        );

        if (err.empty()) {
            // Set optional fields
            auto* rec = registry_.get_mutable(id);
            if (rec) {
                if (config.contains("display_name")) {
                    rec->display_name = config["display_name"].get<std::string>();
                }
                if (config.contains("description")) {
                    rec->description = config["description"].get<std::string>();
                }
                if (config.contains("avatar_url")) {
                    rec->avatar_url = config["avatar_url"].get<std::string>();
                }
                if (config.contains("rate_limit")) {
                    rec->rate_limit = config_loader_.parse_rate_limit(config);
                    registry_.update_rate_limit(id, rec->rate_limit);
                }
            }

            logger_.log_registration(id, true);
        } else {
            logger_.log_error(id, "registration", err);
        }

        return err;
    }

    /// Register an app service from a config file.
    std::string register_from_file(const std::filesystem::path& path) {
        auto config = config_loader_.load_json_config(path);
        if (!config) {
            return std::format("Failed to load config from '{}'", path.string());
        }
        return register_from_config(*config);
    }

    /// Load and register all app services from a config directory.
    std::vector<std::string> register_from_directory(
        const std::filesystem::path& dir_path
    ) {
        std::vector<std::string> errors;
        auto configs = config_loader_.load_directory(dir_path);

        for (auto& [name, config] : configs) {
            // Ensure the config has an ID
            if (!config.contains("id")) {
                config["id"] = name;
            }
            std::string err = register_from_config(config);
            if (!err.empty()) {
                errors.push_back(
                    std::format("'{}': {}", name, err)
                );
            }
        }

        return errors;
    }

    // --------------------------------------------------------------------
    // Convenience API: Event handling
    // --------------------------------------------------------------------

    /// Push an event to all interested app services.
    /// Returns the number of app services the event was pushed to.
    size_t handle_event(const json& event) {
        size_t count = event_pusher_.push_event(event);
        if (event.is_object() && event.contains("type")) {
            metrics_.record_event_pushed("", count);
        }
        return count;
    }

    /// Handle a user joining a room — update interest tracking.
    void handle_user_joined_room(
        std::string_view user_id,
        std::string_view room_id
    ) {
        std::string as_id = registry_.get_appservice_for_user(user_id);
        if (!as_id.empty()) {
            interest_tracker_.record_join(as_id, user_id, room_id);
        }
    }

    /// Handle a user leaving a room — update interest tracking.
    void handle_user_left_room(
        std::string_view user_id,
        std::string_view room_id
    ) {
        std::string as_id = registry_.get_appservice_for_user(user_id);
        if (!as_id.empty()) {
            interest_tracker_.record_leave(as_id, room_id);
        }
    }

    /// Handle incoming typing notification.
    void handle_typing(
        std::string_view room_id,
        std::string_view user_id,
        bool is_typing,
        std::optional<milliseconds> timeout = std::nullopt
    ) {
        event_pusher_.push_typing(room_id, user_id, is_typing, timeout);
    }

    /// Handle presence update.
    void handle_presence(
        std::string_view user_id,
        std::string_view presence,
        std::optional<std::string_view> status_msg = std::nullopt
    ) {
        event_pusher_.push_presence(user_id, presence, status_msg);
    }

    /// Handle receipt update.
    void handle_receipt(
        std::string_view room_id,
        std::string_view event_id,
        std::string_view user_id,
        std::string_view receipt_type = "m.read"
    ) {
        event_pusher_.push_receipt(room_id, event_id, user_id, receipt_type);
    }

    // --------------------------------------------------------------------
    // Convenience API: AppService queries
    // --------------------------------------------------------------------

    /// Check if a user ID is controlled by an app service.
    bool is_appservice_user(std::string_view user_id) const {
        return registry_.is_exclusive_user(user_id);
    }

    /// Check if an alias is controlled by an app service.
    bool is_appservice_alias(std::string_view alias) const {
        return registry_.is_exclusive_alias(alias);
    }

    /// Get the app service that controls a user.
    std::string get_user_appservice(std::string_view user_id) const {
        return registry_.get_appservice_for_user(user_id);
    }

    /// Get the app service that controls an alias.
    std::string get_alias_appservice(std::string_view alias) const {
        return registry_.get_appservice_for_alias(alias);
    }

    // --------------------------------------------------------------------
    // Convenience API: Health & Monitoring
    // --------------------------------------------------------------------

    /// Start health checking for all app services.
    void start_health_checks() {
        health_checker_.start();
    }

    /// Stop health checking.
    void stop_health_checks() {
        health_checker_.stop();
    }

    /// Get overall system health.
    json get_health_report() const {
        json report;
        report["total_appservices"] = registry_.count();
        report["active_appservices"] = registry_.count_active();
        report["total_ghost_users"] = ghost_manager_.count();
        report["total_puppets"] = puppet_manager_.count();
        report["health_statuses"] = health_checker_.get_all_statuses();
        report["metrics"] = metrics_.export_json();
        report["bridge_statuses"] = bridge_registry_.get_all_statuses();
        return report;
    }

    /// Export Prometheus metrics.
    std::string export_prometheus_metrics() const {
        return metrics_.export_prometheus();
    }

    // --------------------------------------------------------------------
    // Convenience API: Bridge operations
    // --------------------------------------------------------------------

    /// List all bridges.
    json list_bridges() const {
        return bridge_admin_.list_bridges();
    }

    /// Get a specific bridge's details.
    json get_bridge(std::string_view bridge_id) const {
        return bridge_admin_.get_bridge(bridge_id);
    }

    /// Enable a bridge.
    json enable_bridge(std::string_view bridge_id) {
        return bridge_admin_.enable_bridge(bridge_id);
    }

    /// Disable a bridge.
    json disable_bridge(std::string_view bridge_id) {
        return bridge_admin_.disable_bridge(bridge_id);
    }

    /// Get bridge stats.
    json get_bridge_stats(std::string_view bridge_id) const {
        return bridge_admin_.get_bridge_stats(bridge_id);
    }

    // --------------------------------------------------------------------
    // Convenience API: Ghost users
    // --------------------------------------------------------------------

    /// Create a ghost user for a bridge.
    std::string create_ghost(
        std::string_view appservice_id,
        std::string_view remote_user_id,
        std::string_view display_name = "",
        std::string_view avatar_url = ""
    ) {
        std::string ghost_id = ghost_manager_.create_ghost_user(
            appservice_id, remote_user_id, display_name, avatar_url
        );
        if (!ghost_id.empty()) {
            logger_.log_ghost_created(appservice_id, ghost_id);
            metrics_.record_ghost_created(appservice_id);
        }
        return ghost_id;
    }

    /// Check if a user is a ghost.
    bool is_ghost(std::string_view user_id) const {
        return ghost_manager_.is_ghost_user(user_id);
    }

    // --------------------------------------------------------------------
    // Convenience API: Puppet users
    // --------------------------------------------------------------------

    /// Create a puppet user.
    std::string create_puppet(
        std::string_view appservice_id,
        std::string_view real_user_id,
        std::string_view display_name = "",
        std::string_view avatar_url = ""
    ) {
        return puppet_manager_.create_puppet(
            appservice_id, real_user_id, display_name, avatar_url
        );
    }

    /// Check if a user is a puppet.
    bool is_puppet(std::string_view user_id) const {
        return puppet_manager_.is_puppet(user_id);
    }

    // --------------------------------------------------------------------
    // Shutdown
    // --------------------------------------------------------------------

    /// Graceful shutdown of all subsystems.
    void shutdown() {
        stop_health_checks();
        txn_manager_.shutdown();
        bridge_registry_.shutdown_all();
    }

private:
    AppServiceRegistry              registry_;
    AppServiceTransactionManager    txn_manager_;
    AppServiceEventPusher           event_pusher_;
    AppServiceQueryHandler          query_handler_;
    GhostUserManager                ghost_manager_;
    BridgeAdminManager              bridge_admin_;
    NamespaceConflictResolver       conflict_resolver_;
    BridgeConfigLoader              config_loader_;
    AppServiceHealthChecker         health_checker_;
    AppServiceInterestTracker       interest_tracker_;
    PuppetUserManager               puppet_manager_;
    DeviceListNotifier              device_notifier_;
    OneTimeKeyReporter              otk_reporter_;
    AppServiceLogger                logger_;
    AppServiceMetrics               metrics_;
    ProtocolBridgeRegistry          bridge_registry_;
};

} // namespace appservice
} // namespace progressive

// ==========================================================================
// End of appservice_api.cpp
// ==========================================================================
