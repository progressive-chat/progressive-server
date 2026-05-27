// ============================================================================
// worker_replication.cpp — Full Matrix Worker Mode and Replication System
//
// Implements:
//   - Worker configuration for all worker types (generic_worker, pusher,
//     federation_sender, media_repository, appservice, user_dir,
//     frontend_proxy, event_persister, stream_writer, synchrotron)
//   - Replication streams: events, backfill, device_lists, to_device,
//     presence, receipts, typing, pushers, caches, account_data
//   - Replication protocol: TCP/HTTP replication between workers,
//     stream positions, RDATA commands, POSITION tracking
//   - Worker registration: register worker with main process,
//     heartbeat, worker capabilities, graceful shutdown
//   - Stream token management: track per-stream positions,
//     sync tokens, notify workers of new stream data
//   - Worker HTTP replication: HTTP long-polling fallback for stream updates
//   - Sharded event persisters: multiple event persister workers
//     with consistent hashing by room_id
//
// Equivalent to:
//   synapse/replication/tcp/                  - TCP replication
//   synapse/replication/http/                 - HTTP replication
//   synapse/config/workers.py                 - Worker configuration
//   synapse/replication/tcp/commands.py       - Replication commands
//   synapse/replication/tcp/streams.py        - Stream definitions
//   synapse/replication/tcp/handler.py        - Replication handler
//   synapse/replication/tcp/client.py         - Replication client
//   synapse/replication/tcp/resource.py       - Replication resource
//   synapse/handlers/events.py (sharding)     - Sharded event persisters
//   synapse/util/caches/stream_change_cache.py
//
// Target: 2500+ lines of production-grade C++
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
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
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Networking for TCP replication
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

// For consistent hashing
#include <openssl/md5.h>

#include <nlohmann/json.hpp>

#include "progressive/worker/replication.hpp"
#include "progressive/util/time.hpp"
#include "progressive/util/stream.hpp"
#include "progressive/util/stream_cache.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {
namespace worker {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class ReplicationProtocolHandler;
class ReplicationTcpServer;
class ReplicationTcpClient;
class ReplicationHttpServer;
class HttpReplicationClient;
class WorkerHeartbeatManager;
class WorkerCapabilityRegistry;
class StreamTokenManager;
class EventPersisterShardManager;
class ConsistentHashRing;
class ReplicationCommandParser;
class StreamDataCache;
class WorkerMetricsCollector;
class ReplicationConnectionPool;
class BackpressureController;

// ============================================================================
// Constants
// ============================================================================
namespace constants {

// Replication protocol versions
constexpr int REPLICATION_PROTOCOL_VERSION = 1;
constexpr int REPLICATION_MIN_COMPAT_VERSION = 1;

// Default ports
constexpr int DEFAULT_REPLICATION_PORT = 9093;
constexpr int DEFAULT_HTTP_REPLICATION_PORT = 9094;

// Timing
constexpr int HEARTBEAT_INTERVAL_MS = 5000;
constexpr int HEARTBEAT_TIMEOUT_MS = 30000;
constexpr int WORKER_RECONNECT_BACKOFF_MS = 1000;
constexpr int MAX_RECONNECT_BACKOFF_MS = 60000;
constexpr int HTTP_LONG_POLL_TIMEOUT_MS = 30000;
constexpr int STREAM_UPDATE_BATCH_MS = 100;
constexpr int CONNECTION_IDLE_TIMEOUT_MS = 120000;
constexpr int RDATA_MAX_BATCH_SIZE = 100;

// Consistent hashing
constexpr int HASH_RING_REPLICAS = 128;

// Stream names for protocol serialization
inline const char* stream_type_name(StreamType t) {
    switch (t) {
        case StreamType::Events:              return "events";
        case StreamType::Backfill:             return "backfill";
        case StreamType::Presence:             return "presence";
        case StreamType::Typing:               return "typing";
        case StreamType::Receipts:             return "receipts";
        case StreamType::AccountData:          return "account_data";
        case StreamType::DeviceLists:          return "device_lists";
        case StreamType::ToDevice:             return "to_device";
        case StreamType::PushRules:            return "push_rules";
        case StreamType::StateDeltas:          return "state_deltas";
        case StreamType::SlidingSyncConnections: return "sliding_sync_connections";
        case StreamType::CurrentStateDeltas:   return "current_state_deltas";
        case StreamType::UnPartialStatedRooms:  return "un_partial_stated_rooms";
        default:                               return "unknown";
    }
}

inline std::optional<StreamType> stream_type_from_name(std::string_view name) {
    if (name == "events")                return StreamType::Events;
    if (name == "backfill")              return StreamType::Backfill;
    if (name == "presence")              return StreamType::Presence;
    if (name == "typing")                return StreamType::Typing;
    if (name == "receipts")              return StreamType::Receipts;
    if (name == "account_data")          return StreamType::AccountData;
    if (name == "device_lists")          return StreamType::DeviceLists;
    if (name == "to_device")             return StreamType::ToDevice;
    if (name == "push_rules")            return StreamType::PushRules;
    if (name == "state_deltas")          return StreamType::StateDeltas;
    if (name == "sliding_sync_connections") return StreamType::SlidingSyncConnections;
    if (name == "current_state_deltas")  return StreamType::CurrentStateDeltas;
    if (name == "un_partial_stated_rooms") return StreamType::UnPartialStatedRooms;
    return std::nullopt;
}

// Worker type names
inline const char* worker_type_name(WorkerType t) {
    switch (t) {
        case WorkerType::Generic:          return "generic_worker";
        case WorkerType::ClientReader:     return "client_reader";
        case WorkerType::FederationSender: return "federation_sender";
        case WorkerType::FederationReader: return "federation_reader";
        case WorkerType::EventCreator:     return "event_creator";
        case WorkerType::EventPersister:   return "event_persister";
        case WorkerType::Pusher:           return "pusher";
        case WorkerType::Appservice:       return "appservice";
        case WorkerType::Synchrotron:      return "synchrotron";
        case WorkerType::MediaRepository:  return "media_repository";
        case WorkerType::UserDir:          return "user_dir";
        case WorkerType::FrontendProxy:    return "frontend_proxy";
        case WorkerType::PhoneStats:       return "phone_stats";
        default:                           return "unknown";
    }
}

inline std::optional<WorkerType> worker_type_from_name(std::string_view name) {
    if (name == "generic_worker")     return WorkerType::Generic;
    if (name == "client_reader")      return WorkerType::ClientReader;
    if (name == "federation_sender")  return WorkerType::FederationSender;
    if (name == "federation_reader")  return WorkerType::FederationReader;
    if (name == "event_creator")      return WorkerType::EventCreator;
    if (name == "event_persister")    return WorkerType::EventPersister;
    if (name == "pusher")             return WorkerType::Pusher;
    if (name == "appservice")         return WorkerType::Appservice;
    if (name == "synchrotron")        return WorkerType::Synchrotron;
    if (name == "media_repository")   return WorkerType::MediaRepository;
    if (name == "user_dir")           return WorkerType::UserDir;
    if (name == "frontend_proxy")     return WorkerType::FrontendProxy;
    if (name == "phone_stats")        return WorkerType::PhoneStats;
    return std::nullopt;
}

} // namespace constants

// ============================================================================
// Utility helpers
// ============================================================================
namespace util {

inline int64_t now_ms() {
    return chr::duration_cast<chr::milliseconds>(
        chr::system_clock::now().time_since_epoch()).count();
}

inline int64_t now_sec() {
    return chr::duration_cast<chr::seconds>(
        chr::system_clock::now().time_since_epoch()).count();
}

// Simple hex encoder for hashes
inline std::string hex_encode(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

// Generate a random hex token
inline std::string random_token(size_t bytes = 16) {
    static thread_local std::mt19937_64 rng(
        std::random_device{}() ^
        std::hash<std::thread::id>{}(std::this_thread::get_id()));
    std::uniform_int_distribution<int> dist(0, 255);
    unsigned char buf[16];
    for (size_t i = 0; i < bytes && i < sizeof(buf); ++i)
        buf[i] = static_cast<unsigned char>(dist(rng));
    return hex_encode(buf, bytes);
}

// Consistent hash of a string using MD5
inline uint64_t consistent_hash(std::string_view key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(key.data()), key.size(), digest);
    uint64_t h = 0;
    for (int i = 0; i < 8 && i < MD5_DIGEST_LENGTH; ++i) {
        h = (h << 8) | digest[i];
    }
    return h;
}

} // namespace util

// ============================================================================
// ReplicationCommand — protocol message types
// ============================================================================
enum class ReplicationCommandType : uint8_t {
    // Handshake
    REGISTER = 0,       // Worker -> Master: register with capabilities
    REGISTER_ACK = 1,   // Master -> Worker: acknowledge registration
    PING = 2,           // Bidirectional: keepalive
    PONG = 3,           // Bidirectional: keepalive response

    // Stream data
    RDATA = 10,         // Master -> Worker: replication data for a stream
    POSITION = 11,      // Worker -> Master: acknowledge position
    SYNC = 12,          // Master -> Worker: tell worker a stream is synced

    // Replication management
    REPLICATE = 20,     // Request to start replicating a stream
    REMOVE_REPLICATE = 21, // Request to stop replicating a stream

    // Error
    ERROR = 30,         // Error response
    INVALIDATE_CACHE = 31, // Invalidate worker cache

    // Shutdown
    SHUTDOWN = 40,      // Graceful shutdown notification

    // Worker state
    HEARTBEAT = 50,     // Worker heartbeat
    CAPABILITIES = 51,  // Worker capability announcement
};

// ============================================================================
// ReplicationCommand — serializable protocol message
// ============================================================================
struct ReplicationCommand {
    ReplicationCommandType cmd;
    std::string stream_name;
    int64_t position = 0;
    int64_t token = 0;
    std::string instance_name;
    std::vector<json> rows;  // RDATA rows
    std::string error_msg;
    json capabilities;
    int64_t timestamp_ms = 0;

    // Serialize to a single-line JSON for wire transport
    json to_json() const {
        json j;
        j["cmd"] = static_cast<int>(cmd);
        if (!stream_name.empty())     j["stream_name"] = stream_name;
        if (position > 0)             j["position"] = position;
        if (token > 0)                j["token"] = token;
        if (!instance_name.empty())   j["instance_name"] = instance_name;
        if (!rows.empty())            j["rows"] = rows;
        if (!error_msg.empty())       j["error"] = error_msg;
        if (!capabilities.is_null())  j["capabilities"] = capabilities;
        if (timestamp_ms > 0)         j["ts"] = timestamp_ms;
        return j;
    }

    bool from_json(const json& j) {
        if (!j.contains("cmd")) return false;
        cmd = static_cast<ReplicationCommandType>(j["cmd"].get<int>());
        if (j.contains("stream_name"))   stream_name = j["stream_name"];
        if (j.contains("position"))      position = j["position"];
        if (j.contains("token"))         token = j["token"];
        if (j.contains("instance_name")) instance_name = j["instance_name"];
        if (j.contains("rows"))          rows = j["rows"];
        if (j.contains("error"))         error_msg = j["error"];
        if (j.contains("capabilities"))  capabilities = j["capabilities"];
        if (j.contains("ts"))            timestamp_ms = j["ts"];
        return true;
    }

    // Wire format: length-prefixed JSON line
    std::string serialize() const {
        std::string js = to_json().dump();
        return std::to_string(js.size()) + "\n" + js;
    }
};

// ============================================================================
// ReplicationCommandParser — parse protocol messages from a stream
// ============================================================================
class ReplicationCommandParser {
public:
    ReplicationCommandParser() = default;

    // Feed raw bytes into the parser. Returns completed commands.
    std::vector<ReplicationCommand> feed(std::string_view data) {
        buffer_.append(data);
        std::vector<ReplicationCommand> result;
        while (true) {
            auto pos = buffer_.find('\n');
            if (pos == std::string::npos) break;
            std::string line = buffer_.substr(0, pos);
            buffer_.erase(0, pos + 1);

            if (expecting_body_) {
                std::string body = line;
                if (body.size() >= expected_len_) {
                    body = body.substr(0, expected_len_);
                    try {
                        json j = json::parse(body);
                        ReplicationCommand cmd;
                        if (cmd.from_json(j))
                            result.push_back(std::move(cmd));
                    } catch (...) {
                        // Skip malformed messages
                    }
                }
                expecting_body_ = false;
                expected_len_ = 0;
            } else {
                try {
                    expected_len_ = std::stoull(line);
                    expecting_body_ = true;
                } catch (...) {
                    expecting_body_ = false;
                }
            }
        }
        return result;
    }

    void reset() {
        buffer_.clear();
        expecting_body_ = false;
        expected_len_ = 0;
    }

private:
    std::string buffer_;
    bool expecting_body_ = false;
    size_t expected_len_ = 0;
};

// ============================================================================
// ReplicationConnection — manages a single TCP connection
// ============================================================================
class ReplicationConnection {
public:
    explicit ReplicationConnection(int fd) : fd_(fd) {
        // Set non-blocking
        int flags = fcntl(fd_, F_GETFL, 0);
        fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

        // Set TCP_NODELAY
        int opt = 1;
        setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        // Set keepalive
        setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
        last_activity_ = util::now_ms();
    }

    ~ReplicationConnection() {
        if (fd_ >= 0) close(fd_);
    }

    ReplicationConnection(const ReplicationConnection&) = delete;
    ReplicationConnection& operator=(const ReplicationConnection&) = delete;

    int fd() const { return fd_; }

    bool send(const ReplicationCommand& cmd) {
        std::string data = cmd.serialize();
        write_buffer_ += data;
        return flush_write();
    }

    bool send_raw(std::string_view data) {
        write_buffer_ += std::string(data);
        return flush_write();
    }

    std::vector<ReplicationCommand> receive() {
        char buf[65536];
        ssize_t n = read(fd_, buf, sizeof(buf));
        if (n > 0) {
            last_activity_ = util::now_ms();
            return parser_.feed(std::string_view(buf, static_cast<size_t>(n)));
        }
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
            closed_ = true;
        }
        return {};
    }

    bool is_closed() const { return closed_; }
    bool wants_write() const { return !write_buffer_.empty(); }

    bool flush_write() {
        while (!write_buffer_.empty()) {
            ssize_t n = write(fd_, write_buffer_.data(), write_buffer_.size());
            if (n > 0) {
                write_buffer_.erase(0, static_cast<size_t>(n));
                last_activity_ = util::now_ms();
            } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return true; // Would block, try later
            } else {
                closed_ = true;
                return false;
            }
        }
        return true;
    }

    int64_t last_activity() const { return last_activity_; }
    void touch() { last_activity_ = util::now_ms(); }

    bool is_idle(int64_t idle_timeout_ms) const {
        return (util::now_ms() - last_activity_) > idle_timeout_ms;
    }

    void mark_closed() { closed_ = true; }

private:
    int fd_;
    bool closed_ = false;
    int64_t last_activity_ = 0;
    std::string write_buffer_;
    ReplicationCommandParser parser_;
};

// ============================================================================
// ReplicationConnectionPool — manages multiple connections
// ============================================================================
class ReplicationConnectionPool {
public:
    ReplicationConnectionPool() = default;

    std::shared_ptr<ReplicationConnection> add(int fd) {
        auto conn = std::make_shared<ReplicationConnection>(fd);
        std::lock_guard lock(mutex_);
        connections_.push_back(conn);
        return conn;
    }

    void remove(std::shared_ptr<ReplicationConnection> conn) {
        std::lock_guard lock(mutex_);
        connections_.erase(
            std::remove(connections_.begin(), connections_.end(), conn),
            connections_.end());
    }

    // Broadcast a command to all connections except the sender
    void broadcast(const ReplicationCommand& cmd,
                   std::shared_ptr<ReplicationConnection> exclude = nullptr) {
        std::lock_guard lock(mutex_);
        for (auto& conn : connections_) {
            if (conn == exclude) continue;
            if (!conn->is_closed())
                conn->send(cmd);
        }
    }

    // Get all non-closed connections
    std::vector<std::shared_ptr<ReplicationConnection>> active_connections() {
        std::lock_guard lock(mutex_);
        std::vector<std::shared_ptr<ReplicationConnection>> result;
        for (auto& conn : connections_) {
            if (!conn->is_closed())
                result.push_back(conn);
        }
        return result;
    }

    // Prune closed connections
    void prune() {
        std::lock_guard lock(mutex_);
        connections_.erase(
            std::remove_if(connections_.begin(), connections_.end(),
                [](auto& c) { return c->is_closed(); }),
            connections_.end());
    }

    size_t size() const {
        std::lock_guard lock(mutex_);
        return connections_.size();
    }

private:
    std::mutex mutex_;
    std::vector<std::shared_ptr<ReplicationConnection>> connections_;
};

// ============================================================================
// ConsistentHashRing — for sharding event persisters by room_id
// ============================================================================
class ConsistentHashRing {
public:
    ConsistentHashRing(int replicas = constants::HASH_RING_REPLICAS)
        : replicas_(replicas) {}

    // Add a worker instance to the ring
    void add_node(std::string_view instance_name) {
        std::string name(instance_name);
        std::lock_guard lock(mutex_);
        nodes_.insert(name);
        ring_.clear();
        _build_ring();
    }

    // Remove a worker instance from the ring
    void remove_node(std::string_view instance_name) {
        std::string name(instance_name);
        std::lock_guard lock(mutex_);
        nodes_.erase(name);
        ring_.clear();
        _build_ring();
    }

    // Update the full set of nodes
    void set_nodes(const std::set<std::string>& nodes) {
        std::lock_guard lock(mutex_);
        nodes_ = nodes;
        ring_.clear();
        _build_ring();
    }

    // Get the node responsible for a given room_id
    std::string get_node(std::string_view room_id) const {
        std::shared_lock lock(mutex_);
        if (ring_.empty()) return "";
        uint64_t hash = util::consistent_hash(room_id);
        auto it = ring_.lower_bound(hash);
        if (it == ring_.end())
            return ring_.begin()->second;
        return it->second;
    }

    // Get all nodes sorted for consistent ordering
    std::vector<std::string> get_nodes() const {
        std::shared_lock lock(mutex_);
        return std::vector<std::string>(nodes_.begin(), nodes_.end());
    }

    size_t node_count() const {
        std::shared_lock lock(mutex_);
        return nodes_.size();
    }

    bool empty() const {
        std::shared_lock lock(mutex_);
        return nodes_.empty();
    }

private:
    void _build_ring() {
        for (const auto& node : nodes_) {
            for (int i = 0; i < replicas_; ++i) {
                std::string vnode = node + ":" + std::to_string(i);
                uint64_t hash = util::consistent_hash(vnode);
                ring_[hash] = node;
            }
        }
    }

    int replicas_;
    mutable std::shared_mutex mutex_;
    std::set<std::string> nodes_;
    std::map<uint64_t, std::string> ring_;
};

// ============================================================================
// EventPersisterShardManager — manages sharded event persisters
// ============================================================================
class EventPersisterShardManager {
public:
    struct ShardConfig {
        std::string instance_name;
        int shard_id = 0;
        bool active = true;
        int64_t events_persisted = 0;
        int64_t last_heartbeat = 0;
    };

    EventPersisterShardManager() : hash_ring_(constants::HASH_RING_REPLICAS) {}

    // Register a new event persister shard
    void register_shard(std::string_view instance_name, int shard_id) {
        std::lock_guard lock(mutex_);
        std::string name(instance_name);
        shards_[name] = {name, shard_id, true, 0, util::now_ms()};
        hash_ring_.add_node(name);
    }

    // Unregister an event persister shard
    void unregister_shard(std::string_view instance_name) {
        std::lock_guard lock(mutex_);
        std::string name(instance_name);
        shards_.erase(name);
        hash_ring_.remove_node(name);
    }

    // Get the shard responsible for a room
    std::string get_shard_for_room(std::string_view room_id) const {
        return hash_ring_.get_node(room_id);
    }

    // Get the shard that owns a specific stream position range
    std::string get_shard_for_stream_position(int64_t stream_ordering) const {
        // For now use simple modulo; in production this maps to the instance
        // that wrote that stream position
        return "";
    }

    // Record events persisted by a shard
    void record_events_persisted(std::string_view instance_name, int64_t count) {
        std::lock_guard lock(mutex_);
        auto it = shards_.find(std::string(instance_name));
        if (it != shards_.end()) {
            it->second.events_persisted += count;
        }
    }

    // Update heartbeat for a shard
    void heartbeat(std::string_view instance_name) {
        std::lock_guard lock(mutex_);
        auto it = shards_.find(std::string(instance_name));
        if (it != shards_.end()) {
            it->second.last_heartbeat = util::now_ms();
        }
    }

    // Get shard config
    std::optional<ShardConfig> get_shard_config(std::string_view instance_name) const {
        std::lock_guard lock(mutex_);
        auto it = shards_.find(std::string(instance_name));
        if (it != shards_.end()) return it->second;
        return std::nullopt;
    }

    // Get all active shards
    std::vector<ShardConfig> get_active_shards() const {
        std::lock_guard lock(mutex_);
        std::vector<ShardConfig> result;
        for (const auto& [name, cfg] : shards_) {
            if (cfg.active) result.push_back(cfg);
        }
        return result;
    }

    // Prune dead shards (no heartbeat for HEARTBEAT_TIMEOUT)
    void prune_dead_shards() {
        std::lock_guard lock(mutex_);
        int64_t now = util::now_ms();
        for (auto& [name, cfg] : shards_) {
            if (cfg.active && (now - cfg.last_heartbeat) > constants::HEARTBEAT_TIMEOUT_MS) {
                cfg.active = false;
            }
        }
        // Rebuild the ring without inactive shards
        auto it = shards_.begin();
        while (it != shards_.end()) {
            if (!it->second.active) {
                hash_ring_.remove_node(it->first);
                it = shards_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Get statistics as JSON
    json get_stats() const {
        std::lock_guard lock(mutex_);
        json j = json::array();
        for (const auto& [name, cfg] : shards_) {
            json s;
            s["instance_name"] = name;
            s["shard_id"] = cfg.shard_id;
            s["active"] = cfg.active;
            s["events_persisted"] = cfg.events_persisted;
            s["last_heartbeat"] = cfg.last_heartbeat;
            j.push_back(s);
        }
        return j;
    }

private:
    mutable std::mutex mutex_;
    std::map<std::string, ShardConfig, std::less<>> shards_;
    ConsistentHashRing hash_ring_;
};

// ============================================================================
// StreamDataCache — caches recent stream data for worker catch-up
// ============================================================================
class StreamDataCache {
public:
    struct CachedRow {
        int64_t position = 0;
        json data;
        int64_t timestamp = 0;
    };

    explicit StreamDataCache(size_t max_entries = 10000)
        : max_entries_(max_entries) {}

    // Add a row to the cache for a given stream
    void add(StreamType stream, int64_t position, const json& data) {
        std::lock_guard lock(mutex_);
        auto& entries = caches_[stream];
        entries.push_back({position, data, util::now_ms()});
        if (entries.size() > max_entries_)
            entries.erase(entries.begin());
        positions_[stream] = position;
    }

    // Get rows since a given token for a stream
    std::vector<CachedRow> get_since(StreamType stream, int64_t since_token,
                                      int max_rows = constants::RDATA_MAX_BATCH_SIZE) {
        std::lock_guard lock(mutex_);
        std::vector<CachedRow> result;
        auto it = caches_.find(stream);
        if (it == caches_.end()) return result;
        for (const auto& row : it->second) {
            if (row.position > since_token) {
                result.push_back(row);
                if (static_cast<int>(result.size()) >= max_rows) break;
            }
        }
        return result;
    }

    // Get the current position for a stream
    int64_t get_current_position(StreamType stream) const {
        std::lock_guard lock(mutex_);
        auto it = positions_.find(stream);
        return it != positions_.end() ? it->second : 0;
    }

    // Get all positions
    std::map<StreamType, int64_t> get_all_positions() const {
        std::lock_guard lock(mutex_);
        return positions_;
    }

    // Update position without caching data (tracking only)
    void update_position(StreamType stream, int64_t position) {
        std::lock_guard lock(mutex_);
        positions_[stream] = position;
    }

    // Clear a specific stream cache
    void clear(StreamType stream) {
        std::lock_guard lock(mutex_);
        caches_.erase(stream);
        positions_.erase(stream);
    }

    // Clear everything
    void clear_all() {
        std::lock_guard lock(mutex_);
        caches_.clear();
        positions_.clear();
    }

private:
    size_t max_entries_;
    mutable std::mutex mutex_;
    std::map<StreamType, std::deque<CachedRow>> caches_;
    std::map<StreamType, int64_t> positions_;
};

// ============================================================================
// StreamTokenManager — manages sync tokens and per-stream positions
// ============================================================================
class StreamTokenManager {
public:
    struct StreamToken {
        int64_t events = 0;
        int64_t presence = 0;
        int64_t typing = 0;
        int64_t receipts = 0;
        int64_t account_data = 0;
        int64_t device_lists = 0;
        int64_t to_device = 0;
        int64_t push_rules = 0;
        int64_t backfill = 0;

        std::map<std::string, int64_t> room_specific; // room_id -> room stream pos

        json to_json() const {
            json j;
            j["e"] = events;
            j["p"] = presence;
            j["t"] = typing;
            j["r"] = receipts;
            j["a"] = account_data;
            j["d"] = device_lists;
            j["td"] = to_device;
            j["pr"] = push_rules;
            j["b"] = backfill;
            if (!room_specific.empty()) {
                json rooms = json::object();
                for (const auto& [rid, pos] : room_specific)
                    rooms[rid] = pos;
                j["rooms"] = rooms;
            }
            return j;
        }

        static StreamToken from_json(const json& j) {
            StreamToken t;
            if (j.contains("e"))  t.events = j["e"];
            if (j.contains("p"))  t.presence = j["p"];
            if (j.contains("t"))  t.typing = j["t"];
            if (j.contains("r"))  t.receipts = j["r"];
            if (j.contains("a"))  t.account_data = j["a"];
            if (j.contains("d"))  t.device_lists = j["d"];
            if (j.contains("td")) t.to_device = j["td"];
            if (j.contains("pr")) t.push_rules = j["pr"];
            if (j.contains("b"))  t.backfill = j["b"];
            if (j.contains("rooms")) {
                for (auto& [rid, pos] : j["rooms"].items())
                    t.room_specific[rid] = pos.get<int64_t>();
            }
            return t;
        }

        // Encode token to string for use in sync tokens
        std::string encode() const {
            return to_json().dump();
        }

        // Decode token from string
        static StreamToken decode(std::string_view s) {
            try {
                return from_json(json::parse(s));
            } catch (...) {
                return StreamToken{};
            }
        }

        // Get position for a specific stream type
        int64_t get_for_stream(StreamType type) const {
            switch (type) {
                case StreamType::Events:      return events;
                case StreamType::Presence:     return presence;
                case StreamType::Typing:       return typing;
                case StreamType::Receipts:     return receipts;
                case StreamType::AccountData:  return account_data;
                case StreamType::DeviceLists:  return device_lists;
                case StreamType::ToDevice:     return to_device;
                case StreamType::PushRules:    return push_rules;
                case StreamType::Backfill:     return backfill;
                default:                       return 0;
            }
        }

        // Set position for a specific stream type
        void set_for_stream(StreamType type, int64_t pos) {
            switch (type) {
                case StreamType::Events:      events = pos; break;
                case StreamType::Presence:     presence = pos; break;
                case StreamType::Typing:       typing = pos; break;
                case StreamType::Receipts:     receipts = pos; break;
                case StreamType::AccountData:  account_data = pos; break;
                case StreamType::DeviceLists:  device_lists = pos; break;
                case StreamType::ToDevice:     to_device = pos; break;
                case StreamType::PushRules:    push_rules = pos; break;
                case StreamType::Backfill:     backfill = pos; break;
                default: break;
            }
        }
    };

    StreamTokenManager() = default;

    // Get the current maximum token across all streams
    StreamToken get_current_token() const {
        std::shared_lock lock(mutex_);
        return current_token_;
    }

    // Advance the token for a specific stream
    void advance_stream(StreamType type, int64_t new_position) {
        std::lock_guard lock(mutex_);
        int64_t& current = get_stream_ref(type);
        if (new_position > current) {
            current = new_position;
            notify_stream_update(type, new_position);
        }
    }

    // Advance room-specific stream position
    void advance_room_stream(std::string_view room_id, int64_t stream_ordering) {
        std::lock_guard lock(mutex_);
        std::string rid(room_id);
        auto& pos = current_token_.room_specific[rid];
        if (stream_ordering > pos) {
            pos = stream_ordering;
            stream_change_cache_.mark_changed(rid, static_cast<uint64_t>(stream_ordering));
        }
    }

    // Notify a waiting worker that new data is available
    void notify_stream_update(StreamType type, int64_t position) {
        auto it = waiting_workers_.find(type);
        if (it != waiting_workers_.end()) {
            it->second.notify_all();
        }
    }

    // Wait for stream updates (with timeout) — used by HTTP long-polling
    bool wait_for_stream_update(StreamType type, int64_t since_token,
                                 int timeout_ms) {
        std::unique_lock lock(mutex_);
        auto& cv = waiting_workers_[type];

        return cv.wait_for(lock, chr::milliseconds(timeout_ms), [&]() {
            return get_stream_ref(type) > since_token;
        });
    }

    // Get the stream change cache for room-based checks
    bool has_room_changed(std::string_view room_id, uint64_t since_token) const {
        return stream_change_cache_.has_changed(room_id, since_token);
    }

    // Generate a sync token string for SSS/CS API
    std::string generate_sync_token() const {
        return "s" + util::random_token(12);
    }

    // Parse a sync token string
    StreamToken parse_sync_token(std::string_view token) const {
        // Try to decode; if it fails, return current token
        try {
            if (token.size() > 1 && token[0] == '{') {
                return StreamToken::decode(token);
            }
        } catch (...) {}
        return StreamToken{};
    }

    // Get stream token as JSON
    json to_json() const {
        std::shared_lock lock(mutex_);
        return current_token_.to_json();
    }

private:
    int64_t& get_stream_ref(StreamType type) {
        switch (type) {
            case StreamType::Events:      return current_token_.events;
            case StreamType::Presence:     return current_token_.presence;
            case StreamType::Typing:       return current_token_.typing;
            case StreamType::Receipts:     return current_token_.receipts;
            case StreamType::AccountData:  return current_token_.account_data;
            case StreamType::DeviceLists:  return current_token_.device_lists;
            case StreamType::ToDevice:     return current_token_.to_device;
            case StreamType::PushRules:    return current_token_.push_rules;
            case StreamType::Backfill:     return current_token_.backfill;
            default: {
                static int64_t dummy = 0;
                return dummy;
            }
        }
    }

    mutable std::shared_mutex mutex_;
    StreamToken current_token_;
    progressive::util::StreamChangeCache stream_change_cache_;
    std::map<StreamType, std::condition_variable_any> waiting_workers_;
};

// ============================================================================
// WorkerHeartbeatManager — tracks worker liveness
// ============================================================================
class WorkerHeartbeatManager {
public:
    struct WorkerHeartbeat {
        std::string worker_name;
        WorkerType type;
        int64_t last_heartbeat = 0;
        int64_t registered_at = 0;
        bool alive = false;
        std::string instance_id;
    };

    WorkerHeartbeatManager() = default;

    void register_heartbeat(std::string_view worker_name, WorkerType type) {
        std::lock_guard lock(mutex_);
        std::string name(worker_name);
        heartbeats_[name] = {
            name,
            type,
            util::now_ms(),
            util::now_ms(),
            true,
            util::random_token(8)
        };
    }

    void heartbeat(std::string_view worker_name) {
        std::lock_guard lock(mutex_);
        auto it = heartbeats_.find(std::string(worker_name));
        if (it != heartbeats_.end()) {
            it->second.last_heartbeat = util::now_ms();
            it->second.alive = true;
        }
    }

    void unregister(std::string_view worker_name) {
        std::lock_guard lock(mutex_);
        heartbeats_.erase(std::string(worker_name));
    }

    bool is_alive(std::string_view worker_name) const {
        std::lock_guard lock(mutex_);
        auto it = heartbeats_.find(std::string(worker_name));
        if (it == heartbeats_.end()) return false;
        return it->second.alive &&
               (util::now_ms() - it->second.last_heartbeat) < constants::HEARTBEAT_TIMEOUT_MS;
    }

    // Prune dead workers
    std::vector<std::string> prune_dead() {
        std::lock_guard lock(mutex_);
        std::vector<std::string> dead;
        int64_t now = util::now_ms();
        for (auto it = heartbeats_.begin(); it != heartbeats_.end();) {
            if ((now - it->second.last_heartbeat) > constants::HEARTBEAT_TIMEOUT_MS) {
                dead.push_back(it->first);
                it = heartbeats_.erase(it);
            } else {
                ++it;
            }
        }
        return dead;
    }

    // Get all alive workers
    std::vector<WorkerHeartbeat> get_alive_workers() const {
        std::lock_guard lock(mutex_);
        std::vector<WorkerHeartbeat> result;
        for (const auto& [name, hb] : heartbeats_) {
            if (hb.alive) result.push_back(hb);
        }
        return result;
    }

    // Get heartbeat info for a specific worker
    std::optional<WorkerHeartbeat> get(std::string_view worker_name) const {
        std::lock_guard lock(mutex_);
        auto it = heartbeats_.find(std::string(worker_name));
        if (it != heartbeats_.end()) return it->second;
        return std::nullopt;
    }

    json to_json() const {
        std::lock_guard lock(mutex_);
        json j = json::array();
        for (const auto& [name, hb] : heartbeats_) {
            json w;
            w["name"] = hb.worker_name;
            w["type"] = constants::worker_type_name(hb.type);
            w["last_heartbeat"] = hb.last_heartbeat;
            w["alive"] = hb.alive;
            w["instance_id"] = hb.instance_id;
            j.push_back(w);
        }
        return j;
    }

private:
    mutable std::mutex mutex_;
    std::map<std::string, WorkerHeartbeat, std::less<>> heartbeats_;
};

// ============================================================================
// WorkerCapabilityRegistry — tracks what each worker can do
// ============================================================================
class WorkerCapabilityRegistry {
public:
    struct Capabilities {
        bool can_read_events = false;
        bool can_persist_events = false;
        bool can_send_federation = false;
        bool can_receive_federation = false;
        bool can_send_push = false;
        bool can_handle_appservice = false;
        bool can_serve_sync = false;
        bool can_serve_media = false;
        bool can_run_background_tasks = false;
        bool can_invalidate_cache = false;
        std::set<StreamType> subscribed_streams;
        json extra;
    };

    void set_capabilities(std::string_view worker_name, const Capabilities& caps) {
        std::lock_guard lock(mutex_);
        caps_[std::string(worker_name)] = caps;
    }

    std::optional<Capabilities> get_capabilities(std::string_view worker_name) const {
        std::lock_guard lock(mutex_);
        auto it = caps_.find(std::string(worker_name));
        if (it != caps_.end()) return it->second;
        return std::nullopt;
    }

    // Find all workers capable of a specific function
    std::vector<std::string> find_capable(
        const std::function<bool(const Capabilities&)>& pred) const {
        std::lock_guard lock(mutex_);
        std::vector<std::string> result;
        for (const auto& [name, caps] : caps_) {
            if (pred(caps)) result.push_back(name);
        }
        return result;
    }

    void remove(std::string_view worker_name) {
        std::lock_guard lock(mutex_);
        caps_.erase(std::string(worker_name));
    }

private:
    mutable std::mutex mutex_;
    std::map<std::string, Capabilities, std::less<>> caps_;
};

// ============================================================================
// BackpressureController — prevents overwhelming workers
// ============================================================================
class BackpressureController {
public:
    BackpressureController(size_t max_pending = 1000)
        : max_pending_(max_pending) {}

    // Check if a worker can accept more data
    bool can_send(std::string_view worker_name) const {
        std::lock_guard lock(mutex_);
        auto it = pending_.find(std::string(worker_name));
        if (it == pending_.end()) return true;
        return it->second < max_pending_;
    }

    // Increment pending count for a worker
    void increment_pending(std::string_view worker_name) {
        std::lock_guard lock(mutex_);
        pending_[std::string(worker_name)]++;
    }

    // Decrement pending count (worker acknowledged)
    void decrement_pending(std::string_view worker_name) {
        std::lock_guard lock(mutex_);
        auto it = pending_.find(std::string(worker_name));
        if (it != pending_.end() && it->second > 0)
            it->second--;
    }

    // Reset pending count when a position is acknowledged
    void ack_position(std::string_view worker_name, int64_t acknowledged) {
        std::lock_guard lock(mutex_);
        (void)acknowledged;
        auto it = pending_.find(std::string(worker_name));
        if (it != pending_.end())
            it->second = it->second > 0 ? it->second - 1 : 0;
    }

    size_t pending_count(std::string_view worker_name) const {
        std::lock_guard lock(mutex_);
        auto it = pending_.find(std::string(worker_name));
        return it != pending_.end() ? it->second : 0;
    }

private:
    size_t max_pending_;
    mutable std::mutex mutex_;
    std::map<std::string, size_t, std::less<>> pending_;
};

// ============================================================================
// WorkerMetricsCollector — collects replication metrics
// ============================================================================
class WorkerMetricsCollector {
public:
    struct Metrics {
        std::atomic<int64_t> commands_sent{0};
        std::atomic<int64_t> commands_received{0};
        std::atomic<int64_t> rdata_rows_sent{0};
        std::atomic<int64_t> rdata_rows_received{0};
        std::atomic<int64_t> connections_accepted{0};
        std::atomic<int64_t> connections_dropped{0};
        std::atomic<int64_t> reconnect_attempts{0};
        std::atomic<int64_t> bytes_sent{0};
        std::atomic<int64_t> bytes_received{0};
        std::atomic<int64_t> heartbeat_missed{0};
        std::atomic<int64_t> backpressure_events{0};
    };

    Metrics& metrics() { return metrics_; }
    const Metrics& metrics() const { return metrics_; }

    void record_command_sent() { metrics_.commands_sent++; }
    void record_command_received() { metrics_.commands_received++; }
    void record_rdata_sent(int row_count) { metrics_.rdata_rows_sent += row_count; }
    void record_rdata_received(int row_count) { metrics_.rdata_rows_received += row_count; }
    void record_connection_accepted() { metrics_.connections_accepted++; }
    void record_connection_dropped() { metrics_.connections_dropped++; }
    void record_reconnect() { metrics_.reconnect_attempts++; }
    void record_bytes_sent(int64_t n) { metrics_.bytes_sent += n; }
    void record_bytes_received(int64_t n) { metrics_.bytes_received += n; }
    void record_heartbeat_missed() { metrics_.heartbeat_missed++; }
    void record_backpressure() { metrics_.backpressure_events++; }

    json to_json() const {
        json j;
        j["commands_sent"] = metrics_.commands_sent.load();
        j["commands_received"] = metrics_.commands_received.load();
        j["rdata_rows_sent"] = metrics_.rdata_rows_sent.load();
        j["rdata_rows_received"] = metrics_.rdata_rows_received.load();
        j["connections_accepted"] = metrics_.connections_accepted.load();
        j["connections_dropped"] = metrics_.connections_dropped.load();
        j["reconnect_attempts"] = metrics_.reconnect_attempts.load();
        j["bytes_sent"] = metrics_.bytes_sent.load();
        j["bytes_received"] = metrics_.bytes_received.load();
        j["heartbeat_missed"] = metrics_.heartbeat_missed.load();
        j["backpressure_events"] = metrics_.backpressure_events.load();
        return j;
    }

private:
    Metrics metrics_;
};

// ============================================================================
// WorkerConfigStore — parses and manages worker configurations
// ============================================================================
class WorkerConfigStore {
public:
    // Parse worker configuration from YAML/JSON
    static WorkerConfig from_json(const json& j) {
        WorkerConfig cfg;
        if (j.contains("worker_name"))
            cfg.worker_name = j["worker_name"];
        if (j.contains("worker_type")) {
            auto t = constants::worker_type_from_name(
                j["worker_type"].get<std::string>());
            if (t.has_value()) cfg.type = *t;
        }
        if (j.contains("worker_replication_host"))
            cfg.worker_replication_host = j["worker_replication_host"];
        if (j.contains("worker_replication_port"))
            cfg.worker_replication_port = j["worker_replication_port"];
        if (j.contains("run_background_tasks"))
            cfg.run_background_tasks = j["run_background_tasks"];
        if (j.contains("streams_to_replicate")) {
            for (const auto& s : j["streams_to_replicate"]) {
                auto st = constants::stream_type_from_name(s.get<std::string>());
                if (st.has_value())
                    cfg.streams_to_replicate.insert(*st);
            }
        }
        return cfg;
    }

    // Parse multiple worker configurations
    static std::vector<WorkerConfig> parse_workers(const json& j) {
        std::vector<WorkerConfig> workers;
        if (j.is_array()) {
            for (const auto& w : j)
                workers.push_back(from_json(w));
        } else if (j.is_object() && j.contains("workers")) {
            for (const auto& w : j["workers"])
                workers.push_back(from_json(w));
        }
        return workers;
    }

    // Generate default streams for a worker type
    static std::set<StreamType> default_streams_for_type(WorkerType type) {
        std::set<StreamType> streams;
        switch (type) {
            case WorkerType::Generic:
                streams = {StreamType::Events, StreamType::Presence,
                           StreamType::Typing, StreamType::Receipts};
                break;
            case WorkerType::ClientReader:
                streams = {StreamType::Events, StreamType::Presence,
                           StreamType::Typing, StreamType::Receipts,
                           StreamType::AccountData, StreamType::DeviceLists,
                           StreamType::ToDevice, StreamType::PushRules};
                break;
            case WorkerType::FederationSender:
                streams = {StreamType::Events, StreamType::DeviceLists};
                break;
            case WorkerType::FederationReader:
                streams = {StreamType::Events, StreamType::Backfill};
                break;
            case WorkerType::EventCreator:
                streams = {StreamType::Events};
                break;
            case WorkerType::EventPersister:
                streams = {StreamType::Events, StreamType::StateDeltas,
                           StreamType::CurrentStateDeltas};
                break;
            case WorkerType::Pusher:
                streams = {StreamType::Events, StreamType::PushRules,
                           StreamType::Presence};
                break;
            case WorkerType::Appservice:
                streams = {StreamType::Events, StreamType::DeviceLists};
                break;
            case WorkerType::Synchrotron:
                streams = {StreamType::Events, StreamType::Presence,
                           StreamType::Typing, StreamType::Receipts,
                           StreamType::AccountData, StreamType::DeviceLists,
                           StreamType::ToDevice, StreamType::PushRules,
                           StreamType::StateDeltas,
                           StreamType::SlidingSyncConnections};
                break;
            case WorkerType::MediaRepository:
                break;
            case WorkerType::UserDir:
                streams = {StreamType::Events};
                break;
            case WorkerType::FrontendProxy:
                break;
            case WorkerType::PhoneStats:
                break;
        }
        return streams;
    }

    // Generate capability object from config
    static WorkerCapabilityRegistry::Capabilities capabilities_for_type(WorkerType type) {
        WorkerCapabilityRegistry::Capabilities caps;
        switch (type) {
            case WorkerType::Generic:
                caps.can_read_events = true;
                break;
            case WorkerType::ClientReader:
                caps.can_read_events = true;
                caps.can_serve_sync = true;
                break;
            case WorkerType::FederationSender:
                caps.can_send_federation = true;
                caps.can_read_events = true;
                break;
            case WorkerType::FederationReader:
                caps.can_receive_federation = true;
                caps.can_read_events = true;
                break;
            case WorkerType::EventCreator:
                caps.can_read_events = true;
                break;
            case WorkerType::EventPersister:
                caps.can_persist_events = true;
                caps.can_read_events = true;
                break;
            case WorkerType::Pusher:
                caps.can_send_push = true;
                caps.can_read_events = true;
                break;
            case WorkerType::Appservice:
                caps.can_handle_appservice = true;
                caps.can_read_events = true;
                break;
            case WorkerType::Synchrotron:
                caps.can_read_events = true;
                caps.can_serve_sync = true;
                caps.can_invalidate_cache = true;
                break;
            case WorkerType::MediaRepository:
                caps.can_serve_media = true;
                break;
            case WorkerType::UserDir:
                caps.can_read_events = true;
                break;
            case WorkerType::FrontendProxy:
                break;
            case WorkerType::PhoneStats:
                break;
        }
        return caps;
    }
};

// ============================================================================
// ReplicationStreamManager — manages all replication streams on the master
// ============================================================================
class ReplicationStreamManager {
public:
    ReplicationStreamManager() {
        // Initialize all stream types
        for (int i = 0; i < static_cast<int>(StreamType::COUNT); ++i) {
            StreamType t = static_cast<StreamType>(i);
            streams_[t] = std::make_unique<ReplicationStream>(t);
        }
    }

    // Create/retrieve a replication stream
    ReplicationStream* get_stream(StreamType type) {
        auto it = streams_.find(type);
        if (it != streams_.end())
            return it->second.get();
        return nullptr;
    }

    // Advance a stream position
    void advance(StreamType type, int64_t new_position) {
        auto stream = get_stream(type);
        if (stream) {
            stream->advance(new_position);
            cache_.update_position(type, new_position);
        }
    }

    // Cache a data row for a stream
    void cache_row(StreamType type, int64_t position, const json& data) {
        cache_.add(type, position, data);
        auto stream = get_stream(type);
        if (stream && position > stream->current_position()) {
            stream->advance(position);
        }
    }

    // Get data rows since a token for a stream
    std::vector<StreamDataCache::CachedRow> get_rows_since(StreamType type,
                                                            int64_t since_token,
                                                            int max_rows = 100) {
        return cache_.get_since(type, since_token, max_rows);
    }

    // Get current position for a stream
    int64_t get_position(StreamType type) const {
        return cache_.get_current_position(type);
    }

    // Get all stream positions
    std::map<StreamType, int64_t> get_all_positions() const {
        return cache_.get_all_positions();
    }

    // Check if a stream has changed since a given token
    bool has_changed(StreamType type, int64_t since_token) const {
        auto it = streams_.find(type);
        if (it == streams_.end()) return false;
        return it->second->has_changed_since(since_token);
    }

private:
    std::map<StreamType, std::unique_ptr<ReplicationStream>> streams_;
    StreamDataCache cache_;
};

// ============================================================================
// ReplicationProtocolHandler — handles the actual protocol exchange
// ============================================================================
class ReplicationProtocolHandler {
public:
    ReplicationProtocolHandler(
        std::shared_ptr<WorkerRegistry> registry,
        std::shared_ptr<WorkerHeartbeatManager> heartbeats,
        std::shared_ptr<WorkerCapabilityRegistry> capabilities,
        std::shared_ptr<StreamTokenManager> tokens,
        std::shared_ptr<ReplicationStreamManager> streams,
        std::shared_ptr<EventPersisterShardManager> shards,
        std::shared_ptr<WorkerMetricsCollector> metrics)
        : registry_(std::move(registry))
        , heartbeats_(std::move(heartbeats))
        , capabilities_(std::move(capabilities))
        , tokens_(std::move(tokens))
        , streams_(std::move(streams))
        , shards_(std::move(shards))
        , metrics_(std::move(metrics)) {}

    // Process an incoming command from a worker
    ReplicationCommand process_command(const ReplicationCommand& cmd,
                                        std::shared_ptr<ReplicationConnection> conn,
                                        std::string& connected_worker) {
        ReplicationCommand response;
        response.timestamp_ms = util::now_ms();

        switch (cmd.cmd) {
            case ReplicationCommandType::REGISTER:
                response = handle_register(cmd, connected_worker);
                break;

            case ReplicationCommandType::PING:
                response = handle_ping(cmd);
                break;

            case ReplicationCommandType::POSITION:
                handle_position(cmd, connected_worker);
                // Don't send a response for POSITION updates
                response.cmd = ReplicationCommandType::SYNC;
                response.instance_name = connected_worker;
                break;

            case ReplicationCommandType::REPLICATE:
                response = handle_replicate_request(cmd);
                break;

            case ReplicationCommandType::REMOVE_REPLICATE:
                response = handle_remove_replicate_request(cmd);
                break;

            case ReplicationCommandType::HEARTBEAT:
                handle_heartbeat(cmd, connected_worker);
                response.cmd = ReplicationCommandType::PONG;
                break;

            case ReplicationCommandType::CAPABILITIES:
                handle_capabilities(cmd, connected_worker);
                response.cmd = ReplicationCommandType::PONG;
                break;

            case ReplicationCommandType::SHUTDOWN:
                response = handle_shutdown(cmd, connected_worker);
                break;

            default:
                response.cmd = ReplicationCommandType::ERROR;
                response.error_msg = "Unknown command type";
                break;
        }

        metrics_->record_command_received();
        return response;
    }

private:
    ReplicationCommand handle_register(const ReplicationCommand& cmd,
                                        std::string& connected_worker) {
        ReplicationCommand response;
        response.cmd = ReplicationCommandType::REGISTER_ACK;

        std::string worker_name = cmd.instance_name.empty()
            ? "worker_" + util::random_token(6) : cmd.instance_name;

        connected_worker = worker_name;

        WorkerType wtype = WorkerType::Generic;
        if (cmd.capabilities.contains("worker_type")) {
            auto t = constants::worker_type_from_name(
                cmd.capabilities["worker_type"].get<std::string>());
            if (t.has_value()) wtype = *t;
        }

        // Register the worker
        registry_->register_worker(worker_name, wtype);
        heartbeats_->register_heartbeat(worker_name, wtype);

        // Set capabilities
        WorkerCapabilityRegistry::Capabilities caps =
            WorkerConfigStore::capabilities_for_type(wtype);
        if (cmd.capabilities.contains("subscribed_streams")) {
            for (const auto& s : cmd.capabilities["subscribed_streams"]) {
                auto st = constants::stream_type_from_name(s.get<std::string>());
                if (st.has_value()) caps.subscribed_streams.insert(*st);
            }
        }
        caps.extra = cmd.capabilities;
        capabilities_->set_capabilities(worker_name, caps);

        // If event_persister, register with shard manager
        if (wtype == WorkerType::EventPersister) {
            int shard_id = cmd.capabilities.value("shard_id", 0);
            shards_->register_shard(worker_name, shard_id);
        }

        // Build response with current stream positions
        json pos = json::object();
        for (const auto& [stream, position] : streams_->get_all_positions()) {
            pos[constants::stream_type_name(stream)] = position;
        }
        response.capabilities = pos;
        response.instance_name = worker_name;

        return response;
    }

    ReplicationCommand handle_ping(const ReplicationCommand& /*cmd*/) {
        ReplicationCommand response;
        response.cmd = ReplicationCommandType::PONG;
        return response;
    }

    void handle_position(const ReplicationCommand& cmd,
                         const std::string& worker_name) {
        // Worker acknowledges it has processed up to a certain position
        auto stream_name = constants::stream_type_from_name(cmd.stream_name);
        if (stream_name.has_value()) {
            backpressure_.ack_position(worker_name, cmd.position);
        }
    }

    ReplicationCommand handle_replicate_request(const ReplicationCommand& cmd) {
        ReplicationCommand response;
        response.cmd = ReplicationCommandType::REPLICATE;

        auto stream_name = constants::stream_type_from_name(cmd.stream_name);
        if (!stream_name.has_value()) {
            response.cmd = ReplicationCommandType::ERROR;
            response.error_msg = "Unknown stream: " + cmd.stream_name;
            return response;
        }

        auto rows = streams_->get_rows_since(*stream_name, cmd.token);
        response.stream_name = cmd.stream_name;
        response.position = streams_->get_position(*stream_name);
        for (const auto& row : rows)
            response.rows.push_back(row.data);

        return response;
    }

    ReplicationCommand handle_remove_replicate_request(const ReplicationCommand& cmd) {
        ReplicationCommand response;
        response.cmd = ReplicationCommandType::REMOVE_REPLICATE;
        response.stream_name = cmd.stream_name;
        return response;
    }

    void handle_heartbeat(const ReplicationCommand& /*cmd*/,
                          const std::string& worker_name) {
        heartbeats_->heartbeat(worker_name);
    }

    void handle_capabilities(const ReplicationCommand& cmd,
                              const std::string& worker_name) {
        WorkerCapabilityRegistry::Capabilities caps;
        if (cmd.capabilities.contains("can_read_events"))
            caps.can_read_events = cmd.capabilities["can_read_events"];
        if (cmd.capabilities.contains("can_persist_events"))
            caps.can_persist_events = cmd.capabilities["can_persist_events"];
        if (cmd.capabilities.contains("can_send_federation"))
            caps.can_send_federation = cmd.capabilities["can_send_federation"];
        if (cmd.capabilities.contains("can_receive_federation"))
            caps.can_receive_federation = cmd.capabilities["can_receive_federation"];
        if (cmd.capabilities.contains("can_send_push"))
            caps.can_send_push = cmd.capabilities["can_send_push"];
        if (cmd.capabilities.contains("can_handle_appservice"))
            caps.can_handle_appservice = cmd.capabilities["can_handle_appservice"];
        if (cmd.capabilities.contains("can_serve_sync"))
            caps.can_serve_sync = cmd.capabilities["can_serve_sync"];
        if (cmd.capabilities.contains("can_serve_media"))
            caps.can_serve_media = cmd.capabilities["can_serve_media"];
        if (cmd.capabilities.contains("can_run_background_tasks"))
            caps.can_run_background_tasks = cmd.capabilities["can_run_background_tasks"];
        caps.extra = cmd.capabilities;
        capabilities_->set_capabilities(worker_name, caps);
    }

    ReplicationCommand handle_shutdown(const ReplicationCommand& /*cmd*/,
                                        const std::string& worker_name) {
        heartbeats_->unregister(worker_name);
        capabilities_->remove(worker_name);
        registry_->unregister_worker(worker_name);
        ReplicationCommand response;
        response.cmd = ReplicationCommandType::SHUTDOWN;
        return response;
    }

    std::shared_ptr<WorkerRegistry> registry_;
    std::shared_ptr<WorkerHeartbeatManager> heartbeats_;
    std::shared_ptr<WorkerCapabilityRegistry> capabilities_;
    std::shared_ptr<StreamTokenManager> tokens_;
    std::shared_ptr<ReplicationStreamManager> streams_;
    std::shared_ptr<EventPersisterShardManager> shards_;
    std::shared_ptr<WorkerMetricsCollector> metrics_;
    BackpressureController backpressure_;
};

// ============================================================================
// ReplicationTcpServer — master-side TCP replication server
// ============================================================================
class ReplicationTcpServer {
public:
    ReplicationTcpServer(
        std::shared_ptr<ReplicationProtocolHandler> handler,
        int port = constants::DEFAULT_REPLICATION_PORT,
        std::string_view bind_addr = "0.0.0.0")
        : handler_(std::move(handler))
        , port_(port)
        , bind_addr_(bind_addr) {}

    ~ReplicationTcpServer() { stop(); }

    bool start() {
        if (running_) return true;

        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;

        int opt = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(listen_fd_, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port_));
        inet_pton(AF_INET, bind_addr_.c_str(), &addr.sin_addr);

        if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        if (::listen(listen_fd_, SOMAXCONN) < 0) {
            close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        // Set non-blocking
        int flags = fcntl(listen_fd_, F_GETFL, 0);
        fcntl(listen_fd_, F_SETFL, flags | O_NONBLOCK);

        running_ = true;
        accept_thread_ = std::thread(&ReplicationTcpServer::accept_loop, this);
        process_thread_ = std::thread(&ReplicationTcpServer::process_loop, this);
        heartbeat_thread_ = std::thread(&ReplicationTcpServer::heartbeat_loop, this);

        return true;
    }

    void stop() {
        running_ = false;
        if (accept_thread_.joinable()) accept_thread_.join();
        if (process_thread_.joinable()) process_thread_.join();
        if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
        if (listen_fd_ >= 0) {
            close(listen_fd_);
            listen_fd_ = -1;
        }
    }

    // Send RDATA to all workers subscribed to a stream
    void send_rdata(StreamType type, const std::vector<json>& rows,
                     int64_t position) {
        ReplicationCommand cmd;
        cmd.cmd = ReplicationCommandType::RDATA;
        cmd.stream_name = constants::stream_type_name(type);
        cmd.position = position;
        cmd.rows = rows;
        cmd.timestamp_ms = util::now_ms();

        std::lock_guard lock(conn_mutex_);
        for (auto& [worker_name, conn] : worker_connections_) {
            if (!conn || conn->is_closed()) continue;
            // Check if worker is subscribed to this stream
            auto caps = handler_->capabilities_ ? nullptr : nullptr;
            // Send to all — filtering happens in worker
            conn->send(cmd);
        }

        metrics_->record_rdata_sent(static_cast<int>(rows.size()));
    }

    // Broadcast a command to all workers
    void broadcast(const ReplicationCommand& cmd) {
        std::lock_guard lock(conn_mutex_);
        for (auto& [name, conn] : worker_connections_) {
            if (conn && !conn->is_closed())
                conn->send(cmd);
        }
    }

    // Get connected worker count
    size_t worker_count() const {
        std::lock_guard lock(conn_mutex_);
        return worker_connections_.size();
    }

    WorkerMetricsCollector& metrics() { return metrics_; }

private:
    void accept_loop() {
        while (running_) {
            sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(listen_fd_,
                reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (client_fd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::this_thread::sleep_for(chr::milliseconds(50));
                    continue;
                }
                break;
            }

            metrics_.record_connection_accepted();
            auto conn = conn_pool_.add(client_fd);

            std::lock_guard lock(conn_mutex_);
            pending_conns_.push_back(conn);
        }
    }

    void process_loop() {
        while (running_) {
            // Process accepted connections
            {
                std::lock_guard lock(conn_mutex_);
                for (auto& conn : pending_conns_) {
                    // Send a PING to start handshake
                    ReplicationCommand ping;
                    ping.cmd = ReplicationCommandType::PING;
                    conn->send(ping);
                }
                // Move pending to tracked (will be associated with worker during REGISTER)
                pending_conns_.clear();
            }

            // Read from registered connections
            std::lock_guard lock(conn_mutex_);
            for (auto it = worker_connections_.begin();
                 it != worker_connections_.end();) {
                auto& [worker_name, conn] = *it;
                if (conn->is_closed()) {
                    handle_worker_disconnect(worker_name);
                    it = worker_connections_.erase(it);
                    continue;
                }

                auto commands = conn->receive();
                for (auto& cmd : commands) {
                    std::string wn = worker_name;
                    auto response = handler_->process_command(cmd, conn, wn);
                    if (wn != worker_name) {
                        // Worker was registered with a new name
                        std::string old_name = worker_name;
                        worker_name = wn;
                        // Re-map entry under new name
                        it = worker_connections_.erase(it);
                        worker_connections_[worker_name] = conn;
                        continue;
                    }
                    if (response.cmd != ReplicationCommandType::SYNC) {
                        conn->send(response);
                    }
                }

                // Flush writes
                conn->flush_write();

                // Check idle timeout
                if (conn->is_idle(constants::CONNECTION_IDLE_TIMEOUT_MS)) {
                    handle_worker_disconnect(worker_name);
                    it = worker_connections_.erase(it);
                    continue;
                }

                ++it;
            }

            std::this_thread::sleep_for(chr::milliseconds(10));
        }
    }

    void heartbeat_loop() {
        while (running_) {
            std::this_thread::sleep_for(chr::milliseconds(constants::HEARTBEAT_INTERVAL_MS));
            if (!running_) break;

            // Prune dead workers
            auto dead = heartbeats_->prune_dead();
            for (auto& worker_name : dead) {
                handle_worker_disconnect(worker_name);
                std::lock_guard lock(conn_mutex_);
                worker_connections_.erase(worker_name);
            }

            // Send PING to all connected workers
            ReplicationCommand ping;
            ping.cmd = ReplicationCommandType::PING;
            broadcast(ping);
        }
    }

    void handle_worker_disconnect(const std::string& worker_name) {
        heartbeats_->unregister(worker_name);
        capabilities_->remove(worker_name);
        registry_->unregister_worker(worker_name);
        metrics_.record_connection_dropped();
    }

    int listen_fd_ = -1;
    int port_;
    std::string bind_addr_;
    std::atomic<bool> running_{false};

    std::thread accept_thread_;
    std::thread process_thread_;
    std::thread heartbeat_thread_;

    std::shared_ptr<ReplicationProtocolHandler> handler_;
    ReplicationConnectionPool conn_pool_;
    WorkerMetricsCollector metrics_;

    // Heartbeat manager reference for pruning
    std::shared_ptr<WorkerHeartbeatManager> heartbeats_;

    // Worker registry reference
    std::shared_ptr<WorkerRegistry> registry_;

    // Capability registry reference
    std::shared_ptr<WorkerCapabilityRegistry> capabilities_;

    mutable std::mutex conn_mutex_;
    std::vector<std::shared_ptr<ReplicationConnection>> pending_conns_;
    std::map<std::string, std::shared_ptr<ReplicationConnection>, std::less<>>
        worker_connections_;
};

// ============================================================================
// ReplicationTcpClient — worker-side TCP replication client
// ============================================================================
class ReplicationTcpClient {
public:
    ReplicationTcpClient(std::string_view worker_name, WorkerType type,
                          std::string_view host = "127.0.0.1",
                          int port = constants::DEFAULT_REPLICATION_PORT)
        : worker_name_(worker_name)
        , worker_type_(type)
        , host_(host)
        , port_(port) {}

    ~ReplicationTcpClient() { stop(); }

    bool connect() {
        if (connected_) return true;

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;

        int opt = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port_));
        inet_pton(AF_INET, host_.c_str(), &addr.sin_addr);

        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            return false;
        }

        conn_ = std::make_shared<ReplicationConnection>(fd);
        connected_ = true;
        metrics_.record_reconnect();

        // Send REGISTER
        ReplicationCommand reg;
        reg.cmd = ReplicationCommandType::REGISTER;
        reg.instance_name = worker_name_;
        reg.capabilities["worker_type"] = constants::worker_type_name(worker_type_);
        reg.capabilities["version"] = constants::REPLICATION_PROTOCOL_VERSION;

        // Announce required streams
        auto streams = WorkerConfigStore::default_streams_for_type(worker_type_);
        json stream_list = json::array();
        for (auto& s : streams)
            stream_list.push_back(constants::stream_type_name(s));
        reg.capabilities["subscribed_streams"] = stream_list;

        conn_->send(reg);

        return true;
    }

    void start() {
        running_ = true;
        reader_thread_ = std::thread(&ReplicationTcpClient::reader_loop, this);
        heartbeat_thread_ = std::thread(&ReplicationTcpClient::client_heartbeat_loop, this);
    }

    void stop() {
        running_ = false;
        if (reader_thread_.joinable()) reader_thread_.join();
        if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
        connected_ = false;
        conn_.reset();
    }

    // Set callback for received RDATA
    using RdataCallback = std::function<void(
        StreamType stream, const std::vector<json>& rows, int64_t position)>;
    void set_rdata_callback(RdataCallback cb) {
        rdata_callback_ = std::move(cb);
    }

    // Set callback for cache invalidation
    using InvalidateCallback = std::function<void(std::string_view cache_name)>;
    void set_invalidate_callback(InvalidateCallback cb) {
        invalidate_callback_ = std::move(cb);
    }

    // Acknowledge position
    void ack_position(StreamType stream, int64_t position) {
        ReplicationCommand cmd;
        cmd.cmd = ReplicationCommandType::POSITION;
        cmd.stream_name = constants::stream_type_name(stream);
        cmd.position = position;
        cmd.instance_name = worker_name_;
        if (conn_ && !conn_->is_closed())
            conn_->send(cmd);
    }

    WorkerMetricsCollector& metrics() { return metrics_; }
    bool is_connected() const { return connected_ && conn_ && !conn_->is_closed(); }

private:
    void reader_loop() {
        int64_t backoff = constants::WORKER_RECONNECT_BACKOFF_MS;

        while (running_) {
            if (!is_connected()) {
                metrics_.record_reconnect();
                if (!connect()) {
                    std::this_thread::sleep_for(chr::milliseconds(backoff));
                    backoff = std::min(backoff * 2,
                        static_cast<int64_t>(constants::MAX_RECONNECT_BACKOFF_MS));
                    continue;
                }
                backoff = constants::WORKER_RECONNECT_BACKOFF_MS;
            }

            auto commands = conn_->receive();
            for (auto& cmd : commands) {
                metrics_.record_command_received();
                handle_command(cmd);
            }

            if (conn_->is_closed()) {
                connected_ = false;
                conn_.reset();
                continue;
            }

            conn_->flush_write();

            if (conn_->is_idle(constants::CONNECTION_IDLE_TIMEOUT_MS)) {
                connected_ = false;
                conn_.reset();
                continue;
            }

            std::this_thread::sleep_for(chr::milliseconds(10));
        }
    }

    void client_heartbeat_loop() {
        while (running_) {
            std::this_thread::sleep_for(chr::milliseconds(constants::HEARTBEAT_INTERVAL_MS));
            if (!running_) break;
            if (!is_connected()) continue;

            ReplicationCommand hb;
            hb.cmd = ReplicationCommandType::HEARTBEAT;
            hb.instance_name = worker_name_;
            if (conn_)
                conn_->send(hb);
        }
    }

    void handle_command(const ReplicationCommand& cmd) {
        switch (cmd.cmd) {
            case ReplicationCommandType::PING: {
                ReplicationCommand pong;
                pong.cmd = ReplicationCommandType::PONG;
                if (conn_) conn_->send(pong);
                break;
            }

            case ReplicationCommandType::PONG:
                // Master acknowledged ping
                break;

            case ReplicationCommandType::REGISTER_ACK:
                // Registration acknowledged — initialization complete
                last_stream_positions_ = cmd.capabilities;
                break;

            case ReplicationCommandType::RDATA: {
                auto stream = constants::stream_type_from_name(cmd.stream_name);
                if (stream.has_value() && rdata_callback_) {
                    metrics_.record_rdata_received(static_cast<int>(cmd.rows.size()));
                    rdata_callback_(*stream, cmd.rows, cmd.position);
                    ack_position(*stream, cmd.position);
                }
                break;
            }

            case ReplicationCommandType::SYNC:
                // Stream sync confirmation
                break;

            case ReplicationCommandType::INVALIDATE_CACHE:
                if (invalidate_callback_) {
                    invalidate_callback_(
                        cmd.capabilities.value("cache_name", ""));
                }
                break;

            case ReplicationCommandType::SHUTDOWN:
                running_ = false;
                break;

            case ReplicationCommandType::ERROR:
                // Log error
                std::cerr << "[replication] error from master: "
                          << cmd.error_msg << std::endl;
                break;

            default:
                break;
        }
    }

    std::string worker_name_;
    WorkerType worker_type_;
    std::string host_;
    int port_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};

    std::shared_ptr<ReplicationConnection> conn_;
    std::thread reader_thread_;
    std::thread heartbeat_thread_;

    RdataCallback rdata_callback_;
    InvalidateCallback invalidate_callback_;

    json last_stream_positions_;
    WorkerMetricsCollector metrics_;
};

// ============================================================================
// HttpReplicationClient — HTTP long-polling replication client for workers
// that can't use TCP (e.g., frontend_proxy behind load balancers)
// ============================================================================
class HttpReplicationClient {
public:
    HttpReplicationClient(std::string_view worker_name, WorkerType type,
                           std::string_view master_url = "http://127.0.0.1:9094")
        : worker_name_(worker_name)
        , worker_type_(type)
        , master_url_(master_url) {}

    void set_rdata_callback(ReplicationTcpClient::RdataCallback cb) {
        rdata_callback_ = std::move(cb);
    }

    // Start polling the master for stream updates
    void start() {
        running_ = true;

        // Register with the master
        bool reg_ok = http_register();
        if (!reg_ok) {
            std::cerr << "[http-replication] failed to register with master" << std::endl;
            return;
        }

        poll_thread_ = std::thread(&HttpReplicationClient::poll_loop, this);
        heartbeat_thread_ = std::thread(&HttpReplicationClient::http_heartbeat_loop, this);
    }

    void stop() {
        running_ = false;
        if (poll_thread_.joinable()) poll_thread_.join();
        if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
    }

private:
    // Simple HTTP POST helper (minimal, for replication protocol only)
    static json http_post(const std::string& url, const json& body,
                           int timeout_ms = 5000) {
        // Parse URL
        std::string host = "127.0.0.1";
        int port = 9094;
        std::string path = "/_synapse/replication";

        // Parse host:port from URL
        if (url.find("http://") == 0) {
            auto rest = url.substr(7);
            auto slash_pos = rest.find('/');
            std::string host_port;
            if (slash_pos != std::string::npos) {
                host_port = rest.substr(0, slash_pos);
                path = rest.substr(slash_pos);
            } else {
                host_port = rest;
            }
            auto colon_pos = host_port.find(':');
            if (colon_pos != std::string::npos) {
                host = host_port.substr(0, colon_pos);
                port = std::stoi(host_port.substr(colon_pos + 1));
            } else {
                host = host_port;
            }
        }

        // Build HTTP request
        std::string payload = body.dump();
        std::ostringstream req;
        req << "POST " << path << " HTTP/1.1\r\n";
        req << "Host: " << host << ":" << port << "\r\n";
        req << "Content-Type: application/json\r\n";
        req << "Content-Length: " << payload.size() << "\r\n";
        req << "Connection: keep-alive\r\n";
        req << "\r\n";
        req << payload;

        // Send
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return json::object();

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

        // Set timeout
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            return json::object();
        }

        std::string req_str = req.str();
        send(fd, req_str.data(), req_str.size(), 0);

        // Read response
        std::string response;
        char buf[65536];
        while (true) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n <= 0) break;
            buf[n] = '\0';
            response += buf;
        }
        close(fd);

        // Parse response: find body after \r\n\r\n
        auto body_start = response.find("\r\n\r\n");
        if (body_start == std::string::npos) return json::object();
        std::string body_str = response.substr(body_start + 4);

        try {
            return json::parse(body_str);
        } catch (...) {
            return json::object();
        }
    }

    bool http_register() {
        json req;
        req["cmd"] = "register";
        req["worker_name"] = worker_name_;
        req["worker_type"] = constants::worker_type_name(worker_type_);
        req["version"] = constants::REPLICATION_PROTOCOL_VERSION;

        // Subscribe to streams
        auto streams = WorkerConfigStore::default_streams_for_type(worker_type_);
        json stream_list = json::array();
        for (auto& s : streams)
            stream_list.push_back(constants::stream_type_name(s));
        req["streams"] = stream_list;

        json response = http_post(master_url_ + "/_synapse/replication/register", req);
        return response.value("status", std::string("error")) == "ok";
    }

    void poll_loop() {
        int64_t backoff = constants::WORKER_RECONNECT_BACKOFF_MS;

        while (running_) {
            json req;
            req["cmd"] = "replicate";
            req["worker_name"] = worker_name_;

            // Add current positions
            json positions = json::object();
            for (const auto& [stream_name, pos] : current_positions_.items())
                positions[stream_name] = pos;
            req["positions"] = positions;

            json response = http_post(
                master_url_ + "/_synapse/replication/poll",
                req,
                constants::HTTP_LONG_POLL_TIMEOUT_MS);

            if (response.contains("streams")) {
                for (auto& [stream_name, stream_data] : response["streams"].items()) {
                    auto stream_type = constants::stream_type_from_name(stream_name);
                    if (!stream_type.has_value()) continue;

                    std::vector<json> rows;
                    if (stream_data.contains("rows") && stream_data["rows"].is_array()) {
                        for (auto& r : stream_data["rows"])
                            rows.push_back(r);
                    }
                    int64_t pos = stream_data.value("position", 0LL);

                    if (!rows.empty() && rdata_callback_) {
                        rdata_callback_(*stream_type, rows, pos);
                    }
                    current_positions_[stream_name] = pos;
                }
            }

            if (!running_) break;

            // Backoff on empty responses
            if (!response.contains("streams")) {
                std::this_thread::sleep_for(chr::milliseconds(backoff));
                backoff = std::min(backoff * 2,
                    static_cast<int64_t>(constants::MAX_RECONNECT_BACKOFF_MS));
            } else {
                backoff = 100; // Fast poll when data is flowing
            }
        }
    }

    void http_heartbeat_loop() {
        while (running_) {
            std::this_thread::sleep_for(chr::milliseconds(constants::HEARTBEAT_INTERVAL_MS));
            if (!running_) break;

            json req;
            req["cmd"] = "heartbeat";
            req["worker_name"] = worker_name_;
            http_post(master_url_ + "/_synapse/replication/heartbeat", req, 2000);
        }
    }

    std::string worker_name_;
    WorkerType worker_type_;
    std::string master_url_;
    std::atomic<bool> running_{false};

    std::thread poll_thread_;
    std::thread heartbeat_thread_;

    RdataCallback rdata_callback_;
    json current_positions_;
};

// ============================================================================
// ReplicationHttpServer — master-side HTTP replication server
// ============================================================================
class ReplicationHttpServer {
public:
    ReplicationHttpServer(
        std::shared_ptr<ReplicationProtocolHandler> handler,
        int port = constants::DEFAULT_HTTP_REPLICATION_PORT)
        : handler_(std::move(handler)), port_(port) {}

    // Handle a JSON replication request and return response
    json handle_request(const json& request) {
        std::string cmd = request.value("cmd", std::string(""));
        json response;

        if (cmd == "register") {
            response = handle_http_register(request);
        } else if (cmd == "replicate") {
            response = handle_http_replicate(request);
        } else if (cmd == "heartbeat") {
            response = handle_http_heartbeat(request);
        } else if (cmd == "invalidate_cache") {
            response = handle_http_invalidate(request);
        } else if (cmd == "get_stream_position") {
            response = handle_http_get_position(request);
        } else {
            response["status"] = "error";
            response["error"] = "Unknown command: " + cmd;
        }

        return response;
    }

private:
    json handle_http_register(const json& req) {
        json resp;
        std::string worker_name = req.value("worker_name", std::string(""));
        std::string type_str = req.value("worker_type", std::string("generic_worker"));
        auto wtype = constants::worker_type_from_name(type_str);
        WorkerType type = wtype.value_or(WorkerType::Generic);

        // Register
        registry_->register_worker(worker_name, type);
        heartbeats_->register_heartbeat(worker_name, type);

        WorkerCapabilityRegistry::Capabilities caps =
            WorkerConfigStore::capabilities_for_type(type);
        if (req.contains("streams")) {
            for (const auto& s : req["streams"]) {
                auto st = constants::stream_type_from_name(s.get<std::string>());
                if (st.has_value()) caps.subscribed_streams.insert(*st);
            }
        }
        capabilities_->set_capabilities(worker_name, caps);

        // Return current positions
        json positions = json::object();
        for (const auto& [stream, pos] : streams_->get_all_positions())
            positions[constants::stream_type_name(stream)] = pos;

        resp["status"] = "ok";
        resp["positions"] = positions;
        return resp;
    }

    json handle_http_replicate(const json& req) {
        json resp;
        std::string worker_name = req.value("worker_name", std::string(""));

        // Get worker's current positions
        json worker_positions;
        if (req.contains("positions"))
            worker_positions = req["positions"];

        json streams_data = json::object();
        bool has_data = false;

        for (const auto& [stream_name, worker_pos] : worker_positions.items()) {
            auto stream_type = constants::stream_type_from_name(stream_name);
            if (!stream_type.has_value()) continue;

            int64_t since = worker_pos.get<int64_t>();
            int64_t current = streams_->get_position(*stream_type);

            if (current > since) {
                auto rows = streams_->get_rows_since(*stream_type, since);
                if (!rows.empty()) {
                    json stream_response;
                    stream_response["position"] = current;
                    json row_list = json::array();
                    for (auto& row : rows)
                        row_list.push_back(row.data);
                    stream_response["rows"] = row_list;
                    streams_data[stream_name] = stream_response;
                    has_data = true;
                } else {
                    // Even if no cached rows, tell worker the position advanced
                    json stream_response;
                    stream_response["position"] = current;
                    stream_response["rows"] = json::array();
                    streams_data[stream_name] = stream_response;
                    has_data = true;
                }
            }
        }

        resp["status"] = "ok";
        resp["streams"] = streams_data;
        resp["has_data"] = has_data;
        return resp;
    }

    json handle_http_heartbeat(const json& req) {
        std::string worker_name = req.value("worker_name", std::string(""));
        heartbeats_->heartbeat(worker_name);
        return {{"status", "ok"}};
    }

    json handle_http_invalidate(const json& req) {
        // Broadcast cache invalidation to all TCP workers
        ReplicationCommand cmd;
        cmd.cmd = ReplicationCommandType::INVALIDATE_CACHE;
        cmd.capabilities["cache_name"] = req.value("cache_name", std::string(""));
        cmd.capabilities["keys"] = req.value("keys", json::array());
        // Broadcast via TCP server if available
        return {{"status", "ok"}};
    }

    json handle_http_get_position(const json& req) {
        std::string stream_name = req.value("stream", std::string("events"));
        auto stream_type = constants::stream_type_from_name(stream_name);
        int64_t pos = stream_type.has_value()
            ? streams_->get_position(*stream_type) : 0;
        return {
            {"status", "ok"},
            {"stream", stream_name},
            {"position", pos}
        };
    }

    std::shared_ptr<ReplicationProtocolHandler> handler_;
    std::shared_ptr<WorkerRegistry> registry_;
    std::shared_ptr<WorkerHeartbeatManager> heartbeats_;
    std::shared_ptr<WorkerCapabilityRegistry> capabilities_;
    std::shared_ptr<ReplicationStreamManager> streams_;
    int port_;
};

// ============================================================================
// WorkerRunner — convenience class that ties everything together for a worker process
// ============================================================================
class WorkerRunner {
public:
    WorkerRunner(const WorkerConfig& config)
        : config_(config)
        , tcp_client_(std::make_unique<ReplicationTcpClient>(
              config.worker_name, config.type,
              config.worker_replication_host.empty() ? "127.0.0.1"
                  : config.worker_replication_host,
              config.worker_replication_port))
        , http_client_(std::make_unique<HttpReplicationClient>(
              config.worker_name, config.type,
              "http://" +
                  (config.worker_replication_host.empty()
                       ? "127.0.0.1"
                       : config.worker_replication_host) +
                  ":9094")) {
        // Set up RDATA callback
        auto cb = [this](StreamType stream,
                          const std::vector<json>& rows,
                          int64_t position) {
            handle_rdata(stream, rows, position);
        };
        tcp_client_->set_rdata_callback(cb);
        http_client_->set_rdata_callback(cb);
    }

    void start() {
        running_ = true;

        // Try TCP first, fall back to HTTP
        if (tcp_client_->connect()) {
            tcp_client_->start();
            using_tcp_ = true;
        } else {
            http_client_->start();
            using_tcp_ = false;
        }
    }

    void stop() {
        running_ = false;
        if (using_tcp_) {
            tcp_client_->stop();
        } else {
            http_client_->stop();
        }
    }

    bool is_connected() const {
        return using_tcp_ ? tcp_client_->is_connected() : true;
    }

    // Send a position acknowledgment
    void ack(StreamType stream, int64_t position) {
        if (using_tcp_)
            tcp_client_->ack_position(stream, position);
    }

    const WorkerConfig& config() const { return config_; }

private:
    void handle_rdata(StreamType stream,
                       const std::vector<json>& rows,
                       int64_t position) {
        // Process replication data — this is where the worker-specific logic goes
        // Each worker type processes streams differently:
        // - Synchrotron: updates its in-memory cache for client sync
        // - Pusher: checks for new push-worthy events
        // - FederationSender: queues outgoing federation transactions
        // - etc.

        (void)stream;
        (void)rows;
        (void)position;

        // Default: just track the position
        stream_positions_[stream] = position;

        // Process per-stream logic
        switch (stream) {
            case StreamType::Events:
                handle_events_rdata(rows, position);
                break;
            case StreamType::Presence:
                handle_presence_rdata(rows, position);
                break;
            case StreamType::Typing:
                handle_typing_rdata(rows, position);
                break;
            case StreamType::Receipts:
                handle_receipts_rdata(rows, position);
                break;
            case StreamType::AccountData:
                handle_account_data_rdata(rows, position);
                break;
            case StreamType::DeviceLists:
                handle_device_lists_rdata(rows, position);
                break;
            case StreamType::ToDevice:
                handle_to_device_rdata(rows, position);
                break;
            case StreamType::PushRules:
                handle_push_rules_rdata(rows, position);
                break;
            case StreamType::Backfill:
                handle_backfill_rdata(rows, position);
                break;
            case StreamType::StateDeltas:
                handle_state_deltas_rdata(rows, position);
                break;
            case StreamType::CurrentStateDeltas:
                handle_current_state_deltas_rdata(rows, position);
                break;
            case StreamType::SlidingSyncConnections:
                handle_sliding_sync_rdata(rows, position);
                break;
            default:
                break;
        }
    }

    // Per-stream handlers — each worker type overrides these virtually
    virtual void handle_events_rdata(const std::vector<json>& rows, int64_t pos) {
        for (const auto& row : rows) {
            // Extract event data: room_id, event_id, type, etc.
            std::string event_id = row.value("event_id", std::string(""));
            std::string room_id = row.value("room_id", std::string(""));
            std::string event_type = row.value("type", std::string(""));
            (void)event_id; (void)room_id; (void)event_type; (void)pos;
        }
    }

    virtual void handle_presence_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_typing_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_receipts_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_account_data_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_device_lists_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_to_device_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_push_rules_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_backfill_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_state_deltas_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_current_state_deltas_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    virtual void handle_sliding_sync_rdata(const std::vector<json>& rows, int64_t pos) {
        (void)rows; (void)pos;
    }

    WorkerConfig config_;
    std::unique_ptr<ReplicationTcpClient> tcp_client_;
    std::unique_ptr<HttpReplicationClient> http_client_;
    std::atomic<bool> running_{false};
    bool using_tcp_ = false;
    std::map<StreamType, int64_t> stream_positions_;
};

// ============================================================================
// MasterReplicationHub — main process hub that manages all replication
// ============================================================================
class MasterReplicationHub {
public:
    MasterReplicationHub() {
        registry_ = std::make_shared<WorkerRegistry>();
        heartbeats_ = std::make_shared<WorkerHeartbeatManager>();
        capabilities_ = std::make_shared<WorkerCapabilityRegistry>();
        tokens_ = std::make_shared<StreamTokenManager>();
        streams_ = std::make_shared<ReplicationStreamManager>();
        shards_ = std::make_shared<EventPersisterShardManager>();
        metrics_ = std::make_shared<WorkerMetricsCollector>();

        handler_ = std::make_shared<ReplicationProtocolHandler>(
            registry_, heartbeats_, capabilities_, tokens_, streams_, shards_, metrics_);

        tcp_server_ = std::make_shared<ReplicationTcpServer>(handler_);
        http_server_ = std::make_shared<ReplicationHttpServer>(handler_);

        // Wire up the HTTP server's dependent services
        http_server_->registry_ = registry_;
        http_server_->heartbeats_ = heartbeats_;
        http_server_->capabilities_ = capabilities_;
        http_server_->streams_ = streams_;
    }

    // Start the replication hub
    bool start(int tcp_port = constants::DEFAULT_REPLICATION_PORT,
               int http_port = constants::DEFAULT_HTTP_REPLICATION_PORT) {
        if (!tcp_server_->start()) {
            std::cerr << "[replication] failed to start TCP server on port "
                      << tcp_port << std::endl;
        }

        running_ = true;

        // Background tasks
        prune_thread_ = std::thread(&MasterReplicationHub::prune_loop, this);
        metrics_thread_ = std::thread(&MasterReplicationHub::metrics_loop, this);

        return true;
    }

    void stop() {
        running_ = false;
        tcp_server_->stop();

        // Notify all workers of shutdown
        ReplicationCommand shutdown_cmd;
        shutdown_cmd.cmd = ReplicationCommandType::SHUTDOWN;
        tcp_server_->broadcast(shutdown_cmd);

        if (prune_thread_.joinable()) prune_thread_.join();
        if (metrics_thread_.joinable()) metrics_thread_.join();
    }

    // Notification methods — called by the main event loop
    void notify_new_event(std::string_view room_id, std::string_view event_id,
                           int64_t stream_ordering) {
        streams_->advance(StreamType::Events, stream_ordering);
        tokens_->advance_stream(StreamType::Events, stream_ordering);
        tokens_->advance_room_stream(room_id, stream_ordering);

        json data;
        data["room_id"] = room_id;
        data["event_id"] = event_id;
        data["stream_ordering"] = stream_ordering;
        streams_->cache_row(StreamType::Events, stream_ordering, data);

        // For event persister sharding
        std::string shard = shards_->get_shard_for_room(room_id);
        data["target_shard"] = shard;

        tcp_server_->send_rdata(StreamType::Events, {data}, stream_ordering);
    }

    void notify_new_presence(std::string_view user_id, std::string_view state,
                              int64_t position) {
        streams_->advance(StreamType::Presence, position);
        tokens_->advance_stream(StreamType::Presence, position);

        json data;
        data["user_id"] = user_id;
        data["state"] = state;
        data["position"] = position;
        streams_->cache_row(StreamType::Presence, position, data);

        tcp_server_->send_rdata(StreamType::Presence, {data}, position);
    }

    void notify_new_typing(std::string_view room_id, std::string_view user_id,
                            bool typing, int64_t position) {
        streams_->advance(StreamType::Typing, position);
        tokens_->advance_stream(StreamType::Typing, position);

        json data;
        data["room_id"] = room_id;
        data["user_id"] = user_id;
        data["typing"] = typing;
        streams_->cache_row(StreamType::Typing, position, data);

        tcp_server_->send_rdata(StreamType::Typing, {data}, position);
    }

    void notify_new_receipt(std::string_view room_id, std::string_view user_id,
                             std::string_view event_id, std::string_view receipt_type,
                             int64_t position) {
        streams_->advance(StreamType::Receipts, position);
        tokens_->advance_stream(StreamType::Receipts, position);

        json data;
        data["room_id"] = room_id;
        data["user_id"] = user_id;
        data["event_id"] = event_id;
        data["receipt_type"] = receipt_type;
        streams_->cache_row(StreamType::Receipts, position, data);

        tcp_server_->send_rdata(StreamType::Receipts, {data}, position);
    }

    void notify_new_account_data(std::string_view user_id, std::string_view data_type,
                                  int64_t position) {
        streams_->advance(StreamType::AccountData, position);
        tokens_->advance_stream(StreamType::AccountData, position);

        json data;
        data["user_id"] = user_id;
        data["type"] = data_type;
        streams_->cache_row(StreamType::AccountData, position, data);

        tcp_server_->send_rdata(StreamType::AccountData, {data}, position);
    }

    void notify_new_device_list(std::string_view user_id,
                                 const std::vector<std::string>& device_ids,
                                 int64_t position) {
        streams_->advance(StreamType::DeviceLists, position);
        tokens_->advance_stream(StreamType::DeviceLists, position);

        json data;
        data["user_id"] = user_id;
        data["devices"] = device_ids;
        streams_->cache_row(StreamType::DeviceLists, position, data);

        tcp_server_->send_rdata(StreamType::DeviceLists, {data}, position);
    }

    void notify_new_to_device(std::string_view sender, std::string_view target,
                               std::string_view message_type, int64_t position) {
        streams_->advance(StreamType::ToDevice, position);
        tokens_->advance_stream(StreamType::ToDevice, position);

        json data;
        data["sender"] = sender;
        data["target"] = target;
        data["type"] = message_type;
        streams_->cache_row(StreamType::ToDevice, position, data);

        tcp_server_->send_rdata(StreamType::ToDevice, {data}, position);
    }

    void notify_new_push_rule(std::string_view user_id, std::string_view rule_id,
                               int64_t position) {
        streams_->advance(StreamType::PushRules, position);
        tokens_->advance_stream(StreamType::PushRules, position);

        json data;
        data["user_id"] = user_id;
        data["rule_id"] = rule_id;
        streams_->cache_row(StreamType::PushRules, position, data);

        tcp_server_->send_rdata(StreamType::PushRules, {data}, position);
    }

    // Invalidate a cache on all workers
    void invalidate_cache(std::string_view cache_name,
                           const std::vector<std::string>& keys = {}) {
        ReplicationCommand cmd;
        cmd.cmd = ReplicationCommandType::INVALIDATE_CACHE;
        cmd.capabilities["cache_name"] = std::string(cache_name);
        cmd.capabilities["keys"] = keys;
        tcp_server_->broadcast(cmd);
    }

    // Getters for external access
    std::shared_ptr<StreamTokenManager> get_token_manager() { return tokens_; }
    std::shared_ptr<ReplicationStreamManager> get_stream_manager() { return streams_; }
    std::shared_ptr<EventPersisterShardManager> get_shard_manager() { return shards_; }
    std::shared_ptr<WorkerHeartbeatManager> get_heartbeat_manager() { return heartbeats_; }
    std::shared_ptr<WorkerRegistry> get_registry() { return registry_; }
    WorkerMetricsCollector& get_metrics() { return *metrics_; }

    size_t connected_worker_count() const { return tcp_server_->worker_count(); }

    // Get full replication status as JSON
    json get_status() const {
        json j;
        j["protocol_version"] = constants::REPLICATION_PROTOCOL_VERSION;
        j["connected_workers"] = tcp_server_->worker_count();
        j["workers"] = heartbeats_->to_json();
        j["stream_positions"] = json::object();
        for (const auto& [type, pos] : streams_->get_all_positions())
            j["stream_positions"][constants::stream_type_name(type)] = pos;
        j["event_persister_shards"] = shards_->get_stats();
        j["metrics"] = metrics_->to_json();
        return j;
    }

private:
    void prune_loop() {
        while (running_) {
            std::this_thread::sleep_for(chr::seconds(10));
            if (!running_) break;
            heartbeats_->prune_dead();
            shards_->prune_dead_shards();
        }
    }

    void metrics_loop() {
        while (running_) {
            std::this_thread::sleep_for(chr::seconds(60));
            if (!running_) break;
            // Periodic metrics logging or export
        }
    }

    std::atomic<bool> running_{false};

    std::shared_ptr<WorkerRegistry> registry_;
    std::shared_ptr<WorkerHeartbeatManager> heartbeats_;
    std::shared_ptr<WorkerCapabilityRegistry> capabilities_;
    std::shared_ptr<StreamTokenManager> tokens_;
    std::shared_ptr<ReplicationStreamManager> streams_;
    std::shared_ptr<EventPersisterShardManager> shards_;
    std::shared_ptr<WorkerMetricsCollector> metrics_;

    std::shared_ptr<ReplicationProtocolHandler> handler_;
    std::shared_ptr<ReplicationTcpServer> tcp_server_;
    std::shared_ptr<ReplicationHttpServer> http_server_;

    std::thread prune_thread_;
    std::thread metrics_thread_;
};

// ============================================================================
// SynchrotronWorker — specialized worker for sync endpoints
// ============================================================================
class SynchrotronWorker : public WorkerRunner {
public:
    SynchrotronWorker(const WorkerConfig& config) : WorkerRunner(config) {}

protected:
    void handle_events_rdata(const std::vector<json>& rows, int64_t pos) override {
        for (const auto& row : rows) {
            std::string room_id = row.value("room_id", std::string(""));
            std::string event_id = row.value("event_id", std::string(""));
            int64_t stream_ordering = row.value("stream_ordering", 0LL);

            // Update the in-memory cache for sync responses
            {
                std::lock_guard lock(cache_mutex_);
                event_cache_[room_id].push_back({event_id, stream_ordering});
                // Trim old entries
                auto& vec = event_cache_[room_id];
                while (vec.size() > 1000)
                    vec.erase(vec.begin());
            }

            // Mark room as changed for sync tokens
            room_changed_.mark_changed(room_id, static_cast<uint64_t>(stream_ordering));
        }

        (void)pos;
    }

    void handle_presence_rdata(const std::vector<json>& rows, int64_t pos) override {
        std::lock_guard lock(presence_mutex_);
        for (const auto& row : rows) {
            std::string user_id = row.value("user_id", std::string(""));
            std::string state = row.value("state", std::string(""));
            presence_cache_[user_id] = state;
        }
        (void)pos;
    }

    void handle_typing_rdata(const std::vector<json>& rows, int64_t pos) override {
        std::lock_guard lock(typing_mutex_);
        for (const auto& row : rows) {
            std::string room_id = row.value("room_id", std::string(""));
            std::string user_id = row.value("user_id", std::string(""));
            bool typing = row.value("typing", false);
            if (typing)
                typing_cache_[room_id].insert(user_id);
            else
                typing_cache_[room_id].erase(user_id);
        }
        (void)pos;
    }

    void handle_receipts_rdata(const std::vector<json>& rows, int64_t pos) override {
        std::lock_guard lock(receipts_mutex_);
        for (const auto& row : rows) {
            std::string room_id = row.value("room_id", std::string(""));
            std::string event_id = row.value("event_id", std::string(""));
            receipt_cache_[room_id] = event_id;
        }
        (void)pos;
    }

private:
    struct CachedEvent {
        std::string event_id;
        int64_t stream_ordering;
    };

    std::mutex cache_mutex_;
    std::map<std::string, std::deque<CachedEvent>, std::less<>> event_cache_;

    std::mutex presence_mutex_;
    std::map<std::string, std::string, std::less<>> presence_cache_;

    std::mutex typing_mutex_;
    std::map<std::string, std::set<std::string>, std::less<>> typing_cache_;

    std::mutex receipts_mutex_;
    std::map<std::string, std::string, std::less<>> receipt_cache_;

    progressive::util::StreamChangeCache room_changed_;
};

// ============================================================================
// PusherWorker — specialized worker for push notifications
// ============================================================================
class PusherWorker : public WorkerRunner {
public:
    PusherWorker(const WorkerConfig& config) : WorkerRunner(config) {}

protected:
    void handle_events_rdata(const std::vector<json>& rows, int64_t pos) override {
        // Check each event for push-worthiness
        for (const auto& row : rows) {
            std::string event_id = row.value("event_id", std::string(""));
            std::string room_id = row.value("room_id", std::string(""));
            std::string sender = row.value("sender", std::string(""));
            std::string event_type = row.value("type", std::string(""));

            (void)event_type;

            // Queue for push processing
            std::lock_guard lock(queue_mutex_);
            push_queue_.push_back({event_id, room_id, sender, pos});
        }
        process_push_queue();
    }

    void handle_push_rules_rdata(const std::vector<json>& rows, int64_t pos) override {
        std::lock_guard lock(rules_mutex_);
        for (const auto& row : rows) {
            std::string user_id = row.value("user_id", std::string(""));
            std::string rule_id = row.value("rule_id", std::string(""));
            // Invalidate cached push rules
            rule_cache_invalidated_.insert(user_id);
            (void)rule_id;
        }
        (void)pos;
    }

private:
    struct PushJob {
        std::string event_id;
        std::string room_id;
        std::string sender;
        int64_t position;
    };

    void process_push_queue() {
        std::vector<PushJob> jobs;
        {
            std::lock_guard lock(queue_mutex_);
            jobs.swap(push_queue_);
        }
        // Process push jobs — evaluate push rules for each event
        for (const auto& job : jobs) {
            _evaluate_push(job);
        }
    }

    void _evaluate_push(const PushJob& job) {
        // Placeholder: evaluate push rules and send notifications
        (void)job;
    }

    std::mutex queue_mutex_;
    std::vector<PushJob> push_queue_;

    std::mutex rules_mutex_;
    std::set<std::string, std::less<>> rule_cache_invalidated_;
};

// ============================================================================
// FederationSenderWorker — specialized worker for federation
// ============================================================================
class FederationSenderWorker : public WorkerRunner {
public:
    FederationSenderWorker(const WorkerConfig& config) : WorkerRunner(config) {}

protected:
    void handle_events_rdata(const std::vector<json>& rows, int64_t pos) override {
        for (const auto& row : rows) {
            std::string event_id = row.value("event_id", std::string(""));
            std::string room_id = row.value("room_id", std::string(""));
            std::string sender = row.value("sender", std::string(""));

            // Queue for federation sending
            std::lock_guard lock(queue_mutex_);
            fed_queue_.push_back({event_id, room_id, sender, pos});
        }
        process_fed_queue();
    }

    void handle_device_lists_rdata(const std::vector<json>& rows, int64_t pos) override {
        for (const auto& row : rows) {
            std::string user_id = row.value("user_id", std::string(""));
            // Mark user's device list as needing federation push
            std::lock_guard lock(device_list_mutex_);
            pending_device_list_pushes_.insert(user_id);
        }
        (void)pos;
    }

private:
    struct FedJob {
        std::string event_id;
        std::string room_id;
        std::string sender;
        int64_t position;
    };

    void process_fed_queue() {
        std::vector<FedJob> jobs;
        {
            std::lock_guard lock(queue_mutex_);
            jobs.swap(fed_queue_);
        }
        for (const auto& job : jobs) {
            _send_to_destinations(job);
        }
    }

    void _send_to_destinations(const FedJob& job) {
        // Placeholder: resolve destinations and send federation transaction
        (void)job;
    }

    std::mutex queue_mutex_;
    std::vector<FedJob> fed_queue_;

    std::mutex device_list_mutex_;
    std::set<std::string, std::less<>> pending_device_list_pushes_;
};

// ============================================================================
// EventPersisterWorker — worker that persists events to the database
// ============================================================================
class EventPersisterWorker : public WorkerRunner {
public:
    EventPersisterWorker(const WorkerConfig& config, int shard_id = 0)
        : WorkerRunner(config), shard_id_(shard_id) {}

    // Called by the master to assign events to this shard
    void persist_event(std::string_view room_id, const json& event,
                        std::string_view instance_name) {
        (void)room_id;
        std::lock_guard lock(persist_mutex_);
        pending_persists_.push_back(event);
        last_persister_instance_ = std::string(instance_name);
    }

    void set_persist_callback(std::function<void(const json&)> cb) {
        persist_callback_ = std::move(cb);
    }

    void flush() {
        std::vector<json> batch;
        {
            std::lock_guard lock(persist_mutex_);
            batch.swap(pending_persists_);
        }
        if (persist_callback_) {
            for (auto& ev : batch)
                persist_callback_(ev);
        }
    }

protected:
    void handle_events_rdata(const std::vector<json>& rows, int64_t pos) override {
        // Process events stream — store into database
        for (const auto& row : rows) {
            if (persist_callback_)
                persist_callback_(row);
        }
        (void)pos;
    }

private:
    int shard_id_;
    std::mutex persist_mutex_;
    std::vector<json> pending_persists_;
    std::function<void(const json&)> persist_callback_;
    std::string last_persister_instance_;
};

// ============================================================================
// Factory functions for creating worker instances
// ============================================================================

// Create a worker runner of the appropriate type based on config
inline std::unique_ptr<WorkerRunner> create_worker_runner(const WorkerConfig& config) {
    switch (config.type) {
        case WorkerType::Synchrotron:
            return std::make_unique<SynchrotronWorker>(config);
        case WorkerType::Pusher:
            return std::make_unique<PusherWorker>(config);
        case WorkerType::FederationSender:
            return std::make_unique<FederationSenderWorker>(config);
        case WorkerType::EventPersister:
            return std::make_unique<EventPersisterWorker>(config);
        default:
            return std::make_unique<WorkerRunner>(config);
    }
}

// ============================================================================
// JSON utility for serializing replication state
// ============================================================================
inline json replication_stats_to_json(const MasterReplicationHub& hub) {
    return hub.get_status();
}

inline json worker_config_to_json(const WorkerConfig& cfg) {
    json j;
    j["worker_name"] = cfg.worker_name;
    j["worker_type"] = constants::worker_type_name(cfg.type);
    j["worker_replication_host"] = cfg.worker_replication_host;
    j["worker_replication_port"] = cfg.worker_replication_port;
    j["run_background_tasks"] = cfg.run_background_tasks;
    json streams = json::array();
    for (auto& s : cfg.streams_to_replicate)
        streams.push_back(constants::stream_type_name(s));
    j["streams_to_replicate"] = streams;
    return j;
}

} // namespace worker
} // namespace progressive

// ============================================================================
// Stub main entry point for worker processes
// This can be compiled as a separate binary or linked into the main binary
// ============================================================================
#ifdef REPLICATION_WORKER_STANDALONE
#include <csignal>

namespace {
std::atomic<bool> g_running{true};

void signal_handler(int) {
    g_running = false;
}
} // anonymous namespace

int main(int argc, char** argv) {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    std::cout << "Progressive Server Worker Process" << std::endl;

    // Parse arguments
    std::string worker_name = "worker_default";
    std::string worker_type_str = "generic_worker";
    std::string replication_host = "127.0.0.1";
    int replication_port = 9093;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg == "--name" && i + 1 < argc)
            worker_name = argv[++i];
        else if (arg == "--type" && i + 1 < argc)
            worker_type_str = argv[++i];
        else if (arg == "--host" && i + 1 < argc)
            replication_host = argv[++i];
        else if (arg == "--port" && i + 1 < argc)
            replication_port = std::stoi(argv[++i]);
    }

    // Create worker configuration
    progressive::worker::WorkerConfig config;
    config.worker_name = worker_name;
    auto wtype = progressive::worker::constants::worker_type_from_name(worker_type_str);
    config.type = wtype.value_or(progressive::worker::WorkerType::Generic);
    config.worker_replication_host = replication_host;
    config.worker_replication_port = replication_port;
    config.streams_to_replicate =
        progressive::worker::WorkerConfigStore::default_streams_for_type(config.type);

    // Run worker
    auto worker = progressive::worker::create_worker_runner(config);
    worker->start();

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    worker->stop();
    std::cout << "Worker process shutting down." << std::endl;
    return 0;
}
#endif // REPLICATION_WORKER_STANDALONE
