#include "replication.hpp"
#include "../json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

// Platform-specific networking
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
#define SOCKET_INVALID INVALID_SOCKET
#define SOCKET_ERROR_CODE WSAGetLastError()
#define SOCKET_WOULDBLOCK WSAEWOULDBLOCK
#define CLOSE_SOCKET closesocket
using socklen_t = int;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using socket_t = int;
#define SOCKET_INVALID (-1)
#define SOCKET_ERROR_CODE errno
#define SOCKET_WOULDBLOCK EAGAIN
#define CLOSE_SOCKET close
#endif

namespace progressive::worker {

// ============================================================================
// Forward declarations
// ============================================================================
class ReplicationManager;
class RedisReplicationBackend;
class TCPReplicationBackend;
class MasterReplicationServer;
class WorkerReplicationClient;
class StreamManager;
class WorkerHealthMonitor;
class WorkerLoadBalancer;
class WorkerConfigManager;
class ReplicationProtocol;

// ============================================================================
// Constants
// ============================================================================
namespace {
constexpr int DEFAULT_REPLICATION_PORT = 9093;
constexpr int MAX_RECONNECT_ATTEMPTS = 20;
constexpr int BASE_RECONNECT_DELAY_MS = 100;
constexpr int MAX_RECONNECT_DELAY_MS = 30000;
constexpr int PING_INTERVAL_MS = 5000;
constexpr int PING_TIMEOUT_MS = 15000;
constexpr int WORKER_TIMEOUT_MS = 30000;
constexpr int MAX_STREAM_BATCH_SIZE = 256;
constexpr int TCP_BUFFER_SIZE = 65536;
constexpr int MAX_REDIS_STREAM_LENGTH = 10000;
constexpr int CATCH_UP_BATCH_SIZE = 100;
constexpr int PROTOCOL_VERSION = 3;

// Replication commands as uint8_t
enum class ReplicationCommand : uint8_t {
  RDATA = 0x01,    // Replication data
  POSITION = 0x02, // Position acknowledgement
  SYNC = 0x03,     // Synchronization request
  PING = 0x04,     // Health check ping
  PONG = 0x05,     // Health check pong
  ERROR = 0x06,    // Error message
  REPLICATE = 0x07,// Subscribe to stream
  UNREPLICATE = 0x08, // Unsubscribe from stream
  REGISTER = 0x09, // Worker registration
  UNREGISTER = 0x0A, // Worker unregistration
  FEDERATION = 0x0B, // Federation stream
  CACHE_INVAL = 0x0C, // Cache invalidation
  BACKFILL_REQUEST = 0x0D, // Backfill request
  BACKFILL_RESPONSE = 0x0E, // Backfill response
  STREAM_ACK = 0x0F, // Stream batch acknowledgement
};

// Wire message framing
constexpr uint8_t FRAME_MAGIC = 0x5A; // 'Z' for sync
constexpr uint32_t FRAME_HEADER_SIZE = 1 + 1 + 4; // magic + command + length

// Stream name constants for Redis
constexpr const char* REDIS_EVENTS_STREAM = "matrix:stream:events";
constexpr const char* REDIS_BACKFILL_STREAM = "matrix:stream:backfill";
constexpr const char* REDIS_TYPING_STREAM = "matrix:stream:typing";
constexpr const char* REDIS_TO_DEVICE_STREAM = "matrix:stream:todevice";
constexpr const char* REDIS_PRESENCE_STREAM = "matrix:stream:presence";
constexpr const char* REDIS_RECEIPTS_STREAM = "matrix:stream:receipts";
constexpr const char* REDIS_ACCOUNT_DATA_STREAM = "matrix:stream:account_data";
constexpr const char* REDIS_DEVICE_LISTS_STREAM = "matrix:stream:device_lists";
constexpr const char* REDIS_CACHES_STREAM = "matrix:stream:caches";
constexpr const char* REDIS_FEDERATION_STREAM = "matrix:stream:federation";
constexpr const char* REDIS_PUSHERS_STREAM = "matrix:stream:pushers";
constexpr const char* REDIS_PUBSUB_CHANNEL = "matrix:pubsub:replication";
constexpr const char* REDIS_POSITION_KEY = "matrix:positions";

// TCP protocol message types
constexpr uint8_t TCP_MSG_RDATA = 0x01;
constexpr uint8_t TCP_MSG_POSITION = 0x02;
constexpr uint8_t TCP_MSG_SYNC = 0x03;
constexpr uint8_t TCP_MSG_PING = 0x04;
constexpr uint8_t TCP_MSG_PONG = 0x05;
constexpr uint8_t TCP_MSG_ERROR = 0x06;

} // anonymous namespace

// ============================================================================
// Utility functions
// ============================================================================

static std::string stream_type_name(StreamType type) {
  switch (type) {
    case StreamType::Events: return "events";
    case StreamType::Backfill: return "backfill";
    case StreamType::Presence: return "presence";
    case StreamType::Typing: return "typing";
    case StreamType::Receipts: return "receipts";
    case StreamType::AccountData: return "account_data";
    case StreamType::DeviceLists: return "device_lists";
    case StreamType::ToDevice: return "to_device";
    case StreamType::PushRules: return "push_rules";
    case StreamType::StateDeltas: return "state_deltas";
    case StreamType::SlidingSyncConnections: return "sliding_sync_connections";
    case StreamType::CurrentStateDeltas: return "current_state_deltas";
    case StreamType::UnPartialStatedRooms: return "un_partial_stated_rooms";
    default: return "unknown";
  }
}

static StreamType stream_type_from_name(std::string_view name) {
  if (name == "events") return StreamType::Events;
  if (name == "backfill") return StreamType::Backfill;
  if (name == "presence") return StreamType::Presence;
  if (name == "typing") return StreamType::Typing;
  if (name == "receipts") return StreamType::Receipts;
  if (name == "account_data") return StreamType::AccountData;
  if (name == "device_lists") return StreamType::DeviceLists;
  if (name == "to_device") return StreamType::ToDevice;
  if (name == "push_rules") return StreamType::PushRules;
  if (name == "state_deltas") return StreamType::StateDeltas;
  if (name == "sliding_sync_connections") return StreamType::SlidingSyncConnections;
  if (name == "current_state_deltas") return StreamType::CurrentStateDeltas;
  if (name == "un_partial_stated_rooms") return StreamType::UnPartialStatedRooms;
  throw std::runtime_error(std::string("Unknown stream type: ") + std::string(name));
}

static std::string worker_type_name(WorkerType type) {
  switch (type) {
    case WorkerType::Generic: return "generic";
    case WorkerType::ClientReader: return "client_reader";
    case WorkerType::FederationSender: return "federation_sender";
    case WorkerType::FederationReader: return "federation_reader";
    case WorkerType::EventCreator: return "event_creator";
    case WorkerType::EventPersister: return "event_persister";
    case WorkerType::Pusher: return "pusher";
    case WorkerType::Appservice: return "appservice";
    case WorkerType::Synchrotron: return "synchrotron";
    case WorkerType::MediaRepository: return "media_repository";
    case WorkerType::UserDir: return "user_dir";
    case WorkerType::FrontendProxy: return "frontend_proxy";
    case WorkerType::PhoneStats: return "phone_stats";
    default: return "unknown";
  }
}

static WorkerType worker_type_from_name(std::string_view name) {
  if (name == "generic") return WorkerType::Generic;
  if (name == "client_reader") return WorkerType::ClientReader;
  if (name == "federation_sender") return WorkerType::FederationSender;
  if (name == "federation_reader") return WorkerType::FederationReader;
  if (name == "event_creator") return WorkerType::EventCreator;
  if (name == "event_persister") return WorkerType::EventPersister;
  if (name == "pusher") return WorkerType::Pusher;
  if (name == "appservice") return WorkerType::Appservice;
  if (name == "synchrotron") return WorkerType::Synchrotron;
  if (name == "media_repository") return WorkerType::MediaRepository;
  if (name == "user_dir") return WorkerType::UserDir;
  if (name == "frontend_proxy") return WorkerType::FrontendProxy;
  if (name == "phone_stats") return WorkerType::PhoneStats;
  throw std::runtime_error(std::string("Unknown worker type: ") + std::string(name));
}

static std::set<StreamType> default_streams_for_worker(WorkerType type) {
  switch (type) {
    case WorkerType::Generic:
      return {
        StreamType::Events, StreamType::Presence, StreamType::Typing,
        StreamType::Receipts, StreamType::AccountData, StreamType::DeviceLists,
        StreamType::ToDevice, StreamType::PushRules, StreamType::StateDeltas,
        StreamType::CurrentStateDeltas
      };
    case WorkerType::Pusher:
      return {
        StreamType::Events, StreamType::Presence, StreamType::Receipts,
        StreamType::AccountData, StreamType::PushRules, StreamType::DeviceLists
      };
    case WorkerType::FederationSender:
      return {
        StreamType::Events, StreamType::Backfill, StreamType::Presence,
        StreamType::Typing, StreamType::Receipts, StreamType::DeviceLists,
        StreamType::ToDevice
      };
    case WorkerType::FederationReader:
      return {
        StreamType::Events, StreamType::Backfill, StreamType::StateDeltas
      };
    case WorkerType::EventCreator:
      return {StreamType::Events};
    case WorkerType::EventPersister:
      return {StreamType::Events, StreamType::StateDeltas, StreamType::CurrentStateDeltas};
    case WorkerType::Appservice:
      return {
        StreamType::Events, StreamType::Presence, StreamType::Typing,
        StreamType::Receipts, StreamType::AccountData, StreamType::DeviceLists,
        StreamType::ToDevice
      };
    case WorkerType::Synchrotron:
      return {
        StreamType::Events, StreamType::Presence, StreamType::Typing,
        StreamType::Receipts, StreamType::AccountData, StreamType::DeviceLists,
        StreamType::ToDevice, StreamType::PushRules, StreamType::StateDeltas,
        StreamType::CurrentStateDeltas, StreamType::SlidingSyncConnections,
        StreamType::UnPartialStatedRooms
      };
    case WorkerType::MediaRepository:
      return {StreamType::Events};
    case WorkerType::UserDir:
      return {StreamType::Events, StreamType::Presence};
    case WorkerType::ClientReader:
      return {
        StreamType::Events, StreamType::Presence, StreamType::Typing,
        StreamType::Receipts, StreamType::AccountData
      };
    case WorkerType::FrontendProxy:
      return {
        StreamType::Events, StreamType::Presence, StreamType::Typing,
        StreamType::Receipts, StreamType::AccountData, StreamType::DeviceLists,
        StreamType::ToDevice
      };
    case WorkerType::PhoneStats:
      return {StreamType::Events};
    default:
      return {
        StreamType::Events, StreamType::Presence, StreamType::Typing,
        StreamType::Receipts, StreamType::AccountData, StreamType::DeviceLists
      };
  }
}

// ============================================================================
// StreamEntry: A single replication stream entry
// ============================================================================

struct StreamEntry {
  StreamType type;
  int64_t position;
  std::string stream_id;
  std::string room_id;
  std::string user_id;
  std::string event_id;
  std::string data;        // JSON-serialized payload
  std::chrono::steady_clock::time_point timestamp;

  nlohmann::json to_json() const {
    nlohmann::json j;
    j["type"] = stream_type_name(type);
    j["position"] = position;
    j["stream_id"] = stream_id;
    if (!room_id.empty()) j["room_id"] = room_id;
    if (!user_id.empty()) j["user_id"] = user_id;
    if (!event_id.empty()) j["event_id"] = event_id;
    if (!data.empty()) j["data"] = data;
    return j;
  }

  static StreamEntry from_json(const nlohmann::json& j) {
    StreamEntry e;
    e.type = stream_type_from_name(j.value("type", "events"));
    e.position = j.value("position", 0LL);
    e.stream_id = j.value("stream_id", "");
    e.room_id = j.value("room_id", "");
    e.user_id = j.value("user_id", "");
    e.event_id = j.value("event_id", "");
    if (j.contains("data") && j["data"].is_string())
      e.data = j["data"].get<std::string>();
    e.timestamp = std::chrono::steady_clock::now();
    return e;
  }
};

// ============================================================================
// ReplicationFrame: Wire protocol frame
// ============================================================================

struct ReplicationFrame {
  ReplicationCommand command;
  uint32_t payload_length;
  std::vector<uint8_t> payload;

  std::vector<uint8_t> serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(FRAME_HEADER_SIZE + payload.size());
    buf.push_back(FRAME_MAGIC);
    buf.push_back(static_cast<uint8_t>(command));
    uint32_t len = htonl(payload_length);
    const auto* len_bytes = reinterpret_cast<const uint8_t*>(&len);
    buf.insert(buf.end(), len_bytes, len_bytes + 4);
    buf.insert(buf.end(), payload.begin(), payload.end());
    return buf;
  }

  static std::optional<ReplicationFrame> parse(const std::vector<uint8_t>& buffer, size_t& consumed) {
    if (buffer.size() < FRAME_HEADER_SIZE) return std::nullopt;
    if (buffer[0] != FRAME_MAGIC) {
      consumed = 1;
      return std::nullopt; // Skip bad byte
    }
    uint32_t plen;
    std::memcpy(&plen, buffer.data() + 2, 4);
    plen = ntohl(plen);
    if (buffer.size() < FRAME_HEADER_SIZE + plen) return std::nullopt;

    ReplicationFrame frame;
    frame.command = static_cast<ReplicationCommand>(buffer[1]);
    frame.payload_length = plen;
    frame.payload.assign(buffer.begin() + FRAME_HEADER_SIZE,
                         buffer.begin() + FRAME_HEADER_SIZE + plen);
    consumed = FRAME_HEADER_SIZE + plen;
    return frame;
  }
};

// ============================================================================
// ReplicationProtocol: Command handling layer
// ============================================================================

class ReplicationProtocol {
public:
  ReplicationProtocol() = default;

  // Create RDATA command
  static ReplicationFrame make_rdata(StreamType type, int64_t position,
                                     const std::string& data) {
    nlohmann::json j;
    j["cmd"] = "RDATA";
    j["stream"] = stream_type_name(type);
    j["position"] = position;
    j["data"] = data;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::RDATA;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Create POSITION command
  static ReplicationFrame make_position(std::string_view worker_name,
                                        StreamType type, int64_t position) {
    nlohmann::json j;
    j["cmd"] = "POSITION";
    j["worker"] = worker_name;
    j["stream"] = stream_type_name(type);
    j["position"] = position;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::POSITION;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Create SYNC command
  static ReplicationFrame make_sync(std::string_view worker_name,
                                    int64_t since_token) {
    nlohmann::json j;
    j["cmd"] = "SYNC";
    j["worker"] = worker_name;
    j["since"] = since_token;
    j["protocol_version"] = PROTOCOL_VERSION;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::SYNC;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Create PING command
  static ReplicationFrame make_ping(std::string_view worker_name,
                                    int64_t ping_id) {
    nlohmann::json j;
    j["cmd"] = "PING";
    j["worker"] = worker_name;
    j["ping_id"] = ping_id;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::PING;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Create PONG command
  static ReplicationFrame make_pong(int64_t ping_id) {
    nlohmann::json j;
    j["cmd"] = "PONG";
    j["ping_id"] = ping_id;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::PONG;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Create ERROR command
  static ReplicationFrame make_error(const std::string& error_msg,
                                     const std::string& context = "") {
    nlohmann::json j;
    j["cmd"] = "ERROR";
    j["message"] = error_msg;
    if (!context.empty()) j["context"] = context;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::ERROR;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Create REPLICATE (subscribe) command
  static ReplicationFrame make_replicate(std::string_view worker_name,
                                         const std::set<StreamType>& streams) {
    nlohmann::json j;
    j["cmd"] = "REPLICATE";
    j["worker"] = worker_name;
    nlohmann::json streams_arr = nlohmann::json::array();
    for (auto st : streams)
      streams_arr.push_back(stream_type_name(st));
    j["streams"] = streams_arr;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::REPLICATE;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Create REGISTER command
  static ReplicationFrame make_register(std::string_view worker_name,
                                        WorkerType worker_type,
                                        const std::set<StreamType>& streams) {
    nlohmann::json j;
    j["cmd"] = "REGISTER";
    j["worker"] = worker_name;
    j["worker_type"] = worker_type_name(worker_type);
    nlohmann::json streams_arr = nlohmann::json::array();
    for (auto st : streams)
      streams_arr.push_back(stream_type_name(st));
    j["streams"] = streams_arr;
    j["protocol_version"] = PROTOCOL_VERSION;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::REGISTER;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Create UNREGISTER command
  static ReplicationFrame make_unregister(std::string_view worker_name) {
    nlohmann::json j;
    j["cmd"] = "UNREGISTER";
    j["worker"] = worker_name;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::UNREGISTER;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Create STREAM_ACK
  static ReplicationFrame make_stream_ack(std::string_view worker_name,
                                          StreamType type, int64_t position) {
    nlohmann::json j;
    j["cmd"] = "STREAM_ACK";
    j["worker"] = worker_name;
    j["stream"] = stream_type_name(type);
    j["position"] = position;

    std::string payload_str = j.dump();
    ReplicationFrame frame;
    frame.command = ReplicationCommand::STREAM_ACK;
    frame.payload.assign(payload_str.begin(), payload_str.end());
    frame.payload_length = static_cast<uint32_t>(frame.payload.size());
    return frame;
  }

  // Parse frame payload as JSON
  static nlohmann::json parse_payload(const ReplicationFrame& frame) {
    if (frame.payload.empty()) return nlohmann::json::object();
    std::string str(frame.payload.begin(), frame.payload.end());
    return nlohmann::json::parse(str);
  }

  // Parse RDATA payload
  static std::optional<StreamEntry> parse_rdata(const ReplicationFrame& frame) {
    auto j = parse_payload(frame);
    StreamEntry entry;
    entry.type = stream_type_from_name(j.value("stream", "events"));
    entry.position = j.value("position", 0LL);
    if (j.contains("data") && j["data"].is_string())
      entry.data = j["data"].get<std::string>();
    if (j.contains("room_id"))
      entry.room_id = j["room_id"].get<std::string>();
    if (j.contains("user_id"))
      entry.user_id = j["user_id"].get<std::string>();
    if (j.contains("event_id"))
      entry.event_id = j["event_id"].get<std::string>();
    entry.timestamp = std::chrono::steady_clock::now();
    return entry;
  }
};

// ============================================================================
// RedisReplicationBackend: Redis PUB/SUB + sorted sets
// ============================================================================

class RedisReplicationBackend {
public:
  RedisReplicationBackend(const std::string& redis_host, int redis_port,
                          const std::string& redis_password = "")
      : host_(redis_host), port_(redis_port), password_(redis_password),
        connected_(false), running_(false) {}

  ~RedisReplicationBackend() { disconnect(); }

  // Connect to Redis
  bool connect() {
    std::lock_guard lock(mutex_);
    if (connected_) return true;

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == SOCKET_INVALID) return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port_));
    struct hostent* he = gethostbyname(host_.c_str());
    if (!he) {
      CLOSE_SOCKET(sock);
      return false;
    }
    std::memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
      CLOSE_SOCKET(sock);
      return false;
    }

    redis_socket_ = sock;
    connected_ = true;

    if (!password_.empty()) {
      send_redis_command("AUTH " + password_);
    }

    return true;
  }

  // Disconnect from Redis
  void disconnect() {
    std::lock_guard lock(mutex_);
    if (redis_socket_ != SOCKET_INVALID) {
      CLOSE_SOCKET(redis_socket_);
      redis_socket_ = SOCKET_INVALID;
    }
    connected_ = false;
  }

  // Check if connected
  bool is_connected() const {
    std::lock_guard lock(mutex_);
    return connected_;
  }

  // Push an entry to a Redis stream
  bool stream_push(StreamType type, const StreamEntry& entry) {
    std::lock_guard lock(mutex_);
    if (!connected_) return false;

    std::string key = "matrix:stream:" + std::string(stream_type_name(type));
    std::string value = entry.to_json().dump();

    // Use XADD to add to stream
    std::ostringstream cmd;
    cmd << "XADD " << key << " MAXLEN ~ " << MAX_REDIS_STREAM_LENGTH
        << " * ";
    if (!entry.room_id.empty()) cmd << "room_id " << entry.room_id << " ";
    if (!entry.user_id.empty()) cmd << "user_id " << entry.user_id << " ";
    if (!entry.event_id.empty()) cmd << "event_id " << entry.event_id << " ";
    cmd << "position " << entry.position << " ";
    cmd << "data " << escape_redis_arg(value);

    return send_redis_command(cmd.str()).find("ERR") == std::string::npos;
  }

  // Read entries from a Redis stream starting from position
  std::vector<StreamEntry> stream_read(StreamType type, int64_t from_position,
                                       int count = MAX_STREAM_BATCH_SIZE) {
    std::lock_guard lock(mutex_);
    std::vector<StreamEntry> results;
    if (!connected_) return results;

    std::string key = "matrix:stream:" + std::string(stream_type_name(type));
    std::ostringstream cmd;
    cmd << "XRANGE " << key << " " << from_position << " + COUNT " << count;

    std::string resp = send_redis_command(cmd.str());
    results = parse_xrange_response(type, resp);
    return results;
  }

  // Get the latest stream position
  int64_t stream_latest_position(StreamType type) {
    std::lock_guard lock(mutex_);
    if (!connected_) return 0;

    std::string key = "matrix:stream:" + std::string(stream_type_name(type));
    std::string resp = send_redis_command("XLEN " + key);
    try {
      size_t colon_pos = resp.find(':');
      if (colon_pos != std::string::npos) {
        return std::stoll(resp.substr(colon_pos + 1));
      }
    } catch (...) {
      return 0;
    }
    return 0;
  }

  // Publish a message on a PUB/SUB channel
  bool publish(const std::string& channel, const std::string& message) {
    std::lock_guard lock(mutex_);
    if (!connected_) return false;

    std::ostringstream cmd;
    cmd << "PUBLISH " << channel << " " << escape_redis_arg(message);
    std::string resp = send_redis_command(cmd.str());
    return resp.find("ERR") == std::string::npos;
  }

  // Subscribe to a PUB/SUB channel (non-blocking registration)
  bool subscribe(const std::string& channel) {
    std::lock_guard lock(mutex_);
    if (!connected_) return false;

    std::ostringstream cmd;
    cmd << "SUBSCRIBE " << channel;
    std::string resp = send_redis_command(cmd.str());
    return resp.find("subscribe") != std::string::npos;
  }

  // Unsubscribe from a PUB/SUB channel
  bool unsubscribe(const std::string& channel) {
    std::lock_guard lock(mutex_);
    if (!connected_) return false;

    std::ostringstream cmd;
    cmd << "UNSUBSCRIBE " << channel;
    std::string resp = send_redis_command(cmd.str());
    return resp.find("unsubscribe") != std::string::npos;
  }

  // Store worker position in sorted set
  bool store_position(std::string_view worker_name, StreamType type,
                      int64_t position) {
    std::lock_guard lock(mutex_);
    if (!connected_) return false;

    std::string key = std::string(REDIS_POSITION_KEY) + ":" +
                      std::string(stream_type_name(type));
    std::ostringstream cmd;
    cmd << "ZADD " << key << " " << position << " " << worker_name;
    std::string resp = send_redis_command(cmd.str());
    return resp.find("ERR") == std::string::npos;
  }

  // Get worker position from sorted set
  int64_t get_position(std::string_view worker_name, StreamType type) {
    std::lock_guard lock(mutex_);
    if (!connected_) return 0;

    std::string key = std::string(REDIS_POSITION_KEY) + ":" +
                      std::string(stream_type_name(type));
    std::ostringstream cmd;
    cmd << "ZSCORE " << key << " " << worker_name;
    std::string resp = send_redis_command(cmd.str());
    try {
      // Parse integer from RESP response
      size_t colon_pos = resp.find(':');
      if (colon_pos != std::string::npos) {
        return std::stoll(resp.substr(colon_pos + 1));
      }
    } catch (...) {
      return 0;
    }
    return 0;
  }

  // Start listening for pub/sub messages in a background thread
  void start_listening(std::function<void(const std::string&, const std::string&)> callback) {
    if (running_) return;
    running_ = true;
    listener_thread_ = std::thread([this, cb = std::move(callback)]() {
      listener_loop(cb);
    });
  }

  // Stop the listener thread
  void stop_listening() {
    running_ = false;
    if (listener_thread_.joinable()) {
      listener_thread_.join();
    }
  }

  // Check if specific stream exists
  bool stream_exists(StreamType type) {
    std::lock_guard lock(mutex_);
    if (!connected_) return false;

    std::string key = "matrix:stream:" + std::string(stream_type_name(type));
    std::string resp = send_redis_command("EXISTS " + key);
    return resp.find(":1") != std::string::npos;
  }

private:
  std::string host_;
  int port_;
  std::string password_;
  socket_t redis_socket_ = SOCKET_INVALID;
  mutable std::mutex mutex_;
  bool connected_;
  std::atomic<bool> running_;
  std::thread listener_thread_;

  // Send a raw Redis command and receive response
  std::string send_redis_command(const std::string& command) {
    std::string cmd = command + "\r\n";
    if (::send(redis_socket_, cmd.c_str(), cmd.size(), 0) < 0) {
      return "-ERR send failed\r\n";
    }

    // Read response (simplified RESP reader)
    char buf[4096];
    int n = recv(redis_socket_, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return "-ERR no response\r\n";
    buf[n] = '\0';
    return std::string(buf, n);
  }

  // Escape a string for Redis arguments
  static std::string escape_redis_arg(const std::string& s) {
    std::ostringstream oss;
    oss << "\"";
    for (char c : s) {
      if (c == '"' || c == '\\') oss << '\\';
      oss << c;
    }
    oss << "\"";
    return oss.str();
  }

  // Parse XRANGE response
  std::vector<StreamEntry> parse_xrange_response(StreamType type,
                                                  const std::string& resp) {
    std::vector<StreamEntry> results;
    if (resp.find("ERR") != std::string::npos) return results;

    // Simplified RESP array parsing
    std::istringstream iss(resp);
    std::string line;
    bool in_array = false;
    StreamEntry current_entry;
    current_entry.type = type;
    std::string current_key;

    while (std::getline(iss, line)) {
      if (line.empty()) continue;
      if (line[0] == '*') {
        in_array = true;
        continue;
      }
      if (line[0] == '$') {
        // Bulk string length indicator, skip
        continue;
      }
      if (line[0] == ':') {
        // Integer
        try {
          int64_t val = std::stoll(line.substr(1));
          if (current_key == "position") {
            current_entry.position = val;
            results.push_back(current_entry);
            current_entry = StreamEntry{};
            current_entry.type = type;
          }
        } catch (...) {}
        continue;
      }
      // Simple string or bulk string content
      if (line[0] == '+' || line[0] == '-') {
        line = line.substr(1);
      }
      if (current_key.empty()) {
        current_key = line;
      } else {
        if (current_key == "room_id") current_entry.room_id = line;
        else if (current_key == "user_id") current_entry.user_id = line;
        else if (current_key == "event_id") current_entry.event_id = line;
        else if (current_key == "data") current_entry.data = line;
        else if (current_key == "position") {
          try {
            current_entry.position = std::stoll(line);
          } catch (...) {
            current_entry.position = 0;
          }
        }
        current_key.clear();
      }
    }
    return results;
  }

  // Background listener loop for pub/sub messages
  void listener_loop(std::function<void(const std::string&, const std::string&)> callback) {
    char buf[8192];
    while (running_) {
      fd_set readfds;
      FD_ZERO(&readfds);
      FD_SET(redis_socket_, &readfds);

      struct timeval tv;
      tv.tv_sec = 1;
      tv.tv_usec = 0;

      int ret = select(redis_socket_ + 1, &readfds, nullptr, nullptr, &tv);
      if (ret > 0 && FD_ISSET(redis_socket_, &readfds)) {
        int n = recv(redis_socket_, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
          buf[n] = '\0';
          std::string msg(buf, n);
          // Parse message type (subscribe, message, etc.)
          size_t type_end = msg.find('\n');
          if (type_end != std::string::npos) {
            std::string type = msg.substr(1, type_end - 1); // Skip '*'
            if (type.find("message") != std::string::npos) {
              // Extract channel and message
              std::istringstream iss(msg);
              std::string line, channel, message;
              int line_count = 0;
              while (std::getline(iss, line)) {
                if (line.empty() || line[0] == '*' || line[0] == '$' || line[0] == ':') continue;
                if (line[0] == '+' || line[0] == '-') line = line.substr(1);
                if (line_count == 2) channel = line;
                else if (line_count == 4) message = line;
                line_count++;
              }
              if (!channel.empty() && callback) {
                callback(channel, message);
              }
            }
          }
        }
      }
    }
  }
};

// ============================================================================
// TCPReplicationBackend: Direct TCP binary protocol
// ============================================================================

class TCPReplicationBackend {
public:
  TCPReplicationBackend() : socket_(SOCKET_INVALID), connected_(false) {}

  ~TCPReplicationBackend() { disconnect(); }

  // Connect to a replication server
  bool connect(const std::string& host, int port) {
    std::lock_guard lock(mutex_);
    if (connected_) return true;

    socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_ == SOCKET_INVALID) return false;

    // Set TCP_NODELAY for low latency
    int flag = 1;
    setsockopt(socket_, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&flag), sizeof(flag));

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&tv), sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) {
      CLOSE_SOCKET(socket_);
      socket_ = SOCKET_INVALID;
      return false;
    }
    std::memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (::connect(socket_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
      CLOSE_SOCKET(socket_);
      socket_ = SOCKET_INVALID;
      return false;
    }

    // Set non-blocking for read loop
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(socket_, FIONBIO, &mode);
#else
    int flags = fcntl(socket_, F_GETFL, 0);
    fcntl(socket_, F_SETFL, flags | O_NONBLOCK);
#endif

    connected_ = true;
    host_ = host;
    port_ = port;
    return true;
  }

  // Disconnect
  void disconnect() {
    std::lock_guard lock(mutex_);
    if (socket_ != SOCKET_INVALID) {
      CLOSE_SOCKET(socket_);
      socket_ = SOCKET_INVALID;
    }
    connected_ = false;
  }

  // Check if connected
  bool is_connected() const {
    std::lock_guard lock(mutex_);
    return connected_;
  }

  // Send a frame over TCP
  bool send_frame(const ReplicationFrame& frame) {
    std::lock_guard lock(mutex_);
    if (!connected_) return false;

    auto data = frame.serialize();
    size_t total = 0;
    while (total < data.size()) {
      int sent = ::send(socket_, reinterpret_cast<const char*>(data.data() + total),
                        static_cast<int>(data.size() - total), 0);
      if (sent <= 0) {
        connected_ = false;
        return false;
      }
      total += static_cast<size_t>(sent);
    }
    return true;
  }

  // Receive a frame (non-blocking)
  std::optional<ReplicationFrame> recv_frame() {
    std::lock_guard lock(mutex_);
    if (!connected_) return std::nullopt;

    // Read into buffer
    uint8_t recv_buf[TCP_BUFFER_SIZE];
    int n = recv(socket_, reinterpret_cast<char*>(recv_buf), sizeof(recv_buf), 0);
    if (n <= 0) {
      if (n < 0) {
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) return std::nullopt;
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) return std::nullopt;
#endif
      }
      connected_ = false;
      return std::nullopt;
    }

    // Append to read buffer
    read_buffer_.insert(read_buffer_.end(), recv_buf, recv_buf + n);

    // Try to parse a complete frame
    size_t consumed = 0;
    auto frame = ReplicationFrame::parse(read_buffer_, consumed);
    if (frame.has_value()) {
      read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + consumed);
      return frame;
    }

    return std::nullopt;
  }

  // Bind and listen for incoming connections
  bool bind_and_listen(int port, int backlog = 128) {
    std::lock_guard lock(mutex_);

    socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_ == SOCKET_INVALID) return false;

    int opt = 1;
    setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(socket_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
      CLOSE_SOCKET(socket_);
      socket_ = SOCKET_INVALID;
      return false;
    }

    if (listen(socket_, backlog) < 0) {
      CLOSE_SOCKET(socket_);
      socket_ = SOCKET_INVALID;
      return false;
    }

    listen_port_ = port;
    return true;
  }

  // Accept an incoming connection
  socket_t accept_connection() {
    std::lock_guard lock(mutex_);
    if (socket_ == SOCKET_INVALID) return SOCKET_INVALID;

    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    return accept(socket_, reinterpret_cast<struct sockaddr*>(&client_addr),
                  &client_len);
  }

  // Get the listening socket (for select/poll)
  socket_t get_socket() const {
    std::lock_guard lock(mutex_);
    return socket_;
  }

  // Send frame on a specific client socket
  static bool send_frame_to(socket_t sock, const ReplicationFrame& frame) {
    auto data = frame.serialize();
    size_t total = 0;
    while (total < data.size()) {
      int sent = ::send(sock, reinterpret_cast<const char*>(data.data() + total),
                        static_cast<int>(data.size() - total), 0);
      if (sent <= 0) return false;
      total += static_cast<size_t>(sent);
    }
    return true;
  }

  // Receive frame from a specific client socket (non-blocking)
  static std::optional<ReplicationFrame> recv_frame_from(socket_t sock,
                                                          std::vector<uint8_t>& read_buf) {
    uint8_t recv_buf[TCP_BUFFER_SIZE];
    int n = recv(sock, reinterpret_cast<char*>(recv_buf), sizeof(recv_buf), 0);
    if (n <= 0) {
      if (n < 0) {
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) return std::nullopt;
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) return std::nullopt;
#endif
      }
      return std::nullopt;
    }

    read_buf.insert(read_buf.end(), recv_buf, recv_buf + n);
    size_t consumed = 0;
    auto frame = ReplicationFrame::parse(read_buf, consumed);
    if (frame.has_value()) {
      read_buf.erase(read_buf.begin(), read_buf.begin() + consumed);
      return frame;
    }
    return std::nullopt;
  }

  // Close a client socket
  static void close_client(socket_t sock) {
    if (sock != SOCKET_INVALID) {
      CLOSE_SOCKET(sock);
    }
  }

  // Reconnect with the stored host/port
  bool reconnect() {
    disconnect();
    return connect(host_, port_);
  }

private:
  socket_t socket_;
  std::string host_;
  int port_ = 0;
  int listen_port_ = 0;
  bool connected_;
  mutable std::mutex mutex_;
  std::vector<uint8_t> read_buffer_;
};

// ============================================================================
// WorkerHealthMonitor: Ping/Pong and timeout detection
// ============================================================================

class WorkerHealthMonitor {
public:
  struct WorkerHealth {
    std::string worker_name;
    std::chrono::steady_clock::time_point last_ping;
    std::chrono::steady_clock::time_point last_pong;
    int64_t ping_id;
    bool awaiting_pong;
    int consecutive_failures;
    bool is_healthy;

    WorkerHealth()
        : last_ping(std::chrono::steady_clock::now()),
          last_pong(std::chrono::steady_clock::now()),
          ping_id(0), awaiting_pong(false),
          consecutive_failures(0), is_healthy(true) {}
  };

  WorkerHealthMonitor() : running_(false) {}

  // Register a worker for health monitoring
  void register_worker(const std::string& name) {
    std::lock_guard lock(mutex_);
    if (workers_.find(name) == workers_.end()) {
      workers_[name] = WorkerHealth{};
      workers_[name].worker_name = name;
    }
  }

  // Unregister a worker
  void unregister_worker(const std::string& name) {
    std::lock_guard lock(mutex_);
    workers_.erase(name);
  }

  // Record that we sent a ping to a worker
  int64_t ping_sent(const std::string& name) {
    std::lock_guard lock(mutex_);
    auto it = workers_.find(name);
    if (it == workers_.end()) return -1;

    it->second.ping_id++;
    it->second.last_ping = std::chrono::steady_clock::now();
    it->second.awaiting_pong = true;
    return it->second.ping_id;
  }

  // Record that we received a pong from a worker
  void pong_received(const std::string& name, int64_t ping_id) {
    std::lock_guard lock(mutex_);
    auto it = workers_.find(name);
    if (it == workers_.end()) return;

    if (it->second.awaiting_pong && it->second.ping_id == ping_id) {
      it->second.awaiting_pong = false;
      it->second.last_pong = std::chrono::steady_clock::now();
      it->second.consecutive_failures = 0;
      it->second.is_healthy = true;
    }
  }

  // Check health of all workers and return unhealthy ones
  std::vector<std::string> check_health() {
    std::lock_guard lock(mutex_);
    std::vector<std::string> unhealthy;
    auto now = std::chrono::steady_clock::now();

    for (auto& [name, health] : workers_) {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          now - health.last_pong).count();

      // Also check pending pings
      if (health.awaiting_pong) {
        auto ping_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - health.last_ping).count();
        if (ping_elapsed > PING_TIMEOUT_MS) {
          health.consecutive_failures++;
          health.awaiting_pong = false;
          health.is_healthy = (health.consecutive_failures < 3);
          if (!health.is_healthy) {
            unhealthy.push_back(name);
          }
        }
      }

      // Check overall timeout
      if (elapsed > WORKER_TIMEOUT_MS && !health.awaiting_pong) {
        health.consecutive_failures++;
        health.is_healthy = false;
        unhealthy.push_back(name);
      }
    }

    return unhealthy;
  }

  // Check if a specific worker is healthy
  bool is_healthy(const std::string& name) {
    std::lock_guard lock(mutex_);
    auto it = workers_.find(name);
    if (it == workers_.end()) return false;
    return it->second.is_healthy;
  }

  // Get time since last pong in milliseconds
  int64_t time_since_last_pong_ms(const std::string& name) {
    std::lock_guard lock(mutex_);
    auto it = workers_.find(name);
    if (it == workers_.end()) return -1;

    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now - it->second.last_pong).count();
  }

  // Get all registered worker names
  std::set<std::string> get_registered_workers() {
    std::lock_guard lock(mutex_);
    std::set<std::string> names;
    for (auto& [name, _] : workers_)
      names.insert(name);
    return names;
  }

  // Start periodic health checker thread
  void start_monitoring(
      std::function<void(const std::string&)> on_worker_unhealthy,
      std::function<void(const std::string&)> on_worker_recovered) {
    if (running_) return;
    running_ = true;
    monitor_thread_ = std::thread([this, on_unhealthy = std::move(on_worker_unhealthy),
                                    on_recovered = std::move(on_worker_recovered)]() {
      health_check_loop(on_unhealthy, on_recovered);
    });
  }

  // Stop the monitoring thread
  void stop_monitoring() {
    running_ = false;
    if (monitor_thread_.joinable()) {
      monitor_thread_.join();
    }
  }

private:
  std::unordered_map<std::string, WorkerHealth> workers_;
  mutable std::mutex mutex_;
  std::atomic<bool> running_;
  std::thread monitor_thread_;

  void health_check_loop(
      std::function<void(const std::string&)> on_unhealthy,
      std::function<void(const std::string&)> on_recovered) {
    std::set<std::string> previously_unhealthy;

    while (running_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(PING_INTERVAL_MS));

      auto unhealthy = check_health();
      std::set<std::string> current_unhealthy(unhealthy.begin(), unhealthy.end());

      // Notify newly unhealthy workers
      for (auto& name : current_unhealthy) {
        if (previously_unhealthy.find(name) == previously_unhealthy.end()) {
          if (on_unhealthy) on_unhealthy(name);
        }
      }

      // Notify recovered workers
      for (auto& name : previously_unhealthy) {
        if (current_unhealthy.find(name) == current_unhealthy.end()) {
          if (on_recovered) on_recovered(name);
        }
      }

      previously_unhealthy = current_unhealthy;
    }
  }
};

// ============================================================================
// WorkerLoadBalancer: Distribute load across multiple workers of same type
// ============================================================================

class WorkerLoadBalancer {
public:
  WorkerLoadBalancer() = default;

  // Register a worker with its type
  void register_worker(const std::string& name, WorkerType type) {
    std::lock_guard lock(mutex_);
    workers_by_type_[type].push_back(WorkerLoad{name, 0});
  }

  // Unregister a worker
  void unregister_worker(const std::string& name) {
    std::lock_guard lock(mutex_);
    for (auto& [type, workers] : workers_by_type_) {
      workers.erase(
          std::remove_if(workers.begin(), workers.end(),
                         [&name](const WorkerLoad& wl) { return wl.name == name; }),
          workers.end());
    }
  }

  // Get the least loaded worker for a given type (round-robin with load tracking)
  std::optional<std::string> get_worker(WorkerType type) {
    std::lock_guard lock(mutex_);
    auto it = workers_by_type_.find(type);
    if (it == workers_by_type_.end() || it->second.empty())
      return std::nullopt;

    // Find worker with minimum load
    auto min_it = std::min_element(it->second.begin(), it->second.end(),
                                    [](const WorkerLoad& a, const WorkerLoad& b) {
                                      return a.current_load < b.current_load;
                                    });
    min_it->current_load++;
    return min_it->name;
  }

  // Release load from a worker
  void release_worker(const std::string& name) {
    std::lock_guard lock(mutex_);
    for (auto& [type, workers] : workers_by_type_) {
      for (auto& wl : workers) {
        if (wl.name == name && wl.current_load > 0) {
          wl.current_load--;
          return;
        }
      }
    }
  }

  // Get count of workers by type
  int worker_count(WorkerType type) {
    std::lock_guard lock(mutex_);
    auto it = workers_by_type_.find(type);
    if (it == workers_by_type_.end()) return 0;
    return static_cast<int>(it->second.size());
  }

  // Get all workers of a type
  std::vector<std::string> get_workers(WorkerType type) {
    std::lock_guard lock(mutex_);
    std::vector<std::string> names;
    auto it = workers_by_type_.find(type);
    if (it != workers_by_type_.end()) {
      for (auto& wl : it->second)
        names.push_back(wl.name);
    }
    return names;
  }

  // Get load statistics
  nlohmann::json get_stats() {
    std::lock_guard lock(mutex_);
    nlohmann::json stats = nlohmann::json::object();
    for (auto& [type, workers] : workers_by_type_) {
      nlohmann::json type_stats = nlohmann::json::object();
      for (auto& wl : workers) {
        type_stats[wl.name] = wl.current_load;
      }
      stats[worker_type_name(type)] = type_stats;
    }
    return stats;
  }

  // Reset all loads
  void reset_loads() {
    std::lock_guard lock(mutex_);
    for (auto& [type, workers] : workers_by_type_) {
      for (auto& wl : workers) {
        wl.current_load = 0;
      }
    }
  }

private:
  struct WorkerLoad {
    std::string name;
    int current_load;
  };

  std::map<WorkerType, std::vector<WorkerLoad>> workers_by_type_;
  mutable std::mutex mutex_;
};

// ============================================================================
// StreamManager: Manages streams, positions, and filtering
// ============================================================================

class StreamManager {
public:
  StreamManager() {
    // Initialize all streams
    for (int i = 0; i < static_cast<int>(StreamType::COUNT); i++) {
      auto type = static_cast<StreamType>(i);
      streams_[type] = ReplicationStream(type);
    }
  }

  // Get current position for a stream
  int64_t get_position(StreamType type) {
    auto it = streams_.find(type);
    return it != streams_.end() ? it->second.current_position() : 0;
  }

  // Advance stream position
  void advance_stream(StreamType type, int64_t new_position) {
    auto it = streams_.find(type);
    if (it != streams_.end()) {
      it->second.advance(new_position);
    }
  }

  // Check if stream has changed since given token
  bool has_changed_since(StreamType type, int64_t token) {
    auto it = streams_.find(type);
    return it != streams_.end() ? it->second.has_changed_since(token) : false;
  }

  // Store position for a worker
  void store_worker_position(const std::string& worker, StreamType type,
                              int64_t position) {
    position_store_.update_position(worker, type, position);
  }

  // Get worker position for a specific stream
  int64_t get_worker_position(const std::string& worker, StreamType type) {
    return position_store_.get_position(worker, type);
  }

  // Get all positions for a worker
  std::map<StreamType, int64_t> get_worker_positions(const std::string& worker) {
    return position_store_.get_all_positions(worker);
  }

  // Determine which streams have data since worker's last position
  std::vector<StreamEntry> get_pending_entries(const std::string& worker,
                                                const std::set<StreamType>& subscribed) {
    std::vector<StreamEntry> entries;
    auto positions = get_worker_positions(worker);

    for (auto type : subscribed) {
      int64_t worker_pos = 0;
      auto pit = positions.find(type);
      if (pit != positions.end()) worker_pos = pit->second;

      int64_t current = get_position(type);
      if (current > worker_pos) {
        // There's pending data
        StreamEntry entry;
        entry.type = type;
        entry.position = current;
        entry.data = "{\"pending\":true,\"from\":" +
                     std::to_string(worker_pos) + ",\"to\":" +
                     std::to_string(current) + "}";
        entry.timestamp = std::chrono::steady_clock::now();
        entries.push_back(entry);
      }
    }
    return entries;
  }

  // Advance worker position
  void acknowledge_worker_position(const std::string& worker, StreamType type,
                                    int64_t position) {
    store_worker_position(worker, type, position);
  }

  // Filter streams allowed for a worker
  std::set<StreamType> filter_streams(const std::set<StreamType>& requested,
                                       const std::set<StreamType>& allowed) {
    std::set<StreamType> filtered;
    for (auto st : requested) {
      if (allowed.find(st) != allowed.end()) {
        filtered.insert(st);
      }
    }
    return filtered;
  }

  // Get all streams
  std::map<StreamType, ReplicationStream>& get_streams() {
    return streams_;
  }

  // Reset all streams
  void reset_all() {
    for (auto& [type, stream] : streams_) {
      stream.advance(0);
    }
    position_store_.clear();
  }

  // Get stream snapshot for crash recovery
  nlohmann::json snapshot() {
    nlohmann::json j = nlohmann::json::object();
    for (auto& [type, stream] : streams_) {
      j[stream_type_name(type)] = stream.current_position();
    }
    return j;
  }

  // Restore from snapshot
  void restore(const nlohmann::json& j) {
    for (auto& [key, value] : j.items()) {
      try {
        auto type = stream_type_from_name(key);
        advance_stream(type, value.get<int64_t>());
      } catch (...) {
        // Unknown stream type, skip
      }
    }
  }

private:
  std::map<StreamType, ReplicationStream> streams_;
  StreamPositionStore position_store_;
};

// ============================================================================
// WorkerConfigManager: Configuration management
// ============================================================================

class WorkerConfigManager {
public:
  WorkerConfigManager() = default;

  // Set configuration for a worker
  void set_config(const std::string& worker_name, const WorkerConfig& config) {
    std::lock_guard lock(mutex_);
    configs_[worker_name] = config;
  }

  // Get configuration for a worker
  WorkerConfig get_config(const std::string& worker_name) {
    std::lock_guard lock(mutex_);
    auto it = configs_.find(worker_name);
    if (it != configs_.end()) return it->second;

    WorkerConfig def;
    def.worker_name = worker_name;
    return def;
  }

  // Load configurations from JSON
  void load_from_json(const nlohmann::json& j) {
    std::lock_guard lock(mutex_);
    if (!j.is_array()) return;

    for (auto& item : j) {
      WorkerConfig cfg;
      if (item.contains("worker_name"))
        cfg.worker_name = item["worker_name"].get<std::string>();
      if (item.contains("worker_type"))
        cfg.type = worker_type_from_name(item["worker_type"].get<std::string>());
      if (item.contains("replication_host"))
        cfg.worker_replication_host = item["replication_host"].get<std::string>();
      if (item.contains("replication_port"))
        cfg.worker_replication_port = item["replication_port"].get<int>();
      if (item.contains("run_background_tasks"))
        cfg.run_background_tasks = item["run_background_tasks"].get<bool>();

      if (item.contains("streams") && item["streams"].is_array()) {
        for (auto& stream_name : item["streams"]) {
          try {
            auto st = stream_type_from_name(stream_name.get<std::string>());
            cfg.streams_to_replicate.insert(st);
          } catch (...) {}
        }
      } else {
        cfg.streams_to_replicate = default_streams_for_worker(cfg.type);
      }

      configs_[cfg.worker_name] = cfg;
    }
  }

  // Export configurations to JSON
  nlohmann::json export_to_json() {
    std::lock_guard lock(mutex_);
    nlohmann::json arr = nlohmann::json::array();
    for (auto& [name, cfg] : configs_) {
      nlohmann::json item;
      item["worker_name"] = name;
      item["worker_type"] = worker_type_name(cfg.type);
      item["replication_host"] = cfg.worker_replication_host;
      item["replication_port"] = cfg.worker_replication_port;
      item["run_background_tasks"] = cfg.run_background_tasks;

      nlohmann::json streams_arr = nlohmann::json::array();
      for (auto st : cfg.streams_to_replicate) {
        streams_arr.push_back(stream_type_name(st));
      }
      item["streams"] = streams_arr;
      arr.push_back(item);
    }
    return arr;
  }

  // Get all worker names
  std::set<std::string> get_all_worker_names() {
    std::lock_guard lock(mutex_);
    std::set<std::string> names;
    for (auto& [name, _] : configs_)
      names.insert(name);
    return names;
  }

  // Remove worker config
  void remove_config(const std::string& worker_name) {
    std::lock_guard lock(mutex_);
    configs_.erase(worker_name);
  }

  // Check if worker exists
  bool has_worker(const std::string& worker_name) {
    std::lock_guard lock(mutex_);
    return configs_.find(worker_name) != configs_.end();
  }

  // Update specific field
  void update_field(const std::string& worker_name,
                    const std::string& field,
                    const nlohmann::json& value) {
    std::lock_guard lock(mutex_);
    auto it = configs_.find(worker_name);
    if (it == configs_.end()) return;

    if (field == "replication_host")
      it->second.worker_replication_host = value.get<std::string>();
    else if (field == "replication_port")
      it->second.worker_replication_port = value.get<int>();
    else if (field == "run_background_tasks")
      it->second.run_background_tasks = value.get<bool>();
  }

private:
  std::map<std::string, WorkerConfig> configs_;
  mutable std::mutex mutex_;
};

// ============================================================================
// GenericWorker: Serves all client-facing endpoints, no background tasks
// ============================================================================

class GenericWorker {
public:
  explicit GenericWorker(const WorkerConfig& config)
      : config_(config), running_(false) {
    config_.type = WorkerType::Generic;
    config_.run_background_tasks = false;
    if (config_.streams_to_replicate.empty())
      config_.streams_to_replicate = default_streams_for_worker(WorkerType::Generic);
  }

  // Start the worker
  void start() {
    if (running_) return;
    running_ = true;
    worker_thread_ = std::thread([this]() { worker_loop(); });
  }

  // Stop the worker
  void stop() {
    running_ = false;
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }

  bool is_running() const { return running_; }

  const WorkerConfig& get_config() const { return config_; }

  // Get endpoints this worker should serve
  std::set<std::string> get_endpoints() const {
    return {
      "/_matrix/client/r0/login",
      "/_matrix/client/r0/register",
      "/_matrix/client/r0/account/password",
      "/_matrix/client/r0/account/deactivate",
      "/_matrix/client/r0/account/3pid",
      "/_matrix/client/r0/account/whoami",
      "/_matrix/client/r0/capabilities",
      "/_matrix/client/r0/createRoom",
      "/_matrix/client/r0/join",
      "/_matrix/client/r0/rooms",
      "/_matrix/client/r0/sync",
      "/_matrix/client/r0/keys",
      "/_matrix/client/r0/search",
      "/_matrix/client/r0/profile",
      "/_matrix/client/r0/directory",
      "/_matrix/client/r0/publicRooms",
      "/_matrix/client/r0/joined_rooms",
      "/_matrix/client/r0/user_directory",
      "/_矩阵/client/r0/thirdparty",
      "/_matrix/client/r0/presence",
      "/_matrix/client/r0/pushrules",
      "/_matrix/client/r0/notifications",
      "/_matrix/client/r0/tags",
      "/_matrix/client/r0/account_data",
      "/_matrix/client/r0/admin",
      "/_matrix/client/r0/voip",
      "/_matrix/media/r0",
      "/_matrix/client/r0/sendToDevice",
      "/_matrix/client/r0/devices",
      "/_matrix/client/r0/logout",
      "/_matrix/client/r0/joined_groups",
      "/_matrix/client/r0/rooms/{roomId}/event/{eventId}",
      "/_matrix/client/r0/rooms/{roomId}/state",
      "/_matrix/client/r0/rooms/{roomId}/members",
      "/_matrix/client/r0/rooms/{roomId}/messages",
      "/_matrix/client/r0/rooms/{roomId}/context",
      "/_matrix/client/r0/rooms/{roomId}/typing",
      "/_matrix/client/r0/rooms/{roomId}/receipt",
      "/_matrix/client/r0/rooms/{roomId}/read_markers",
      "/_matrix/client/r0/rooms/{roomId}/report",
      "/_matrix/client/r0/rooms/{roomId}/invite",
      "/_matrix/client/r0/rooms/{roomId}/leave",
      "/_matrix/client/r0/rooms/{roomId}/forget",
      "/_matrix/client/r0/rooms/{roomId}/kick",
      "/_matrix/client/r0/rooms/{roomId}/ban",
      "/_matrix/client/r0/rooms/{roomId}/unban",
      "/_matrix/client/r0/rooms/{roomId}/redact",
      "/_matrix/client/r0/rooms/{roomId}/upgrade",
      "/_matrix/client/r0/rooms/{roomId}/relations",
      "/_matrix/client/r0/rooms/{roomId}/threads",
      "/_matrix/client/r0/rooms/{roomId}/timestamp_to_event",
      "/_matrix/client/r0/user/{userId}/openid",
      "/_matrix/client/r0/user/{userId}/account_data",
      "/_matrix/client/r0/user/{userId}/rooms/{roomId}/account_data",
      "/_matrix/client/r0/user/{userId}/rooms/{roomId}/tags",
      "/_matrix/client/r0/user/{userId}/filter"
    };
  }

  // Handle a client request (returns JSON response)
  nlohmann::json handle_request(const std::string& method,
                                 const std::string& path,
                                 const nlohmann::json& body,
                                 const std::map<std::string, std::string>& headers,
                                 std::string& out_status) {
    nlohmann::json response;
    out_status = "200 OK";

    // Minimal routing - actual implementation delegates to handler modules
    if (path.find("/_matrix/client/r0/login") != std::string::npos) {
      response["flows"] = nlohmann::json::array();
      nlohmann::json password_flow;
      password_flow["type"] = "m.login.password";
      response["flows"].push_back(password_flow);
    } else if (path.find("/_matrix/client/r0/capabilities") != std::string::npos) {
      response["capabilities"] = nlohmann::json::object();
      response["capabilities"]["m.room_versions"] = nlohmann::json::object();
      response["capabilities"]["m.room_versions"]["default"] = "10";
      response["capabilities"]["m.room_versions"]["available"] =
          nlohmann::json::object();
      response["capabilities"]["m.change_password"] = nlohmann::json::object();
      response["capabilities"]["m.change_password"]["enabled"] = true;
    } else if (path.find("/_matrix/client/r0/sync") != std::string::npos) {
      response["next_batch"] = "s0_0_0_0_0_0_0_0_0_0";
      response["rooms"] = nlohmann::json::object();
      response["rooms"]["join"] = nlohmann::json::object();
      response["rooms"]["invite"] = nlohmann::json::object();
      response["rooms"]["leave"] = nlohmann::json::object();
      response["presence"] = nlohmann::json::object();
      response["presence"]["events"] = nlohmann::json::array();
      response["account_data"] = nlohmann::json::object();
      response["account_data"]["events"] = nlohmann::json::array();
      response["to_device"] = nlohmann::json::object();
      response["to_device"]["events"] = nlohmann::json::array();
      response["device_lists"] = nlohmann::json::object();
      response["device_lists"]["changed"] = nlohmann::json::array();
      response["device_lists"]["left"] = nlohmann::json::array();
      response["device_one_time_keys_count"] = nlohmann::json::object();
    } else if (path.find("/_matrix/client/r0/keys/upload") != std::string::npos) {
      response["one_time_key_counts"] = nlohmann::json::object();
      response["one_time_key_counts"]["signed_curve25519"] = 50;
      response["one_time_key_counts"]["curve25519"] = 0;
    } else {
      out_status = "404 Not Found";
      response["errcode"] = "M_UNRECOGNIZED";
      response["error"] = "Unrecognized request";
    }

    return response;
  }

private:
  WorkerConfig config_;
  std::atomic<bool> running_;
  std::thread worker_thread_;

  void worker_loop() {
    auto start_time = std::chrono::steady_clock::now();

    while (running_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

      // Periodic health reporting
      auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::steady_clock::now() - start_time).count();
      if (elapsed > 0 && elapsed % 30 == 0) {
        // Log health status periodically
        (void)elapsed; // Use in production logging
      }
    }
  }
};

// ============================================================================
// PusherWorker: Processes push notifications separately
// ============================================================================

class PusherWorker {
public:
  explicit PusherWorker(const WorkerConfig& config)
      : config_(config), running_(false) {
    config_.type = WorkerType::Pusher;
    if (config_.streams_to_replicate.empty())
      config_.streams_to_replicate = default_streams_for_worker(WorkerType::Pusher);
    next_push_id_ = 0;
    pending_notifications_.clear();
  }

  void start() {
    if (running_) return;
    running_ = true;
    worker_thread_ = std::thread([this]() { worker_loop(); });
  }

  void stop() {
    running_ = false;
    if (worker_thread_.joinable())
      worker_thread_.join();
  }

  bool is_running() const { return running_; }

  // Process an incoming stream entry for push
  void on_stream_entry(const StreamEntry& entry) {
    if (entry.type == StreamType::Events ||
        entry.type == StreamType::Receipts) {
      // Queue push notification
      PushNotification notif;
      notif.id = next_push_id_++;
      notif.room_id = entry.room_id;
      notif.event_id = entry.event_id;
      notif.stream_type = entry.type;
      notif.data = entry.data;
      notif.timestamp = entry.timestamp;

      std::lock_guard lock(push_mutex_);
      pending_notifications_.push_back(std::move(notif));
    }
  }

  // Get the number of pending notifications
  int pending_count() {
    std::lock_guard lock(push_mutex_);
    return static_cast<int>(pending_notifications_.size());
  }

  // Get push configuration
  nlohmann::json get_push_rules(const std::string& user_id) {
    nlohmann::json rules;
    rules["global"] = nlohmann::json::object();
    rules["global"]["override"] = nlohmann::json::array();
    rules["global"]["content"] = nlohmann::json::array();
    rules["global"]["room"] = nlohmann::json::array();
    rules["global"]["sender"] = nlohmann::json::array();
    rules["global"]["underride"] = nlohmann::json::array();

    // Default push rules
    nlohmann::json rule;
    rule["rule_id"] = ".m.rule.contains_display_name";
    rule["default"] = true;
    rule["enabled"] = true;
    rule["actions"] = nlohmann::json::array({"notify", nlohmann::json::object(
        {{"set_tweak", "sound"}, {"value", "default"}})});
    rule["conditions"] = nlohmann::json::array();
    nlohmann::json condition;
    condition["kind"] = "contains_display_name";
    rule["conditions"].push_back(condition);
    rules["global"]["override"].push_back(rule);

    nlohmann::json rule2;
    rule2["rule_id"] = ".m.rule.master";
    rule2["default"] = true;
    rule2["enabled"] = false;
    rule2["actions"] = nlohmann::json::array({"dont_notify"});
    rules["global"]["override"].push_back(rule2);

    (void)user_id; // In production, load custom rules per user
    return rules;
  }

  // Send push notification via gateway
  bool send_push(const PushNotification& notif, const std::string& push_gateway,
                 const std::string& push_key) {
    // Build push payload
    nlohmann::json payload;
    payload["notification"] = nlohmann::json::object();
    payload["notification"]["id"] = notif.id;
    payload["notification"]["room_id"] = notif.room_id;
    payload["notification"]["event_id"] = notif.event_id;
    payload["notification"]["counts"] = nlohmann::json::object();
    payload["notification"]["counts"]["unread"] = pending_count();
    payload["notification"]["devices"] = nlohmann::json::array();

    nlohmann::json device;
    device["app_id"] = "matrix";
    device["pushkey"] = push_key;
    device["pushkey_ts"] = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    device["data"] = nlohmann::json::object();
    payload["notification"]["devices"].push_back(device);

    (void)push_gateway;

    // Actual HTTP push would be sent here
    return true;
  }

private:
  struct PushNotification {
    int64_t id;
    std::string room_id;
    std::string event_id;
    StreamType stream_type;
    std::string data;
    std::chrono::steady_clock::time_point timestamp;
  };

  WorkerConfig config_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
  std::atomic<int64_t> next_push_id_;
  std::deque<PushNotification> pending_notifications_;
  mutable std::mutex push_mutex_;

  void worker_loop() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));

      std::deque<PushNotification> batch;
      {
        std::lock_guard lock(push_mutex_);
        if (!pending_notifications_.empty()) {
          int batch_size = std::min(static_cast<int>(pending_notifications_.size()),
                                     MAX_STREAM_BATCH_SIZE);
          batch.assign(pending_notifications_.begin(),
                       pending_notifications_.begin() + batch_size);
          pending_notifications_.erase(pending_notifications_.begin(),
                                       pending_notifications_.begin() + batch_size);
        }
      }

      // Process batch
      for (auto& notif : batch) {
        process_notification(notif);
      }

      // If no batch, slow down
      if (batch.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
      }
    }
  }

  void process_notification(const PushNotification& notif) {
    // Parse event data
    nlohmann::json event_data;
    try {
      if (!notif.data.empty()) {
        event_data = nlohmann::json::parse(notif.data);
      }
    } catch (...) {
      // Invalid JSON, skip silently
      return;
    }

    // Check for push rules matching here
    // Production code would query push rules, evaluate conditions,
    // and send push via appropriate gateway
    (void)event_data;
  }
};

// ============================================================================
// FederationSenderWorker: Processes outgoing federation
// ============================================================================

class FederationSenderWorker {
public:
  explicit FederationSenderWorker(const WorkerConfig& config)
      : config_(config), running_(false) {
    config_.type = WorkerType::FederationSender;
    if (config_.streams_to_replicate.empty())
      config_.streams_to_replicate = default_streams_for_worker(
          WorkerType::FederationSender);
    next_txn_id_ = 0;
  }

  void start() {
    if (running_) return;
    running_ = true;
    worker_thread_ = std::thread([this]() { worker_loop(); });
  }

  void stop() {
    running_ = false;
    if (worker_thread_.joinable())
      worker_thread_.join();
  }

  bool is_running() const { return running_; }

  // Process a stream entry for federation
  void on_stream_entry(const StreamEntry& entry) {
    if (entry.type == StreamType::Events ||
        entry.type == StreamType::Backfill ||
        entry.type == StreamType::Presence ||
        entry.type == StreamType::Typing) {
      FederationTask task;
      task.id = next_txn_id_++;
      task.stream_type = entry.type;
      task.room_id = entry.room_id;
      task.event_id = entry.event_id;
      task.data = entry.data;
      task.timestamp = entry.timestamp;
      task.retry_count = 0;
      task.next_retry = std::chrono::steady_clock::now();

      std::lock_guard lock(fed_mutex_);
      pending_tasks_.push_back(std::move(task));
    }
  }

  // Queue a federation transaction
  void queue_federation_transaction(const std::string& destination,
                                     const std::string& event_json,
                                     const std::string& txn_id = "") {
    FederationTask task;
    task.id = next_txn_id_++;
    task.destination = destination;
    task.data = event_json;
    task.txn_id = txn_id.empty() ? generate_txn_id() : txn_id;
    task.timestamp = std::chrono::steady_clock::now();
    task.retry_count = 0;
    task.next_retry = std::chrono::steady_clock::now();

    std::lock_guard lock(fed_mutex_);
    pending_tasks_.push_back(std::move(task));
  }

  // Get number of pending federation tasks
  int pending_count() {
    std::lock_guard lock(fed_mutex_);
    return static_cast<int>(pending_tasks_.size());
  }

  // Get destinations with pending transactions
  std::set<std::string> get_pending_destinations() {
    std::lock_guard lock(fed_mutex_);
    std::set<std::string> dests;
    for (auto& task : pending_tasks_) {
      if (!task.destination.empty())
        dests.insert(task.destination);
    }
    return dests;
  }

  // Process a federation transaction (PDU format)
  nlohmann::json build_pdu(const std::string& event_json) {
    nlohmann::json pdu;
    try {
      auto event = nlohmann::json::parse(event_json);
      pdu["pdus"] = nlohmann::json::array({event});
      pdu["origin"] = config_.worker_name;
      pdu["origin_server_ts"] = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();
    } catch (...) {
      pdu["pdus"] = nlohmann::json::array();
      pdu["error"] = "Invalid event JSON";
    }
    return pdu;
  }

  // Build EDU (Ephemeral Data Unit) for presence/typing
  nlohmann::json build_edu(const std::string& event_json) {
    nlohmann::json edu;
    edu["edus"] = nlohmann::json::array();
    try {
      auto event = nlohmann::json::parse(event_json);
      edu["edus"].push_back(event);
    } catch (...) {}
    return edu;
  }

private:
  struct FederationTask {
    int64_t id;
    std::string destination;
    std::string room_id;
    std::string event_id;
    std::string data;
    std::string txn_id;
    StreamType stream_type = StreamType::Events;
    std::chrono::steady_clock::time_point timestamp;
    int retry_count;
    std::chrono::steady_clock::time_point next_retry;
  };

  WorkerConfig config_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
  std::atomic<int64_t> next_txn_id_;
  std::deque<FederationTask> pending_tasks_;
  std::deque<FederationTask> retry_queue_;
  mutable std::mutex fed_mutex_;

  // Per-destination transaction maps: dest -> (room_id -> list of events)
  std::map<std::string, std::map<std::string, std::vector<std::string>>> dest_rooms_;
  mutable std::mutex dest_mutex_;

  std::string generate_txn_id() {
    static std::atomic<int64_t> counter{0};
    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    return std::to_string(ts) + "-" + std::to_string(counter++);
  }

  void worker_loop() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

      std::deque<FederationTask> ready_tasks;
      auto now = std::chrono::steady_clock::now();

      {
        std::lock_guard lock(fed_mutex_);

        // Build per-destination batches from pending tasks
        for (auto it = pending_tasks_.begin(); it != pending_tasks_.end();) {
          if (it->next_retry <= now) {
            ready_tasks.push_back(*it);
            it = pending_tasks_.erase(it);
          } else {
            ++it;
          }
        }
      }

      // Process ready tasks
      for (auto& task : ready_tasks) {
        bool success = send_to_destination(task);
        if (!success && task.retry_count < 5) {
          task.retry_count++;
          // Exponential backoff: 1s, 2s, 4s, 8s, 16s
          int delay_ms = 1000 * (1 << task.retry_count);
          task.next_retry = now + std::chrono::milliseconds(delay_ms);

          std::lock_guard lock(fed_mutex_);
          retry_queue_.push_back(task);
        }
      }

      // Process retry queue
      {
        std::lock_guard lock(fed_mutex_);
        for (auto it = retry_queue_.begin(); it != retry_queue_.end();) {
          if (it->next_retry <= now) {
            pending_tasks_.push_back(*it);
            it = retry_queue_.erase(it);
          } else {
            ++it;
          }
        }
      }
    }
  }

  bool send_to_destination(FederationTask& task) {
    // In production, send via HTTP POST to the destination's federation endpoint
    // For now, simulate success
    if (task.data.empty()) return false;

    // Determine destination from event data if not set
    if (task.destination.empty()) {
      try {
        auto event = nlohmann::json::parse(task.data);
        // Extract destination from event if available
        if (event.contains("sender")) {
          auto sender = event["sender"].get<std::string>();
          auto pos = sender.find(':');
          if (pos != std::string::npos) {
            task.destination = sender.substr(pos + 1);
          }
        }
      } catch (...) {
        return false;
      }
    }

    if (task.destination.empty()) return false;

    // Build the transaction payload
    nlohmann::json txn;
    txn["origin"] = config_.worker_name;
    txn["origin_server_ts"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (task.stream_type == StreamType::Presence ||
        task.stream_type == StreamType::Typing ||
        task.stream_type == StreamType::Receipts) {
      // Send as EDU
      txn["edus"] = nlohmann::json::array();
      try {
        auto event = nlohmann::json::parse(task.data);
        txn["edus"].push_back(event);
      } catch (...) {
        txn["edus"].push_back(nlohmann::json::object());
      }
    } else {
      // Send as PDU
      txn["pdus"] = nlohmann::json::array();
      try {
        auto event = nlohmann::json::parse(task.data);
        txn["pdus"].push_back(event);
      } catch (...) {
        return false;
      }
    }

    // Simulate sending - in production, make HTTP PUT to:
    // https://{destination}/_matrix/federation/v1/send/{txnId}
    (void)txn;
    return true;
  }
};

// ============================================================================
// MediaRepositoryWorker: Handle media uploads/downloads
// ============================================================================

class MediaRepositoryWorker {
public:
  explicit MediaRepositoryWorker(const WorkerConfig& config)
      : config_(config), running_(false) {
    config_.type = WorkerType::MediaRepository;
    if (config_.streams_to_replicate.empty())
      config_.streams_to_replicate = default_streams_for_worker(
          WorkerType::MediaRepository);
    total_uploaded_ = 0;
    total_downloaded_ = 0;
  }

  void start() {
    if (running_) return;
    running_ = true;
    worker_thread_ = std::thread([this]() { worker_loop(); });
  }

  void stop() {
    running_ = false;
    if (worker_thread_.joinable())
      worker_thread_.join();
  }

  bool is_running() const { return running_; }

  // Handle media upload
  nlohmann::json handle_upload(const std::string& filename,
                                 const std::string& content_type,
                                 const std::vector<uint8_t>& data,
                                 const std::string& user_id) {
    // Generate media ID
    std::string media_id = generate_media_id();
    std::string content_uri = "mxc://" + config_.worker_name + "/" + media_id;

    // Store media (in production, write to disk or object storage)
    MediaInfo info;
    info.media_id = media_id;
    info.filename = filename;
    info.content_type = content_type;
    info.size_bytes = data.size();
    info.uploader = user_id;
    info.upload_ts = std::chrono::system_clock::now();
    info.content_uri = content_uri;

    {
      std::lock_guard lock(media_mutex_);
      media_store_[media_id] = info;
      total_uploaded_ += data.size();
    }

    // Return content URI
    nlohmann::json response;
    response["content_uri"] = content_uri;
    return response;
  }

  // Handle media download
  std::optional<MediaInfo> handle_download(const std::string& media_id) {
    std::lock_guard lock(media_mutex_);
    auto it = media_store_.find(media_id);
    if (it == media_store_.end()) return std::nullopt;
    total_downloaded_ += it->second.size_bytes;
    return it->second;
  }

  // Get thumbnail
  nlohmann::json create_thumbnail(const std::string& media_id,
                                    int width, int height,
                                    const std::string& method) {
    nlohmann::json result;
    result["media_id"] = media_id;
    result["thumbnail_info"] = nlohmann::json::object();
    result["thumbnail_info"]["w"] = width;
    result["thumbnail_info"]["h"] = height;
    result["thumbnail_info"]["method"] = method;
    result["thumbnail_info"]["mimetype"] = "image/jpeg";
    result["thumbnail_info"]["size"] = 1024;
    // In production, actually resize the image
    return result;
  }

  // Get media configuration
  nlohmann::json get_config() {
    nlohmann::json cfg;
    cfg["m.upload.size"] = 104857600; // 100MB
    cfg["m.upload.allow"] = nlohmann::json::array({
        "image/jpeg", "image/png", "image/gif", "image/webp",
        "video/mp4", "video/webm",
        "audio/mp3", "audio/ogg", "audio/wav",
        "application/pdf", "text/plain"
    });
    return cfg;
  }

  // Get storage statistics
  nlohmann::json get_stats() {
    std::lock_guard lock(media_mutex_);
    nlohmann::json stats;
    stats["total_files"] = media_store_.size();
    stats["total_uploaded_bytes"] = total_uploaded_.load();
    stats["total_downloaded_bytes"] = total_downloaded_.load();
    return stats;
  }

  // Evict old media based on LRU
  int evict_old_media(size_t max_files) {
    std::lock_guard lock(media_mutex_);
    int removed = 0;
    while (media_store_.size() > max_files) {
      // Find oldest entry
      auto oldest = media_store_.begin();
      for (auto it = media_store_.begin(); it != media_store_.end(); ++it) {
        if (it->second.upload_ts < oldest->second.upload_ts)
          oldest = it;
      }
      media_store_.erase(oldest);
      removed++;
    }
    return removed;
  }

private:
  struct MediaInfo {
    std::string media_id;
    std::string filename;
    std::string content_type;
    size_t size_bytes = 0;
    std::string uploader;
    std::chrono::system_clock::time_point upload_ts;
    std::chrono::system_clock::time_point last_access;
    std::string content_uri;
  };

  WorkerConfig config_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
  std::map<std::string, MediaInfo> media_store_;
  mutable std::mutex media_mutex_;
  std::atomic<size_t> total_uploaded_;
  std::atomic<size_t> total_downloaded_;

  std::string generate_media_id() {
    static std::atomic<int64_t> counter{0};
    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t ts = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
    return std::to_string(ts) + "-" + std::to_string(counter++) +
           "-" + config_.worker_name;
  }

  void worker_loop() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::seconds(60));

      // Periodic cleanup
      std::lock_guard lock(media_mutex_);
      auto now = std::chrono::system_clock::now();
      auto one_day = std::chrono::hours(24);

      // Purge expired temporary uploads (unclaimed after 24h)
      for (auto it = media_store_.begin(); it != media_store_.end();) {
        if (it->second.uploader.empty() &&
            (now - it->second.upload_ts) > one_day) {
          it = media_store_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }
};

// ============================================================================
// AppserviceWorker: Handle appservice transactions
// ============================================================================

class AppserviceWorker {
public:
  explicit AppserviceWorker(const WorkerConfig& config)
      : config_(config), running_(false) {
    config_.type = WorkerType::Appservice;
    if (config_.streams_to_replicate.empty())
      config_.streams_to_replicate = default_streams_for_worker(
          WorkerType::Appservice);
    next_txn_id_ = 0;
  }

  void start() {
    if (running_) return;
    running_ = true;
    worker_thread_ = std::thread([this]() { worker_loop(); });
  }

  void stop() {
    running_ = false;
    if (worker_thread_.joinable())
      worker_thread_.join();
  }

  bool is_running() const { return running_; }

  // Register an application service
  bool register_appservice(const std::string& as_token,
                             const std::string& url,
                             const std::string& sender_localpart,
                             const std::vector<std::string>& namespaces) {
    AppServiceInfo info;
    info.as_token = as_token;
    info.url = url;
    info.sender_localpart = sender_localpart;
    info.namespaces = namespaces;
    info.registered_at = std::chrono::system_clock::now();

    std::lock_guard lock(as_mutex_);
    appservices_[as_token] = info;
    return true;
  }

  // Unregister an application service
  bool unregister_appservice(const std::string& as_token) {
    std::lock_guard lock(as_mutex_);
    return appservices_.erase(as_token) > 0;
  }

  // Process a stream entry for appservice delivery
  void on_stream_entry(const StreamEntry& entry) {
    // Build transaction data
    Transaction txn;
    txn.id = next_txn_id_++;
    txn.room_id = entry.room_id;
    txn.event_id = entry.event_id;
    txn.data = entry.data;
    txn.stream_type = entry.type;
    txn.timestamp = entry.timestamp;
    txn.retry_count = 0;

    std::lock_guard lock(as_mutex_);
    pending_transactions_.push_back(std::move(txn));
  }

  // Push transaction to all registered appservices
  void push_transactions() {
    std::lock_guard lock(as_mutex_);

    for (auto& [token, as_info] : appservices_) {
      // For each appservice, check if events match their namespaces
      for (auto& txn : pending_transactions_) {
        if (should_deliver_to_as(txn, as_info)) {
          // Queue delivery
          as_info.pending_events.push_back(txn);
        }
      }
    }
    pending_transactions_.clear();
  }

  // Check if a transaction should be delivered to an appservice
  bool should_deliver_to_as(const Transaction& txn,
                              const AppServiceInfo& as_info) {
    // If the appservice has users namespace matching the sender,
    // or rooms namespace matching the room, deliver it
    for (auto& ns : as_info.namespaces) {
      // Check user namespace
      if (ns.find("users") != std::string::npos) {
        return true;
      }
      // Check room namespace
      if (ns.find("rooms") != std::string::npos && !txn.room_id.empty()) {
        return true;
      }
      // Check aliases namespace
      if (ns.find("aliases") != std::string::npos) {
        return true;
      }
    }
    return false;
  }

  // Get all registered appservices
  nlohmann::json get_appservices() {
    std::lock_guard lock(as_mutex_);
    nlohmann::json arr = nlohmann::json::array();
    for (auto& [token, info] : appservices_) {
      nlohmann::json item;
      item["as_token"] = token;
      item["url"] = info.url;
      item["sender_localpart"] = info.sender_localpart;
      item["namespaces"] = info.namespaces;
      arr.push_back(item);
    }
    return arr;
  }

  // Handle appservice API: /_matrix/app/v1/transactions/{txnId}
  nlohmann::json get_transaction(const std::string& txn_id) {
    std::lock_guard lock(as_mutex_);
    nlohmann::json txn;
    txn["events"] = nlohmann::json::array();

    for (auto& [token, info] : appservices_) {
      for (auto& ev : info.pending_events) {
        try {
          txn["events"].push_back(nlohmann::json::parse(ev.data));
        } catch (...) {}
      }
    }

    // Clear processed events
    for (auto& [token, info] : appservices_) {
      info.pending_events.clear();
    }

    (void)txn_id;
    return txn;
  }

  // Handle user query from appservice
  nlohmann::json query_user(const std::string& user_id) {
    nlohmann::json result;
    result["user_id"] = user_id;
    // Look up user info in production
    return result;
  }

  // Handle room alias query from appservice
  nlohmann::json query_alias(const std::string& alias) {
    nlohmann::json result;
    result["alias"] = alias;
    // Look up alias in production
    return result;
  }

  // Get pending transaction count
  int pending_count() {
    std::lock_guard lock(as_mutex_);
    return static_cast<int>(pending_transactions_.size());
  }

private:
  struct Transaction {
    int64_t id;
    std::string room_id;
    std::string event_id;
    std::string data;
    StreamType stream_type;
    std::chrono::steady_clock::time_point timestamp;
    int retry_count;
  };

  struct AppServiceInfo {
    std::string as_token;
    std::string url;
    std::string sender_localpart;
    std::vector<std::string> namespaces;
    std::chrono::system_clock::time_point registered_at;
    std::vector<Transaction> pending_events;
  };

  WorkerConfig config_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
  std::atomic<int64_t> next_txn_id_;
  std::map<std::string, AppServiceInfo> appservices_;
  std::deque<Transaction> pending_transactions_;
  mutable std::mutex as_mutex_;

  void worker_loop() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(500));

      // Periodically push transactions to appservices
      static auto last_push = std::chrono::steady_clock::now();
      auto now = std::chrono::steady_clock::now();
      auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
          now - last_push).count();

      if (elapsed >= 1) {
        push_transactions();
        last_push = now;
      }
    }
  }
};

// ============================================================================
// UserDirWorker: Handle user directory search
// ============================================================================

class UserDirWorker {
public:
  explicit UserDirWorker(const WorkerConfig& config)
      : config_(config), running_(false) {
    config_.type = WorkerType::UserDir;
    if (config_.streams_to_replicate.empty())
      config_.streams_to_replicate = default_streams_for_worker(
          WorkerType::UserDir);
  }

  void start() {
    if (running_) return;
    running_ = true;
    worker_thread_ = std::thread([this]() { worker_loop(); });
  }

  void stop() {
    running_ = false;
    if (worker_thread_.joinable())
      worker_thread_.join();
  }

  bool is_running() const { return running_; }

  // Add or update a user in the directory
  void upsert_user(const std::string& user_id,
                    const std::string& display_name,
                    const std::string& avatar_url) {
    std::lock_guard lock(dir_mutex_);

    UserDirEntry entry;
    entry.user_id = user_id;
    entry.display_name = display_name;
    entry.avatar_url = avatar_url;
    entry.last_updated = std::chrono::system_clock::now();

    // Try to find existing
    for (auto& e : user_directory_) {
      if (e.user_id == user_id) {
        e = entry;
        return;
      }
    }
    user_directory_.push_back(std::move(entry));
  }

  // Remove a user from the directory
  void remove_user(const std::string& user_id) {
    std::lock_guard lock(dir_mutex_);
    user_directory_.erase(
        std::remove_if(user_directory_.begin(), user_directory_.end(),
                       [&user_id](const UserDirEntry& e) {
                         return e.user_id == user_id;
                       }),
        user_directory_.end());
  }

  // Search the user directory
  nlohmann::json search(const std::string& search_term,
                          int limit = 10) {
    std::lock_guard lock(dir_mutex_);

    std::vector<UserDirEntry> results;
    std::string lower_term = search_term;
    std::transform(lower_term.begin(), lower_term.end(),
                   lower_term.begin(), ::tolower);

    for (auto& entry : user_directory_) {
      std::string lower_name = entry.display_name;
      std::transform(lower_name.begin(), lower_name.end(),
                     lower_name.begin(), ::tolower);

      std::string lower_id = entry.user_id;
      std::transform(lower_id.begin(), lower_id.end(),
                     lower_id.begin(), ::tolower);

      if (lower_name.find(lower_term) != std::string::npos ||
          lower_id.find(lower_term) != std::string::npos) {
        results.push_back(entry);
        if (static_cast<int>(results.size()) >= limit) break;
      }
    }

    // Sort by relevance (exact match first)
    std::sort(results.begin(), results.end(),
              [&lower_term](const UserDirEntry& a, const UserDirEntry& b) {
                std::string a_lower = a.display_name;
                std::transform(a_lower.begin(), a_lower.end(),
                               a_lower.begin(), ::tolower);
                std::string b_lower = b.display_name;
                std::transform(b_lower.begin(), b_lower.end(),
                               b_lower.begin(), ::tolower);

                bool a_exact = (a_lower == lower_term);
                bool b_exact = (b_lower == lower_term);
                if (a_exact != b_exact) return a_exact > b_exact;

                bool a_starts = (a_lower.find(lower_term) == 0);
                bool b_starts = (b_lower.find(lower_term) == 0);
                if (a_starts != b_starts) return a_starts > b_starts;

                return a_lower < b_lower;
              });

    nlohmann::json response;
    response["results"] = nlohmann::json::array();
    response["limited"] = (static_cast<int>(results.size()) >= limit);

    for (auto& entry : results) {
      nlohmann::json item;
      item["user_id"] = entry.user_id;
      if (!entry.display_name.empty())
        item["display_name"] = entry.display_name;
      if (!entry.avatar_url.empty())
        item["avatar_url"] = entry.avatar_url;
      response["results"].push_back(item);
    }

    return response;
  }

  // Process stream entry for directory updates
  void on_stream_entry(const StreamEntry& entry) {
    if (entry.type == StreamType::Presence) {
      try {
        auto data = nlohmann::json::parse(entry.data);
        std::string user_id = data.value("user_id", "");
        std::string display_name = data.value("displayname", "");
        std::string avatar_url = data.value("avatar_url", "");

        if (!user_id.empty()) {
          upsert_user(user_id, display_name, avatar_url);
        }
      } catch (...) {
        // Invalid data, skip
      }
    }
  }

  // Get directory statistics
  nlohmann::json get_stats() {
    std::lock_guard lock(dir_mutex_);
    nlohmann::json stats;
    stats["total_users"] = user_directory_.size();
    return stats;
  }

  // Bulk import users
  void bulk_import(const std::vector<UserDirEntry>& users) {
    std::lock_guard lock(dir_mutex_);
    for (auto& user : users) {
      bool found = false;
      for (auto& existing : user_directory_) {
        if (existing.user_id == user.user_id) {
          existing = user;
          found = true;
          break;
        }
      }
      if (!found) {
        user_directory_.push_back(user);
      }
    }
  }

  // Rebuild the entire directory (expensive operation)
  void rebuild() {
    std::lock_guard lock(dir_mutex_);
    // In production, this would query the database for all users
    // and rebuild the in-memory directory
    user_directory_.clear();
  }

private:
  struct UserDirEntry {
    std::string user_id;
    std::string display_name;
    std::string avatar_url;
    std::chrono::system_clock::time_point last_updated;
  };

  WorkerConfig config_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
  std::vector<UserDirEntry> user_directory_;
  mutable std::mutex dir_mutex_;

  void worker_loop() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::seconds(60));

      // Periodic cleanup: remove stale entries (not updated in 30 days)
      std::lock_guard lock(dir_mutex_);
      auto now = std::chrono::system_clock::now();
      auto thirty_days = std::chrono::hours(720);

      user_directory_.erase(
          std::remove_if(user_directory_.begin(), user_directory_.end(),
                         [&now, &thirty_days](const UserDirEntry& e) {
                           return (now - e.last_updated) > thirty_days;
                         }),
          user_directory_.end());
    }
  }
};

// ============================================================================
// SynchrotronWorker: Handles sync requests exclusively
// ============================================================================

class SynchrotronWorker {
public:
  explicit SynchrotronWorker(const WorkerConfig& config)
      : config_(config), running_(false) {
    config_.type = WorkerType::Synchrotron;
    if (config_.streams_to_replicate.empty())
      config_.streams_to_replicate = default_streams_for_worker(
          WorkerType::Synchrotron);
    next_sync_token_ = 0;
  }

  void start() {
    if (running_) return;
    running_ = true;
    worker_thread_ = std::thread([this]() { worker_loop(); });
  }

  void stop() {
    running_ = false;
    if (worker_thread_.joinable())
      worker_thread_.join();
  }

  bool is_running() const { return running_; }

  // Process a sync request
  nlohmann::json handle_sync(const std::string& user_id,
                                const std::string& since_token,
                                int timeout_ms,
                                const std::string& filter_id,
                                bool full_state) {
    SyncState state;
    state.user_id = user_id;
    state.since_token = since_token;
    state.timeout_ms = timeout_ms;
    state.filter_id = filter_id;
    state.full_state = full_state;
    state.start_time = std::chrono::steady_clock::now();

    // Register active sync
    std::string sync_key = user_id + ":" + since_token;
    {
      std::lock_guard lock(sync_mutex_);
      active_syncs_[sync_key] = state;
    }

    // Build sync response
    nlohmann::json response;
    response["next_batch"] = generate_sync_token();

    // Rooms section
    response["rooms"] = nlohmann::json::object();
    response["rooms"]["join"] = nlohmann::json::object();
    response["rooms"]["invite"] = nlohmann::json::object();
    response["rooms"]["leave"] = nlohmann::json::object();

    // Build joined rooms timeline
    auto joined = get_joined_room_updates(user_id, since_token);
    for (auto& [room_id, updates] : joined) {
      nlohmann::json room_data;
      room_data["timeline"] = nlohmann::json::object();
      room_data["timeline"]["events"] = updates.timeline_events;
      room_data["timeline"]["limited"] = updates.limited;
      room_data["timeline"]["prev_batch"] = updates.prev_batch;

      room_data["state"] = nlohmann::json::object();
      room_data["state"]["events"] = updates.state_events;

      room_data["ephemeral"] = nlohmann::json::object();
      room_data["ephemeral"]["events"] = updates.ephemeral_events;

      room_data["account_data"] = nlohmann::json::object();
      room_data["account_data"]["events"] = updates.account_data_events;

      room_data["unread_notifications"] = updates.unread_counts;
      room_data["summary"] = updates.summary;

      response["rooms"]["join"][room_id] = room_data;
    }

    // Invited rooms
    auto invited = get_invited_rooms(user_id);
    for (auto& [room_id, invite_state] : invited) {
      nlohmann::json room_data;
      room_data["invite_state"] = nlohmann::json::object();
      room_data["invite_state"]["events"] = invite_state;
      response["rooms"]["invite"][room_id] = room_data;
    }

    // Left rooms
    auto left = get_left_room_updates(user_id, since_token);
    for (auto& [room_id, updates] : left) {
      nlohmann::json room_data;
      room_data["timeline"] = nlohmann::json::object();
      room_data["timeline"]["events"] = updates.timeline_events;
      room_data["timeline"]["limited"] = updates.limited;
      room_data["state"] = nlohmann::json::object();
      room_data["state"]["events"] = updates.state_events;
      room_data["account_data"] = nlohmann::json::object();
      room_data["account_data"]["events"] = updates.account_data_events;
      response["rooms"]["leave"][room_id] = room_data;
    }

    // Presence
    response["presence"] = nlohmann::json::object();
    response["presence"]["events"] = get_presence_updates(user_id, since_token);

    // Account data
    response["account_data"] = nlohmann::json::object();
    response["account_data"]["events"] = get_account_data_updates(
        user_id, since_token);

    // To-device messages
    response["to_device"] = nlohmann::json::object();
    response["to_device"]["events"] = get_to_device_messages(user_id, since_token);

    // Device lists
    response["device_lists"] = nlohmann::json::object();
    response["device_lists"]["changed"] = get_changed_devices(user_id, since_token);
    response["device_lists"]["left"] = nlohmann::json::array();

    // One-time keys count
    response["device_one_time_keys_count"] = nlohmann::json::object();
    response["device_one_time_keys_count"]["signed_curve25519"] = 50;
    response["device_one_time_keys_count"]["curve25519"] = 0;

    // Groups (deprecated but often still expected)
    response["groups"] = nlohmann::json::object();
    response["groups"]["join"] = nlohmann::json::object();
    response["groups"]["invite"] = nlohmann::json::object();
    response["groups"]["leave"] = nlohmann::json::object();

    // Clean up active sync
    {
      std::lock_guard lock(sync_mutex_);
      active_syncs_.erase(sync_key);
    }

    return response;
  }

  // Process stream entry for sync updates
  void on_stream_entry(const StreamEntry& entry) {
    std::lock_guard lock(sync_mutex_);

    switch (entry.type) {
      case StreamType::Events: {
        SyncUpdate update;
        update.type = "timeline";
        update.room_id = entry.room_id;
        update.data = entry.data;
        update.position = entry.position;

        auto& updates = recent_updates_[entry.room_id];
        updates.push_back(update);

        // Keep max 100 recent updates per room
        if (updates.size() > 100) {
          updates.erase(updates.begin());
        }
        break;
      }
      case StreamType::Presence: {
        PresenceUpdate pu;
        pu.user_id = entry.user_id;
        pu.data = entry.data;
        pu.timestamp = entry.timestamp;
        recent_presence_.push_back(pu);

        if (recent_presence_.size() > 500) {
          recent_presence_.erase(recent_presence_.begin());
        }
        break;
      }
      case StreamType::Typing: {
        TypingUpdate tu;
        tu.room_id = entry.room_id;
        tu.data = entry.data;
        recent_typing_[entry.room_id] = tu;
        break;
      }
      case StreamType::Receipts: {
        ReceiptUpdate ru;
        ru.room_id = entry.room_id;
        ru.data = entry.data;
        recent_receipts_[entry.room_id] = ru;
        break;
      }
      case StreamType::AccountData: {
        AccountDataUpdate au;
        au.user_id = entry.user_id;
        au.room_id = entry.room_id;
        au.data = entry.data;
        recent_account_data_.push_back(au);

        if (recent_account_data_.size() > 500) {
          recent_account_data_.erase(recent_account_data_.begin());
        }
        break;
      }
      case StreamType::ToDevice: {
        ToDeviceUpdate td;
        td.user_id = entry.user_id;
        td.data = entry.data;
        recent_to_device_.push_back(td);

        if (recent_to_device_.size() > 500) {
          recent_to_device_.erase(recent_to_device_.begin());
        }
        break;
      }
      case StreamType::DeviceLists: {
        DeviceListUpdate dl;
        dl.user_id = entry.user_id;
        dl.data = entry.data;
        recent_device_lists_.push_back(dl);

        if (recent_device_lists_.size() > 500) {
          recent_device_lists_.erase(recent_device_lists_.begin());
        }
        break;
      }
      default:
        break;
    }

    // Wake up any waiting sync requests
    sync_cv_.notify_all();
  }

  // Wait for new data (for long-poll sync)
  void wait_for_updates(const std::string& user_id, int timeout_ms) {
    std::unique_lock lock(sync_mutex_);
    sync_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this]() {
      return has_pending_updates_;
    });
    has_pending_updates_ = false;
  }

  // Check if there are pending updates for a user
  bool has_updates(const std::string& user_id) {
    std::lock_guard lock(sync_mutex_);

    for (auto& [room_id, updates] : recent_updates_) {
      for (auto& update : updates) {
        try {
          auto event = nlohmann::json::parse(update.data);
          if (event.value("user_id", "") == user_id ||
              event.value("sender", "") == user_id) {
            return true;
          }
        } catch (...) {}
      }
    }
    return false;
  }

  // Get active sync count
  int active_sync_count() {
    std::lock_guard lock(sync_mutex_);
    return static_cast<int>(active_syncs_.size());
  }

  // Generate the next sync token
  std::string generate_sync_token() {
    int64_t current = next_sync_token_++;
    // Format as standard Matrix sync token
    // s{pos}_{p0}_{p1}_{p2}_{p3}_{p4}_{p5}_{p6}_{p7}
    std::ostringstream oss;
    oss << "s" << current;
    // Each component represents position of a stream
    for (int i = 0; i < 8; i++) {
      oss << "_" << (current + i);
    }
    return oss.str();
  }

  // Parse a sync token to extract stream positions
  void parse_sync_token(const std::string& token, int64_t positions[8]) {
    // Parse sPOS_P0_P1_P2_P3_P4_P5_P6_P7 format
    if (token.empty() || token[0] != 's') {
      for (int i = 0; i < 8; i++) positions[i] = 0;
      return;
    }

    std::istringstream iss(token.substr(1));
    std::string part;
    int idx = 0;
    while (std::getline(iss, part, '_') && idx < 8) {
      try {
        positions[idx] = std::stoll(part);
      } catch (...) {
        positions[idx] = 0;
      }
      idx++;
    }
    while (idx < 8) positions[idx++] = 0;
  }

private:
  struct SyncState {
    std::string user_id;
    std::string since_token;
    int timeout_ms = 0;
    std::string filter_id;
    bool full_state = false;
    std::chrono::steady_clock::time_point start_time;
  };

  struct SyncUpdate {
    std::string type;
    std::string room_id;
    std::string data;
    int64_t position = 0;
  };

  struct RoomSyncData {
    nlohmann::json timeline_events = nlohmann::json::array();
    nlohmann::json state_events = nlohmann::json::array();
    nlohmann::json ephemeral_events = nlohmann::json::array();
    nlohmann::json account_data_events = nlohmann::json::array();
    nlohmann::json unread_counts = nlohmann::json::object();
    nlohmann::json summary = nlohmann::json::object();
    std::string prev_batch;
    bool limited = false;
  };

  struct PresenceUpdate {
    std::string user_id;
    std::string data;
    std::chrono::steady_clock::time_point timestamp;
  };

  struct TypingUpdate {
    std::string room_id;
    std::string data;
  };

  struct ReceiptUpdate {
    std::string room_id;
    std::string data;
  };

  struct AccountDataUpdate {
    std::string user_id;
    std::string room_id;
    std::string data;
  };

  struct ToDeviceUpdate {
    std::string user_id;
    std::string data;
  };

  struct DeviceListUpdate {
    std::string user_id;
    std::string data;
  };

  WorkerConfig config_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
  std::atomic<int64_t> next_sync_token_;

  mutable std::mutex sync_mutex_;
  std::condition_variable sync_cv_;
  bool has_pending_updates_ = false;

  std::map<std::string, SyncState> active_syncs_;
  std::map<std::string, std::vector<SyncUpdate>> recent_updates_;
  std::vector<PresenceUpdate> recent_presence_;
  std::map<std::string, TypingUpdate> recent_typing_;
  std::map<std::string, ReceiptUpdate> recent_receipts_;
  std::vector<AccountDataUpdate> recent_account_data_;
  std::vector<ToDeviceUpdate> recent_to_device_;
  std::vector<DeviceListUpdate> recent_device_lists_;

  std::map<std::string, RoomSyncData> get_joined_room_updates(
      const std::string& user_id, const std::string& since_token) {
    std::map<std::string, RoomSyncData> result;
    // Return accumulated updates since the token
    for (auto& [room_id, updates] : recent_updates_) {
      RoomSyncData room_data;
      for (auto& update : updates) {
        try {
          room_data.timeline_events.push_back(nlohmann::json::parse(update.data));
        } catch (...) {}
      }
      if (!room_data.timeline_events.empty()) {
        result[room_id] = room_data;
      }
    }
    // Include typing/receipts
    for (auto& [room_id, typing] : recent_typing_) {
      try {
        auto j = nlohmann::json::parse(typing.data);
        result[room_id].ephemeral_events.push_back(j);
      } catch (...) {}
    }
    for (auto& [room_id, receipt] : recent_receipts_) {
      try {
        auto j = nlohmann::json::parse(receipt.data);
        result[room_id].ephemeral_events.push_back(j);
      } catch (...) {}
    }
    (void)user_id;  // In production, filter by user's joined rooms
    (void)since_token;
    return result;
  }

  std::map<std::string, nlohmann::json> get_invited_rooms(
      const std::string& user_id) {
    std::map<std::string, nlohmann::json> result;
    (void)user_id;  // Placeholder
    return result;
  }

  std::map<std::string, RoomSyncData> get_left_room_updates(
      const std::string& user_id, const std::string& since_token) {
    std::map<std::string, RoomSyncData> result;
    (void)user_id;
    (void)since_token;
    return result;
  }

  nlohmann::json get_presence_updates(
      const std::string& user_id, const std::string& since_token) {
    nlohmann::json events = nlohmann::json::array();
    for (auto& pu : recent_presence_) {
      try {
        events.push_back(nlohmann::json::parse(pu.data));
      } catch (...) {}
    }
    (void)user_id;
    (void)since_token;
    return events;
  }

  nlohmann::json get_account_data_updates(
      const std::string& user_id, const std::string& since_token) {
    nlohmann::json events = nlohmann::json::array();
    for (auto& au : recent_account_data_) {
      if (au.user_id == user_id) {
        try {
          events.push_back(nlohmann::json::parse(au.data));
        } catch (...) {}
      }
    }
    (void)since_token;
    return events;
  }

  nlohmann::json get_to_device_messages(
      const std::string& user_id, const std::string& since_token) {
    nlohmann::json events = nlohmann::json::array();
    for (auto& td : recent_to_device_) {
      if (td.user_id == user_id) {
        try {
          events.push_back(nlohmann::json::parse(td.data));
        } catch (...) {}
      }
    }
    (void)since_token;
    return events;
  }

  nlohmann::json get_changed_devices(
      const std::string& user_id, const std::string& since_token) {
    nlohmann::json devices = nlohmann::json::array();
    for (auto& dl : recent_device_lists_) {
      if (dl.user_id == user_id) {
        devices.push_back(dl.user_id);
      }
    }
    (void)since_token;
    return devices;
  }

  void worker_loop() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

      // Wake up any stale syncs
      auto now = std::chrono::steady_clock::now();
      {
        std::lock_guard lock(sync_mutex_);
        for (auto it = active_syncs_.begin(); it != active_syncs_.end();) {
          auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
              now - it->second.start_time).count();
          if (elapsed > it->second.timeout_ms) {
            // Sync timed out, send empty response
            has_pending_updates_ = true;
            sync_cv_.notify_all();
            it = active_syncs_.erase(it);
          } else {
            ++it;
          }
        }
      }

      // Dump pending updates to pending flag
      {
        std::lock_guard lock(sync_mutex_);
        if (!recent_updates_.empty() || !recent_presence_.empty() ||
            !recent_to_device_.empty()) {
          has_pending_updates_ = true;
          sync_cv_.notify_all();
        }
      }
    }
  }
};

// ============================================================================
// MasterReplicationServer: Accepts worker connections, streams data
// ============================================================================

class MasterReplicationServer {
public:
  MasterReplicationServer(int port = DEFAULT_REPLICATION_PORT)
      : port_(port), running_(false) {}

  ~MasterReplicationServer() { stop(); }

  // Initialize and start the master server
  bool start(StreamManager* stream_manager,
             WorkerRegistry* registry,
             WorkerHealthMonitor* health_monitor,
             WorkerLoadBalancer* load_balancer) {
    if (running_) return false;

    stream_manager_ = stream_manager;
    registry_ = registry;
    health_monitor_ = health_monitor;
    load_balancer_ = load_balancer;

    // Initialize TCP backend
    tcp_backend_ = std::make_unique<TCPReplicationBackend>();
    if (!tcp_backend_->bind_and_listen(port_, 256)) {
      return false;
    }

    running_ = true;
    server_thread_ = std::thread([this]() { server_loop(); });

    return true;
  }

  // Stop the master server
  void stop() {
    running_ = false;
    if (server_thread_.joinable()) {
      server_thread_.join();
    }
    tcp_backend_.reset();
  }

  bool is_running() const { return running_; }

  // Set Redis backend
  void set_redis_backend(std::shared_ptr<RedisReplicationBackend> redis) {
    redis_backend_ = std::move(redis);
  }

  // Broadcast an event to all connected workers via TCP
  void broadcast_rdata(StreamType type, int64_t position,
                       const std::string& data) {
    auto frame = ReplicationProtocol::make_rdata(type, position, data);

    std::lock_guard lock(client_mutex_);
    for (auto& [sock, client_info] : clients_) {
      // Only send to clients subscribed to this stream
      if (client_info.subscribed_streams.find(type) !=
          client_info.subscribed_streams.end()) {
        TCPReplicationBackend::send_frame_to(sock, frame);
      }
    }
  }

  // Also push to Redis for Redis-connected workers
  void publish_to_redis(StreamType type, const StreamEntry& entry) {
    if (redis_backend_ && redis_backend_->is_connected()) {
      redis_backend_->stream_push(type, entry);
      redis_backend_->publish(REDIS_PUBSUB_CHANNEL,
                              entry.to_json().dump());
    }
  }

  // Get number of connected clients
  int client_count() {
    std::lock_guard lock(client_mutex_);
    return static_cast<int>(clients_.size());
  }

private:
  struct ClientInfo {
    std::string worker_name;
    WorkerType worker_type = WorkerType::Generic;
    std::set<StreamType> subscribed_streams;
    std::chrono::steady_clock::time_point connected_at;
    int64_t last_ping_id = 0;
    std::vector<uint8_t> read_buffer;
  };

  int port_;
  std::atomic<bool> running_;
  std::thread server_thread_;
  std::unique_ptr<TCPReplicationBackend> tcp_backend_;
  std::shared_ptr<RedisReplicationBackend> redis_backend_;

  StreamManager* stream_manager_ = nullptr;
  WorkerRegistry* registry_ = nullptr;
  WorkerHealthMonitor* health_monitor_ = nullptr;
  WorkerLoadBalancer* load_balancer_ = nullptr;

  std::map<socket_t, ClientInfo> clients_;
  mutable std::mutex client_mutex_;

  void server_loop() {
    while (running_) {
      // Use select/poll to handle connections
      fd_set readfds;
      FD_ZERO(&readfds);
      socket_t listen_sock = tcp_backend_->get_socket();
      FD_SET(listen_sock, &readfds);
      socket_t max_fd = listen_sock;

      {
        std::lock_guard lock(client_mutex_);
        for (auto& [sock, _] : clients_) {
          FD_SET(sock, &readfds);
          if (sock > max_fd) max_fd = sock;
        }
      }

      struct timeval tv;
      tv.tv_sec = 0;
      tv.tv_usec = 100000; // 100ms timeout

      int ret = select(max_fd + 1, &readfds, nullptr, nullptr, &tv);

      if (ret < 0) {
        if (SOCKET_ERROR_CODE == SOCKET_WOULDBLOCK) continue;
        break; // Fatal error
      }

      // Accept new connections
      if (FD_ISSET(listen_sock, &readfds)) {
        socket_t client_sock = tcp_backend_->accept_connection();
        if (client_sock != SOCKET_INVALID) {
          // Set non-blocking
#ifdef _WIN32
          u_long mode = 1;
          ioctlsocket(client_sock, FIONBIO, &mode);
#else
          int flags = fcntl(client_sock, F_GETFL, 0);
          fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);
#endif
          std::lock_guard lock(client_mutex_);
          ClientInfo info;
          info.connected_at = std::chrono::steady_clock::now();
          clients_[client_sock] = std::move(info);
        }
      }

      // Handle client I/O
      std::vector<socket_t> closed_clients;
      {
        std::lock_guard lock(client_mutex_);
        for (auto& [sock, info] : clients_) {
          if (FD_ISSET(sock, &readfds)) {
            auto frame = TCPReplicationBackend::recv_frame_from(
                sock, info.read_buffer);
            if (frame.has_value()) {
              process_client_frame(sock, info, *frame);
            } else if (info.read_buffer.size() > TCP_BUFFER_SIZE * 4) {
              // Buffer overflow, close connection
              closed_clients.push_back(sock);
            }
          }
        }

        // Clean up closed clients
        for (auto& sock : closed_clients) {
          auto it = clients_.find(sock);
          if (it != clients_.end()) {
            if (registry_)
              registry_->unregister_worker(it->second.worker_name);
            if (health_monitor_)
              health_monitor_->unregister_worker(it->second.worker_name);
            if (load_balancer_)
              load_balancer_->unregister_worker(it->second.worker_name);
          }
          TCPReplicationBackend::close_client(sock);
          clients_.erase(sock);
        }
      }

      // Periodic ping
      static auto last_ping = std::chrono::steady_clock::now();
      auto now = std::chrono::steady_clock::now();
      if (std::chrono::duration_cast<std::chrono::milliseconds>(
              now - last_ping).count() > PING_INTERVAL_MS) {
        ping_all_clients();
        last_ping = now;
      }

      // Check health
      if (health_monitor_) {
        auto unhealthy = health_monitor_->check_health();
        for (auto& name : unhealthy) {
          drop_worker(name);
        }
      }
    }
  }

  void process_client_frame(socket_t sock, ClientInfo& info,
                             const ReplicationFrame& frame) {
    switch (frame.command) {
      case ReplicationCommand::REGISTER: {
        auto j = ReplicationProtocol::parse_payload(frame);
        info.worker_name = j.value("worker", "");
        info.worker_type = worker_type_from_name(
            j.value("worker_type", "generic"));

        // Parse subscribed streams
        if (j.contains("streams") && j["streams"].is_array()) {
          for (auto& s : j["streams"]) {
            try {
              info.subscribed_streams.insert(
                  stream_type_from_name(s.get<std::string>()));
            } catch (...) {}
          }
        } else {
          info.subscribed_streams = default_streams_for_worker(
              info.worker_type);
        }

        // Register in all managers
        if (registry_)
          registry_->register_worker(info.worker_name, info.worker_type);
        if (health_monitor_)
          health_monitor_->register_worker(info.worker_name);
        if (load_balancer_)
          load_balancer_->register_worker(info.worker_name, info.worker_type);

        // Send back a SYNC response
        auto sync_frame = ReplicationProtocol::make_sync(
            info.worker_name, 0);
        TCPReplicationBackend::send_frame_to(sock, sync_frame);
        break;
      }

      case ReplicationCommand::REPLICATE: {
        auto j = ReplicationProtocol::parse_payload(frame);
        if (j.contains("streams") && j["streams"].is_array()) {
          info.subscribed_streams.clear();
          for (auto& s : j["streams"]) {
            try {
              info.subscribed_streams.insert(
                  stream_type_from_name(s.get<std::string>()));
            } catch (...) {}
          }
        }
        break;
      }

      case ReplicationCommand::UNREPLICATE: {
        auto j = ReplicationProtocol::parse_payload(frame);
        if (j.contains("streams") && j["streams"].is_array()) {
          for (auto& s : j["streams"]) {
            try {
              info.subscribed_streams.erase(
                  stream_type_from_name(s.get<std::string>()));
            } catch (...) {}
          }
        }
        break;
      }

      case ReplicationCommand::POSITION: {
        auto j = ReplicationProtocol::parse_payload(frame);
        auto stream_name = j.value("stream", "");
        int64_t pos = j.value("position", 0LL);
        if (!stream_name.empty() && stream_manager_) {
          try {
            auto st = stream_type_from_name(stream_name);
            stream_manager_->store_worker_position(
                info.worker_name, st, pos);
          } catch (...) {}
        }
        break;
      }

      case ReplicationCommand::PING: {
        auto j = ReplicationProtocol::parse_payload(frame);
        int64_t ping_id = j.value("ping_id", 0LL);
        auto pong = ReplicationProtocol::make_pong(ping_id);
        TCPReplicationBackend::send_frame_to(sock, pong);
        break;
      }

      case ReplicationCommand::PONG: {
        auto j = ReplicationProtocol::parse_payload(frame);
        int64_t ping_id = j.value("ping_id", 0LL);
        if (health_monitor_)
          health_monitor_->pong_received(info.worker_name, ping_id);
        break;
      }

      case ReplicationCommand::UNREGISTER: {
        if (registry_)
          registry_->unregister_worker(info.worker_name);
        if (health_monitor_)
          health_monitor_->unregister_worker(info.worker_name);
        if (load_balancer_)
          load_balancer_->unregister_worker(info.worker_name);
        TCPReplicationBackend::close_client(sock);
        std::lock_guard lock(client_mutex_);
        clients_.erase(sock);
        break;
      }

      default:
        break;
    }
  }

  void ping_all_clients() {
    std::lock_guard lock(client_mutex_);
    for (auto& [sock, info] : clients_) {
      info.last_ping_id++;
      auto ping = ReplicationProtocol::make_ping(
          info.worker_name, info.last_ping_id);
      TCPReplicationBackend::send_frame_to(sock, ping);

      if (health_monitor_)
        health_monitor_->ping_sent(info.worker_name);
    }
  }

  void drop_worker(const std::string& name) {
    std::lock_guard lock(client_mutex_);
    for (auto it = clients_.begin(); it != clients_.end(); ++it) {
      if (it->second.worker_name == name) {
        TCPReplicationBackend::close_client(it->first);
        if (registry_)
          registry_->unregister_worker(name);
        if (load_balancer_)
          load_balancer_->unregister_worker(name);
        clients_.erase(it);
        break;
      }
    }
  }
};

// ============================================================================
// WorkerReplicationClient: Connects to master, receives stream data
// ============================================================================

class WorkerReplicationClient {
public:
  WorkerReplicationClient(const WorkerConfig& config)
      : config_(config), running_(false), reconnect_attempts_(0),
        current_backoff_ms_(BASE_RECONNECT_DELAY_MS) {}

  ~WorkerReplicationClient() { disconnect(); }

  // Connect to the master replication server
  bool connect() {
    tcp_backend_ = std::make_unique<TCPReplicationBackend>();
    if (!tcp_backend_->connect(config_.worker_replication_host,
                                config_.worker_replication_port)) {
      return false;
    }

    // Send REGISTER command
    auto register_frame = ReplicationProtocol::make_register(
        config_.worker_name, config_.type,
        config_.streams_to_replicate);
    if (!tcp_backend_->send_frame(register_frame)) {
      tcp_backend_->disconnect();
      return false;
    }

    connected_ = true;
    reconnect_attempts_ = 0;
    current_backoff_ms_ = BASE_RECONNECT_DELAY_MS;
    return true;
  }

  // Connect via Redis
  bool connect_redis(const std::string& redis_host, int redis_port,
                     const std::string& redis_password = "") {
    redis_backend_ = std::make_shared<RedisReplicationBackend>(
        redis_host, redis_port, redis_password);
    if (!redis_backend_->connect()) {
      return false;
    }

    // Subscribe to the PUB/SUB channel
    redis_backend_->subscribe(REDIS_PUBSUB_CHANNEL);

    // Store initial positions
    for (auto st : config_.streams_to_replicate) {
      redis_backend_->store_position(config_.worker_name, st, 0);
    }

    connected_ = true;
    using_redis_ = true;

    // Start listening for pub/sub messages
    redis_backend_->start_listening(
        [this](const std::string& channel, const std::string& message) {
          on_redis_message(channel, message);
        });

    return true;
  }

  // Disconnect
  void disconnect() {
    running_ = false;
    connected_ = false;

    if (redis_backend_) {
      redis_backend_->stop_listening();
      redis_backend_->disconnect();
    }

    if (tcp_backend_) {
      tcp_backend_->disconnect();
    }
  }

  // Start the client loop
  void start() {
    if (running_) return;
    running_ = true;
    client_thread_ = std::thread([this]() { client_loop(); });
  }

  // Stop the client loop
  void stop() {
    running_ = false;
    if (client_thread_.joinable()) {
      client_thread_.join();
    }
    disconnect();
  }

  bool is_connected() const { return connected_; }

  bool is_running() const { return running_; }

  // Set callback for incoming stream entries
  void set_on_entry(std::function<void(const StreamEntry&)> callback) {
    on_entry_callback_ = std::move(callback);
  }

  // Set callback for errors
  void set_on_error(std::function<void(const std::string&)> callback) {
    on_error_callback_ = std::move(callback);
  }

  // Send position acknowledgement
  void send_position(StreamType type, int64_t position) {
    auto pos_frame = ReplicationProtocol::make_position(
        config_.worker_name, type, position);

    if (tcp_backend_ && tcp_backend_->is_connected()) {
      tcp_backend_->send_frame(pos_frame);
    }

    if (redis_backend_ && redis_backend_->is_connected()) {
      redis_backend_->store_position(config_.worker_name, type, position);
    }
  }

  // Subscribe to additional streams
  void subscribe_streams(const std::set<StreamType>& streams) {
    auto rep_frame = ReplicationProtocol::make_replicate(
        config_.worker_name, streams);

    if (tcp_backend_ && tcp_backend_->is_connected()) {
      tcp_backend_->send_frame(rep_frame);
    }

    for (auto st : streams) {
      config_.streams_to_replicate.insert(st);
    }
  }

  // Handle reconnection with exponential backoff
  bool attempt_reconnect() {
    disconnect();

    int delay = calculate_backoff_delay();
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    bool result = connect();
    if (!result && config_.worker_replication_host.empty()) {
      // Try Redis if no TCP host configured
      result = false;
    }

    if (result) {
      reconnect_attempts_ = 0;
      current_backoff_ms_ = BASE_RECONNECT_DELAY_MS;
    } else {
      reconnect_attempts_++;
    }

    return result;
  }

  // Get connection statistics
  nlohmann::json get_stats() {
    nlohmann::json stats;
    stats["connected"] = connected_;
    stats["using_redis"] = using_redis_;
    stats["reconnect_attempts"] = reconnect_attempts_.load();
    stats["current_backoff_ms"] = current_backoff_ms_.load();
    stats["subscribed_streams"] = nlohmann::json::array();
    for (auto st : config_.streams_to_replicate) {
      stats["subscribed_streams"].push_back(stream_type_name(st));
    }
    return stats;
  }

private:
  WorkerConfig config_;
  std::atomic<bool> running_;
  std::atomic<bool> connected_;
  std::atomic<bool> using_redis_;
  std::thread client_thread_;
  std::unique_ptr<TCPReplicationBackend> tcp_backend_;
  std::shared_ptr<RedisReplicationBackend> redis_backend_;
  std::atomic<int> reconnect_attempts_;
  std::atomic<int> current_backoff_ms_;

  std::function<void(const StreamEntry&)> on_entry_callback_;
  std::function<void(const std::string&)> on_error_callback_;

  // Stream position tracker per stream for catch-up
  std::map<StreamType, int64_t> stream_positions_;
  mutable std::mutex pos_mutex_;

  int calculate_backoff_delay() {
    int delay = BASE_RECONNECT_DELAY_MS;
    for (int i = 0; i < reconnect_attempts_ && i < MAX_RECONNECT_ATTEMPTS; i++) {
      delay = std::min(delay * 2, MAX_RECONNECT_DELAY_MS);
    }
    // Add jitter: +/- 25%
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> jitter(-delay / 4, delay / 4);
    int result = delay + jitter(rng);
    current_backoff_ms_ = result;
    return result;
  }

  void client_loop() {
    while (running_) {
      if (!connected_) {
        // Try to reconnect
        if (reconnect_attempts_ < MAX_RECONNECT_ATTEMPTS) {
          bool reconnected = attempt_reconnect();
          if (!reconnected) continue;
        } else {
          // Max reconnect attempts reached, wait longer
          std::this_thread::sleep_for(std::chrono::seconds(30));
          reconnect_attempts_ = 0;
          continue;
        }
      }

      if (using_redis_) {
        // Redis backend handles messages via callback thread
        // Just do periodic ping and position check
        ping_master();
        std::this_thread::sleep_for(std::chrono::milliseconds(PING_INTERVAL_MS));
      } else if (tcp_backend_ && tcp_backend_->is_connected()) {
        // TCP mode: receive frames
        auto frame = tcp_backend_->recv_frame();
        if (frame.has_value()) {
          process_frame(*frame);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }
  }

  void process_frame(const ReplicationFrame& frame) {
    switch (frame.command) {
      case ReplicationCommand::RDATA: {
        if (on_entry_callback_) {
          auto entry = ReplicationProtocol::parse_rdata(frame);
          if (entry.has_value()) {
            on_entry_callback_(*entry);

            // Update local position
            std::lock_guard lock(pos_mutex_);
            stream_positions_[entry->type] = entry->position;

            // Acknowledge position to master
            send_position(entry->type, entry->position);
          }
        }
        break;
      }

      case ReplicationCommand::SYNC: {
        // Master sent us sync info, perform catch-up
        auto j = ReplicationProtocol::parse_payload(frame);
        int64_t since = j.value("since", 0LL);

        // Request backfill for streams we're behind on
        for (auto st : config_.streams_to_replicate) {
          int64_t local_pos = 0;
          {
            std::lock_guard lock(pos_mutex_);
            auto it = stream_positions_.find(st);
            if (it != stream_positions_.end()) local_pos = it->second;
          }

          if (local_pos < since) {
            // We need catch-up data
            send_position(st, local_pos);
          }
        }
        break;
      }

      case ReplicationCommand::PING: {
        // Respond with PONG immediately
        auto j = ReplicationProtocol::parse_payload(frame);
        int64_t ping_id = j.value("ping_id", 0LL);
        auto pong = ReplicationProtocol::make_pong(ping_id);
        if (tcp_backend_) tcp_backend_->send_frame(pong);
        break;
      }

      case ReplicationCommand::ERROR: {
        auto j = ReplicationProtocol::parse_payload(frame);
        std::string msg = j.value("message", "Unknown error");
        if (on_error_callback_) on_error_callback_(msg);
        break;
      }

      default:
        break;
    }
  }

  void on_redis_message(const std::string& channel, const std::string& message) {
    if (channel == REDIS_PUBSUB_CHANNEL && on_entry_callback_) {
      try {
        auto j = nlohmann::json::parse(message);
        auto entry = StreamEntry::from_json(j);

        // Check if we're subscribed to this stream
        if (config_.streams_to_replicate.find(entry.type) !=
            config_.streams_to_replicate.end()) {
          on_entry_callback_(entry);

          // Update local position
          std::lock_guard lock(pos_mutex_);
          stream_positions_[entry.type] = entry.position;

          // Store position back to Redis
          if (redis_backend_) {
            redis_backend_->store_position(
                config_.worker_name, entry.type, entry.position);
          }
        }
      } catch (...) {
        // Invalid message, skip
      }
    }
  }

  void ping_master() {
    if (tcp_backend_ && tcp_backend_->is_connected()) {
      static int64_t ping_counter = 0;
      ping_counter++;
      auto ping = ReplicationProtocol::make_ping(
          config_.worker_name, ping_counter);
      tcp_backend_->send_frame(ping);
    }
  }
};

// ============================================================================
// ReplicationManager: Top-level orchestrator
// ============================================================================

class ReplicationManager {
public:
  ReplicationManager()
      : running_(false),
        mode_(ReplicationMode::Master) {}

  ~ReplicationManager() { shutdown(); }

  enum class ReplicationMode {
    Master,
    Worker
  };

  // Initialize as Master
  bool init_as_master(const nlohmann::json& config) {
    std::lock_guard lock(mutex_);

    mode_ = ReplicationMode::Master;
    int port = config.value("replication_port", DEFAULT_REPLICATION_PORT);
    std::string redis_host = config.value("redis_host", "");
    int redis_port = config.value("redis_port", 6379);
    std::string redis_password = config.value("redis_password", "");

    // Create core components
    stream_manager_ = std::make_unique<StreamManager>();
    registry_ = std::make_unique<WorkerRegistry>();
    health_monitor_ = std::make_unique<WorkerHealthMonitor>();
    load_balancer_ = std::make_unique<WorkerLoadBalancer>();
    config_manager_ = std::make_unique<WorkerConfigManager>();

    // Load worker configurations
    if (config.contains("workers") && config["workers"].is_array()) {
      config_manager_->load_from_json(config["workers"]);
    }

    // Start master server
    master_server_ = std::make_unique<MasterReplicationServer>(port);

    // Set up Redis if configured
    if (!redis_host.empty()) {
      auto* redis = new RedisReplicationBackend(redis_host, redis_port,
                                                  redis_password);
      redis_backend_.reset(redis);
      redis_backend_->connect();
      master_server_->set_redis_backend(redis_backend_);

      // Start Redis listener for worker messages
      redis_backend_->start_listening(
          [this](const std::string& channel, const std::string& message) {
            on_redis_worker_message(channel, message);
          });
    }

    if (!master_server_->start(stream_manager_.get(), registry_.get(),
                                 health_monitor_.get(), load_balancer_.get())) {
      return false;
    }

    // Start health monitoring
    health_monitor_->start_monitoring(
        [this](const std::string& worker) {
          on_worker_unhealthy(worker);
        },
        [this](const std::string& worker) {
          on_worker_recovered(worker);
        });

    running_ = true;
    worker_name_ = config.value("worker_name", "master");

    // Start maintenance thread
    maintenance_thread_ = std::thread([this]() { maintenance_loop(); });

    return true;
  }

  // Initialize as Worker
  bool init_as_worker(const nlohmann::json& config) {
    std::lock_guard lock(mutex_);

    mode_ = ReplicationMode::Worker;
    worker_name_ = config.value("worker_name", "worker");

    WorkerConfig worker_cfg;
    worker_cfg.worker_name = worker_name_;
    worker_cfg.type = worker_type_from_name(
        config.value("worker_type", "generic"));
    worker_cfg.worker_replication_host = config.value(
        "replication_host", "127.0.0.1");
    worker_cfg.worker_replication_port = config.value(
        "replication_port", DEFAULT_REPLICATION_PORT);
    worker_cfg.run_background_tasks = config.value(
        "run_background_tasks", true);

    // Parse subscribed streams
    if (config.contains("streams") && config["streams"].is_array()) {
      for (auto& s : config["streams"]) {
        try {
          worker_cfg.streams_to_replicate.insert(
              stream_type_from_name(s.get<std::string>()));
        } catch (...) {}
      }
    } else {
      worker_cfg.streams_to_replicate = default_streams_for_worker(
          worker_cfg.type);
    }

    // Create the appropriate specialized worker
    switch (worker_cfg.type) {
      case WorkerType::Generic:
        generic_worker_ = std::make_unique<GenericWorker>(worker_cfg);
        generic_worker_->start();
        break;
      case WorkerType::Pusher:
        pusher_worker_ = std::make_unique<PusherWorker>(worker_cfg);
        pusher_worker_->start();
        break;
      case WorkerType::FederationSender:
        federation_worker_ = std::make_unique<FederationSenderWorker>(worker_cfg);
        federation_worker_->start();
        break;
      case WorkerType::MediaRepository:
        media_worker_ = std::make_unique<MediaRepositoryWorker>(worker_cfg);
        media_worker_->start();
        break;
      case WorkerType::Appservice:
        appservice_worker_ = std::make_unique<AppserviceWorker>(worker_cfg);
        appservice_worker_->start();
        break;
      case WorkerType::UserDir:
        userdir_worker_ = std::make_unique<UserDirWorker>(worker_cfg);
        userdir_worker_->start();
        break;
      case WorkerType::Synchrotron:
        synchrotron_worker_ = std::make_unique<SynchrotronWorker>(worker_cfg);
        synchrotron_worker_->start();
        break;
      default:
        generic_worker_ = std::make_unique<GenericWorker>(worker_cfg);
        generic_worker_->start();
        break;
    }

    // Create replication client
    replication_client_ = std::make_unique<WorkerReplicationClient>(worker_cfg);

    // Set up callbacks
    replication_client_->set_on_entry(
        [this](const StreamEntry& entry) {
          on_replication_entry(entry);
        });
    replication_client_->set_on_error(
        [this](const std::string& error) {
          on_replication_error(error);
        });

    // Try TCP first, then Redis
    bool connected = replication_client_->connect();
    if (!connected) {
      std::string redis_host = config.value("redis_host", "");
      int redis_port = config.value("redis_port", 6379);
      std::string redis_password = config.value("redis_password", "");

      if (!redis_host.empty()) {
        connected = replication_client_->connect_redis(
            redis_host, redis_port, redis_password);
      }
    }

    if (!connected) {
      // Will retry in background
      replication_client_->start();
    } else {
      replication_client_->start();
    }

    running_ = true;

    // Start periodic position sync thread
    position_sync_thread_ = std::thread([this]() { position_sync_loop(); });

    return true;
  }

  // Shutdown everything
  void shutdown() {
    running_ = false;

    if (master_server_) {
      master_server_->stop();
    }

    if (health_monitor_) {
      health_monitor_->stop_monitoring();
    }

    if (replication_client_) {
      replication_client_->stop();
    }

    if (generic_worker_) generic_worker_->stop();
    if (pusher_worker_) pusher_worker_->stop();
    if (federation_worker_) federation_worker_->stop();
    if (media_worker_) media_worker_->stop();
    if (appservice_worker_) appservice_worker_->stop();
    if (userdir_worker_) userdir_worker_->stop();
    if (synchrotron_worker_) synchrotron_worker_->stop();

    if (redis_backend_) {
      redis_backend_->stop_listening();
      redis_backend_->disconnect();
    }

    if (maintenance_thread_.joinable()) maintenance_thread_.join();
    if (position_sync_thread_.joinable()) position_sync_thread_.join();
  }

  // Master: Publish an event to replication stream
  void publish_event(StreamType type, const StreamEntry& entry) {
    if (mode_ != ReplicationMode::Master) return;

    std::lock_guard lock(mutex_);

    // Advance the stream position
    if (stream_manager_) {
      stream_manager_->advance_stream(type, entry.position);
    }

    // Broadcast via TCP to connected workers
    if (master_server_) {
      master_server_->broadcast_rdata(type, entry.position, entry.data);
    }

    // Push to Redis for Redis-connected workers
    if (redis_backend_ && redis_backend_->is_connected()) {
      master_server_->publish_to_redis(type, entry);
    }
  }

  // Master: Get list of registered workers
  nlohmann::json get_workers() {
    std::lock_guard lock(mutex_);
    nlohmann::json result = nlohmann::json::array();

    if (registry_) {
      for (auto& name : registry_->get_all_workers()) {
        nlohmann::json w;
        w["name"] = name;
        if (config_manager_ && config_manager_->has_worker(name)) {
          auto cfg = config_manager_->get_config(name);
          w["type"] = worker_type_name(cfg.type);
          w["host"] = cfg.worker_replication_host;
          w["port"] = cfg.worker_replication_port;
        }
        if (health_monitor_) {
          w["healthy"] = health_monitor_->is_healthy(name);
          w["ms_since_pong"] = health_monitor_->time_since_last_pong_ms(name);
        }
        result.push_back(w);
      }
    }
    return result;
  }

  // Get replication status
  nlohmann::json get_status() {
    std::lock_guard lock(mutex_);
    nlohmann::json status;
    status["mode"] = (mode_ == ReplicationMode::Master) ? "master" : "worker";
    status["worker_name"] = worker_name_;
    status["running"] = running_;

    if (mode_ == ReplicationMode::Master) {
      status["connected_workers"] = master_server_ ? master_server_->client_count() : 0;
      if (stream_manager_) {
        status["streams"] = stream_manager_->snapshot();
      }
    } else {
      if (replication_client_) {
        status["replication"] = replication_client_->get_stats();
      }
    }

    if (load_balancer_) {
      status["load_balancer"] = load_balancer_->get_stats();
    }

    return status;
  }

  // Master: Add a new worker configuration
  void add_worker_config(const std::string& name, const WorkerConfig& cfg) {
    std::lock_guard lock(mutex_);
    if (config_manager_) {
      config_manager_->set_config(name, cfg);
    }
  }

  // Master: Remove a worker configuration
  void remove_worker_config(const std::string& name) {
    std::lock_guard lock(mutex_);
    if (config_manager_) {
      config_manager_->remove_config(name);
    }
  }

  // Get stream manager (for master)
  StreamManager* get_stream_manager() {
    return stream_manager_.get();
  }

  // Get worker registry
  WorkerRegistry* get_registry() {
    return registry_.get();
  }

  // Get health monitor
  WorkerHealthMonitor* get_health_monitor() {
    return health_monitor_.get();
  }

  // Get load balancer
  WorkerLoadBalancer* get_load_balancer() {
    return load_balancer_.get();
  }

  // Get config manager
  WorkerConfigManager* get_config_manager() {
    return config_manager_.get();
  }

  // Worker: Get the appropriate specialized worker
  GenericWorker* get_generic_worker() { return generic_worker_.get(); }
  PusherWorker* get_pusher_worker() { return pusher_worker_.get(); }
  FederationSenderWorker* get_federation_worker() { return federation_worker_.get(); }
  MediaRepositoryWorker* get_media_worker() { return media_worker_.get(); }
  AppserviceWorker* get_appservice_worker() { return appservice_worker_.get(); }
  UserDirWorker* get_userdir_worker() { return userdir_worker_.get(); }
  SynchrotronWorker* get_synchrotron_worker() { return synchrotron_worker_.get(); }
  WorkerReplicationClient* get_replication_client() { return replication_client_.get(); }

  // Check if running
  bool is_running() const { return running_; }

  // Get replication mode
  ReplicationMode get_mode() const { return mode_; }

  // Get worker name
  const std::string& get_worker_name() const { return worker_name_; }

  // Stream catch-up: replay events from a given position
  void request_catch_up(const std::set<StreamType>& streams,
                        int64_t from_position) {
    if (!replication_client_) return;

    for (auto st : streams) {
      replication_client_->send_position(st, from_position);
    }
  }

  // Master: force health check on a worker
  bool check_worker_health(const std::string& name) {
    if (!health_monitor_) return false;
    return health_monitor_->is_healthy(name);
  }

private:
  ReplicationMode mode_;
  std::string worker_name_;
  std::atomic<bool> running_;
  mutable std::mutex mutex_;

  // Master components
  std::unique_ptr<MasterReplicationServer> master_server_;
  std::unique_ptr<StreamManager> stream_manager_;
  std::unique_ptr<WorkerRegistry> registry_;
  std::unique_ptr<WorkerHealthMonitor> health_monitor_;
  std::unique_ptr<WorkerLoadBalancer> load_balancer_;
  std::unique_ptr<WorkerConfigManager> config_manager_;
  std::shared_ptr<RedisReplicationBackend> redis_backend_;

  // Worker components
  std::unique_ptr<WorkerReplicationClient> replication_client_;
  std::unique_ptr<GenericWorker> generic_worker_;
  std::unique_ptr<PusherWorker> pusher_worker_;
  std::unique_ptr<FederationSenderWorker> federation_worker_;
  std::unique_ptr<MediaRepositoryWorker> media_worker_;
  std::unique_ptr<AppserviceWorker> appservice_worker_;
  std::unique_ptr<UserDirWorker> userdir_worker_;
  std::unique_ptr<SynchrotronWorker> synchrotron_worker_;

  // Threads
  std::thread maintenance_thread_;
  std::thread position_sync_thread_;

  // Callback: Worker received replication entry
  void on_replication_entry(const StreamEntry& entry) {
    // Route to appropriate specialized worker
    if (generic_worker_ && generic_worker_->is_running()) {
      // Generic worker consumes all streams
    }
    if (pusher_worker_ && pusher_worker_->is_running()) {
      pusher_worker_->on_stream_entry(entry);
    }
    if (federation_worker_ && federation_worker_->is_running()) {
      federation_worker_->on_stream_entry(entry);
    }
    if (media_worker_ && media_worker_->is_running()) {
      // Media worker handles events
    }
    if (appservice_worker_ && appservice_worker_->is_running()) {
      appservice_worker_->on_stream_entry(entry);
    }
    if (userdir_worker_ && userdir_worker_->is_running()) {
      userdir_worker_->on_stream_entry(entry);
    }
    if (synchrotron_worker_ && synchrotron_worker_->is_running()) {
      synchrotron_worker_->on_stream_entry(entry);
    }
  }

  // Callback: Replication error
  void on_replication_error(const std::string& error) {
    // Log error, attempt reconnection handled by client
    (void)error;
  }

  // Callback: Worker became unhealthy
  void on_worker_unhealthy(const std::string& worker) {
    // Log and potentially rebalance
    if (load_balancer_) {
      load_balancer_->unregister_worker(worker);
    }
  }

  // Callback: Worker recovered
  void on_worker_recovered(const std::string& worker) {
    if (config_manager_ && config_manager_->has_worker(worker)) {
      auto cfg = config_manager_->get_config(worker);
      if (load_balancer_) {
        load_balancer_->register_worker(worker, cfg.type);
      }
    }
  }

  // Handle Redis messages from workers
  void on_redis_worker_message(const std::string& channel,
                                 const std::string& message) {
    if (channel != REDIS_PUBSUB_CHANNEL) return;

    try {
      auto j = nlohmann::json::parse(message);
      std::string cmd = j.value("cmd", "");

      if (cmd == "POSITION" && stream_manager_) {
        std::string worker = j.value("worker", "");
        std::string stream = j.value("stream", "");
        int64_t pos = j.value("position", 0LL);

        try {
          auto st = stream_type_from_name(stream);
          stream_manager_->store_worker_position(worker, st, pos);
        } catch (...) {}
      }
    } catch (...) {
      // Invalid message
    }
  }

  // Master maintenance loop
  void maintenance_loop() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::seconds(30));

      // Periodic maintenance tasks for master
      if (mode_ == ReplicationMode::Master && load_balancer_) {
        // Reset load counters every 5 minutes
        static int counter = 0;
        counter++;
        if (counter >= 10) {
          load_balancer_->reset_loads();
          counter = 0;
        }
      }
    }
  }

  // Worker position sync loop
  void position_sync_loop() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::seconds(10));

      if (replication_client_ && replication_client_->is_connected()) {
        // No explicit sync needed for TCP mode; protocol handles it
        // For Redis, we send periodic position updates
      }
    }
  }
};

} // namespace progressive::worker
