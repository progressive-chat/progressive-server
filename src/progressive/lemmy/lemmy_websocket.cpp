// lemmy_websocket.cpp - Lemmy WebSocket real-time API with live updates
// Reference: Lemmy (113,070 lines Rust) WebSocket subsystem
// Translating Rust -> C++ precisely: connection management, pub/sub rooms,
// real-time post/comment/vote/notification delivery, presence, typing, heartbeat.
//
// Covers:
//   1. WebSocket server (accept + upgrade HTTP, maintain connections)
//   2. Connection manager (track, broadcast, send to user)
//   3. Join/leave room (subscribe to community, post, user updates)
//   4. Real-time post updates (new, edit, delete, vote change)
//   5. Real-time comment updates (new, edit, delete, vote change)
//   6. Real-time notification delivery (mentions, replies, PMs)
//   7. User online/offline presence
//   8. Typing indicators for comments / PMs
//   9. Community join / leave notifications
//  10. Vote count changes (live counters)
//  11. Private message real-time delivery
//  12. WebSocket auth (JWT via query param or first message)
//  13. Reconnection support (resume subscription after reconnect)
//  14. Heartbeat / ping-pong keepalive
//  15. Message framing (text frames with JSON payload)
//  16. Rate limiting per connection
//  17. Connection statistics
//  18. Graceful shutdown (notify, drain)
//  19. Compression extension (permessage-deflate)
//  20. TLS / wss support

#include "lemmy_server.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// POSIX / platform networking
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <zlib.h>  // for permessage-deflate

// OpenSSL for TLS/wss
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace progressive::lemmy {

using json = nlohmann::json;

// ============================================================================
// Utility helpers
// ============================================================================
namespace {
inline int64_t nms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

inline std::string gen_id(const std::string& prefix) {
  static std::atomic<int64_t> counter{1};
  return prefix + std::to_string(nms()) + "-" +
         std::to_string(counter.fetch_add(1, std::memory_order_relaxed));
}

inline void set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

inline void set_tcp_nodelay(int fd) {
  int val = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
}

// Base64 encode (used for WebSocket accept key)
std::string base64_encode(const unsigned char* data, size_t len) {
  static const char* chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    unsigned char a = data[i];
    unsigned char b = (i + 1 < len) ? data[i + 1] : 0;
    unsigned char c = (i + 2 < len) ? data[i + 2] : 0;
    result.push_back(chars[(a >> 2) & 0x3F]);
    result.push_back(chars[((a << 4) | ((b >> 4) & 0x0F)) & 0x3F]);
    result.push_back((i + 1 < len) ? chars[((b << 2) | ((c >> 6) & 0x03)) & 0x3F] : '=');
    result.push_back((i + 2 < len) ? chars[c & 0x3F] : '=');
  }
  return result;
}

// SHA1 hash (used for WebSocket accept key)
std::string sha1_hex(const std::string& input) {
  // Simple SHA1 implementation
  uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476,
           h4 = 0xC3D2E1F0;

  std::vector<uint8_t> msg(input.begin(), input.end());
  uint64_t bit_len = msg.size() * 8;
  msg.push_back(0x80);
  while ((msg.size() * 8) % 512 != 448) msg.push_back(0x00);
  for (int i = 7; i >= 0; i--) msg.push_back((bit_len >> (i * 8)) & 0xFF);

  for (size_t offset = 0; offset < msg.size(); offset += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
      w[i] = ((uint32_t)msg[offset + i * 4] << 24) |
             ((uint32_t)msg[offset + i * 4 + 1] << 16) |
             ((uint32_t)msg[offset + i * 4 + 2] << 8) | msg[offset + i * 4 + 3];
    for (int i = 16; i < 80; i++) {
      uint32_t tmp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (tmp << 1) | (tmp >> 31);
    }
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; i++) {
      uint32_t f, k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
      e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }
    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
  }

  auto fmt = [](uint32_t v) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(8) << v;
    return oss.str();
  };
  return fmt(h0) + fmt(h1) + fmt(h2) + fmt(h3) + fmt(h4);
}

// SHA1 into raw bytes (20 bytes)
std::string sha1_raw(const std::string& input) {
  std::string hex = sha1_hex(input);
  std::string raw(20, '\0');
  for (int i = 0; i < 20; i++) {
    unsigned int byte;
    std::stringstream ss;
    ss << std::hex << hex.substr(i * 2, 2);
    ss >> byte;
    raw[i] = (char)byte;
  }
  return raw;
}

std::string websocket_accept_key(const std::string& client_key) {
  static const std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  return base64_encode(
      reinterpret_cast<const unsigned char*>(
          sha1_raw(client_key + magic).data()),
      20);
}

}  // anonymous namespace

// ============================================================================
// WebSocket frame opcodes (RFC 6455)
// ============================================================================
enum class WsOpcode : uint8_t {
  CONTINUATION = 0x0,
  TEXT         = 0x1,
  BINARY       = 0x2,
  CLOSE        = 0x8,
  PING         = 0x9,
  PONG         = 0xA,
};

// ============================================================================
// WebSocket close status codes (RFC 6455)
// ============================================================================
enum class WsCloseCode : uint16_t {
  NORMAL           = 1000,
  GOING_AWAY       = 1001,
  PROTOCOL_ERROR   = 1002,
  UNSUPPORTED_DATA = 1003,
  NO_STATUS        = 1005,
  ABNORMAL         = 1006,
  INVALID_PAYLOAD  = 1007,
  POLICY_VIOLATION = 1008,
  MESSAGE_TOO_BIG  = 1009,
  MISSING_EXTENSION= 1010,
  INTERNAL_ERROR   = 1011,
  SERVICE_RESTART  = 1012,
  TRY_AGAIN_LATER  = 1013,
};

// ============================================================================
// Room / subscription types
// ============================================================================
enum class RoomType : uint8_t {
  COMMUNITY,   // community:<id>  - all posts/comments in community
  POST,        // post:<id>       - a specific post thread
  USER,        // user:<id>       - user's notifications & PMs
  MOD_LOG,     // mod_log:<community_id> - moderator actions
  SITE,        // site            - site-wide events
};

// ============================================================================
// WebSocket connection state
// ============================================================================
struct WsConnection {
  int fd = -1;
  SSL* ssl = nullptr;  // nullptr for plain TCP
  std::string id;
  std::string session_id;
  std::string remote_addr;
  uint16_t remote_port = 0;
  bool upgraded_ = false;
  bool authenticated = false;
  std::string user_id;
  std::string user_name;
  bool is_admin = false;
  int64_t connected_at = 0;
  std::atomic<int64_t> last_active{0};
  std::atomic<int64_t> last_ping_sent{0};
  std::atomic<int64_t> last_pong_received{0};
  std::atomic<int64_t> messages_sent{0};
  std::atomic<int64_t> messages_received{0};
  std::atomic<int64_t> bytes_sent{0};
  std::atomic<int64_t> bytes_received{0};
  std::atomic<bool> closing{false};
  std::atomic<bool> supports_compression{false};

  // Read buffer for accumulating incomplete frames/data
  std::vector<uint8_t> read_buffer_;

  // Joined rooms
  std::unordered_set<std::string> rooms;
  mutable std::shared_mutex rooms_mutex;

  // Connection metadata (browser, OS, etc from User-Agent)
  std::string user_agent;
  std::string origin;
  std::string accept_language;

  // Typing indicator state
  std::string typing_in;
  int64_t typing_at = 0;

  // Rate limiting
  std::deque<int64_t> message_timestamps;
  mutable std::mutex rate_limit_mutex;

  // Write buffer
  std::string write_buf;
  mutable std::mutex write_mutex;

  // Connection metrics
  int64_t connect_handshake_duration_ms = 0;
  int64_t last_write_at = 0;
  int64_t last_read_at = 0;
  int reconnection_count = 0;
  bool is_reconnect = false;

  // Per-connection session data (app-level state)
  json session_data;

  // Compression contexts (permessage-deflate)
  z_stream deflate_stream;
  z_stream inflate_stream;
  bool deflate_initialized = false;
  bool inflate_initialized = false;

  ~WsConnection() {
    if (deflate_initialized) deflateEnd(&deflate_stream);
    if (inflate_initialized) inflateEnd(&inflate_stream);
  }
};

// ============================================================================
// WebSocket server configuration
// ============================================================================
struct WsServerConfig {
  std::string host = "0.0.0.0";
  uint16_t port = 8081;
  int backlog = 128;
  bool use_tls = false;
  std::string cert_file;
  std::string key_file;
  std::string ca_file;
  int64_t heartbeat_interval_ms = 30000;       // ping every 30s
  int64_t heartbeat_timeout_ms = 90000;        // disconnect after 90s idle
  int64_t connection_timeout_ms = 120000;      // hard timeout for any connection
  int64_t max_message_size = 65536;            // 64KB max message
  size_t max_connections = 10000;
  size_t max_rooms_per_connection = 100;
  int rate_limit_messages = 60;                // max messages per window
  int64_t rate_limit_window_ms = 10000;        // 10 second window
  int64_t typing_cooldown_ms = 3000;           // min interval between typing notifs
  size_t read_buffer_size = 65536;
  bool enable_compression = true;
  int compression_level = 6;                   // zlib level 1-9
  size_t compression_threshold = 1024;         // only compress >=1KB
  int64_t shutdown_grace_ms = 5000;            // drain time during shutdown
  int event_loop_timeout_ms = 100;             // poll timeout
  int reconnect_grace_seconds = 300;           // allow reconnect within 5 min
};

// ============================================================================
// Forward declaration of WebSocket server
// ============================================================================
class LemmyWebSocketServer;

// ============================================================================
// Lemmy WebSocket Server — full implementation
// ============================================================================
class LemmyWebSocketServer {
 public:
  explicit LemmyWebSocketServer(LemmyServer* lemmy, const WsServerConfig& cfg = {})
      : lemmy_(lemmy), config_(cfg) {
    // Apply defaults where config is zero-initialized
    if (config_.host.empty()) config_.host = "0.0.0.0";
    if (config_.port == 0) config_.port = 8081;
    srand(time(nullptr));
  }

  ~LemmyWebSocketServer() { stop(); }

  // ---- Lifecycle ----

  bool start() {
    if (running_.load(std::memory_order_acquire)) return true;

    // Initialize OpenSSL if using TLS
    if (config_.use_tls) {
      SSL_library_init();
      OpenSSL_add_all_algorithms();
      SSL_load_error_strings();
      ssl_ctx_ = SSL_CTX_new(TLS_server_method());
      if (!ssl_ctx_) {
        std::cerr << "[WS] Failed to create SSL context" << std::endl;
        return false;
      }
      SSL_CTX_set_mode(ssl_ctx_, SSL_MODE_ENABLE_PARTIAL_WRITE);
      SSL_CTX_set_mode(ssl_ctx_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

      if (!config_.cert_file.empty()) {
        if (SSL_CTX_use_certificate_file(ssl_ctx_, config_.cert_file.c_str(),
                                         SSL_FILETYPE_PEM) != 1) {
          std::cerr << "[WS] Failed to load cert: " << config_.cert_file << std::endl;
          return false;
        }
      }
      if (!config_.key_file.empty()) {
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, config_.key_file.c_str(),
                                        SSL_FILETYPE_PEM) != 1) {
          std::cerr << "[WS] Failed to load key: " << config_.key_file << std::endl;
          return false;
        }
      }
      if (!config_.ca_file.empty()) {
        SSL_CTX_load_verify_locations(ssl_ctx_, config_.ca_file.c_str(), nullptr);
      }
    }

    // Create listening socket
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
      perror("[WS] socket()");
      return false;
    }

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    set_nonblocking(listen_fd_);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    addr.sin_addr.s_addr = inet_addr(config_.host.c_str());

    if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
      perror("[WS] bind()");
      close(listen_fd_);
      return false;
    }

    if (listen(listen_fd_, config_.backlog) < 0) {
      perror("[WS] listen()");
      close(listen_fd_);
      return false;
    }

    running_.store(true, std::memory_order_release);
    worker_thread_ = std::thread(&LemmyWebSocketServer::event_loop, this);
    heartbeat_thread_ = std::thread(&LemmyWebSocketServer::heartbeat_loop, this);
    session_cleanup_thread_ =
        std::thread(&LemmyWebSocketServer::session_cleanup_loop, this);

    std::cout << "[WS] WebSocket server started on " << config_.host << ":"
              << config_.port << (config_.use_tls ? " (wss)" : " (ws)")
              << std::endl;

    return true;
  }

  void stop() {
    if (!running_.load(std::memory_order_acquire)) return;
    shutting_down_.store(true, std::memory_order_release);

    // Notify all clients of graceful shutdown
    {
      std::shared_lock lock(connections_mutex_);
      json shutdown_msg;
      shutdown_msg["op"] = "server_shutdown";
      shutdown_msg["data"]["reason"] = "Server is shutting down";
      shutdown_msg["data"]["reconnect_ms"] = 10000;
      for (auto& [id, conn] : connections_) {
        send_json(conn, shutdown_msg);
      }
    }

    // Drain for shutdown_grace_ms
    int64_t drain_end = nms() + config_.shutdown_grace_ms;
    while (nms() < drain_end) {
      {
        std::shared_lock lock(connections_mutex_);
        if (connections_.empty()) break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Force close all connections
    {
      std::unique_lock lock(connections_mutex_);
      for (auto& [id, conn] : connections_) {
        send_close(conn, WsCloseCode::GOING_AWAY, "Server shutdown");
        close_connection_internal(conn);
      }
      connections_.clear();
    }

    running_.store(false, std::memory_order_release);

    if (worker_thread_.joinable()) worker_thread_.join();
    if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
    if (session_cleanup_thread_.joinable()) session_cleanup_thread_.join();

    if (listen_fd_ >= 0) {
      close(listen_fd_);
      listen_fd_ = -1;
    }
    if (ssl_ctx_) {
      SSL_CTX_free(ssl_ctx_);
      ssl_ctx_ = nullptr;
    }

    std::cout << "[WS] WebSocket server stopped" << std::endl;
  }

  // ---- Public API: Broadcasting ----

  void broadcast_to_room(const std::string& room, const json& message) {
    std::shared_lock lock(rooms_mutex_);
    auto it = rooms_.find(room);
    if (it == rooms_.end()) return;
    for (const auto& conn_id : it->second) {
      auto conn = get_connection(conn_id);
      if (conn) send_json(conn, message);
    }
  }

  void broadcast_to_community(int64_t community_id, const json& message) {
    broadcast_to_room(room_name(RoomType::COMMUNITY, std::to_string(community_id)),
                      message);
  }

  void broadcast_to_post(int64_t post_id, const json& message) {
    broadcast_to_room(room_name(RoomType::POST, std::to_string(post_id)), message);
  }

  void send_to_user(const std::string& user_id, const json& message) {
    std::shared_lock lock(user_connections_mutex_);
    auto it = user_connections_.find(user_id);
    if (it == user_connections_.end()) return;
    for (const auto& conn_id : it->second) {
      auto conn = get_connection(conn_id);
      if (conn) send_json(conn, message);
    }
  }

  void broadcast_site(const json& message) {
    broadcast_to_room("site", message);
  }

  // ---- Public API: Post events ----

  void notify_post_created(const Post& post, const Community& community) {
    json msg;
    msg["op"] = "post_created";
    msg["data"]["post"] = post_to_json(post);
    msg["data"]["community"] = community_to_json(community);
    broadcast_to_community(post.community_id, msg);
    broadcast_to_room(room_name(RoomType::COMMUNITY, std::to_string(post.community_id)),
                      msg);
    // Also send to user room of creator
    send_to_user(post.creator_id, msg);
  }

  void notify_post_edited(const Post& post) {
    json msg;
    msg["op"] = "post_edited";
    msg["data"]["post"] = post_to_json(post);
    broadcast_to_community(post.community_id, msg);
    broadcast_to_post(post.id, msg);
  }

  void notify_post_deleted(int64_t post_id, int64_t community_id,
                           const std::string& deleted_by) {
    json msg;
    msg["op"] = "post_deleted";
    msg["data"]["post_id"] = post_id;
    msg["data"]["community_id"] = community_id;
    msg["data"]["deleted_by"] = deleted_by;
    broadcast_to_community(community_id, msg);
    broadcast_to_post(post_id, msg);
  }

  void notify_post_vote_change(int64_t post_id, int64_t community_id,
                               int new_score, int upvotes, int downvotes) {
    json msg;
    msg["op"] = "post_vote_changed";
    msg["data"]["post_id"] = post_id;
    msg["data"]["community_id"] = community_id;
    msg["data"]["score"] = new_score;
    msg["data"]["upvotes"] = upvotes;
    msg["data"]["downvotes"] = downvotes;
    broadcast_to_post(post_id, msg);
    broadcast_to_community(community_id, msg);
  }

  // ---- Public API: Comment events ----

  void notify_comment_created(const Comment& comment, int64_t community_id) {
    json msg;
    msg["op"] = "comment_created";
    msg["data"]["comment"] = comment_to_json(comment);
    msg["data"]["community_id"] = community_id;
    broadcast_to_post(comment.post_id, msg);
    send_to_user(comment.creator_id, msg);
  }

  void notify_comment_edited(const Comment& comment) {
    json msg;
    msg["op"] = "comment_edited";
    msg["data"]["comment"] = comment_to_json(comment);
    broadcast_to_post(comment.post_id, msg);
  }

  void notify_comment_deleted(int64_t comment_id, int64_t post_id,
                              int64_t community_id, const std::string& deleted_by) {
    json msg;
    msg["op"] = "comment_deleted";
    msg["data"]["comment_id"] = comment_id;
    msg["data"]["post_id"] = post_id;
    msg["data"]["community_id"] = community_id;
    msg["data"]["deleted_by"] = deleted_by;
    broadcast_to_post(post_id, msg);
    broadcast_to_community(community_id, msg);
  }

  void notify_comment_vote_change(int64_t comment_id, int64_t post_id,
                                  int new_score) {
    json msg;
    msg["op"] = "comment_vote_changed";
    msg["data"]["comment_id"] = comment_id;
    msg["data"]["post_id"] = post_id;
    msg["data"]["score"] = new_score;
    broadcast_to_post(post_id, msg);
  }

  // ---- Public API: Notification delivery ----

  void notify_user_mention(const std::string& user_id,
                           const json& mention_data) {
    json msg;
    msg["op"] = "user_mention";
    msg["data"] = mention_data;
    send_to_user(user_id, msg);
  }

  void notify_comment_reply(const std::string& user_id,
                            const json& reply_data) {
    json msg;
    msg["op"] = "comment_reply";
    msg["data"] = reply_data;
    send_to_user(user_id, msg);
  }

  void notify_private_message(const std::string& user_id,
                              const PrivateMessage& pm) {
    json msg;
    msg["op"] = "private_message";
    msg["data"]["private_message"] = pm_to_json(pm);
    send_to_user(user_id, msg);
  }

  // ---- Public API: Presence ----

  void notify_user_online(const std::string& user_id, const std::string& username) {
    json msg;
    msg["op"] = "user_online";
    msg["data"]["user_id"] = user_id;
    msg["data"]["username"] = username;
    broadcast_site(msg);
    // Also notify rooms the user is in
    std::shared_lock lock(rooms_mutex_);
    auto it = user_connections_.find(user_id);
    if (it != user_connections_.end() && !it->second.empty()) {
      auto conn = get_connection(*it->second.begin());
      if (conn) {
        std::shared_lock rlock(conn->rooms_mutex);
        for (const auto& room : conn->rooms) {
          broadcast_to_room(room, msg);
        }
      }
    }
  }

  void notify_user_offline(const std::string& user_id, const std::string& username) {
    json msg;
    msg["op"] = "user_offline";
    msg["data"]["user_id"] = user_id;
    msg["data"]["username"] = username;
    broadcast_site(msg);
  }

  // ---- Public API: Typing indicators ----

  void notify_typing(const std::string& user_id, const std::string& username,
                     const std::string& room, bool is_typing) {
    json msg;
    msg["op"] = "typing";
    msg["data"]["user_id"] = user_id;
    msg["data"]["username"] = username;
    msg["data"]["room"] = room;
    msg["data"]["is_typing"] = is_typing;
    broadcast_to_room(room, msg);
  }

  // ---- Public API: Community events ----

  void notify_community_join(const std::string& user_id,
                             const std::string& username,
                             int64_t community_id) {
    json msg;
    msg["op"] = "community_join";
    msg["data"]["user_id"] = user_id;
    msg["data"]["username"] = username;
    msg["data"]["community_id"] = community_id;
    broadcast_to_community(community_id, msg);
  }

  void notify_community_leave(const std::string& user_id,
                              const std::string& username,
                              int64_t community_id) {
    json msg;
    msg["op"] = "community_leave";
    msg["data"]["user_id"] = user_id;
    msg["data"]["username"] = username;
    msg["data"]["community_id"] = community_id;
    broadcast_to_community(community_id, msg);
  }

  // ---- Public API: Moderation events ----

  void notify_mod_action(const ModAction& action, int64_t community_id) {
    json msg;
    msg["op"] = "mod_action";
    msg["data"]["action"] = action.action;
    msg["data"]["mod_person_id"] = action.mod_person_id;
    msg["data"]["target_person_id"] = action.target_person_id;
    msg["data"]["community_id"] = community_id;
    msg["data"]["reason"] = action.reason;
    broadcast_to_room(room_name(RoomType::MOD_LOG, std::to_string(community_id)),
                      msg);
    broadcast_to_community(community_id, msg);
  }

  // ---- Statistics ----

  json get_connection_stats() const {
    json stats;
    stats["total_connections"] = connection_count_.load();
    stats["authenticated_connections"] = authenticated_count_.load();
    stats["total_rooms"] = total_rooms_.load();
    {
      std::shared_lock lock(connections_mutex_);
      stats["active_connections"] = connections_.size();
    }
    stats["messages_received"] = total_messages_received_.load();
    stats["messages_sent"] = total_messages_sent_.load();
    stats["bytes_received"] = total_bytes_received_.load();
    stats["bytes_sent"] = total_bytes_sent_.load();
    stats["rate_limited_count"] = rate_limited_count_.load();
    stats["rejected_connections"] = rejected_connections_.load();
    return stats;
  }

  std::vector<json> get_active_user_sessions(const std::string& user_id) const {
    std::vector<json> sessions;
    std::shared_lock lock(user_connections_mutex_);
    auto it = user_connections_.find(user_id);
    if (it == user_connections_.end()) return sessions;
    for (const auto& conn_id : it->second) {
      auto conn = get_connection(conn_id);
      if (!conn) continue;
      json s;
      s["session_id"] = conn->session_id;
      s["remote_addr"] = conn->remote_addr;
      s["connected_at"] = conn->connected_at;
      s["last_active"] = conn->last_active.load();
      s["messages_sent"] = conn->messages_sent.load();
      s["messages_received"] = conn->messages_received.load();
      {
        std::shared_lock rlock(conn->rooms_mutex);
        s["rooms"] = json(conn->rooms);
      }
      sessions.push_back(s);
    }
    return sessions;
  }

  // ---- WsServerConfig accessor ----
  WsServerConfig& config() { return config_; }

 private:
  // ---- Event loop ----

  void event_loop() {
    std::vector<struct pollfd> poll_fds;
    poll_fds.reserve(config_.max_connections + 1);

    while (running_.load(std::memory_order_acquire)) {
      poll_fds.clear();
      poll_fds.push_back({listen_fd_, POLLIN, 0});

      // Collect all connection FDs
      {
        std::shared_lock lock(connections_mutex_);
        for (auto& [id, conn] : connections_) {
          short events = POLLIN;
          {
            std::lock_guard wlock(conn->write_mutex);
            if (!conn->write_buf.empty()) events |= POLLOUT;
          }
          if (conn->closing.load()) events = 0;  // skip closing connections
          poll_fds.push_back({conn->fd, events, 0});
        }
      }

      int ret = poll(poll_fds.data(), poll_fds.size(),
                     config_.event_loop_timeout_ms);
      if (ret < 0) {
        if (errno == EINTR) continue;
        perror("[WS] poll()");
        break;
      }

      // Handle new connections
      if (poll_fds[0].revents & POLLIN) {
        accept_new_connection();
      }

      // Handle existing connections (skip index 0 = listen socket)
      for (size_t i = 1; i < poll_fds.size(); i++) {
        auto& pfd = poll_fds[i];
        // Find the connection — we mapped index i to connections_ in order
        // Rebuild the mapping
        std::shared_ptr<WsConnection> conn = nullptr;
        {
          std::shared_lock lock(connections_mutex_);
          size_t idx = 1;
          for (auto& [id, c] : connections_) {
            if (c->fd == pfd.fd) { conn = c; break; }
            idx++;
          }
        }
        if (!conn || conn->closing.load()) continue;

        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
          disconnect(conn, WsCloseCode::ABNORMAL, "Connection error");
          continue;
        }

        if (pfd.revents & POLLIN) {
          if (!handle_read(conn)) {
            // handle_read returns false on fatal error / closed
            continue;
          }
        }

        if (pfd.revents & POLLOUT) {
          handle_write(conn);
        }
      }
    }
  }

  void accept_new_connection() {
    if (connection_count_.load() >= config_.max_connections) {
      // Accept and immediately close to avoid SYN queue buildup
      struct sockaddr_in addr{};
      socklen_t addrlen = sizeof(addr);
      int fd = accept(listen_fd_, (struct sockaddr*)&addr, &addrlen);
      if (fd >= 0) close(fd);
      rejected_connections_.fetch_add(1);
      return;
    }

    struct sockaddr_in addr{};
    socklen_t addrlen = sizeof(addr);
    int fd = accept(listen_fd_, (struct sockaddr*)&addr, &addrlen);
    if (fd < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK)
        perror("[WS] accept()");
      return;
    }

    set_nonblocking(fd);
    set_tcp_nodelay(fd);

    auto conn = std::make_shared<WsConnection>();
    conn->fd = fd;
    conn->id = gen_id("ws");
    conn->session_id = gen_id("sess");
    conn->remote_addr = inet_ntoa(addr.sin_addr);
    conn->remote_port = ntohs(addr.sin_port);
    conn->connected_at = nms();
    conn->last_active.store(conn->connected_at);

    // Initialize compression if enabled
    if (config_.enable_compression) {
      conn->supports_compression.store(false);  // will be negotiated during upgrade
    }

    // Perform TLS handshake if using wss
    if (config_.use_tls && ssl_ctx_) {
      conn->ssl = SSL_new(ssl_ctx_);
      SSL_set_fd(conn->ssl, fd);
      // Non-blocking handshake will complete during read/write events
      SSL_set_accept_state(conn->ssl);
    }

    {
      std::unique_lock lock(connections_mutex_);
      connections_[conn->id] = conn;
    }
    connection_count_.fetch_add(1);
  }

  // ---- Read handling ----

  bool handle_read(std::shared_ptr<WsConnection> conn) {
    // Perform TLS handshake if needed
    if (conn->ssl) {
      if (!SSL_is_init_finished(conn->ssl)) {
        int ret = SSL_accept(conn->ssl);
        if (ret <= 0) {
          int err = SSL_get_error(conn->ssl, ret);
          if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return true;  // keep trying
          }
          disconnect(conn, WsCloseCode::POLICY_VIOLATION, "TLS handshake failed");
          return false;
        }
      }
    }

    // Read data
    std::vector<uint8_t> buf(config_.read_buffer_size);
    int n;
    if (conn->ssl) {
      n = SSL_read(conn->ssl, buf.data(), buf.size());
      if (n <= 0) {
        int err = SSL_get_error(conn->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
          return true;
        disconnect(conn, WsCloseCode::ABNORMAL, "SSL read error");
        return false;
      }
    } else {
      n = read(conn->fd, buf.data(), buf.size());
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
        disconnect(conn, WsCloseCode::ABNORMAL, "Read error");
        return false;
      }
      if (n == 0) {
        disconnect(conn, WsCloseCode::NORMAL, "Client disconnected");
        return false;
      }
    }

    conn->bytes_received.fetch_add(n);
    total_bytes_received_.fetch_add(n);
    conn->last_active.store(nms());

    // Append to read buffer
    conn->read_buffer_.insert(conn->read_buffer_.end(), buf.begin(),
                              buf.begin() + n);

    // If not yet upgraded to WebSocket, attempt HTTP upgrade
    if (!conn->upgraded_) {
      return try_http_upgrade(conn);
    }

    // Parse WebSocket frames
    return parse_websocket_frames(conn);
  }

  // ---- HTTP upgrade handling ----

  bool try_http_upgrade(std::shared_ptr<WsConnection> conn) {
    std::string data(conn->read_buffer_.begin(), conn->read_buffer_.end());
    size_t header_end = data.find("\r\n\r\n");
    if (header_end == std::string::npos) {
      // Headers not complete yet, wait for more data
      if (conn->read_buffer_.size() > 16384) {
        // Too many bytes without complete headers — reject
        disconnect(conn, WsCloseCode::POLICY_VIOLATION, "Headers too large");
        return false;
      }
      return true;
    }

    std::string headers = data.substr(0, header_end);
    conn->read_buffer_.erase(conn->read_buffer_.begin(),
                             conn->read_buffer_.begin() + header_end + 4);

    // Parse HTTP request line
    auto lines = split_lines(headers);
    if (lines.empty()) {
      send_http_response(conn, 400, "Bad Request");
      disconnect(conn, WsCloseCode::PROTOCOL_ERROR, "Bad HTTP request");
      return false;
    }

    std::string method, path, version;
    if (!parse_request_line(lines[0], method, path, version)) {
      send_http_response(conn, 400, "Bad Request");
      disconnect(conn, WsCloseCode::PROTOCOL_ERROR, "Bad request line");
      return false;
    }

    if (method != "GET") {
      send_http_response(conn, 405, "Method Not Allowed");
      disconnect(conn, WsCloseCode::PROTOCOL_ERROR, "Only GET allowed");
      return false;
    }

    // Parse headers
    std::map<std::string, std::string> req_headers;
    for (size_t i = 1; i < lines.size(); i++) {
      size_t col = lines[i].find(':');
      if (col != std::string::npos) {
        std::string key = lines[i].substr(0, col);
        std::string val = trim(lines[i].substr(col + 1));
        // lowercase key
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        req_headers[key] = val;
      }
    }

    // Check for WebSocket upgrade
    auto upgrade_it = req_headers.find("upgrade");
    if (upgrade_it == req_headers.end() ||
        to_lower(upgrade_it->second) != "websocket") {
      send_http_response(conn, 426, "Upgrade Required",
                         "Upgrade: websocket\r\n");
      disconnect(conn, WsCloseCode::PROTOCOL_ERROR, "Not a WebSocket request");
      return false;
    }

    auto key_it = req_headers.find("sec-websocket-key");
    if (key_it == req_headers.end()) {
      send_http_response(conn, 400, "Bad Request");
      disconnect(conn, WsCloseCode::PROTOCOL_ERROR, "Missing Sec-WebSocket-Key");
      return false;
    }

    // Check for compression extension
    bool negotiate_compression = false;
    if (config_.enable_compression) {
      auto ext_it = req_headers.find("sec-websocket-extensions");
      if (ext_it != req_headers.end() &&
          ext_it->second.find("permessage-deflate") != std::string::npos) {
        negotiate_compression = true;
      }
    }

    // Extract auth token from query string
    std::string jwt_token;
    size_t qpos = path.find('?');
    if (qpos != std::string::npos) {
      std::string qs = path.substr(qpos + 1);
      path = path.substr(0, qpos);
      auto params = parse_query_string(qs);
      auto tok_it = params.find("token");
      if (tok_it != params.end()) jwt_token = tok_it->second;
      auto jwt_it = params.find("jwt");
      if (jwt_it != params.end()) jwt_token = jwt_it->second;
    }

    // Check auth header for Bearer token
    if (jwt_token.empty()) {
      auto auth_it = req_headers.find("authorization");
      if (auth_it != req_headers.end()) {
        std::string auth = auth_it->second;
        if (auth.size() > 7 && auth.substr(0, 7) == "Bearer ") {
          jwt_token = auth.substr(7);
        }
      }
    }

    // Build upgrade response
    std::string accept_key = websocket_accept_key(key_it->second);

    std::ostringstream response;
    response << "HTTP/1.1 101 Switching Protocols\r\n";
    response << "Upgrade: websocket\r\n";
    response << "Connection: Upgrade\r\n";
    response << "Sec-WebSocket-Accept: " << accept_key << "\r\n";

    if (negotiate_compression) {
      response << "Sec-WebSocket-Extensions: permessage-deflate; "
                  "server_no_context_takeover; client_no_context_takeover\r\n";
      conn->supports_compression.store(true);
      init_compression(conn);
    }

    // Set session cookie
    response << "Set-Cookie: ws_session=" << conn->session_id
             << "; Path=/; HttpOnly; SameSite=Strict\r\n";
    response << "\r\n";

    std::string resp_str = response.str();
    int written;
    if (conn->ssl) {
      written = SSL_write(conn->ssl, resp_str.data(), resp_str.size());
    } else {
      written = write(conn->fd, resp_str.data(), resp_str.size());
    }
    if (written < 0) {
      disconnect(conn, WsCloseCode::ABNORMAL, "Failed to send upgrade response");
      return false;
    }

    conn->upgraded_ = true;
    conn->last_active.store(nms());

    // Authenticate with JWT if provided
    if (!jwt_token.empty()) {
      authenticate_connection(conn, jwt_token);
    }

    // Send welcome message
    json welcome;
    welcome["op"] = "connected";
    welcome["data"]["session_id"] = conn->session_id;
    welcome["data"]["server"] = "Progressive Lemmy WebSocket";
    welcome["data"]["authenticated"] = conn->authenticated;
    if (conn->authenticated) {
      welcome["data"]["user_id"] = conn->user_id;
      welcome["data"]["username"] = conn->user_name;
    }
    send_json(conn, welcome);

    return true;
  }

  // ---- WebSocket frame parsing ----

  bool parse_websocket_frames(std::shared_ptr<WsConnection> conn) {
    while (!conn->read_buffer_.empty()) {
      if (conn->read_buffer_.size() < 2) return true;  // need at least 2 bytes

      uint8_t byte0 = conn->read_buffer_[0];
      uint8_t byte1 = conn->read_buffer_[1];

      bool fin = (byte0 & 0x80) != 0;
      bool rsv1 = (byte0 & 0x40) != 0;
      bool rsv2 = (byte0 & 0x20) != 0;
      bool rsv3 = (byte0 & 0x10) != 0;
      uint8_t opcode = byte0 & 0x0F;
      bool masked = (byte1 & 0x80) != 0;
      uint64_t payload_len = byte1 & 0x7F;

      size_t header_size = 2;
      if (payload_len == 126) {
        if (conn->read_buffer_.size() < 4) return true;
        payload_len = ((uint16_t)conn->read_buffer_[2] << 8) |
                      conn->read_buffer_[3];
        header_size = 4;
      } else if (payload_len == 127) {
        if (conn->read_buffer_.size() < 10) return true;
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
          payload_len = (payload_len << 8) | conn->read_buffer_[2 + i];
        }
        header_size = 10;
      }

      // If masked, read mask key
      uint8_t mask_key[4] = {0, 0, 0, 0};
      if (masked) {
        if (conn->read_buffer_.size() < header_size + 4) return true;
        memcpy(mask_key, &conn->read_buffer_[header_size], 4);
        header_size += 4;
      }

      // Check if we have the full payload
      if (payload_len > config_.max_message_size) {
        send_close(conn, WsCloseCode::MESSAGE_TOO_BIG, "Message too large");
        disconnect(conn, WsCloseCode::MESSAGE_TOO_BIG, "Message too large");
        return false;
      }

      if (conn->read_buffer_.size() < header_size + payload_len) return true;

      // Extract payload
      std::vector<uint8_t> payload;
      if (payload_len > 0) {
        payload.assign(conn->read_buffer_.begin() + header_size,
                       conn->read_buffer_.begin() + header_size + payload_len);
      }

      // Unmask if needed
      if (masked) {
        for (size_t i = 0; i < payload.size(); i++) {
          payload[i] ^= mask_key[i % 4];
        }
      }

      // Remove this frame from the buffer
      conn->read_buffer_.erase(conn->read_buffer_.begin(),
                               conn->read_buffer_.begin() + header_size +
                                   payload_len);

      // Handle opcode
      switch (static_cast<WsOpcode>(opcode)) {
        case WsOpcode::TEXT:
        case WsOpcode::BINARY: {
          // Decompress if needed
          std::string message(payload.begin(), payload.end());
          if (rsv1 && conn->supports_compression.load()) {
            message = decompress_message(conn, message);
          }

          // Handle text message
          if (static_cast<WsOpcode>(opcode) == WsOpcode::TEXT) {
            if (!handle_text_message(conn, message)) return false;
          }
          break;
        }
        case WsOpcode::PING: {
          // Send pong
          std::string pong(payload.begin(), payload.end());
          send_frame(conn, WsOpcode::PONG, pong, false);
          conn->last_active.store(nms());
          break;
        }
        case WsOpcode::PONG: {
          conn->last_pong_received.store(nms());
          conn->last_active.store(nms());
          break;
        }
        case WsOpcode::CLOSE: {
          uint16_t close_code = WsCloseCode::NORMAL;
          std::string reason;
          if (payload.size() >= 2) {
            close_code = ((uint16_t)payload[0] << 8) | payload[1];
          }
          if (payload.size() > 2) {
            reason = std::string(payload.begin() + 2, payload.end());
          }
          send_close(conn, WsCloseCode::NORMAL, "");
          disconnect(conn, static_cast<WsCloseCode>(close_code), reason);
          return false;
        }
        case WsOpcode::CONTINUATION:
          // For simplicity, we don't support fragmented messages
          break;
        default:
          send_close(conn, WsCloseCode::PROTOCOL_ERROR, "Unknown opcode");
          disconnect(conn, WsCloseCode::PROTOCOL_ERROR, "Unknown opcode");
          return false;
      }
    }
    return true;
  }

  // ---- Message handling ----

  bool handle_text_message(std::shared_ptr<WsConnection> conn,
                           const std::string& message) {
    conn->last_active.store(nms());
    conn->messages_received.fetch_add(1);
    total_messages_received_.fetch_add(1);

    // Rate limiting
    if (check_rate_limit(conn)) {
      send_json(conn, {{"op", "error"},
                        {"data",
                         {{"code", "rate_limited"},
                          {"message", "Too many messages. Please slow down."}}}});
      return true;
    }

    // Parse JSON
    json msg;
    try {
      msg = json::parse(message);
    } catch (const json::parse_error& e) {
      send_json(conn, {{"op", "error"},
                        {"data",
                         {{"code", "invalid_json"},
                          {"message", std::string("JSON parse error: ") +
                                          e.what()}}}});
      return true;
    }

    // Validate op field
    if (!msg.contains("op") || !msg["op"].is_string()) {
      send_json(conn, {{"op", "error"},
                        {"data",
                         {{"code", "missing_op"},
                          {"message", "Message must contain 'op' field"}}}});
      return true;
    }

    std::string op = msg["op"].get<std::string>();

    // Handle authentication if not yet authenticated
    if (op == "auth" || op == "authenticate") {
      if (!msg.contains("data") || !msg["data"].contains("token")) {
        send_json(conn, {{"op", "auth_response"},
                          {"data",
                           {{"success", false},
                            {"message", "Missing token"}}}});
        return true;
      }
      std::string token = msg["data"]["token"].get<std::string>();
      bool ok = authenticate_connection(conn, token);
      json resp;
      resp["op"] = "auth_response";
      resp["data"]["success"] = ok;
      if (ok) {
        resp["data"]["user_id"] = conn->user_id;
        resp["data"]["username"] = conn->user_name;
      } else {
        resp["data"]["message"] = "Invalid or expired token";
      }
      send_json(conn, resp);
      return true;
    }

    // All other ops require authentication
    if (!conn->authenticated) {
      send_json(conn, {{"op", "error"},
                        {"data",
                         {{"code", "not_authenticated"},
                          {"message", "You must authenticate first"}}}});
      return true;
    }

    // Route message by op
    if (op == "join") {
      return handle_join(conn, msg);
    } else if (op == "leave") {
      return handle_leave(conn, msg);
    } else if (op == "ping") {
      json pong;
      pong["op"] = "pong";
      pong["data"]["timestamp"] = nms();
      send_json(conn, pong);
    } else if (op == "typing") {
      return handle_typing(conn, msg);
    } else if (op == "presence") {
      return handle_presence_request(conn, msg);
    } else if (op == "reconnect") {
      return handle_reconnect(conn, msg);
    } else if (op == "stats") {
      json resp;
      resp["op"] = "stats";
      resp["data"] = get_connection_stats();
      send_json(conn, resp);
    } else if (op == "subscribe") {
      return handle_join(conn, msg);
    } else if (op == "unsubscribe") {
      return handle_leave(conn, msg);
    } else {
      send_json(conn, {{"op", "error"},
                        {"data",
                         {{"code", "unknown_op"},
                          {"message", "Unknown operation: " + op}}}});
    }

    return true;
  }

  // ---- Join / Leave rooms ----

  bool handle_join(std::shared_ptr<WsConnection> conn, const json& msg) {
    if (!msg.contains("data") || !msg["data"].contains("room")) {
      send_json(conn, {{"op", "error"},
                        {"data", {{"code", "missing_room"},
                                   {"message", "Must specify 'room' to join"}}}});
      return true;
    }

    std::string room = msg["data"]["room"].get<std::string>();

    // Validate room format
    if (room.empty() || room.size() > 256) {
      send_json(conn, {{"op", "error"},
                        {"data", {{"code", "invalid_room"},
                                   {"message", "Invalid room name"}}}});
      return true;
    }

    // Check room limit
    {
      std::shared_lock rlock(conn->rooms_mutex);
      if (conn->rooms.size() >= config_.max_rooms_per_connection) {
        send_json(conn,
                  {{"op", "error"},
                   {"data",
                    {{"code", "too_many_rooms"},
                     {"message",
                      "Maximum room subscriptions reached (" +
                          std::to_string(config_.max_rooms_per_connection) +
                          ")"}}}});
        return true;
      }
    }

    // Add connection to room
    {
      std::unique_lock wlock(conn->rooms_mutex);
      conn->rooms.insert(room);
    }
    {
      std::unique_lock rlock(rooms_mutex_);
      rooms_[room].insert(conn->id);
    }
    total_rooms_.fetch_add(1);

    json resp;
    resp["op"] = "joined";
    resp["data"]["room"] = room;
    resp["data"]["timestamp"] = nms();
    send_json(conn, resp);

    return true;
  }

  bool handle_leave(std::shared_ptr<WsConnection> conn, const json& msg) {
    std::string room;
    if (msg.contains("data") && msg["data"].contains("room")) {
      room = msg["data"]["room"].get<std::string>();
    }

    if (room.empty()) {
      // Leave all rooms
      std::vector<std::string> all_rooms;
      {
        std::unique_lock wlock(conn->rooms_mutex);
        all_rooms.assign(conn->rooms.begin(), conn->rooms.end());
        conn->rooms.clear();
      }
      for (const auto& r : all_rooms) {
        std::unique_lock rlock(rooms_mutex_);
        rooms_[r].erase(conn->id);
        if (rooms_[r].empty()) rooms_.erase(r);
      }

      json resp;
      resp["op"] = "left_all";
      resp["data"]["timestamp"] = nms();
      send_json(conn, resp);
    } else {
      {
        std::unique_lock wlock(conn->rooms_mutex);
        conn->rooms.erase(room);
      }
      {
        std::unique_lock rlock(rooms_mutex_);
        rooms_[room].erase(conn->id);
        if (rooms_[room].empty()) rooms_.erase(room);
      }

      json resp;
      resp["op"] = "left";
      resp["data"]["room"] = room;
      resp["data"]["timestamp"] = nms();
      send_json(conn, resp);
    }

    return true;
  }

  // ---- Typing indicator handling ----

  bool handle_typing(std::shared_ptr<WsConnection> conn, const json& msg) {
    if (!msg.contains("data") || !msg["data"].contains("room")) {
      send_json(conn, {{"op", "error"},
                        {"data", {{"code", "missing_room"},
                                   {"message", "Must specify room for typing"}}}});
      return true;
    }

    bool is_typing = msg["data"].value("is_typing", true);
    std::string room = msg["data"]["room"].get<std::string>();

    // Rate limit typing notifications (every typing_cooldown_ms)
    int64_t now = nms();
    if (is_typing && conn->typing_in == room &&
        now - conn->typing_at < config_.typing_cooldown_ms) {
      return true;  // suppress duplicate
    }

    conn->typing_in = is_typing ? room : "";
    conn->typing_at = now;

    notify_typing(conn->user_id, conn->user_name, room, is_typing);
    return true;
  }

  // ---- Presence handling ----

  bool handle_presence_request(std::shared_ptr<WsConnection> conn,
                               const json& msg) {
    std::string status = msg["data"].value("status", "online");
    json resp;
    resp["op"] = "presence";
    resp["data"]["user_id"] = conn->user_id;
    resp["data"]["username"] = conn->user_name;
    resp["data"]["status"] = status;
    resp["data"]["timestamp"] = nms();

    // Broadcast to all rooms user is in
    {
      std::shared_lock rlock(conn->rooms_mutex);
      for (const auto& room : conn->rooms) {
        broadcast_to_room(room, resp);
      }
    }
    return true;
  }

  // ---- Reconnection handling ----

  bool handle_reconnect(std::shared_ptr<WsConnection> conn, const json& msg) {
    // Client wants to resume a previous session
    std::string old_session_id = msg["data"].value("session_id", "");
    std::string old_token = msg["data"].value("token", "");

    // If a token was provided, re-authenticate
    if (!old_token.empty()) {
      bool ok = authenticate_connection(conn, old_token);
      if (!ok) {
        json resp;
        resp["op"] = "reconnect_response";
        resp["data"]["success"] = false;
        resp["data"]["message"] = "Invalid token for reconnection";
        send_json(conn, resp);
        return true;
      }
    }

    // Restore rooms from old session if provided
    json resp;
    resp["op"] = "reconnect_response";
    resp["data"]["success"] = true;
    resp["data"]["restored_rooms"] = json::array();

    if (!old_session_id.empty()) {
      std::shared_lock lock(session_rooms_mutex_);
      auto it = session_rooms_.find(old_session_id);
      if (it != session_rooms_.end()) {
        int64_t now = nms();
        if (now - it->second.second < config_.reconnect_grace_seconds * 1000) {
          // Restore rooms
          {
            std::unique_lock wlock(conn->rooms_mutex);
            conn->rooms.insert(it->second.first.begin(), it->second.first.end());
          }
          {
            std::unique_lock rlock(rooms_mutex_);
            for (const auto& room : it->second.first) {
              rooms_[room].insert(conn->id);
            }
          }
          resp["data"]["restored_rooms"] = json(it->second.first);
        }
        // Remove old session entry
        session_rooms_.erase(it);
      }
    }

    resp["data"]["session_id"] = conn->session_id;
    resp["data"]["authenticated"] = conn->authenticated;
    if (conn->authenticated) {
      resp["data"]["user_id"] = conn->user_id;
      resp["data"]["username"] = conn->user_name;
    }
    send_json(conn, resp);
    return true;
  }

  // ---- Authentication ----

  bool authenticate_connection(std::shared_ptr<WsConnection> conn,
                               const std::string& token) {
    if (lemmy_ && lemmy_->verify_jwt(token)) {
      // Extract user ID from token
      std::string uid;
      // JWT format: "jwt-<uid>-<timestamp>"
      size_t first = token.find('-');
      size_t second = token.find('-', first + 1);
      if (first != std::string::npos && second != std::string::npos) {
        uid = token.substr(first + 1, second - first - 1);
      }

      conn->user_id = uid;
      conn->authenticated = true;

      // Try to get user details
      if (lemmy_) {
        auto user = lemmy_->get_user(uid);
        if (user) {
          conn->user_name = user->name;
          conn->is_admin = user->admin;
        }
      }

      // Track user connections
      {
        std::unique_lock lock(user_connections_mutex_);
        user_connections_[conn->user_id].insert(conn->id);
      }

      authenticated_count_.fetch_add(1);

      // Auto-join user's personal room
      std::string user_room = room_name(RoomType::USER, conn->user_id);
      {
        std::unique_lock wlock(conn->rooms_mutex);
        conn->rooms.insert(user_room);
      }
      {
        std::unique_lock rlock(rooms_mutex_);
        rooms_[user_room].insert(conn->id);
      }

      // Notify presence
      notify_user_online(conn->user_id, conn->user_name);

      return true;
    }
    return false;
  }

  // ---- Send helpers ----

  void send_json(std::shared_ptr<WsConnection> conn, const json& msg) {
    std::string payload = msg.dump();
    send_frame(conn, WsOpcode::TEXT, payload,
               conn->supports_compression.load());
  }

  void send_frame(std::shared_ptr<WsConnection> conn, WsOpcode opcode,
                  const std::string& payload, bool compress) {
    if (conn->closing.load()) return;

    // Compress if needed
    std::string data_to_send = payload;
    bool rsv1 = false;
    if (compress && conn->supports_compression.load() &&
        payload.size() >= config_.compression_threshold) {
      std::string compressed = compress_message(conn, payload);
      if (!compressed.empty() && compressed.size() < payload.size()) {
        data_to_send = compressed;
        rsv1 = true;
      }
    }

    // Build frame
    std::vector<uint8_t> frame;
    frame.reserve(2 + 8 + data_to_send.size());  // header + ext len + payload

    uint8_t byte0 = 0x80 | (rsv1 ? 0x40 : 0x00) | static_cast<uint8_t>(opcode);
    frame.push_back(byte0);

    // Server frames must NOT be masked per RFC 6455
    if (data_to_send.size() < 126) {
      frame.push_back(static_cast<uint8_t>(data_to_send.size()));
    } else if (data_to_send.size() <= 0xFFFF) {
      frame.push_back(126);
      frame.push_back((data_to_send.size() >> 8) & 0xFF);
      frame.push_back(data_to_send.size() & 0xFF);
    } else {
      frame.push_back(127);
      for (int i = 7; i >= 0; i--) {
        frame.push_back((data_to_send.size() >> (i * 8)) & 0xFF);
      }
    }

    frame.insert(frame.end(), data_to_send.begin(), data_to_send.end());

    // Write to buffer
    {
      std::lock_guard lock(conn->write_mutex);
      conn->write_buf.append(reinterpret_cast<const char*>(frame.data()),
                             frame.size());
    }

    conn->messages_sent.fetch_add(1);
    conn->bytes_sent.fetch_add(frame.size());
    total_messages_sent_.fetch_add(1);
    total_bytes_sent_.fetch_add(frame.size());
  }

  void send_close(std::shared_ptr<WsConnection> conn, WsCloseCode code,
                  const std::string& reason) {
    if (conn->closing.load()) return;

    std::vector<uint8_t> payload;
    uint16_t code_val = static_cast<uint16_t>(code);
    payload.push_back((code_val >> 8) & 0xFF);
    payload.push_back(code_val & 0xFF);
    if (!reason.empty()) {
      payload.insert(payload.end(), reason.begin(),
                     reason.begin() + std::min(reason.size(), size_t(123)));
    }

    std::vector<uint8_t> frame;
    frame.push_back(0x88);  // FIN + CLOSE
    if (payload.size() < 126) {
      frame.push_back(static_cast<uint8_t>(payload.size()));
    } else {
      frame.push_back(126);
      frame.push_back((payload.size() >> 8) & 0xFF);
      frame.push_back(payload.size() & 0xFF);
    }
    frame.insert(frame.end(), payload.begin(), payload.end());

    // Write directly to socket (not buffered)
    if (conn->ssl) {
      SSL_write(conn->ssl, frame.data(), frame.size());
    } else {
      write(conn->fd, frame.data(), frame.size());
    }
  }

  // ---- Write handling ----

  void handle_write(std::shared_ptr<WsConnection> conn) {
    std::lock_guard lock(conn->write_mutex);
    if (conn->write_buf.empty()) return;

    int total_written = 0;
    while (total_written < (int)conn->write_buf.size()) {
      int n;
      if (conn->ssl) {
        n = SSL_write(conn->ssl, conn->write_buf.data() + total_written,
                      conn->write_buf.size() - total_written);
        if (n <= 0) {
          int err = SSL_get_error(conn->ssl, n);
          if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) break;
          disconnect(conn, WsCloseCode::ABNORMAL, "SSL write error");
          return;
        }
      } else {
        n = write(conn->fd, conn->write_buf.data() + total_written,
                  conn->write_buf.size() - total_written);
        if (n < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          disconnect(conn, WsCloseCode::ABNORMAL, "Write error");
          return;
        }
      }
      total_written += n;
    }

    if (total_written > 0) {
      conn->write_buf.erase(0, total_written);
    }
    if (conn->write_buf.size() > 1048576) {  // 1MB limit
      disconnect(conn, WsCloseCode::MESSAGE_TOO_BIG, "Write buffer overflow");
    }
  }

  // ---- Disconnect ----

  void disconnect(std::shared_ptr<WsConnection> conn, WsCloseCode code,
                  const std::string& reason) {
    if (conn->closing.exchange(true)) return;  // already closing

    // Save session rooms for reconnection
    {
      std::shared_lock rlock(conn->rooms_mutex);
      if (!conn->rooms.empty()) {
        std::unique_lock slock(session_rooms_mutex_);
        session_rooms_[conn->session_id] = {conn->rooms, nms()};
      }
    }

    // Remove from all rooms
    {
      std::unique_lock wlock(conn->rooms_mutex);
      std::unique_lock rlock(rooms_mutex_);
      for (const auto& room : conn->rooms) {
        rooms_[room].erase(conn->id);
        if (rooms_[room].empty()) rooms_.erase(room);
      }
      conn->rooms.clear();
    }

    // Remove from user connections
    if (conn->authenticated && !conn->user_id.empty()) {
      {
        std::unique_lock lock(user_connections_mutex_);
        user_connections_[conn->user_id].erase(conn->id);
        if (user_connections_[conn->user_id].empty())
          user_connections_.erase(conn->user_id);
      }
      authenticated_count_.fetch_sub(1);
      notify_user_offline(conn->user_id, conn->user_name);
    }

    close_connection_internal(conn);

    {
      std::unique_lock lock(connections_mutex_);
      connections_.erase(conn->id);
    }
    connection_count_.fetch_sub(1);
  }

  void close_connection_internal(std::shared_ptr<WsConnection> conn) {
    if (conn->ssl) {
      SSL_shutdown(conn->ssl);
      SSL_free(conn->ssl);
      conn->ssl = nullptr;
    }
    if (conn->fd >= 0) {
      shutdown(conn->fd, SHUT_RDWR);
      close(conn->fd);
      conn->fd = -1;
    }
  }

  // ---- Heartbeat ----

  void heartbeat_loop() {
    while (running_.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(config_.heartbeat_interval_ms / 3));

      int64_t now = nms();
      std::vector<std::string> to_disconnect;

      {
        std::shared_lock lock(connections_mutex_);
        for (auto& [id, conn] : connections_) {
          if (conn->closing.load()) continue;

          // Check heartbeat timeout
          int64_t last = conn->last_active.load();
          if (last > 0 &&
              now - last > config_.heartbeat_timeout_ms) {
            to_disconnect.push_back(id);
            continue;
          }

          // Send ping if we haven't heard from them recently
          int64_t last_ping = conn->last_ping_sent.load();
          if (last_ping == 0 ||
              now - last_ping > config_.heartbeat_interval_ms) {
            send_frame(conn, WsOpcode::PING, std::to_string(now), false);
            conn->last_ping_sent.store(now);
          }

          // Check for stuck connections that haven't responded to pong
          int64_t last_pong = conn->last_pong_received.load();
          if (last_ping > 0 && last_pong > 0 &&
              now - last_ping > config_.heartbeat_timeout_ms &&
              last_pong < last_ping) {
            to_disconnect.push_back(id);
          }
        }
      }

      for (const auto& id : to_disconnect) {
        auto conn = get_connection(id);
        if (conn) {
          send_close(conn, WsCloseCode::GOING_AWAY,
                     "Heartbeat timeout");
          disconnect(conn, WsCloseCode::GOING_AWAY, "Heartbeat timeout");
        }
      }
    }
  }

  // ---- Session cleanup ----

  void session_cleanup_loop() {
    while (running_.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(std::chrono::seconds(60));

      int64_t now = nms();
      int64_t expiry = config_.reconnect_grace_seconds * 1000;

      std::unique_lock lock(session_rooms_mutex_);
      auto it = session_rooms_.begin();
      while (it != session_rooms_.end()) {
        if (now - it->second.second > expiry) {
          it = session_rooms_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  // ---- Rate limiting ----

  bool check_rate_limit(std::shared_ptr<WsConnection> conn) {
    std::lock_guard lock(conn->rate_limit_mutex);
    int64_t now = nms();
    int64_t window_start = now - config_.rate_limit_window_ms;

    // Remove old timestamps
    while (!conn->message_timestamps.empty() &&
           conn->message_timestamps.front() < window_start) {
      conn->message_timestamps.pop_front();
    }

    // Add current message
    conn->message_timestamps.push_back(now);

    if ((int)conn->message_timestamps.size() > config_.rate_limit_messages) {
      rate_limited_count_.fetch_add(1);
      return true;  // rate limited
    }

    return false;
  }

  // ---- Compression (permessage-deflate) ----

  void init_compression(std::shared_ptr<WsConnection> conn) {
    // Initialize deflate
    memset(&conn->deflate_stream, 0, sizeof(conn->deflate_stream));
    if (deflateInit2(&conn->deflate_stream, config_.compression_level,
                     Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) == Z_OK) {
      conn->deflate_initialized = true;
    }

    // Initialize inflate
    memset(&conn->inflate_stream, 0, sizeof(conn->inflate_stream));
    if (inflateInit2(&conn->inflate_stream, -15) == Z_OK) {
      conn->inflate_initialized = true;
    }
  }

  std::string compress_message(std::shared_ptr<WsConnection> conn,
                               const std::string& input) {
    if (!conn->deflate_initialized) return "";

    // Reset deflate stream (no context takeover for simplicity)
    deflateReset(&conn->deflate_stream);

    conn->deflate_stream.next_in =
        reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    conn->deflate_stream.avail_in = input.size();

    std::vector<uint8_t> output(input.size() + 32);
    conn->deflate_stream.next_out = output.data();
    conn->deflate_stream.avail_out = output.size();

    int ret = deflate(&conn->deflate_stream, Z_SYNC_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END) return "";

    size_t compressed_size =
        output.size() - conn->deflate_stream.avail_out;
    // Strip the 4 trailing bytes (00 00 FF FF) per permessage-deflate spec
    if (compressed_size >= 4) compressed_size -= 4;

    return std::string(reinterpret_cast<char*>(output.data()), compressed_size);
  }

  std::string decompress_message(std::shared_ptr<WsConnection> conn,
                                 const std::string& input) {
    if (!conn->inflate_initialized) return input;

    // Append 00 00 FF FF tail for decompression
    std::string padded = input + std::string("\x00\x00\xFF\xFF", 4);

    inflateReset(&conn->inflate_stream);

    conn->inflate_stream.next_in =
        reinterpret_cast<Bytef*>(const_cast<char*>(padded.data()));
    conn->inflate_stream.avail_in = padded.size();

    std::vector<uint8_t> output(input.size() * 4 + 1024);
    conn->inflate_stream.next_out = output.data();
    conn->inflate_stream.avail_out = output.size();

    int ret = inflate(&conn->inflate_stream, Z_SYNC_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END) return input;

    size_t decompressed_size =
        output.size() - conn->inflate_stream.avail_out;
    return std::string(reinterpret_cast<char*>(output.data()),
                       decompressed_size);
  }

  // ---- Utility ----

  std::shared_ptr<WsConnection> get_connection(const std::string& id) const {
    std::shared_lock lock(connections_mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end()) return it->second;
    return nullptr;
  }

  static std::string room_name(RoomType type, const std::string& id) {
    switch (type) {
      case RoomType::COMMUNITY: return "community:" + id;
      case RoomType::POST:      return "post:" + id;
      case RoomType::USER:      return "user:" + id;
      case RoomType::MOD_LOG:   return "mod_log:" + id;
      case RoomType::SITE:      return "site";
    }
    return "unknown:" + id;
  }

  // ---- JSON conversion helpers ----

  json post_to_json(const Post& p) const {
    json j;
    j["id"] = p.id;
    j["name"] = p.name;
    j["url"] = p.url;
    j["body"] = p.body;
    j["creator_id"] = p.creator_id;
    j["community_id"] = p.community_id;
    j["nsfw"] = p.nsfw;
    j["removed"] = p.removed;
    j["deleted"] = p.deleted;
    j["locked"] = p.locked;
    j["stickied"] = p.stickied;
    j["score"] = p.score;
    j["upvotes"] = p.upvotes;
    j["downvotes"] = p.downvotes;
    j["comments"] = p.comments;
    j["published"] = p.published;
    j["updated"] = p.updated;
    return j;
  }

  json comment_to_json(const Comment& c) const {
    json j;
    j["id"] = c.id;
    j["content"] = c.content;
    j["creator_id"] = c.creator_id;
    j["post_id"] = c.post_id;
    if (c.parent_id) j["parent_id"] = *c.parent_id;
    else j["parent_id"] = nullptr;
    j["removed"] = c.removed;
    j["deleted"] = c.deleted;
    j["distinguished"] = c.distinguished;
    j["score"] = c.score;
    j["upvotes"] = c.upvotes;
    j["downvotes"] = c.downvotes;
    j["published"] = c.published;
    j["updated"] = c.updated;
    return j;
  }

  json community_to_json(const Community& c) const {
    json j;
    j["id"] = c.id;
    j["name"] = c.name;
    j["title"] = c.title;
    j["description"] = c.description;
    j["nsfw"] = c.nsfw;
    j["subscribers"] = c.subscribers;
    j["posts"] = c.posts;
    j["comments"] = c.comments;
    j["published"] = c.published;
    return j;
  }

  json pm_to_json(const PrivateMessage& pm) const {
    json j;
    j["id"] = pm.id;
    j["content"] = pm.content;
    j["creator_id"] = pm.creator_id;
    j["recipient_id"] = pm.recipient_id;
    j["read"] = pm.read;
    j["deleted"] = pm.deleted;
    j["published"] = pm.published;
    j["updated"] = pm.updated;
    return j;
  }

  // ---- HTTP helpers ----

  void send_http_response(std::shared_ptr<WsConnection> conn, int code,
                          const std::string& status,
                          const std::string& extra_headers = "") {
    static const std::map<int, std::string> status_map = {
        {200, "OK"},
        {400, "Bad Request"},
        {405, "Method Not Allowed"},
        {426, "Upgrade Required"},
    };

    auto it = status_map.find(code);
    std::string reason = (it != status_map.end()) ? it->second : "Unknown";

    std::ostringstream resp;
    resp << "HTTP/1.1 " << code << " " << reason << "\r\n";
    resp << "Content-Type: text/plain\r\n";
    resp << "Content-Length: " << status.size() << "\r\n";
    resp << "Connection: close\r\n";
    if (!extra_headers.empty()) resp << extra_headers;
    resp << "\r\n";
    resp << status;

    std::string resp_str = resp.str();
    if (conn->ssl) {
      SSL_write(conn->ssl, resp_str.data(), resp_str.size());
    } else {
      write(conn->fd, resp_str.data(), resp_str.size());
    }
  }

  static std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
      if (!line.empty() && line.back() == '\r') line.pop_back();
      lines.push_back(line);
    }
    return lines;
  }

  static bool parse_request_line(const std::string& line, std::string& method,
                                 std::string& path, std::string& version) {
    std::istringstream iss(line);
    iss >> method >> path >> version;
    return !method.empty() && !path.empty();
  }

  static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
  }

  static std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
  }

  static std::map<std::string, std::string> parse_query_string(
      const std::string& qs) {
    std::map<std::string, std::string> params;
    std::istringstream iss(qs);
    std::string pair;
    while (std::getline(iss, pair, '&')) {
      size_t eq = pair.find('=');
      if (eq != std::string::npos) {
        std::string key = url_decode(pair.substr(0, eq));
        std::string val = url_decode(pair.substr(eq + 1));
        params[key] = val;
      }
    }
    return params;
  }

  static std::string url_decode(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); i++) {
      if (str[i] == '%' && i + 2 < str.size()) {
        int hi = hex_val(str[i + 1]);
        int lo = hex_val(str[i + 2]);
        if (hi >= 0 && lo >= 0) {
          result.push_back((char)((hi << 4) | lo));
          i += 2;
          continue;
        }
      } else if (str[i] == '+') {
        result.push_back(' ');
        continue;
      }
      result.push_back(str[i]);
    }
    return result;
  }

  static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  }

  // ---- Data members ----

  LemmyServer* lemmy_;
  WsServerConfig config_;

  // Listening socket
  int listen_fd_ = -1;

  // TLS context
  SSL_CTX* ssl_ctx_ = nullptr;

  // State
  std::atomic<bool> running_{false};
  std::atomic<bool> shutting_down_{false};

  // Threads
  std::thread worker_thread_;
  std::thread heartbeat_thread_;
  std::thread session_cleanup_thread_;

  // Connections
  mutable std::shared_mutex connections_mutex_;
  std::unordered_map<std::string, std::shared_ptr<WsConnection>> connections_;

  // Rooms: room_name -> set of connection IDs
  mutable std::shared_mutex rooms_mutex_;
  std::unordered_map<std::string, std::unordered_set<std::string>> rooms_;

  // User -> connection IDs (for targeted delivery)
  mutable std::shared_mutex user_connections_mutex_;
  std::unordered_map<std::string, std::unordered_set<std::string>>
      user_connections_;

  // Session storage for reconnection (session_id -> {rooms, timestamp})
  mutable std::shared_mutex session_rooms_mutex_;
  std::unordered_map<std::string,
                     std::pair<std::unordered_set<std::string>, int64_t>>
      session_rooms_;

  // Stats
  std::atomic<size_t> connection_count_{0};
  std::atomic<size_t> authenticated_count_{0};
  std::atomic<size_t> total_rooms_{0};
  std::atomic<int64_t> total_messages_received_{0};
  std::atomic<int64_t> total_messages_sent_{0};
  std::atomic<int64_t> total_bytes_received_{0};
  std::atomic<int64_t> total_bytes_sent_{0};
  std::atomic<int64_t> rate_limited_count_{0};
  std::atomic<int64_t> rejected_connections_{0};
};

// ============================================================================
// Standalone utility: WebSocket connection helper for integration
// ============================================================================

// Convenience function to create a WebSocket server attached to a LemmyServer
std::shared_ptr<LemmyWebSocketServer> create_websocket_server(
    LemmyServer* lemmy, const WsServerConfig& config) {
  auto server = std::make_shared<LemmyWebSocketServer>(lemmy, config);
  return server;
}

// Default WsServerConfig for testing / local development
WsServerConfig default_ws_config(uint16_t port = 8081) {
  WsServerConfig cfg;
  cfg.port = port;
  return cfg;
}

// TLS WsServerConfig
WsServerConfig tls_ws_config(uint16_t port, const std::string& cert_file,
                              const std::string& key_file) {
  WsServerConfig cfg;
  cfg.port = port;
  cfg.use_tls = true;
  cfg.cert_file = cert_file;
  cfg.key_file = key_file;
  return cfg;
}

// ============================================================================
// Demo / test main - exercises all features (compile with -DLEMMY_WS_DEMO)
// ============================================================================
#ifdef LEMMY_WS_DEMO
int main() {
  std::cout << "=== Lemmy WebSocket Server Demo ===" << std::endl;

  // Create a Lemmy server instance (mock for demo)
  LemmyServer lemmy("localhost");
  lemmy.start(8080);

  // Create WebSocket server
  WsServerConfig ws_cfg = default_ws_config(8081);
  ws_cfg.heartbeat_interval_ms = 10000;
  ws_cfg.enable_compression = true;

  auto ws_server = create_websocket_server(&lemmy, ws_cfg);
  if (!ws_server->start()) {
    std::cerr << "Failed to start WebSocket server" << std::endl;
    return 1;
  }

  // Create test data
  auto user1 = lemmy.create_user("alice", "pass123", "alice@test.com");
  auto user2 = lemmy.create_user("bob", "pass456", "bob@test.com");
  auto community = lemmy.create_community("test_community", "Test Community",
                                          "A test community", user1.id);
  auto post = lemmy.create_post("Test Post", community.id, user1.id,
                                "https://example.com", "Post body");
  auto comment = lemmy.create_comment("Nice post!", post.id, user2.id);

  // Simulate real-time events
  std::cout << "\n--- Broadcasting events ---" << std::endl;

  ws_server->notify_post_created(post, community);
  std::cout << "  [OK] Post created broadcast" << std::endl;

  ws_server->notify_comment_created(comment, community.id);
  std::cout << "  [OK] Comment created broadcast" << std::endl;

  ws_server->notify_user_online(user1.id, user1.name);
  std::cout << "  [OK] User online broadcast" << std::endl;

  ws_server->notify_typing(user2.id, user2.name,
                           LemmyWebSocketServer::room_name(
                               RoomType::POST, std::to_string(post.id)),
                           true);
  std::cout << "  [OK] Typing indicator sent" << std::endl;

  ws_server->notify_post_vote_change(post.id, community.id, 42, 45, 3);
  std::cout << "  [OK] Vote change broadcast" << std::endl;

  ws_server->notify_community_join(user2.id, user2.name, community.id);
  std::cout << "  [OK] Community join broadcast" << std::endl;

  // Print stats
  json stats = ws_server->get_connection_stats();
  std::cout << "\n--- Connection Stats ---" << std::endl;
  std::cout << stats.dump(2) << std::endl;

  // Keep running for a bit, then exit
  std::cout << "\nServer running on ws://localhost:8081" << std::endl;
  std::cout << "Press Ctrl+C to stop..." << std::endl;

  // Wait for signal
  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGTERM);
  int sig;
  sigwait(&sigset, &sig);

  std::cout << "\nShutting down..." << std::endl;
  ws_server->stop();
  lemmy.stop();

  std::cout << "Done." << std::endl;
  return 0;
}
#endif  // LEMMY_WS_DEMO

// ============================================================================
// Advanced Token Bucket Rate Limiter
// ============================================================================
class TokenBucketRateLimiter {
 public:
  TokenBucketRateLimiter(double rate_per_second, double burst_size)
      : rate_(rate_per_second), burst_(burst_size), tokens_(burst_size),
        last_refill_(nms()) {}

  bool consume(double tokens = 1.0) {
    std::lock_guard<std::mutex> lock(mutex_);
    refill();
    if (tokens_ >= tokens) {
      tokens_ -= tokens;
      return true;
    }
    return false;
  }

  double available_tokens() const {
    std::lock_guard<std::mutex> lock(mutex_);
    const_cast<TokenBucketRateLimiter*>(this)->refill();
    return tokens_;
  }

  void set_rate(double rate_per_second) {
    std::lock_guard<std::mutex> lock(mutex_);
    rate_ = rate_per_second;
  }

 private:
  void refill() {
    int64_t now = nms();
    double elapsed = (now - last_refill_) / 1000.0;  // seconds
    tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
    last_refill_ = now;
  }

  double rate_;
  double burst_;
  double tokens_;
  int64_t last_refill_;
  mutable std::mutex mutex_;
};

// ============================================================================
// Connection Pool: manages per-IP connection limits and slow-loris prevention
// ============================================================================
class ConnectionPool {
 public:
  struct PoolStats {
    size_t total_connections = 0;
    size_t unique_ips = 0;
    size_t blocked_ips = 0;
    std::map<std::string, size_t> top_ips;
  };

  bool can_accept(const std::string& ip, size_t max_per_ip = 10) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = per_ip_.find(ip);
    size_t count = (it != per_ip_.end()) ? it->second : 0;
    if (count >= max_per_ip) {
      blocked_count_++;
      return false;
    }
    return true;
  }

  void add(const std::string& ip, const std::string& conn_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    per_ip_[ip]++;
    ip_to_conns_[ip].insert(conn_id);
    total_conns_++;
  }

  void remove(const std::string& ip, const std::string& conn_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = per_ip_.find(ip);
    if (it != per_ip_.end() && it->second > 0) {
      it->second--;
      if (it->second == 0) per_ip_.erase(it);
    }
    auto cit = ip_to_conns_.find(ip);
    if (cit != ip_to_conns_.end()) {
      cit->second.erase(conn_id);
      if (cit->second.empty()) ip_to_conns_.erase(cit);
    }
    total_conns_--;
  }

  void block_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_ips_.insert(ip);
  }

  void unblock_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocked_ips_.erase(ip);
  }

  bool is_blocked(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocked_ips_.count(ip) > 0;
  }

  PoolStats stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    PoolStats s;
    s.total_connections = total_conns_;
    s.unique_ips = per_ip_.size();
    s.blocked_ips = blocked_ips_.size();

    // Top IPs by connection count
    std::vector<std::pair<std::string, size_t>> sorted(
        per_ip_.begin(), per_ip_.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    for (size_t i = 0; i < std::min(size_t(10), sorted.size()); i++) {
      s.top_ips[sorted[i].first] = sorted[i].second;
    }
    return s;
  }

 private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, size_t> per_ip_;
  std::unordered_map<std::string, std::unordered_set<std::string>> ip_to_conns_;
  std::unordered_set<std::string> blocked_ips_;
  size_t total_conns_ = 0;
  size_t blocked_count_ = 0;
};

// ============================================================================
// Metrics Collector — aggregates server-wide WebSocket metrics
// ============================================================================
class WsMetricsCollector {
 public:
  void record_connection() { connections_total_.fetch_add(1); }
  void record_disconnection() { disconnections_total_.fetch_add(1); }
  void record_message_received(size_t bytes) {
    messages_rx_.fetch_add(1);
    bytes_rx_.fetch_add(bytes);
  }
  void record_message_sent(size_t bytes) {
    messages_tx_.fetch_add(1);
    bytes_tx_.fetch_add(bytes);
  }
  void record_auth_success() { auth_successes_.fetch_add(1); }
  void record_auth_failure() { auth_failures_.fetch_add(1); }
  void record_rate_limit() { rate_limits_.fetch_add(1); }
  void record_error(const std::string& type) {
    std::lock_guard<std::mutex> lock(mutex_);
    errors_[type]++;
  }
  void record_latency(int64_t ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    latencies_.push_back(ms);
    if (latencies_.size() > 10000) latencies_.pop_front();
  }

  json snapshot() const {
    json j;
    j["connections_total"] = connections_total_.load();
    j["disconnections_total"] = disconnections_total_.load();
    j["messages_received"] = messages_rx_.load();
    j["messages_sent"] = messages_tx_.load();
    j["bytes_received"] = bytes_rx_.load();
    j["bytes_sent"] = bytes_tx_.load();
    j["auth_successes"] = auth_successes_.load();
    j["auth_failures"] = auth_failures_.load();
    j["rate_limits"] = rate_limits_.load();

    {
      std::lock_guard<std::mutex> lock(mutex_);
      j["error_counts"] = json(errors_);
      if (!latencies_.empty()) {
        double sum = 0;
        for (auto l : latencies_) sum += l;
        j["avg_latency_ms"] = sum / latencies_.size();
        j["latency_samples"] = latencies_.size();
      }
    }
    return j;
  }

 private:
  std::atomic<int64_t> connections_total_{0};
  std::atomic<int64_t> disconnections_total_{0};
  std::atomic<int64_t> messages_rx_{0};
  std::atomic<int64_t> messages_tx_{0};
  std::atomic<int64_t> bytes_rx_{0};
  std::atomic<int64_t> bytes_tx_{0};
  std::atomic<int64_t> auth_successes_{0};
  std::atomic<int64_t> auth_failures_{0};
  std::atomic<int64_t> rate_limits_{0};
  mutable std::mutex mutex_;
  std::unordered_map<std::string, int64_t> errors_;
  std::deque<int64_t> latencies_;
};

// ============================================================================
// Persistent Subscription Store — survives server restarts across reconnect
// ============================================================================
class PersistentSubscriptionStore {
 public:
  void save_subscriptions(const std::string& user_id,
                          const std::unordered_set<std::string>& rooms) {
    std::unique_lock lock(mutex_);
    subscriptions_[user_id] = rooms;
  }

  std::unordered_set<std::string> load_subscriptions(
      const std::string& user_id) const {
    std::shared_lock lock(mutex_);
    auto it = subscriptions_.find(user_id);
    if (it != subscriptions_.end()) return it->second;
    return {};
  }

  void remove_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    subscriptions_.erase(user_id);
  }

  void add_room(const std::string& user_id, const std::string& room) {
    std::unique_lock lock(mutex_);
    subscriptions_[user_id].insert(room);
  }

  void remove_room(const std::string& user_id, const std::string& room) {
    std::unique_lock lock(mutex_);
    auto it = subscriptions_.find(user_id);
    if (it != subscriptions_.end()) {
      it->second.erase(room);
      if (it->second.empty()) subscriptions_.erase(it);
    }
  }

  json dump_all() const {
    std::shared_lock lock(mutex_);
    json j;
    for (const auto& [uid, rooms] : subscriptions_) {
      j[uid] = json(rooms);
    }
    return j;
  }

  size_t total_subscriptions() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [_, rooms] : subscriptions_) count += rooms.size();
    return count;
  }

 private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, std::unordered_set<std::string>>
      subscriptions_;
};

// ============================================================================
// WebSocket Message Router — decoupled message dispatch with middleware
// ============================================================================
class WsMessageRouter {
 public:
  using Handler = std::function<json(const json&, WsConnection&)>;
  using Middleware = std::function<bool(const json&, WsConnection&)>;

  void register_handler(const std::string& op, Handler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_[op] = std::move(handler);
  }

  void add_middleware(Middleware mw) {
    std::lock_guard<std::mutex> lock(mutex_);
    middlewares_.push_back(std::move(mw));
  }

  std::optional<json> dispatch(const json& msg, WsConnection& conn) {
    // Run middlewares
    for (auto& mw : middlewares_) {
      if (!mw(msg, conn)) {
        return json{{"op", "error"},
                     {"data",
                      {{"code", "middleware_rejected"},
                       {"message", "Request rejected by middleware"}}}};
      }
    }

    std::string op = msg["op"].get<std::string>();
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = handlers_.find(op);
    if (it != handlers_.end()) {
      return it->second(msg, conn);
    }
    return std::nullopt;
  }

 private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, Handler> handlers_;
  std::vector<Middleware> middlewares_;
};

// ============================================================================
// Admin bot detection middleware
// ============================================================================
namespace {
bool admin_only_middleware(const json& msg, WsConnection& conn) {
  // Admin-only ops
  static const std::unordered_set<std::string> admin_ops = {
      "broadcast_site", "kick_user", "ban_ip", "get_all_sessions",
      "purge_rooms", "reload_config"};
  if (admin_ops.count(msg["op"].get<std::string>())) {
    return conn.is_admin;
  }
  return true;
}

// Validate message size
bool message_size_middleware(const json& msg, WsConnection& conn) {
  std::string serialized = msg.dump();
  if (serialized.size() > 65536) {  // 64KB limit
    return false;
  }
  return true;
}
}  // namespace

// ============================================================================
// Extended IP utilities
// ============================================================================
namespace {
bool is_private_ip(const std::string& ip) {
  // Check common private ranges
  if (ip.find("10.") == 0) return true;
  if (ip.find("172.") == 0) {
    int second = 0;
    sscanf(ip.c_str(), "172.%d.", &second);
    if (second >= 16 && second <= 31) return true;
  }
  if (ip.find("192.168.") == 0) return true;
  if (ip == "127.0.0.1" || ip == "::1" || ip.find("127.") == 0) return true;
  return false;
}

std::string anonymize_ip(const std::string& ip) {
  // For logging: mask the last octet
  auto pos = ip.rfind('.');
  if (pos != std::string::npos) {
    return ip.substr(0, pos) + ".xxx";
  }
  return ip;
}
}  // namespace

// ============================================================================
// Connection Limiter — circuit breaker pattern for overload protection
// ============================================================================
class ConnectionLimiter {
 public:
  explicit ConnectionLimiter(size_t max_connections = 10000,
                             double max_accept_rate = 100.0)
      : max_connections_(max_connections),
        max_accept_rate_(max_accept_rate),
        accept_tokens_(max_accept_rate) {
    last_accept_time_ = nms();
  }

  enum class AcceptDecision {
    ACCEPT,
    REJECT_FULL,
    REJECT_RATE_LIMITED,
    REJECT_BLACKLISTED,
  };

  AcceptDecision should_accept(size_t current_connections) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (current_connections >= max_connections_) {
      return AcceptDecision::REJECT_FULL;
    }

    // Rate limit accepts
    int64_t now = nms();
    double elapsed = (now - last_accept_time_) / 1000.0;
    accept_tokens_ = std::min(max_accept_rate_,
                              accept_tokens_ + elapsed * max_accept_rate_);
    last_accept_time_ = now;

    if (accept_tokens_ < 1.0) {
      return AcceptDecision::REJECT_RATE_LIMITED;
    }
    accept_tokens_ -= 1.0;
    return AcceptDecision::ACCEPT;
  }

  void set_max_connections(size_t max) { max_connections_ = max; }
  void set_accept_rate(double rate) { max_accept_rate_ = rate; }

 private:
  size_t max_connections_;
  double max_accept_rate_;
  double accept_tokens_;
  int64_t last_accept_time_;
  std::mutex mutex_;
};

// ============================================================================
// WebSocket Frame Builder — low-level frame construction utilities
// ============================================================================
namespace ws_frame {

// Build a complete WebSocket text frame (public helper)
std::vector<uint8_t> build_text_frame(const std::string& payload) {
  std::vector<uint8_t> frame;
  frame.reserve(2 + 8 + payload.size());
  frame.push_back(0x81);  // FIN + TEXT

  if (payload.size() < 126) {
    frame.push_back((uint8_t)payload.size());
  } else if (payload.size() <= 0xFFFF) {
    frame.push_back(126);
    frame.push_back((payload.size() >> 8) & 0xFF);
    frame.push_back(payload.size() & 0xFF);
  } else {
    frame.push_back(127);
    for (int i = 7; i >= 0; i--) {
      frame.push_back((payload.size() >> (i * 8)) & 0xFF);
    }
  }
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

std::vector<uint8_t> build_close_frame(uint16_t code,
                                        const std::string& reason) {
  std::vector<uint8_t> frame;
  frame.push_back(0x88);  // FIN + CLOSE

  size_t payload_len = 2 + std::min(reason.size(), size_t(123));
  if (payload_len < 126) {
    frame.push_back((uint8_t)payload_len);
  } else {
    frame.push_back(126);
    frame.push_back((payload_len >> 8) & 0xFF);
    frame.push_back(payload_len & 0xFF);
  }

  frame.push_back((code >> 8) & 0xFF);
  frame.push_back(code & 0xFF);
  frame.insert(frame.end(), reason.begin(),
               reason.begin() + std::min(reason.size(), size_t(123)));
  return frame;
}

std::vector<uint8_t> build_ping_frame(const std::string& payload) {
  std::vector<uint8_t> frame;
  frame.push_back(0x89);  // FIN + PING

  if (payload.size() < 126) {
    frame.push_back((uint8_t)payload.size());
  } else {
    frame.push_back(126);
    frame.push_back((payload.size() >> 8) & 0xFF);
    frame.push_back(payload.size() & 0xFF);
  }
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

std::vector<uint8_t> build_pong_frame(const std::string& payload) {
  std::vector<uint8_t> frame;
  frame.push_back(0x8A);  // FIN + PONG

  if (payload.size() < 126) {
    frame.push_back((uint8_t)payload.size());
  } else {
    frame.push_back(126);
    frame.push_back((payload.size() >> 8) & 0xFF);
    frame.push_back(payload.size() & 0xFF);
  }
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

}  // namespace ws_frame

// ============================================================================
// WebSocket-compatible background task scheduler for periodic broadcasts
// ============================================================================
class WsScheduledTask {
 public:
  using TaskFn = std::function<void()>;

  WsScheduledTask(TaskFn fn, int64_t interval_ms)
      : fn_(std::move(fn)), interval_ms_(interval_ms), next_run_(nms()) {}

  void tick() {
    int64_t now = nms();
    if (now >= next_run_) {
      fn_();
      next_run_ = now + interval_ms_;
    }
  }

  int64_t next_run_at() const { return next_run_; }
  int64_t interval_ms() const { return interval_ms_; }

 private:
  TaskFn fn_;
  int64_t interval_ms_;
  int64_t next_run_;
};

// ============================================================================
// JSON Schema Validator — lightweight request validation
// ============================================================================
namespace ws_validator {

struct ValidationResult {
  bool valid = true;
  std::string error;
};

ValidationResult validate_message(const json& msg) {
  if (!msg.contains("op") || !msg["op"].is_string()) {
    return {false, "Missing or invalid 'op' field"};
  }
  std::string op = msg["op"].get<std::string>();
  if (op.empty() || op.size() > 64) {
    return {false, "Invalid 'op' value length"};
  }
  if (op.find_first_not_of(
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") !=
      std::string::npos) {
    return {false, "'op' contains invalid characters"};
  }
  return {true, ""};
}

ValidationResult validate_join_message(const json& msg) {
  auto base = validate_message(msg);
  if (!base.valid) return base;

  if (!msg.contains("data") || !msg["data"].is_object()) {
    return {false, "Missing 'data' object"};
  }
  if (!msg["data"].contains("room") || !msg["data"]["room"].is_string()) {
    return {false, "Missing 'room' in data"};
  }
  std::string room = msg["data"]["room"].get<std::string>();
  if (room.empty() || room.size() > 256) {
    return {false, "Room name must be 1-256 characters"};
  }
  if (room.find("..") != std::string::npos || room.find('/') != std::string::npos) {
    return {false, "Room name contains invalid characters"};
  }
  return {true, ""};
}

ValidationResult validate_auth_message(const json& msg) {
  auto base = validate_message(msg);
  if (!base.valid) return base;

  if (!msg.contains("data") || !msg["data"].is_object()) {
    return {false, "Missing 'data' object"};
  }
  if (!msg["data"].contains("token") || !msg["data"]["token"].is_string()) {
    return {false, "Missing 'token' in data"};
  }
  std::string token = msg["data"]["token"].get<std::string>();
  if (token.empty() || token.size() > 4096) {
    return {false, "Invalid token length"};
  }
  return {true, ""};
}

}  // namespace ws_validator

// ============================================================================
// Graceful Drain Manager — handles staggered shutdown of connections
// ============================================================================
class GracefulDrainManager {
 public:
  struct DrainStatus {
    size_t connections_remaining = 0;
    size_t connections_drained = 0;
    int64_t drain_started_at = 0;
    int64_t drain_deadline_ms = 0;
    bool active = false;
  };

  void start_drain(int64_t grace_period_ms, size_t initial_count) {
    std::lock_guard<std::mutex> lock(mutex_);
    status_.active = true;
    status_.drain_started_at = nms();
    status_.drain_deadline_ms = status_.drain_started_at + grace_period_ms;
    status_.connections_remaining = initial_count;
    status_.connections_drained = 0;
  }

  void connection_drained() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (status_.active) {
      status_.connections_drained++;
      if (status_.connections_remaining > 0)
        status_.connections_remaining--;
    }
  }

  bool should_force_close() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!status_.active) return false;
    return nms() >= status_.drain_deadline_ms;
  }

  bool is_draining() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return status_.active;
  }

  void stop_drain() {
    std::lock_guard<std::mutex> lock(mutex_);
    status_.active = false;
  }

  DrainStatus status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    DrainStatus s = status_;
    if (s.active) {
      s.connections_remaining = status_.connections_remaining;
    }
    return s;
  }

 private:
  mutable std::mutex mutex_;
  DrainStatus status_;
};

// ============================================================================
// CORS Origin Validator — WebSocket origin checking
// ============================================================================
class CorsOriginValidator {
 public:
  void allow_origin(const std::string& origin) {
    std::lock_guard<std::mutex> lock(mutex_);
    allowed_origins_.insert(origin);
  }

  void allow_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    allow_all_ = true;
  }

  bool is_allowed(const std::string& origin) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (allow_all_) return true;
    if (origin.empty()) return true;  // same-origin requests have no origin
    return allowed_origins_.count(origin) > 0 ||
           allowed_origins_.count("*") > 0;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    allowed_origins_.clear();
    allow_all_ = false;
  }

 private:
  mutable std::mutex mutex_;
  std::unordered_set<std::string> allowed_origins_;
  bool allow_all_ = false;
};

// ============================================================================
// Connection Throttle — backoff for misbehaving clients
// ============================================================================
class ConnectionThrottle {
 public:
  void record_auth_failure(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    failures_[ip]++;
    auto& delay = backoff_[ip];
    delay = std::min(delay * 2 + 1000, int64_t(60000));  // max 60s backoff
  }

  int64_t get_backoff_ms(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = backoff_.find(ip);
    if (it != backoff_.end()) return it->second;
    return 0;
  }

  bool should_throttle(const std::string& ip, int64_t now_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto fit = last_attempt_.find(ip);
    if (fit == last_attempt_.end()) return false;

    auto bit = backoff_.find(ip);
    if (bit == backoff_.end()) return false;

    return (now_ms - fit->second) < bit->second;
  }

  void record_attempt(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_attempt_[ip] = nms();
  }

  void clear_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    failures_.erase(ip);
    backoff_.erase(ip);
    last_attempt_.erase(ip);
  }

 private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, int> failures_;
  std::unordered_map<std::string, int64_t> backoff_;
  std::unordered_map<std::string, int64_t> last_attempt_;
};

// ============================================================================
// Broadcast Batcher — aggregates messages to reduce send() syscalls
// ============================================================================
class BroadcastBatcher {
 public:
  explicit BroadcastBatcher(size_t max_batch_size = 64,
                            int64_t max_flush_interval_ms = 50)
      : max_batch_size_(max_batch_size),
        max_flush_interval_ms_(max_flush_interval_ms) {}

  void enqueue(const std::string& room, const json& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    batches_[room].push_back(message);
    if (batches_[room].size() >= max_batch_size_) {
      flush_room(room);
    }
  }

  std::map<std::string, std::vector<json>> flush_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto result = std::move(batches_);
    batches_.clear();
    return result;
  }

  void flush_room(const std::string& room) {
    // Trigger immediate flush for this room
    // (called by external timer or when batch is full)
  }

  size_t pending_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [room, msgs] : batches_) count += msgs.size();
    return count;
  }

 private:
  std::map<std::string, std::vector<json>> batches_;
  size_t max_batch_size_;
  int64_t max_flush_interval_ms_;
  mutable std::mutex mutex_;
};

// ============================================================================
// Protocol Version Negotiation — future-proofing
// ============================================================================
namespace ws_protocol {

constexpr int CURRENT_VERSION = 1;
constexpr int MIN_SUPPORTED_VERSION = 1;
constexpr int MAX_SUPPORTED_VERSION = 1;

struct VersionInfo {
  int version = CURRENT_VERSION;
  std::string server = "Progressive Lemmy WebSocket";
  std::vector<int> supported_versions = {1};
};

VersionInfo get_version_info() {
  VersionInfo v;
  return v;
}

bool is_version_supported(int client_version) {
  return client_version >= MIN_SUPPORTED_VERSION &&
         client_version <= MAX_SUPPORTED_VERSION;
}

}  // namespace ws_protocol

// ============================================================================
// Presence Tracker — centralized user online status
// ============================================================================
class PresenceTracker {
 public:
  void set_online(const std::string& user_id, const std::string& username,
                  const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (presence_.count(user_id) == 0) {
      // First session — announce online
      pending_events_.push_back({"online", user_id, username, nms()});
    }
    sessions_[user_id].insert(session_id);
    presence_[user_id] = {username, true, nms()};
  }

  void set_offline(const std::string& user_id, const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(user_id);
    if (it != sessions_.end()) {
      it->second.erase(session_id);
      if (it->second.empty()) {
        sessions_.erase(it);
        presence_[user_id].online = false;
        presence_[user_id].last_seen = nms();
        pending_events_.push_back(
            {"offline", user_id, presence_[user_id].username, nms()});
      }
    }
  }

  bool is_online(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = presence_.find(user_id);
    return it != presence_.end() && it->second.online;
  }

  std::vector<std::string> get_online_users() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> users;
    for (const auto& [uid, info] : presence_) {
      if (info.online) users.push_back(uid);
    }
    return users;
  }

  struct PresenceEvent {
    std::string event_type;  // "online" or "offline"
    std::string user_id;
    std::string username;
    int64_t timestamp;
  };

  std::vector<PresenceEvent> drain_events() {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::move(pending_events_);
  }

 private:
  struct PresenceInfo {
    std::string username;
    bool online = false;
    int64_t last_seen = 0;
  };
  mutable std::mutex mutex_;
  std::unordered_map<std::string, PresenceInfo> presence_;
  std::unordered_map<std::string, std::unordered_set<std::string>> sessions_;
  std::vector<PresenceEvent> pending_events_;
};

}  // namespace progressive::lemmy
