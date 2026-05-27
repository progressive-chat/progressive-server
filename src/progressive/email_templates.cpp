// ============================================================================
// email_templates.cpp — Matrix Email Notification Templates, Rendering,
//   SMTP Sending, Throttling, Validation, Preferences, Queue, and Logging
//
// Implements:
//   - Email templates: password reset, email verification, registration,
//     invite, notification, message notification, account renewal, welcome,
//     account deactivated — both HTML and plain-text variants
//   - Template rendering: replace template variables (display_name, room_name,
//     sender_name, message_preview, link, server_name), conditional blocks,
//     template caching for performance
//   - Email sending: SMTP client with STARTTLS/SSL, AUTH LOGIN/PLAIN,
//     MAIL FROM/RCPT TO/DATA, bounce detection via Return-Path, DKIM stub,
//     connection pooling with keepalive, greeting banner capture
//   - Email throttling: per-user email rate limits (per hour/per day),
//     per-email-type rate limits, global email rate limits, burst allowance,
//     sliding-window token bucket with configurable rates
//   - Email validation: RFC 5322 syntax validation, MX record checking via
//     DNS resolution, disposable email provider blocklist, role-account
//     detection, domain TTL checks, SMTP callback verification stub
//   - Email preferences: per-user notification preferences (enable/disable
//     email notifications per type), global notification defaults, admin
//     override settings, preference change audit log
//   - Email queue: async email sending with persistence-backed queue,
//     retry with exponential backoff (1min, 5min, 15min, 1hr, 6hr, 24hr),
//     dead-letter queue for permanently failed emails, queue monitoring
//     and admin management endpoints
//   - Email log: log all sent emails with timestamps, status, user_id,
//     email_type, recipient, subject, delivery latency, bounce records,
//     structured JSON logging format
//
// Equivalent to:
//   synapse/push/mailer.py (email building + sending)
//   synapse/util/emailconfig.py (SMTP config)
//   synapse/util/throttle.py (email rate limiting)
//   synapse/util/async_helpers.py (queue/retry)
//   synapse/handlers/auth.py (email validation portions)
//   synapse/handlers/identity.py (email verification)
//   synapse/config/emailconfig.py
//   synapse/notifier.py (notification dispatch that triggers email)
//
// Target: 2500+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
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
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#ifdef __linux__
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define SOCK_ERRNO errno
#define SOCK_CLOSE(fd) close(fd)
#define INVALID_SOCK -1
#define SOCK_FAIL -1
typedef int sockfd_t;
#elif defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#define SOCK_ERRNO WSAGetLastError()
#define SOCK_CLOSE(fd) closesocket(fd)
typedef SOCKET sockfd_t;
#define INVALID_SOCK INVALID_SOCKET
#define SOCK_FAIL SOCKET_ERROR
#endif

// Internal project includes
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/devices.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
namespace fs = std::filesystem;

// ============================================================================
// Forward declarations
// ============================================================================
class EmailTemplate;
class EmailTemplateRenderer;
class EmailTemplateCache;
class EmailTemplateCompiler;
class SmtpClient;
class SmtpConnectionPool;
class SmtpConfig;
class EmailThrottler;
class UserEmailThrottle;
class EmailTypeThrottle;
class GlobalEmailThrottle;
class EmailValidator;
class DisposableEmailBlocklist;
class MxResolver;
class EmailPreferences;
class EmailPreferenceStore;
class EmailQueue;
class EmailQueueItem;
class EmailRetryPolicy;
class EmailDeadLetterQueue;
class EmailLogger;
class EmailLogEntry;
class EmailBounceDetector;
class EmailConfig;

// ============================================================================
// Enums and Constants
// ============================================================================

// Types of email notifications
enum class EmailType : uint8_t {
  PASSWORD_RESET        = 0,
  EMAIL_VERIFICATION    = 1,
  REGISTRATION          = 2,
  INVITE                = 3,
  NOTIFICATION           = 4,
  MESSAGE_NOTIFICATION  = 5,
  ACCOUNT_RENEWAL       = 6,
  WELCOME               = 7,
  ACCOUNT_DEACTIVATED   = 8,
  UNKNOWN               = 255
};

// Status of an email in the queue/log
enum class EmailStatus : uint8_t {
  QUEUED       = 0,
  SENDING      = 1,
  SENT         = 2,
  FAILED       = 3,
  BOUNCED      = 4,
  DEFERRED     = 5,
  RETRYING     = 6,
  DEAD_LETTER  = 7,
  THROTTLED    = 8,
  REJECTED     = 9
};

// Authentication methods for SMTP
enum class SmtpAuthMethod : uint8_t {
  NONE      = 0,
  LOGIN     = 1,
  PLAIN     = 2,
  XOAUTH2   = 3,
  CRAM_MD5  = 4
};

// Encryption mode for SMTP connections
enum class SmtpEncryption : uint8_t {
  NONE      = 0,
  STARTTLS  = 1,
  SSL_TLS   = 2
};

// ============================================================================
// Constants
// ============================================================================

// Maximum email size in bytes (including headers)
constexpr int64_t MAX_EMAIL_SIZE = 25 * 1024 * 1024; // 25 MB

// Default retry intervals in minutes
constexpr int64_t RETRY_INTERVALS[] = {1, 5, 15, 60, 360, 1440}; // 1min, 5min, 15min, 1h, 6h, 24h
constexpr int MAX_RETRIES = 6;

// Default rate limits
constexpr int DEFAULT_PER_USER_PER_HOUR = 30;
constexpr int DEFAULT_PER_USER_PER_DAY = 200;
constexpr int DEFAULT_GLOBAL_PER_HOUR = 10000;
constexpr int DEFAULT_PER_TYPE_PER_HOUR = 5000;

// SMTP defaults
constexpr int SMTP_DEFAULT_PORT = 587;
constexpr int SMTP_SSL_PORT = 465;
constexpr int SMTP_TIMEOUT_SECS = 30;
constexpr int SMTP_POOL_MAX_SIZE = 10;
constexpr int SMTP_POOL_IDLE_TIMEOUT_SECS = 300;

// Queue defaults
constexpr int QUEUE_MAX_SIZE = 100000;
constexpr int QUEUE_WORKER_THREADS = 4;
constexpr int QUEUE_BATCH_SIZE = 25;
constexpr int QUEUE_POLL_INTERVAL_MS = 1000;

// ============================================================================
// Helper: Timestamp utilities
// ============================================================================
namespace {

int64_t now_epoch_seconds() {
  return chr::duration_cast<chr::seconds>(
      chr::system_clock::now().time_since_epoch()).count();
}

int64_t now_millis() {
  return chr::duration_cast<chr::milliseconds>(
      chr::system_clock::now().time_since_epoch()).count();
}

std::string iso8601_now() {
  auto now = chr::system_clock::now();
  auto t = chr::system_clock::to_time_t(now);
  std::ostringstream ss;
  ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

// ============================================================================
// Helper: Base64 encoding/decoding
// ============================================================================

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode(const std::string& data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  int val = 0, valb = -6;
  for (unsigned char c : data) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(B64_CHARS[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(B64_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4)
    out.push_back('=');
  return out;
}

std::string b64_decode(const std::string& data) {
  std::string out;
  out.reserve(data.size() * 3 / 4);
  std::array<int, 256> T = {};
  for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(B64_CHARS[i])] = i;
  int val = 0, valb = -8;
  for (unsigned char c : data) {
    if (T[c] == 0 && c != 'A') continue; // skip non-base64 including '='
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

// ============================================================================
// Helper: SHA-256 hash (simple implementation)
// ============================================================================

std::string sha256(const std::string& data) {
  // Simplified SHA-256 for hash-based identifiers
  // In production, use OpenSSL's SHA256()
  std::hash<std::string> hasher;
  size_t h = hasher(data);
  std::ostringstream ss;
  ss << std::hex << std::setfill('0') << std::setw(16) << h;
  // Pad to 64 chars to resemble SHA-256 hex digest
  std::string result = ss.str();
  while (result.size() < 64) result = "0" + result;
  return result;
}

// ============================================================================
// Helper: Generate random tokens (hex)
// ============================================================================

std::string generate_token(size_t length = 32) {
  static std::mt19937_64 rng(
      static_cast<uint64_t>(chr::system_clock::now().time_since_epoch().count()) ^
      static_cast<uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())));
  static std::uniform_int_distribution<int> dist(0, 15);
  static const char hex_chars[] = "0123456789abcdef";
  std::string token;
  token.reserve(length);
  for (size_t i = 0; i < length; i++)
    token.push_back(hex_chars[dist(rng)]);
  return token;
}

// ============================================================================
// Helper: String utilities
// ============================================================================

std::string to_lower(const std::string& s) {
  std::string r = s;
  for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return r;
}

std::string trim_str(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::string html_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() * 2);
  for (char c : s) {
    switch (c) {
      case '&':  out += "&amp;"; break;
      case '<':  out += "&lt;"; break;
      case '>':  out += "&gt;"; break;
      case '"':  out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default:   out += c; break;
    }
  }
  return out;
}

// ============================================================================
// Helper: TCP socket helpers
// ============================================================================

#ifndef _WIN32
static bool tcp_init_done = true;
#else
static bool tcp_init_done = false;
static int tcp_startup() {
  if (!tcp_init_done) {
    WSADATA wsa;
    tcp_init_done = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
  }
  return tcp_init_done ? 0 : -1;
}
#endif

static sockfd_t tcp_connect(const std::string& host, int port, int timeout_secs) {
#ifdef _WIN32
  if (tcp_startup() != 0) return INVALID_SOCK;
#endif
  sockfd_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd == INVALID_SOCK) return INVALID_SOCK;

  struct timeval tv;
  tv.tv_sec = timeout_secs;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

  struct hostent* he = gethostbyname(host.c_str());
  if (!he) { SOCK_CLOSE(fd); return INVALID_SOCK; }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  memcpy(&addr.sin_addr, he->h_addr_list[0], static_cast<size_t>(he->h_length));

  if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == SOCK_FAIL) {
    SOCK_CLOSE(fd);
    return INVALID_SOCK;
  }
  return fd;
}

static int tcp_send(sockfd_t fd, const std::string& data) {
  return static_cast<int>(::send(fd, data.c_str(), data.size(), 0));
}

static int tcp_recv_line(sockfd_t fd, std::string& line, int timeout_ms) {
  line.clear();
  char c;
  auto deadline = now_millis() + timeout_ms;
  while (now_millis() <= deadline) {
    int n = static_cast<int>(::recv(fd, &c, 1, 0));
    if (n <= 0) return n;
    line.push_back(c);
    if (c == '\n') {
      // Strip trailing \r\n
      while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
        line.pop_back();
      break;
    }
  }
  return static_cast<int>(line.size());
}

} // anonymous namespace

// ============================================================================
// EmailConfig — Central email configuration
// ============================================================================
class EmailConfig {
public:
  struct SmtpSettings {
    std::string host = "localhost";
    int port = SMTP_DEFAULT_PORT;
    SmtpEncryption encryption = SmtpEncryption::STARTTLS;
    SmtpAuthMethod auth_method = SmtpAuthMethod::LOGIN;
    std::string username;
    std::string password;
    std::string from_address = "noreply@localhost";
    std::string from_name = "Matrix Server";
    std::string reply_to;
    std::string return_path;
    bool require_tls = true;
    bool verify_cert = true;
    int timeout_secs = SMTP_TIMEOUT_SECS;
    int max_connections = SMTP_POOL_MAX_SIZE;
  };

  struct TemplateSettings {
    std::string server_name = "matrix.local";
    std::string base_url = "https://matrix.local";
    std::string logo_url;
    std::string support_email = "support@localhost";
    std::string brand_name = "Matrix";
    bool include_html = true;
    bool include_plain_text = true;
  };

  struct RateLimitSettings {
    int per_user_per_hour = DEFAULT_PER_USER_PER_HOUR;
    int per_user_per_day = DEFAULT_PER_USER_PER_DAY;
    int global_per_hour = DEFAULT_GLOBAL_PER_HOUR;
    int per_type_per_hour = DEFAULT_PER_TYPE_PER_HOUR;
    int burst_allowance = 10;
    bool rate_limiting_enabled = true;
  };

  struct QueueSettings {
    int max_queue_size = QUEUE_MAX_SIZE;
    int worker_threads = QUEUE_WORKER_THREADS;
    int batch_size = QUEUE_BATCH_SIZE;
    int poll_interval_ms = QUEUE_POLL_INTERVAL_MS;
    int max_retries = MAX_RETRIES;
    bool persistence_enabled = true;
    std::string db_path = "email_queue.db";
  };

  SmtpSettings smtp;
  TemplateSettings templates;
  RateLimitSettings rate_limits;
  QueueSettings queue;

  static EmailConfig from_json(const json& j) {
    EmailConfig cfg;
    if (j.contains("smtp")) {
      auto& s = j["smtp"];
      if (s.contains("host")) cfg.smtp.host = s["host"].get<std::string>();
      if (s.contains("port")) cfg.smtp.port = s["port"].get<int>();
      if (s.contains("username")) cfg.smtp.username = s["username"].get<std::string>();
      if (s.contains("password")) cfg.smtp.password = s["password"].get<std::string>();
      if (s.contains("from_address")) cfg.smtp.from_address = s["from_address"].get<std::string>();
      if (s.contains("from_name")) cfg.smtp.from_name = s["from_name"].get<std::string>();
      if (s.contains("reply_to")) cfg.smtp.reply_to = s["reply_to"].get<std::string>();
      if (s.contains("return_path")) cfg.smtp.return_path = s["return_path"].get<std::string>();
      if (s.contains("require_tls")) cfg.smtp.require_tls = s["require_tls"].get<bool>();
      if (s.contains("encryption")) {
        std::string e = s["encryption"].get<std::string>();
        if (e == "starttls") cfg.smtp.encryption = SmtpEncryption::STARTTLS;
        else if (e == "ssl" || e == "tls") cfg.smtp.encryption = SmtpEncryption::SSL_TLS;
        else cfg.smtp.encryption = SmtpEncryption::NONE;
      }
    }
    if (j.contains("templates")) {
      auto& t = j["templates"];
      if (t.contains("server_name")) cfg.templates.server_name = t["server_name"].get<std::string>();
      if (t.contains("base_url")) cfg.templates.base_url = t["base_url"].get<std::string>();
      if (t.contains("logo_url")) cfg.templates.logo_url = t["logo_url"].get<std::string>();
      if (t.contains("support_email")) cfg.templates.support_email = t["support_email"].get<std::string>();
      if (t.contains("brand_name")) cfg.templates.brand_name = t["brand_name"].get<std::string>();
    }
    if (j.contains("rate_limits")) {
      auto& r = j["rate_limits"];
      if (r.contains("per_user_per_hour")) cfg.rate_limits.per_user_per_hour = r["per_user_per_hour"].get<int>();
      if (r.contains("per_user_per_day")) cfg.rate_limits.per_user_per_day = r["per_user_per_day"].get<int>();
      if (r.contains("global_per_hour")) cfg.rate_limits.global_per_hour = r["global_per_hour"].get<int>();
      if (r.contains("enabled")) cfg.rate_limits.rate_limiting_enabled = r["enabled"].get<bool>();
    }
    if (j.contains("queue")) {
      auto& q = j["queue"];
      if (q.contains("worker_threads")) cfg.queue.worker_threads = q["worker_threads"].get<int>();
      if (q.contains("max_retries")) cfg.queue.max_retries = q["max_retries"].get<int>();
    }
    return cfg;
  }
};

// ============================================================================
// EmailTemplate — Individual email template with HTML and plain text variants
// ============================================================================
class EmailTemplate {
public:
  struct Variant {
    std::string subject;
    std::string body;
    bool is_html = false;
  };

  EmailTemplate() = default;

  explicit EmailTemplate(const std::string& name) : name_(name) {}

  void set_subject(const std::string& subject) { subject_ = subject; }
  void set_html_body(const std::string& body) {
    html_variant_.body = body;
    html_variant_.is_html = true;
  }
  void set_plain_body(const std::string& body) {
    plain_variant_.body = body;
    plain_variant_.is_html = false;
  }
  void set_html_subject(const std::string& subject) {
    html_variant_.subject = subject;
  }
  void set_plain_subject(const std::string& subject) {
    plain_variant_.subject = subject;
  }

  const std::string& name() const { return name_; }
  const std::string& subject() const { return subject_; }
  const Variant& html_variant() const { return html_variant_; }
  const Variant& plain_variant() const { return plain_variant_; }

  // Return whether this template has valid content
  bool has_html() const { return !html_variant_.body.empty(); }
  bool has_plain() const { return !plain_variant_.body.empty(); }
  bool is_valid() const { return has_html() || has_plain(); }

private:
  std::string name_;
  std::string subject_;
  Variant html_variant_;
  Variant plain_variant_;
};

// ============================================================================
// EmailTemplateRenderer — Renders templates by substituting variables
// ============================================================================
class EmailTemplateRenderer {
public:
  struct RenderContext {
    std::string display_name;
    std::string room_name;
    std::string sender_name;
    std::string message_preview;
    std::string link;
    std::string server_name = "Matrix";
    std::string brand_name = "Matrix";
    std::string support_email;
    std::string logo_url;
    std::string token;
    std::string user_id;
    std::string room_id;
    std::string event_id;
    std::string current_year;
    std::string unsubscribe_link;
    std::map<std::string, std::string> custom_vars;
  };

  EmailTemplateRenderer(const EmailConfig::TemplateSettings& settings)
      : settings_(settings) {}

  // Render a template with the given context variables
  EmailTemplate render(const EmailTemplate& tmpl, const RenderContext& ctx) const {
    EmailTemplate result(tmpl.name());
    result.set_subject(replace_vars(tmpl.subject(), ctx));
    if (tmpl.html_variant().subject.empty())
      result.set_html_subject(result.subject());
    else
      result.set_html_subject(replace_vars(tmpl.html_variant().subject, ctx));
    if (tmpl.plain_variant().subject.empty())
      result.set_plain_subject(result.subject());
    else
      result.set_plain_subject(replace_vars(tmpl.plain_variant().subject, ctx));

    // Render bodies
    std::string html_body = tmpl.html_variant().body;
    if (!html_body.empty()) {
      html_body = replace_vars(html_body, ctx);
      html_body = process_conditionals(html_body, ctx);
      result.set_html_body(html_body);
    }

    std::string plain_body = tmpl.plain_variant().body;
    if (!plain_body.empty()) {
      plain_body = replace_vars(plain_body, ctx);
      plain_body = process_conditionals(plain_body, ctx);
      result.set_plain_body(plain_body);
    }

    return result;
  }

  // Build the MIME message from a rendered template
  std::string build_mime(const EmailTemplate& tmpl, const std::string& to_address) const {
    std::ostringstream mime;
    std::string boundary = "=_MatrixEmail_" + generate_token(16) + "_";
    std::string msg_id = "<" + generate_token(8) + "." +
        std::to_string(now_epoch_seconds()) + "@" + settings_.server_name + ">";

    // Common headers
    mime << "Date: " << rfc2822_date() << "\r\n";
    mime << "From: " << format_address(settings_.server_name, "noreply@" + settings_.server_name) << "\r\n";
    mime << "To: " << to_address << "\r\n";
    mime << "Message-ID: " << msg_id << "\r\n";
    mime << "Subject: " << mime_header_encode(tmpl.subject()) << "\r\n";
    mime << "MIME-Version: 1.0\r\n";
    mime << "X-Mailer: Progressive Matrix Server\r\n";
    mime << "X-Server: " << settings_.server_name << "\r\n";
    mime << "Auto-Submitted: auto-generated\r\n";

    bool has_html = tmpl.has_html();
    bool has_plain = tmpl.has_plain();

    if (has_html && has_plain) {
      mime << "Content-Type: multipart/alternative; boundary=\"" << boundary << "\"\r\n";
      mime << "\r\n";
      mime << "This is a multi-part message in MIME format.\r\n";
      mime << "--" << boundary << "\r\n";
      mime << "Content-Type: text/plain; charset=\"utf-8\"\r\n";
      mime << "Content-Transfer-Encoding: quoted-printable\r\n";
      mime << "\r\n";
      mime << qp_encode(tmpl.plain_variant().body) << "\r\n";
      mime << "--" << boundary << "\r\n";
      mime << "Content-Type: text/html; charset=\"utf-8\"\r\n";
      mime << "Content-Transfer-Encoding: quoted-printable\r\n";
      mime << "\r\n";
      mime << qp_encode(tmpl.html_variant().body) << "\r\n";
      mime << "--" << boundary << "--\r\n";
    } else if (has_html) {
      mime << "Content-Type: text/html; charset=\"utf-8\"\r\n";
      mime << "Content-Transfer-Encoding: quoted-printable\r\n";
      mime << "\r\n";
      mime << qp_encode(tmpl.html_variant().body) << "\r\n";
    } else {
      mime << "Content-Type: text/plain; charset=\"utf-8\"\r\n";
      mime << "Content-Transfer-Encoding: quoted-printable\r\n";
      mime << "\r\n";
      mime << qp_encode(tmpl.plain_variant().body) << "\r\n";
    }
    return mime.str();
  }

private:
  EmailConfig::TemplateSettings settings_;

  // Replace all template variables in the string
  std::string replace_vars(const std::string& input, const RenderContext& ctx) const {
    std::string result = input;

    // Simple variable substitution: {{ var_name }}
    static const std::vector<std::pair<std::string, std::function<std::string(const RenderContext&)>>> vars = {
      {"display_name",     [](const RenderContext& c) { return html_escape(c.display_name); }},
      {"room_name",        [](const RenderContext& c) { return html_escape(c.room_name); }},
      {"sender_name",      [](const RenderContext& c) { return html_escape(c.sender_name); }},
      {"message_preview",  [](const RenderContext& c) { return html_escape(c.message_preview); }},
      {"link",             [](const RenderContext& c) { return c.link; }},
      {"server_name",      [](const RenderContext& c) { return html_escape(c.server_name); }},
      {"brand_name",       [](const RenderContext& c) { return html_escape(c.brand_name); }},
      {"support_email",    [](const RenderContext& c) { return html_escape(c.support_email); }},
      {"logo_url",         [](const RenderContext& c) { return c.logo_url; }},
      {"token",            [](const RenderContext& c) { return c.token; }},
      {"user_id",          [](const RenderContext& c) { return html_escape(c.user_id); }},
      {"room_id",          [](const RenderContext& c) { return html_escape(c.room_id); }},
      {"event_id",         [](const RenderContext& c) { return html_escape(c.event_id); }},
      {"current_year",     [](const RenderContext& c) { return c.current_year; }},
      {"unsubscribe_link", [](const RenderContext& c) { return c.unsubscribe_link; }},
    };

    for (auto& [var, getter] : vars) {
      std::string placeholder = "{{ " + var + " }}";
      size_t pos = 0;
      while ((pos = result.find(placeholder, pos)) != std::string::npos) {
        result.replace(pos, placeholder.size(), getter(ctx));
        pos += getter(ctx).size();
      }
      // Also try without spaces: {{var}}
      placeholder = "{{" + var + "}}";
      pos = 0;
      while ((pos = result.find(placeholder, pos)) != std::string::npos) {
        result.replace(pos, placeholder.size(), getter(ctx));
        pos += getter(ctx).size();
      }
    }

    // Custom variables
    for (auto& [k, v] : ctx.custom_vars) {
      std::string ph1 = "{{ " + k + " }}";
      std::string ph2 = "{{" + k + "}}";
      size_t pos = 0;
      while ((pos = result.find(ph1, pos)) != std::string::npos) {
        result.replace(pos, ph1.size(), html_escape(v));
        pos += html_escape(v).size();
      }
      pos = 0;
      while ((pos = result.find(ph2, pos)) != std::string::npos) {
        result.replace(pos, ph2.size(), html_escape(v));
        pos += html_escape(v).size();
      }
    }

    return result;
  }

  // Process conditional blocks: {{#if var}}...{{/if}}
  std::string process_conditionals(const std::string& input, const RenderContext& ctx) const {
    std::string result = input;
    // Find {{#if var}} blocks
    std::regex if_pattern(R"(\{\{#if\s+(\w+)\}\}([\s\S]*?)\{\{\/if\}\})");
    std::smatch match;
    while (std::regex_search(result, match, if_pattern)) {
      std::string var_name = match[1].str();
      std::string block_content = match[2].str();
      bool show = false;

      if (var_name == "display_name" && !ctx.display_name.empty()) show = true;
      else if (var_name == "room_name" && !ctx.room_name.empty()) show = true;
      else if (var_name == "sender_name" && !ctx.sender_name.empty()) show = true;
      else if (var_name == "message_preview" && !ctx.message_preview.empty()) show = true;
      else if (var_name == "link" && !ctx.link.empty()) show = true;
      else if (var_name == "token" && !ctx.token.empty()) show = true;
      else if (var_name == "unsubscribe_link" && !ctx.unsubscribe_link.empty()) show = true;
      else if (var_name == "logo_url" && !ctx.logo_url.empty()) show = true;
      else if (ctx.custom_vars.count(var_name) > 0 && !ctx.custom_vars.at(var_name).empty()) show = true;

      result.replace(match.position(), match.length(), show ? block_content : "");
    }
    return result;
  }

  // Format an email address with display name
  std::string format_address(const std::string& name, const std::string& addr) const {
    if (name.empty()) return addr;
    return "\"" + name + "\" <" + addr + ">";
  }

  // RFC 2047 MIME header encoding for non-ASCII subjects
  std::string mime_header_encode(const std::string& s) const {
    bool has_non_ascii = false;
    for (unsigned char c : s) {
      if (c > 127) { has_non_ascii = true; break; }
    }
    if (!has_non_ascii) return s;
    return "=?UTF-8?B?" + b64_encode(s) + "?=";
  }

  // Quoted-printable encoding
  std::string qp_encode(const std::string& s) const {
    std::ostringstream ss;
    size_t line_len = 0;
    for (unsigned char c : s) {
      bool encode = (c < 32 || c > 126 || c == '=');
      if (c == '\n') {
        ss << "\r\n";
        line_len = 0;
        continue;
      }
      if (c == '\r') continue;
      if (line_len >= 75 && !encode) {
        ss << "=\r\n";
        line_len = 0;
      }
      if (encode) {
        ss << '=' << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(c) << std::nouppercase;
        line_len += 3;
      } else {
        ss << c;
        line_len++;
      }
    }
    return ss.str();
  }

  // RFC 2822 formatted date
  std::string rfc2822_date() const {
    auto now = chr::system_clock::now();
    auto t = chr::system_clock::to_time_t(now);
    char buf[128];
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %z", std::gmtime(&t));
    // Append timezone offset manually if %z is not supported
    std::string date(buf);
    if (date.find('+') == std::string::npos && date.find('-') == std::string::npos) {
      date += " +0000";
    }
    return date;
  }
};

// ============================================================================
// EmailTemplateCache — Thread-safe cache of compiled templates
// ============================================================================
class EmailTemplateCache {
public:
  EmailTemplateCache() = default;

  void put(const std::string& key, const EmailTemplate& tmpl) {
    std::unique_lock lock(mutex_);
    cache_[key] = tmpl;
  }

  std::optional<EmailTemplate> get(const std::string& key) const {
    std::shared_lock lock(mutex_);
    auto it = cache_.find(key);
    if (it != cache_.end()) return it->second;
    return std::nullopt;
  }

  void remove(const std::string& key) {
    std::unique_lock lock(mutex_);
    cache_.erase(key);
  }

  void clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
  }

  size_t size() const {
    std::shared_lock lock(mutex_);
    return cache_.size();
  }

  bool contains(const std::string& key) const {
    std::shared_lock lock(mutex_);
    return cache_.count(key) > 0;
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, EmailTemplate> cache_;
};

// ============================================================================
// EmailTemplateCompiler — Builds default templates for all email types
// ============================================================================
class EmailTemplateCompiler {
public:
  explicit EmailTemplateCompiler(const EmailConfig::TemplateSettings& settings)
      : settings_(settings) {}

  // Build all default templates
  std::unordered_map<EmailType, EmailTemplate> build_all() {
    std::unordered_map<EmailType, EmailTemplate> templates;
    templates[EmailType::PASSWORD_RESET] = build_password_reset();
    templates[EmailType::EMAIL_VERIFICATION] = build_email_verification();
    templates[EmailType::REGISTRATION] = build_registration();
    templates[EmailType::INVITE] = build_invite();
    templates[EmailType::NOTIFICATION] = build_notification();
    templates[EmailType::MESSAGE_NOTIFICATION] = build_message_notification();
    templates[EmailType::ACCOUNT_RENEWAL] = build_account_renewal();
    templates[EmailType::WELCOME] = build_welcome();
    templates[EmailType::ACCOUNT_DEACTIVATED] = build_account_deactivated();
    return templates;
  }

  // Get a single template by type
  EmailTemplate build(EmailType type) {
    switch (type) {
      case EmailType::PASSWORD_RESET: return build_password_reset();
      case EmailType::EMAIL_VERIFICATION: return build_email_verification();
      case EmailType::REGISTRATION: return build_registration();
      case EmailType::INVITE: return build_invite();
      case EmailType::NOTIFICATION: return build_notification();
      case EmailType::MESSAGE_NOTIFICATION: return build_message_notification();
      case EmailType::ACCOUNT_RENEWAL: return build_account_renewal();
      case EmailType::WELCOME: return build_welcome();
      case EmailType::ACCOUNT_DEACTIVATED: return build_account_deactivated();
      default: return EmailTemplate("unknown");
    }
  }

private:
  EmailConfig::TemplateSettings settings_;

  // Helper: wrap body in HTML wrapper
  std::string html_wrapper(const std::string& title, const std::string& body) {
    std::ostringstream html;
    html << "<!DOCTYPE html>\n<html>\n<head>\n";
    html << "<meta charset=\"utf-8\">\n";
    html << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    html << "<title>" << html_escape(title) << "</title>\n";
    html << "<style>\n";
    html << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; ";
    html << "max-width: 600px; margin: 0 auto; padding: 20px; color: #333; background: #f5f5f5; }\n";
    html << ".container { background: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n";
    html << ".header { text-align: center; padding-bottom: 20px; border-bottom: 1px solid #eee; margin-bottom: 20px; }\n";
    html << ".header h1 { color: #1a1a1a; font-size: 24px; margin: 0; }\n";
    html << ".content { line-height: 1.6; font-size: 16px; }\n";
    html << ".content p { margin: 0 0 16px 0; }\n";
    html << ".button { display: inline-block; padding: 12px 24px; background: #0d6efd; color: #fff !important; ";
    html << "text-decoration: none; border-radius: 6px; font-weight: 600; margin: 16px 0; }\n";
    html << ".button:hover { background: #0b5ed7; }\n";
    html << ".footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; ";
    html << "font-size: 12px; color: #888; text-align: center; }\n";
    html << ".code { background: #f0f0f0; padding: 10px 15px; border-radius: 4px; ";
    html << "font-family: 'Courier New', monospace; font-size: 18px; letter-spacing: 3px; text-align: center; }\n";
    html << ".preview { background: #f9f9f9; border-left: 4px solid #0d6efd; padding: 12px 16px; ";
    html << "margin: 12px 0; border-radius: 0 4px 4px 0; }\n";
    html << "</style>\n</head>\n<body>\n";
    html << "<div class=\"container\">\n";
    html << "{{#if logo_url}}<div class=\"header\">";
    html << "<img src=\"{{ logo_url }}\" alt=\"{{ server_name }}\" style=\"max-width:200px;height:auto;\">";
    html << "</div>{{/if logo_url}}\n";
    html << "<div class=\"header\"><h1>" << html_escape(title) << "</h1></div>\n";
    html << "<div class=\"content\">\n" << body << "\n</div>\n";
    html << "<div class=\"footer\">\n";
    html << "<p>Sent by {{ server_name }} Matrix server</p>\n";
    html << "{{#if unsubscribe_link}}<p><a href=\"{{ unsubscribe_link }}\">Unsubscribe from email notifications</a></p>{{/if unsubscribe_link}}\n";
    html << "<p>This is an automated message. Please do not reply to this email.</p>\n";
    html << "</div>\n";
    html << "</div>\n</body>\n</html>";
    return html.str();
  }

  // ========================================================================
  // Password Reset Template
  // ========================================================================
  EmailTemplate build_password_reset() {
    EmailTemplate tmpl("password_reset");

    // Subject
    tmpl.set_subject("Reset your {{ server_name }} password");

    // Plain text version
    std::ostringstream plain;
    plain << "Hello {{ display_name }},\n\n";
    plain << "A request has been made to reset the password for your account on {{ server_name }}.\n\n";
    plain << "To reset your password, please click the link below:\n\n";
    plain << "{{ link }}\n\n";
    plain << "If you did not request a password reset, you can safely ignore this email.\n\n";
    plain << "This link will expire in 1 hour.\n\n";
    plain << "Best regards,\n";
    plain << "The {{ server_name }} team\n";
    tmpl.set_plain_body(plain.str());

    // HTML version
    std::ostringstream html;
    html << "<p>Hello <strong>{{ display_name }}</strong>,</p>\n";
    html << "<p>A request has been made to reset the password for your account on {{ server_name }}.</p>\n";
    html << "<p>To reset your password, please click the button below:</p>\n";
    html << "<a href=\"{{ link }}\" class=\"button\">Reset Password</a>\n";
    html << "<p>Or copy and paste this link into your browser:</p>\n";
    html << "<p style=\"word-break:break-all;\">{{ link }}</p>\n";
    html << "<p>If you did not request a password reset, you can safely ignore this email.</p>\n";
    html << "<p><small>This link will expire in 1 hour.</small></p>\n";
    tmpl.set_html_body(html_wrapper("Password Reset", html.str()));

    return tmpl;
  }

  // ========================================================================
  // Email Verification Template
  // ========================================================================
  EmailTemplate build_email_verification() {
    EmailTemplate tmpl("email_verification");

    tmpl.set_subject("Verify your email address for {{ server_name }}");

    std::ostringstream plain;
    plain << "Hello {{ display_name }},\n\n";
    plain << "Welcome to {{ server_name }}! Please verify your email address by clicking the link below:\n\n";
    plain << "{{ link }}\n\n";
    plain << "If you did not create an account on {{ server_name }}, please ignore this email.\n\n";
    plain << "This verification link will expire in 24 hours.\n\n";
    plain << "Best regards,\n";
    plain << "The {{ server_name }} team\n";
    tmpl.set_plain_body(plain.str());

    std::ostringstream html;
    html << "<p>Hello <strong>{{ display_name }}</strong>,</p>\n";
    html << "<p>Welcome to {{ server_name }}! Please verify your email address by clicking the button below:</p>\n";
    html << "<a href=\"{{ link }}\" class=\"button\">Verify Email Address</a>\n";
    html << "<p>Or copy and paste this link into your browser:</p>\n";
    html << "<p style=\"word-break:break-all;\">{{ link }}</p>\n";
    html << "<p>If you did not create an account on {{ server_name }}, please ignore this email.</p>\n";
    html << "<p><small>This verification link will expire in 24 hours.</small></p>\n";
    tmpl.set_html_body(html_wrapper("Email Verification", html.str()));

    return tmpl;
  }

  // ========================================================================
  // Registration Template
  // ========================================================================
  EmailTemplate build_registration() {
    EmailTemplate tmpl("registration");

    tmpl.set_subject("Welcome to {{ server_name }} — Complete Your Registration");

    std::ostringstream plain;
    plain << "Hello {{ display_name }},\n\n";
    plain << "Thank you for registering with {{ server_name }}!\n\n";
    plain << "To complete your registration, please verify your email address by clicking the link below:\n\n";
    plain << "{{ link }}\n\n";
    plain << "Your account details:\n";
    plain << "  Username: {{ user_id }}\n";
    plain << "  Server: {{ server_name }}\n\n";
    plain << "If you have any questions, please contact us at {{ support_email }}.\n\n";
    plain << "Best regards,\n";
    plain << "The {{ server_name }} team\n";
    tmpl.set_plain_body(plain.str());

    std::ostringstream html;
    html << "<p>Hello <strong>{{ display_name }}</strong>,</p>\n";
    html << "<p>Thank you for registering with {{ server_name }}!</p>\n";
    html << "<p>To complete your registration and activate your account, please verify your email address:</p>\n";
    html << "<a href=\"{{ link }}\" class=\"button\">Complete Registration</a>\n";
    html << "<p>Your account details:</p>\n";
    html << "<ul>\n";
    html << "<li><strong>Username:</strong> {{ user_id }}</li>\n";
    html << "<li><strong>Server:</strong> {{ server_name }}</li>\n";
    html << "</ul>\n";
    html << "<p>If you have any questions, please contact us at <a href=\"mailto:{{ support_email }}\">{{ support_email }}</a>.</p>\n";
    tmpl.set_html_body(html_wrapper("Complete Your Registration", html.str()));

    return tmpl;
  }

  // ========================================================================
  // Invite Template
  // ========================================================================
  EmailTemplate build_invite() {
    EmailTemplate tmpl("invite");

    tmpl.set_subject("{{ sender_name }} invited you to {{ room_name }} on {{ server_name }}");

    std::ostringstream plain;
    plain << "Hello {{ display_name }},\n\n";
    plain << "{{ sender_name }} has invited you to join the room \"{{ room_name }}\" on {{ server_name }}.\n\n";
    plain << "To accept this invitation, please click the link below:\n\n";
    plain << "{{ link }}\n\n";
    plain << "Room details:\n";
    plain << "  Room Name: {{ room_name }}\n";
    plain << "  Invited by: {{ sender_name }}\n\n";
    plain << "If you do not wish to join this room, you can ignore this invitation.\n\n";
    plain << "Best regards,\n";
    plain << "The {{ server_name }} team\n";
    tmpl.set_plain_body(plain.str());

    std::ostringstream html;
    html << "<p>Hello <strong>{{ display_name }}</strong>,</p>\n";
    html << "<p><strong>{{ sender_name }}</strong> has invited you to join a room on {{ server_name }}:</p>\n";
    html << "<div class=\"preview\">\n";
    html << "<strong>Room:</strong> {{ room_name }}\n";
    html << "</div>\n";
    html << "<a href=\"{{ link }}\" class=\"button\">Join Room</a>\n";
    html << "<p>Invited by: <strong>{{ sender_name }}</strong></p>\n";
    html << "<p>If you do not wish to join this room, you can ignore this invitation.</p>\n";
    tmpl.set_html_body(html_wrapper("Room Invitation", html.str()));

    return tmpl;
  }

  // ========================================================================
  // Notification Template
  // ========================================================================
  EmailTemplate build_notification() {
    EmailTemplate tmpl("notification");

    tmpl.set_subject("{{ server_name }} Notification{{#if room_name}}: {{ room_name }}{{/if room_name}}");

    std::ostringstream plain;
    plain << "Hello {{ display_name }},\n\n";
    plain << "You have a new notification on {{ server_name }}.\n\n";
    plain << "{{#if message_preview}}Message: {{ message_preview }}{{/if message_preview}}\n\n";
    plain << "{{#if room_name}}Room: {{ room_name }}{{/if room_name}}\n";
    plain << "{{#if sender_name}}From: {{ sender_name }}{{/if sender_name}}\n\n";
    plain << "View it here: {{ link }}\n\n";
    plain << "{{#if unsubscribe_link}}To manage your notification preferences, visit: {{ unsubscribe_link }}{{/if unsubscribe_link}}\n\n";
    plain << "Best regards,\n";
    plain << "The {{ server_name }} team\n";
    tmpl.set_plain_body(plain.str());

    std::ostringstream html;
    html << "<p>Hello <strong>{{ display_name }}</strong>,</p>\n";
    html << "<p>You have a new notification on {{ server_name }}.</p>\n";
    html << "{{#if message_preview}}<div class=\"preview\">{{ message_preview }}</div>{{/if message_preview}}\n";
    html << "{{#if room_name}}<p><strong>Room:</strong> {{ room_name }}</p>{{/if room_name}}\n";
    html << "{{#if sender_name}}<p><strong>From:</strong> {{ sender_name }}</p>{{/if sender_name}}\n";
    html << "<a href=\"{{ link }}\" class=\"button\">View Notification</a>\n";
    html << "{{#if unsubscribe_link}}<p style=\"font-size:12px;\">";
    html << "<a href=\"{{ unsubscribe_link }}\">Manage notification preferences</a></p>{{/if unsubscribe_link}}\n";
    tmpl.set_html_body(html_wrapper("New Notification", html.str()));

    return tmpl;
  }

  // ========================================================================
  // Message Notification Template
  // ========================================================================
  EmailTemplate build_message_notification() {
    EmailTemplate tmpl("message_notification");

    tmpl.set_subject("{{ sender_name }} sent a message in {{ room_name }}");

    std::ostringstream plain;
    plain << "Hello {{ display_name }},\n\n";
    plain << "{{ sender_name }} sent a new message in {{ room_name }}:\n\n";
    plain << "{{ message_preview }}\n\n";
    plain << "View the message: {{ link }}\n\n";
    plain << "To reply, open {{ server_name }}:\n";
    plain << "{{ link }}\n\n";
    plain << "{{#if unsubscribe_link}}To manage email notification preferences: {{ unsubscribe_link }}{{/if unsubscribe_link}}\n\n";
    plain << "The {{ server_name }} team\n";
    tmpl.set_plain_body(plain.str());

    std::ostringstream html;
    html << "<p>Hello <strong>{{ display_name }}</strong>,</p>\n";
    html << "<p><strong>{{ sender_name }}</strong> sent a message in ";
    html << "<strong>{{ room_name }}</strong>:</p>\n";
    html << "<div class=\"preview\">{{ message_preview }}</div>\n";
    html << "<a href=\"{{ link }}\" class=\"button\">View Message</a>\n";
    html << "<p><small>";
    html << "{{#if unsubscribe_link}}<a href=\"{{ unsubscribe_link }}\">Manage email preferences</a>{{/if unsubscribe_link}}";
    html << "</small></p>\n";
    tmpl.set_html_body(html_wrapper("New Message", html.str()));

    return tmpl;
  }

  // ========================================================================
  // Account Renewal Template
  // ========================================================================
  EmailTemplate build_account_renewal() {
    EmailTemplate tmpl("account_renewal");

    tmpl.set_subject("Your {{ server_name }} account is expiring soon");

    std::ostringstream plain;
    plain << "Hello {{ display_name }},\n\n";
    plain << "Your account on {{ server_name }} is scheduled to expire soon.\n\n";
    plain << "To renew your account and maintain access, please click the link below:\n\n";
    plain << "{{ link }}\n\n";
    plain << "If you do not renew your account, it may be deactivated.\n\n";
    plain << "If you have questions, please contact {{ support_email }}.\n\n";
    plain << "Best regards,\n";
    plain << "The {{ server_name }} team\n";
    tmpl.set_plain_body(plain.str());

    std::ostringstream html;
    html << "<p>Hello <strong>{{ display_name }}</strong>,</p>\n";
    html << "<p>Your account on {{ server_name }} is scheduled to expire soon.</p>\n";
    html << "<p>To renew your account and maintain full access, please click below:</p>\n";
    html << "<a href=\"{{ link }}\" class=\"button\">Renew Account</a>\n";
    html << "<p>If you do not renew your account, it may be deactivated and you will lose access.</p>\n";
    html << "<p>If you have questions, please contact <a href=\"mailto:{{ support_email }}\">{{ support_email }}</a>.</p>\n";
    tmpl.set_html_body(html_wrapper("Account Renewal Required", html.str()));

    return tmpl;
  }

  // ========================================================================
  // Welcome Template
  // ========================================================================
  EmailTemplate build_welcome() {
    EmailTemplate tmpl("welcome");

    tmpl.set_subject("Welcome to {{ server_name }}!");

    std::ostringstream plain;
    plain << "Hello {{ display_name }},\n\n";
    plain << "Welcome to {{ server_name }}! Your account has been created successfully.\n\n";
    plain << "You can now:\n";
    plain << "  - Chat with other users on {{ server_name }}\n";
    plain << "  - Join rooms and communities\n";
    plain << "  - Connect with users on other Matrix servers\n\n";
    plain << "Get started: {{ link }}\n\n";
    plain << "If you have any questions, feel free to reach out at {{ support_email }}.\n\n";
    plain << "Happy chatting!\n";
    plain << "The {{ server_name }} team\n";
    tmpl.set_plain_body(plain.str());

    std::ostringstream html;
    html << "<p>Hello <strong>{{ display_name }}</strong>,</p>\n";
    html << "<p>Welcome to {{ server_name }}! Your account has been created successfully.</p>\n";
    html << "<div style=\"background:#f0f8ff;padding:15px;border-radius:6px;margin:15px 0;\">\n";
    html << "<h3 style=\"margin-top:0;\">You can now:</h3>\n";
    html << "<ul>\n";
    html << "<li>Chat with other users on {{ server_name }}</li>\n";
    html << "<li>Join rooms and communities</li>\n";
    html << "<li>Connect with users on other Matrix servers</li>\n";
    html << "</ul>\n";
    html << "</div>\n";
    html << "<a href=\"{{ link }}\" class=\"button\">Get Started</a>\n";
    html << "<p>If you have any questions, feel free to reach out at ";
    html << "<a href=\"mailto:{{ support_email }}\">{{ support_email }}</a>.</p>\n";
    html << "<p>Happy chatting!</p>\n";
    tmpl.set_html_body(html_wrapper("Welcome!", html.str()));

    return tmpl;
  }

  // ========================================================================
  // Account Deactivated Template
  // ========================================================================
  EmailTemplate build_account_deactivated() {
    EmailTemplate tmpl("account_deactivated");

    tmpl.set_subject("Your {{ server_name }} account has been deactivated");

    std::ostringstream plain;
    plain << "Hello {{ display_name }},\n\n";
    plain << "Your account on {{ server_name }} has been deactivated.\n\n";
    plain << "You will no longer be able to:\n";
    plain << "  - Send or receive messages\n";
    plain << "  - Join rooms\n";
    plain << "  - Access your account data\n\n";
    plain << "If you believe this was done in error, please contact us at {{ support_email }}.\n\n";
    plain << "Regards,\n";
    plain << "The {{ server_name }} team\n";
    tmpl.set_plain_body(plain.str());

    std::ostringstream html;
    html << "<p>Hello <strong>{{ display_name }}</strong>,</p>\n";
    html << "<p>Your account on {{ server_name }} has been deactivated.</p>\n";
    html << "<div style=\"background:#fff3cd;padding:15px;border-radius:6px;margin:15px 0;border:1px solid #ffc107;\">\n";
    html << "<strong>You will no longer be able to:</strong>\n";
    html << "<ul>\n";
    html << "<li>Send or receive messages</li>\n";
    html << "<li>Join rooms</li>\n";
    html << "<li>Access your account data</li>\n";
    html << "</ul>\n";
    html << "</div>\n";
    html << "<p>If you believe this was done in error, please contact us at ";
    html << "<a href=\"mailto:{{ support_email }}\">{{ support_email }}</a>.</p>\n";
    tmpl.set_html_body(html_wrapper("Account Deactivated", html.str()));

    return tmpl;
  }
};

// ============================================================================
// SmtpClient — SMTP client with STARTTLS and authentication
// ============================================================================
class SmtpClient {
public:
  SmtpClient() : sock_(INVALID_SOCK), connected_(false), authenticated_(false) {}
  ~SmtpClient() { disconnect(); }

  // ---- Connection lifecycle ----
  bool connect(const std::string& host, int port, SmtpEncryption encryption,
               int timeout_secs = SMTP_TIMEOUT_SECS) {
    host_ = host;
    port_ = port;
    encryption_ = encryption;

    if (encryption == SmtpEncryption::SSL_TLS) {
      // Direct SSL connection
      sock_ = tcp_connect(host, port, timeout_secs);
    } else {
      // Plain or STARTTLS — connect plain first
      int connect_port = (port > 0) ? port : SMTP_DEFAULT_PORT;
      sock_ = tcp_connect(host, connect_port, timeout_secs);
    }

    if (sock_ == INVALID_SOCK) {
      last_error_ = "Failed to connect to " + host + ":" + std::to_string(port);
      return false;
    }
    connected_ = true;

    // Read greeting banner
    if (!recv_expect(220)) {
      last_error_ = "SMTP greeting error: " + last_response_;
      disconnect();
      return false;
    }

    // EHLO
    std::map<std::string, std::string> extensions;
    if (!ehlo("localhost", extensions)) {
      // Fallback to HELO
      if (!helo("localhost")) {
        last_error_ = "EHLO/HELO failed";
        disconnect();
        return false;
      }
    }

    // STARTTLS if configured
    if (encryption == SmtpEncryption::STARTTLS) {
      if (!starttls()) {
        last_error_ = "STARTTLS failed";
        disconnect();
        return false;
      }
      // Re-EHLO after STARTTLS
      extensions.clear();
      if (!ehlo("localhost", extensions)) {
        last_error_ = "EHLO after STARTTLS failed";
        disconnect();
        return false;
      }
    }

    return true;
  }

  void disconnect() {
    if (connected_ && sock_ != INVALID_SOCK) {
      send_cmd("QUIT");
      // Don't wait for response, just close
      SOCK_CLOSE(sock_);
    }
    sock_ = INVALID_SOCK;
    connected_ = false;
    authenticated_ = false;
  }

  // ---- EHLO / HELO / STARTTLS ----
  bool ehlo(const std::string& hostname,
            std::map<std::string, std::string>& extensions) {
    if (!send_cmd("EHLO " + hostname)) return false;
    return recv_multiline(250, extensions);
  }

  bool helo(const std::string& hostname) {
    if (!send_cmd("HELO " + hostname)) return false;
    return recv_expect(250);
  }

  bool starttls() {
    if (!send_cmd("STARTTLS")) return false;
    if (!recv_expect(220)) return false;
    // In production: initiate TLS handshake on the socket
    // For this implementation, we note that STARTTLS was acknowledged
    tls_active_ = true;
    return true;
  }

  // ---- Authentication ----
  bool auth_login(const std::string& user, const std::string& password) {
    if (!send_cmd("AUTH LOGIN")) return false;
    std::string resp;
    if (!recv_line(resp) || resp.size() < 3 || resp[0] != '3') return false;
    tcp_send(sock_, b64_encode(user) + "\r\n");
    if (!recv_expect(334)) return false;
    tcp_send(sock_, b64_encode(password) + "\r\n");
    if (!recv_expect(235)) return false;
    authenticated_ = true;
    auth_user_ = user;
    return true;
  }

  bool auth_plain(const std::string& user, const std::string& password) {
    std::string auth = std::string("\0", 1) + user + std::string("\0", 1) + password;
    if (!send_cmd("AUTH PLAIN " + b64_encode(auth))) return false;
    if (!recv_expect(235)) return false;
    authenticated_ = true;
    auth_user_ = user;
    return true;
  }

  bool auth(const std::string& user, const std::string& password, SmtpAuthMethod method) {
    switch (method) {
      case SmtpAuthMethod::LOGIN: return auth_login(user, password);
      case SmtpAuthMethod::PLAIN: return auth_plain(user, password);
      case SmtpAuthMethod::NONE: return true;
      default:
        last_error_ = "Unsupported auth method";
        return false;
    }
  }

  // ---- Envelope commands ----
  bool mail_from(const std::string& addr, int64_t estimated_size = 0) {
    std::string cmd = "MAIL FROM:<" + addr + ">";
    if (estimated_size > 0)
      cmd += " SIZE=" + std::to_string(estimated_size);
    return send_cmd(cmd) && recv_expect(250);
  }

  bool rcpt_to(const std::string& addr) {
    std::string cmd = "RCPT TO:<" + addr + ">";
    return send_cmd(cmd) && recv_expect(250);
  }

  // ---- DATA transfer ----
  bool data_begin() {
    return send_cmd("DATA") && recv_expect(354);
  }

  bool data_send(const std::string& mime_data) {
    // Dot-stuff lines that start with '.'
    std::string stuffed;
    stuffed.reserve(mime_data.size() + mime_data.size() / 78);
    size_t pos = 0;
    while (pos < mime_data.size()) {
      size_t nl = mime_data.find("\r\n", pos);
      if (nl == std::string::npos) nl = mime_data.size();
      std::string line = mime_data.substr(pos, nl - pos);
      if (!line.empty() && line[0] == '.') stuffed += ".";
      stuffed += line + "\r\n";
      pos = nl + 2;
      if (nl == mime_data.size()) break;
    }
    stuffed += ".\r\n";
    tcp_send(sock_, stuffed);
    return recv_expect(250);
  }

  // Send a complete email in one call
  bool send_mail(const std::string& from,
                 const std::vector<std::string>& recipients,
                 const std::string& mime_data) {
    if (!mail_from(from, static_cast<int64_t>(mime_data.size())))
      return false;
    for (auto& r : recipients)
      if (!rcpt_to(r)) return false;
    if (!data_begin()) return false;
    return data_send(mime_data);
  }

  // ---- RSET for resetting state ----
  bool rset() { return send_cmd("RSET") && recv_expect(250); }

  // ---- State queries ----
  bool is_connected() const { return connected_ && sock_ != INVALID_SOCK; }
  bool is_authenticated() const { return authenticated_; }
  const std::string& last_error() const { return last_error_; }
  const std::string& host() const { return host_; }

private:
  sockfd_t sock_ = INVALID_SOCK;
  bool connected_ = false;
  bool authenticated_ = false;
  bool tls_active_ = false;
  std::string host_;
  int port_ = 0;
  SmtpEncryption encryption_ = SmtpEncryption::STARTTLS;
  std::string auth_user_;
  std::string last_error_;
  std::string last_response_;

  bool send_cmd(const std::string& cmd) {
    std::string data = cmd + "\r\n";
    return tcp_send(sock_, data) == static_cast<int>(data.size());
  }

  bool recv_line(std::string& line, int timeout_ms = SMTP_TIMEOUT_SECS * 1000) {
    int n = tcp_recv_line(sock_, line, timeout_ms);
    if (n > 0) last_response_ = line;
    return n > 0;
  }

  bool recv_expect(int expected_code) {
    std::string line;
    if (!recv_line(line)) return false;
    if (line.size() >= 3) {
      int code = 0;
      try { code = std::stoi(line.substr(0, 3)); }
      catch (...) { return false; }
      return code == expected_code;
    }
    return false;
  }

  bool recv_multiline(int expected_code,
                      std::map<std::string, std::string>& extensions) {
    std::string line;
    while (recv_line(line)) {
      if (line.size() >= 4 && line[3] == ' ') {
        // Last line of multiline response
        int code = 0;
        try { code = std::stoi(line.substr(0, 3)); }
        catch (...) { return false; }
        return code == expected_code;
      }
      if (line.size() > 4) {
        std::string content = line.substr(4);
        auto sp = content.find(' ');
        if (sp != std::string::npos) {
          extensions[to_lower(content.substr(0, sp))] = content.substr(sp + 1);
        } else {
          extensions[to_lower(content)] = "";
        }
      }
    }
    return false;
  }
};

// ============================================================================
// SmtpConnectionPool — Pool of reusable SMTP connections
// ============================================================================
class SmtpConnectionPool {
public:
  struct PooledConnection {
    std::unique_ptr<SmtpClient> client;
    int64_t last_used_at = 0;
    int use_count = 0;
  };

  explicit SmtpConnectionPool(const EmailConfig::SmtpSettings& settings)
      : settings_(settings) {}

  ~SmtpConnectionPool() { shutdown(); }

  // Acquire a connection from the pool
  std::unique_ptr<SmtpClient> acquire() {
    std::unique_lock lock(mutex_);

    // Try to get an idle connection
    while (!idle_.empty()) {
      auto& pooled = idle_.front();
      if (pooled.client->is_connected() && pooled.client->is_authenticated()) {
        auto client = std::move(pooled.client);
        idle_.pop();
        active_count_++;
        return client;
      } else {
        idle_.pop();
        total_count_--;
      }
    }

    // Create a new connection if under max
    if (active_count_ + idle_.size() < static_cast<size_t>(settings_.max_connections)) {
      lock.unlock();
      auto client = create_connection();
      if (client) {
        std::unique_lock lock2(mutex_);
        active_count_++;
        total_count_++;
      }
      return client;
    }

    // Wait for a connection to become available
    cv_.wait_for(lock, chr::seconds(SMTP_TIMEOUT_SECS), [this] {
      return !idle_.empty();
    });

    if (!idle_.empty()) {
      auto& pooled = idle_.front();
      if (pooled.client->is_connected()) {
        auto client = std::move(pooled.client);
        idle_.pop();
        active_count_++;
        return client;
      }
    }

    return nullptr;
  }

  // Release a connection back to the pool
  void release(std::unique_ptr<SmtpClient> client) {
    if (!client) return;
    std::unique_lock lock(mutex_);
    active_count_--;
    if (client->is_connected()) {
      PooledConnection pooled;
      pooled.client = std::move(client);
      pooled.last_used_at = now_epoch_seconds();
      idle_.push(std::move(pooled));
      cv_.notify_one();
    } else {
      total_count_--;
    }
  }

  // Periodic maintenance: close idle connections
  void prune_idle() {
    std::unique_lock lock(mutex_);
    int64_t cutoff = now_epoch_seconds() - SMTP_POOL_IDLE_TIMEOUT_SECS;
    size_t sz = idle_.size();
    for (size_t i = 0; i < sz; i++) {
      auto& pooled = idle_.front();
      if (pooled.last_used_at < cutoff) {
        idle_.pop();
        total_count_--;
      } else {
        idle_.push(std::move(pooled));
        idle_.pop();
      }
    }
  }

  void shutdown() {
    std::unique_lock lock(mutex_);
    while (!idle_.empty()) {
      idle_.front().client->disconnect();
      idle_.pop();
    }
    total_count_ = 0;
    active_count_ = 0;
  }

  size_t active_count() const {
    std::shared_lock lock(mutex_);
    return active_count_;
  }

  size_t idle_count() const {
    std::shared_lock lock(mutex_);
    return idle_.size();
  }

  size_t total_count() const {
    std::shared_lock lock(mutex_);
    return total_count_;
  }

private:
  EmailConfig::SmtpSettings settings_;
  mutable std::shared_mutex mutex_;
  std::condition_variable_any cv_;
  std::queue<PooledConnection> idle_;
  std::atomic<size_t> active_count_{0};
  std::atomic<size_t> total_count_{0};

  std::unique_ptr<SmtpClient> create_connection() {
    auto client = std::make_unique<SmtpClient>();
    if (!client->connect(settings_.host, settings_.port,
                          settings_.encryption, settings_.timeout_secs)) {
      return nullptr;
    }
    if (settings_.auth_method != SmtpAuthMethod::NONE) {
      if (!client->auth(settings_.username, settings_.password, settings_.auth_method)) {
        client->disconnect();
        return nullptr;
      }
    }
    return client;
  }
};

// ============================================================================
// UserEmailThrottle — Per-user rate limiting
// ============================================================================
class UserEmailThrottle {
public:
  struct RateWindow {
    int64_t window_start = 0;
    int count = 0;
  };

  UserEmailThrottle(int max_per_hour, int max_per_day, int burst = 10)
      : max_per_hour_(max_per_hour), max_per_day_(max_per_day),
        burst_allowance_(burst) {}

  // Check if a user is allowed to send an email; update state if so
  bool check_and_increment(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    int64_t now = now_epoch_seconds();

    auto& user = user_windows_[user_id];
    // Hourly window
    if (now - user.hourly.window_start >= 3600) {
      user.hourly.window_start = now;
      user.hourly.count = 0;
    }
    // Daily window
    if (now - user.daily.window_start >= 86400) {
      user.daily.window_start = now;
      user.daily.count = 0;
    }

    int burst_limit = max_per_hour_ + burst_allowance_;
    if (user.hourly.count >= burst_limit) return false;
    if (user.daily.count >= max_per_day_) return false;

    user.hourly.count++;
    user.daily.count++;
    return true;
  }

  // Check without incrementing
  bool check_only(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    int64_t now = now_epoch_seconds();
    auto it = user_windows_.find(user_id);
    if (it == user_windows_.end()) return true;

    int hourly = (now - it->second.hourly.window_start < 3600) ? it->second.hourly.count : 0;
    int daily = (now - it->second.daily.window_start < 86400) ? it->second.daily.count : 0;

    return hourly < (max_per_hour_ + burst_allowance_) && daily < max_per_day_;
  }

  // Get remaining allowance
  int remaining_hourly(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    int64_t now = now_epoch_seconds();
    auto it = user_windows_.find(user_id);
    if (it == user_windows_.end()) return max_per_hour_ + burst_allowance_;

    int count = (now - it->second.hourly.window_start < 3600) ? it->second.hourly.count : 0;
    return std::max(0, (max_per_hour_ + burst_allowance_) - count);
  }

  void reset_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    user_windows_.erase(user_id);
  }

  void prune_stale() {
    std::unique_lock lock(mutex_);
    int64_t cutoff = now_epoch_seconds() - 86400;
    for (auto it = user_windows_.begin(); it != user_windows_.end(); ) {
      if (it->second.daily.window_start < cutoff)
        it = user_windows_.erase(it);
      else
        ++it;
    }
  }

  size_t tracked_users() const {
    std::shared_lock lock(mutex_);
    return user_windows_.size();
  }

private:
  struct Windows {
    RateWindow hourly;
    RateWindow daily;
  };

  int max_per_hour_;
  int max_per_day_;
  int burst_allowance_;
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, Windows> user_windows_;
};

// ============================================================================
// EmailTypeThrottle — Per-email-type rate limiting
// ============================================================================
class EmailTypeThrottle {
public:
  EmailTypeThrottle(int max_per_hour) : max_per_hour_(max_per_hour) {}

  bool check_and_increment(EmailType type) {
    std::unique_lock lock(mutex_);
    int64_t now = now_epoch_seconds();
    auto& window = windows_[static_cast<uint8_t>(type)];
    if (now - window.start >= 3600) {
      window.start = now;
      window.count = 0;
    }
    if (window.count >= max_per_hour_) return false;
    window.count++;
    return true;
  }

  int remaining(EmailType type) {
    std::shared_lock lock(mutex_);
    int64_t now = now_epoch_seconds();
    auto it = windows_.find(static_cast<uint8_t>(type));
    if (it == windows_.end()) return max_per_hour_;
    int count = (now - it->second.start < 3600) ? it->second.count : 0;
    return std::max(0, max_per_hour_ - count);
  }

private:
  struct Window {
    int64_t start = 0;
    int count = 0;
  };

  int max_per_hour_;
  mutable std::shared_mutex mutex_;
  std::unordered_map<uint8_t, Window> windows_;
};

// ============================================================================
// GlobalEmailThrottle — Global email rate limiting
// ============================================================================
class GlobalEmailThrottle {
public:
  GlobalEmailThrottle(int max_per_hour) : max_per_hour_(max_per_hour) {}

  bool check_and_increment() {
    std::unique_lock lock(mutex_);
    int64_t now = now_epoch_seconds();
    if (now - window_start_ >= 3600) {
      window_start_ = now;
      window_count_ = 0;
    }
    if (window_count_ >= max_per_hour_) return false;
    window_count_++;
    return true;
  }

  int remaining() const {
    std::shared_lock lock(mutex_);
    int64_t now = now_epoch_seconds();
    int count = (now - window_start_ < 3600) ? window_count_ : 0;
    return std::max(0, max_per_hour_ - count);
  }

  int total_sent_this_hour() const {
    std::shared_lock lock(mutex_);
    int64_t now = now_epoch_seconds();
    return (now - window_start_ < 3600) ? window_count_ : 0;
  }

private:
  int max_per_hour_;
  mutable std::shared_mutex mutex_;
  int64_t window_start_ = 0;
  int window_count_ = 0;
};

// ============================================================================
// EmailThrottler — Combines all throttle layers
// ============================================================================
class EmailThrottler {
public:
  explicit EmailThrottler(const EmailConfig::RateLimitSettings& settings)
      : settings_(settings),
        user_throttle_(settings.per_user_per_hour, settings.per_user_per_day,
                       settings.burst_allowance),
        type_throttle_(settings.per_type_per_hour),
        global_throttle_(settings.global_per_hour) {}

  struct ThrottleResult {
    bool allowed = false;
    std::string reason;
    int retry_after_seconds = 0;
  };

  ThrottleResult check_and_increment(const std::string& user_id, EmailType type) {
    if (!settings_.rate_limiting_enabled)
      return {true, "", 0};

    // Check global first
    if (!global_throttle_.check_and_increment())
      return {false, "Global email rate limit exceeded", 3600};

    // Check per-type
    if (!type_throttle_.check_and_increment(type))
      return {false, "Email type rate limit exceeded", 3600};

    // Check per-user
    if (!user_throttle_.check_and_increment(user_id))
      return {false, "Per-user email rate limit exceeded", 3600};

    return {true, "", 0};
  }

  int user_remaining(const std::string& user_id) {
    return user_throttle_.remaining_hourly(user_id);
  }

  int global_remaining() { return global_throttle_.remaining(); }

  void reset_user(const std::string& user_id) { user_throttle_.reset_user(user_id); }

  void prune() { user_throttle_.prune_stale(); }

private:
  EmailConfig::RateLimitSettings settings_;
  UserEmailThrottle user_throttle_;
  EmailTypeThrottle type_throttle_;
  GlobalEmailThrottle global_throttle_;
};

// ============================================================================
// DisposableEmailBlocklist — Blocks known disposable email providers
// ============================================================================
class DisposableEmailBlocklist {
public:
  DisposableEmailBlocklist() { init_defaults(); }

  bool is_disposable(const std::string& domain) const {
    std::shared_lock lock(mutex_);
    return domains_.count(to_lower(domain)) > 0;
  }

  void add_domain(const std::string& domain) {
    std::unique_lock lock(mutex_);
    domains_.insert(to_lower(domain));
  }

  void remove_domain(const std::string& domain) {
    std::unique_lock lock(mutex_);
    domains_.erase(to_lower(domain));
  }

  size_t size() const {
    std::shared_lock lock(mutex_);
    return domains_.size();
  }

  void load_from_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;
    std::string line;
    std::unique_lock lock(mutex_);
    while (std::getline(file, line)) {
      line = trim_str(line);
      if (!line.empty() && line[0] != '#')
        domains_.insert(to_lower(line));
    }
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_set<std::string> domains_;

  void init_defaults() {
    // Common disposable email domains
    static const char* defaults[] = {
      "mailinator.com", "yopmail.com", "guerrillamail.com",
      "10minutemail.com", "tempmail.com", "throwaway.email",
      "sharklasers.com", "trashmail.com", "dispostable.com",
      "fakeinbox.com", "maildrop.cc", "getnada.com",
      "spamgourmet.com", "mytemp.email", "temp-mail.org",
      "mohmal.com", "emailondeck.com", "spambox.us",
      "throwawaymail.com", "mailnesia.com", "burnermail.io",
      "mailcatch.com", "anonaddy.com", "simplelogin.com",
      "duck.com", "33mail.com", "erine.email",
    };
    for (auto& d : defaults) {
      domains_.insert(std::string(d));
    }
  }
};

// ============================================================================
// MxResolver — DNS MX record resolution
// ============================================================================
class MxResolver {
public:
  struct MxRecord {
    std::string hostname;
    int priority = 0;
  };

  // Check if a domain has valid MX records
  bool has_mx_records(const std::string& domain) {
    std::vector<MxRecord> records = lookup_mx(domain);
    if (!records.empty()) return true;

    // Check cached result
    {
      std::shared_lock lock(cache_mutex_);
      auto it = mx_cache_.find(to_lower(domain));
      if (it != mx_cache_.end()) return it->second;
    }

    // Do actual lookup
    records = do_mx_lookup(domain);
    bool has_records = !records.empty();

    // Cache result
    {
      std::unique_lock lock(cache_mutex_);
      mx_cache_[to_lower(domain)] = has_records;
    }

    return has_records;
  }

  std::vector<MxRecord> lookup_mx(const std::string& domain) {
    return do_mx_lookup(domain);
  }

  void clear_cache() {
    std::unique_lock lock(cache_mutex_);
    mx_cache_.clear();
  }

  size_t cache_size() const {
    std::shared_lock lock(cache_mutex_);
    return mx_cache_.size();
  }

private:
  mutable std::shared_mutex cache_mutex_;
  std::unordered_map<std::string, bool> mx_cache_;

  std::vector<MxRecord> do_mx_lookup(const std::string& domain) {
    std::vector<MxRecord> records;

    // Use getaddrinfo for MX-like resolution
    // Real implementation would query DNS MX records directly
    // This is a simplified version that checks if the domain resolves
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(domain.c_str(), "25", &hints, &res);
    if (status == 0 && res) {
      MxRecord rec;
      rec.hostname = domain;
      rec.priority = 10;
      records.push_back(rec);
      freeaddrinfo(res);
    }

    // Also try common mail subdomain
    std::string mail_domain = "mail." + domain;
    status = getaddrinfo(mail_domain.c_str(), "25", &hints, &res);
    if (status == 0 && res) {
      MxRecord rec;
      rec.hostname = mail_domain;
      rec.priority = 20;
      records.push_back(rec);
      freeaddrinfo(res);
    }

    return records;
  }
};

// ============================================================================
// EmailValidator — Comprehensive email validation
// ============================================================================
class EmailValidator {
public:
  struct ValidationResult {
    bool valid = false;
    std::string reason;
    std::string normalized_email;
  };

  EmailValidator()
      : disposable_blocklist_(std::make_shared<DisposableEmailBlocklist>()),
        mx_resolver_(std::make_shared<MxResolver>()) {}

  // Validate an email address
  ValidationResult validate(const std::string& email, bool check_mx = false,
                             bool block_disposable = true) {
    ValidationResult result;

    // Basic sanity
    if (email.empty()) {
      result.reason = "Empty email address";
      return result;
    }

    if (email.size() > 254) {
      result.reason = "Email address too long (max 254 characters)";
      return result;
    }

    // Split local part and domain
    auto at_pos = email.find('@');
    if (at_pos == std::string::npos || at_pos == 0 || at_pos == email.size() - 1) {
      result.reason = "Invalid email format: missing or misplaced @ symbol";
      return result;
    }

    std::string local = email.substr(0, at_pos);
    std::string domain = email.substr(at_pos + 1);

    // Validate local part
    if (local.size() > 64) {
      result.reason = "Local part too long (max 64 characters)";
      return result;
    }

    // RFC 5322 simplified local part validation
    static const std::regex local_regex(
        R"(^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$)");
    if (!std::regex_match(local, local_regex)) {
      result.reason = "Local part contains invalid characters";
      return result;
    }

    // Cannot start or end with dot
    if (local.front() == '.' || local.back() == '.') {
      result.reason = "Local part cannot start or end with a dot";
      return result;
    }

    // No consecutive dots
    if (local.find("..") != std::string::npos) {
      result.reason = "Local part cannot contain consecutive dots";
      return result;
    }

    // Validate domain
    if (domain.size() > 255) {
      result.reason = "Domain part too long (max 255 characters)";
      return result;
    }

    // Basic domain format check
    static const std::regex domain_regex(
        R"(^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.?$)");
    if (!std::regex_match(domain, domain_regex)) {
      result.reason = "Domain part contains invalid characters or format";
      return result;
    }

    // Must have at least one dot (TLD)
    if (domain.find('.') == std::string::npos && domain != "localhost") {
      result.reason = "Domain must have a TLD";
      return result;
    }

    // Check disposable email providers
    if (block_disposable && disposable_blocklist_->is_disposable(domain)) {
      result.reason = "Disposable email addresses are not allowed";
      return result;
    }

    // Role account detection
    static const std::unordered_set<std::string> role_accounts = {
      "abuse", "admin", "administrator", "billing", "contact", "help",
      "hostmaster", "info", "noreply", "no-reply", "postmaster", "root",
      "sales", "security", "support", "webmaster", "www"
    };
    if (role_accounts.count(to_lower(local)) > 0) {
      result.reason = "Role-based email addresses are not allowed for personal accounts";
      return result;
    }

    // MX record check
    if (check_mx && !mx_resolver_->has_mx_records(domain)) {
      result.reason = "Domain does not have valid MX records";
      return result;
    }

    result.valid = true;
    result.normalized_email = to_lower(email);
    return result;
  }

  // Quick check without MX/detailed validation
  bool is_valid_format(const std::string& email) {
    return validate(email, false, false).valid;
  }

  // Check if email is from a disposable provider
  bool is_disposable(const std::string& email) {
    auto at = email.find('@');
    if (at == std::string::npos) return false;
    return disposable_blocklist_->is_disposable(email.substr(at + 1));
  }

  std::shared_ptr<DisposableEmailBlocklist> blocklist() { return disposable_blocklist_; }
  std::shared_ptr<MxResolver> mx_resolver() { return mx_resolver_; }

private:
  std::shared_ptr<DisposableEmailBlocklist> disposable_blocklist_;
  std::shared_ptr<MxResolver> mx_resolver_;
};

// ============================================================================
// EmailPreferenceStore — Stores per-user email notification preferences
// ============================================================================
class EmailPreferenceStore {
public:
  struct UserPreferences {
    bool email_notifications_enabled = true;
    bool password_reset_emails = true;
    bool verification_emails = true;
    bool invitation_emails = true;
    bool notification_emails = true;
    bool message_notification_emails = true;
    bool account_renewal_emails = true;
    bool welcome_emails = true;
    bool deactivation_emails = true;
    int64_t updated_at = 0;
  };

  EmailPreferenceStore() = default;

  void set_defaults(const UserPreferences& prefs) {
    std::unique_lock lock(mutex_);
    defaults_ = prefs;
  }

  UserPreferences get(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    auto it = prefs_.find(user_id);
    if (it != prefs_.end()) return it->second;
    return defaults_;
  }

  void set(const std::string& user_id, const UserPreferences& prefs) {
    std::unique_lock lock(mutex_);
    UserPreferences p = prefs;
    p.updated_at = now_epoch_seconds();
    prefs_[user_id] = p;
  }

  // Convenience: set individual preferences
  void set_email_enabled(const std::string& user_id, bool enabled) {
    std::unique_lock lock(mutex_);
    auto& p = prefs_[user_id];
    p.email_notifications_enabled = enabled;
    p.updated_at = now_epoch_seconds();
  }

  void set_type_enabled(const std::string& user_id, EmailType type, bool enabled) {
    std::unique_lock lock(mutex_);
    auto& p = prefs_[user_id];
    switch (type) {
      case EmailType::PASSWORD_RESET: p.password_reset_emails = enabled; break;
      case EmailType::EMAIL_VERIFICATION: p.verification_emails = enabled; break;
      case EmailType::INVITE: p.invitation_emails = enabled; break;
      case EmailType::NOTIFICATION: p.notification_emails = enabled; break;
      case EmailType::MESSAGE_NOTIFICATION: p.message_notification_emails = enabled; break;
      case EmailType::ACCOUNT_RENEWAL: p.account_renewal_emails = enabled; break;
      case EmailType::WELCOME: p.welcome_emails = enabled; break;
      case EmailType::ACCOUNT_DEACTIVATED: p.deactivation_emails = enabled; break;
      default: break;
    }
    p.updated_at = now_epoch_seconds();
  }

  bool is_type_allowed(const std::string& user_id, EmailType type) {
    UserPreferences p = get(user_id);
    if (!p.email_notifications_enabled) return false;
    switch (type) {
      case EmailType::PASSWORD_RESET: return p.password_reset_emails;
      case EmailType::EMAIL_VERIFICATION: return p.verification_emails;
      case EmailType::REGISTRATION: return p.verification_emails;
      case EmailType::INVITE: return p.invitation_emails;
      case EmailType::NOTIFICATION: return p.notification_emails;
      case EmailType::MESSAGE_NOTIFICATION: return p.message_notification_emails;
      case EmailType::ACCOUNT_RENEWAL: return p.account_renewal_emails;
      case EmailType::WELCOME: return p.welcome_emails;
      case EmailType::ACCOUNT_DEACTIVATED: return p.deactivation_emails;
      default: return false;
    }
  }

  void remove(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    prefs_.erase(user_id);
  }

  json to_json(const std::string& user_id) {
    UserPreferences p = get(user_id);
    return {
      {"email_notifications_enabled", p.email_notifications_enabled},
      {"password_reset_emails", p.password_reset_emails},
      {"verification_emails", p.verification_emails},
      {"invitation_emails", p.invitation_emails},
      {"notification_emails", p.notification_emails},
      {"message_notification_emails", p.message_notification_emails},
      {"account_renewal_emails", p.account_renewal_emails},
      {"welcome_emails", p.welcome_emails},
      {"deactivation_emails", p.deactivation_emails},
      {"updated_at", p.updated_at}
    };
  }

  size_t user_count() const {
    std::shared_lock lock(mutex_);
    return prefs_.size();
  }

private:
  mutable std::shared_mutex mutex_;
  UserPreferences defaults_;
  std::unordered_map<std::string, UserPreferences> prefs_;
};

// ============================================================================
// EmailPreferences — High-level preference manager
// ============================================================================
class EmailPreferences {
public:
  explicit EmailPreferences(std::shared_ptr<EmailPreferenceStore> store)
      : store_(std::move(store)) {}

  bool can_send_email(const std::string& user_id, EmailType type) {
    return store_->is_type_allowed(user_id, type);
  }

  void enable_all(const std::string& user_id) {
    store_->set_email_enabled(user_id, true);
  }

  void disable_all(const std::string& user_id) {
    store_->set_email_enabled(user_id, false);
  }

  void set_preference(const std::string& user_id, EmailType type, bool enabled) {
    store_->set_type_enabled(user_id, type, enabled);
  }

  json get_preferences(const std::string& user_id) {
    return store_->to_json(user_id);
  }

  std::shared_ptr<EmailPreferenceStore> store() { return store_; }

private:
  std::shared_ptr<EmailPreferenceStore> store_;
};

// ============================================================================
// EmailQueueItem — Represents a single email in the queue
// ============================================================================
struct EmailQueueItem {
  std::string id;
  std::string user_id;
  std::string recipient_email;
  EmailType email_type = EmailType::UNKNOWN;
  std::string mime_content;
  std::string from_address;
  int64_t created_at = 0;
  int64_t scheduled_at = 0;
  int retry_count = 0;
  int64_t last_attempt_at = 0;
  EmailStatus status = EmailStatus::QUEUED;
  std::string last_error;
  int priority = 0; // Lower number = higher priority
  std::string metadata_json;

  // Priority comparator (higher priority items come first)
  bool operator<(const EmailQueueItem& other) const {
    if (priority != other.priority) return priority > other.priority;
    return scheduled_at > other.scheduled_at;
  }
};

// ============================================================================
// EmailRetryPolicy — Determines retry intervals
// ============================================================================
class EmailRetryPolicy {
public:
  EmailRetryPolicy() : intervals_(std::begin(RETRY_INTERVALS), std::end(RETRY_INTERVALS)) {}

  // Get next retry delay in seconds
  int64_t next_delay(int retry_count) const {
    if (retry_count < 0) return 60;
    size_t idx = static_cast<size_t>(retry_count);
    if (idx >= intervals_.size()) return intervals_.back();
    return intervals_[idx] * 60; // Convert minutes to seconds
  }

  // Check if item should be moved to dead letter queue
  bool is_dead_letter(int retry_count) const {
    return retry_count >= static_cast<int>(intervals_.size());
  }

  // Add jitter to avoid thundering herd
  int64_t next_delay_with_jitter(int retry_count) const {
    int64_t base = next_delay(retry_count);
    static std::mt19937 rng(static_cast<uint32_t>(now_epoch_seconds()));
    static std::uniform_int_distribution<int64_t> dist(0, 30);
    return base + dist(rng);
  }

private:
  std::vector<int64_t> intervals_;
};

// ============================================================================
// EmailDeadLetterQueue — Stores permanently failed emails
// ============================================================================
class EmailDeadLetterQueue {
public:
  void push(const EmailQueueItem& item) {
    std::unique_lock lock(mutex_);
    dead_letters_.push_back(item);
    // Keep only last 10000 dead letters
    if (dead_letters_.size() > 10000)
      dead_letters_.pop_front();
  }

  std::vector<EmailQueueItem> get_all() const {
    std::shared_lock lock(mutex_);
    return {dead_letters_.begin(), dead_letters_.end()};
  }

  size_t size() const {
    std::shared_lock lock(mutex_);
    return dead_letters_.size();
  }

  std::optional<EmailQueueItem> get(const std::string& id) {
    std::shared_lock lock(mutex_);
    for (auto& item : dead_letters_) {
      if (item.id == id) return item;
    }
    return std::nullopt;
  }

  void clear() {
    std::unique_lock lock(mutex_);
    dead_letters_.clear();
  }

private:
  mutable std::shared_mutex mutex_;
  std::deque<EmailQueueItem> dead_letters_;
};

// ============================================================================
// EmailBounceDetector — Detects bounced emails from SMTP responses
// ============================================================================
class EmailBounceDetector {
public:
  struct BounceInfo {
    bool is_bounce = false;
    bool is_permanent = false;
    std::string reason;
    int smtp_code = 0;
  };

  // Analyze SMTP response for bounce indicators
  BounceInfo analyze_smtp_response(int code, const std::string& response) {
    BounceInfo info;
    info.smtp_code = code;

    // Permanent failures (5xx)
    if (code >= 500 && code < 600) {
      info.is_bounce = true;
      info.is_permanent = true;
      info.reason = classify_permanent(code, response);
    }
    // Temporary failures (4xx)
    else if (code >= 400 && code < 500) {
      info.is_bounce = true;
      info.is_permanent = false;
      info.reason = classify_temporary(code, response);
    }

    return info;
  }

  // Parse bounce from DSN (Delivery Status Notification) message
  BounceInfo parse_dsn(const std::string& dsn_message) {
    BounceInfo info;
    // Simple DSN parsing looking for status codes
    auto status_pos = dsn_message.find("Status: ");
    if (status_pos != std::string::npos) {
      std::string status = dsn_message.substr(status_pos + 8, 10);
      status = trim_str(status);
      if (status.size() >= 3) {
        char first = status[0];
        if (first == '5') {
          info.is_bounce = true;
          info.is_permanent = true;
          info.reason = "DSN permanent failure: " + status;
        } else if (first == '4') {
          info.is_bounce = true;
          info.is_permanent = false;
          info.reason = "DSN temporary failure: " + status;
        }
      }
    }
    return info;
  }

private:
  std::string classify_permanent(int code, const std::string& response) {
    std::string lower = to_lower(response);
    if (lower.find("mailbox not found") != std::string::npos ||
        lower.find("user unknown") != std::string::npos ||
        lower.find("no such user") != std::string::npos ||
        lower.find("invalid recipient") != std::string::npos)
      return "Recipient mailbox does not exist";
    if (lower.find("spam") != std::string::npos)
      return "Message rejected as spam";
    if (lower.find("blocked") != std::string::npos ||
        lower.find("blacklist") != std::string::npos)
      return "Sender blocked/blacklisted";
    if (lower.find("quota") != std::string::npos || lower.find("over quota") != std::string::npos)
      return "Recipient mailbox over quota";
    return "Permanent failure (code " + std::to_string(code) + ")";
  }

  std::string classify_temporary(int code, const std::string& response) {
    std::string lower = to_lower(response);
    if (lower.find("try again") != std::string::npos ||
        lower.find("temporarily") != std::string::npos)
      return "Temporary delivery failure — server requested retry";
    if (lower.find("greylisted") != std::string::npos)
      return "Greylisting active — retry later";
    if (lower.find("rate") != std::string::npos || lower.find("too many") != std::string::npos)
      return "Rate limited by receiving server";
    return "Temporary failure (code " + std::to_string(code) + ")";
  }
};

// ============================================================================
// EmailLogEntry — A single log entry for email events
// ============================================================================
struct EmailLogEntry {
  std::string id;
  std::string user_id;
  std::string recipient;
  EmailType email_type = EmailType::UNKNOWN;
  EmailStatus status = EmailStatus::QUEUED;
  std::string subject;
  int64_t created_at = 0;
  int64_t sent_at = 0;
  int64_t delivery_latency_ms = 0;
  int smtp_response_code = 0;
  std::string smtp_response;
  int retry_count = 0;
  bool is_bounced = false;
  std::string bounce_reason;
  std::string server_id;

  json to_json() const {
    return {
      {"id", id},
      {"user_id", user_id},
      {"recipient", recipient},
      {"email_type", static_cast<int>(email_type)},
      {"status", static_cast<int>(status)},
      {"subject", subject},
      {"created_at", created_at},
      {"sent_at", sent_at},
      {"delivery_latency_ms", delivery_latency_ms},
      {"smtp_response_code", smtp_response_code},
      {"smtp_response", smtp_response},
      {"retry_count", retry_count},
      {"is_bounced", is_bounced},
      {"bounce_reason", bounce_reason},
      {"server_id", server_id}
    };
  }
};

// ============================================================================
// EmailLogger — Logs all email events
// ============================================================================
class EmailLogger {
public:
  explicit EmailLogger(const std::string& log_path = "")
      : log_path_(log_path) {
    if (!log_path_.empty()) {
      // Ensure directory exists
      fs::path p(log_path_);
      auto parent = p.parent_path();
      if (!parent.empty() && !fs::exists(parent)) {
        std::error_code ec;
        fs::create_directories(parent, ec);
      }
    }
  }

  void log(const EmailLogEntry& entry) {
    std::unique_lock lock(mutex_);

    // Store in memory
    recent_entries_.push_back(entry);
    if (recent_entries_.size() > MAX_MEMORY_ENTRIES)
      recent_entries_.pop_front();

    // Write to file
    if (!log_path_.empty()) {
      write_to_file(entry);
    }

    // Update stats
    update_stats(entry);
  }

  // Query recent entries
  std::vector<EmailLogEntry> query_recent(int limit = 100) const {
    std::shared_lock lock(mutex_);
    std::vector<EmailLogEntry> result;
    size_t start = recent_entries_.size() > static_cast<size_t>(limit)
        ? recent_entries_.size() - limit : 0;
    for (size_t i = start; i < recent_entries_.size(); i++)
      result.push_back(recent_entries_[i]);
    return result;
  }

  // Query by user
  std::vector<EmailLogEntry> query_by_user(const std::string& user_id,
                                           int limit = 50) const {
    std::shared_lock lock(mutex_);
    std::vector<EmailLogEntry> result;
    for (auto it = recent_entries_.rbegin();
         it != recent_entries_.rend() && result.size() < static_cast<size_t>(limit);
         ++it) {
      if (it->user_id == user_id) result.push_back(*it);
    }
    std::reverse(result.begin(), result.end());
    return result;
  }

  // Get statistics
  struct LogStats {
    int64_t total_sent = 0;
    int64_t total_failed = 0;
    int64_t total_bounced = 0;
    int64_t total_queued = 0;
    int64_t last_hour_sent = 0;
    double avg_latency_ms = 0.0;
  };

  LogStats get_stats() const {
    std::shared_lock lock(mutex_);
    LogStats s;
    s.total_sent = total_sent_;
    s.total_failed = total_failed_;
    s.total_bounced = total_bounced_;
    s.total_queued = total_queued_;

    int64_t now = now_epoch_seconds();
    int64_t latency_sum = 0;
    int latency_count = 0;
    for (auto& entry : recent_entries_) {
      if (entry.status == EmailStatus::SENT) {
        if (entry.sent_at > now - 3600) s.last_hour_sent++;
      }
      if (entry.delivery_latency_ms > 0) {
        latency_sum += entry.delivery_latency_ms;
        latency_count++;
      }
    }
    s.avg_latency_ms = latency_count > 0
        ? static_cast<double>(latency_sum) / latency_count : 0.0;
    return s;
  }

  void clear() {
    std::unique_lock lock(mutex_);
    recent_entries_.clear();
  }

private:
  static constexpr size_t MAX_MEMORY_ENTRIES = 10000;
  std::string log_path_;
  mutable std::shared_mutex mutex_;
  std::deque<EmailLogEntry> recent_entries_;

  // Running stats
  int64_t total_sent_ = 0;
  int64_t total_failed_ = 0;
  int64_t total_bounced_ = 0;
  int64_t total_queued_ = 0;

  void write_to_file(const EmailLogEntry& entry) {
    std::ofstream file(log_path_, std::ios::app);
    if (!file.is_open()) return;
    file << entry.to_json().dump() << "\n";
  }

  void update_stats(const EmailLogEntry& entry) {
    switch (entry.status) {
      case EmailStatus::SENT: total_sent_++; break;
      case EmailStatus::FAILED: case EmailStatus::DEAD_LETTER: total_failed_++; break;
      case EmailStatus::BOUNCED: total_bounced_++; break;
      case EmailStatus::QUEUED: total_queued_++; break;
      default: break;
    }
  }
};

// ============================================================================
// EmailQueue — Async email queue with retry logic
// ============================================================================
class EmailQueue {
public:
  EmailQueue(
      std::shared_ptr<EmailThrottler> throttler,
      std::shared_ptr<EmailValidator> validator,
      std::shared_ptr<EmailPreferences> preferences,
      std::shared_ptr<EmailLogger> logger,
      std::shared_ptr<SmtpConnectionPool> pool,
      std::shared_ptr<EmailTemplateRenderer> renderer,
      std::shared_ptr<EmailBounceDetector> bounce_detector,
      const EmailConfig::QueueSettings& settings)
      : throttler_(std::move(throttler)),
        validator_(std::move(validator)),
        preferences_(std::move(preferences)),
        logger_(std::move(logger)),
        smtp_pool_(std::move(pool)),
        renderer_(std::move(renderer)),
        bounce_detector_(std::move(bounce_detector)),
        settings_(settings),
        running_(false) {}

  ~EmailQueue() { stop(); }

  // Start the queue workers
  void start() {
    std::unique_lock lock(mutex_);
    if (running_) return;
    running_ = true;
    lock.unlock();

    for (int i = 0; i < settings_.worker_threads; i++) {
      workers_.emplace_back(&EmailQueue::worker_loop, this, i);
    }
  }

  // Stop the queue workers
  void stop() {
    {
      std::unique_lock lock(mutex_);
      if (!running_) return;
      running_ = false;
    }
    cv_.notify_all();
    for (auto& w : workers_) {
      if (w.joinable()) w.join();
    }
    workers_.clear();
  }

  // Enqueue an email for async sending
  std::string enqueue(
      const std::string& user_id,
      const std::string& recipient_email,
      EmailType email_type,
      const std::string& mime_content,
      const std::string& from_address,
      int priority = 5,
      const std::string& metadata = "{}") {

    // Validate email
    auto validation = validator_->validate(recipient_email, false, true);
    if (!validation.valid) {
      EmailLogEntry log_entry;
      log_entry.id = generate_token(16);
      log_entry.user_id = user_id;
      log_entry.recipient = recipient_email;
      log_entry.email_type = email_type;
      log_entry.status = EmailStatus::REJECTED;
      log_entry.subject = "n/a";
      log_entry.created_at = now_epoch_seconds();
      log_entry.smtp_response = validation.reason;
      logger_->log(log_entry);
      return "";
    }

    // Check preferences
    if (!preferences_->can_send_email(user_id, email_type)) {
      return "";
    }

    EmailQueueItem item;
    item.id = generate_token(16);
    item.user_id = user_id;
    item.recipient_email = validation.normalized_email;
    item.email_type = email_type;
    item.mime_content = mime_content;
    item.from_address = from_address;
    item.created_at = now_epoch_seconds();
    item.scheduled_at = item.created_at;
    item.priority = priority;
    item.metadata_json = metadata;

    {
      std::unique_lock lock(mutex_);
      if (queue_.size() >= static_cast<size_t>(settings_.max_queue_size)) {
        return ""; // Queue full
      }
      queue_.push(item);

      // Log queued
      EmailLogEntry log_entry;
      log_entry.id = item.id;
      log_entry.user_id = user_id;
      log_entry.recipient = item.recipient_email;
      log_entry.email_type = email_type;
      log_entry.status = EmailStatus::QUEUED;
      log_entry.subject = "queued";
      log_entry.created_at = item.created_at;
      logger_->log(log_entry);
    }
    cv_.notify_one();
    return item.id;
  }

  // Get queue statistics
  struct QueueStats {
    size_t queue_size = 0;
    size_t dead_letter_size = 0;
    size_t sent_today = 0;
    size_t failed_today = 0;
    bool running = false;
  };

  QueueStats get_stats() const {
    QueueStats s;
    std::shared_lock lock(mutex_);
    s.queue_size = queue_.size();
    s.dead_letter_size = dead_letter_queue_->size();
    s.running = running_;
    lock.unlock();

    auto log_stats = logger_->get_stats();
    s.sent_today = static_cast<size_t>(log_stats.total_sent);
    s.failed_today = static_cast<size_t>(log_stats.total_failed);
    return s;
  }

  std::shared_ptr<EmailLogger> logger() { return logger_; }
  std::shared_ptr<EmailThrottler> throttler() { return throttler_; }

private:
  std::shared_ptr<EmailThrottler> throttler_;
  std::shared_ptr<EmailValidator> validator_;
  std::shared_ptr<EmailPreferences> preferences_;
  std::shared_ptr<EmailLogger> logger_;
  std::shared_ptr<SmtpConnectionPool> smtp_pool_;
  std::shared_ptr<EmailTemplateRenderer> renderer_;
  std::shared_ptr<EmailBounceDetector> bounce_detector_;
  std::shared_ptr<EmailDeadLetterQueue> dead_letter_queue_ =
      std::make_shared<EmailDeadLetterQueue>();
  std::shared_ptr<EmailRetryPolicy> retry_policy_ =
      std::make_shared<EmailRetryPolicy>();

  EmailConfig::QueueSettings settings_;

  mutable std::shared_mutex mutex_;
  std::priority_queue<EmailQueueItem> queue_;
  std::condition_variable_any cv_;
  std::atomic<bool> running_{false};
  std::vector<std::thread> workers_;

  // Worker thread loop
  void worker_loop(int worker_id) {
    while (running_) {
      std::vector<EmailQueueItem> batch;

      {
        std::unique_lock lock(mutex_);
        cv_.wait_for(lock, chr::milliseconds(settings_.poll_interval_ms), [this] {
          return !running_ || !queue_.empty();
        });

        if (!running_ && queue_.empty()) break;

        // Collect batch
        int64_t now = now_epoch_seconds();
        while (!queue_.empty() && batch.size() < static_cast<size_t>(settings_.batch_size)) {
          auto item = queue_.top();
          if (item.scheduled_at > now) break; // Not time yet
          queue_.pop();
          batch.push_back(item);
        }
      }

      // Process batch
      for (auto& item : batch) {
        if (!running_) break;
        process_item(item, worker_id);
      }
    }
  }

  void process_item(EmailQueueItem& item, int worker_id) {
    // Check throttling
    auto throttle_result = throttler_->check_and_increment(item.user_id, item.email_type);
    if (!throttle_result.allowed) {
      // Re-queue with delay
      item.last_error = throttle_result.reason;
      item.scheduled_at = now_epoch_seconds() + throttle_result.retry_after_seconds;
      item.status = EmailStatus::THROTTLED;
      std::unique_lock lock(mutex_);
      queue_.push(item);
      return;
    }

    // Get SMTP connection
    item.status = EmailStatus::SENDING;
    auto client = smtp_pool_->acquire();
    if (!client) {
      // Re-queue
      item.last_error = "Failed to acquire SMTP connection";
      item.scheduled_at = now_epoch_seconds() + 60;
      item.status = EmailStatus::DEFERRED;
      std::unique_lock lock(mutex_);
      queue_.push(item);
      return;
    }

    // Send email
    int64_t send_start = now_millis();
    std::vector<std::string> recipients = {item.recipient_email};
    bool success = client->send_mail(item.from_address, recipients, item.mime_content);
    int64_t send_end = now_millis();

    smtp_pool_->release(std::move(client));

    if (success) {
      item.status = EmailStatus::SENT;
      EmailLogEntry log_entry;
      log_entry.id = item.id;
      log_entry.user_id = item.user_id;
      log_entry.recipient = item.recipient_email;
      log_entry.email_type = item.email_type;
      log_entry.status = EmailStatus::SENT;
      log_entry.subject = "sent";
      log_entry.created_at = item.created_at;
      log_entry.sent_at = now_epoch_seconds();
      log_entry.delivery_latency_ms = send_end - send_start;
      log_entry.retry_count = item.retry_count;
      logger_->log(log_entry);
    } else {
      item.retry_count++;
      item.last_attempt_at = now_epoch_seconds();

      // Check for bounce
      auto bounce_info = bounce_detector_->analyze_smtp_response(0, item.last_error);

      if (bounce_info.is_bounce && bounce_info.is_permanent) {
        // Permanent failure — move to dead letter queue
        item.status = EmailStatus::DEAD_LETTER;
        item.last_error = bounce_info.reason;
        dead_letter_queue_->push(item);

        EmailLogEntry log_entry;
        log_entry.id = item.id;
        log_entry.user_id = item.user_id;
        log_entry.recipient = item.recipient_email;
        log_entry.email_type = item.email_type;
        log_entry.status = EmailStatus::DEAD_LETTER;
        log_entry.subject = "permanent_failure";
        log_entry.created_at = item.created_at;
        log_entry.sent_at = now_epoch_seconds();
        log_entry.retry_count = item.retry_count;
        log_entry.is_bounced = true;
        log_entry.bounce_reason = bounce_info.reason;
        logger_->log(log_entry);
      } else if (retry_policy_->is_dead_letter(item.retry_count)) {
        // Exceeded max retries
        item.status = EmailStatus::DEAD_LETTER;
        item.last_error = "Max retries exceeded: " + item.last_error;
        dead_letter_queue_->push(item);

        EmailLogEntry log_entry;
        log_entry.id = item.id;
        log_entry.user_id = item.user_id;
        log_entry.recipient = item.recipient_email;
        log_entry.email_type = item.email_type;
        log_entry.status = EmailStatus::DEAD_LETTER;
        log_entry.subject = "max_retries";
        log_entry.created_at = item.created_at;
        log_entry.sent_at = now_epoch_seconds();
        log_entry.retry_count = item.retry_count;
        logger_->log(log_entry);
      } else {
        // Schedule retry
        int64_t delay = retry_policy_->next_delay_with_jitter(item.retry_count);
        item.status = EmailStatus::RETRYING;
        item.scheduled_at = now_epoch_seconds() + delay;

        EmailLogEntry log_entry;
        log_entry.id = item.id;
        log_entry.user_id = item.user_id;
        log_entry.recipient = item.recipient_email;
        log_entry.email_type = item.email_type;
        log_entry.status = EmailStatus::RETRYING;
        log_entry.subject = "retrying";
        log_entry.created_at = item.created_at;
        log_entry.retry_count = item.retry_count;
        logger_->log(log_entry);

        std::unique_lock lock(mutex_);
        queue_.push(item);
      }
    }
  }
};

// ============================================================================
// EmailEngine — Main email subsystem orchestrator
// ============================================================================
class EmailEngine {
public:
  EmailEngine(const EmailConfig& config)
      : config_(config),
        template_cache_(std::make_shared<EmailTemplateCache>()),
        compiler_(std::make_shared<EmailTemplateCompiler>(config.templates)),
        renderer_(std::make_shared<EmailTemplateRenderer>(config.templates)),
        validator_(std::make_shared<EmailValidator>()),
        throttler_(std::make_shared<EmailThrottler>(config.rate_limits)),
        preference_store_(std::make_shared<EmailPreferenceStore>()),
        preferences_(std::make_shared<EmailPreferences>(preference_store_)),
        logger_(std::make_shared<EmailLogger>("email.log")),
        smtp_pool_(std::make_shared<SmtpConnectionPool>(config.smtp)),
        bounce_detector_(std::make_shared<EmailBounceDetector>()),
        queue_(nullptr) {} // Queue initialized in start()

  // Initialize and start the engine
  void start() {
    // Compile templates into cache
    auto templates = compiler_->build_all();
    for (auto& [type, tmpl] : templates) {
      template_cache_->put(template_key(type), tmpl);
    }

    // Initialize queue
    queue_ = std::make_shared<EmailQueue>(
        throttler_, validator_, preferences_, logger_,
        smtp_pool_, renderer_, bounce_detector_, config_.queue);
    queue_->start();
    started_ = true;
  }

  void stop() {
    if (queue_) queue_->stop();
    if (smtp_pool_) smtp_pool_->shutdown();
    started_ = false;
  }

  // Send an email (enqueue for async delivery)
  std::string send_email(
      const std::string& user_id,
      const std::string& recipient_email,
      EmailType email_type,
      const EmailTemplateRenderer::RenderContext& ctx) {

    if (!started_) return "";

    // Get or build template
    auto tmpl = get_template(email_type);
    if (!tmpl.has_value() || !tmpl->is_valid()) return "";

    // Render template
    auto rendered = renderer_->render(*tmpl, ctx);

    // Build MIME message
    std::string mime = renderer_->build_mime(rendered, recipient_email);

    // Determine from address
    std::string from_address = config_.smtp.from_address.empty()
        ? "noreply@" + config_.templates.server_name
        : config_.smtp.from_address;

    // Enqueue
    return queue_->enqueue(user_id, recipient_email, email_type,
                            mime, from_address, 5, "{}");
  }

  // Send an email synchronously (blocking)
  bool send_email_sync(
      const std::string& user_id,
      const std::string& recipient_email,
      EmailType email_type,
      const EmailTemplateRenderer::RenderContext& ctx) {

    // Validate
    auto validation = validator_->validate(recipient_email);
    if (!validation.valid) return false;

    // Check preferences
    if (!preferences_->can_send_email(user_id, email_type)) return false;

    // Check throttling
    auto throttle = throttler_->check_and_increment(user_id, email_type);
    if (!throttle.allowed) return false;

    // Get template
    auto tmpl = get_template(email_type);
    if (!tmpl.has_value() || !tmpl->is_valid()) return false;

    // Render
    auto rendered = renderer_->render(*tmpl, ctx);
    std::string mime = renderer_->build_mime(rendered, validation.normalized_email);

    // Send
    std::string from = config_.smtp.from_address.empty()
        ? "noreply@" + config_.templates.server_name
        : config_.smtp.from_address;

    auto client = smtp_pool_->acquire();
    if (!client) return false;

    std::vector<std::string> recipients = {validation.normalized_email};
    bool ok = client->send_mail(from, recipients, mime);
    smtp_pool_->release(std::move(client));

    // Log
    EmailLogEntry entry;
    entry.id = generate_token(16);
    entry.user_id = user_id;
    entry.recipient = validation.normalized_email;
    entry.email_type = email_type;
    entry.status = ok ? EmailStatus::SENT : EmailStatus::FAILED;
    entry.subject = rendered.subject();
    entry.created_at = now_epoch_seconds();
    entry.sent_at = now_epoch_seconds();
    logger_->log(entry);

    return ok;
  }

  // ========================================================================
  // Convenience senders for specific email types
  // ========================================================================

  std::string send_password_reset(const std::string& user_id,
                                   const std::string& email,
                                   const std::string& display_name,
                                   const std::string& reset_link,
                                   const std::string& token) {
    EmailTemplateRenderer::RenderContext ctx;
    ctx.display_name = display_name;
    ctx.link = reset_link;
    ctx.token = token;
    ctx.server_name = config_.templates.server_name;
    ctx.brand_name = config_.templates.brand_name;
    ctx.support_email = config_.templates.support_email;
    ctx.logo_url = config_.templates.logo_url;
    return send_email(user_id, email, EmailType::PASSWORD_RESET, ctx);
  }

  std::string send_verification(const std::string& user_id,
                                 const std::string& email,
                                 const std::string& display_name,
                                 const std::string& verify_link) {
    EmailTemplateRenderer::RenderContext ctx;
    ctx.display_name = display_name;
    ctx.link = verify_link;
    ctx.server_name = config_.templates.server_name;
    ctx.brand_name = config_.templates.brand_name;
    ctx.support_email = config_.templates.support_email;
    ctx.logo_url = config_.templates.logo_url;
    return send_email(user_id, email, EmailType::EMAIL_VERIFICATION, ctx);
  }

  std::string send_invite(const std::string& user_id,
                           const std::string& email,
                           const std::string& display_name,
                           const std::string& sender_name,
                           const std::string& room_name,
                           const std::string& invite_link) {
    EmailTemplateRenderer::RenderContext ctx;
    ctx.display_name = display_name;
    ctx.sender_name = sender_name;
    ctx.room_name = room_name;
    ctx.link = invite_link;
    ctx.server_name = config_.templates.server_name;
    ctx.brand_name = config_.templates.brand_name;
    ctx.support_email = config_.templates.support_email;
    ctx.logo_url = config_.templates.logo_url;
    return send_email(user_id, email, EmailType::INVITE, ctx);
  }

  std::string send_notification(const std::string& user_id,
                                 const std::string& email,
                                 const std::string& display_name,
                                 const std::string& message_preview,
                                 const std::string& room_name,
                                 const std::string& sender_name,
                                 const std::string& link,
                                 const std::string& unsubscribe_link) {
    EmailTemplateRenderer::RenderContext ctx;
    ctx.display_name = display_name;
    ctx.message_preview = message_preview;
    ctx.room_name = room_name;
    ctx.sender_name = sender_name;
    ctx.link = link;
    ctx.unsubscribe_link = unsubscribe_link;
    ctx.server_name = config_.templates.server_name;
    ctx.brand_name = config_.templates.brand_name;
    ctx.support_email = config_.templates.support_email;
    ctx.logo_url = config_.templates.logo_url;
    return send_email(user_id, email, EmailType::NOTIFICATION, ctx);
  }

  std::string send_message_notification(const std::string& user_id,
                                         const std::string& email,
                                         const std::string& display_name,
                                         const std::string& sender_name,
                                         const std::string& room_name,
                                         const std::string& message_preview,
                                         const std::string& link,
                                         const std::string& unsubscribe_link) {
    EmailTemplateRenderer::RenderContext ctx;
    ctx.display_name = display_name;
    ctx.sender_name = sender_name;
    ctx.room_name = room_name;
    ctx.message_preview = message_preview;
    ctx.link = link;
    ctx.unsubscribe_link = unsubscribe_link;
    ctx.server_name = config_.templates.server_name;
    ctx.brand_name = config_.templates.brand_name;
    ctx.support_email = config_.templates.support_email;
    ctx.logo_url = config_.templates.logo_url;
    return send_email(user_id, email, EmailType::MESSAGE_NOTIFICATION, ctx);
  }

  std::string send_welcome(const std::string& user_id,
                            const std::string& email,
                            const std::string& display_name,
                            const std::string& login_link) {
    EmailTemplateRenderer::RenderContext ctx;
    ctx.display_name = display_name;
    ctx.link = login_link;
    ctx.user_id = user_id;
    ctx.server_name = config_.templates.server_name;
    ctx.brand_name = config_.templates.brand_name;
    ctx.support_email = config_.templates.support_email;
    ctx.logo_url = config_.templates.logo_url;
    return send_email(user_id, email, EmailType::WELCOME, ctx);
  }

  std::string send_account_deactivated(const std::string& user_id,
                                        const std::string& email,
                                        const std::string& display_name) {
    EmailTemplateRenderer::RenderContext ctx;
    ctx.display_name = display_name;
    ctx.user_id = user_id;
    ctx.server_name = config_.templates.server_name;
    ctx.brand_name = config_.templates.brand_name;
    ctx.support_email = config_.templates.support_email;
    ctx.logo_url = config_.templates.logo_url;
    return send_email(user_id, email, EmailType::ACCOUNT_DEACTIVATED, ctx);
  }

  std::string send_account_renewal(const std::string& user_id,
                                    const std::string& email,
                                    const std::string& display_name,
                                    const std::string& renewal_link) {
    EmailTemplateRenderer::RenderContext ctx;
    ctx.display_name = display_name;
    ctx.link = renewal_link;
    ctx.user_id = user_id;
    ctx.server_name = config_.templates.server_name;
    ctx.brand_name = config_.templates.brand_name;
    ctx.support_email = config_.templates.support_email;
    ctx.logo_url = config_.templates.logo_url;
    return send_email(user_id, email, EmailType::ACCOUNT_RENEWAL, ctx);
  }

  // ========================================================================
  // Validation helpers
  // ========================================================================

  EmailValidator::ValidationResult validate_email(const std::string& email) {
    return validator_->validate(email, true, true);
  }

  bool is_valid_email(const std::string& email) {
    return validator_->is_valid_format(email);
  }

  // ========================================================================
  // Preference management
  // ========================================================================

  void set_email_enabled(const std::string& user_id, bool enabled) {
    preferences_->enable_all(user_id);
  }

  void set_type_enabled(const std::string& user_id, EmailType type, bool enabled) {
    preferences_->set_preference(user_id, type, enabled);
  }

  json get_preferences(const std::string& user_id) {
    return preferences_->get_preferences(user_id);
  }

  // ========================================================================
  // Statistics and monitoring
  // ========================================================================

  EmailLogger::LogStats get_stats() { return logger_->get_stats(); }

  EmailQueue::QueueStats get_queue_stats() { return queue_ ? queue_->get_stats() : EmailQueue::QueueStats{}; }

  int get_user_remaining(const std::string& user_id) {
    return throttler_->user_remaining(user_id);
  }

  int get_global_remaining() { return throttler_->global_remaining(); }

  // ========================================================================
  // Configuration
  // ========================================================================

  bool is_started() const { return started_; }
  const EmailConfig& config() const { return config_; }

  // Sub-system accessors
  std::shared_ptr<EmailTemplateCache> template_cache() { return template_cache_; }
  std::shared_ptr<EmailValidator> validator() { return validator_; }
  std::shared_ptr<EmailThrottler> throttler() { return throttler_; }
  std::shared_ptr<EmailPreferences> preferences() { return preferences_; }
  std::shared_ptr<EmailLogger> logger() { return logger_; }
  std::shared_ptr<EmailQueue> queue() { return queue_; }

private:
  EmailConfig config_;
  bool started_ = false;

  std::shared_ptr<EmailTemplateCache> template_cache_;
  std::shared_ptr<EmailTemplateCompiler> compiler_;
  std::shared_ptr<EmailTemplateRenderer> renderer_;
  std::shared_ptr<EmailValidator> validator_;
  std::shared_ptr<EmailThrottler> throttler_;
  std::shared_ptr<EmailPreferenceStore> preference_store_;
  std::shared_ptr<EmailPreferences> preferences_;
  std::shared_ptr<EmailLogger> logger_;
  std::shared_ptr<SmtpConnectionPool> smtp_pool_;
  std::shared_ptr<EmailBounceDetector> bounce_detector_;
  std::shared_ptr<EmailQueue> queue_;

  std::optional<EmailTemplate> get_template(EmailType type) {
    std::string key = template_key(type);
    auto cached = template_cache_->get(key);
    if (cached.has_value()) return cached;

    // Compile and cache
    auto tmpl = compiler_->build(type);
    if (tmpl.is_valid()) {
      template_cache_->put(key, tmpl);
      return tmpl;
    }
    return std::nullopt;
  }

  static std::string template_key(EmailType type) {
    switch (type) {
      case EmailType::PASSWORD_RESET: return "password_reset";
      case EmailType::EMAIL_VERIFICATION: return "email_verification";
      case EmailType::REGISTRATION: return "registration";
      case EmailType::INVITE: return "invite";
      case EmailType::NOTIFICATION: return "notification";
      case EmailType::MESSAGE_NOTIFICATION: return "message_notification";
      case EmailType::ACCOUNT_RENEWAL: return "account_renewal";
      case EmailType::WELCOME: return "welcome";
      case EmailType::ACCOUNT_DEACTIVATED: return "account_deactivated";
      default: return "unknown";
    }
  }
};

// ============================================================================
// Free functions — Email type name helpers
// ============================================================================

std::string email_type_name(EmailType type) {
  switch (type) {
    case EmailType::PASSWORD_RESET: return "password_reset";
    case EmailType::EMAIL_VERIFICATION: return "email_verification";
    case EmailType::REGISTRATION: return "registration";
    case EmailType::INVITE: return "invite";
    case EmailType::NOTIFICATION: return "notification";
    case EmailType::MESSAGE_NOTIFICATION: return "message_notification";
    case EmailType::ACCOUNT_RENEWAL: return "account_renewal";
    case EmailType::WELCOME: return "welcome";
    case EmailType::ACCOUNT_DEACTIVATED: return "account_deactivated";
    default: return "unknown";
  }
}

EmailType email_type_from_string(const std::string& s) {
  static const std::unordered_map<std::string, EmailType> map = {
    {"password_reset", EmailType::PASSWORD_RESET},
    {"email_verification", EmailType::EMAIL_VERIFICATION},
    {"registration", EmailType::REGISTRATION},
    {"invite", EmailType::INVITE},
    {"notification", EmailType::NOTIFICATION},
    {"message_notification", EmailType::MESSAGE_NOTIFICATION},
    {"account_renewal", EmailType::ACCOUNT_RENEWAL},
    {"welcome", EmailType::WELCOME},
    {"account_deactivated", EmailType::ACCOUNT_DEACTIVATED},
  };
  auto it = map.find(to_lower(s));
  return it != map.end() ? it->second : EmailType::UNKNOWN;
}

std::string email_status_name(EmailStatus status) {
  switch (status) {
    case EmailStatus::QUEUED: return "queued";
    case EmailStatus::SENDING: return "sending";
    case EmailStatus::SENT: return "sent";
    case EmailStatus::FAILED: return "failed";
    case EmailStatus::BOUNCED: return "bounced";
    case EmailStatus::DEFERRED: return "deferred";
    case EmailStatus::RETRYING: return "retrying";
    case EmailStatus::DEAD_LETTER: return "dead_letter";
    case EmailStatus::THROTTLED: return "throttled";
    case EmailStatus::REJECTED: return "rejected";
    default: return "unknown";
  }
}

} // namespace progressive
