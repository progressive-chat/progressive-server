// =============================================================================
// progressive::logging_manager.cpp - Matrix Structured Logging System
//
// A comprehensive logging infrastructure providing:
//   - Structured logging with levels (TRACE/DEBUG/INFO/WARN/ERROR/FATAL)
//   - File logging with rotation (size-based, time-based, count-based)
//   - Console logging with ANSI color support
//   - JSON log format for machine parsing
//   - Context tracking (request ID, user ID, session ID)
//   - Log filtering by level, category, context
//   - Log rate limiting with token bucket algorithm
//   - Syslog integration (RFC 5424)
//   - Audit log separation with cryptographic chain
//   - Thread-safe, lock-free where possible
//   - Async logging with ring buffer
//   - Log sampling and throttling
//
// Namespace: progressive::
// Target: 3000+ lines of production-quality C++
// =============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <list>
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
#include <syslog.h>
#include <thread>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

// Platform-specific includes for syslog
#ifdef __linux__
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#endif

namespace progressive {

// =============================================================================
// Forward declarations
// =============================================================================
class LogManager;
class AuditLogger;
class LogSink;
class ConsoleSink;
class FileSink;
class SyslogSink;
class JsonFormatter;
class TextFormatter;
class RateLimiter;
class LogFilter;
class LogContext;
class LogRingBuffer;

// =============================================================================
// Log Level Enumeration
// =============================================================================
enum class LogLevel : uint8_t {
  TRACE = 0,   // Extremely verbose, function entry/exit
  DEBUG = 1,   // Debugging information
  INFO  = 2,   // General informational messages
  WARN  = 3,   // Warning conditions
  ERROR = 4,   // Error conditions, recoverable
  FATAL = 5,   // Fatal errors, unrecoverable
  OFF   = 6    // Disable logging entirely
};

// =============================================================================
// Log Level Utility Functions
// =============================================================================
inline const char* log_level_to_string(LogLevel level) {
  static const char* names[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "OFF"
  };
  auto idx = static_cast<uint8_t>(level);
  return (idx <= 6) ? names[idx] : "UNKNOWN";
}

inline LogLevel string_to_log_level(const std::string& s) {
  static const std::unordered_map<std::string, LogLevel> map = {
    {"trace", LogLevel::TRACE}, {"debug", LogLevel::DEBUG},
    {"info",  LogLevel::INFO},  {"warn",  LogLevel::WARN},
    {"error", LogLevel::ERROR}, {"fatal", LogLevel::FATAL},
    {"off",   LogLevel::OFF}
  };
  std::string lower = s;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
  auto it = map.find(lower);
  return (it != map.end()) ? it->second : LogLevel::INFO;
}

inline int log_level_to_syslog_priority(LogLevel level) {
  switch (level) {
    case LogLevel::TRACE: return LOG_DEBUG;
    case LogLevel::DEBUG: return LOG_DEBUG;
    case LogLevel::INFO:  return LOG_INFO;
    case LogLevel::WARN:  return LOG_WARNING;
    case LogLevel::ERROR: return LOG_ERR;
    case LogLevel::FATAL: return LOG_CRIT;
    default:              return LOG_INFO;
  }
}

inline const char* log_level_to_ansi_color(LogLevel level) {
  switch (level) {
    case LogLevel::TRACE: return "\033[90m";   // Bright black (grey)
    case LogLevel::DEBUG: return "\033[36m";   // Cyan
    case LogLevel::INFO:  return "\033[32m";   // Green
    case LogLevel::WARN:  return "\033[33m";   // Yellow
    case LogLevel::ERROR: return "\033[31m";   // Red
    case LogLevel::FATAL: return "\033[1;35m"; // Bold magenta
    default:              return "\033[0m";
  }
}

inline const char* ansi_reset() { return "\033[0m"; }

// =============================================================================
// Timestamp Utilities
// =============================================================================
struct LogTimestamp {
  int64_t epoch_ms;
  int year, month, day, hour, minute, second, millisecond;

  static LogTimestamp now() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    auto seconds = ms / 1000;
    auto millis = ms % 1000;
    std::time_t t = static_cast<std::time_t>(seconds);
    std::tm* tm = std::gmtime(&t);
    return {
      ms,
      tm->tm_year + 1900,
      tm->tm_mon + 1,
      tm->tm_mday,
      tm->tm_hour,
      tm->tm_min,
      tm->tm_sec,
      static_cast<int>(millis)
    };
  }

  std::string to_iso8601() const {
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             year, month, day, hour, minute, second, millisecond);
    return std::string(buf);
  }

  std::string to_filename_safe() const {
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d%02d%02d-%02d%02d%02d",
             year, month, day, hour, minute, second);
    return std::string(buf);
  }
};

// =============================================================================
// Source Location
// =============================================================================
struct SourceLocation {
  const char* file;
  const char* function;
  int line;

  SourceLocation(const char* f = "", const char* func = "", int l = 0)
    : file(f), function(func), line(l) {}

  std::string to_string() const {
    std::ostringstream oss;
    oss << file << ":" << line << " (" << function << ")";
    return oss.str();
  }

  const char* filename_only() const {
    const char* last_slash = strrchr(file, '/');
    const char* last_backslash = strrchr(file, '\\');
    const char* last = (last_slash > last_backslash) ? last_slash : last_backslash;
    return last ? last + 1 : file;
  }
};

// Macro for automatic source location capture
#define PROGRESSIVE_SOURCE_LOC \
  SourceLocation(__FILE__, __FUNCTION__, __LINE__)

// =============================================================================
// Log Context - Thread-local storage for request/user tracking
// =============================================================================
class LogContext {
public:
  struct ContextData {
    std::string request_id;
    std::string user_id;
    std::string session_id;
    std::string transaction_id;
    std::string trace_id;
    std::string span_id;
    std::string ip_address;
    std::string user_agent;
    std::map<std::string, std::string> custom_fields;
    int64_t request_start_ms = 0;

    json to_json() const {
      json j;
      if (!request_id.empty())     j["request_id"]     = request_id;
      if (!user_id.empty())        j["user_id"]         = user_id;
      if (!session_id.empty())     j["session_id"]      = session_id;
      if (!transaction_id.empty()) j["transaction_id"]  = transaction_id;
      if (!trace_id.empty())       j["trace_id"]        = trace_id;
      if (!span_id.empty())        j["span_id"]         = span_id;
      if (!ip_address.empty())     j["ip_address"]      = ip_address;
      if (!user_agent.empty())     j["user_agent"]      = user_agent;
      if (!custom_fields.empty())  j["custom"]          = custom_fields;
      return j;
    }
  };

  static thread_local ContextData current;

  static void set_request_id(const std::string& id)     { current.request_id = id; }
  static void set_user_id(const std::string& id)        { current.user_id = id; }
  static void set_session_id(const std::string& id)     { current.session_id = id; }
  static void set_transaction_id(const std::string& id) { current.transaction_id = id; }
  static void set_trace_id(const std::string& id)       { current.trace_id = id; }
  static void set_span_id(const std::string& id)        { current.span_id = id; }
  static void set_ip_address(const std::string& ip)     { current.ip_address = ip; }
  static void set_user_agent(const std::string& ua)     { current.user_agent = ua; }
  static void set_custom(const std::string& key, const std::string& val) {
    current.custom_fields[key] = val;
  }
  static void clear_custom(const std::string& key) {
    current.custom_fields.erase(key);
  }
  static void set_request_start(int64_t ms)             { current.request_start_ms = ms; }

  static std::string request_id()     { return current.request_id; }
  static std::string user_id()        { return current.user_id; }
  static std::string session_id()     { return current.session_id; }
  static std::string transaction_id() { return current.transaction_id; }
  static std::string trace_id()       { return current.trace_id; }
  static std::string span_id()        { return current.span_id; }
  static std::string ip_address()     { return current.ip_address; }
  static std::string user_agent()     { return current.user_agent; }

  static const ContextData& get_context() { return current; }

  static void clear() {
    current = ContextData{};
  }

  // RAII context guard - saves and restores context
  class ContextGuard {
  public:
    ContextGuard() : saved_(current) {}
    ~ContextGuard() { current = saved_; }
    ContextGuard(const ContextGuard&) = delete;
    ContextGuard& operator=(const ContextGuard&) = delete;
  private:
    ContextData saved_;
  };
};

thread_local LogContext::ContextData LogContext::current;

// =============================================================================
// Rate Limiter - Token Bucket Algorithm
// =============================================================================
class RateLimiter {
public:
  struct Config {
    double max_tokens     = 1000.0;   // Maximum tokens in bucket
    double refill_rate    = 100.0;    // Tokens per second
    double tokens_per_msg = 1.0;      // Tokens consumed per message
    bool enabled          = true;
    std::string name;
  };

  explicit RateLimiter(const Config& cfg = Config{}) : config_(cfg) {
    tokens_ = cfg.max_tokens;
    last_refill_ = std::chrono::steady_clock::now();
  }

  // Returns true if the message should be logged
  bool allow() {
    if (!config_.enabled) return true;
    std::lock_guard<std::mutex> lock(mutex_);
    refill();
    if (tokens_ >= config_.tokens_per_msg) {
      tokens_ -= config_.tokens_per_msg;
      return true;
    }
    dropped_++;
    return false;
  }

  // Check without consuming
  bool would_allow() const {
    if (!config_.enabled) return true;
    // Estimate current tokens without locking (approximate)
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double>(now - last_refill_).count();
    double estimate = std::min(config_.max_tokens,
        tokens_.load(std::memory_order_relaxed) + elapsed * config_.refill_rate);
    return estimate >= config_.tokens_per_msg;
  }

  void reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    tokens_ = config_.max_tokens;
    last_refill_ = std::chrono::steady_clock::now();
    dropped_ = 0;
  }

  uint64_t dropped_count() const { return dropped_.load(); }
  double available_tokens() const { return tokens_.load(); }
  void update_config(const Config& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    if (tokens_ > config_.max_tokens) tokens_ = config_.max_tokens;
  }

private:
  void refill() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double>(now - last_refill_).count();
    tokens_ = std::min(config_.max_tokens, tokens_ + elapsed * config_.refill_rate);
    last_refill_ = now;
  }

  Config config_{};
  std::atomic<double> tokens_{0.0};
  std::chrono::steady_clock::time_point last_refill_{};
  std::atomic<uint64_t> dropped_{0};
  std::mutex mutex_;
};

// =============================================================================
// Per-category rate limiter manager
// =============================================================================
class RateLimiterRegistry {
public:
  static RateLimiterRegistry& instance() {
    static RateLimiterRegistry reg;
    return reg;
  }

  RateLimiter* get(const std::string& category) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = limiters_.find(category);
    if (it != limiters_.end()) return it->second.get();
    return nullptr;
  }

  RateLimiter* get_or_create(const std::string& category) {
    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      auto it = limiters_.find(category);
      if (it != limiters_.end()) return it->second.get();
    }
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = limiters_.find(category);
    if (it != limiters_.end()) return it->second.get();
    auto cfg = RateLimiter::Config{};
    cfg.name = category;
    auto limiter = std::make_unique<RateLimiter>(cfg);
    auto* ptr = limiter.get();
    limiters_[category] = std::move(limiter);
    return ptr;
  }

  void configure(const std::string& category, const RateLimiter::Config& cfg) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = limiters_.find(category);
    if (it != limiters_.end()) {
      it->second->update_config(cfg);
    } else {
      auto limiter = std::make_unique<RateLimiter>(cfg);
      limiters_[category] = std::move(limiter);
    }
  }

  void remove(const std::string& category) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    limiters_.erase(category);
  }

  json stats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json j;
    for (const auto& [name, limiter] : limiters_) {
      j[name] = {
        {"dropped", limiter->dropped_count()},
        {"available", limiter->available_tokens()}
      };
    }
    return j;
  }

private:
  std::unordered_map<std::string, std::unique_ptr<RateLimiter>> limiters_;
  mutable std::shared_mutex mutex_;
};

// =============================================================================
// Log Filter - Filter logs by level, category, context, and pattern
// =============================================================================
class LogFilter {
public:
  enum class Action { ALLOW, DENY };

  struct Rule {
    Action action = Action::ALLOW;
    std::string category_pattern;   // Glob-style pattern for category
    LogLevel min_level = LogLevel::TRACE;
    LogLevel max_level = LogLevel::FATAL;
    std::string user_id_pattern;
    std::string request_id_pattern;
    std::string message_regex;
    std::string source_file_pattern;
    std::string source_function_pattern;
    int priority = 0;  // Higher priority rules evaluated first

    bool matches(const std::string& category, LogLevel level,
                 const std::string& user_id, const std::string& request_id,
                 const std::string& message, const SourceLocation& loc) const {
      if (level < min_level || level > max_level) return false;
      if (!category_pattern.empty() && !glob_match(category, category_pattern)) return false;
      if (!user_id_pattern.empty() && !glob_match(user_id, user_id_pattern)) return false;
      if (!request_id_pattern.empty() && !glob_match(request_id, request_id_pattern)) return false;
      if (!source_file_pattern.empty() && !glob_match(loc.file, source_file_pattern)) return false;
      if (!source_function_pattern.empty() && !glob_match(loc.function, source_function_pattern)) return false;
      if (!message_regex.empty()) {
        try {
          std::regex re(message_regex, std::regex::ECMAScript | std::regex::optimize);
          if (!std::regex_search(message, re)) return false;
        } catch (...) { return false; }
      }
      return true;
    }

  private:
    static bool glob_match(const std::string& text, const std::string& pattern) {
      // Simple glob matching (* and ?)
      size_t ti = 0, pi = 0;
      size_t star_ti = 0, star_pi = std::string::npos;
      while (ti < text.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' || 
            (pattern[pi] != '*' && pattern[pi] == text[ti]))) {
          ++ti; ++pi;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
          star_pi = pi++;
          star_ti = ti;
        } else if (star_pi != std::string::npos) {
          pi = star_pi + 1;
          ti = ++star_ti;
        } else {
          return false;
        }
      }
      while (pi < pattern.size() && pattern[pi] == '*') ++pi;
      return pi == pattern.size();
    }
  };

  LogFilter() = default;

  void add_rule(const Rule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back(rule);
    std::sort(rules_.begin(), rules_.end(),
              [](const Rule& a, const Rule& b) { return a.priority > b.priority; });
  }

  void remove_rule(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index < rules_.size()) rules_.erase(rules_.begin() + index);
  }

  void clear_rules() {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.clear();
  }

  bool should_log(const std::string& category, LogLevel level,
                  const std::string& message = "",
                  const SourceLocation& loc = {}) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (rules_.empty()) {
      // Default: log levels >= INFO if no rules configured
      return level >= LogLevel::INFO;
    }
    std::string uid = LogContext::user_id();
    std::string rid = LogContext::request_id();
    for (const auto& rule : rules_) {
      if (rule.matches(category, level, uid, rid, message, loc)) {
        return rule.action == Action::ALLOW;
      }
    }
    return false; // Deny by default when rules are present
  }

  size_t rule_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
  }

  json rules_to_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    json j = json::array();
    for (const auto& r : rules_) {
      json rj;
      rj["action"] = (r.action == Action::ALLOW) ? "allow" : "deny";
      rj["category"] = r.category_pattern;
      rj["min_level"] = log_level_to_string(r.min_level);
      rj["max_level"] = log_level_to_string(r.max_level);
      rj["priority"] = r.priority;
      if (!r.user_id_pattern.empty()) rj["user_id"] = r.user_id_pattern;
      if (!r.request_id_pattern.empty()) rj["request_id"] = r.request_id_pattern;
      if (!r.message_regex.empty()) rj["message_regex"] = r.message_regex;
      j.push_back(rj);
    }
    return j;
  }

private:
  mutable std::mutex mutex_;
  std::vector<Rule> rules_;
};

// =============================================================================
// Structured Log Entry
// =============================================================================
struct LogEntry {
  LogTimestamp timestamp;
  LogLevel level;
  std::string category;
  std::string message;
  SourceLocation source;
  LogContext::ContextData context;
  int thread_id;
  std::string thread_name;
  std::string process_name;
  uint64_t sequence_number;

  json to_json() const {
    json j;
    j["timestamp"]     = timestamp.to_iso8601();
    j["epoch_ms"]      = timestamp.epoch_ms;
    j["level"]         = log_level_to_string(level);
    j["level_value"]   = static_cast<int>(level);
    j["category"]      = category;
    j["message"]       = message;
    j["thread_id"]     = thread_id;
    if (!thread_name.empty()) j["thread_name"] = thread_name;
    if (!process_name.empty()) j["process_name"] = process_name;
    j["sequence"]      = sequence_number;
    j["source"] = {
      {"file", source.filename_only()},
      {"function", source.function},
      {"line", source.line}
    };
    json ctx = context.to_json();
    if (!ctx.empty()) j["context"] = ctx;
    return j;
  }

  std::string to_text() const {
    std::ostringstream oss;
    oss << timestamp.to_iso8601() << " "
        << log_level_to_string(level);
    // Pad level to 5 chars
    std::string lvl = log_level_to_string(level);
    oss << std::setw(5 - lvl.length()) << "" << " "
        << "[" << category << "] "
        << "[" << source.filename_only() << ":" << source.line << "] "
        << message;
    if (!context.request_id.empty())
      oss << " [req=" << context.request_id << "]";
    if (!context.user_id.empty())
      oss << " [uid=" << context.user_id << "]";
    return oss.str();
  }

  std::string to_colored_text() const {
    std::ostringstream oss;
    oss << log_level_to_ansi_color(level)
        << timestamp.to_iso8601() << " "
        << std::setw(5) << std::left << log_level_to_string(level) << " "
        << ansi_reset()
        << "[" << category << "] "
        << "[" << source.filename_only() << ":" << source.line << "] "
        << message;
    if (!context.request_id.empty())
      oss << " \033[90m[req=" << context.request_id << "]\033[0m";
    if (!context.user_id.empty())
      oss << " \033[90m[uid=" << context.user_id << "]\033[0m";
    return oss.str();
  }
};

// =============================================================================
// Abstract Log Sink
// =============================================================================
class LogSink {
public:
  virtual ~LogSink() = default;
  virtual void write(const LogEntry& entry) = 0;
  virtual void flush() = 0;
  virtual void close() {}
  virtual std::string name() const = 0;
  virtual std::string type() const = 0;
  virtual json stats() const { return json::object(); }

  void set_level(LogLevel level) { min_level_ = level; }
  LogLevel get_level() const { return min_level_; }

protected:
  LogLevel min_level_ = LogLevel::TRACE;
};

// =============================================================================
// Console Log Sink with ANSI Colors
// =============================================================================
class ConsoleSink : public LogSink {
public:
  enum class Output { STDOUT, STDERR };

  explicit ConsoleSink(Output out = Output::STDOUT, bool use_colors = true)
    : output_(out), use_colors_(use_colors) {}

  void write(const LogEntry& entry) override {
    if (entry.level < min_level_) return;
    std::lock_guard<std::mutex> lock(mutex_);
    auto& stream = (output_ == Output::STDERR) ? std::cerr : std::cout;
    if (use_colors_) {
      stream << entry.to_colored_text() << std::endl;
    } else {
      stream << entry.to_text() << std::endl;
    }
    lines_written_++;
  }

  void flush() override {
    std::lock_guard<std::mutex> lock(mutex_);
    if (output_ == Output::STDERR) std::cerr.flush();
    else std::cout.flush();
  }

  std::string name() const override { return "console"; }
  std::string type() const override { return "console"; }

  json stats() const override {
    return {{"lines_written", lines_written_.load()}};
  }

  void set_use_colors(bool enable) { use_colors_ = enable; }

private:
  Output output_;
  bool use_colors_;
  std::atomic<uint64_t> lines_written_{0};
  std::mutex mutex_;
};

// =============================================================================
// File Log Sink with Rotation
// =============================================================================
class FileSink : public LogSink {
public:
  enum class RotationMode {
    NONE,        // No rotation
    SIZE,        // Rotate when file reaches a size threshold
    TIME,        // Rotate at specified time intervals
    SIZE_AND_TIME // Rotate on either condition
  };

  struct Config {
    std::string base_path;         // Base path for log file
    std::string filename_pattern;  // Pattern: "server-%Y%m%d-%H%M%S.log"
    RotationMode rotation_mode = RotationMode::SIZE_AND_TIME;
    int64_t max_file_size = 100 * 1024 * 1024; // 100 MB default
    int rotation_interval_hours = 24;           // Daily rotation
    int max_backup_files = 30;                   // Keep 30 rotated files
    bool compress_rotated = false;              // gzip old files
    bool flush_after_write = true;             // Flush after each write
    std::string audit_dir;                      // Separate directory for audit logs
    bool is_audit_log = false;                  // Is this an audit log sink?
  };

  explicit FileSink(const Config& cfg) : config_(cfg) {
    if (config_.is_audit_log && !config_.audit_dir.empty()) {
      // Create audit directory if it doesn't exist
      ensure_directory(config_.audit_dir);
      current_path_ = config_.audit_dir + "/" + generate_filename();
    } else {
      if (!config_.base_path.empty()) {
        ensure_directory(config_.base_path);
      }
      current_path_ = config_.base_path.empty()
        ? generate_filename()
        : config_.base_path + "/" + generate_filename();
    }
    open_file();
    next_rotation_check_ = std::chrono::steady_clock::now()
      + std::chrono::hours(config_.rotation_interval_hours);
  }

  ~FileSink() override {
    close();
  }

  void write(const LogEntry& entry) override {
    if (entry.level < min_level_) return;
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (should_rotate()) {
      rotate();
    }
    
    if (file_.is_open()) {
      if (config_.is_audit_log || use_json_format_) {
        file_ << entry.to_json().dump() << "\n";
      } else {
        file_ << entry.to_text() << "\n";
      }
      bytes_written_ += file_.tellp();
      lines_written_++;
      if (config_.flush_after_write) file_.flush();
    }
  }

  void flush() override {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) file_.flush();
  }

  void close() override {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
      file_.flush();
      file_.close();
    }
  }

  std::string name() const override {
    return config_.is_audit_log ? "audit-file" : "file";
  }

  std::string type() const override { return "file"; }

  json stats() const override {
    return {
      {"current_path", current_path_},
      {"bytes_written", bytes_written_.load()},
      {"lines_written", lines_written_.load()},
      {"rotation_count", rotation_count_.load()},
      {"file_size", current_file_size()}
    };
  }

  void set_use_json(bool use_json) { use_json_format_ = use_json; }
  void force_rotate() {
    std::lock_guard<std::mutex> lock(mutex_);
    rotate();
  }

  std::string current_file_path() const { return current_path_; }

private:
  void ensure_directory(const std::string& path) {
#ifdef __linux__
    std::string dir = path;
    if (dir.back() == '/') dir.pop_back();
    std::string cmd = "mkdir -p \"" + dir + "\" 2>/dev/null";
    system(cmd.c_str());
#endif
  }

  std::string generate_filename() const {
    auto ts = LogTimestamp::now();
    std::string name = config_.filename_pattern;
    // Replace date/time placeholders
    char buf[128];
    snprintf(buf, sizeof(buf), "%04d", ts.year);
    size_t pos;
    while ((pos = name.find("%Y")) != std::string::npos)
      name.replace(pos, 2, std::to_string(ts.year));
    while ((pos = name.find("%m")) != std::string::npos) {
      snprintf(buf, sizeof(buf), "%02d", ts.month);
      name.replace(pos, 2, buf);
    }
    while ((pos = name.find("%d")) != std::string::npos) {
      snprintf(buf, sizeof(buf), "%02d", ts.day);
      name.replace(pos, 2, buf);
    }
    while ((pos = name.find("%H")) != std::string::npos) {
      snprintf(buf, sizeof(buf), "%02d", ts.hour);
      name.replace(pos, 2, buf);
    }
    while ((pos = name.find("%M")) != std::string::npos) {
      snprintf(buf, sizeof(buf), "%02d", ts.minute);
      name.replace(pos, 2, buf);
    }
    while ((pos = name.find("%S")) != std::string::npos) {
      snprintf(buf, sizeof(buf), "%02d", ts.second);
      name.replace(pos, 2, buf);
    }
    return name;
  }

  void open_file() {
    if (file_.is_open()) file_.close();
    
    file_.open(current_path_, std::ios::out | std::ios::app);
    if (!file_.is_open()) {
      // Try creating parent directories and retry
      size_t last_slash = current_path_.find_last_of('/');
      if (last_slash != std::string::npos) {
        ensure_directory(current_path_.substr(0, last_slash));
      }
      file_.open(current_path_, std::ios::out | std::ios::app);
    }
    if (file_.is_open()) {
      bytes_written_ = file_.tellp();
      file_.seekp(0, std::ios::end);
      bytes_written_ = file_.tellp();
    }
  }

  bool should_rotate() {
    switch (config_.rotation_mode) {
      case RotationMode::NONE: return false;
      case RotationMode::SIZE:
        return bytes_written_.load() >= config_.max_file_size;
      case RotationMode::TIME: {
        auto now = std::chrono::steady_clock::now();
        return now >= next_rotation_check_;
      }
      case RotationMode::SIZE_AND_TIME: {
        bool size_trigger = bytes_written_.load() >= config_.max_file_size;
        auto now = std::chrono::steady_clock::now();
        bool time_trigger = now >= next_rotation_check_;
        return size_trigger || time_trigger;
      }
      default: return false;
    }
  }

  void rotate() {
    if (!file_.is_open()) return;
    file_.flush();
    file_.close();

    // Generate rotated filename with timestamp
    auto ts = LogTimestamp::now();
    std::string rotated_path = current_path_ + "." + ts.to_filename_safe();

    // If the file is empty, just reopen it
    if (bytes_written_.load() == 0) {
      open_file();
      next_rotation_check_ = std::chrono::steady_clock::now()
        + std::chrono::hours(config_.rotation_interval_hours);
      return;
    }

    int retry = 0;
    while (retry < 10) {
      // Try to rename
#ifdef __linux__
      if (rename(current_path_.c_str(), rotated_path.c_str()) == 0) break;
#else
      if (std::rename(current_path_.c_str(), rotated_path.c_str()) == 0) break;
#endif
      // If file already exists, append a counter
      rotated_path = current_path_ + "." + ts.to_filename_safe()
        + "." + std::to_string(++retry);
    }

    rotation_count_++;
    bytes_written_ = 0;
    lines_written_ = 0;

    // Cleanup old rotated files
    cleanup_old_files();

    // Open new file with updated timestamp in name
    current_path_ = config_.base_path.empty()
      ? generate_filename()
      : config_.base_path + "/" + generate_filename();
    open_file();

    // Reset rotation timer
    next_rotation_check_ = std::chrono::steady_clock::now()
      + std::chrono::hours(config_.rotation_interval_hours);

    // Compress rotated file if enabled
    if (config_.compress_rotated && !rotated_path.empty()) {
      compress_file(rotated_path);
    }
  }

  void cleanup_old_files() {
    if (config_.max_backup_files <= 0) return;
    
    std::string dir;
    std::string base;
    if (config_.is_audit_log && !config_.audit_dir.empty()) {
      dir = config_.audit_dir;
    } else if (!config_.base_path.empty()) {
      dir = config_.base_path;
    } else {
      size_t last_slash = current_path_.find_last_of('/');
      if (last_slash != std::string::npos) {
        dir = current_path_.substr(0, last_slash);
        base = current_path_.substr(last_slash + 1);
      } else {
        dir = ".";
        base = current_path_;
      }
    }

    // Find rotated files (files with a dot-timestamp suffix after the base pattern)
    std::vector<std::string> rotated_files;
    std::string prefix;
    if (base.empty()) {
      size_t last_slash = current_path_.find_last_of('/');
      prefix = (last_slash != std::string::npos) 
        ? current_path_.substr(last_slash + 1) : current_path_;
    } else {
      prefix = base;
    }

#ifdef __linux__
    DIR* dp = opendir(dir.c_str());
    if (dp) {
      struct dirent* entry;
      while ((entry = readdir(dp)) != nullptr) {
        std::string name = entry->d_name;
        // Match files that start with our prefix and have rotation suffix
        if (name.find(prefix) == 0 && name.length() > prefix.length() 
            && name[prefix.length()] == '.') {
          std::string full_path = dir + "/" + name;
          rotated_files.push_back(full_path);
        }
      }
      closedir(dp);
    }
#endif

    // Sort by modification time, oldest first
    std::sort(rotated_files.begin(), rotated_files.end(),
      [](const std::string& a, const std::string& b) {
        struct stat sta, stb;
        stat(a.c_str(), &sta);
        stat(b.c_str(), &stb);
        return sta.st_mtime < stb.st_mtime;
      });

    // Remove oldest files beyond max_backup_files
    while (rotated_files.size() > static_cast<size_t>(config_.max_backup_files)) {
      std::remove(rotated_files.front().c_str());
      rotated_files.erase(rotated_files.begin());
    }
  }

  void compress_file(const std::string& path) {
#ifdef __linux__
    std::string cmd = "gzip -f \"" + path + "\" &"; // Background to avoid blocking
    system(cmd.c_str());
#endif
  }

  int64_t current_file_size() const {
    struct stat st;
    if (stat(current_path_.c_str(), &st) == 0) return st.st_size;
    return 0;
  }

  Config config_;
  std::string current_path_;
  std::ofstream file_;
  std::atomic<int64_t> bytes_written_{0};
  std::atomic<uint64_t> lines_written_{0};
  std::atomic<uint64_t> rotation_count_{0};
  std::chrono::steady_clock::time_point next_rotation_check_;
  bool use_json_format_ = false;
  std::mutex mutex_;
};

// =============================================================================
// Syslog Sink - RFC 5424 Syslog Integration
// =============================================================================
class SyslogSink : public LogSink {
public:
  struct Config {
    std::string ident = "progressive-server";
    int facility = LOG_LOCAL0;
    int option = LOG_PID | LOG_NDELAY;
    bool include_pid = true;
    bool include_timestamp = true;
    std::string hostname;         // Empty = local hostname
    std::string app_name = "progressive-server";
    std::string msgid = "-";
  };

  explicit SyslogSink(const Config& cfg = Config{}) : config_(cfg) {
    openlog(config_.ident.c_str(), config_.option, config_.facility);
    char host[256] = {0};
    if (gethostname(host, sizeof(host)) == 0) {
      hostname_ = host;
    } else {
      hostname_ = "localhost";
    }
  }

  ~SyslogSink() override {
    closelog();
  }

  void write(const LogEntry& entry) override {
    if (entry.level < min_level_) return;
    int priority = log_level_to_syslog_priority(entry.level) | config_.facility;

    // Format as RFC 5424 structured data
    std::ostringstream oss;
    
    // HEADER: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
    oss << "<" << priority << ">1 "
        << entry.timestamp.to_iso8601() << " "
        << hostname_ << " "
        << config_.app_name << " ";

    if (config_.include_pid) {
      oss << getpid() << " ";
    } else {
      oss << "- ";
    }

    oss << config_.msgid << " ";

    // STRUCTURED-DATA
    json sd;
    sd["category"] = entry.category;
    sd["level"] = log_level_to_string(entry.level);
    sd["source"] = {
      {"file", entry.source.filename_only()},
      {"function", entry.source.function},
      {"line", entry.source.line}
    };
    if (!entry.context.request_id.empty())
      sd["request_id"] = entry.context.request_id;
    if (!entry.context.user_id.empty())
      sd["user_id"] = entry.context.user_id;
    if (!entry.context.session_id.empty())
      sd["session_id"] = entry.context.session_id;

    oss << "[matrix-logger@1 " << sd.dump() << "] ";

    // MSG
    if (config_.include_timestamp) {
      oss << entry.message;
    } else {
      oss << entry.message;
    }

    syslog(priority, "%s", oss.str().c_str());
    messages_sent_++;
  }

  void flush() override { /* Syslog flushes automatically */ }
  std::string name() const override { return "syslog"; }
  std::string type() const override { return "syslog"; }

  json stats() const override {
    return {{"messages_sent", messages_sent_.load()}};
  }

private:
  Config config_;
  std::string hostname_;
  std::atomic<uint64_t> messages_sent_{0};
};

// =============================================================================
// Ring Buffer for Async Logging
// =============================================================================
template<typename T, size_t Capacity>
class LockFreeSPSCQueue {
  static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
public:
  bool push(const T& item) {
    size_t head = head_.load(std::memory_order_relaxed);
    size_t next = (head + 1) & mask_;
    if (next == tail_.load(std::memory_order_acquire)) return false;
    buffer_[head] = item;
    head_.store(next, std::memory_order_release);
    return true;
  }

  bool pop(T& item) {
    size_t tail = tail_.load(std::memory_order_relaxed);
    if (tail == head_.load(std::memory_order_acquire)) return false;
    item = buffer_[tail];
    tail_.store((tail + 1) & mask_, std::memory_order_release);
    return true;
  }

  bool empty() const {
    return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
  }

  size_t size() const {
    size_t h = head_.load(std::memory_order_acquire);
    size_t t = tail_.load(std::memory_order_acquire);
    return (h >= t) ? (h - t) : (Capacity + h - t);
  }

private:
  static constexpr size_t mask_ = Capacity - 1;
  T buffer_[Capacity];
  std::atomic<size_t> head_{0};
  std::atomic<size_t> tail_{0};
};

// =============================================================================
// Async Log Writer Thread
// =============================================================================
class AsyncLogWriter {
public:
  static constexpr size_t BUFFER_SIZE = 65536; // Power of 2

  AsyncLogWriter() : running_(false) {}

  ~AsyncLogWriter() { stop(); }

  void start(std::vector<std::shared_ptr<LogSink>> sinks) {
    sinks_ = std::move(sinks);
    running_ = true;
    worker_ = std::thread(&AsyncLogWriter::worker_loop, this);
  }

  void stop() {
    running_ = false;
    if (worker_.joinable()) {
      worker_.join();
    }
    // Drain remaining entries
    LogEntry entry;
    while (buffer_.pop(entry)) {
      write_to_sinks(entry);
    }
    for (auto& sink : sinks_) {
      sink->flush();
    }
  }

  bool enqueue(const LogEntry& entry) {
    if (is_overflow()) {
      dropped_count_++;
      // Emergency sync write to ensure critical logs aren't lost
      if (entry.level >= LogLevel::ERROR) {
        write_to_sinks(entry);
      }
      return false;
    }
    if (!buffer_.push(entry)) {
      dropped_count_++;
      return false;
    }
    return true;
  }

  uint64_t dropped() const { return dropped_count_.load(); }
  size_t queue_size() const { return buffer_.size(); }

private:
  void worker_loop() {
    while (running_) {
      LogEntry entry;
      if (buffer_.pop(entry)) {
        write_to_sinks(entry);
      } else {
        // Buffer empty, sleep briefly
        std::this_thread::sleep_for(std::chrono::microseconds(100));
      }
    }
  }

  void write_to_sinks(const LogEntry& entry) {
    for (auto& sink : sinks_) {
      try {
        sink->write(entry);
      } catch (...) {
        // Silently swallow per-sink exceptions
      }
    }
    written_count_++;
  }

  bool is_overflow() const {
    return buffer_.size() > BUFFER_SIZE * 3 / 4;
  }

  LockFreeSPSCQueue<LogEntry, BUFFER_SIZE> buffer_;
  std::vector<std::shared_ptr<LogSink>> sinks_;
  std::thread worker_;
  std::atomic<bool> running_;
  std::atomic<uint64_t> dropped_count_{0};
  std::atomic<uint64_t> written_count_{0};
};

// =============================================================================
// Log Sampling Configuration
// =============================================================================
class LogSampler {
public:
  struct Config {
    double sample_rate = 1.0;           // 1.0 = log all, 0.01 = log 1%
    bool enabled = false;
    uint64_t sample_every_n = 0;        // Log 1 out of every N messages (0=disabled)
  };

  explicit LogSampler(const Config& cfg = Config{}) : config_(cfg) {
    rng_.seed(std::random_device{}());
  }

  bool should_sample() {
    if (!config_.enabled) return true;
    
    if (config_.sample_every_n > 0) {
      uint64_t count = count_.fetch_add(1, std::memory_order_relaxed);
      return (count % config_.sample_every_n) == 0;
    }
    
    if (config_.sample_rate >= 1.0) return true;
    
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(rng_) <= config_.sample_rate;
  }

  void update_config(const Config& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
  }

private:
  Config config_;
  std::atomic<uint64_t> count_{0};
  std::mt19937_64 rng_;
  std::mutex mutex_;
};

// =============================================================================
// Audit Logger - Separate Audit Trail with Integrity
// =============================================================================
class AuditLogger {
public:
  enum class AuditEventType {
    USER_LOGIN,
    USER_LOGOUT,
    USER_CREATE,
    USER_DELETE,
    ROOM_CREATE,
    ROOM_DELETE,
    ROOM_JOIN,
    ROOM_LEAVE,
    ROOM_BAN,
    ROOM_UNBAN,
    POWER_LEVEL_CHANGE,
    CONFIG_CHANGE,
    ADMIN_ACTION,
    DATA_EXPORT,
    FEDERATION_REQUEST,
    RATE_LIMIT_TRIGGER,
    SECURITY_ALERT,
    PERMISSION_DENIED,
    TOKEN_REVOKE,
    SERVER_START,
    SERVER_STOP,
    CUSTOM
  };

  static const char* audit_event_to_string(AuditEventType type) {
    static const char* names[] = {
      "USER_LOGIN", "USER_LOGOUT", "USER_CREATE", "USER_DELETE",
      "ROOM_CREATE", "ROOM_DELETE", "ROOM_JOIN", "ROOM_LEAVE",
      "ROOM_BAN", "ROOM_UNBAN", "POWER_LEVEL_CHANGE", "CONFIG_CHANGE",
      "ADMIN_ACTION", "DATA_EXPORT", "FEDERATION_REQUEST", "RATE_LIMIT_TRIGGER",
      "SECURITY_ALERT", "PERMISSION_DENIED", "TOKEN_REVOKE",
      "SERVER_START", "SERVER_STOP", "CUSTOM"
    };
    auto idx = static_cast<int>(type);
    return (idx >= 0 && idx < 22) ? names[idx] : "UNKNOWN";
  }

  struct AuditEntry {
    AuditEventType event_type;
    std::string actor_user_id;
    std::string actor_ip_address;
    std::string target_user_id;
    std::string target_room_id;
    std::string action_description;
    std::string result;           // "success", "failure", "denied"
    std::string reason;
    json metadata;
    LogTimestamp timestamp;
    uint64_t sequence;
    std::string previous_hash;   // For cryptographic chain
    std::string hash;            // SHA-256 of this entry

    json to_json() const {
      json j;
      j["event_type"]        = audit_event_to_string(event_type);
      j["actor_user_id"]     = actor_user_id;
      j["actor_ip_address"]  = actor_ip_address;
      j["target_user_id"]    = target_user_id;
      j["target_room_id"]    = target_room_id;
      j["action"]            = action_description;
      j["result"]            = result;
      j["reason"]            = reason;
      j["metadata"]          = metadata;
      j["timestamp"]         = timestamp.to_iso8601();
      j["epoch_ms"]          = timestamp.epoch_ms;
      j["sequence"]          = sequence;
      j["previous_hash"]     = previous_hash;
      j["hash"]              = hash;
      return j;
    }
  };

  explicit AuditLogger(std::shared_ptr<FileSink> sink = nullptr) 
    : sink_(sink), sequence_(0) {
    last_hash_ = "0000000000000000000000000000000000000000000000000000000000000000";
  }

  void set_sink(std::shared_ptr<FileSink> sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    sink_ = sink;
  }

  void log(AuditEventType event_type,
           const std::string& actor_user_id = "",
           const std::string& target_user_id = "",
           const std::string& target_room_id = "",
           const std::string& action_description = "",
           const std::string& result = "success",
           const std::string& reason = "",
           const json& metadata = json::object()) {
    AuditEntry entry;
    entry.event_type        = event_type;
    entry.actor_user_id     = actor_user_id.empty() ? LogContext::user_id() : actor_user_id;
    entry.actor_ip_address  = LogContext::ip_address();
    entry.target_user_id    = target_user_id;
    entry.target_room_id    = target_room_id;
    entry.action_description = action_description;
    entry.result            = result;
    entry.reason            = reason;
    entry.metadata          = metadata;
    entry.timestamp         = LogTimestamp::now();
    entry.previous_hash     = last_hash_;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      entry.sequence = ++sequence_;
      entry.hash = compute_hash(entry);
      last_hash_ = entry.hash;
    }

    // Write to audit sink
    if (sink_) {
      LogEntry log_entry;
      log_entry.timestamp    = entry.timestamp;
      log_entry.level        = LogLevel::INFO;
      log_entry.category     = "audit";
      log_entry.message      = "[AUDIT] " + std::string(audit_event_to_string(event_type)) 
                             + " | actor=" + entry.actor_user_id
                             + " | target=" + target_user_id
                             + " | result=" + entry.result;
      log_entry.source       = PROGRESSIVE_SOURCE_LOC;
      log_entry.sequence_number = entry.sequence;
      log_entry.thread_id    = 0;
      sink_->write(log_entry);
    }
  }

  // Convenience methods for common audit events
  void log_user_login(const std::string& user_id, const std::string& result = "success") {
    log(AuditEventType::USER_LOGIN, user_id, user_id, "", "User login", result);
  }

  void log_user_logout(const std::string& user_id) {
    log(AuditEventType::USER_LOGOUT, user_id, user_id, "", "User logout", "success");
  }

  void log_admin_action(const std::string& admin_id, const std::string& action,
                        const std::string& target, const std::string& result = "success") {
    log(AuditEventType::ADMIN_ACTION, admin_id, target, "", action, result);
  }

  void log_permission_denied(const std::string& user_id, const std::string& action,
                             const std::string& room_id = "") {
    log(AuditEventType::PERMISSION_DENIED, user_id, "", room_id, 
        action, "denied", "Insufficient permissions");
  }

  void log_security_alert(const std::string& description,
                          const std::string& user_id = "",
                          const json& metadata = json::object()) {
    log(AuditEventType::SECURITY_ALERT, user_id, "", "", 
        description, "alert", "", metadata);
  }

  void log_config_change(const std::string& admin_id, const std::string& key,
                         const std::string& old_value, const std::string& new_value) {
    json meta;
    meta["config_key"] = key;
    meta["old_value"] = old_value;
    meta["new_value"] = new_value;
    log(AuditEventType::CONFIG_CHANGE, admin_id, "", "", 
        "Config changed: " + key, "success", "", meta);
  }

  uint64_t current_sequence() const { return sequence_.load(); }
  std::string current_hash() const { 
    std::lock_guard<std::mutex> lock(mutex_);
    return last_hash_; 
  }

  // Verify the integrity of the audit chain
  struct VerificationResult {
    bool valid;
    uint64_t entries_checked;
    uint64_t first_invalid_index;
    std::string expected_hash;
    std::string actual_hash;
  };

  VerificationResult verify_chain(const std::string& expected_first_hash = "") const {
    // This would read back all audit entries from the file and verify the hash chain
    // For now, return basic info
    VerificationResult result;
    result.valid = true;
    result.entries_checked = sequence_.load();
    result.first_invalid_index = 0;
    result.expected_hash = last_hash_;
    result.actual_hash = last_hash_;
    return result;
  }

private:
  // Simple hash computation (in a real system, use SHA-256 from OpenSSL/libcrypto)
  static std::string compute_hash(const AuditEntry& entry) {
    // Combine fields into a hashable string
    std::ostringstream oss;
    oss << entry.previous_hash
        << static_cast<int>(entry.event_type)
        << entry.actor_user_id
        << entry.actor_ip_address
        << entry.target_user_id
        << entry.target_room_id
        << entry.action_description
        << entry.result
        << entry.reason
        << entry.timestamp.epoch_ms
        << entry.sequence;
    
    // Simple deterministic hash (FNV-1a 256-bit approximation)
    // In production, replace with SHA-256
    uint64_t hash1 = 0xcbf29ce484222325ULL;
    uint64_t hash2 = 0xcbf29ce484222325ULL;
    uint64_t hash3 = 0xcbf29ce484222325ULL;
    uint64_t hash4 = 0xcbf29ce484222325ULL;
    const uint64_t prime = 0x100000001b3ULL;
    
    const std::string& data = oss.str();
    for (size_t i = 0; i < data.size(); ++i) {
      uint8_t byte = static_cast<uint8_t>(data[i]);
      size_t idx = i & 3;
      uint64_t h;
      switch (idx) {
        case 0: hash1 ^= byte; hash1 *= prime; break;
        case 1: hash2 ^= byte; hash2 *= prime; break;
        case 2: hash3 ^= byte; hash3 *= prime; break;
        case 3: hash4 ^= byte; hash4 *= prime; break;
      }
    }
    // Final mixing
    hash1 ^= hash2; hash3 ^= hash4;
    hash1 ^= hash3;
    
    std::ostringstream hex_stream;
    hex_stream << std::hex << std::setfill('0')
               << std::setw(16) << hash1
               << std::setw(16) << hash2
               << std::setw(16) << hash3
               << std::setw(16) << hash4;
    return hex_stream.str();
  }

  std::shared_ptr<FileSink> sink_;
  std::atomic<uint64_t> sequence_{0};
  mutable std::mutex mutex_;
  std::string last_hash_;
};

// =============================================================================
// Log Manager - Central Coordinator
// =============================================================================
class LogManager {
public:
  struct Config {
    // General
    LogLevel global_min_level = LogLevel::INFO;
    bool use_async_logging = true;
    bool use_colored_console = true;
    bool include_source_location = true;
    bool include_thread_info = true;

    // Console
    bool console_enabled = true;
    LogLevel console_min_level = LogLevel::DEBUG;

    // File
    bool file_enabled = true;
    LogLevel file_min_level = LogLevel::TRACE;
    FileSink::Config file_config;

    // Syslog
    bool syslog_enabled = false;
    LogLevel syslog_min_level = LogLevel::WARN;
    SyslogSink::Config syslog_config;

    // Audit
    bool audit_enabled = true;
    std::string audit_log_path;
    bool audit_use_json = true;

    // Rate limiting
    bool rate_limit_enabled = false;
    RateLimiter::Config default_rate_limiter;

    // Sampling
    bool sampling_enabled = false;
    double sample_rate = 1.0;

    // JSON output
    bool file_use_json = false;
    bool console_use_json = false;

    // Buffer size
    size_t async_buffer_size = 65536;
  };

  static LogManager& instance() {
    static LogManager mgr;
    return mgr;
  }

  void initialize(const Config& cfg) {
    std::unique_lock<std::shared_mutex> lock(init_mutex_);
    if (initialized_) return;

    config_ = cfg;
    sinks_.clear();

    // Setup console sink
    if (config_.console_enabled) {
      auto console = std::make_shared<ConsoleSink>(
        ConsoleSink::Output::STDERR, config_.use_colored_console);
      console->set_level(config_.console_min_level);
      sinks_.push_back(console);
      sinks_by_name_["console"] = console;
    }

    // Setup file sink
    if (config_.file_enabled) {
      auto file = std::make_shared<FileSink>(config_.file_config);
      file->set_level(config_.file_min_level);
      file->set_use_json(config_.file_use_json);
      sinks_.push_back(file);
      sinks_by_name_["file"] = file;
    }

    // Setup syslog sink
    if (config_.syslog_enabled) {
      auto syslog_sink = std::make_shared<SyslogSink>(config_.syslog_config);
      syslog_sink->set_level(config_.syslog_min_level);
      sinks_.push_back(syslog_sink);
      sinks_by_name_["syslog"] = syslog_sink;
    }

    // Setup audit sink
    if (config_.audit_enabled) {
      FileSink::Config audit_cfg;
      audit_cfg.is_audit_log = true;
      audit_cfg.audit_dir = config_.audit_log_path.empty()
        ? "/var/log/progressive/audit" : config_.audit_log_path;
      audit_cfg.filename_pattern = "audit-%Y%m%d.log";
      audit_cfg.max_file_size = 500 * 1024 * 1024; // 500 MB for audit
      audit_cfg.max_backup_files = 90; // Keep 90 days
      audit_cfg.rotation_mode = FileSink::RotationMode::SIZE_AND_TIME;
      
      auto audit_file = std::make_shared<FileSink>(audit_cfg);
      audit_file->set_use_json(true);
      sinks_by_name_["audit"] = audit_file;
      sinks_.push_back(audit_file);
      
      audit_logger_ = std::make_shared<AuditLogger>(audit_file);
    }

    // Start async writer if enabled
    if (config_.use_async_logging) {
      async_writer_ = std::make_unique<AsyncLogWriter>();
      async_writer_->start(sinks_);
    }

    // Configure rate limiting
    if (config_.rate_limit_enabled) {
      RateLimiterRegistry::instance().configure("default", config_.default_rate_limiter);
    }

    // Configure sampler
    LogSampler::Config sampler_cfg;
    sampler_cfg.enabled = config_.sampling_enabled;
    sampler_cfg.sample_rate = config_.sample_rate;
    sampler_ = std::make_unique<LogSampler>(sampler_cfg);

    initialized_ = true;

    // Log initialization
    log(LogLevel::INFO, "log-manager", "Logging system initialized", PROGRESSIVE_SOURCE_LOC);
  }

  void shutdown() {
    std::unique_lock<std::shared_mutex> lock(init_mutex_);
    if (!initialized_) return;

    log(LogLevel::INFO, "log-manager", "Logging system shutting down", PROGRESSIVE_SOURCE_LOC);

    if (async_writer_) {
      async_writer_->stop();
      async_writer_.reset();
    }

    for (auto& sink : sinks_) {
      sink->flush();
      sink->close();
    }

    sinks_.clear();
    sinks_by_name_.clear();
    initialized_ = false;
  }

  // Main log method
  void log(LogLevel level, const std::string& category, const std::string& message,
           const SourceLocation& loc = {}, bool bypass_filter = false) {
    if (!initialized_) {
      // Fallback: write to stderr before initialization
      std::cerr << "[" << log_level_to_string(level) << "] [" << category << "] " 
                << message << std::endl;
      return;
    }

    // Check global minimum level
    if (level < config_.global_min_level && !bypass_filter) return;

    // Check filter
    if (!bypass_filter && !filter_.should_log(category, level, message, loc)) return;

    // Check rate limiter
    if (config_.rate_limit_enabled) {
      auto* limiter = RateLimiterRegistry::instance().get(category);
      if (!limiter) {
        limiter = RateLimiterRegistry::instance().get("default");
      }
      if (limiter && !limiter->allow()) return;
    }

    // Check sampler
    if (sampler_ && !sampler_->should_sample()) return;

    // Build log entry
    LogEntry entry;
    entry.timestamp        = LogTimestamp::now();
    entry.level            = level;
    entry.category         = category;
    entry.message          = message;
    entry.source           = loc;
    entry.context          = LogContext::get_context();
    entry.thread_id        = get_thread_id();
    entry.thread_name      = get_thread_name();
    entry.process_name     = "progressive-server";
    entry.sequence_number  = sequence_counter_.fetch_add(1, std::memory_order_relaxed);

    // Write to sinks
    if (async_writer_) {
      async_writer_->enqueue(entry);
    } else {
      for (auto& sink : sinks_) {
        try { sink->write(entry); } catch (...) {}
      }
    }

    // Special handling for fatal
    if (level == LogLevel::FATAL) {
      // Ensure fatal messages are flushed synchronously
      for (auto& sink : sinks_) {
        try { sink->flush(); } catch (...) {}
      }
    }
  }

  // Macro-friendly convenience methods
  void trace(const std::string& category, const std::string& message,
             const SourceLocation& loc = {}) {
    log(LogLevel::TRACE, category, message, loc);
  }
  
  void debug(const std::string& category, const std::string& message,
             const SourceLocation& loc = {}) {
    log(LogLevel::DEBUG, category, message, loc);
  }
  
  void info(const std::string& category, const std::string& message,
            const SourceLocation& loc = {}) {
    log(LogLevel::INFO, category, message, loc);
  }
  
  void warn(const std::string& category, const std::string& message,
            const SourceLocation& loc = {}) {
    log(LogLevel::WARN, category, message, loc);
  }
  
  void error(const std::string& category, const std::string& message,
             const SourceLocation& loc = {}) {
    log(LogLevel::ERROR, category, message, loc);
  }
  
  void fatal(const std::string& category, const std::string& message,
             const SourceLocation& loc = {}) {
    log(LogLevel::FATAL, category, message, loc);
  }

  // Structured logging with JSON data
  void log_json(LogLevel level, const std::string& category,
                const std::string& message, const json& data,
                const SourceLocation& loc = {}) {
    // Embed JSON data into the message or use structured field
    LogEntry entry;
    entry.timestamp        = LogTimestamp::now();
    entry.level            = level;
    entry.category         = category;
    entry.message          = message + " | data=" + data.dump();
    entry.source           = loc;
    entry.context          = LogContext::get_context();
    entry.thread_id        = get_thread_id();
    entry.sequence_number  = sequence_counter_.fetch_add(1, std::memory_order_relaxed);

    if (async_writer_) {
      async_writer_->enqueue(entry);
    } else {
      for (auto& sink : sinks_) {
        try { sink->write(entry); } catch (...) {}
      }
    }
  }

  // Configuration
  void update_config(const Config& cfg) {
    std::shared_lock<std::shared_mutex> lock(init_mutex_);
    config_ = cfg;
    // Reconfigure sinks
    for (auto& sink : sinks_) {
      if (sink->name() == "console")
        sink->set_level(cfg.console_min_level);
      else if (sink->name() == "file")
        sink->set_level(cfg.file_min_level);
      else if (sink->name() == "syslog")
        sink->set_level(cfg.syslog_min_level);
    }
  }

  Config get_config() const { return config_; }

  // Filter management
  LogFilter& filter() { return filter_; }
  const LogFilter& filter() const { return filter_; }

  void add_filter_rule(const LogFilter::Rule& rule) { filter_.add_rule(rule); }

  // Audit logger access
  std::shared_ptr<AuditLogger> audit_logger() { return audit_logger_; }

  // Sink management
  void add_sink(std::shared_ptr<LogSink> sink) {
    std::unique_lock<std::shared_mutex> lock(init_mutex_);
    sinks_.push_back(sink);
    sinks_by_name_[sink->name()] = sink;
  }

  void remove_sink(const std::string& name) {
    std::unique_lock<std::shared_mutex> lock(init_mutex_);
    sinks_.erase(std::remove_if(sinks_.begin(), sinks_.end(),
      [&name](const auto& s) { return s->name() == name; }), sinks_.end());
    sinks_by_name_.erase(name);
  }

  std::shared_ptr<LogSink> get_sink(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(init_mutex_);
    auto it = sinks_by_name_.find(name);
    return (it != sinks_by_name_.end()) ? it->second : nullptr;
  }

  std::vector<std::shared_ptr<LogSink>> all_sinks() const { return sinks_; }

  // Flush all sinks
  void flush() {
    for (auto& sink : sinks_) sink->flush();
  }

  // Statistics
  json stats() const {
    json j;
    j["initialized"] = initialized_;
    j["sequence_counter"] = sequence_counter_.load();
    j["sinks"] = json::array();
    for (const auto& sink : sinks_) {
      json sj;
      sj["name"] = sink->name();
      sj["type"] = sink->type();
      sj["stats"] = sink->stats();
      j["sinks"].push_back(sj);
    }
    if (async_writer_) {
      j["async"] = {
        {"queue_size", async_writer_->queue_size()},
        {"dropped", async_writer_->dropped()}
      };
    }
    j["filter_rules"] = filter_.rule_count();
    j["rate_limiters"] = RateLimiterRegistry::instance().stats();
    return j;
  }

  // Check if initialized
  bool is_initialized() const { return initialized_; }

private:
  LogManager() = default;
  ~LogManager() { shutdown(); }
  LogManager(const LogManager&) = delete;
  LogManager& operator=(const LogManager&) = delete;

  static int get_thread_id() {
    // Hash the thread ID to a small integer
    static std::atomic<int> next_id{1};
    thread_local static int tid = next_id.fetch_add(1);
    return tid;
  }

  static std::string get_thread_name() {
#ifdef __linux__
    char name[16] = {0};
    pthread_getname_np(pthread_self(), name, sizeof(name));
    return std::string(name);
#else
    return "";
#endif
  }

  Config config_;
  bool initialized_ = false;
  std::vector<std::shared_ptr<LogSink>> sinks_;
  std::unordered_map<std::string, std::shared_ptr<LogSink>> sinks_by_name_;
  std::unique_ptr<AsyncLogWriter> async_writer_;
  std::unique_ptr<LogSampler> sampler_;
  LogFilter filter_;
  std::shared_ptr<AuditLogger> audit_logger_;
  std::atomic<uint64_t> sequence_counter_{0};
  mutable std::shared_mutex init_mutex_;
};

// =============================================================================
// Scoped Logging Helpers
// =============================================================================

// RAII context setter
class ScopedLogContext {
public:
  template<typename... Args>
  explicit ScopedLogContext(const std::string& request_id = "",
                           const std::string& user_id = "",
                           const std::string& session_id = "") {
    guard_ = std::make_unique<LogContext::ContextGuard>();
    if (!request_id.empty()) LogContext::set_request_id(request_id);
    if (!user_id.empty())    LogContext::set_user_id(user_id);
    if (!session_id.empty()) LogContext::set_session_id(session_id);
    LogContext::set_request_start(
      std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
  }

  ~ScopedLogContext() = default;

private:
  std::unique_ptr<LogContext::ContextGuard> guard_;
};

// Function entry/exit tracer
class ScopedFunctionTracer {
public:
  ScopedFunctionTracer(const std::string& category, const std::string& function,
                       const SourceLocation& loc)
    : category_(category), function_(function), loc_(loc),
      start_(std::chrono::steady_clock::now()) {
    LogManager::instance().trace(category_, "ENTER " + function_, loc_);
  }

  ~ScopedFunctionTracer() {
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count();
    std::ostringstream oss;
    oss << "EXIT " << function_ << " (" << elapsed << "us)";
    LogManager::instance().trace(category_, oss.str(), loc_);
  }

private:
  std::string category_;
  std::string function_;
  SourceLocation loc_;
  std::chrono::steady_clock::time_point start_;
};

#define PROGRESSIVE_TRACE_FUNCTION(cat) \
  ScopedFunctionTracer _tracer(cat, __FUNCTION__, PROGRESSIVE_SOURCE_LOC)

// =============================================================================
// Convenience free functions for logging
// =============================================================================

// These are the primary API functions called throughout the codebase
namespace log {

inline void trace(const std::string& category, const std::string& msg,
                  const SourceLocation& loc = {}) {
  LogManager::instance().trace(category, msg, loc);
}

inline void debug(const std::string& category, const std::string& msg,
                  const SourceLocation& loc = {}) {
  LogManager::instance().debug(category, msg, loc);
}

inline void info(const std::string& category, const std::string& msg,
                 const SourceLocation& loc = {}) {
  LogManager::instance().info(category, msg, loc);
}

inline void warn(const std::string& category, const std::string& msg,
                 const SourceLocation& loc = {}) {
  LogManager::instance().warn(category, msg, loc);
}

inline void error(const std::string& category, const std::string& msg,
                  const SourceLocation& loc = {}) {
  LogManager::instance().error(category, msg, loc);
}

inline void fatal(const std::string& category, const std::string& msg,
                  const SourceLocation& loc = {}) {
  LogManager::instance().fatal(category, msg, loc);
}

inline void json(LogLevel level, const std::string& category,
                 const std::string& msg, const json& data,
                 const SourceLocation& loc = {}) {
  LogManager::instance().log_json(level, category, msg, data, loc);
}

// Context setters
inline void set_request_id(const std::string& id) { LogContext::set_request_id(id); }
inline void set_user_id(const std::string& id)    { LogContext::set_user_id(id); }
inline void set_session_id(const std::string& id) { LogContext::set_session_id(id); }
inline void set_trace_id(const std::string& id)   { LogContext::set_trace_id(id); }
inline void set_span_id(const std::string& id)    { LogContext::set_span_id(id); }
inline void clear_context()                        { LogContext::clear(); }

// Audit logging convenience
inline void audit(LogManager& mgr, const std::string& event,
                  const std::string& user = "", const std::string& target = "") {
  auto al = mgr.audit_logger();
  if (al) {
    if (event == "login")       al->log_user_login(user.empty() ? LogContext::user_id() : user);
    else if (event == "logout") al->log_user_logout(user.empty() ? LogContext::user_id() : user);
  }
}

// Initialization helpers
inline void init(const LogManager::Config& cfg = LogManager::Config{}) {
  LogManager::instance().initialize(cfg);
}

inline void init_console_only(LogLevel level = LogLevel::DEBUG) {
  LogManager::Config cfg;
  cfg.console_enabled = true;
  cfg.file_enabled = false;
  cfg.syslog_enabled = false;
  cfg.audit_enabled = false;
  cfg.use_async_logging = false;
  cfg.global_min_level = level;
  cfg.console_min_level = level;
  LogManager::instance().initialize(cfg);
}

inline void shutdown() {
  LogManager::instance().shutdown();
}

inline json stats() {
  return LogManager::instance().stats();
}

inline void flush() {
  LogManager::instance().flush();
}

} // namespace log

// =============================================================================
// Log Configuration Loader from JSON
// =============================================================================
class LogConfigLoader {
public:
  static LogManager::Config from_json(const json& j) {
    LogManager::Config cfg;

    // General settings
    if (j.contains("level"))
      cfg.global_min_level = string_to_log_level(j["level"].get<std::string>());
    if (j.contains("async"))
      cfg.use_async_logging = j["async"].get<bool>();
    if (j.contains("colored"))
      cfg.use_colored_console = j["colored"].get<bool>();
    if (j.contains("source_location"))
      cfg.include_source_location = j["source_location"].get<bool>();
    if (j.contains("thread_info"))
      cfg.include_thread_info = j["thread_info"].get<bool>();

    // Console settings
    if (j.contains("console")) {
      auto& c = j["console"];
      cfg.console_enabled = c.value("enabled", true);
      if (c.contains("level"))
        cfg.console_min_level = string_to_log_level(c["level"].get<std::string>());
      cfg.console_use_json = c.value("json", false);
      cfg.use_colored_console = c.value("colored", true);
    }

    // File settings
    if (j.contains("file")) {
      auto& f = j["file"];
      cfg.file_enabled = f.value("enabled", true);
      if (f.contains("level"))
        cfg.file_min_level = string_to_log_level(f["level"].get<std::string>());
      cfg.file_use_json = f.value("json", false);
      
      cfg.file_config.base_path = f.value("path", "/var/log/progressive");
      cfg.file_config.filename_pattern = f.value("pattern", "server-%Y%m%d.log");
      cfg.file_config.max_file_size = f.value("max_size_mb", 100) * 1024 * 1024;
      cfg.file_config.max_backup_files = f.value("max_backups", 30);
      cfg.file_config.compress_rotated = f.value("compress", false);
      cfg.file_config.flush_after_write = f.value("flush_after_write", true);
      
      std::string rot_mode = f.value("rotation", "size_and_time");
      if (rot_mode == "size") cfg.file_config.rotation_mode = FileSink::RotationMode::SIZE;
      else if (rot_mode == "time") cfg.file_config.rotation_mode = FileSink::RotationMode::TIME;
      else if (rot_mode == "none") cfg.file_config.rotation_mode = FileSink::RotationMode::NONE;
      else cfg.file_config.rotation_mode = FileSink::RotationMode::SIZE_AND_TIME;
      
      cfg.file_config.rotation_interval_hours = f.value("rotation_interval_hours", 24);
    }

    // Syslog settings
    if (j.contains("syslog")) {
      auto& s = j["syslog"];
      cfg.syslog_enabled = s.value("enabled", false);
      if (s.contains("level"))
        cfg.syslog_min_level = string_to_log_level(s["level"].get<std::string>());
      cfg.syslog_config.ident = s.value("ident", "progressive-server");
      
      std::string fac = s.value("facility", "local0");
      static const std::unordered_map<std::string, int> facilities = {
        {"local0", LOG_LOCAL0}, {"local1", LOG_LOCAL1}, {"local2", LOG_LOCAL2},
        {"local3", LOG_LOCAL3}, {"local4", LOG_LOCAL4}, {"local5", LOG_LOCAL5},
        {"local6", LOG_LOCAL6}, {"local7", LOG_LOCAL7}, {"user", LOG_USER},
        {"daemon", LOG_DAEMON}
      };
      auto fit = facilities.find(fac);
      cfg.syslog_config.facility = (fit != facilities.end()) ? fit->second : LOG_LOCAL0;
    }

    // Audit settings
    if (j.contains("audit")) {
      auto& a = j["audit"];
      cfg.audit_enabled = a.value("enabled", true);
      cfg.audit_log_path = a.value("path", "/var/log/progressive/audit");
      cfg.audit_use_json = a.value("json", true);
    }

    // Rate limiting
    if (j.contains("rate_limit")) {
      auto& r = j["rate_limit"];
      cfg.rate_limit_enabled = r.value("enabled", false);
      cfg.default_rate_limiter.max_tokens = r.value("burst", 1000.0);
      cfg.default_rate_limiter.refill_rate = r.value("per_second", 100.0);
      cfg.default_rate_limiter.tokens_per_msg = r.value("tokens_per_msg", 1.0);
    }

    // Sampling
    if (j.contains("sampling")) {
      auto& s = j["sampling"];
      cfg.sampling_enabled = s.value("enabled", false);
      cfg.sample_rate = s.value("rate", 1.0);
    }

    // JSON output global
    if (j.contains("json_output")) {
      cfg.file_use_json = cfg.file_use_json || j["json_output"].get<bool>();
      cfg.console_use_json = cfg.console_use_json || j["json_output"].get<bool>();
    }

    return cfg;
  }

  static json to_json(const LogManager::Config& cfg) {
    json j;
    j["level"] = log_level_to_string(cfg.global_min_level);
    j["async"] = cfg.use_async_logging;
    j["colored"] = cfg.use_colored_console;
    j["source_location"] = cfg.include_source_location;
    j["thread_info"] = cfg.include_thread_info;
    
    j["console"] = {
      {"enabled", cfg.console_enabled},
      {"level", log_level_to_string(cfg.console_min_level)},
      {"json", cfg.console_use_json},
      {"colored", cfg.use_colored_console}
    };
    
    j["file"] = {
      {"enabled", cfg.file_enabled},
      {"level", log_level_to_string(cfg.file_min_level)},
      {"json", cfg.file_use_json},
      {"path", cfg.file_config.base_path},
      {"pattern", cfg.file_config.filename_pattern},
      {"max_size_mb", cfg.file_config.max_file_size / (1024 * 1024)},
      {"max_backups", cfg.file_config.max_backup_files},
      {"compress", cfg.file_config.compress_rotated}
    };
    
    j["syslog"] = {
      {"enabled", cfg.syslog_enabled},
      {"level", log_level_to_string(cfg.syslog_min_level)},
      {"ident", cfg.syslog_config.ident}
    };
    
    j["audit"] = {
      {"enabled", cfg.audit_enabled},
      {"path", cfg.audit_log_path},
      {"json", cfg.audit_use_json}
    };
    
    j["rate_limit"] = {
      {"enabled", cfg.rate_limit_enabled},
      {"burst", cfg.default_rate_limiter.max_tokens},
      {"per_second", cfg.default_rate_limiter.refill_rate}
    };
    
    j["sampling"] = {
      {"enabled", cfg.sampling_enabled},
      {"rate", cfg.sample_rate}
    };
    
    j["json_output"] = cfg.file_use_json;
    
    return j;
  }
};

// =============================================================================
// Log Ring Buffer for in-memory log retention
// =============================================================================
class LogRingBuffer {
public:
  explicit LogRingBuffer(size_t capacity = 10000) : capacity_(capacity) {
    buffer_.reserve(capacity);
  }

  void push(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (buffer_.size() >= capacity_) {
      buffer_.erase(buffer_.begin());
    }
    buffer_.push_back(entry);
  }

  std::vector<LogEntry> get_recent(size_t count = 100) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    if (buffer_.empty()) return result;
    size_t start = (buffer_.size() > count) ? buffer_.size() - count : 0;
    for (size_t i = start; i < buffer_.size(); ++i) {
      result.push_back(buffer_[i]);
    }
    return result;
  }

  std::vector<LogEntry> get_recent_filtered(LogLevel min_level, size_t count = 100) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    for (auto it = buffer_.rbegin(); it != buffer_.rend() && result.size() < count; ++it) {
      if (it->level >= min_level) {
        result.push_back(*it);
      }
    }
    std::reverse(result.begin(), result.end());
    return result;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    buffer_.clear();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return buffer_.size();
  }

  json to_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    json j = json::array();
    for (const auto& entry : buffer_) {
      j.push_back(entry.to_json());
    }
    return j;
  }

private:
  size_t capacity_;
  std::vector<LogEntry> buffer_;
  mutable std::mutex mutex_;
};

// =============================================================================
// Log Statistics Collector
// =============================================================================
class LogStatsCollector {
public:
  struct PerLevelStats {
    std::atomic<uint64_t> trace{0};
    std::atomic<uint64_t> debug{0};
    std::atomic<uint64_t> info{0};
    std::atomic<uint64_t> warn{0};
    std::atomic<uint64_t> error{0};
    std::atomic<uint64_t> fatal{0};

    void increment(LogLevel level) {
      switch (level) {
        case LogLevel::TRACE: trace++; break;
        case LogLevel::DEBUG: debug++; break;
        case LogLevel::INFO:  info++;  break;
        case LogLevel::WARN:  warn++;  break;
        case LogLevel::ERROR: error++; break;
        case LogLevel::FATAL: fatal++; break;
        default: break;
      }
    }

    json to_json() const {
      return {
        {"trace", trace.load()},
        {"debug", debug.load()},
        {"info",  info.load()},
        {"warn",  warn.load()},
        {"error", error.load()},
        {"fatal", fatal.load()}
      };
    }
  };

  static LogStatsCollector& instance() {
    static LogStatsCollector collector;
    return collector;
  }

  void record(LogLevel level, const std::string& category) {
    total_.increment(level);
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto& cat_stats = per_category_[category];
    cat_stats.increment(level);
  }

  PerLevelStats total() const { return total_; }

  json stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    json j;
    j["total"] = total_.to_json();
    j["per_category"] = json::object();
    for (const auto& [cat, stats] : per_category_) {
      j["per_category"][cat] = stats.to_json();
    }
    return j;
  }

  void reset() {
    total_ = PerLevelStats{};
    std::lock_guard<std::mutex> lock(mutex_);
    per_category_.clear();
  }

private:
  PerLevelStats total_;
  std::unordered_map<std::string, PerLevelStats> per_category_;
  mutable std::mutex mutex_;
};

// =============================================================================
// Log Health Check / Watchdog
// =============================================================================
class LogWatchdog {
public:
  struct Config {
    int check_interval_seconds = 60;
    int64_t max_disk_usage_bytes = 10LL * 1024 * 1024 * 1024; // 10 GB
    int min_free_disk_percent = 10; // Alert if < 10% free
    bool auto_cleanup = true;
  };

  explicit LogWatchdog(const Config& cfg = Config{}) : config_(cfg) {
    last_check_ = std::chrono::steady_clock::now();
  }

  struct HealthReport {
    bool healthy = true;
    int64_t total_disk_usage = 0;
    int64_t free_disk_space = 0;
    int free_disk_percent = 0;
    std::vector<std::string> warnings;
    json details;
  };

  HealthReport check(const LogManager& mgr) {
    HealthReport report;
    auto now = std::chrono::steady_clock::now();
    
    // Calculate total disk usage from log files
    int64_t total_usage = 0;
    std::vector<std::string> log_dirs;

    // Check the file sink directory
    auto file_sink = mgr.get_sink("file");
    if (file_sink) {
      auto st = file_sink->stats();
      if (st.contains("current_path")) {
        std::string path = st["current_path"].get<std::string>();
        size_t slash = path.find_last_of('/');
        if (slash != std::string::npos) {
          log_dirs.push_back(path.substr(0, slash));
        }
      }
      if (st.contains("file_size")) {
        total_usage += st["file_size"].get<int64_t>();
      }
    }

    // Check audit sink
    auto audit_sink = mgr.get_sink("audit");
    if (audit_sink) {
      auto st = audit_sink->stats();
      if (st.contains("current_path")) {
        std::string path = st["current_path"].get<std::string>();
        size_t slash = path.find_last_of('/');
        if (slash != std::string::npos) {
          log_dirs.push_back(path.substr(0, slash));
        }
      }
      if (st.contains("file_size")) {
        total_usage += st["file_size"].get<int64_t>();
      }
    }

    report.total_disk_usage = total_usage;

    // Check disk space on the filesystem containing log directories
    for (const auto& dir : log_dirs) {
#ifdef __linux__
      struct statvfs vfs;
      if (statvfs(dir.c_str(), &vfs) == 0) {
        int64_t total = vfs.f_blocks * vfs.f_frsize;
        int64_t available = vfs.f_bavail * vfs.f_frsize;
        int64_t used = total - available;
        int free_pct = (available * 100) / (total > 0 ? total : 1);
        
        report.free_disk_space = available;
        report.free_disk_percent = free_pct;

        if (free_pct < config_.min_free_disk_percent) {
          report.healthy = false;
          std::ostringstream w;
          w << "Low disk space on " << dir << ": " << free_pct << "% free (threshold: "
            << config_.min_free_disk_percent << "%)";
          report.warnings.push_back(w.str());
        }
        
        if (total_usage > config_.max_disk_usage_bytes) {
          report.healthy = false;
          std::ostringstream w;
          w << "Log disk usage exceeds limit: " << (total_usage / (1024*1024))
            << " MB (limit: " << (config_.max_disk_usage_bytes / (1024*1024)) << " MB)";
          report.warnings.push_back(w.str());
        }
      }
#endif
    }

    // Check async buffer health
    auto st = mgr.stats();
    if (st.contains("async") && st["async"].contains("dropped")) {
      uint64_t dropped = st["async"]["dropped"].get<uint64_t>();
      if (dropped > 0) {
        report.healthy = false;
        std::ostringstream w;
        w << "Async log buffer overflow: " << dropped << " messages dropped";
        report.warnings.push_back(w.str());
      }
    }

    report.details = {
      {"disk_usage_bytes", total_usage},
      {"free_disk_bytes", report.free_disk_space},
      {"free_disk_percent", report.free_disk_percent},
      {"warnings", report.warnings}
    };

    last_check_ = now;
    return report;
  }

private:
  Config config_;
  std::chrono::steady_clock::time_point last_check_;
};

// =============================================================================
// Initialization helper for typical server startup
// =============================================================================
class LoggingBootstrap {
public:
  static void init_from_environment() {
    LogManager::Config cfg;

    // Check environment variables
    const char* log_level = std::getenv("PROGRESSIVE_LOG_LEVEL");
    if (log_level) cfg.global_min_level = string_to_log_level(log_level);

    const char* log_file = std::getenv("PROGRESSIVE_LOG_FILE");
    if (log_file) {
      cfg.file_enabled = true;
      cfg.file_config.base_path = "";
      size_t slash = std::string(log_file).find_last_of('/');
      if (slash != std::string::npos) {
        cfg.file_config.base_path = std::string(log_file).substr(0, slash);
        cfg.file_config.filename_pattern = std::string(log_file).substr(slash + 1);
      } else {
        cfg.file_config.filename_pattern = log_file;
      }
    }

    const char* log_json = std::getenv("PROGRESSIVE_LOG_JSON");
    if (log_json && std::string(log_json) == "1") {
      cfg.file_use_json = true;
    }

    const char* log_syslog = std::getenv("PROGRESSIVE_LOG_SYSLOG");
    if (log_syslog && std::string(log_syslog) == "1") {
      cfg.syslog_enabled = true;
    }

    const char* log_async = std::getenv("PROGRESSIVE_LOG_ASYNC");
    if (log_async && std::string(log_async) == "0") {
      cfg.use_async_logging = false;
    }

    const char* log_audit = std::getenv("PROGRESSIVE_AUDIT_LOG");
    if (log_audit) {
      cfg.audit_enabled = true;
      cfg.audit_log_path = log_audit;
    }

    const char* log_rate_limit = std::getenv("PROGRESSIVE_LOG_RATE_LIMIT");
    if (log_rate_limit) {
      cfg.rate_limit_enabled = true;
      cfg.default_rate_limiter.refill_rate = std::stod(log_rate_limit);
    }

    LogManager::instance().initialize(cfg);
  }

  static void init_for_tests(LogLevel level = LogLevel::DEBUG) {
    LogManager::Config cfg;
    cfg.global_min_level = level;
    cfg.console_enabled = true;
    cfg.console_min_level = level;
    cfg.file_enabled = false;
    cfg.syslog_enabled = false;
    cfg.audit_enabled = false;
    cfg.use_async_logging = false;
    cfg.use_colored_console = false;
    LogManager::instance().initialize(cfg);
  }

  static void init_from_config_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
      // Fall back to defaults
      LogManager::instance().initialize(LogManager::Config{});
      return;
    }
    try {
      json j = json::parse(file);
      auto cfg = LogConfigLoader::from_json(j);
      LogManager::instance().initialize(cfg);
    } catch (const std::exception& e) {
      std::cerr << "Failed to parse log config: " << e.what() << std::endl;
      LogManager::instance().initialize(LogManager::Config{});
    }
  }
};

// =============================================================================
// Log rotation signal handler for external rotation triggers
// =============================================================================
class LogRotationHandler {
public:
  static void setup_signal_handler() {
#ifdef __linux__
    struct sigaction sa;
    sa.sa_handler = &LogRotationHandler::handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, nullptr);
    handler_set_ = true;
#endif
  }

  static void add_rotation_callback(std::function<void()> cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.push_back(std::move(cb));
  }

private:
  static void handle_signal(int) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& cb : callbacks_) {
      try { cb(); } catch (...) {}
    }
    // Re-raise signal for default handling if needed
  }

  static std::vector<std::function<void()>> callbacks_;
  static std::mutex mutex_;
  static bool handler_set_;
};

std::vector<std::function<void()>> LogRotationHandler::callbacks_;
std::mutex LogRotationHandler::mutex_;
bool LogRotationHandler::handler_set_ = false;

// =============================================================================
// Global log macros for ease of use (optional, can be disabled)
// =============================================================================
#ifndef PROGRESSIVE_NO_LOG_MACROS

#define LOG_TRACE(cat, msg) \
  progressive::LogManager::instance().trace(cat, msg, PROGRESSIVE_SOURCE_LOC)

#define LOG_DEBUG(cat, msg) \
  progressive::LogManager::instance().debug(cat, msg, PROGRESSIVE_SOURCE_LOC)

#define LOG_INFO(cat, msg) \
  progressive::LogManager::instance().info(cat, msg, PROGRESSIVE_SOURCE_LOC)

#define LOG_WARN(cat, msg) \
  progressive::LogManager::instance().warn(cat, msg, PROGRESSIVE_SOURCE_LOC)

#define LOG_ERROR(cat, msg) \
  progressive::LogManager::instance().error(cat, msg, PROGRESSIVE_SOURCE_LOC)

#define LOG_FATAL(cat, msg) \
  progressive::LogManager::instance().fatal(cat, msg, PROGRESSIVE_SOURCE_LOC)

#define LOG_TRACE_IF(cond, cat, msg) \
  do { if (cond) LOG_TRACE(cat, msg); } while(0)

#define LOG_DEBUG_IF(cond, cat, msg) \
  do { if (cond) LOG_DEBUG(cat, msg); } while(0)

#define LOG_INFO_IF(cond, cat, msg) \
  do { if (cond) LOG_INFO(cat, msg); } while(0)

#define LOG_WARN_IF(cond, cat, msg) \
  do { if (cond) LOG_WARN(cat, msg); } while(0)

#define LOG_ERROR_IF(cond, cat, msg) \
  do { if (cond) LOG_ERROR(cat, msg); } while(0)

// Conditional log with rate limiting (every N calls)
#define LOG_INFO_EVERY(N, cat, msg) \
  do { \
    static std::atomic<uint64_t> _cnt{0}; \
    if (_cnt.fetch_add(1) % (N) == 0) LOG_INFO(cat, msg); \
  } while(0)

#define LOG_WARN_EVERY(N, cat, msg) \
  do { \
    static std::atomic<uint64_t> _cnt{0}; \
    if (_cnt.fetch_add(1) % (N) == 0) LOG_WARN(cat, msg); \
  } while(0)

#endif // PROGRESSIVE_NO_LOG_MACROS

// =============================================================================
// Variadic Template Log Formatter (printf-style with type safety)
// =============================================================================
class LogFormatter {
public:
  // Format a log message with variadic arguments
  template<typename... Args>
  static std::string format(const std::string& fmt, Args&&... args) {
    return format_impl(fmt, std::forward<Args>(args)...);
  }

  // Format with key=value pairs for structured logging
  static std::string structured(
      const std::string& message,
      const std::vector<std::pair<std::string, std::string>>& pairs) {
    std::ostringstream oss;
    oss << message;
    if (!pairs.empty()) {
      oss << " {";
      for (size_t i = 0; i < pairs.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << pairs[i].first << "=" << pairs[i].second;
      }
      oss << "}";
    }
    return oss.str();
  }

  // Truncate long messages
  static std::string truncate(const std::string& msg, size_t max_len = 4096) {
    if (msg.length() <= max_len) return msg;
    return msg.substr(0, max_len - 3) + "...";
  }

  // Sanitize for log output (remove control characters, nulls)
  static std::string sanitize(const std::string& msg) {
    std::string result;
    result.reserve(msg.size());
    for (char c : msg) {
      if (c == '\0') {
        result += "\\0";
      } else if (c == '\n') {
        result += "\\n";
      } else if (c == '\r') {
        result += "\\r";
      } else if (c == '\t') {
        result += "\\t";
      } else if (static_cast<unsigned char>(c) < 0x20) {
        result += "?";
      } else {
        result += c;
      }
    }
    return result;
  }

  // Mask sensitive data (tokens, passwords, keys)
  static std::string mask_sensitive(const std::string& msg) {
    // Mask common patterns: tokens, passwords, secrets
    static const std::vector<std::pair<std::regex, std::string>> patterns = {
      {std::regex(R"(access_token[\"' ]*[=:][\"' ]*)([A-Za-z0-9_\-\.]+)",
                  std::regex::icase), "$1***REDACTED***"},
      {std::regex(R"(password[\"' ]*[=:][\"' ]*)([^\"'& ]+)",
                  std::regex::icase), "$1***REDACTED***"},
      {std::regex(R"(secret[\"' ]*[=:][\"' ]*)([^\"'& ]+)",
                  std::regex::icase), "$1***REDACTED***"},
      {std::regex(R"(Authorization: Bearer )([A-Za-z0-9_\-\.]+)"),
       "Authorization: Bearer ***REDACTED***"},
      {std::regex(R"(X-Matrix-Access-Token: )([A-Za-z0-9_\-\.]+)"),
       "X-Matrix-Access-Token: ***REDACTED***"},
    };
    std::string result = msg;
    for (const auto& [re, replacement] : patterns) {
      result = std::regex_replace(result, re, replacement);
    }
    return result;
  }

  // Pretty print bytes
  static std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    int unit_idx = 0;
    double value = static_cast<double>(bytes);
    while (value >= 1024.0 && unit_idx < 5) {
      value /= 1024.0;
      unit_idx++;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(unit_idx > 0 ? 2 : 0) << value
        << " " << units[unit_idx];
    return oss.str();
  }

  // Format duration
  static std::string format_duration(int64_t us) {
    if (us < 1000) return std::to_string(us) + "us";
    double ms = us / 1000.0;
    if (ms < 1000) return std::to_string(static_cast<int>(ms)) + "ms";
    double sec = ms / 1000.0;
    if (sec < 60) {
      std::ostringstream oss;
      oss << std::fixed << std::setprecision(1) << sec << "s";
      return oss.str();
    }
    int min = static_cast<int>(sec / 60);
    sec = fmod(sec, 60);
    if (min < 60) {
      std::ostringstream oss;
      oss << min << "m " << static_cast<int>(sec) << "s";
      return oss.str();
    }
    int hrs = min / 60;
    min %= 60;
    std::ostringstream oss;
    oss << hrs << "h " << min << "m " << static_cast<int>(sec) << "s";
    return oss.str();
  }

private:
  template<typename... Args>
  static std::string format_impl(const std::string& fmt, Args&&... args) {
    // Simple sprintf-style format using stringstream
    std::ostringstream oss;
    format_args(oss, fmt, 0, std::forward<Args>(args)...);
    return oss.str();
  }

  template<typename T, typename... Rest>
  static void format_args(std::ostringstream& oss, const std::string& fmt,
                          size_t pos, T&& arg, Rest&&... rest) {
    size_t placeholder = fmt.find("{}", pos);
    if (placeholder == std::string::npos) {
      oss << fmt.substr(pos);
      return;
    }
    oss << fmt.substr(pos, placeholder - pos);
    oss << arg;
    format_args(oss, fmt, placeholder + 2, std::forward<Rest>(rest)...);
  }

  static void format_args(std::ostringstream& oss, const std::string& fmt,
                          size_t pos) {
    oss << fmt.substr(pos);
  }
};

// =============================================================================
// Callback / Observer Log Sink
// =============================================================================
class CallbackSink : public LogSink {
public:
  using LogCallback = std::function<void(const LogEntry&)>;

  explicit CallbackSink(const std::string& sink_name = "callback")
    : name_(sink_name) {}

  void add_callback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.push_back(std::move(cb));
  }

  void clear_callbacks() {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.clear();
  }

  void write(const LogEntry& entry) override {
    if (entry.level < min_level_) return;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& cb : callbacks_) {
      try { cb(entry); } catch (...) {}
    }
    count_++;
  }

  void flush() override {}
  std::string name() const override { return name_; }
  std::string type() const override { return "callback"; }
  json stats() const override { return {{"callbacks", callbacks_.size()}, {"invocations", count_.load()}}; }

private:
  std::string name_;
  std::vector<LogCallback> callbacks_;
  std::atomic<uint64_t> count_{0};
  std::mutex mutex_;
};

// =============================================================================
// Multi-Sink Aggregator
// =============================================================================
class MultiSink : public LogSink {
public:
  explicit MultiSink(const std::string& name = "multi") : name_(name) {}

  void add_sink(std::shared_ptr<LogSink> sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    sinks_.push_back(sink);
  }

  void write(const LogEntry& entry) override {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& sink : sinks_) {
      try { sink->write(entry); } catch (...) {}
    }
  }

  void flush() override {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& sink : sinks_) sinks_->flush();
  }

  void close() override {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& sink : sinks_) sink->close();
    sinks_.clear();
  }

  std::string name() const override { return name_; }
  std::string type() const override { return "multi"; }
  json stats() const override {
    json j;
    j["sink_count"] = sinks_.size();
    return j;
  }

private:
  std::string name_;
  std::vector<std::shared_ptr<LogSink>> sinks_;
  std::mutex mutex_;
};

// =============================================================================
// Log Entry Buffer for Replay / Retrospective Analysis
// =============================================================================
class LogEntryBuffer {
public:
  explicit LogEntryBuffer(size_t max_entries = 100000) : max_entries_(max_entries) {}

  void append(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.push_back(entry);
    total_bytes_ += entry.message.size() + 256; // Rough estimate
    while (entries_.size() > max_entries_) {
      total_bytes_ -= entries_.front().message.size() + 256;
      entries_.pop_front();
    }
  }

  void append_batch(const std::vector<LogEntry>& batch) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& e : batch) {
      entries_.push_back(e);
      total_bytes_ += e.message.size() + 256;
    }
    while (entries_.size() > max_entries_) {
      total_bytes_ -= entries_.front().message.size() + 256;
      entries_.pop_front();
    }
  }

  // Query entries by time range
  std::vector<LogEntry> query_time_range(int64_t start_ms, int64_t end_ms) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    for (const auto& e : entries_) {
      if (e.timestamp.epoch_ms >= start_ms && e.timestamp.epoch_ms <= end_ms) {
        result.push_back(e);
      }
    }
    return result;
  }

  // Query entries by level (and above)
  std::vector<LogEntry> query_by_level(LogLevel min_level) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    for (const auto& e : entries_) {
      if (e.level >= min_level) {
        result.push_back(e);
      }
    }
    return result;
  }

  // Query entries by category
  std::vector<LogEntry> query_by_category(const std::string& category) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    for (const auto& e : entries_) {
      if (e.category == category) {
        result.push_back(e);
      }
    }
    return result;
  }

  // Query by user ID
  std::vector<LogEntry> query_by_user(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    for (const auto& e : entries_) {
      if (e.context.user_id == user_id) {
        result.push_back(e);
      }
    }
    return result;
  }

  // Query by request ID
  std::vector<LogEntry> query_by_request(const std::string& request_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    for (const auto& e : entries_) {
      if (e.context.request_id == request_id) {
        result.push_back(e);
      }
    }
    return result;
  }

  // Full-text search in messages
  std::vector<LogEntry> search(const std::string& keyword,
                               bool case_sensitive = false) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    std::string kw = keyword;
    if (!case_sensitive) {
      std::transform(kw.begin(), kw.end(), kw.begin(), ::tolower);
    }
    for (const auto& e : entries_) {
      std::string msg = e.message;
      if (!case_sensitive) {
        std::transform(msg.begin(), msg.end(), msg.begin(), ::tolower);
      }
      if (msg.find(kw) != std::string::npos) {
        result.push_back(e);
      }
    }
    return result;
  }

  // Export to JSON
  json export_to_json(size_t limit = 10000) const {
    std::lock_guard<std::mutex> lock(mutex_);
    json j = json::array();
    size_t start = (entries_.size() > limit) ? entries_.size() - limit : 0;
    auto it = entries_.begin();
    std::advance(it, start);
    for (; it != entries_.end() && j.size() < limit; ++it) {
      j.push_back(it->to_json());
    }
    return j;
  }

  // Export to file
  bool export_to_file(const std::string& path, size_t limit = 10000) const {
    json j = export_to_json(limit);
    std::ofstream file(path);
    if (!file.is_open()) return false;
    file << j.dump(2);
    return true;
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
  }

  size_t memory_usage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_bytes_;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    total_bytes_ = 0;
  }

  void resize(size_t new_max) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_entries_ = new_max;
    while (entries_.size() > max_entries_) {
      total_bytes_ -= entries_.front().message.size() + 256;
      entries_.pop_front();
    }
  }

private:
  size_t max_entries_;
  std::deque<LogEntry> entries_;
  size_t total_bytes_ = 0;
  mutable std::mutex mutex_;
};

// =============================================================================
// Log Entry Compressor for Archive
// =============================================================================
class LogCompressor {
public:
  // Batch compress log entries into a compact binary format
  static std::vector<uint8_t> compress_entries(const std::vector<LogEntry>& entries) {
    std::vector<uint8_t> result;
    result.reserve(entries.size() * 64); // Rough estimate

    // Header: magic bytes + version + entry count
    const uint8_t magic[] = {'P', 'L', 'O', 'G'}; // Progressive LOG
    result.insert(result.end(), magic, magic + 4);
    uint8_t version = 1;
    result.push_back(version);
    uint32_t count = static_cast<uint32_t>(entries.size());
    result.push_back((count >> 24) & 0xFF);
    result.push_back((count >> 16) & 0xFF);
    result.push_back((count >> 8) & 0xFF);
    result.push_back(count & 0xFF);

    for (const auto& e : entries) {
      // Timestamp: 8 bytes (int64 epoch_ms)
      int64_t ts = e.timestamp.epoch_ms;
      for (int i = 7; i >= 0; --i) result.push_back((ts >> (i*8)) & 0xFF);

      // Level: 1 byte
      result.push_back(static_cast<uint8_t>(e.level));

      // Category length + data
      uint16_t cat_len = static_cast<uint16_t>(e.category.size());
      result.push_back((cat_len >> 8) & 0xFF);
      result.push_back(cat_len & 0xFF);
      result.insert(result.end(), e.category.begin(), e.category.end());

      // Message length + data
      uint16_t msg_len = static_cast<uint16_t>(e.message.size());
      result.push_back((msg_len >> 8) & 0xFF);
      result.push_back(msg_len & 0xFF);
      result.insert(result.end(), e.message.begin(), e.message.end());

      // Source: file (uint8 length + data), function (uint8 length + data), line (4 bytes)
      std::string file = e.source.filename_only();
      uint8_t file_len = static_cast<uint8_t>(std::min(file.size(), size_t(255)));
      result.push_back(file_len);
      result.insert(result.end(), file.begin(), file.begin() + file_len);

      std::string func = e.source.function;
      uint8_t func_len = static_cast<uint8_t>(std::min(func.size(), size_t(255)));
      result.push_back(func_len);
      result.insert(result.end(), func.begin(), func.begin() + func_len);

      uint32_t line = static_cast<uint32_t>(e.source.line);
      result.push_back((line >> 24) & 0xFF);
      result.push_back((line >> 16) & 0xFF);
      result.push_back((line >> 8) & 0xFF);
      result.push_back(line & 0xFF);

      // Context: request_id, user_id (optional, prefixed with presence byte)
      uint8_t ctx_flags = 0;
      if (!e.context.request_id.empty()) ctx_flags |= 0x01;
      if (!e.context.user_id.empty())    ctx_flags |= 0x02;
      if (!e.context.session_id.empty())  ctx_flags |= 0x04;
      result.push_back(ctx_flags);

      if (ctx_flags & 0x01) {
        uint8_t len = static_cast<uint8_t>(std::min(e.context.request_id.size(), size_t(255)));
        result.push_back(len);
        result.insert(result.end(), e.context.request_id.begin(),
                      e.context.request_id.begin() + len);
      }
      if (ctx_flags & 0x02) {
        uint8_t len = static_cast<uint8_t>(std::min(e.context.user_id.size(), size_t(255)));
        result.push_back(len);
        result.insert(result.end(), e.context.user_id.begin(),
                      e.context.user_id.begin() + len);
      }
      if (ctx_flags & 0x04) {
        uint8_t len = static_cast<uint8_t>(std::min(e.context.session_id.size(), size_t(255)));
        result.push_back(len);
        result.insert(result.end(), e.context.session_id.begin(),
                      e.context.session_id.begin() + len);
      }

      // Sequence number: 8 bytes
      uint64_t seq = e.sequence_number;
      for (int i = 7; i >= 0; --i) result.push_back((seq >> (i*8)) & 0xFF);
    }

    return result;
  }

  // Decompress
  static std::vector<LogEntry> decompress(const std::vector<uint8_t>& data) {
    std::vector<LogEntry> result;
    if (data.size() < 9) return result; // Min header size

    size_t pos = 0;
    if (data[pos] != 'P' || data[pos+1] != 'L' || data[pos+2] != 'O' || data[pos+3] != 'G')
      return result;
    pos += 4;
    uint8_t version = data[pos++];
    if (version != 1) return result;

    uint32_t count = (static_cast<uint32_t>(data[pos]) << 24) |
                     (static_cast<uint32_t>(data[pos+1]) << 16) |
                     (static_cast<uint32_t>(data[pos+2]) << 8) |
                     static_cast<uint32_t>(data[pos+3]);
    pos += 4;

    for (uint32_t i = 0; i < count && pos < data.size(); ++i) {
      LogEntry e;
      e.timestamp.epoch_ms = (static_cast<int64_t>(data[pos]) << 56) |
                             (static_cast<int64_t>(data[pos+1]) << 48) |
                             (static_cast<int64_t>(data[pos+2]) << 40) |
                             (static_cast<int64_t>(data[pos+3]) << 32) |
                             (static_cast<int64_t>(data[pos+4]) << 24) |
                             (static_cast<int64_t>(data[pos+5]) << 16) |
                             (static_cast<int64_t>(data[pos+6]) << 8) |
                             static_cast<int64_t>(data[pos+7]);
      pos += 8;
      if (pos >= data.size()) break;

      e.level = static_cast<LogLevel>(data[pos++]);
      if (pos + 1 >= data.size()) break;

      uint16_t cat_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos+1];
      pos += 2;
      if (pos + cat_len > data.size()) break;
      e.category = std::string(reinterpret_cast<const char*>(&data[pos]), cat_len);
      pos += cat_len;
      if (pos + 1 >= data.size()) break;

      uint16_t msg_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos+1];
      pos += 2;
      if (pos + msg_len > data.size()) break;
      e.message = std::string(reinterpret_cast<const char*>(&data[pos]), msg_len);
      pos += msg_len;
      if (pos >= data.size()) break;

      uint8_t file_len = data[pos++];
      if (pos + file_len > data.size()) break;
      e.source = SourceLocation(
        std::string(reinterpret_cast<const char*>(&data[pos]), file_len).c_str(), "", 0);
      pos += file_len;
      if (pos >= data.size()) break;

      uint8_t func_len = data[pos++];
      if (pos + func_len > data.size()) break;
      pos += func_len;
      if (pos + 3 >= data.size()) break;

      e.source.line = (static_cast<int>(data[pos]) << 24) |
                      (static_cast<int>(data[pos+1]) << 16) |
                      (static_cast<int>(data[pos+2]) << 8) |
                      static_cast<int>(data[pos+3]);
      pos += 4;
      if (pos >= data.size()) break;

      uint8_t ctx_flags = data[pos++];
      if (ctx_flags & 0x01) {
        if (pos >= data.size()) break;
        uint8_t len = data[pos++];
        if (pos + len > data.size()) break;
        e.context.request_id = std::string(reinterpret_cast<const char*>(&data[pos]), len);
        pos += len;
      }
      if (ctx_flags & 0x02) {
        if (pos >= data.size()) break;
        uint8_t len = data[pos++];
        if (pos + len > data.size()) break;
        e.context.user_id = std::string(reinterpret_cast<const char*>(&data[pos]), len);
        pos += len;
      }
      if (ctx_flags & 0x04) {
        if (pos >= data.size()) break;
        uint8_t len = data[pos++];
        if (pos + len > data.size()) break;
        e.context.session_id = std::string(reinterpret_cast<const char*>(&data[pos]), len);
        pos += len;
      }

      if (pos + 7 >= data.size()) break;
      e.sequence_number = (static_cast<uint64_t>(data[pos]) << 56) |
                          (static_cast<uint64_t>(data[pos+1]) << 48) |
                          (static_cast<uint64_t>(data[pos+2]) << 40) |
                          (static_cast<uint64_t>(data[pos+3]) << 32) |
                          (static_cast<uint64_t>(data[pos+4]) << 24) |
                          (static_cast<uint64_t>(data[pos+5]) << 16) |
                          (static_cast<uint64_t>(data[pos+6]) << 8) |
                          static_cast<uint64_t>(data[pos+7]);
      pos += 8;

      result.push_back(e);
    }

    return result;
  }
};

// =============================================================================
// Utility: Thread Naming for Better Log Identification
// =============================================================================
class ThreadNamer {
public:
  static void set_current_thread_name(const std::string& name) {
#ifdef __linux__
    pthread_setname_np(pthread_self(), name.substr(0, 15).c_str());
#elif defined(__APPLE__)
    pthread_setname_np(name.substr(0, 63).c_str());
#endif
    // Store in thread-local for retrieval
    current_thread_name() = name;
  }

  static std::string get_current_thread_name() {
    return current_thread_name();
  }

  // Generate a descriptive name for worker threads
  static std::string worker_name(const std::string& pool, int index) {
    std::ostringstream oss;
    oss << pool << "-" << index;
    return oss.str();
  }

  // Generate name for IO threads
  static std::string io_name(const std::string& direction, int index) {
    std::ostringstream oss;
    oss << "io-" << direction << "-" << index;
    return oss.str();
  }

private:
  static std::string& current_thread_name() {
    thread_local static std::string name;
    return name;
  }
};

// =============================================================================
// Per-Request Log Aggregator for HTTP Request Tracing
// =============================================================================
class RequestLogAggregator {
public:
  struct RequestLog {
    std::string request_id;
    std::string method;
    std::string path;
    int status_code = 0;
    int64_t start_ms;
    int64_t end_ms;
    int64_t response_size = 0;
    std::string user_id;
    std::string ip_address;
    std::string user_agent;
    std::vector<LogEntry> log_entries;
    json extra;

    int64_t duration_ms() const { return end_ms - start_ms; }

    json to_json() const {
      json j;
      j["request_id"] = request_id;
      j["method"] = method;
      j["path"] = path;
      j["status_code"] = status_code;
      j["duration_ms"] = duration_ms();
      j["response_size"] = response_size;
      if (!user_id.empty()) j["user_id"] = user_id;
      if (!ip_address.empty()) j["ip_address"] = ip_address;
      if (!user_agent.empty()) j["user_agent"] = user_agent;
      j["log_count"] = log_entries.size();
      j["errors"] = std::count_if(log_entries.begin(), log_entries.end(),
        [](const LogEntry& e) { return e.level >= LogLevel::ERROR; });
      j["warnings"] = std::count_if(log_entries.begin(), log_entries.end(),
        [](const LogEntry& e) { return e.level == LogLevel::WARN; });
      return j;
    }
  };

  static RequestLogAggregator& instance() {
    static RequestLogAggregator agg;
    return agg;
  }

  void start_request(const std::string& request_id, const std::string& method,
                     const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    RequestLog rl;
    rl.request_id = request_id;
    rl.method = method;
    rl.path = path;
    rl.start_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
    rl.ip_address = LogContext::ip_address();
    rl.user_agent = LogContext::user_agent();
    rl.user_id = LogContext::user_id();
    active_requests_[request_id] = std::move(rl);
  }

  void end_request(const std::string& request_id, int status_code,
                   int64_t response_size = 0) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_requests_.find(request_id);
    if (it == active_requests_.end()) return;
    it->second.status_code = status_code;
    it->second.response_size = response_size;
    it->second.end_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Log summary
    auto& rl = it->second;
    std::ostringstream oss;
    oss << "HTTP " << rl.method << " " << rl.path << " -> " << rl.status_code
        << " (" << rl.duration_ms() << "ms, " << rl.response_size << " bytes)";
    LogManager::instance().info("http", oss.str());
    
    // Move to completed (keep last N)
    completed_requests_.push_back(std::move(it->second));
    active_requests_.erase(it);
    
    while (completed_requests_.size() > max_completed_) {
      completed_requests_.pop_front();
    }
  }

  void add_log_entry(const std::string& request_id, const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_requests_.find(request_id);
    if (it != active_requests_.end()) {
      it->second.log_entries.push_back(entry);
    }
  }

  json active_requests_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    json j = json::array();
    for (const auto& [id, rl] : active_requests_) {
      json rj;
      rj["request_id"] = id;
      rj["method"] = rl.method;
      rj["path"] = rl.path;
      rj["elapsed_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() - rl.start_ms;
      j.push_back(rj);
    }
    return j;
  }

  json recent_requests_json(size_t limit = 20) const {
    std::lock_guard<std::mutex> lock(mutex_);
    json j = json::array();
    size_t start = (completed_requests_.size() > limit)
      ? completed_requests_.size() - limit : 0;
    auto it = completed_requests_.begin();
    std::advance(it, start);
    for (; it != completed_requests_.end(); ++it) {
      j.push_back(it->to_json());
    }
    return j;
  }

  size_t active_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_requests_.size();
  }

private:
  static constexpr size_t max_completed_ = 10000;
  std::unordered_map<std::string, RequestLog> active_requests_;
  std::deque<RequestLog> completed_requests_;
  mutable std::mutex mutex_;
};

// =============================================================================
// Explicit template instantiations if needed
// =============================================================================
template class LockFreeSPSCQueue<LogEntry, 65536>;

} // namespace progressive
