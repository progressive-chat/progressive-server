// spam_checker.cpp — Matrix Spam Checker and Content Moderation
//
// Implements:
//   - Spam checker interface: check_event_for_spam (before persisting),
//     user_may_join_room, user_may_create_room, user_may_create_room_alias,
//     user_may_publish_room, check_username_for_spam, check_media_file_for_spam
//   - Default spam checker: URL blocklist (regex patterns), username pattern
//     blocking, room name pattern blocking, media type blocking
//   - Event content filtering: filter event content before storing, URL
//     extraction and validation
//   - Room creation limits: per-user room creation rate limiting
//   - Invite rate limiting: per-user invite rate limiting
//   - Username blacklist: reserved usernames, admin names, offensive patterns
//   - Module loading: load external spam checker modules (.so plugins) with
//     dynamic symbol loading (dlsym)
//   - Antispam hooks: call hooks in order, first match wins, allow/block/flag
//     decisions
//
// Equivalent to synapse/events/spamcheck.py + synapse/spam_checker_api +
//              synapse/module_api/ + synapse/handlers/spam_checker.py
// Target: 2000+ lines

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <dlfcn.h>
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
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

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
class SpamCheckResult;
class SpamCheckerInterface;
class DefaultSpamChecker;
class SpamCheckerRegistry;
class UrlBlocklist;
class UsernameBlacklist;
class RateLimiter;
class RoomCreationLimiter;
class InviteRateLimiter;
class ContentFilter;
class SpamCheckerModule;
class ModuleLoader;
class AntispamHookChain;
class MediaTypeFilter;
class PatternMatcher;

// ============================================================================
// Enums and Constants
// ============================================================================

// Represents the decision of a spam check
enum class SpamDecision : uint8_t {
  ALLOW = 0,        // Allow the action/event
  BLOCK = 1,        // Block the action/event (silently or with error)
  FLAG = 2,         // Allow but flag for review
  DEFER = 3,        // Defer to the next checker in chain
  MODIFY = 4,       // Allow but modify content
};

// Action that is being checked
enum class SpamAction : uint8_t {
  SEND_MESSAGE = 0,
  CREATE_ROOM = 1,
  JOIN_ROOM = 2,
  INVITE_USER = 3,
  CREATE_ALIAS = 4,
  PUBLISH_ROOM = 5,
  REGISTER_USER = 6,
  UPLOAD_MEDIA = 7,
  SET_DISPLAY_NAME = 8,
  SET_AVATAR = 9,
};

// Severity of a spam detection
enum class SpamSeverity : uint8_t {
  LOW = 0,
  MEDIUM = 1,
  HIGH = 2,
  CRITICAL = 3,
};

// Convert enum to string for logging
const char* spam_decision_str(SpamDecision d) {
  switch (d) {
    case SpamDecision::ALLOW:  return "ALLOW";
    case SpamDecision::BLOCK:  return "BLOCK";
    case SpamDecision::FLAG:   return "FLAG";
    case SpamDecision::DEFER:  return "DEFER";
    case SpamDecision::MODIFY: return "MODIFY";
    default: return "UNKNOWN";
  }
}

const char* spam_action_str(SpamAction a) {
  switch (a) {
    case SpamAction::SEND_MESSAGE:    return "SEND_MESSAGE";
    case SpamAction::CREATE_ROOM:     return "CREATE_ROOM";
    case SpamAction::JOIN_ROOM:       return "JOIN_ROOM";
    case SpamAction::INVITE_USER:     return "INVITE_USER";
    case SpamAction::CREATE_ALIAS:    return "CREATE_ALIAS";
    case SpamAction::PUBLISH_ROOM:    return "PUBLISH_ROOM";
    case SpamAction::REGISTER_USER:   return "REGISTER_USER";
    case SpamAction::UPLOAD_MEDIA:    return "UPLOAD_MEDIA";
    case SpamAction::SET_DISPLAY_NAME: return "SET_DISPLAY_NAME";
    case SpamAction::SET_AVATAR:      return "SET_AVATAR";
    default: return "UNKNOWN";
  }
}

const char* spam_severity_str(SpamSeverity s) {
  switch (s) {
    case SpamSeverity::LOW:      return "LOW";
    case SpamSeverity::MEDIUM:   return "MEDIUM";
    case SpamSeverity::HIGH:     return "HIGH";
    case SpamSeverity::CRITICAL: return "CRITICAL";
    default: return "UNKNOWN";
  }
}

// ============================================================================
// SpamCheckResult — result of a spam check
// ============================================================================
struct SpamCheckResult {
  SpamDecision decision{SpamDecision::ALLOW};
  SpamSeverity severity{SpamSeverity::LOW};
  std::string reason;
  std::string checker_name;
  std::optional<json> modified_content;
  bool should_notify_admin{false};
  int error_code{403};  // HTTP error code when blocking
  std::string error_message{"Request denied by spam checker"};

  // Factory methods
  static SpamCheckResult allow() {
    return SpamCheckResult{SpamDecision::ALLOW, SpamSeverity::LOW, "", "", std::nullopt, false};
  }

  static SpamCheckResult block(const std::string& reason,
                                const std::string& checker = "default",
                                int code = 403,
                                const std::string& msg = "Request denied by spam checker") {
    return SpamCheckResult{SpamDecision::BLOCK, SpamSeverity::HIGH, reason, checker,
                           std::nullopt, true, code, msg};
  }

  static SpamCheckResult flag(const std::string& reason,
                               SpamSeverity sev = SpamSeverity::MEDIUM,
                               const std::string& checker = "default") {
    return SpamCheckResult{SpamDecision::FLAG, sev, reason, checker, std::nullopt, true};
  }

  static SpamCheckResult defer() {
    return SpamCheckResult{SpamDecision::DEFER, SpamSeverity::LOW, "", "", std::nullopt, false};
  }

  static SpamCheckResult modify(const json& new_content,
                                 const std::string& checker = "default") {
    return SpamCheckResult{SpamDecision::MODIFY, SpamSeverity::LOW, "", checker, new_content, false};
  }

  bool is_allowed() const { return decision == SpamDecision::ALLOW; }
  bool is_blocked() const { return decision == SpamDecision::BLOCK; }
  bool is_flagged() const { return decision == SpamDecision::FLAG; }
  bool is_deferred() const { return decision == SpamDecision::DEFER; }
  bool is_modified() const { return decision == SpamDecision::MODIFY; }
};

// ============================================================================
// Utility: string helpers (anonymous namespace)
// ============================================================================
namespace {

bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size()) == suffix;
}

bool contains(std::string_view s, std::string_view sub) {
  return s.find(sub) != std::string_view::npos;
}

std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

std::string to_upper(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::toupper);
  return s;
}

std::string trim(const std::string& s) {
  auto start = s.begin();
  while (start != s.end() && std::isspace(*start)) ++start;
  auto end = s.end();
  while (end != start && std::isspace(*(end - 1))) --end;
  return std::string(start, end);
}

std::vector<std::string> split(const std::string& str, char delim) {
  std::vector<std::string> result;
  std::string item;
  for (char c : str) {
    if (c == delim) {
      if (!item.empty()) result.push_back(item);
      item.clear();
    } else {
      item += c;
    }
  }
  if (!item.empty()) result.push_back(item);
  return result;
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
  std::string result;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) result += sep;
    result += parts[i];
  }
  return result;
}

// Simple leaky-bucket rate limit tracker entry
struct RateBucket {
  std::atomic<int64_t> tokens{0};
  int64_t max_tokens{10};
  chr::steady_clock::time_point last_refill{chr::steady_clock::now()};
  chr::seconds refill_interval{1};
  int64_t refill_rate{1};
  std::mutex mtx;

  bool try_consume(int64_t count = 1) {
    std::lock_guard<std::mutex> lock(mtx);
    auto now = chr::steady_clock::now();
    auto elapsed = chr::duration_cast<chr::seconds>(now - last_refill).count();
    if (elapsed > 0) {
      int64_t added = elapsed * refill_rate;
      tokens.store(std::min(tokens.load() + added, max_tokens));
      last_refill = now;
    }
    int64_t cur = tokens.load();
    if (cur >= count) {
      tokens.store(cur - count);
      return true;
    }
    return false;
  }

  void reset() {
    std::lock_guard<std::mutex> lock(mtx);
    tokens.store(max_tokens);
    last_refill = chr::steady_clock::now();
  }
};

} // anonymous namespace

// ============================================================================
// PatternMatcher — regex-based pattern matching with caching
// ============================================================================
class PatternMatcher {
public:
  PatternMatcher() = default;

  void add_pattern(const std::string& name, const std::string& pattern,
                   SpamSeverity severity = SpamSeverity::HIGH) {
    try {
      std::regex re(pattern, std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
      patterns_.push_back({name, std::move(re), severity});
    } catch (const std::regex_error& e) {
      std::cerr << "[PatternMatcher] Invalid regex '" << pattern
                << "': " << e.what() << std::endl;
    }
  }

  struct MatchResult {
    bool matched{false};
    std::string pattern_name;
    std::string matched_text;
    SpamSeverity severity{SpamSeverity::MEDIUM};
  };

  MatchResult match(const std::string& text) const {
    for (const auto& entry : patterns_) {
      std::smatch m;
      if (std::regex_search(text, m, entry.re)) {
        return {true, entry.name, m.str(0), entry.severity};
      }
    }
    return {};
  }

  bool matches_any(const std::string& text) const {
    for (const auto& entry : patterns_) {
      if (std::regex_search(text, entry.re)) return true;
    }
    return false;
  }

  size_t pattern_count() const { return patterns_.size(); }

  void clear() { patterns_.clear(); }

private:
  struct PatternEntry {
    std::string name;
    std::regex re;
    SpamSeverity severity;
  };
  std::vector<PatternEntry> patterns_;
};

// ============================================================================
// UrlBlocklist — URL/domain blocklist with regex patterns
// ============================================================================
class UrlBlocklist {
public:
  UrlBlocklist() {
    load_default_patterns();
  }

  // Check if a URL or domain is in the blocklist
  SpamCheckResult check_url(const std::string& url) const {
    auto result = url_patterns_.match(url);
    if (result.matched) {
      return SpamCheckResult::block(
        "URL matches blocklist pattern '" + result.pattern_name + "': " + result.matched_text,
        "url_blocklist", 403,
        "Message contains blocked URL"
      );
    }

    // Also check extracted domain
    std::string domain = extract_domain(url);
    if (!domain.empty()) {
      auto dresult = domain_patterns_.match(domain);
      if (dresult.matched) {
        return SpamCheckResult::block(
          "Domain matches blocklist pattern '" + dresult.pattern_name + "': " + dresult.matched_text,
          "url_blocklist", 403,
          "Message contains link to blocked domain"
        );
      }
    }

    // Check TLD
    std::string tld = extract_tld(domain.empty() ? url : domain);
    if (!tld.empty() && blocked_tlds_.count(to_lower(tld))) {
      return SpamCheckResult::block(
        "Top-level domain '" + tld + "' is blocked",
        "url_blocklist", 403,
        "Message contains link to blocked TLD"
      );
    }

    return SpamCheckResult::allow();
  }

  // Check ALL URLs in a text body
  SpamCheckResult check_text(const std::string& text) const {
    auto urls = extract_urls(text);
    for (const auto& url : urls) {
      auto result = check_url(url);
      if (result.is_blocked()) return result;
    }
    return SpamCheckResult::allow();
  }

  // Add a URL regex pattern
  void add_url_pattern(const std::string& name, const std::string& pattern,
                       SpamSeverity severity = SpamSeverity::HIGH) {
    url_patterns_.add_pattern(name, pattern, severity);
  }

  // Add a domain regex pattern
  void add_domain_pattern(const std::string& name, const std::string& pattern,
                          SpamSeverity severity = SpamSeverity::HIGH) {
    domain_patterns_.add_pattern(name, pattern, severity);
  }

  // Add a blocked TLD
  void add_blocked_tld(const std::string& tld) {
    blocked_tlds_.insert(to_lower(tld));
  }

  // Extract all URLs from text
  static std::vector<std::string> extract_urls(const std::string& text) {
    std::vector<std::string> urls;
    // RFC 3986 based URL regex
    static const std::regex url_re(
      R"(\b(https?://|matrix\.to/#/|mxc://)[^\s<>"'`{}\[\]|\\^]+)",
      std::regex::ECMAScript | std::regex::icase
    );
    std::sregex_iterator it(text.begin(), text.end(), url_re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
      urls.push_back(it->str());
    }
    return urls;
  }

  // Extract domain from URL
  static std::string extract_domain(const std::string& url) {
    static const std::regex domain_re(
      R"(^(?:https?://)?(?:[^@/\n]+@)?(?:www\.)?([^:/\n?]+))",
      std::regex::ECMAScript | std::regex::icase
    );
    std::smatch m;
    if (std::regex_search(url, m, domain_re) && m.size() > 1) {
      return to_lower(m[1].str());
    }
    return "";
  }

  // Extract TLD from domain
  static std::string extract_tld(const std::string& domain_or_url) {
    std::string d = extract_domain(domain_or_url);
    if (d.empty()) d = domain_or_url;
    auto dot_pos = d.rfind('.');
    if (dot_pos != std::string::npos && dot_pos + 1 < d.size()) {
      return to_lower(d.substr(dot_pos + 1));
    }
    return "";
  }

  // Load default blocklist patterns
  void load_default_patterns() {
    // Common spam/phishing domains
    add_domain_pattern("numeric_ip", R"(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)", SpamSeverity::MEDIUM);
    add_domain_pattern("short_url", R"((bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|shorte\.st|bc\.vc|t\.co|lnkd\.in|db\.tt|qr\.ae|cur\.lv|x\.co|v\.gd|cutt\.ly|short\.link|rb\.gy|t2m\.io|clck\.ru|shorturl\.at))", SpamSeverity::HIGH);
    add_domain_pattern("free_domain", R"((\.tk$|\.ml$|\.ga$|\.cf$|\.gq$))", SpamSeverity::MEDIUM);
    add_domain_pattern("disposable_email_domain", R"((mailinator\.com|guerrillamail\.com|10minutemail\.com|yopmail\.com|temp-mail\.org|throwaway\.email|maildrop\.cc|sharklasers\.com|trashmail\.com|getnada\.com|dispostable\.com))", SpamSeverity::HIGH);

    // Blocked TLDs (often used for spam)
    blocked_tlds_.insert({"tk", "ml", "ga", "cf", "gq", "loan", "work", "date", "win", "review", "country", "stream", "download", "trade", "accountant", "science", "party", "webcam", "racing", "bid", "cricket", "faith", "men"});

    // URL patterns for known spam
    add_url_pattern("crypto_scam", R"((free.*(btc|bitcoin|eth|ethereum|crypto).*giveaway|elon.*musk.*giveaway))", SpamSeverity::CRITICAL);
    add_url_pattern("phishing_generic", R"((login.*verify|account.*suspended|security.*alert|password.*reset.*click|confirm.*identity).*\.(tk|ml|ga|cf|gq))", SpamSeverity::CRITICAL);
  }

  size_t url_pattern_count() const { return url_patterns_.pattern_count(); }
  size_t domain_pattern_count() const { return domain_patterns_.pattern_count(); }
  size_t tld_count() const { return blocked_tlds_.size(); }

private:
  PatternMatcher url_patterns_;
  PatternMatcher domain_patterns_;
  std::unordered_set<std::string> blocked_tlds_;
};

// ============================================================================
// UsernameBlacklist — reserved usernames, admin names, offensive patterns
// ============================================================================
class UsernameBlacklist {
public:
  UsernameBlacklist() {
    load_defaults();
  }

  // Check if a username is on any blacklist
  SpamCheckResult check_username(const std::string& username) const {
    std::string lower = to_lower(username);

    // Check reserved usernames (system accounts)
    if (reserved_usernames_.count(lower)) {
      return SpamCheckResult::block(
        "Username '" + username + "' is reserved for system use",
        "username_blacklist", 400,
        "This username is reserved and cannot be registered"
      );
    }

    // Check admin-like usernames (impersonation protection)
    for (const auto& pattern : admin_patterns_) {
      if (contains(lower, pattern)) {
        return SpamCheckResult::block(
          "Username '" + username + "' mimics administrative account",
          "username_blacklist", 400,
          "This username is not allowed (impersonating administrative accounts)"
        );
      }
    }

    // Check offensive username patterns
    auto offensive_result = offensive_patterns_.match(lower);
    if (offensive_result.matched) {
      return SpamCheckResult::block(
        "Username matches offensive pattern '" + offensive_result.pattern_name + "'",
        "username_blacklist", 400,
        "This username is not allowed"
      );
    }

    // Check format: must be valid Matrix user ID localpart
    if (!is_valid_localpart(username)) {
      return SpamCheckResult::block(
        "Username '" + username + "' does not match valid Matrix localpart format",
        "username_blacklist", 400,
        "Username contains invalid characters"
      );
    }

    // Check length
    if (username.size() < min_length_) {
      return SpamCheckResult::block(
        "Username too short (minimum " + std::to_string(min_length_) + " characters)",
        "username_blacklist", 400,
        "Username is too short"
      );
    }

    if (username.size() > max_length_) {
      return SpamCheckResult::block(
        "Username too long (maximum " + std::to_string(max_length_) + " characters)",
        "username_blacklist", 400,
        "Username is too long"
      );
    }

    // Check for excessive digits (bot-like usernames)
    int digit_count = 0;
    for (char c : lower) { if (std::isdigit(c)) ++digit_count; }
    if (digit_count > max_digits_ && lower.size() > 3) {
      return SpamCheckResult::flag(
        "Username contains excessive digits (" + std::to_string(digit_count) + ")",
        SpamSeverity::LOW, "username_blacklist"
      );
    }

    return SpamCheckResult::allow();
  }

  void add_reserved_username(const std::string& name) {
    reserved_usernames_.insert(to_lower(name));
  }

  void add_admin_pattern(const std::string& pattern) {
    admin_patterns_.push_back(to_lower(pattern));
  }

  void add_offensive_pattern(const std::string& name, const std::string& pattern,
                              SpamSeverity severity = SpamSeverity::HIGH) {
    offensive_patterns_.add_pattern(name, pattern, severity);
  }

  void set_min_length(size_t min) { min_length_ = min; }
  void set_max_length(size_t max) { max_length_ = max; }
  void set_max_digits(int max) { max_digits_ = max; }

  // Accessor for stats
  size_t pattern_count_placeholder() const { return offensive_patterns_.pattern_count(); }

private:
  void load_defaults() {
    // Reserved system usernames
    reserved_usernames_ = {
      "admin", "administrator", "root", "system", "server", "service",
      "matrix", "synapse", "progressive", "moderator", "mod", "support",
      "security", "abuse", "postmaster", "webmaster", "hostmaster",
      "noreply", "no-reply", "no_reply", "daemon", "nobody", "operator",
      "bot", "spam", "report", "help", "info", "contact", "feedback",
      "test", "testing", "guest", "anonymous", "anon", "null",
      "undefined", "none", "everyone", "all", "here", "channel",
      "slackbot", "discord", "telegram", "whatsapp", "signal",
    };

    // Admin-like patterns (impersonation protection)
    admin_patterns_ = {
      "admin", "administrator", "moderator", "staff", "official",
      "support_team", "security_team", "trust_and_safety",
      "server_admin", "sysadmin", "root_admin",
    };

    // Offensive username patterns
    offensive_patterns_.add_pattern("hate_speech", R"((nazi|hitler|kkk|whitepower|aryan|heil))", SpamSeverity::CRITICAL);
    offensive_patterns_.add_pattern("profanity_common", R"(\b(fuck|shit|asshole|bastard|bitch|cunt|dick)\b)", SpamSeverity::HIGH);
    offensive_patterns_.add_pattern("scam_keywords", R"((free.*money|earn.*fast|work.*home|make.*cash|click.*here.*win))", SpamSeverity::HIGH);
    offensive_patterns_.add_pattern("sexual_explicit", R"((sex|porn|xxx|nsfw|nude|escort|onlyfans|camgirl))", SpamSeverity::MEDIUM);
  }

  static bool is_valid_localpart(const std::string& localpart) {
    if (localpart.empty()) return false;
    // Matrix localpart: a-z, 0-9, . _ = - / +
    static const std::regex localpart_re(R"(^[a-z0-9._=\-/\+]+$)", std::regex::icase);
    return std::regex_match(localpart, localpart_re);
  }

  std::unordered_set<std::string> reserved_usernames_;
  std::vector<std::string> admin_patterns_;
  PatternMatcher offensive_patterns_;
  size_t min_length_{3};
  size_t max_length_{255};
  int max_digits_{6};
};

// ============================================================================
// MediaTypeFilter — block dangerous/abusive media types
// ============================================================================
class MediaTypeFilter {
public:
  MediaTypeFilter() {
    load_defaults();
  }

  // Check if a media MIME type is allowed
  SpamCheckResult check_media(const std::string& mime_type,
                               int64_t file_size_bytes = 0) const {
    // Check if MIME type is explicitly blocked
    std::string lower_mime = to_lower(mime_type);
    for (const auto& pattern : blocked_mime_patterns_) {
      if (contains(lower_mime, pattern) || pattern == "*") {
        return SpamCheckResult::block(
          "Media type '" + mime_type + "' is blocked",
          "media_type_filter", 415,
          "This type of media is not allowed"
        );
      }
    }

    // Check file size limits
    if (file_size_bytes > 0) {
      if (file_size_bytes > max_file_size_bytes_) {
        return SpamCheckResult::block(
          "File size " + std::to_string(file_size_bytes) + " bytes exceeds maximum " +
          std::to_string(max_file_size_bytes_) + " bytes",
          "media_type_filter", 413,
          "File is too large"
        );
      }
    }

    // Check for executable/script types
    if (is_executable_type(lower_mime)) {
      return SpamCheckResult::block(
        "Executable type '" + mime_type + "' is not allowed",
        "media_type_filter", 415,
        "Executable files are not allowed"
      );
    }

    // Check for archive bombs (just warn, don't block)
    if (is_archive_type(lower_mime) && file_size_bytes > max_archive_size_bytes_) {
      return SpamCheckResult::flag(
        "Large archive file uploaded: " + std::to_string(file_size_bytes) + " bytes",
        SpamSeverity::MEDIUM, "media_type_filter"
      );
    }

    // SVG can contain scripts — flag
    if (contains(lower_mime, "svg")) {
      return SpamCheckResult::flag(
        "SVG file uploaded — may contain embedded scripts",
        SpamSeverity::LOW, "media_type_filter"
      );
    }

    return SpamCheckResult::allow();
  }

  void set_max_file_size(int64_t bytes) { max_file_size_bytes_ = bytes; }
  void set_max_archive_size(int64_t bytes) { max_archive_size_bytes_ = bytes; }
  int64_t max_file_size() const { return max_file_size_bytes_; }

  void block_mime_type(const std::string& mime_pattern) {
    blocked_mime_patterns_.push_back(to_lower(mime_pattern));
  }

private:
  void load_defaults() {
    // Block executable types
    // These are handled by is_executable_type() but also added to patterns
    // for explicit matching
  }

  static bool is_executable_type(const std::string& mime) {
    static const std::vector<std::string> exec_types = {
      "application/x-executable", "application/x-elf", "application/x-dosexec",
      "application/x-msdownload", "application/x-sh", "application/x-bat",
      "application/x-csh", "application/x-ksh", "application/x-tcsh",
      "application/x-perl", "application/x-python", "application/x-ruby",
      "application/x-php", "application/x-java-archive",
      "application/x-msdos-program", "application/x-shellscript",
      "application/vnd.microsoft.portable-executable",
    };
    for (const auto& t : exec_types) {
      if (contains(mime, t)) return true;
    }
    return false;
  }

  static bool is_archive_type(const std::string& mime) {
    return contains(mime, "zip") || contains(mime, "tar") ||
           contains(mime, "gzip") || contains(mime, "rar") ||
           contains(mime, "7z") || contains(mime, "archive") ||
           contains(mime, "x-bzip") || contains(mime, "x-xz") ||
           contains(mime, "x-compress");
  }

  std::vector<std::string> blocked_mime_patterns_;
  int64_t max_file_size_bytes_{100 * 1024 * 1024};    // 100 MB default
  int64_t max_archive_size_bytes_{50 * 1024 * 1024};   // 50 MB default for archives
};

// ============================================================================
// ContentFilter — filters and sanitizes event content
// ============================================================================
class ContentFilter {
public:
  ContentFilter() = default;

  // Filter event content before storing — remove/replace problematic content
  json filter_content(const json& event_content) const {
    json filtered = event_content;

    // Filter message body
    if (filtered.contains("body") && filtered["body"].is_string()) {
      std::string body = filtered["body"].get<std::string>();
      body = filter_text(body);
      filtered["body"] = body;
    }

    // Filter formatted_body
    if (filtered.contains("formatted_body") && filtered["formatted_body"].is_string()) {
      std::string formatted = filtered["formatted_body"].get<std::string>();
      formatted = filter_html(formatted);
      filtered["formatted_body"] = formatted;
    }

    // Filter room name
    if (filtered.contains("name") && filtered["name"].is_string()) {
      std::string name = filtered["name"].get<std::string>();
      name = filter_text(name);
      filtered["name"] = name;
    }

    // Filter room topic
    if (filtered.contains("topic") && filtered["topic"].is_string()) {
      std::string topic = filtered["topic"].get<std::string>();
      topic = filter_text(topic);
      filtered["topic"] = topic;
    }

    // Filter displayname
    if (filtered.contains("displayname") && filtered["displayname"].is_string()) {
      std::string dn = filtered["displayname"].get<std::string>();
      dn = filter_text(dn);
      filtered["displayname"] = dn;
    }

    return filtered;
  }

  // Extract all URLs from event content for spam checking
  std::vector<std::string> extract_urls_from_event(const json& event_content) const {
    std::vector<std::string> all_urls;
    std::string text = extract_all_text(event_content);
    auto urls = UrlBlocklist::extract_urls(text);
    all_urls.insert(all_urls.end(), urls.begin(), urls.end());
    return all_urls;
  }

  // Validate URLs found in content
  struct UrlValidation {
    bool valid{true};
    std::string url;
    std::string issue;
  };

  UrlValidation validate_url(const std::string& url) const {
    UrlValidation result;
    result.url = url;

    // Check URL length
    if (url.size() > max_url_length_) {
      result.valid = false;
      result.issue = "URL exceeds maximum length";
      return result;
    }

    // Check for suspicious URL patterns
    if (contains(url, "@")) {
      result.valid = false;
      result.issue = "URL contains '@' character (possible credential leak)";
      return result;
    }

    // Check for data: URIs (can contain arbitrary data)
    if (starts_with(to_lower(url), "data:")) {
      result.valid = false;
      result.issue = "data: URIs are not allowed in events";
      return result;
    }

    // Check for javascript: URIs
    if (starts_with(to_lower(url), "javascript:")) {
      result.valid = false;
      result.issue = "javascript: URIs are not allowed in events";
      return result;
    }

    return result;
  }

  void set_max_url_length(size_t len) { max_url_length_ = len; }

  // Enable/disable features
  void set_strip_null_bytes(bool v) { strip_null_bytes_ = v; }
  void set_max_body_length(size_t len) { max_body_length_ = len; }

private:
  std::string filter_text(const std::string& text) const {
    std::string result = text;

    // Strip null bytes
    if (strip_null_bytes_) {
      result.erase(std::remove(result.begin(), result.end(), '\0'), result.end());
    }

    // Normalize excessive whitespace
    if (normalize_whitespace_) {
      bool in_space = false;
      size_t write = 0;
      for (size_t read = 0; read < result.size(); ++read) {
        if (std::isspace(static_cast<unsigned char>(result[read]))) {
          if (!in_space) {
            result[write++] = ' ';
            in_space = true;
          }
        } else {
          result[write++] = result[read];
          in_space = false;
        }
      }
      result.resize(write);
    }

    // Trim
    result = trim(result);

    // Truncate if too long
    if (max_body_length_ > 0 && result.size() > max_body_length_) {
      result.resize(max_body_length_);
    }

    return result;
  }

  std::string filter_html(const std::string& html) const {
    std::string result = html;

    // Strip null bytes
    if (strip_null_bytes_) {
      result.erase(std::remove(result.begin(), result.end(), '\0'), result.end());
    }

    // Remove script tags (basic)
    static const std::regex script_re(R"(<\s*script[^>]*>.*?<\s*/\s*script\s*>)",
                                       std::regex::icase | std::regex::ECMAScript);
    result = std::regex_replace(result, script_re, "[script removed]");

    // Remove iframe tags
    static const std::regex iframe_re(R"(<\s*iframe[^>]*>.*?<\s*/\s*iframe\s*>)",
                                       std::regex::icase | std::regex::ECMAScript);
    result = std::regex_replace(result, iframe_re, "[iframe removed]");

    // Remove event handler attributes (onclick, onerror, onload, etc.)
    static const std::regex evt_re(
      R"(\s+on\w+\s*=\s*["'][^"']*["'])",
      std::regex::icase | std::regex::ECMAScript
    );
    result = std::regex_replace(result, evt_re, "");

    // Remove javascript: in href/src
    static const std::regex js_re(
      R"((href|src)\s*=\s*["']javascript:[^"']*["'])",
      std::regex::icase | std::regex::ECMAScript
    );
    result = std::regex_replace(result, js_re, "$1=\"#blocked\"");

    return result;
  }

  std::string extract_all_text(const json& content) const {
    std::ostringstream oss;
    if (content.contains("body") && content["body"].is_string()) {
      oss << content["body"].get<std::string>() << " ";
    }
    if (content.contains("formatted_body") && content["formatted_body"].is_string()) {
      oss << content["formatted_body"].get<std::string>() << " ";
    }
    if (content.contains("url") && content["url"].is_string()) {
      oss << content["url"].get<std::string>() << " ";
    }
    return oss.str();
  }

  bool strip_null_bytes_{true};
  bool normalize_whitespace_{true};
  size_t max_body_length_{65536};   // 64 KB
  size_t max_url_length_{2048};
};

// ============================================================================
// RateLimiter — generic sliding-window rate limiter
// ============================================================================
class RateLimiter {
public:
  RateLimiter(size_t max_actions, chr::seconds window)
    : max_actions_(max_actions), window_(window) {}

  // Record an action and return whether it's allowed
  bool try_action(const std::string& key) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto now = chr::steady_clock::now();
    auto& window = windows_[key];

    // Purge old entries
    auto cutoff = now - window_;
    window.timestamps.erase(
      std::remove_if(window.timestamps.begin(), window.timestamps.end(),
                     [&cutoff](const auto& t) { return t < cutoff; }),
      window.timestamps.end()
    );

    // Check if under limit
    if (window.timestamps.size() >= max_actions_) {
      return false;
    }

    // Record action
    window.timestamps.push_back(now);
    return true;
  }

  // Get how many actions remaining in current window
  size_t remaining(const std::string& key) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto now = chr::steady_clock::now();
    auto& window = windows_[key];
    auto cutoff = now - window_;
    window.timestamps.erase(
      std::remove_if(window.timestamps.begin(), window.timestamps.end(),
                     [&cutoff](const auto& t) { return t < cutoff; }),
      window.timestamps.end()
    );
    return max_actions_ > window.timestamps.size()
               ? max_actions_ - window.timestamps.size()
               : 0;
  }

  // Reset a key's rate limit
  void reset(const std::string& key) {
    std::lock_guard<std::mutex> lock(mtx_);
    windows_[key].timestamps.clear();
  }

  // Periodically clean up stale keys
  void cleanup() {
    std::lock_guard<std::mutex> lock(mtx_);
    auto cutoff = chr::steady_clock::now() - chr::minutes(10);
    for (auto it = windows_.begin(); it != windows_.end(); ) {
      // Purge old entries in this window
      auto& w = it->second;
      w.timestamps.erase(
        std::remove_if(w.timestamps.begin(), w.timestamps.end(),
                       [&cutoff](const auto& t) { return t < cutoff; }),
        w.timestamps.end()
      );
      // Remove entirely empty windows that haven't seen activity
      if (w.timestamps.empty()) {
        it = windows_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Stats
  size_t active_keys() const {
    return windows_.size();
  }

  void set_max_actions(size_t max) { max_actions_ = max; }
  void set_window(chr::seconds w) { window_ = w; }

private:
  struct WindowData {
    std::vector<chr::steady_clock::time_point> timestamps;
  };

  size_t max_actions_;
  chr::seconds window_;
  std::unordered_map<std::string, WindowData> windows_;
  std::mutex mtx_;
};

// ============================================================================
// RoomCreationLimiter — per-user room creation rate limiting
// ============================================================================
class RoomCreationLimiter {
public:
  RoomCreationLimiter()
    : rate_limiter_(10, chr::seconds(3600))  // 10 rooms per hour
    , burst_limiter_(3, chr::seconds(60))     // 3 rooms per minute
  {}

  SpamCheckResult check_room_creation(const std::string& user_id) {
    // Check burst limit (per minute)
    if (!burst_limiter_.try_action(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " exceeded room creation burst limit",
        "room_creation_limiter", 429,
        "You are creating rooms too quickly. Please wait before creating another room."
      );
    }

    // Check hourly limit
    if (!rate_limiter_.try_action(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " exceeded hourly room creation limit",
        "room_creation_limiter", 429,
        "You have reached the maximum number of rooms you can create. Please try again later."
      );
    }

    return SpamCheckResult::allow();
  }

  // Check if user can create a room (does NOT consume the rate limit)
  bool can_create(const std::string& user_id) {
    return rate_limiter_.remaining(user_id) > 0;
  }

  // Get remaining room creations this hour
  size_t remaining(const std::string& user_id) {
    return rate_limiter_.remaining(user_id);
  }

  // Configure limits
  void set_hourly_limit(size_t limit) {
    rate_limiter_.set_max_actions(limit);
  }
  void set_burst_limit(size_t limit) {
    burst_limiter_.set_max_actions(limit);
  }
  void set_hourly_window(int seconds) {
    rate_limiter_.set_window(chr::seconds(seconds));
  }

  void cleanup() {
    rate_limiter_.cleanup();
    burst_limiter_.cleanup();
  }

private:
  RateLimiter rate_limiter_;
  RateLimiter burst_limiter_;
};

// ============================================================================
// InviteRateLimiter — per-user invite rate limiting
// ============================================================================
class InviteRateLimiter {
public:
  InviteRateLimiter()
    : per_user_limiter_(50, chr::seconds(3600))    // 50 invites per hour
    , per_room_limiter_(100, chr::seconds(3600))   // 100 invites per room per hour
    , burst_limiter_(5, chr::seconds(60))           // 5 invites per minute
  {}

  SpamCheckResult check_invite(const std::string& inviter_id,
                                const std::string& room_id) {
    // Check burst limit
    std::string burst_key = inviter_id;
    if (!burst_limiter_.try_action(burst_key)) {
      return SpamCheckResult::block(
        "User " + inviter_id + " exceeded invite burst limit",
        "invite_rate_limiter", 429,
        "You are sending invites too quickly. Please wait before inviting more users."
      );
    }

    // Check per-user hourly limit
    if (!per_user_limiter_.try_action(inviter_id)) {
      return SpamCheckResult::block(
        "User " + inviter_id + " exceeded hourly invite limit",
        "invite_rate_limiter", 429,
        "You have reached the maximum number of invites. Please try again later."
      );
    }

    // Check per-room hourly limit
    if (!per_room_limiter_.try_action(room_id)) {
      return SpamCheckResult::block(
        "Room " + room_id + " exceeded hourly invite limit",
        "invite_rate_limiter", 429,
        "This room has reached the maximum number of invites. Please try again later."
      );
    }

    return SpamCheckResult::allow();
  }

  void set_per_user_hourly_limit(size_t limit) {
    per_user_limiter_.set_max_actions(limit);
  }
  void set_per_room_hourly_limit(size_t limit) {
    per_room_limiter_.set_max_actions(limit);
  }
  void set_burst_limit(size_t limit) {
    burst_limiter_.set_max_actions(limit);
  }

  void cleanup() {
    per_user_limiter_.cleanup();
    per_room_limiter_.cleanup();
    burst_limiter_.cleanup();
  }

private:
  RateLimiter per_user_limiter_;
  RateLimiter per_room_limiter_;
  RateLimiter burst_limiter_;
};

// ============================================================================
// SpamCheckerInterface — abstract base class for all spam checkers
// ============================================================================
class SpamCheckerInterface {
public:
  virtual ~SpamCheckerInterface() = default;

  // Return the name of this checker module
  virtual const char* checker_name() const = 0;

  // Return the version of this checker
  virtual const char* checker_version() const { return "1.0"; }

  // Called once when the checker is loaded — can be used for initialization
  virtual void on_load(const json& config) {}

  // Called when the checker is unloaded
  virtual void on_unload() {}

  // ===================================================================
  // Core spam check methods
  // ===================================================================

  // Check an event for spam before it is persisted.
  // Return ALLOW to proceed, BLOCK to reject, FLAG to allow but flag.
  virtual SpamCheckResult check_event_for_spam(
      const json& event,
      const std::string& sender,
      const std::string& room_id) {
    return SpamCheckResult::defer();
  }

  // Check whether a user may join a room.
  virtual SpamCheckResult user_may_join_room(
      const std::string& user_id,
      const std::string& room_id,
      bool is_invited) {
    return SpamCheckResult::defer();
  }

  // Check whether a user may create a room.
  virtual SpamCheckResult user_may_create_room(
      const std::string& user_id) {
    return SpamCheckResult::defer();
  }

  // Check whether a user may create a room alias.
  virtual SpamCheckResult user_may_create_room_alias(
      const std::string& user_id,
      const std::string& room_alias) {
    return SpamCheckResult::defer();
  }

  // Check whether a user may publish a room to the public directory.
  virtual SpamCheckResult user_may_publish_room(
      const std::string& user_id,
      const std::string& room_id) {
    return SpamCheckResult::defer();
  }

  // Check a username for spam when a user registers or changes username.
  virtual SpamCheckResult check_username_for_spam(
      const std::string& username,
      const std::string& user_id) {
    return SpamCheckResult::defer();
  }

  // Check media file for spam before upload completes.
  // Called with the MIME type, file size, and optional metadata.
  virtual SpamCheckResult check_media_file_for_spam(
      const std::string& mime_type,
      int64_t file_size_bytes,
      const std::string& upload_name,
      const std::string& user_id) {
    return SpamCheckResult::defer();
  }

  // Check whether a user may invite another user.
  virtual SpamCheckResult user_may_invite(
      const std::string& inviter_id,
      const std::string& invitee_id,
      const std::string& room_id) {
    return SpamCheckResult::defer();
  }

  // Check whether a user may send a message in a room.
  virtual SpamCheckResult user_may_send_message(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& message_type) {
    return SpamCheckResult::defer();
  }

  // Check whether a user may set a display name.
  virtual SpamCheckResult check_displayname_for_spam(
      const std::string& displayname,
      const std::string& user_id) {
    return SpamCheckResult::defer();
  }

  // Check whether a user may set an avatar URL.
  virtual SpamCheckResult check_avatar_url_for_spam(
      const std::string& avatar_url,
      const std::string& user_id) {
    return SpamCheckResult::defer();
  }

  // ===================================================================
  // Content filtering hooks
  // ===================================================================

  // Filter/modify event content before it is stored.
  // Return the (possibly modified) content.
  virtual json filter_event_content(const json& content) {
    return content;
  }

  // Validate a URL found in event content.
  virtual bool is_url_allowed(const std::string& url) {
    return true;
  }
};

// ============================================================================
// DefaultSpamChecker — built-in spam checker with all features
// ============================================================================
class DefaultSpamChecker : public SpamCheckerInterface {
public:
  DefaultSpamChecker() = default;

  const char* checker_name() const override { return "default"; }
  const char* checker_version() const override { return "1.0.0"; }

  void on_load(const json& config) override {
    load_config(config);
  }

  void on_unload() override {
    // Clean up periodic cleanup thread
    stop_cleanup_thread();
  }

  // ===================================================================
  // Core spam checks
  // ===================================================================

  SpamCheckResult check_event_for_spam(
      const json& event,
      const std::string& sender,
      const std::string& room_id) override {

    // 1. Check event type
    std::string event_type = event.value("type", "");
    if (!event_type.empty() && blocked_event_types_.count(event_type)) {
      return SpamCheckResult::block(
        "Event type '" + event_type + "' is blocked",
        checker_name()
      );
    }

    // 2. Check content for URLs
    json content = event.value("content", json::object());
    std::string text = extract_event_text(content);

    if (!text.empty()) {
      // Check URL blocklist
      auto url_result = url_blocklist_.check_text(text);
      if (url_result.is_blocked()) return url_result;

      // Check content patterns
      auto pat_result = content_patterns_.match(text);
      if (pat_result.matched) {
        return SpamCheckResult::block(
          "Content matches spam pattern '" + pat_result.pattern_name + "': " + pat_result.matched_text,
          checker_name()
        );
      }

      // Check for excessive mentions/spam signals
      if (check_spam_signals_ && has_spam_signals(text)) {
        return SpamCheckResult::flag(
          "Event content has spam-like signals",
          SpamSeverity::MEDIUM, checker_name()
        );
      }
    }

    // 3. Check sender for known spammer flags
    if (flagged_users_.count(sender)) {
      return SpamCheckResult::flag(
        "Sender " + sender + " is flagged for review",
        SpamSeverity::HIGH, checker_name()
      );
    }

    // 4. Check newly registered users (more sensitive checks)
    if (new_user_treatment_ && is_new_user(sender)) {
      // New users: check content more strictly
      if (!text.empty()) {
        auto new_user_result = new_user_patterns_.match(text);
        if (new_user_result.matched) {
          return SpamCheckResult::block(
            "New user content matches spam pattern '" + new_user_result.pattern_name + "'",
            checker_name()
          );
        }
      }

      // New users cannot post URLs
      if (!text.empty() && UrlBlocklist::extract_urls(text).size() > 0) {
        if (!new_users_can_post_urls_) {
          return SpamCheckResult::block(
            "New users are not allowed to post URLs",
            checker_name(), 403,
            "New accounts cannot post links. Please wait before sending messages with URLs."
          );
        }
      }
    }

    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_join_room(
      const std::string& user_id,
      const std::string& room_id,
      bool is_invited) override {

    // Check if user is banned from joining rooms
    if (join_banned_users_.count(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " is banned from joining rooms",
        checker_name()
      );
    }

    // Check per-user join rate
    if (!join_rate_limiter_.try_action(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " exceeded join rate limit",
        checker_name(), 429,
        "You are joining rooms too quickly. Please wait before joining more rooms."
      );
    }

    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_create_room(
      const std::string& user_id) override {

    // Check if user is banned from creating rooms
    if (create_banned_users_.count(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " is banned from creating rooms",
        checker_name()
      );
    }

    // Check room creation rate limits
    auto rate_result = room_creation_limiter_.check_room_creation(user_id);
    if (rate_result.is_blocked()) {
      rate_result.checker_name = checker_name();
      return rate_result;
    }

    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_create_room_alias(
      const std::string& user_id,
      const std::string& room_alias) override {

    // Check if user is banned from creating aliases
    if (alias_banned_users_.count(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " is banned from creating room aliases",
        checker_name()
      );
    }

    // Check alias format
    std::string lower_alias = to_lower(room_alias);
    auto alias_result = alias_patterns_.match(lower_alias);
    if (alias_result.matched) {
      return SpamCheckResult::block(
        "Room alias matches blocked pattern '" + alias_result.pattern_name + "'",
        checker_name()
      );
    }

    // Check alias length
    if (room_alias.size() < min_alias_length_ || room_alias.size() > max_alias_length_) {
      return SpamCheckResult::block(
        "Room alias length out of allowed range",
        checker_name(), 400,
        "Room alias must be between " + std::to_string(min_alias_length_) +
        " and " + std::to_string(max_alias_length_) + " characters"
      );
    }

    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_publish_room(
      const std::string& user_id,
      const std::string& room_id) override {

    // Check if user can publish rooms
    if (publish_banned_users_.count(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " is banned from publishing rooms",
        checker_name()
      );
    }

    // Check publish rate
    if (!publish_rate_limiter_.try_action(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " exceeded room publish rate limit",
        checker_name(), 429,
        "You are publishing rooms too quickly. Please wait."
      );
    }

    return SpamCheckResult::allow();
  }

  SpamCheckResult check_username_for_spam(
      const std::string& username,
      const std::string& user_id) override {

    return username_blacklist_.check_username(username);
  }

  SpamCheckResult check_media_file_for_spam(
      const std::string& mime_type,
      int64_t file_size_bytes,
      const std::string& upload_name,
      const std::string& user_id) override {

    // Check media type
    auto result = media_filter_.check_media(mime_type, file_size_bytes);
    if (result.is_blocked()) return result;

    // Check upload filename for suspicious patterns
    if (!upload_name.empty()) {
      std::string lower_name = to_lower(upload_name);
      auto name_result = filename_patterns_.match(lower_name);
      if (name_result.matched) {
        return SpamCheckResult::block(
          "Filename matches suspicious pattern '" + name_result.pattern_name + "'",
          checker_name()
        );
      }
    }

    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_invite(
      const std::string& inviter_id,
      const std::string& invitee_id,
      const std::string& room_id) override {

    // Check invite rate limits
    auto result = invite_rate_limiter_.check_invite(inviter_id, room_id);
    if (result.is_blocked()) {
      result.checker_name = checker_name();
      return result;
    }

    // Check if inviter is banned from inviting
    if (invite_banned_users_.count(inviter_id)) {
      return SpamCheckResult::block(
        "User " + inviter_id + " is banned from inviting users",
        checker_name()
      );
    }

    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_send_message(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& message_type) override {

    // Check if user is muted
    if (muted_users_.count(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " is muted",
        checker_name(), 403,
        "You are currently muted and cannot send messages."
      );
    }

    // Check message send rate
    if (!message_rate_limiter_.try_action(user_id)) {
      return SpamCheckResult::block(
        "User " + user_id + " exceeded message rate limit",
        checker_name(), 429,
        "You are sending messages too quickly. Please wait."
      );
    }

    return SpamCheckResult::allow();
  }

  SpamCheckResult check_displayname_for_spam(
      const std::string& displayname,
      const std::string& user_id) override {

    // Check length
    if (displayname.size() > max_displayname_length_) {
      return SpamCheckResult::block(
        "Display name too long (" + std::to_string(displayname.size()) + " chars)",
        checker_name(), 400,
        "Display name is too long"
      );
    }

    // Check against username blacklist patterns
    auto result = username_blacklist_.check_username(displayname);
    if (result.is_blocked()) return result;

    return SpamCheckResult::allow();
  }

  SpamCheckResult check_avatar_url_for_spam(
      const std::string& avatar_url,
      const std::string& user_id) override {

    if (!avatar_url.empty()) {
      // Check if URL is blocked
      auto result = url_blocklist_.check_url(avatar_url);
      if (result.is_blocked()) return result;
    }

    return SpamCheckResult::allow();
  }

  // ===================================================================
  // Content filtering
  // ===================================================================

  json filter_event_content(const json& content) override {
    return content_filter_.filter_content(content);
  }

  bool is_url_allowed(const std::string& url) override {
    auto result = url_blocklist_.check_url(url);
    return result.is_allowed();
  }

  // ===================================================================
  // Management methods
  // ===================================================================

  void flag_user(const std::string& user_id) {
    flagged_users_.insert(user_id);
  }

  void unflag_user(const std::string& user_id) {
    flagged_users_.erase(user_id);
  }

  void mute_user(const std::string& user_id) {
    muted_users_.insert(user_id);
  }

  void unmute_user(const std::string& user_id) {
    muted_users_.erase(user_id);
  }

  void ban_user_from_creating_rooms(const std::string& user_id) {
    create_banned_users_.insert(user_id);
  }

  void ban_user_from_joining(const std::string& user_id) {
    join_banned_users_.insert(user_id);
  }

  void ban_user_from_inviting(const std::string& user_id) {
    invite_banned_users_.insert(user_id);
  }

  void block_event_type(const std::string& event_type) {
    blocked_event_types_.insert(event_type);
  }

  void add_content_pattern(const std::string& name, const std::string& pattern,
                           SpamSeverity severity = SpamSeverity::HIGH) {
    content_patterns_.add_pattern(name, pattern, severity);
  }

  void add_new_user_pattern(const std::string& name, const std::string& pattern,
                             SpamSeverity severity = SpamSeverity::HIGH) {
    new_user_patterns_.add_pattern(name, pattern, severity);
  }

  void add_alias_pattern(const std::string& name, const std::string& pattern,
                          SpamSeverity severity = SpamSeverity::HIGH) {
    alias_patterns_.add_pattern(name, pattern, severity);
  }

  void add_filename_pattern(const std::string& name, const std::string& pattern,
                             SpamSeverity severity = SpamSeverity::HIGH) {
    filename_patterns_.add_pattern(name, pattern, severity);
  }

  // Configure limits
  void set_new_user_period_seconds(int64_t seconds) {
    new_user_period_seconds_ = seconds;
  }

  void set_new_users_can_post_urls(bool allowed) {
    new_users_can_post_urls_ = allowed;
  }

  void enable_new_user_treatment(bool enabled) {
    new_user_treatment_ = enabled;
  }

  void enable_spam_signal_detection(bool enabled) {
    check_spam_signals_ = enabled;
  }

  void set_max_displayname_length(size_t len) {
    max_displayname_length_ = len;
  }

  void set_min_alias_length(size_t len) { min_alias_length_ = len; }
  void set_max_alias_length(size_t len) { max_alias_length_ = len; }

  // Access sub-modules for configuration
  UrlBlocklist& url_blocklist() { return url_blocklist_; }
  UsernameBlacklist& username_blacklist() { return username_blacklist_; }
  ContentFilter& content_filter() { return content_filter_; }
  MediaTypeFilter& media_filter() { return media_filter_; }
  RoomCreationLimiter& room_creation_limiter() { return room_creation_limiter_; }
  InviteRateLimiter& invite_rate_limiter() { return invite_rate_limiter_; }

  // Periodic cleanup (should be called from a background thread)
  void periodic_cleanup() {
    room_creation_limiter_.cleanup();
    invite_rate_limiter_.cleanup();
    join_rate_limiter_.cleanup();
    publish_rate_limiter_.cleanup();
    message_rate_limiter_.cleanup();
  }

  // Start/Restart cleanup thread
  void start_cleanup_thread(chr::seconds interval = chr::seconds(300)) {
    stop_cleanup_thread();
    cleanup_running_ = true;
    cleanup_thread_ = std::thread([this, interval]() {
      while (cleanup_running_) {
        std::this_thread::sleep_for(interval);
        if (cleanup_running_) {
          periodic_cleanup();
        }
      }
    });
  }

  // Load configuration from JSON
  void load_config(const json& config) {
    if (config.contains("url_blocklist") && config["url_blocklist"].is_object()) {
      auto& ub = config["url_blocklist"];
      if (ub.contains("url_patterns") && ub["url_patterns"].is_array()) {
        for (const auto& p : ub["url_patterns"]) {
          url_blocklist_.add_url_pattern(p.value("name", ""), p.value("pattern", ""));
        }
      }
      if (ub.contains("domain_patterns") && ub["domain_patterns"].is_array()) {
        for (const auto& p : ub["domain_patterns"]) {
          url_blocklist_.add_domain_pattern(p.value("name", ""), p.value("pattern", ""));
        }
      }
      if (ub.contains("blocked_tlds") && ub["blocked_tlds"].is_array()) {
        for (const auto& t : ub["blocked_tlds"]) {
          url_blocklist_.add_blocked_tld(t.get<std::string>());
        }
      }
    }

    if (config.contains("username_blacklist") && config["username_blacklist"].is_object()) {
      auto& ub = config["username_blacklist"];
      if (ub.contains("reserved_usernames") && ub["reserved_usernames"].is_array()) {
        for (const auto& u : ub["reserved_usernames"]) {
          username_blacklist_.add_reserved_username(u.get<std::string>());
        }
      }
      if (ub.contains("admin_patterns") && ub["admin_patterns"].is_array()) {
        for (const auto& p : ub["admin_patterns"]) {
          username_blacklist_.add_admin_pattern(p.get<std::string>());
        }
      }
      if (ub.contains("offensive_patterns") && ub["offensive_patterns"].is_array()) {
        for (const auto& p : ub["offensive_patterns"]) {
          username_blacklist_.add_offensive_pattern(
            p.value("name", ""), p.value("pattern", ""));
        }
      }
      if (ub.contains("min_length")) username_blacklist_.set_min_length(ub["min_length"]);
      if (ub.contains("max_length")) username_blacklist_.set_max_length(ub["max_length"]);
      if (ub.contains("max_digits")) username_blacklist_.set_max_digits(ub["max_digits"]);
    }

    if (config.contains("rate_limits") && config["rate_limits"].is_object()) {
      auto& rl = config["rate_limits"];
      if (rl.contains("room_creation_per_hour"))
        room_creation_limiter_.set_hourly_limit(rl["room_creation_per_hour"]);
      if (rl.contains("room_creation_burst"))
        room_creation_limiter_.set_burst_limit(rl["room_creation_burst"]);
      if (rl.contains("invites_per_user_per_hour"))
        invite_rate_limiter_.set_per_user_hourly_limit(rl["invites_per_user_per_hour"]);
      if (rl.contains("invites_per_room_per_hour"))
        invite_rate_limiter_.set_per_room_hourly_limit(rl["invites_per_room_per_hour"]);
      if (rl.contains("invite_burst"))
        invite_rate_limiter_.set_burst_limit(rl["invite_burst"]);
    }

    if (config.contains("new_user_treatment") && config["new_user_treatment"].is_object()) {
      auto& nut = config["new_user_treatment"];
      new_user_treatment_ = nut.value("enabled", false);
      new_users_can_post_urls_ = nut.value("can_post_urls", false);
      new_user_period_seconds_ = nut.value("period_seconds", 86400);
    }

    if (config.contains("content_filtering") && config["content_filtering"].is_object()) {
      auto& cf = config["content_filtering"];
      if (cf.contains("max_body_length"))
        content_filter_.set_max_body_length(cf["max_body_length"]);
      if (cf.contains("max_url_length"))
        content_filter_.set_max_url_length(cf["max_url_length"]);
      if (cf.contains("strip_null_bytes"))
        content_filter_.set_strip_null_bytes(cf["strip_null_bytes"]);
    }

    if (config.contains("media") && config["media"].is_object()) {
      auto& med = config["media"];
      if (med.contains("max_file_size"))
        media_filter_.set_max_file_size(med["max_file_size"]);
      if (med.contains("max_archive_size"))
        media_filter_.set_max_archive_size(med["max_archive_size"]);
      if (med.contains("blocked_mime_types") && med["blocked_mime_types"].is_array()) {
        for (const auto& m : med["blocked_mime_types"]) {
          media_filter_.block_mime_type(m.get<std::string>());
        }
      }
    }
  }

  // Statistics
  struct Stats {
    size_t flagged_users;
    size_t muted_users;
    size_t create_banned;
    size_t join_banned;
    size_t url_patterns;
    size_t domain_patterns;
    size_t blocked_tlds;
    size_t reserved_usernames;
    size_t content_patterns;
  };

  Stats get_stats() const {
    return {
      flagged_users_.size(),
      muted_users_.size(),
      create_banned_users_.size(),
      join_banned_users_.size(),
      url_blocklist_.url_pattern_count(),
      url_blocklist_.domain_pattern_count(),
      url_blocklist_.tld_count(),
      username_blacklist_.pattern_count_placeholder(),
      content_patterns_.pattern_count()
    };
  }

private:
  void stop_cleanup_thread() {
    cleanup_running_ = false;
    if (cleanup_thread_.joinable()) {
      cleanup_thread_.join();
    }
  }

  std::string extract_event_text(const json& content) const {
    std::ostringstream oss;
    if (content.contains("body") && content["body"].is_string()) {
      oss << content["body"].get<std::string>() << " ";
    }
    if (content.contains("formatted_body") && content["formatted_body"].is_string()) {
      oss << content["formatted_body"].get<std::string>() << " ";
    }
    return oss.str();
  }

  bool is_new_user(const std::string& user_id) const {
    auto it = user_creation_times_.find(user_id);
    if (it == user_creation_times_.end()) return false;
    auto age = chr::steady_clock::now() - it->second;
    return age < chr::seconds(new_user_period_seconds_);
  }

  bool has_spam_signals(const std::string& text) const {
    // Check for common spam signals
    // 1. Excessive caps
    int upper_count = 0;
    int alpha_count = 0;
    for (char c : text) {
      if (std::isalpha(static_cast<unsigned char>(c))) {
        ++alpha_count;
        if (std::isupper(static_cast<unsigned char>(c))) ++upper_count;
      }
    }
    if (alpha_count > 20 && (upper_count * 100 / alpha_count) > 70) {
      return true;  // > 70% caps
    }

    // 2. Excessive punctuation
    int punct_count = 0;
    for (char c : text) {
      if (c == '!' || c == '?' || c == '.') ++punct_count;
    }
    if (text.size() > 0 && punct_count > 5 && (punct_count * 100 / text.size()) > 10) {
      return true;  // > 10% punctuation
    }

    // 3. Excessive emoji (check for common emoji codepoints)
    int emoji_count = 0;
    for (size_t i = 0; i < text.size(); ) {
      unsigned char c = static_cast<unsigned char>(text[i]);
      if (c >= 0xF0) {
        ++emoji_count;
        i += 4;
      } else if (c >= 0xE0) {
        i += 3;
      } else if (c >= 0xC0) {
        i += 2;
      } else {
        ++i;
      }
    }
    if (text.size() > 20 && emoji_count > 10) {
      return true;
    }

    // 4. Repeated characters (>5 same char in a row)
    for (size_t i = 5; i < text.size(); ++i) {
      if (text[i] == text[i-1] && text[i] == text[i-2] &&
          text[i] == text[i-3] && text[i] == text[i-4]) {
        return true;
      }
    }

    return false;
  }

  // Sub-modules
  UrlBlocklist url_blocklist_;
  UsernameBlacklist username_blacklist_;
  MediaTypeFilter media_filter_;
  ContentFilter content_filter_;
  RoomCreationLimiter room_creation_limiter_;
  InviteRateLimiter invite_rate_limiter_;

  // Rate limiters
  RateLimiter join_rate_limiter_{20, chr::seconds(3600)};    // 20 joins/hour
  RateLimiter publish_rate_limiter_{5, chr::seconds(3600)};  // 5 publishes/hour
  RateLimiter message_rate_limiter_{30, chr::seconds(60)};   // 30 messages/min

  // Content patterns
  PatternMatcher content_patterns_;
  PatternMatcher new_user_patterns_;
  PatternMatcher alias_patterns_;
  PatternMatcher filename_patterns_;

  // User sets
  std::unordered_set<std::string> flagged_users_;
  std::unordered_set<std::string> muted_users_;
  std::unordered_set<std::string> create_banned_users_;
  std::unordered_set<std::string> join_banned_users_;
  std::unordered_set<std::string> invite_banned_users_;
  std::unordered_set<std::string> alias_banned_users_;
  std::unordered_set<std::string> publish_banned_users_;
  std::unordered_set<std::string> blocked_event_types_;

  // New user tracking
  bool new_user_treatment_{true};
  bool new_users_can_post_urls_{false};
  int64_t new_user_period_seconds_{86400};  // 24 hours
  bool check_spam_signals_{true};
  std::unordered_map<std::string, chr::steady_clock::time_point> user_creation_times_;

  // Limits
  size_t max_displayname_length_{100};
  size_t min_alias_length_{3};
  size_t max_alias_length_{255};

  // Cleanup thread
  std::thread cleanup_thread_;
  std::atomic<bool> cleanup_running_{false};
};

// ============================================================================
// SpamCheckerModule — wrapper for external .so plugins
// ============================================================================
class SpamCheckerModule {
public:
  using CreateFn = SpamCheckerInterface* (*)();
  using DestroyFn = void (*)(SpamCheckerInterface*);
  using GetInfoFn = const char* (*)();

  SpamCheckerModule() = default;

  ~SpamCheckerModule() {
    unload();
  }

  // Load an external spam checker module
  bool load(const std::string& path, const json& config) {
    unload();  // Ensure previous module is unloaded

    // Open the shared library
    handle_ = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle_) {
      last_error_ = std::string("dlopen failed: ") + dlerror();
      std::cerr << "[SpamCheckerModule] Failed to load " << path
                << ": " << last_error_ << std::endl;
      return false;
    }

    // Clear any existing errors
    dlerror();

    // Resolve the create function
    create_fn_ = reinterpret_cast<CreateFn>(dlsym(handle_, "create_spam_checker"));
    const char* dlsym_error = dlerror();
    if (dlsym_error) {
      last_error_ = std::string("dlsym create_spam_checker failed: ") + dlsym_error;
      dlclose(handle_);
      handle_ = nullptr;
      return false;
    }

    // Resolve the destroy function
    destroy_fn_ = reinterpret_cast<DestroyFn>(dlsym(handle_, "destroy_spam_checker"));
    dlsym_error = dlerror();
    if (dlsym_error) {
      // Destroy function is optional; if missing, we just warn
      std::cerr << "[SpamCheckerModule] Warning: no destroy_spam_checker in "
                << path << ": " << dlsym_error << std::endl;
      destroy_fn_ = nullptr;
    }

    // Resolve the info function (optional)
    info_fn_ = reinterpret_cast<GetInfoFn>(dlsym(handle_, "spam_checker_info"));
    dlsym_error = dlerror();
    if (dlsym_error) {
      info_fn_ = nullptr;  // Optional
    }

    // Create the checker instance
    instance_ = create_fn_();
    if (!instance_) {
      last_error_ = "create_spam_checker returned null";
      dlclose(handle_);
      handle_ = nullptr;
      return false;
    }

    // Initialize with config
    instance_->on_load(config);

    path_ = path;
    loaded_ = true;
    std::cout << "[SpamCheckerModule] Loaded module: " << instance_->checker_name()
              << " v" << instance_->checker_version() << " from " << path << std::endl;
    return true;
  }

  // Unload the module
  void unload() {
    if (instance_ && destroy_fn_) {
      instance_->on_unload();
      destroy_fn_(instance_);
    } else if (instance_) {
      instance_->on_unload();
      // No destroy function; leak is on the module author
    }
    instance_ = nullptr;
    create_fn_ = nullptr;
    destroy_fn_ = nullptr;
    info_fn_ = nullptr;

    if (handle_) {
      dlclose(handle_);
      handle_ = nullptr;
    }

    path_.clear();
    loaded_ = false;
  }

  // Get the underlying checker interface
  SpamCheckerInterface* checker() const { return instance_; }

  // Check if module is loaded
  bool is_loaded() const { return loaded_; }

  // Get the module path
  const std::string& path() const { return path_; }

  // Get the last error
  const std::string& last_error() const { return last_error_; }

  // Module info
  const char* info() const {
    if (info_fn_) return info_fn_();
    return nullptr;
  }

  // Check if the module exports a given symbol
  bool has_symbol(const std::string& name) const {
    if (!handle_) return false;
    dlerror();
    void* sym = dlsym(handle_, name.c_str());
    return dlerror() == nullptr && sym != nullptr;
  }

private:
  void* handle_{nullptr};
  CreateFn create_fn_{nullptr};
  DestroyFn destroy_fn_{nullptr};
  GetInfoFn info_fn_{nullptr};
  SpamCheckerInterface* instance_{nullptr};
  std::string path_;
  std::string last_error_;
  bool loaded_{false};
};

// ============================================================================
// ModuleLoader — manages loading/unloading of multiple .so plugins
// ============================================================================
class ModuleLoader {
public:
  ModuleLoader() = default;

  ~ModuleLoader() {
    unload_all();
  }

  // Load a module from a .so file
  bool load_module(const std::string& name, const std::string& path,
                   const json& config = json::object()) {
    if (modules_.count(name)) {
      std::cerr << "[ModuleLoader] Module '" << name << "' already loaded" << std::endl;
      return false;
    }

    auto module = std::make_unique<SpamCheckerModule>();
    if (!module->load(path, config)) {
      std::cerr << "[ModuleLoader] Failed to load module '" << name
                << "': " << module->last_error() << std::endl;
      return false;
    }

    modules_[name] = std::move(module);
    module_order_.push_back(name);
    return true;
  }

  // Load all .so files from a directory
  size_t load_directory(const std::string& dir_path, const json& config = json::object()) {
    size_t loaded = 0;
    try {
      for (const auto& entry : fs::directory_iterator(dir_path)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext == ".so" || ext == ".dylib") {
          std::string name = entry.path().stem().string();
          if (starts_with(name, "lib")) {
            name = name.substr(3);  // Strip "lib" prefix
          }
          if (load_module(name, entry.path().string(), config)) {
            ++loaded;
          }
        }
      }
    } catch (const fs::filesystem_error& e) {
      std::cerr << "[ModuleLoader] Error scanning directory " << dir_path
                << ": " << e.what() << std::endl;
    }
    std::cout << "[ModuleLoader] Loaded " << loaded << " modules from " << dir_path << std::endl;
    return loaded;
  }

  // Unload a specific module
  bool unload_module(const std::string& name) {
    auto it = modules_.find(name);
    if (it == modules_.end()) return false;

    it->second->unload();
    modules_.erase(it);

    auto order_it = std::find(module_order_.begin(), module_order_.end(), name);
    if (order_it != module_order_.end()) {
      module_order_.erase(order_it);
    }
    return true;
  }

  // Unload all modules
  void unload_all() {
    for (auto& [name, module] : modules_) {
      module->unload();
    }
    modules_.clear();
    module_order_.clear();
  }

  // Reload a module
  bool reload_module(const std::string& name, const json& config = json::object()) {
    auto it = modules_.find(name);
    if (it == modules_.end()) return false;

    std::string path = it->second->path();
    unload_module(name);
    return load_module(name, path, config);
  }

  // Get a module by name
  SpamCheckerInterface* get_checker(const std::string& name) const {
    auto it = modules_.find(name);
    if (it != modules_.end()) {
      return it->second->checker();
    }
    return nullptr;
  }

  // Get all loaded checker interfaces
  std::vector<SpamCheckerInterface*> get_all_checkers() const {
    std::vector<SpamCheckerInterface*> result;
    for (const auto& name : module_order_) {
      auto it = modules_.find(name);
      if (it != modules_.end()) {
        result.push_back(it->second->checker());
      }
    }
    return result;
  }

  // Get all module names
  std::vector<std::string> module_names() const {
    return module_order_;
  }

  // Get module count
  size_t module_count() const { return modules_.size(); }

  // Check if a module is loaded
  bool has_module(const std::string& name) const {
    return modules_.count(name) > 0;
  }

private:
  std::unordered_map<std::string, std::unique_ptr<SpamCheckerModule>> modules_;
  std::vector<std::string> module_order_;
};

// ============================================================================
// AntispamHookChain — chain of spam checkers, first match wins
// ============================================================================
class AntispamHookChain {
public:
  AntispamHookChain() = default;

  // Add a checker to the chain
  void add_checker(SpamCheckerInterface* checker) {
    if (checker) {
      checkers_.push_back(checker);
    }
  }

  // Remove a checker by name
  void remove_checker(const std::string& name) {
    checkers_.erase(
      std::remove_if(checkers_.begin(), checkers_.end(),
                     [&name](SpamCheckerInterface* c) {
                       return c && c->checker_name() == name;
                     }),
      checkers_.end()
    );
  }

  // Clear all checkers
  void clear() {
    checkers_.clear();
  }

  // Get number of checkers in chain
  size_t size() const { return checkers_.size(); }

  // ===================================================================
  // Chain execution methods — first non-deferred result wins
  // ===================================================================

  SpamCheckResult check_event_for_spam(const json& event,
                                        const std::string& sender,
                                        const std::string& room_id) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->check_event_for_spam(event, sender, room_id);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_join_room(const std::string& user_id,
                                      const std::string& room_id,
                                      bool is_invited) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->user_may_join_room(user_id, room_id, is_invited);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_create_room(const std::string& user_id) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->user_may_create_room(user_id);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_create_room_alias(const std::string& user_id,
                                              const std::string& room_alias) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->user_may_create_room_alias(user_id, room_alias);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_publish_room(const std::string& user_id,
                                         const std::string& room_id) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->user_may_publish_room(user_id, room_id);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult check_username_for_spam(const std::string& username,
                                           const std::string& user_id) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->check_username_for_spam(username, user_id);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult check_media_file_for_spam(const std::string& mime_type,
                                             int64_t file_size,
                                             const std::string& upload_name,
                                             const std::string& user_id) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->check_media_file_for_spam(mime_type, file_size,
                                                        upload_name, user_id);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_invite(const std::string& inviter_id,
                                   const std::string& invitee_id,
                                   const std::string& room_id) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->user_may_invite(inviter_id, invitee_id, room_id);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult user_may_send_message(const std::string& user_id,
                                         const std::string& room_id,
                                         const std::string& message_type) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->user_may_send_message(user_id, room_id, message_type);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult check_displayname_for_spam(const std::string& displayname,
                                              const std::string& user_id) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->check_displayname_for_spam(displayname, user_id);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  SpamCheckResult check_avatar_url_for_spam(const std::string& avatar_url,
                                             const std::string& user_id) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      auto result = checker->check_avatar_url_for_spam(avatar_url, user_id);
      if (!result.is_deferred()) {
        result.checker_name = checker->checker_name();
        return result;
      }
    }
    return SpamCheckResult::allow();
  }

  // ===================================================================
  // Content filtering chain
  // ===================================================================

  json filter_event_content(const json& content) {
    json result = content;
    for (auto* checker : checkers_) {
      if (!checker) continue;
      result = checker->filter_event_content(result);
    }
    return result;
  }

  bool is_url_allowed(const std::string& url) {
    for (auto* checker : checkers_) {
      if (!checker) continue;
      if (!checker->is_url_allowed(url)) return false;
    }
    return true;
  }

private:
  std::vector<SpamCheckerInterface*> checkers_;
};

// ============================================================================
// SpamCheckerRegistry — central registry and configuration
// ============================================================================
class SpamCheckerRegistry {
public:
  SpamCheckerRegistry() {
    // Always add the default checker
    default_checker_ = std::make_unique<DefaultSpamChecker>();
    hook_chain_.add_checker(default_checker_.get());
  }

  // Configure from JSON
  void configure(const json& config) {
    std::lock_guard<std::mutex> lock(mtx_);

    if (config.contains("enabled") && !config["enabled"].get<bool>()) {
      enabled_ = false;
      return;
    }
    enabled_ = true;

    // Configure default checker
    if (config.contains("default") && config["default"].is_object()) {
      default_checker_->load_config(config["default"]);
    }

    // Load external modules
    if (config.contains("modules") && config["modules"].is_object()) {
      auto& mod_cfg = config["modules"];

      // Load individual modules
      if (mod_cfg.contains("load") && mod_cfg["load"].is_array()) {
        for (const auto& mod : mod_cfg["load"]) {
          std::string name = mod.value("name", "");
          std::string path = mod.value("path", "");
          json mod_config = mod.value("config", json::object());
          if (!name.empty() && !path.empty()) {
            if (module_loader_.load_module(name, path, mod_config)) {
              auto* checker = module_loader_.get_checker(name);
              if (checker) {
                hook_chain_.add_checker(checker);
              }
            }
          }
        }
      }

      // Load all modules from a directory
      if (mod_cfg.contains("directory") && mod_cfg["directory"].is_string()) {
        std::string dir = mod_cfg["directory"].get<std::string>();
        json dir_config = mod_cfg.value("default_config", json::object());
        size_t loaded = module_loader_.load_directory(dir, dir_config);
        for (auto* checker : module_loader_.get_all_checkers()) {
          if (checker) {
            hook_chain_.add_checker(checker);
          }
        }
        std::cout << "[SpamCheckerRegistry] Loaded " << loaded
                  << " modules from " << dir << std::endl;
      }

      // Set module search order
      if (mod_cfg.contains("order") && mod_cfg["order"].is_array()) {
        // Modules are added in order already; just log
        std::cout << "[SpamCheckerRegistry] Module execution order: ";
        for (size_t i = 0; i < mod_cfg["order"].size(); ++i) {
          if (i > 0) std::cout << " -> ";
          std::cout << mod_cfg["order"][i].get<std::string>();
        }
        std::cout << std::endl;
      }
    }

    // Start the cleanup thread
    default_checker_->start_cleanup_thread(chr::seconds(300));
  }

  // Convenience: configure from YAML
  void configure_from_yaml(const std::string& yaml_path) {
    try {
      YAML::Node yaml = YAML::LoadFile(yaml_path);
      if (yaml["spam_checker"]) {
        json j = yaml_to_json(yaml["spam_checker"]);
        configure(j);
      }
    } catch (const std::exception& e) {
      std::cerr << "[SpamCheckerRegistry] Failed to load config from "
                << yaml_path << ": " << e.what() << std::endl;
    }
  }

  // ===================================================================
  // Check methods (delegates to hook chain)
  // ===================================================================

  SpamCheckResult check_event_for_spam(const json& event,
                                        const std::string& sender,
                                        const std::string& room_id) {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.check_event_for_spam(event, sender, room_id);
  }

  SpamCheckResult user_may_join_room(const std::string& user_id,
                                      const std::string& room_id,
                                      bool is_invited = false) {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.user_may_join_room(user_id, room_id, is_invited);
  }

  SpamCheckResult user_may_create_room(const std::string& user_id) {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.user_may_create_room(user_id);
  }

  SpamCheckResult user_may_create_room_alias(const std::string& user_id,
                                              const std::string& room_alias) {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.user_may_create_room_alias(user_id, room_alias);
  }

  SpamCheckResult user_may_publish_room(const std::string& user_id,
                                         const std::string& room_id) {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.user_may_publish_room(user_id, room_id);
  }

  SpamCheckResult check_username_for_spam(const std::string& username,
                                           const std::string& user_id = "") {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.check_username_for_spam(username, user_id);
  }

  SpamCheckResult check_media_file_for_spam(const std::string& mime_type,
                                             int64_t file_size,
                                             const std::string& upload_name = "",
                                             const std::string& user_id = "") {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.check_media_file_for_spam(mime_type, file_size,
                                                  upload_name, user_id);
  }

  SpamCheckResult user_may_invite(const std::string& inviter_id,
                                   const std::string& invitee_id,
                                   const std::string& room_id) {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.user_may_invite(inviter_id, invitee_id, room_id);
  }

  SpamCheckResult user_may_send_message(const std::string& user_id,
                                         const std::string& room_id,
                                         const std::string& message_type = "m.room.message") {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.user_may_send_message(user_id, room_id, message_type);
  }

  SpamCheckResult check_displayname_for_spam(const std::string& displayname,
                                              const std::string& user_id = "") {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.check_displayname_for_spam(displayname, user_id);
  }

  SpamCheckResult check_avatar_url_for_spam(const std::string& avatar_url,
                                             const std::string& user_id = "") {
    if (!enabled_) return SpamCheckResult::allow();
    return hook_chain_.check_avatar_url_for_spam(avatar_url, user_id);
  }

  // ===================================================================
  // Content filtering
  // ===================================================================

  json filter_event_content(const json& content) {
    if (!enabled_) return content;
    return hook_chain_.filter_event_content(content);
  }

  // ===================================================================
  // Management
  // ===================================================================

  DefaultSpamChecker& default_checker() { return *default_checker_; }
  ModuleLoader& module_loader() { return module_loader_; }
  AntispamHookChain& hook_chain() { return hook_chain_; }

  void set_enabled(bool enabled) { enabled_ = enabled; }
  bool is_enabled() const { return enabled_; }

  // Reload configuration
  void reload(const json& config) {
    std::lock_guard<std::mutex> lock(mtx_);
    module_loader_.unload_all();
    hook_chain_.clear();
    hook_chain_.add_checker(default_checker_.get());
    configure(config);
  }

  // Shutdown
  void shutdown() {
    std::lock_guard<std::mutex> lock(mtx_);
    module_loader_.unload_all();
    hook_chain_.clear();
    default_checker_->on_unload();
    enabled_ = false;
  }

private:
  // Convert a YAML node to JSON
  static json yaml_to_json(const YAML::Node& node) {
    if (node.IsNull()) return nullptr;
    if (node.IsScalar()) {
      try { return node.as<int64_t>(); } catch (...) {}
      try { return node.as<double>(); } catch (...) {}
      try { return node.as<bool>(); } catch (...) {}
      return node.as<std::string>();
    }
    if (node.IsSequence()) {
      json arr = json::array();
      for (const auto& item : node) {
        arr.push_back(yaml_to_json(item));
      }
      return arr;
    }
    if (node.IsMap()) {
      json obj = json::object();
      for (const auto& kv : node) {
        obj[kv.first.as<std::string>()] = yaml_to_json(kv.second);
      }
      return obj;
    }
    return nullptr;
  }

  bool enabled_{true};
  std::unique_ptr<DefaultSpamChecker> default_checker_;
  ModuleLoader module_loader_;
  AntispamHookChain hook_chain_;
  std::mutex mtx_;
};

// ============================================================================
// SpamCheckLogger — logs all spam check decisions for auditing
// ============================================================================
class SpamCheckLogger {
public:
  struct LogEntry {
    chr::system_clock::time_point timestamp;
    std::string action;
    std::string user_id;
    std::string room_id;
    std::string checker_name;
    SpamDecision decision;
    std::string reason;
  };

  SpamCheckLogger() = default;

  void log(const std::string& action, const std::string& user_id,
           const std::string& room_id, const SpamCheckResult& result) {
    LogEntry entry{
      chr::system_clock::now(),
      action,
      user_id,
      room_id,
      result.checker_name,
      result.decision,
      result.reason
    };

    std::lock_guard<std::mutex> lock(mtx_);

    // Only log non-ALLOW results to save memory
    if (result.decision != SpamDecision::ALLOW) {
      entries_.push_back(std::move(entry));
      if (entries_.size() > max_entries_) {
        entries_.pop_front();
      }
    }

    // Always increment counters
    stats_.total_checks++;
    switch (result.decision) {
      case SpamDecision::ALLOW:  stats_.allowed++; break;
      case SpamDecision::BLOCK:  stats_.blocked++; break;
      case SpamDecision::FLAG:   stats_.flagged++; break;
      case SpamDecision::MODIFY: stats_.modified++; break;
      default: break;
    }
  }

  // Get recent log entries
  std::vector<LogEntry> recent_entries(size_t count = 100) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<LogEntry> result;
    size_t start = entries_.size() > count ? entries_.size() - count : 0;
    for (size_t i = start; i < entries_.size(); ++i) {
      result.push_back(entries_[i]);
    }
    return result;
  }

  // Get all entries for a specific user
  std::vector<LogEntry> entries_for_user(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<LogEntry> result;
    for (const auto& e : entries_) {
      if (e.user_id == user_id) {
        result.push_back(e);
      }
    }
    return result;
  }

  // Get stats
  struct Stats {
    uint64_t total_checks{0};
    uint64_t allowed{0};
    uint64_t blocked{0};
    uint64_t flagged{0};
    uint64_t modified{0};
  };

  Stats get_stats() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return stats_;
  }

  // Clear logs
  void clear() {
    std::lock_guard<std::mutex> lock(mtx_);
    entries_.clear();
    stats_ = Stats{};
  }

  void set_max_entries(size_t max) { max_entries_ = max; }

private:
  std::deque<LogEntry> entries_;
  Stats stats_;
  size_t max_entries_{10000};
  mutable std::mutex mtx_;
};

// ============================================================================
// Global singleton accessor
// ============================================================================
namespace {

std::shared_ptr<SpamCheckerRegistry> g_spam_checker_registry;
std::mutex g_spam_checker_mutex;

std::shared_ptr<SpamCheckLogger> g_spam_check_logger;
std::mutex g_spam_check_logger_mutex;

} // anonymous namespace

std::shared_ptr<SpamCheckerRegistry> get_spam_checker_registry() {
  std::lock_guard<std::mutex> lock(g_spam_checker_mutex);
  if (!g_spam_checker_registry) {
    g_spam_checker_registry = std::make_shared<SpamCheckerRegistry>();
  }
  return g_spam_checker_registry;
}

void set_spam_checker_registry(std::shared_ptr<SpamCheckerRegistry> registry) {
  std::lock_guard<std::mutex> lock(g_spam_checker_mutex);
  g_spam_checker_registry = std::move(registry);
}

std::shared_ptr<SpamCheckLogger> get_spam_check_logger() {
  std::lock_guard<std::mutex> lock(g_spam_check_logger_mutex);
  if (!g_spam_check_logger) {
    g_spam_check_logger = std::make_shared<SpamCheckLogger>();
  }
  return g_spam_check_logger;
}

void set_spam_check_logger(std::shared_ptr<SpamCheckLogger> logger) {
  std::lock_guard<std::mutex> lock(g_spam_check_logger_mutex);
  g_spam_check_logger = std::move(logger);
}

// ============================================================================
// Convenience free functions for easier integration
// ============================================================================

// Quick spam check for event — returns pair of (allowed, error_message)
std::pair<bool, std::string> spam_check_event(const json& event,
                                               const std::string& sender,
                                               const std::string& room_id) {
  auto registry = get_spam_checker_registry();
  auto result = registry->check_event_for_spam(event, sender, room_id);
  auto logger = get_spam_check_logger();
  logger->log("check_event_for_spam", sender, room_id, result);
  return {result.is_allowed(), result.error_message};
}

// Quick spam check for room join
std::pair<bool, std::string> spam_check_join(const std::string& user_id,
                                              const std::string& room_id,
                                              bool is_invited = false) {
  auto registry = get_spam_checker_registry();
  auto result = registry->user_may_join_room(user_id, room_id, is_invited);
  auto logger = get_spam_check_logger();
  logger->log("user_may_join_room", user_id, room_id, result);
  return {result.is_allowed(), result.error_message};
}

// Quick spam check for room creation
std::pair<bool, std::string> spam_check_create_room(const std::string& user_id) {
  auto registry = get_spam_checker_registry();
  auto result = registry->user_may_create_room(user_id);
  auto logger = get_spam_check_logger();
  logger->log("user_may_create_room", user_id, "", result);
  return {result.is_allowed(), result.error_message};
}

// Quick spam check for username
std::pair<bool, std::string> spam_check_username(const std::string& username,
                                                   const std::string& user_id = "") {
  auto registry = get_spam_checker_registry();
  auto result = registry->check_username_for_spam(username, user_id);
  auto logger = get_spam_check_logger();
  logger->log("check_username_for_spam", user_id, "", result);
  return {result.is_allowed(), result.error_message};
}

// Quick spam check for media
std::pair<bool, std::string> spam_check_media(const std::string& mime_type,
                                               int64_t file_size,
                                               const std::string& upload_name = "",
                                               const std::string& user_id = "") {
  auto registry = get_spam_checker_registry();
  auto result = registry->check_media_file_for_spam(mime_type, file_size,
                                                      upload_name, user_id);
  auto logger = get_spam_check_logger();
  logger->log("check_media_file_for_spam", user_id, "", result);
  return {result.is_allowed(), result.error_message};
}

// ============================================================================
// Placeholder for UsernameBlacklist pattern count accessor
// ============================================================================
// NOTE: In practice this would expose internal stats; here we provide a stub
// that can be wired up if needed.

// ============================================================================
// Stats reporting convenience
// ============================================================================
json spam_checker_stats_to_json() {
  auto registry = get_spam_checker_registry();
  auto logger = get_spam_check_logger();

  auto def_stats = registry->default_checker().get_stats();
  auto log_stats = logger->get_stats();

  json j;
  j["enabled"] = registry->is_enabled();
  j["default_checker"] = {
    {"flagged_users", def_stats.flagged_users},
    {"muted_users", def_stats.muted_users},
    {"create_banned_users", def_stats.create_banned},
    {"join_banned_users", def_stats.join_banned},
    {"url_patterns", def_stats.url_patterns},
    {"domain_patterns", def_stats.domain_patterns},
    {"blocked_tlds", def_stats.blocked_tlds},
    {"reserved_usernames", def_stats.reserved_usernames},
    {"content_patterns", def_stats.content_patterns},
  };
  j["modules_loaded"] = registry->module_loader().module_count();
  j["hook_chain_length"] = registry->hook_chain().size();
  j["log_stats"] = {
    {"total_checks", log_stats.total_checks},
    {"allowed", log_stats.allowed},
    {"blocked", log_stats.blocked},
    {"flagged", log_stats.flagged},
    {"modified", log_stats.modified},
  };
  return j;
}

} // namespace progressive
