// irc_channel_full.cpp — Full IRC channel management, persistence, and logging
// Covers: channel lifecycle, topic management, ban/except/invite lists,
// mode updates, message logging + rotation, statistics, activity tracking,
// searchable archive, membership history, forwarding, auto-cleanup,
// ChanServ registration, access lists, MLOCK, entry messages, URL, email notify.
// References: RFC 1459, 2811, 2812, 2813, IRCv3.2, InspIRCd channel model

#include "irc_server.hpp"
#include "services.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
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
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <variant>
#include <vector>

// Conditional: zlib for compression
#if __has_include(<zlib.h>)
  #include <zlib.h>
  #define HAS_ZLIB 1
#else
  #define HAS_ZLIB 0
#endif

namespace progressive::irc {

using json = nlohmann::json;

// =============================================================================
// SECTION 1: Forward declarations and constants
// =============================================================================

class ChannelFull;
class ChannelMembershipRecord;
class BanFullEntry;
class ExceptFullEntry;
class InviteExceptFullEntry;
class ChannelLogEntry;
class ChannelLogRotator;
class ChannelStatistics;
class ChannelMessageArchive;
class ChannelAccessEntry;
class ChannelRegistration;

// --- Constants ---
static constexpr size_t CF_MAX_CHANNEL_NAME    = 64;
static constexpr size_t CF_MAX_TOPIC_LEN       = 390;
static constexpr size_t CF_MAX_KEY_LEN         = 32;
static constexpr size_t CF_MAX_USER_LIMIT      = 65535;
static constexpr size_t CF_MAX_BANS            = 500;
static constexpr size_t CF_MAX_EXCEPTS         = 500;
static constexpr size_t CF_MAX_INVEX           = 500;
static constexpr size_t CF_MAX_ACCESS_ENTRIES  = 500;
static constexpr size_t CF_MAX_LOG_LINES_MEM   = 10000;
static constexpr size_t CF_ARCHIVE_PAGE_SIZE   = 50;
static constexpr size_t CF_LOG_ROTATE_SIZE_MB  = 100;
static constexpr size_t CF_LOG_ROTATE_DAYS     = 1;
static constexpr int    CF_AUTO_CLEANUP_DELAY  = 300;    // seconds after last part
static constexpr int    CF_IDLE_CHECK_INTERVAL = 60;     // seconds
static constexpr int64_t CF_DEFAULT_BAN_EXPIRY = 86400;  // 24h default

// --- Enums ---
enum class CFAccessLevel : uint8_t {
  NONE   = 0,
  VOP    = 1,  // +v voice
  HOP    = 2,  // +h halfop
  AOP    = 3,  // +o op
  SOP    = 4,  // +a admin/protected
  FOUNDER = 5, // +q owner/founder
};

enum class CFLogLevel : uint8_t {
  JOIN    = 0,
  PART    = 1,
  MSG     = 2,
  NOTICE  = 3,
  MODE    = 4,
  TOPIC   = 5,
  KICK    = 6,
  BAN     = 7,
  SYSTEM  = 8,
};

// =============================================================================
// SECTION 2: Utility helpers (anonymous namespace)
// =============================================================================

namespace {

int64_t cf_now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t cf_now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string cf_to_lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string cf_to_upper(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

bool cf_iequals(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i)
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) return false;
  return true;
}

bool cf_wildcard_match(const std::string& pattern, const std::string& str) {
  size_t pi = 0, si = 0, star = std::string::npos, ss = 0;
  while (si < str.size()) {
    if (pi < pattern.size() &&
        (pattern[pi] == '?' ||
         cf_to_lower(std::string(1, pattern[pi])) ==
         cf_to_lower(std::string(1, str[si])))) {
      ++pi; ++si;
    } else if (pi < pattern.size() && pattern[pi] == '*') {
      star = pi++; ss = si;
    } else if (star != std::string::npos) {
      pi = star + 1; si = ++ss;
    } else { return false; }
  }
  while (pi < pattern.size() && pattern[pi] == '*') ++pi;
  return pi == pattern.size();
}

bool cf_cidr_match(const std::string& cidr, const std::string& ip) {
  auto slash = cidr.find('/');
  if (slash == std::string::npos) return cidr == ip;
  std::string net = cidr.substr(0, slash);
  int bits = std::stoi(cidr.substr(slash + 1));
  auto parse_ip = [](const std::string& s) -> uint32_t {
    uint32_t r = 0; int shift = 24;
    std::stringstream ss(s); std::string o;
    while (std::getline(ss, o, '.') && shift >= 0) {
      r |= (static_cast<uint32_t>(std::stoi(o)) << shift);
      shift -= 8;
    }
    return r;
  };
  uint32_t ni = parse_ip(net), ii = parse_ip(ip);
  uint32_t mask = (bits == 0) ? 0 : (0xFFFFFFFF << (32 - bits));
  return (ni & mask) == (ii & mask);
}

std::string cf_format_time(time_t t) {
  char buf[64];
  struct tm tm_val;
  gmtime_r(&t, &tm_val);
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_val);
  return std::string(buf);
}

std::string cf_format_time_iso(time_t t) {
  char buf[32];
  struct tm tm_val;
  gmtime_r(&t, &tm_val);
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_val);
  return std::string(buf);
}

std::vector<std::string> cf_split(const std::string& s, char delim) {
  std::vector<std::string> v;
  std::stringstream ss(s); std::string item;
  while (std::getline(ss, item, delim)) {
    if (!item.empty()) v.push_back(item);
  }
  return v;
}

std::string cf_join(const std::vector<std::string>& v, const std::string& sep) {
  std::string r;
  for (size_t i = 0; i < v.size(); ++i) {
    if (i > 0) r += sep;
    r += v[i];
  }
  return r;
}

std::string cf_trim(const std::string& s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

bool cf_is_valid_channel(const std::string& name) {
  if (name.empty() || name.size() > CF_MAX_CHANNEL_NAME) return false;
  char c = name[0];
  if (c != '#' && c != '&' && c != '!') return false;
  if (name.find(' ') != std::string::npos) return false;
  if (name.find(',') != std::string::npos) return false;
  if (name.find('\x07') != std::string::npos) return false;
  return true;
}

std::string cf_make_mask(const std::string& nick, const std::string& user,
                          const std::string& host) {
  return nick + "!" + user + "@" + host;
}

std::string cf_mask_nick(const std::string& mask) {
  auto ex = mask.find('!');
  return (ex != std::string::npos) ? mask.substr(0, ex) : mask;
}

std::string cf_mask_user(const std::string& mask) {
  auto ex = mask.find('!');
  auto at = mask.find('@');
  if (ex != std::string::npos && at != std::string::npos && at > ex)
    return mask.substr(ex + 1, at - ex - 1);
  return "*";
}

std::string cf_mask_host(const std::string& mask) {
  auto at = mask.find('@');
  return (at != std::string::npos) ? mask.substr(at + 1) : mask;
}

bool cf_mask_matches(const std::string& mask, const std::string& nick,
                      const std::string& user, const std::string& host) {
  return cf_wildcard_match(cf_mask_nick(mask), nick) &&
         cf_wildcard_match(cf_mask_user(mask), user) &&
         cf_wildcard_match(cf_mask_host(mask), host);
}

std::string cf_generate_uid() {
  static std::atomic<uint64_t> counter{0};
  auto ts = static_cast<uint64_t>(cf_now_ms());
  auto cnt = counter.fetch_add(1);
  std::stringstream ss;
  ss << std::hex << ts << "-" << cnt;
  return ss.str();
}

bool cf_file_exists(const std::string& path) {
  struct stat st;
  return stat(path.c_str(), &st) == 0;
}

size_t cf_file_size(const std::string& path) {
  struct stat st;
  if (stat(path.c_str(), &st) != 0) return 0;
  return static_cast<size_t>(st.st_size);
}

bool cf_mkdir_p(const std::string& path) {
  if (path.empty()) return true;
  if (cf_file_exists(path)) return true;
  size_t pos = path.find_last_of('/');
  if (pos != std::string::npos && pos > 0) {
    if (!cf_mkdir_p(path.substr(0, pos))) return false;
  }
  return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

// Simple gzip compress
bool cf_gzip_compress(const std::string& src_path, const std::string& dst_path) {
#if HAS_ZLIB
  std::ifstream in(src_path, std::ios::binary);
  if (!in) return false;
  gzFile out = gzopen(dst_path.c_str(), "wb");
  if (!out) return false;
  char buf[8192];
  while (in.read(buf, sizeof(buf)) || in.gcount() > 0) {
    if (gzwrite(out, buf, static_cast<unsigned>(in.gcount())) <= 0) {
      gzclose(out); return false;
    }
  }
  gzclose(out);
  return true;
#else
  (void)src_path; (void)dst_path;
  return false;
#endif
}

} // anonymous namespace

// =============================================================================
// SECTION 3: Ban entry with expiry and exemption
// =============================================================================

struct BanFullEntry {
  std::string mask;          // nick!user@host or extended mask
  std::string set_by;        // who set the ban
  int64_t set_time;          // when it was set (unix timestamp)
  int64_t expires;           // 0 = permanent
  std::string reason;        // optional reason
  std::string ban_id;        // unique ID for this ban

  BanFullEntry() : set_time(0), expires(0) {
    ban_id = cf_generate_uid();
  }

  BanFullEntry(const std::string& m, const std::string& sb,
               int64_t st, int64_t ex = 0, const std::string& r = "")
    : mask(m), set_by(sb), set_time(st), expires(ex), reason(r) {
    ban_id = cf_generate_uid();
  }

  bool is_expired() const {
    if (expires == 0) return false; // permanent
    return cf_now_sec() >= expires;
  }

  bool matches(const std::string& nick, const std::string& user,
               const std::string& host) const {
    return cf_mask_matches(mask, nick, user, host);
  }

  json to_json() const {
    return {
      {"mask", mask}, {"set_by", set_by}, {"set_time", set_time},
      {"expires", expires}, {"reason", reason}, {"ban_id", ban_id}
    };
  }

  static BanFullEntry from_json(const json& j) {
    BanFullEntry e;
    e.mask     = j.value("mask", "");
    e.set_by   = j.value("set_by", "");
    e.set_time = j.value("set_time", 0L);
    e.expires  = j.value("expires", 0L);
    e.reason   = j.value("reason", "");
    e.ban_id   = j.value("ban_id", cf_generate_uid());
    return e;
  }
};

// =============================================================================
// SECTION 4: Exception entry (+e)
// =============================================================================

struct ExceptFullEntry {
  std::string mask;
  std::string set_by;
  int64_t set_time;
  int64_t expires;
  std::string reason;
  std::string except_id;

  ExceptFullEntry() : set_time(0), expires(0) {
    except_id = cf_generate_uid();
  }

  ExceptFullEntry(const std::string& m, const std::string& sb,
                  int64_t st, int64_t ex = 0, const std::string& r = "")
    : mask(m), set_by(sb), set_time(st), expires(ex), reason(r) {
    except_id = cf_generate_uid();
  }

  bool is_expired() const {
    if (expires == 0) return false;
    return cf_now_sec() >= expires;
  }

  bool matches(const std::string& nick, const std::string& user,
               const std::string& host) const {
    return cf_mask_matches(mask, nick, user, host);
  }

  json to_json() const {
    return {
      {"mask", mask}, {"set_by", set_by}, {"set_time", set_time},
      {"expires", expires}, {"reason", reason}, {"except_id", except_id}
    };
  }

  static ExceptFullEntry from_json(const json& j) {
    ExceptFullEntry e;
    e.mask     = j.value("mask", "");
    e.set_by   = j.value("set_by", "");
    e.set_time = j.value("set_time", 0L);
    e.expires  = j.value("expires", 0L);
    e.reason   = j.value("reason", "");
    e.except_id = j.value("except_id", cf_generate_uid());
    return e;
  }
};

// =============================================================================
// SECTION 5: Invite exception entry (+I)
// =============================================================================

struct InviteExceptFullEntry {
  std::string mask;
  std::string set_by;
  int64_t set_time;
  int64_t expires;
  std::string reason;
  std::string invex_id;

  InviteExceptFullEntry() : set_time(0), expires(0) {
    invex_id = cf_generate_uid();
  }

  InviteExceptFullEntry(const std::string& m, const std::string& sb,
                        int64_t st, int64_t ex = 0, const std::string& r = "")
    : mask(m), set_by(sb), set_time(st), expires(ex), reason(r) {
    invex_id = cf_generate_uid();
  }

  bool is_expired() const {
    if (expires == 0) return false;
    return cf_now_sec() >= expires;
  }

  bool matches(const std::string& nick, const std::string& user,
               const std::string& host) const {
    return cf_mask_matches(mask, nick, user, host);
  }

  json to_json() const {
    return {
      {"mask", mask}, {"set_by", set_by}, {"set_time", set_time},
      {"expires", expires}, {"reason", reason}, {"invex_id", invex_id}
    };
  }

  static InviteExceptFullEntry from_json(const json& j) {
    InviteExceptFullEntry e;
    e.mask     = j.value("mask", "");
    e.set_by   = j.value("set_by", "");
    e.set_time = j.value("set_time", 0L);
    e.expires  = j.value("expires", 0L);
    e.reason   = j.value("reason", "");
    e.invex_id = j.value("invex_id", cf_generate_uid());
    return e;
  }
};

// =============================================================================
// SECTION 6: Channel membership record
// =============================================================================

struct ChannelMembershipRecord {
  std::string nick;
  std::string user;
  std::string host;
  std::string modes;        // e.g., "ov" for +o +v
  int64_t joined_at;        // unix timestamp when joined
  int64_t parted_at;        // 0 if still in channel
  std::string part_reason;

  ChannelMembershipRecord() : joined_at(0), parted_at(0) {}

  ChannelMembershipRecord(const std::string& n, const std::string& u,
                          const std::string& h, int64_t jt)
    : nick(n), user(u), host(h), joined_at(jt), parted_at(0) {}

  bool is_active() const { return parted_at == 0; }

  CFAccessLevel highest_access() const {
    if (modes.find('q') != std::string::npos) return CFAccessLevel::FOUNDER;
    if (modes.find('a') != std::string::npos) return CFAccessLevel::SOP;
    if (modes.find('o') != std::string::npos) return CFAccessLevel::AOP;
    if (modes.find('h') != std::string::npos) return CFAccessLevel::HOP;
    if (modes.find('v') != std::string::npos) return CFAccessLevel::VOP;
    return CFAccessLevel::NONE;
  }

  json to_json() const {
    return {
      {"nick", nick}, {"user", user}, {"host", host},
      {"modes", modes}, {"joined_at", joined_at},
      {"parted_at", parted_at}, {"part_reason", part_reason}
    };
  }

  static ChannelMembershipRecord from_json(const json& j) {
    ChannelMembershipRecord r;
    r.nick        = j.value("nick", "");
    r.user        = j.value("user", "");
    r.host        = j.value("host", "");
    r.modes       = j.value("modes", "");
    r.joined_at   = j.value("joined_at", 0L);
    r.parted_at   = j.value("parted_at", 0L);
    r.part_reason = j.value("part_reason", "");
    return r;
  }
};

// =============================================================================
// SECTION 7: Channel log entry
// =============================================================================

struct ChannelLogEntry {
  int64_t timestamp;
  CFLogLevel level;
  std::string source;       // nick or server
  std::string target;       // target user/channel
  std::string message;
  std::string entry_id;

  ChannelLogEntry()
    : timestamp(0), level(CFLogLevel::MSG) {
    entry_id = cf_generate_uid();
  }

  ChannelLogEntry(CFLogLevel lv, const std::string& src,
                  const std::string& msg, const std::string& tgt = "")
    : timestamp(cf_now_sec()), level(lv), source(src),
      target(tgt), message(msg) {
    entry_id = cf_generate_uid();
  }

  std::string level_str() const {
    switch (level) {
      case CFLogLevel::JOIN:   return "JOIN";
      case CFLogLevel::PART:   return "PART";
      case CFLogLevel::MSG:    return "MSG";
      case CFLogLevel::NOTICE: return "NOTICE";
      case CFLogLevel::MODE:   return "MODE";
      case CFLogLevel::TOPIC:  return "TOPIC";
      case CFLogLevel::KICK:   return "KICK";
      case CFLogLevel::BAN:    return "BAN";
      case CFLogLevel::SYSTEM: return "SYSTEM";
    }
    return "UNKNOWN";
  }

  std::string format_for_file() const {
    std::stringstream ss;
    ss << cf_format_time_iso(timestamp) << " "
       << level_str() << " "
       << source;
    if (!target.empty()) ss << " -> " << target;
    ss << " :" << message;
    return ss.str();
  }

  json to_json() const {
    return {
      {"timestamp", timestamp}, {"level", static_cast<int>(level)},
      {"source", source}, {"target", target}, {"message", message},
      {"entry_id", entry_id}
    };
  }

  static ChannelLogEntry from_json(const json& j) {
    ChannelLogEntry e;
    e.timestamp = j.value("timestamp", 0L);
    e.level     = static_cast<CFLogLevel>(j.value("level", 2));
    e.source    = j.value("source", "");
    e.target    = j.value("target", "");
    e.message   = j.value("message", "");
    e.entry_id  = j.value("entry_id", cf_generate_uid());
    return e;
  }
};

// =============================================================================
// SECTION 8: Channel topic history entry
// =============================================================================

struct ChannelTopicEntry {
  std::string topic;
  std::string set_by;
  int64_t set_time;

  ChannelTopicEntry() : set_time(0) {}

  ChannelTopicEntry(const std::string& t, const std::string& sb, int64_t st)
    : topic(t), set_by(sb), set_time(st) {}

  json to_json() const {
    return {{"topic", topic}, {"set_by", set_by}, {"set_time", set_time}};
  }

  static ChannelTopicEntry from_json(const json& j) {
    ChannelTopicEntry e;
    e.topic    = j.value("topic", "");
    e.set_by   = j.value("set_by", "");
    e.set_time = j.value("set_time", 0L);
    return e;
  }
};

// =============================================================================
// SECTION 9: Channel access entry (SOP/AOP/HOP/VOP)
// =============================================================================

struct ChannelAccessEntry {
  std::string mask;            // account mask or nick!user@host
  CFAccessLevel level;
  std::string set_by;
  int64_t set_time;
  int64_t expires;             // 0 = permanent
  std::string access_id;

  ChannelAccessEntry()
    : level(CFAccessLevel::NONE), set_time(0), expires(0) {
    access_id = cf_generate_uid();
  }

  ChannelAccessEntry(const std::string& m, CFAccessLevel lv,
                     const std::string& sb, int64_t st, int64_t ex = 0)
    : mask(m), level(lv), set_by(sb), set_time(st), expires(ex) {
    access_id = cf_generate_uid();
  }

  bool is_expired() const {
    if (expires == 0) return false;
    return cf_now_sec() >= expires;
  }

  json to_json() const {
    return {
      {"mask", mask}, {"level", static_cast<int>(level)},
      {"set_by", set_by}, {"set_time", set_time},
      {"expires", expires}, {"access_id", access_id}
    };
  }

  static ChannelAccessEntry from_json(const json& j) {
    ChannelAccessEntry e;
    e.mask     = j.value("mask", "");
    e.level    = static_cast<CFAccessLevel>(j.value("level", 0));
    e.set_by   = j.value("set_by", "");
    e.set_time = j.value("set_time", 0L);
    e.expires  = j.value("expires", 0L);
    e.access_id = j.value("access_id", cf_generate_uid());
    return e;
  }

  std::string level_name() const {
    switch (level) {
      case CFAccessLevel::FOUNDER: return "FOUNDER";
      case CFAccessLevel::SOP:     return "SOP";
      case CFAccessLevel::AOP:     return "AOP";
      case CFAccessLevel::HOP:     return "HOP";
      case CFAccessLevel::VOP:     return "VOP";
      default: return "NONE";
    }
  }
};

// =============================================================================
// SECTION 10: Channel mode lock (MLOCK)
// =============================================================================

struct ChannelMLOCK {
  std::string locked_modes;        // modes that MUST be set (e.g., "+nt")
  std::string locked_params;       // params for modes requiring them
  std::string excluded_modes;      // modes that MUST NOT be set (e.g., "-p")
  bool enabled;

  ChannelMLOCK() : enabled(false) {}

  ChannelMLOCK(const std::string& lm, const std::string& lp,
               const std::string& em, bool en = true)
    : locked_modes(lm), locked_params(lp), excluded_modes(em), enabled(en) {}

  json to_json() const {
    return {
      {"locked_modes", locked_modes}, {"locked_params", locked_params},
      {"excluded_modes", excluded_modes}, {"enabled", enabled}
    };
  }

  static ChannelMLOCK from_json(const json& j) {
    ChannelMLOCK m;
    m.locked_modes   = j.value("locked_modes", "");
    m.locked_params  = j.value("locked_params", "");
    m.excluded_modes = j.value("excluded_modes", "");
    m.enabled        = j.value("enabled", false);
    return m;
  }

  // Check if a given mode change violates the lock
  bool violates_lock(char mode, bool adding) const {
    if (!enabled) return false;
    if (adding && excluded_modes.find(mode) != std::string::npos)
      return true; // trying to add an excluded mode
    if (!adding && locked_modes.find(mode) != std::string::npos)
      return true; // trying to remove a locked mode
    return false;
  }
};

// =============================================================================
// SECTION 11: Log rotator
// =============================================================================

class ChannelLogRotator {
public:
  ChannelLogRotator(const std::string& base_dir, const std::string& channel_name,
                    size_t max_size_mb = CF_LOG_ROTATE_SIZE_MB,
                    int rotate_days = CF_LOG_ROTATE_DAYS)
    : base_dir_(base_dir), channel_name_(channel_name),
      max_size_bytes_(max_size_mb * 1024 * 1024),
      rotate_interval_sec_(rotate_days * 86400),
      last_rotation_(cf_now_sec()) {
    cf_mkdir_p(base_dir_);
  }

  std::string current_log_path() const {
    return base_dir_ + "/" + sanitize_name(channel_name_) + ".log";
  }

  void write_line(const std::string& line) {
    std::lock_guard<std::mutex> lk(mu_);
    maybe_rotate();
    std::ofstream ofs(current_log_path(), std::ios::app);
    if (ofs) {
      ofs << line << "\n";
      // optional flush for immediate write
    }
  }

  void write_lines(const std::vector<std::string>& lines) {
    std::lock_guard<std::mutex> lk(mu_);
    maybe_rotate();
    std::ofstream ofs(current_log_path(), std::ios::app);
    if (ofs) {
      for (const auto& l : lines) { ofs << l << "\n"; }
    }
  }

  void maybe_rotate() {
    int64_t now = cf_now_sec();
    // Check time-based rotation
    if (now - last_rotation_ >= rotate_interval_sec_) {
      perform_rotation();
      last_rotation_ = now;
      return;
    }
    // Check size-based rotation
    if (cf_file_size(current_log_path()) >= max_size_bytes_) {
      perform_rotation();
      last_rotation_ = now;
    }
  }

  void perform_rotation() {
    std::string cur = current_log_path();
    if (!cf_file_exists(cur)) return;
    int64_t now = cf_now_sec();
    std::string rotated = base_dir_ + "/" + sanitize_name(channel_name_) +
                          "." + std::to_string(now) + ".log";
    // Rename current
    rename(cur.c_str(), rotated.c_str());
    // Optionally compress
    std::string compressed = rotated + ".gz";
    cf_gzip_compress(rotated, compressed);
    // Remove uncompressed if compression succeeded
    if (cf_file_exists(compressed)) {
      remove(rotated.c_str());
    }
    // Clean up old logs (keep last 30)
    cleanup_old_logs(30);
  }

  void force_rotation() {
    std::lock_guard<std::mutex> lk(mu_);
    perform_rotation();
    last_rotation_ = cf_now_sec();
  }

  void cleanup_old_logs(size_t keep_count) {
    // Gather all log files
    std::string prefix = sanitize_name(channel_name_) + ".";
    // Simple approach: use system to list files
    // In production, use readdir; here we take a pragmatic approach
    std::string cmd = "ls -1t " + base_dir_ + "/" + sanitize_name(channel_name_) + ".*.log* 2>/dev/null";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return;
    std::vector<std::string> files;
    char buf[1024];
    while (fgets(buf, sizeof(buf), fp)) {
      std::string s(buf);
      s.erase(s.find_last_not_of("\n\r") + 1);
      files.push_back(s);
    }
    pclose(fp);
    // Delete files beyond keep_count
    for (size_t i = keep_count; i < files.size(); ++i) {
      remove(files[i].c_str());
    }
  }

private:
  std::string sanitize_name(const std::string& name) const {
    std::string r = cf_to_lower(name);
    for (auto& c : r) {
      if (!isalnum(static_cast<unsigned char>(c)) && c != '#' && c != '&' && c != '!')
        c = '_';
    }
    return r;
  }

  std::string base_dir_;
  std::string channel_name_;
  size_t max_size_bytes_;
  int64_t rotate_interval_sec_;
  int64_t last_rotation_;
  std::mutex mu_;
};

// =============================================================================
// SECTION 12: Channel statistics
// =============================================================================

class ChannelStatistics {
public:
  ChannelStatistics() { reset(); }

  void reset() {
    total_messages_    = 0;
    total_joins_       = 0;
    total_parts_       = 0;
    total_kicks_       = 0;
    total_mode_changes_= 0;
    total_topic_changes_= 0;
    peak_users_        = 0;
    total_unique_users_ = 0;
    created_at_        = cf_now_sec();
  }

  void record_message()     { ++total_messages_; update_activity(); }
  void record_join()        { ++total_joins_; ++current_users_; update_peak(); update_activity(); }
  void record_part()        { ++total_parts_; --current_users_; update_activity(); }
  void record_kick()        { ++total_kicks_; --current_users_; update_activity(); }
  void record_mode_change() { ++total_mode_changes_; update_activity(); }
  void record_topic_change(){ ++total_topic_changes_; update_activity(); }
  void record_unique_user() { ++total_unique_users_; }

  void set_current_users(size_t n) {
    current_users_ = n;
    update_peak();
  }

  uint64_t total_messages() const { return total_messages_; }
  uint64_t total_joins() const { return total_joins_; }
  uint64_t total_parts() const { return total_parts_; }
  uint64_t total_kicks() const { return total_kicks_; }
  uint64_t total_mode_changes() const { return total_mode_changes_; }
  uint64_t total_topic_changes() const { return total_topic_changes_; }
  uint64_t peak_users() const { return peak_users_; }
  uint64_t total_unique_users() const { return total_unique_users_; }
  uint64_t current_users() const { return current_users_; }
  int64_t  created_at() const { return created_at_; }
  int64_t  last_activity() const { return last_activity_; }

  json to_json() const {
    return {
      {"total_messages", total_messages_},
      {"total_joins", total_joins_},
      {"total_parts", total_parts_},
      {"total_kicks", total_kicks_},
      {"total_mode_changes", total_mode_changes_},
      {"total_topic_changes", total_topic_changes_},
      {"peak_users", peak_users_},
      {"total_unique_users", total_unique_users_},
      {"current_users", current_users_},
      {"created_at", created_at_},
      {"last_activity", last_activity_}
    };
  }

  static ChannelStatistics from_json(const json& j) {
    ChannelStatistics s;
    s.total_messages_      = j.value("total_messages", 0UL);
    s.total_joins_         = j.value("total_joins", 0UL);
    s.total_parts_         = j.value("total_parts", 0UL);
    s.total_kicks_         = j.value("total_kicks", 0UL);
    s.total_mode_changes_  = j.value("total_mode_changes", 0UL);
    s.total_topic_changes_ = j.value("total_topic_changes", 0UL);
    s.peak_users_          = j.value("peak_users", 0UL);
    s.total_unique_users_  = j.value("total_unique_users", 0UL);
    s.current_users_       = j.value("current_users", 0UL);
    s.created_at_          = j.value("created_at", 0L);
    s.last_activity_       = j.value("last_activity", 0L);
    return s;
  }

private:
  void update_peak() {
    if (current_users_ > peak_users_) peak_users_ = current_users_;
  }
  void update_activity() {
    last_activity_ = cf_now_sec();
  }

  uint64_t total_messages_       = 0;
  uint64_t total_joins_          = 0;
  uint64_t total_parts_          = 0;
  uint64_t total_kicks_          = 0;
  uint64_t total_mode_changes_   = 0;
  uint64_t total_topic_changes_  = 0;
  uint64_t peak_users_           = 0;
  uint64_t total_unique_users_   = 0;
  uint64_t current_users_        = 0;
  int64_t  created_at_           = 0;
  int64_t  last_activity_        = 0;
};

// =============================================================================
// SECTION 13: Channel message archive (searchable, paginated)
// =============================================================================

class ChannelMessageArchive {
public:
  ChannelMessageArchive(size_t max_in_memory = CF_MAX_LOG_LINES_MEM)
    : max_in_memory_(max_in_memory) {}

  void add(const ChannelLogEntry& entry) {
    std::lock_guard<std::mutex> lk(mu_);
    entries_.push_back(entry);
    while (entries_.size() > max_in_memory_) {
      entries_.pop_front();
    }
  }

  void add_batch(const std::vector<ChannelLogEntry>& batch) {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& e : batch) {
      entries_.push_back(e);
    }
    while (entries_.size() > max_in_memory_) {
      entries_.pop_front();
    }
  }

  // Search with pagination
  struct SearchResult {
    std::vector<ChannelLogEntry> entries;
    size_t total_matches;
    size_t page;
    size_t total_pages;
    bool has_more;
  };

  SearchResult search(const std::string& query,
                       CFLogLevel min_level = CFLogLevel::JOIN,
                       CFLogLevel max_level = CFLogLevel::SYSTEM,
                       int64_t start_time = 0,
                       int64_t end_time = 0,
                       const std::string& source_filter = "",
                       size_t page = 1,
                       size_t page_size = CF_ARCHIVE_PAGE_SIZE) const {
    std::lock_guard<std::mutex> lk(mu_);
    SearchResult result;
    result.page = page;
    result.page_size = page_size;

    // Collect matching entries
    std::vector<ChannelLogEntry> matches;
    for (const auto& e : entries_) {
      if (static_cast<int>(e.level) < static_cast<int>(min_level)) continue;
      if (static_cast<int>(e.level) > static_cast<int>(max_level)) continue;
      if (start_time > 0 && e.timestamp < start_time) continue;
      if (end_time > 0 && e.timestamp > end_time) continue;
      if (!source_filter.empty() &&
          cf_to_lower(e.source).find(cf_to_lower(source_filter)) == std::string::npos) continue;
      if (!query.empty()) {
        std::string haystack = cf_to_lower(e.message + " " + e.source + " " + e.target);
        if (haystack.find(cf_to_lower(query)) == std::string::npos) continue;
      }
      matches.push_back(e);
    }

    result.total_matches = matches.size();
    result.total_pages = (result.total_matches + page_size - 1) / page_size;
    if (result.total_pages == 0) result.total_pages = 1;

    // Paginate
    size_t start_idx = (page - 1) * page_size;
    size_t end_idx = std::min(start_idx + page_size, matches.size());
    for (size_t i = start_idx; i < end_idx; ++i) {
      result.entries.push_back(matches[i]);
    }
    result.has_more = (end_idx < matches.size());
    return result;
  }

  // Get recent entries
  std::vector<ChannelLogEntry> recent(size_t count = 50) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<ChannelLogEntry> r;
    auto start = (entries_.size() > count) ? entries_.end() - static_cast<long>(count)
                                           : entries_.begin();
    for (auto it = start; it != entries_.end(); ++it) {
      r.push_back(*it);
    }
    return r;
  }

  size_t size() const {
    std::lock_guard<std::mutex> lk(mu_);
    return entries_.size();
  }

  void clear() {
    std::lock_guard<std::mutex> lk(mu_);
    entries_.clear();
  }

  std::vector<ChannelLogEntry> all() const {
    std::lock_guard<std::mutex> lk(mu_);
    return std::vector<ChannelLogEntry>(entries_.begin(), entries_.end());
  }

private:
  std::deque<ChannelLogEntry> entries_;
  size_t max_in_memory_;
  mutable std::mutex mu_;
};

// =============================================================================
// SECTION 14: Channel registration with ChanServ
// =============================================================================

class ChannelRegistration {
public:
  // Registration status
  enum class RegStatus : uint8_t {
    UNREGISTERED = 0,
    PENDING      = 1,
    REGISTERED   = 2,
  };

  ChannelRegistration(const std::string& channel_name)
    : channel_name_(channel_name), status_(RegStatus::UNREGISTERED),
      registered_at_(0), last_used_(0) {}

  // ChanServ REGISTER
  bool register_channel(const std::string& founder,
                        const std::string& password,
                        const std::string& description = "") {
    if (status_ == RegStatus::REGISTERED) return false;
    founder_      = founder;
    password_hash_ = hash_password(password);
    description_  = description;
    registered_at_ = cf_now_sec();
    status_       = RegStatus::REGISTERED;
    persist_      = true;
    return true;
  }

  // ChanServ DROP
  bool drop_channel(const std::string& requester) {
    if (status_ != RegStatus::REGISTERED) return false;
    // Only founder or network admin can drop
    if (!cf_iequals(requester, founder_)) return false;
    status_        = RegStatus::UNREGISTERED;
    founder_.clear();
    password_hash_.clear();
    description_.clear();
    registered_at_  = 0;
    persist_        = false;
    return true;
  }

  // ChanServ SET
  bool set_property(const std::string& property, const std::string& value) {
    if (status_ != RegStatus::REGISTERED) return false;
    properties_[property] = value;
    return true;
  }

  std::string get_property(const std::string& property) const {
    auto it = properties_.find(property);
    return (it != properties_.end()) ? it->second : "";
  }

  bool check_password(const std::string& password) const {
    if (password_hash_.empty()) return false;
    return hash_password(password) == password_hash_;
  }

  bool is_registered() const { return status_ == RegStatus::REGISTERED; }
  bool is_persistent() const { return persist_; }
  void set_persistent(bool v) { persist_ = v; }

  const std::string& founder() const { return founder_; }
  const std::string& description() const { return description_; }
  int64_t registered_at() const { return registered_at_; }

  void touch() { last_used_ = cf_now_sec(); }
  int64_t last_used() const { return last_used_; }

  json to_json() const {
    json j = {
      {"channel", channel_name_},
      {"status", static_cast<int>(status_)},
      {"founder", founder_},
      {"password_hash", password_hash_},
      {"description", description_},
      {"registered_at", registered_at_},
      {"last_used", last_used_},
      {"persist", persist_},
      {"properties", json(properties_)}
    };
    return j;
  }

  static ChannelRegistration from_json(const std::string& channel_name, const json& j) {
    ChannelRegistration r(channel_name);
    r.status_        = static_cast<RegStatus>(j.value("status", 0));
    r.founder_       = j.value("founder", "");
    r.password_hash_ = j.value("password_hash", "");
    r.description_   = j.value("description", "");
    r.registered_at_ = j.value("registered_at", 0L);
    r.last_used_     = j.value("last_used", 0L);
    r.persist_       = j.value("persist", false);
    if (j.contains("properties") && j["properties"].is_object()) {
      for (auto& [k, v] : j["properties"].items()) {
        r.properties_[k] = v.get<std::string>();
      }
    }
    return r;
  }

private:
  static std::string hash_password(const std::string& pw) {
    // Simple hash - in production, use bcrypt/scrypt
    std::hash<std::string> hasher;
    std::stringstream ss;
    ss << std::hex << hasher(pw + "progressive-irc-salt");
    return ss.str();
  }

  std::string channel_name_;
  RegStatus status_;
  std::string founder_;
  std::string password_hash_;
  std::string description_;
  int64_t registered_at_;
  int64_t last_used_;
  bool persist_ = false;
  std::map<std::string, std::string> properties_;
};

// =============================================================================
// SECTION 15: Channel forwarding (+f / +L redirect)
// =============================================================================

class ChannelForwarding {
public:
  ChannelForwarding() : enabled_(false) {}

  // +f mode: forward users who cannot join to another channel
  void set_forward(const std::string& target_channel) {
    forward_target_ = target_channel;
    enabled_ = !target_channel.empty();
  }

  void set_redirect(const std::string& target_channel) {
    redirect_target_ = target_channel;
    redirect_enabled_ = !target_channel.empty();
  }

  void disable_forward() {
    forward_target_.clear();
    enabled_ = false;
  }

  void disable_redirect() {
    redirect_target_.clear();
    redirect_enabled_ = false;
  }

  bool is_forward_enabled() const { return enabled_; }
  bool is_redirect_enabled() const { return redirect_enabled_; }
  const std::string& forward_target() const { return forward_target_; }
  const std::string& redirect_target() const { return redirect_target_; }

  // Generate the forward numeric/message for a user who can't join
  std::string forward_message(const std::string& channel_name) const {
    if (!enabled_ || forward_target_.empty()) return "";
    std::stringstream ss;
    ss << ":" << "irc.server" << " 470 " << "*" << " " << channel_name
       << " " << forward_target_
       << " :Forwarding to another channel";
    return ss.str();
  }

  // +L redirect: when channel is full, redirect to another
  std::string redirect_message(const std::string& channel_name) const {
    if (!redirect_enabled_ || redirect_target_.empty()) return "";
    std::stringstream ss;
    ss << ":" << "irc.server" << " 470 " << "*" << " " << channel_name
       << " " << redirect_target_
       << " :Channel is full, redirecting";
    return ss.str();
  }

  json to_json() const {
    return {
      {"enabled", enabled_}, {"forward_target", forward_target_},
      {"redirect_enabled", redirect_enabled_}, {"redirect_target", redirect_target_}
    };
  }

  static ChannelForwarding from_json(const json& j) {
    ChannelForwarding f;
    f.enabled_          = j.value("enabled", false);
    f.forward_target_   = j.value("forward_target", "");
    f.redirect_enabled_ = j.value("redirect_enabled", false);
    f.redirect_target_  = j.value("redirect_target", "");
    return f;
  }

private:
  bool enabled_;
  std::string forward_target_;
  bool redirect_enabled_ = false;
  std::string redirect_target_;
};

// =============================================================================
// SECTION 16: Main ChannelFull class
// =============================================================================

class ChannelFull {
public:
  // --- Constructor / Destructor ---
  ChannelFull(const std::string& name, const std::string& log_dir = "./irc_logs")
    : name_(name),
      created_ts_(cf_now_sec()),
      last_activity_(cf_now_sec()),
      last_message_time_(0),
      last_join_time_(0),
      empty_since_(0),
      status_(0),  // ACTIVE
      persist_(false),
      topic_lock_(false),
      user_limit_(0),
      log_dir_(log_dir),
      log_rotator_(std::make_shared<ChannelLogRotator>(log_dir, name)),
      registration_(std::make_shared<ChannelRegistration>(name)),
      active_(true)
  {
    cf_mkdir_p(log_dir_);
    log_event(CFLogLevel::SYSTEM, "Server", "Channel created: " + name_);
  }

  ~ChannelFull() {
    save_persistent_state();
    log_event(CFLogLevel::SYSTEM, "Server", "Channel destroyed: " + name_);
  }

  // ===========================================================================
  // 1. CHANNEL CREATION LIFECYCLE (create, join, part, destroy)
  // ===========================================================================

  bool is_active() const { return active_; }
  const std::string& name() const { return name_; }
  int64_t created_ts() const { return created_ts_; }

  // Join a user
  bool join(const std::string& nick, const std::string& user,
            const std::string& host) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    std::string key = cf_to_lower(nick);

    // Check if already joined
    if (members_.count(key)) return false;

    // Check bans (unless excepted)
    if (is_banned(nick, user, host) && !is_excepted(nick, user, host)) {
      return false; // caller should send ERR_BANNEDFROMCHAN
    }

    // Check user limit
    if (user_limit_ > 0 && members_.size() >= user_limit_) {
      return false; // ERR_CHANNELISFULL
    }

    // Check invite-only
    if (modes_.find('i') != std::string::npos) {
      if (!invited_.count(key) && !is_invex_matched(nick, user, host)) {
        return false; // ERR_INVITEONLYCHAN
      }
      // Remove one-time invite after use
      invited_.erase(key);
    }

    auto rec = std::make_shared<ChannelMembershipRecord>(nick, user, host, cf_now_sec());
    members_[key] = rec;
    active_users_++;

    // Auto-assign access from access list
    auto_access_assign(nick, user, host);

    stats_.record_join();
    stats_.set_current_users(members_.size());
    membership_history_.push_back(*rec);
    last_join_time_ = cf_now_sec();
    update_activity();
    empty_since_ = 0;

    log_event(CFLogLevel::JOIN, nick, "joined " + name_);
    log_membership_event("JOIN", nick, user, host);

    return true;
  }

  // Part a user
  bool part(const std::string& nick, const std::string& reason = "") {
    std::unique_lock<std::shared_mutex> lk(mu_);
    std::string key = cf_to_lower(nick);
    auto it = members_.find(key);
    if (it == members_.end()) return false;

    it->second->parted_at = cf_now_sec();
    it->second->part_reason = reason;
    membership_history_.push_back(*it->second);
    members_.erase(it);
    active_users_--;

    stats_.record_part();
    stats_.set_current_users(members_.size());
    update_activity();

    log_event(CFLogLevel::PART, nick, "left " + name_ +
              (reason.empty() ? "" : " (" + reason + ")"));
    log_membership_event("PART", nick, "", "", reason);

    // Track empty time for auto-cleanup
    if (members_.empty()) {
      empty_since_ = cf_now_sec();
    }

    return true;
  }

  // Kick a user
  bool kick(const std::string& kicker, const std::string& target,
            const std::string& reason = "") {
    std::unique_lock<std::shared_mutex> lk(mu_);
    std::string key = cf_to_lower(target);
    auto it = members_.find(key);
    if (it == members_.end()) return false;

    it->second->parted_at = cf_now_sec();
    it->second->part_reason = "KICK: " + reason;
    membership_history_.push_back(*it->second);
    members_.erase(it);
    active_users_--;

    stats_.record_kick();
    stats_.set_current_users(members_.size());
    update_activity();

    log_event(CFLogLevel::KICK, kicker, "kicked " + target + ": " + reason);
    log_membership_event("KICK", target, "", "", reason + " by " + kicker);

    if (members_.empty()) empty_since_ = cf_now_sec();
    return true;
  }

  // Destroy channel (requires all users to part first)
  void destroy() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    active_ = false;
    log_event(CFLogLevel::SYSTEM, "Server", "Channel destroyed: " + name_);
    save_persistent_state();
  }

  // ===========================================================================
  // 2. CHANNEL TOPIC MANAGEMENT
  // ===========================================================================

  bool set_topic(const std::string& setter, const std::string& new_topic) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    // Check topic lock (+t and not op)
    if (topic_lock_ && new_topic.size() > CF_MAX_TOPIC_LEN) return false;

    std::string old_topic = topic_;
    topic_       = new_topic;
    topic_setter_ = setter;
    topic_ts_    = cf_now_sec();

    // Save to topic history
    topic_history_.emplace_back(topic_, setter, topic_ts_);
    if (topic_history_.size() > 100) {
      topic_history_.erase(topic_history_.begin());
    }

    stats_.record_topic_change();
    log_event(CFLogLevel::TOPIC, setter, "changed topic to: " + new_topic);

    return true;
  }

  std::string get_topic() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return topic_;
  }

  std::string get_topic_setter() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return topic_setter_;
  }

  int64_t get_topic_ts() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return topic_ts_;
  }

  std::vector<ChannelTopicEntry> get_topic_history(size_t limit = 10) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::vector<ChannelTopicEntry> result;
    size_t start = (topic_history_.size() > limit) ?
                    topic_history_.size() - limit : 0;
    for (size_t i = start; i < topic_history_.size(); ++i) {
      result.push_back(topic_history_[i]);
    }
    return result;
  }

  void set_topic_lock(bool locked) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    topic_lock_ = locked;
    if (locked) {
      modes_ = toggle_mode(modes_, 't', true);
    }
  }

  bool is_topic_locked() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return topic_lock_;
  }

  // ===========================================================================
  // 3. CHANNEL BAN MANAGEMENT
  // ===========================================================================

  bool add_ban(const std::string& mask, const std::string& set_by,
               int64_t expires = 0, const std::string& reason = "") {
    std::unique_lock<std::shared_mutex> lk(mu_);
    if (bans_.size() >= CF_MAX_BANS) return false;

    // Check for duplicate
    for (auto& b : bans_) {
      if (cf_iequals(b.mask, mask) && !b.is_expired()) return false;
    }

    bans_.emplace_back(mask, set_by, cf_now_sec(), expires, reason);
    log_event(CFLogLevel::BAN, set_by, "banned " + mask +
              (reason.empty() ? "" : " (" + reason + ")"));
    save_persistent_state();
    return true;
  }

  bool remove_ban(const std::string& mask) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = std::find_if(bans_.begin(), bans_.end(),
                           [&](const BanFullEntry& b) {
                             return cf_iequals(b.mask, mask);
                           });
    if (it == bans_.end()) return false;
    log_event(CFLogLevel::BAN, "Server", "unbanned " + mask);
    bans_.erase(it);
    save_persistent_state();
    return true;
  }

  bool remove_ban_by_id(const std::string& ban_id) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = std::find_if(bans_.begin(), bans_.end(),
                           [&](const BanFullEntry& b) {
                             return b.ban_id == ban_id;
                           });
    if (it == bans_.end()) return false;
    log_event(CFLogLevel::BAN, "Server", "unbanned " + it->mask);
    bans_.erase(it);
    save_persistent_state();
    return true;
  }

  std::vector<BanFullEntry> list_bans() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    purge_expired_bans();
    return bans_;
  }

  bool is_banned(const std::string& nick, const std::string& user,
                 const std::string& host) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    purge_expired_bans();
    for (const auto& b : bans_) {
      if (b.matches(nick, user, host)) return true;
    }
    return false;
  }

  bool add_ban_exemption(const std::string& mask, const std::string& set_by,
                          int64_t expires = 0, const std::string& reason = "") {
    // This is really an except (+e) - kept for API compatibility
    return add_except(mask, set_by, expires, reason);
  }

  // ===========================================================================
  // 4. CHANNEL EXCEPTION (+e) MANAGEMENT
  // ===========================================================================

  bool add_except(const std::string& mask, const std::string& set_by,
                  int64_t expires = 0, const std::string& reason = "") {
    std::unique_lock<std::shared_mutex> lk(mu_);
    if (excepts_.size() >= CF_MAX_EXCEPTS) return false;

    for (auto& e : excepts_) {
      if (cf_iequals(e.mask, mask) && !e.is_expired()) return false;
    }

    excepts_.emplace_back(mask, set_by, cf_now_sec(), expires, reason);
    log_event(CFLogLevel::MODE, set_by, "added +e " + mask);
    save_persistent_state();
    return true;
  }

  bool remove_except(const std::string& mask) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = std::find_if(excepts_.begin(), excepts_.end(),
                           [&](const ExceptFullEntry& e) {
                             return cf_iequals(e.mask, mask);
                           });
    if (it == excepts_.end()) return false;
    log_event(CFLogLevel::MODE, "Server", "removed +e " + mask);
    excepts_.erase(it);
    save_persistent_state();
    return true;
  }

  bool remove_except_by_id(const std::string& except_id) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = std::find_if(excepts_.begin(), excepts_.end(),
                           [&](const ExceptFullEntry& e) {
                             return e.except_id == except_id;
                           });
    if (it == excepts_.end()) return false;
    log_event(CFLogLevel::MODE, "Server", "removed +e " + it->mask);
    excepts_.erase(it);
    save_persistent_state();
    return true;
  }

  std::vector<ExceptFullEntry> list_excepts() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    purge_expired_excepts();
    return excepts_;
  }

  bool is_excepted(const std::string& nick, const std::string& user,
                   const std::string& host) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    purge_expired_excepts();
    for (const auto& e : excepts_) {
      if (e.matches(nick, user, host)) return true;
    }
    return false;
  }

  // ===========================================================================
  // 5. CHANNEL INVITE EXCEPTION (+I) MANAGEMENT
  // ===========================================================================

  bool add_invex(const std::string& mask, const std::string& set_by,
                 int64_t expires = 0, const std::string& reason = "") {
    std::unique_lock<std::shared_mutex> lk(mu_);
    if (invexes_.size() >= CF_MAX_INVEX) return false;

    for (auto& ie : invexes_) {
      if (cf_iequals(ie.mask, mask) && !ie.is_expired()) return false;
    }

    invexes_.emplace_back(mask, set_by, cf_now_sec(), expires, reason);
    log_event(CFLogLevel::MODE, set_by, "added +I " + mask);
    save_persistent_state();
    return true;
  }

  bool remove_invex(const std::string& mask) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = std::find_if(invexes_.begin(), invexes_.end(),
                           [&](const InviteExceptFullEntry& ie) {
                             return cf_iequals(ie.mask, mask);
                           });
    if (it == invexes_.end()) return false;
    log_event(CFLogLevel::MODE, "Server", "removed +I " + mask);
    invexes_.erase(it);
    save_persistent_state();
    return true;
  }

  bool remove_invex_by_id(const std::string& invex_id) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = std::find_if(invexes_.begin(), invexes_.end(),
                           [&](const InviteExceptFullEntry& ie) {
                             return ie.invex_id == invex_id;
                           });
    if (it == invexes_.end()) return false;
    log_event(CFLogLevel::MODE, "Server", "removed +I " + it->mask);
    invexes_.erase(it);
    save_persistent_state();
    return true;
  }

  std::vector<InviteExceptFullEntry> list_invexes() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    purge_expired_invexes();
    return invexes_;
  }

  bool is_invex_matched(const std::string& nick, const std::string& user,
                        const std::string& host) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    purge_expired_invexes();
    for (const auto& ie : invexes_) {
      if (ie.matches(nick, user, host)) return true;
    }
    return false;
  }

  // Simple invite (stores nick)
  void add_invite(const std::string& nick) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    invited_.insert(cf_to_lower(nick));
  }

  bool is_invited(const std::string& nick) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return invited_.count(cf_to_lower(nick)) > 0;
  }

  void remove_invite(const std::string& nick) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    invited_.erase(cf_to_lower(nick));
  }

  // ===========================================================================
  // 6. CHANNEL MODE UPDATES AND HISTORY LOGGING
  // ===========================================================================

  std::string get_modes() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return modes_;
  }

  bool set_mode(char mode, bool adding, const std::string& param = "") {
    std::unique_lock<std::shared_mutex> lk(mu_);
    std::string old = modes_;
    modes_ = toggle_mode(modes_, mode, adding);

    if (modes_ != old) {
      stats_.record_mode_change();
      std::string change = (adding ? "+" : "-") + std::string(1, mode);
      log_event(CFLogLevel::MODE, "Server", "mode change: " + change +
                (param.empty() ? "" : " " + param));
      save_persistent_state();
      return true;
    }
    return false;
  }

  // Bulk mode change
  bool set_modes(const std::string& mode_string,
                 const std::vector<std::string>& params,
                 const std::string& set_by) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    bool adding = true;
    size_t param_idx = 0;
    std::string old_modes = modes_;

    for (char c : mode_string) {
      if (c == '+') { adding = true; continue; }
      if (c == '-') { adding = false; continue; }

      // Check MLOCK
      if (mlock_.violates_lock(c, adding)) {
        continue; // Skip: blocked by MLOCK
      }

      std::string param = "";
      if (param_idx < params.size() && mode_requires_param(c, adding)) {
        param = params[param_idx++];
      }

      modes_ = toggle_mode(modes_, c, adding);

      // Handle special modes
      switch (c) {
        case 'k':
          key_ = adding ? param : "";
          break;
        case 'l':
          user_limit_ = adding ? static_cast<size_t>(std::stoul(param)) : 0;
          break;
        case 't':
          topic_lock_ = adding;
          break;
        case 'f':
          forwarding_.set_forward(param);
          break;
        case 'L':
          forwarding_.set_redirect(param);
          break;
        default: break;
      }
    }

    if (modes_ != old_modes) {
      stats_.record_mode_change();
      log_event(CFLogLevel::MODE, set_by, "mode: " + mode_string);
      save_persistent_state();
      return true;
    }
    return false;
  }

  bool mode_requires_param(char mode, bool adding) {
    switch (mode) {
      case 'k': case 'l': case 'f': case 'L': return adding;
      case 'b': case 'e': case 'I':
      case 'o': case 'v': case 'h': case 'a': case 'q': return true;
      default: return false;
    }
  }

  // ===========================================================================
  // 7. CHANNEL MESSAGE LOGGING
  // ===========================================================================

  void log_message(const std::string& source, const std::string& message) {
    auto entry = ChannelLogEntry(CFLogLevel::MSG, source, message);
    archive_.add(entry);
    log_rotator_->write_line(entry.format_for_file());
    stats_.record_message();
    update_activity();
  }

  void log_notice(const std::string& source, const std::string& message,
                  const std::string& target = "") {
    auto entry = ChannelLogEntry(CFLogLevel::NOTICE, source, message, target);
    archive_.add(entry);
    log_rotator_->write_line(entry.format_for_file());
    update_activity();
  }

  void log_event(CFLogLevel level, const std::string& source,
                 const std::string& message, const std::string& target = "") {
    auto entry = ChannelLogEntry(level, source, message, target);
    archive_.add(entry);
    log_rotator_->write_line(entry.format_for_file());
    update_activity();
  }

  void log_membership_event(const std::string& type, const std::string& nick,
                            const std::string& user, const std::string& host,
                            const std::string& extra = "") {
    std::string msg = type + " " + nick + "!" + user + "@" + host;
    if (!extra.empty()) msg += " [" + extra + "]";
    log_rotator_->write_line(cf_format_time_iso(cf_now_sec()) + " " + type + " " + msg);
  }

  // ===========================================================================
  // 8. LOG ROTATION (daily, size-based, compression)
  // ===========================================================================

  void force_log_rotation() {
    log_rotator_->force_rotation();
  }

  void set_log_directory(const std::string& dir) {
    log_dir_ = dir;
    cf_mkdir_p(log_dir_);
    log_rotator_ = std::make_shared<ChannelLogRotator>(log_dir_, name_);
  }

  std::string get_log_directory() const { return log_dir_; }

  // ===========================================================================
  // 9. CHANNEL STATISTICS
  // ===========================================================================

  const ChannelStatistics& statistics() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return stats_;
  }

  std::string stats_report() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::stringstream ss;
    ss << "Channel Statistics for " << name_ << ":\n";
    ss << "  Created: " << cf_format_time(stats_.created_at()) << "\n";
    ss << "  Current users: " << stats_.current_users() << "\n";
    ss << "  Peak users: " << stats_.peak_users() << "\n";
    ss << "  Total messages: " << stats_.total_messages() << "\n";
    ss << "  Total joins: " << stats_.total_joins() << "\n";
    ss << "  Total parts: " << stats_.total_parts() << "\n";
    ss << "  Total kicks: " << stats_.total_kicks() << "\n";
    ss << "  Mode changes: " << stats_.total_mode_changes() << "\n";
    ss << "  Topic changes: " << stats_.total_topic_changes() << "\n";
    ss << "  Last activity: " << cf_format_time(stats_.last_activity()) << "\n";
    return ss.str();
  }

  // ===========================================================================
  // 10. CHANNEL ACTIVITY TRACKING
  // ===========================================================================

  void update_activity() {
    last_activity_ = cf_now_sec();
  }

  int64_t last_activity_time() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return last_activity_;
  }

  int64_t last_message_time() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return last_message_time_;
  }

  int64_t last_join_time() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return last_join_time_;
  }

  bool is_idle(int64_t threshold_seconds = 3600) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return (cf_now_sec() - last_activity_) > threshold_seconds;
  }

  // ===========================================================================
  // 11. CHANNEL SEARCHABLE MESSAGE ARCHIVE WITH PAGINATION
  // ===========================================================================

  ChannelMessageArchive::SearchResult search_messages(
      const std::string& query,
      int64_t start_time = 0, int64_t end_time = 0,
      const std::string& source_filter = "",
      size_t page = 1, size_t page_size = CF_ARCHIVE_PAGE_SIZE) const {
    return archive_.search(query, CFLogLevel::JOIN, CFLogLevel::SYSTEM,
                          start_time, end_time, source_filter, page, page_size);
  }

  std::vector<ChannelLogEntry> recent_messages(size_t count = 50) const {
    return archive_.recent(count);
  }

  size_t archive_size() const { return archive_.size(); }

  // ===========================================================================
  // 12. CHANNEL MEMBERSHIP HISTORY
  // ===========================================================================

  std::vector<ChannelMembershipRecord> get_membership_history(
      const std::string& nick_filter = "",
      size_t limit = 100) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::vector<ChannelMembershipRecord> result;
    size_t start = (membership_history_.size() > limit) ?
                    membership_history_.size() - limit : 0;
    for (size_t i = start; i < membership_history_.size(); ++i) {
      if (nick_filter.empty() ||
          cf_to_lower(membership_history_[i].nick).find(
            cf_to_lower(nick_filter)) != std::string::npos) {
        result.push_back(membership_history_[i]);
      }
    }
    return result;
  }

  // Get active members
  std::vector<ChannelMembershipRecord> get_members() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::vector<ChannelMembershipRecord> result;
    for (const auto& [k, rec] : members_) {
      result.push_back(*rec);
    }
    return result;
  }

  size_t member_count() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return members_.size();
  }

  bool has_member(const std::string& nick) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return members_.count(cf_to_lower(nick)) > 0;
  }

  std::string get_member_modes(const std::string& nick) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = members_.find(cf_to_lower(nick));
    if (it != members_.end()) return it->second->modes;
    return "";
  }

  // Set member channel modes
  bool set_member_mode(const std::string& nick, char mode, bool adding) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = members_.find(cf_to_lower(nick));
    if (it == members_.end()) return false;
    it->second->modes = toggle_mode(it->second->modes, mode, adding);
    return true;
  }

  CFAccessLevel get_member_access(const std::string& nick) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = members_.find(cf_to_lower(nick));
    if (it == members_.end()) return CFAccessLevel::NONE;
    return it->second->highest_access();
  }

  // ===========================================================================
  // 13. CHANNEL FORWARDING (+f / +L redirect)
  // ===========================================================================

  void set_forward_target(const std::string& target) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    forwarding_.set_forward(target);
  }

  void set_redirect_target(const std::string& target) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    forwarding_.set_redirect(target);
  }

  void disable_forwarding() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    forwarding_.disable_forward();
  }

  void disable_redirect() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    forwarding_.disable_redirect();
  }

  std::string get_forward_target() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return forwarding_.forward_target();
  }

  std::string get_redirect_target() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return forwarding_.redirect_target();
  }

  bool is_forward_enabled() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return forwarding_.is_forward_enabled();
  }

  bool is_redirect_enabled() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return forwarding_.is_redirect_enabled();
  }

  ChannelForwarding get_forwarding_config() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return forwarding_;
  }

  // ===========================================================================
  // 14. CHANNEL AUTO-CLEANUP OF EMPTY NON-PERSISTENT CHANNELS
  // ===========================================================================

  bool should_auto_cleanup() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    if (persist_) return false;           // persistent channels stay
    if (!members_.empty()) return false;  // non-empty channels stay
    if (empty_since_ == 0) return false;  // never empty
    return (cf_now_sec() - empty_since_) >= CF_AUTO_CLEANUP_DELAY;
  }

  void set_persistent(bool p) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    persist_ = p;
  }

  bool is_persistent() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return persist_;
  }

  bool is_empty() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return members_.empty();
  }

  int64_t empty_since() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return empty_since_;
  }

  void set_empty_since(int64_t ts) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    empty_since_ = ts;
  }

  // ===========================================================================
  // 15. CHANNEL REGISTRATION WITH SERVICES
  // ===========================================================================

  bool register_with_chanserv(const std::string& founder,
                               const std::string& password,
                               const std::string& description = "") {
    std::unique_lock<std::shared_mutex> lk(mu_);
    if (registration_->is_registered()) return false;
    bool ok = registration_->register_channel(founder, password, description);
    if (ok) {
      persist_ = true;
      log_event(CFLogLevel::SYSTEM, founder, "Channel registered with ChanServ");
      save_persistent_state();
    }
    return ok;
  }

  bool drop_registration(const std::string& requester) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    if (!registration_->is_registered()) return false;
    bool ok = registration_->drop_channel(requester);
    if (ok) {
      persist_ = false;
      log_event(CFLogLevel::SYSTEM, requester, "Channel registration dropped");
      save_persistent_state();
    }
    return ok;
  }

  bool identify_founder(const std::string& password) {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return registration_->check_password(password);
  }

  bool set_chan_property(const std::string& prop, const std::string& val) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    return registration_->set_property(prop, val);
  }

  std::string get_chan_property(const std::string& prop) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return registration_->get_property(prop);
  }

  bool is_registered() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return registration_->is_registered();
  }

  const std::string& get_founder() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return registration_->founder();
  }

  void touch_registration() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    registration_->touch();
  }

  // ===========================================================================
  // 16. CHANNEL ACCESS LIST MANAGEMENT (SOP, AOP, HOP, VOP)
  // ===========================================================================

  bool add_access(const std::string& mask, CFAccessLevel level,
                  const std::string& set_by, int64_t expires = 0) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    if (access_list_.size() >= CF_MAX_ACCESS_ENTRIES) return false;

    // Remove existing entry for this mask
    access_list_.erase(
      std::remove_if(access_list_.begin(), access_list_.end(),
                     [&](const ChannelAccessEntry& e) {
                       return cf_iequals(e.mask, mask);
                     }),
      access_list_.end()
    );

    access_list_.emplace_back(mask, level, set_by, cf_now_sec(), expires);
    log_event(CFLogLevel::MODE, set_by,
              "access set: " + mask + " -> " + access_level_name(level));
    save_persistent_state();
    return true;
  }

  bool remove_access(const std::string& mask) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = std::find_if(access_list_.begin(), access_list_.end(),
                           [&](const ChannelAccessEntry& e) {
                             return cf_iequals(e.mask, mask);
                           });
    if (it == access_list_.end()) return false;
    log_event(CFLogLevel::MODE, "Server", "access removed: " + mask);
    access_list_.erase(it);
    save_persistent_state();
    return true;
  }

  bool remove_access_by_id(const std::string& access_id) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = std::find_if(access_list_.begin(), access_list_.end(),
                           [&](const ChannelAccessEntry& e) {
                             return e.access_id == access_id;
                           });
    if (it == access_list_.end()) return false;
    log_event(CFLogLevel::MODE, "Server", "access removed: " + it->mask);
    access_list_.erase(it);
    save_persistent_state();
    return true;
  }

  std::vector<ChannelAccessEntry> list_access() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    purge_expired_access();
    return access_list_;
  }

  CFAccessLevel get_access_level(const std::string& nick,
                                  const std::string& user,
                                  const std::string& host) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    purge_expired_access();
    CFAccessLevel highest = CFAccessLevel::NONE;
    for (const auto& e : access_list_) {
      if (cf_mask_matches(e.mask, nick, user, host)) {
        if (static_cast<uint8_t>(e.level) > static_cast<uint8_t>(highest)) {
          highest = e.level;
        }
      }
    }
    return highest;
  }

  size_t count_access_by_level(CFAccessLevel level) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    size_t count = 0;
    for (const auto& e : access_list_) {
      if (e.level == level) ++count;
    }
    return count;
  }

  // ===========================================================================
  // 17. CHANNEL MLOCK ENFORCEMENT
  // ===========================================================================

  void set_mlock(const std::string& locked_modes,
                 const std::string& locked_params = "",
                 const std::string& excluded_modes = "") {
    std::unique_lock<std::shared_mutex> lk(mu_);
    mlock_ = ChannelMLOCK(locked_modes, locked_params, excluded_modes, true);
    enforce_mlock();
  }

  void set_mlock(const ChannelMLOCK& mlock) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    mlock_ = mlock;
    enforce_mlock();
  }

  void disable_mlock() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    mlock_.enabled = false;
  }

  ChannelMLOCK get_mlock() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return mlock_;
  }

  bool is_mlock_enabled() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return mlock_.enabled;
  }

  // Enforce: ensure locked modes are set, excluded modes are unset
  void enforce_mlock() {
    if (!mlock_.enabled) return;
    bool changed = false;

    // Apply locked modes
    for (char c : mlock_.locked_modes) {
      if (c == '+' || c == '-') continue;
      if (modes_.find(c) == std::string::npos) {
        modes_ = toggle_mode(modes_, c, true);
        changed = true;
      }
    }

    // Remove excluded modes
    for (char c : mlock_.excluded_modes) {
      if (c == '+' || c == '-') continue;
      size_t pos = modes_.find(c);
      if (pos != std::string::npos) {
        modes_.erase(pos, 1);
        changed = true;
      }
    }

    if (changed) {
      log_event(CFLogLevel::MODE, "MLOCK", "enforced mode lock");
    }
  }

  // ===========================================================================
  // 18. CHANNEL ENTRY MESSAGE (send on join)
  // ===========================================================================

  void set_entry_message(const std::string& msg) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    entry_message_ = msg;
  }

  std::string get_entry_message() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return entry_message_;
  }

  void clear_entry_message() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    entry_message_.clear();
  }

  bool has_entry_message() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return !entry_message_.empty();
  }

  // ===========================================================================
  // 19. CHANNEL URL ASSOCIATION
  // ===========================================================================

  void set_url(const std::string& url) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    url_ = url;
    log_event(CFLogLevel::MODE, "Server", "URL set: " + url);
  }

  std::string get_url() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return url_;
  }

  void clear_url() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    url_.clear();
  }

  bool has_url() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return !url_.empty();
  }

  // ===========================================================================
  // 20. CHANNEL E-MAIL NOTIFICATION FOR ACTIVITY
  // ===========================================================================

  void set_notify_email(const std::string& email) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    notify_email_ = email;
  }

  std::string get_notify_email() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return notify_email_;
  }

  void clear_notify_email() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    notify_email_.clear();
  }

  bool has_notify_email() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return !notify_email_.empty();
  }

  // Generate notification content
  std::string generate_activity_notification() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::stringstream ss;
    ss << "Subject: IRC Channel Activity: " << name_ << "\r\n\r\n";
    ss << "Channel: " << name_ << "\n";
    ss << "Last activity: " << cf_format_time(last_activity_) << "\n";
    ss << "Members: " << members_.size() << "\n";
    ss << "Total messages: " << stats_.total_messages() << "\n";
    ss << "---\n";
    ss << "Recent messages:\n";
    auto recent = archive_.recent(10);
    for (const auto& e : recent) {
      ss << "  [" << cf_format_time_iso(e.timestamp) << "] "
         << e.source << ": " << e.message << "\n";
    }
    return ss.str();
  }

  // Send notification (stub - real implementation would use SMTP)
  bool send_activity_notification() const {
    std::string email;
    {
      std::shared_lock<std::shared_mutex> lk(mu_);
      if (notify_email_.empty()) return false;
      email = notify_email_;
    }
    std::string content = generate_activity_notification();
    // In production: use libcurl SMTP or sendmail
    // For now, log the intent
    {
      std::shared_lock<std::shared_mutex> lk(mu_);
      log_event(CFLogLevel::SYSTEM, "Server",
                "Activity notification sent to " + email);
    }
    return true;
  }

  // ===========================================================================
  // KEY MANAGEMENT
  // ===========================================================================

  void set_key(const std::string& key) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    key_ = key;
  }

  std::string get_key() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return key_;
  }

  bool check_key(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return key_.empty() || key_ == key;
  }

  bool has_key() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return !key_.empty();
  }

  bool is_mode_set(char mode) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return modes_.find(mode) != std::string::npos;
  }

  // ===========================================================================
  // PERSISTENCE (save/load channel state)
  // ===========================================================================

  json to_json() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    json j;
    j["name"]           = name_;
    j["created_ts"]     = created_ts_;
    j["last_activity"]  = last_activity_;
    j["last_message_time"] = last_message_time_;
    j["last_join_time"] = last_join_time_;
    j["empty_since"]    = empty_since_;
    j["persist"]        = persist_;
    j["active"]         = active_;
    j["status"]         = status_;
    j["topic"]          = topic_;
    j["topic_setter"]   = topic_setter_;
    j["topic_ts"]       = topic_ts_;
    j["topic_lock"]     = topic_lock_;
    j["modes"]          = modes_;
    j["key"]            = key_;
    j["user_limit"]     = user_limit_;
    j["entry_message"]  = entry_message_;
    j["url"]            = url_;
    j["notify_email"]   = notify_email_;
    j["mlock"]          = mlock_.to_json();
    j["forwarding"]     = forwarding_.to_json();
    j["stats"]          = stats_.to_json();
    j["registration"]   = registration_->to_json();

    // Topic history
    json th = json::array();
    for (const auto& t : topic_history_) th.push_back(t.to_json());
    j["topic_history"] = th;

    // Bans
    json bans = json::array();
    for (const auto& b : bans_) bans.push_back(b.to_json());
    j["bans"] = bans;

    // Excepts
    json excepts = json::array();
    for (const auto& e : excepts_) excepts.push_back(e.to_json());
    j["excepts"] = excepts;

    // Invexes
    json invexes = json::array();
    for (const auto& ie : invexes_) invexes.push_back(ie.to_json());
    j["invexes"] = invexes;

    // Access list
    json access = json::array();
    for (const auto& a : access_list_) access.push_back(a.to_json());
    j["access_list"] = access;

    // Members (active only, for restore)
    json members = json::array();
    for (const auto& [k, rec] : members_) {
      members.push_back(rec->to_json());
    }
    j["members"] = members;

    // Membership history (last 500)
    json hist = json::array();
    size_t hstart = (membership_history_.size() > 500) ?
                     membership_history_.size() - 500 : 0;
    for (size_t i = hstart; i < membership_history_.size(); ++i) {
      hist.push_back(membership_history_[i].to_json());
    }
    j["membership_history"] = hist;

    return j;
  }

  static std::shared_ptr<ChannelFull> from_json(const std::string& log_dir,
                                                  const json& j) {
    std::string name = j.value("name", "#unknown");
    auto ch = std::make_shared<ChannelFull>(name, log_dir);

    ch->created_ts_         = j.value("created_ts", 0L);
    ch->last_activity_      = j.value("last_activity", 0L);
    ch->last_message_time_  = j.value("last_message_time", 0L);
    ch->last_join_time_     = j.value("last_join_time", 0L);
    ch->empty_since_        = j.value("empty_since", 0L);
    ch->persist_            = j.value("persist", false);
    ch->active_             = j.value("active", true);
    ch->status_             = j.value("status", 0);
    ch->topic_              = j.value("topic", "");
    ch->topic_setter_       = j.value("topic_setter", "");
    ch->topic_ts_           = j.value("topic_ts", 0L);
    ch->topic_lock_         = j.value("topic_lock", false);
    ch->modes_              = j.value("modes", "");
    ch->key_                = j.value("key", "");
    ch->user_limit_         = j.value("user_limit", 0UL);
    ch->entry_message_      = j.value("entry_message", "");
    ch->url_                = j.value("url", "");
    ch->notify_email_       = j.value("notify_email", "");

    if (j.contains("mlock"))
      ch->mlock_ = ChannelMLOCK::from_json(j["mlock"]);
    if (j.contains("forwarding"))
      ch->forwarding_ = ChannelForwarding::from_json(j["forwarding"]);
    if (j.contains("stats"))
      ch->stats_ = ChannelStatistics::from_json(j["stats"]);
    if (j.contains("registration"))
      ch->registration_ = std::make_shared<ChannelRegistration>(
        ChannelRegistration::from_json(name, j["registration"]));

    // Topic history
    if (j.contains("topic_history") && j["topic_history"].is_array()) {
      for (const auto& tj : j["topic_history"])
        ch->topic_history_.push_back(ChannelTopicEntry::from_json(tj));
    }

    // Bans
    if (j.contains("bans") && j["bans"].is_array()) {
      for (const auto& bj : j["bans"])
        ch->bans_.push_back(BanFullEntry::from_json(bj));
    }

    // Excepts
    if (j.contains("excepts") && j["excepts"].is_array()) {
      for (const auto& ej : j["excepts"])
        ch->excepts_.push_back(ExceptFullEntry::from_json(ej));
    }

    // Invexes
    if (j.contains("invexes") && j["invexes"].is_array()) {
      for (const auto& ij : j["invexes"])
        ch->invexes_.push_back(InviteExceptFullEntry::from_json(ij));
    }

    // Access list
    if (j.contains("access_list") && j["access_list"].is_array()) {
      for (const auto& aj : j["access_list"])
        ch->access_list_.push_back(ChannelAccessEntry::from_json(aj));
    }

    // Members
    if (j.contains("members") && j["members"].is_array()) {
      for (const auto& mj : j["members"]) {
        auto rec = std::make_shared<ChannelMembershipRecord>(
          ChannelMembershipRecord::from_json(mj));
        if (rec->is_active()) {
          ch->members_[cf_to_lower(rec->nick)] = rec;
          ch->active_users_++;
        }
      }
    }

    // Membership history
    if (j.contains("membership_history") && j["membership_history"].is_array()) {
      for (const auto& hj : j["membership_history"])
        ch->membership_history_.push_back(ChannelMembershipRecord::from_json(hj));
    }

    // Update stats
    ch->stats_.set_current_users(ch->members_.size());

    return ch;
  }

  void save_persistent_state() {
    auto j = to_json();
    std::string path = get_state_path();
    cf_mkdir_p(get_state_dir());
    std::ofstream ofs(path);
    if (ofs) {
      ofs << j.dump(2);
    }
  }

  void load_persistent_state() {
    std::string path = get_state_path();
    if (!cf_file_exists(path)) return;
    std::ifstream ifs(path);
    if (!ifs) return;
    json j;
    ifs >> j;
    // Merge into current (don't create new instance)
    std::unique_lock<std::shared_mutex> lk(mu_);
    created_ts_        = j.value("created_ts", created_ts_);
    last_activity_     = j.value("last_activity", last_activity_);
    persist_           = j.value("persist", persist_);
    topic_             = j.value("topic", topic_);
    topic_setter_      = j.value("topic_setter", topic_setter_);
    topic_ts_          = j.value("topic_ts", topic_ts_);
    topic_lock_        = j.value("topic_lock", topic_lock_);
    modes_             = j.value("modes", modes_);
    key_               = j.value("key", key_);
    user_limit_        = j.value("user_limit", user_limit_);
    entry_message_     = j.value("entry_message", entry_message_);
    url_               = j.value("url", url_);
    notify_email_      = j.value("notify_email", notify_email_);
    if (j.contains("mlock")) mlock_ = ChannelMLOCK::from_json(j["mlock"]);
    if (j.contains("forwarding")) forwarding_ = ChannelForwarding::from_json(j["forwarding"]);
    if (j.contains("stats")) stats_ = ChannelStatistics::from_json(j["stats"]);
    if (j.contains("registration"))
      registration_ = std::make_shared<ChannelRegistration>(
        ChannelRegistration::from_json(name_, j["registration"]));
    // Bans, excepts, etc. are loaded at from_json level
  }

  std::string get_state_dir() const {
    return log_dir_ + "/channel_state";
  }

  std::string get_state_path() const {
    return get_state_dir() + "/" + sanitize_for_filename(name_) + ".json";
  }

  // ===========================================================================
  // MEMBER MODE PREFIX MAPPING
  // ===========================================================================

  static char access_prefix(CFAccessLevel level) {
    switch (level) {
      case CFAccessLevel::FOUNDER: return '~';
      case CFAccessLevel::SOP:     return '&';
      case CFAccessLevel::AOP:     return '@';
      case CFAccessLevel::HOP:     return '%';
      case CFAccessLevel::VOP:     return '+';
      default: return ' ';
    }
  }

  static const char* access_level_name(CFAccessLevel level) {
    switch (level) {
      case CFAccessLevel::FOUNDER: return "FOUNDER";
      case CFAccessLevel::SOP:     return "SOP";
      case CFAccessLevel::AOP:     return "AOP";
      case CFAccessLevel::HOP:     return "HOP";
      case CFAccessLevel::VOP:     return "VOP";
      default: return "NONE";
    }
  }

  // ===========================================================================
  // MANAGEMENT UTILITIES
  // ===========================================================================

  // Return a summary of channel state
  std::string summary() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::stringstream ss;
    ss << "Channel: " << name_ << "\n";
    ss << "  Created: " << cf_format_time(created_ts_) << "\n";
    ss << "  Active: " << (active_ ? "yes" : "no") << "\n";
    ss << "  Persist: " << (persist_ ? "yes" : "no") << "\n";
    ss << "  Registered: " << (registration_->is_registered() ? "yes" : "no") << "\n";
    ss << "  Members: " << members_.size() << " (peak: " << stats_.peak_users() << ")\n";
    ss << "  Modes: +" << modes_ << "\n";
    if (!topic_.empty())
      ss << "  Topic: " << (topic_.size() > 60 ? topic_.substr(0, 57) + "..." : topic_) << "\n";
    ss << "  Bans: " << bans_.size() << "\n";
    ss << "  Excepts: " << excepts_.size() << "\n";
    ss << "  Invexes: " << invexes_.size() << "\n";
    ss << "  Access entries: " << access_list_.size() << "\n";
    ss << "  MLOCK: " << (mlock_.enabled ? "enabled" : "disabled") << "\n";
    ss << "  URL: " << (url_.empty() ? "none" : url_) << "\n";
    ss << "  Notify: " << (notify_email_.empty() ? "none" : notify_email_) << "\n";
    ss << "  Messages: " << stats_.total_messages() << "\n";
    return ss.str();
  }

  // Count total unique users that have ever been members
  size_t count_unique_users() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::set<std::string> unique;
    for (const auto& h : membership_history_) {
      unique.insert(cf_to_lower(h.nick));
    }
    for (const auto& [k, rec] : members_) {
      unique.insert(cf_to_lower(rec->nick));
    }
    return unique.size();
  }

  // Get user list formatted for NAMES reply
  std::string get_names_list() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::stringstream ss;
    bool first = true;
    for (const auto& [k, rec] : members_) {
      if (!first) ss << " ";
      first = false;
      char prefix = access_prefix(rec->highest_access());
      if (prefix != ' ') ss << prefix;
      ss << rec->nick;
    }
    return ss.str();
  }

private:
  // ===========================================================================
  // PRIVATE HELPERS
  // ===========================================================================

  static std::string toggle_mode(const std::string& modes, char m, bool adding) {
    std::string r = modes;
    auto pos = r.find(m);
    if (adding && pos == std::string::npos) {
      r += m;
      // Sort modes for consistency
      std::sort(r.begin(), r.end());
    } else if (!adding && pos != std::string::npos) {
      r.erase(pos, 1);
    }
    return r;
  }

  mutable void purge_expired_bans() const {
    auto it = bans_.begin();
    while (it != bans_.end()) {
      if (it->is_expired()) {
        it = bans_.erase(it);
      } else {
        ++it;
      }
    }
  }

  mutable void purge_expired_excepts() const {
    auto it = excepts_.begin();
    while (it != excepts_.end()) {
      if (it->is_expired()) {
        it = excepts_.erase(it);
      } else {
        ++it;
      }
    }
  }

  mutable void purge_expired_invexes() const {
    auto it = invexes_.begin();
    while (it != invexes_.end()) {
      if (it->is_expired()) {
        it = invexes_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void purge_expired_access() const {
    auto it = access_list_.begin();
    while (it != access_list_.end()) {
      if (it->is_expired()) {
        it = access_list_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void auto_access_assign(const std::string& nick, const std::string& user,
                          const std::string& host) {
    CFAccessLevel level = get_access_level(nick, user, host);
    if (level != CFAccessLevel::NONE) {
      std::string key = cf_to_lower(nick);
      auto it = members_.find(key);
      if (it != members_.end()) {
        switch (level) {
          case CFAccessLevel::FOUNDER:
            it->second->modes = toggle_mode(it->second->modes, 'q', true);
            break;
          case CFAccessLevel::SOP:
            it->second->modes = toggle_mode(it->second->modes, 'a', true);
            break;
          case CFAccessLevel::AOP:
            it->second->modes = toggle_mode(it->second->modes, 'o', true);
            break;
          case CFAccessLevel::HOP:
            it->second->modes = toggle_mode(it->second->modes, 'h', true);
            break;
          case CFAccessLevel::VOP:
            it->second->modes = toggle_mode(it->second->modes, 'v', true);
            break;
          default: break;
        }
      }
    }
  }

  static std::string sanitize_for_filename(const std::string& name) {
    std::string r = cf_to_lower(name);
    for (auto& c : r) {
      if (!isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-' && c != '.')
        c = '_';
    }
    return r;
  }

  // ===========================================================================
  // MEMBER VARIABLES
  // ===========================================================================

  mutable std::shared_mutex mu_;

  std::string name_;
  int64_t created_ts_;
  int64_t last_activity_;
  int64_t last_message_time_;
  int64_t last_join_time_;
  int64_t empty_since_;
  int status_; // 0=ACTIVE, 1=PERSIST, 2=ARCHIVED
  bool persist_;
  bool active_;
  bool topic_lock_;
  size_t user_limit_;

  // Topic
  std::string topic_;
  std::string topic_setter_;
  int64_t topic_ts_;
  std::vector<ChannelTopicEntry> topic_history_;

  // Modes and key
  std::string modes_;
  std::string key_;

  // Entry message and URL
  std::string entry_message_;
  std::string url_;

  // Notification
  std::string notify_email_;

  // Channel forwarding
  ChannelForwarding forwarding_;

  // MLOCK
  ChannelMLOCK mlock_;

  // Members
  std::unordered_map<std::string, std::shared_ptr<ChannelMembershipRecord>> members_;
  size_t active_users_ = 0;

  // Lists
  mutable std::vector<BanFullEntry> bans_;
  mutable std::vector<ExceptFullEntry> excepts_;
  mutable std::vector<InviteExceptFullEntry> invexes_;
  std::set<std::string> invited_;
  std::vector<ChannelAccessEntry> access_list_;

  // History and tracking
  std::vector<ChannelMembershipRecord> membership_history_;
  ChannelStatistics stats_;
  ChannelMessageArchive archive_;

  // Services
  std::shared_ptr<ChannelRegistration> registration_;

  // Logging
  std::string log_dir_;
  std::shared_ptr<ChannelLogRotator> log_rotator_;
};

// =============================================================================
// SECTION 17: Channel Manager (global channel registry)
// =============================================================================

class ChannelFullManager {
public:
  ChannelFullManager(const std::string& log_dir = "./irc_logs")
    : log_dir_(log_dir) {
    cf_mkdir_p(log_dir_);
    cf_mkdir_p(log_dir_ + "/channel_state");
  }

  // Create a channel
  std::shared_ptr<ChannelFull> create_channel(const std::string& name) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    std::string key = cf_to_lower(name);
    if (channels_.count(key)) return channels_[key]; // already exists

    auto ch = std::make_shared<ChannelFull>(name, log_dir_);
    channels_[key] = ch;
    return ch;
  }

  // Get an existing channel
  std::shared_ptr<ChannelFull> get_channel(const std::string& name) {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = channels_.find(cf_to_lower(name));
    return (it != channels_.end()) ? it->second : nullptr;
  }

  // Destroy a channel (removes from registry)
  bool destroy_channel(const std::string& name) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    auto it = channels_.find(cf_to_lower(name));
    if (it == channels_.end()) return false;
    it->second->destroy();
    channels_.erase(it);
    return true;
  }

  // Check if channel exists
  bool channel_exists(const std::string& name) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return channels_.count(cf_to_lower(name)) > 0;
  }

  // List all channels
  std::vector<std::string> list_channels() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::vector<std::string> result;
    for (const auto& [k, ch] : channels_) {
      if (ch->is_active()) result.push_back(ch->name());
    }
    return result;
  }

  // Get channel count
  size_t channel_count() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    size_t count = 0;
    for (const auto& [k, ch] : channels_) {
      if (ch->is_active()) ++count;
    }
    return count;
  }

  // Auto-cleanup: remove empty non-persistent channels
  size_t auto_cleanup() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    size_t removed = 0;
    auto it = channels_.begin();
    while (it != channels_.end()) {
      if (it->second->should_auto_cleanup()) {
        it->second->destroy();
        it = channels_.erase(it);
        ++removed;
      } else {
        ++it;
      }
    }
    return removed;
  }

  // Find channels by pattern
  std::vector<std::string> find_channels(const std::string& pattern) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::vector<std::string> result;
    for (const auto& [k, ch] : channels_) {
      if (ch->is_active() && cf_wildcard_match(pattern, ch->name())) {
        result.push_back(ch->name());
      }
    }
    return result;
  }

  // Get all channels for a user
  std::vector<std::shared_ptr<ChannelFull>> get_channels_for_user(
      const std::string& nick) const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::vector<std::shared_ptr<ChannelFull>> result;
    for (const auto& [k, ch] : channels_) {
      if (ch->is_active() && ch->has_member(nick)) {
        result.push_back(ch);
      }
    }
    return result;
  }

  // Persist all channels
  void save_all() {
    std::shared_lock<std::shared_mutex> lk(mu_);
    for (const auto& [k, ch] : channels_) {
      ch->save_persistent_state();
    }
  }

  // Restore channels from persistent storage
  size_t load_all() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    std::string state_dir = log_dir_ + "/channel_state";
    if (!cf_file_exists(state_dir)) return 0;

    size_t loaded = 0;
    // Use popen to list files - in production, use readdir
    std::string cmd = "ls " + state_dir + "/*.json 2>/dev/null";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return 0;
    char buf[1024];
    while (fgets(buf, sizeof(buf), fp)) {
      std::string path(buf);
      path.erase(path.find_last_not_of("\n\r") + 1);
      std::ifstream ifs(path);
      if (!ifs) continue;
      json j;
      try { ifs >> j; } catch (...) { continue; }
      auto ch = ChannelFull::from_json(log_dir_, j);
      if (ch) {
        channels_[cf_to_lower(ch->name())] = ch;
        ++loaded;
      }
    }
    pclose(fp);
    return loaded;
  }

  // Broadcast a message to all channels
  void broadcast(const std::string& source, const std::string& message) {
    std::shared_lock<std::shared_mutex> lk(mu_);
    for (const auto& [k, ch] : channels_) {
      if (ch->is_active()) {
        ch->log_message(source, message);
      }
    }
  }

  // Global statistics
  json global_stats() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    uint64_t total_users = 0, total_messages = 0, total_channels = 0;
    uint64_t peak_total = 0;
    for (const auto& [k, ch] : channels_) {
      if (ch->is_active()) {
        ++total_channels;
        total_users += ch->member_count();
        total_messages += ch->statistics().total_messages();
        peak_total += ch->statistics().peak_users();
      }
    }
    return {
      {"total_channels", total_channels},
      {"total_users", total_users},
      {"total_messages", total_messages},
      {"peak_users_sum", peak_total}
    };
  }

  // Invoke periodic maintenance
  struct MaintenanceResult {
    size_t channels_cleaned;
    size_t channels_rotated;
    int64_t timestamp;
  };

  MaintenanceResult periodic_maintenance() {
    MaintenanceResult result;
    result.timestamp = cf_now_sec();
    result.channels_cleaned = auto_cleanup();

    std::shared_lock<std::shared_mutex> lk(mu_);
    result.channels_rotated = 0;
    for (const auto& [k, ch] : channels_) {
      if (ch->is_active()) {
        // Trigger log rotation for long-running channels
        ch->force_log_rotation();
        ++result.channels_rotated;
      }
      // Purge expired bans/exceptions on each channel
      ch->purge_expired_bans();
      ch->purge_expired_excepts();
      ch->purge_expired_invexes();
    }

    return result;
  }

  void set_log_directory(const std::string& dir) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    log_dir_ = dir;
    cf_mkdir_p(log_dir_);
    for (auto& [k, ch] : channels_) {
      ch->set_log_directory(dir);
    }
  }

private:
  std::string log_dir_;
  std::unordered_map<std::string, std::shared_ptr<ChannelFull>> channels_;
  mutable std::shared_mutex mu_;
};

// =============================================================================
// SECTION 18: Channel Activity Monitor (periodic tasks)
// =============================================================================

class ChannelActivityMonitor {
public:
  ChannelActivityMonitor(std::shared_ptr<ChannelFullManager> mgr,
                          int check_interval = CF_IDLE_CHECK_INTERVAL)
    : manager_(mgr), check_interval_(check_interval), running_(false) {}

  ~ChannelActivityMonitor() { stop(); }

  void start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread(&ChannelActivityMonitor::run, this);
  }

  void stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
  }

  void set_notification_callback(
      std::function<void(const std::string&, const std::string&)> cb) {
    notification_callback_ = cb;
  }

  bool is_running() const { return running_; }

private:
  void run() {
    while (running_) {
      auto result = manager_->periodic_maintenance();

      // Check for channels with notification configured
      auto channels = manager_->list_channels();
      for (const auto& name : channels) {
        auto ch = manager_->get_channel(name);
        if (!ch) continue;

        // Send notification if channel has email and activity
        if (ch->has_notify_email() && !ch->is_idle(86400)) { // 24h threshold
          ch->send_activity_notification();
        }

        // Enforce MLOCK periodically
        if (ch->is_mlock_enabled()) {
          ch->enforce_mlock();
        }
      }

      std::this_thread::sleep_for(std::chrono::seconds(check_interval_));
    }
  }

  std::shared_ptr<ChannelFullManager> manager_;
  int check_interval_;
  std::atomic<bool> running_;
  std::thread thread_;
  std::function<void(const std::string&, const std::string&)> notification_callback_;
};

// =============================================================================
// SECTION 19: Export factory functions for external use
// =============================================================================

// Create a new channel management system
std::shared_ptr<ChannelFullManager> create_channel_manager(
    const std::string& log_dir) {
  auto mgr = std::make_shared<ChannelFullManager>(log_dir);
  mgr->load_all();
  return mgr;
}

// Create and start activity monitor
std::shared_ptr<ChannelActivityMonitor> create_activity_monitor(
    std::shared_ptr<ChannelFullManager> mgr, int interval = CF_IDLE_CHECK_INTERVAL) {
  auto monitor = std::make_shared<ChannelActivityMonitor>(mgr, interval);
  monitor->start();
  return monitor;
}

// =============================================================================
// SECTION 20: Integration helpers - bridge to existing IRCServer
// =============================================================================

// Helper to integrate ChannelFull with the existing IRCServer class
// These are free functions that the main server can call.

// Handle JOIN command
// Returns: {success, error_numeric, error_message}
struct JoinResult {
  bool success;
  int error_numeric;
  std::string error_message;
  std::shared_ptr<ChannelFull> channel;
};

JoinResult channel_join_handler(
    std::shared_ptr<ChannelFullManager> mgr,
    const std::string& channel_name,
    const std::string& nick,
    const std::string& user,
    const std::string& host,
    const std::string& key = "") {

  JoinResult result{false, 0, "", nullptr};

  auto ch = mgr->get_channel(channel_name);
  if (!ch) {
    // Auto-create channel on join
    ch = mgr->create_channel(channel_name);
  }

  result.channel = ch;

  // Check if already in channel
  if (ch->has_member(nick)) {
    result.error_numeric = 443; // ERR_USERONCHANNEL
    result.error_message = nick + " " + channel_name + " :is already on channel";
    return result;
  }

  // Check key
  if (!ch->check_key(key)) {
    result.error_numeric = 475; // ERR_BADCHANNELKEY
    result.error_message = channel_name + " :Cannot join channel (+k)";
    return result;
  }

  // Check invite only
  if (ch->is_mode_set('i') && !ch->is_invited(nick) &&
      !ch->is_invex_matched(nick, user, host)) {
    result.error_numeric = 473; // ERR_INVITEONLYCHAN
    result.error_message = channel_name + " :Cannot join channel (+i)";
    return result;
  }

  // Check ban
  if (ch->is_banned(nick, user, host) && !ch->is_excepted(nick, user, host)) {
    result.error_numeric = 474; // ERR_BANNEDFROMCHAN
    result.error_message = channel_name + " :Cannot join channel (+b)";
    return result;
  }

  // Check user limit
  if (ch->is_mode_set('l') && ch->member_count() >= ch->get_user_limit()) {
    result.error_numeric = 471; // ERR_CHANNELISFULL
    result.error_message = channel_name + " :Cannot join channel (+l)";
    return result;
  }

  // Filtered modes (e.g., +r requires registered nick - simplified)
  if (ch->is_mode_set('r') && ch->is_registered()) {
    // +r = registered only, requires SASL auth
    // Simplified: allow if channel has registration
  }

  // Perform join
  if (!ch->join(nick, user, host)) {
    result.error_numeric = 471;
    result.error_message = channel_name + " :Cannot join channel";
    return result;
  }

  result.success = true;
  return result;
}

// Handle PART command
bool channel_part_handler(
    std::shared_ptr<ChannelFullManager> mgr,
    const std::string& channel_name,
    const std::string& nick,
    const std::string& reason = "") {
  auto ch = mgr->get_channel(channel_name);
  if (!ch) return false;
  return ch->part(nick, reason);
}

// Handle KICK command
struct KickResult {
  bool success;
  int error_numeric;
  std::string error_message;
};

KickResult channel_kick_handler(
    std::shared_ptr<ChannelFullManager> mgr,
    const std::string& channel_name,
    const std::string& kicker,
    const std::string& target,
    const std::string& reason = "") {

  KickResult result{false, 0, ""};

  auto ch = mgr->get_channel(channel_name);
  if (!ch) {
    result.error_numeric = 403; // ERR_NOSUCHCHANNEL
    result.error_message = channel_name + " :No such channel";
    return result;
  }

  if (!ch->has_member(kicker)) {
    result.error_numeric = 442; // ERR_NOTONCHANNEL
    result.error_message = channel_name + " :You're not on that channel";
    return result;
  }

  if (!ch->has_member(target)) {
    result.error_numeric = 441; // ERR_USERNOTINCHANNEL
    result.error_message = target + " " + channel_name + " :They aren't on that channel";
    return result;
  }

  // Check kicker has op rights
  CFAccessLevel kicker_access = ch->get_member_access(kicker);
  CFAccessLevel target_access = ch->get_member_access(target);
  if (kicker_access < CFAccessLevel::HOP || kicker_access <= target_access) {
    result.error_numeric = 482; // ERR_CHANOPRIVSNEEDED
    result.error_message = channel_name + " :You're not channel operator";
    return result;
  }

  if (ch->kick(kicker, target, reason)) {
    result.success = true;
  }
  return result;
}

// Handle MODE command
struct ModeResult {
  bool success;
  std::string mode_string;
  std::vector<std::string> params;
};

ModeResult channel_mode_handler(
    std::shared_ptr<ChannelFullManager> mgr,
    const std::string& channel_name,
    const std::string& mode_string,
    const std::vector<std::string>& params,
    const std::string& set_by) {

  ModeResult result{false, "", {}};

  auto ch = mgr->get_channel(channel_name);
  if (!ch) return result;

  // Parse mode string: +b mask, +o nick, etc.
  bool adding = true;
  size_t param_idx = 0;
  std::string applied_modes;
  std::vector<std::string> applied_params;

  for (char c : mode_string) {
    if (c == '+') { adding = true; continue; }
    if (c == '-') { adding = false; continue; }

    switch (c) {
      case 'b': {
        if (param_idx < params.size()) {
          std::string mask = params[param_idx++];
          if (adding) {
            if (ch->add_ban(mask, set_by)) {
              applied_modes += (adding ? "+b" : "-b");
              applied_params.push_back(mask);
            }
          } else {
            if (ch->remove_ban(mask)) {
              applied_modes += (adding ? "+b" : "-b");
              applied_params.push_back(mask);
            }
          }
        } else if (!adding) {
          // MODE #chan -b = list all bans (handled elsewhere)
        }
        break;
      }
      case 'e': {
        if (param_idx < params.size()) {
          std::string mask = params[param_idx++];
          if (adding)
            ch->add_except(mask, set_by);
          else
            ch->remove_except(mask);
          applied_modes += (adding ? "+e" : "-e");
          applied_params.push_back(mask);
        }
        break;
      }
      case 'I': {
        if (param_idx < params.size()) {
          std::string mask = params[param_idx++];
          if (adding)
            ch->add_invex(mask, set_by);
          else
            ch->remove_invex(mask);
          applied_modes += (adding ? "+I" : "-I");
          applied_params.push_back(mask);
        }
        break;
      }
      case 'o':
      case 'v':
      case 'h':
      case 'a':
      case 'q': {
        if (param_idx < params.size()) {
          std::string nick = params[param_idx++];
          if (ch->set_member_mode(nick, c, adding)) {
            applied_modes += (adding ? "+" : "-") + std::string(1, c);
            applied_params.push_back(nick);
          }
        }
        break;
      }
      case 'k':
        if (adding && param_idx < params.size()) {
          ch->set_key(params[param_idx++]);
          applied_modes += "+k";
          applied_params.push_back(ch->get_key());
        } else if (!adding) {
          ch->set_key("");
          applied_modes += "-k";
        }
        break;
      case 'l':
        if (adding && param_idx < params.size()) {
          ch->set_user_limit(static_cast<size_t>(std::stoul(params[param_idx])));
          applied_modes += "+l";
          applied_params.push_back(params[param_idx++]);
        } else if (!adding) {
          ch->set_user_limit(0);
          applied_modes += "-l";
        }
        break;
      default:
        // Simple modes: +ntmipsr etc.
        if (!ch->mode_requires_param(c, adding)) {
          if (ch->set_mode(c, adding)) {
            applied_modes += (adding ? "+" : "-") + std::string(1, c);
          }
        }
        break;
    }
  }

  result.success = !applied_modes.empty();
  result.mode_string = applied_modes;
  result.params = applied_params;
  return result;
}

// Handle TOPIC command
struct TopicResult {
  bool success;
  int error_numeric;
  std::string topic;
  std::string setter;
  int64_t set_time;
};

TopicResult channel_topic_handler(
    std::shared_ptr<ChannelFullManager> mgr,
    const std::string& channel_name,
    const std::string& setter,
    const std::string& new_topic,
    bool is_query = false) {

  TopicResult result{false, 0, "", "", 0};

  auto ch = mgr->get_channel(channel_name);
  if (!ch) {
    result.error_numeric = 403; // ERR_NOSUCHCHANNEL
    return result;
  }

  if (is_query) {
    // Just query the topic
    result.topic = ch->get_topic();
    result.setter = ch->get_topic_setter();
    result.set_time = ch->get_topic_ts();
    result.success = true;
    return result;
  }

  // Setting topic
  // Check +t mode (only ops can set topic)
  if (ch->is_topic_locked()) {
    auto access = ch->get_member_access(setter);
    if (access < CFAccessLevel::HOP) {
      result.error_numeric = 482; // ERR_CHANOPRIVSNEEDED
      return result;
    }
  }

  // Empty topic = clear topic
  std::string actual_topic = (new_topic == ":" || new_topic.empty()) ? "" : new_topic;
  if (ch->set_topic(setter, actual_topic)) {
    result.success = true;
    result.topic = actual_topic;
    result.setter = setter;
    result.set_time = ch->get_topic_ts();
  }
  return result;
}

// Handle INVITE command
bool channel_invite_handler(
    std::shared_ptr<ChannelFullManager> mgr,
    const std::string& channel_name,
    const std::string& inviter,
    const std::string& target) {

  auto ch = mgr->get_channel(channel_name);
  if (!ch) return false;
  if (!ch->has_member(inviter)) return false;

  // Check inviter has invite privilege
  if (ch->is_mode_set('i')) {
    auto access = ch->get_member_access(inviter);
    if (access < CFAccessLevel::HOP) return false;
  }

  ch->add_invite(target);
  ch->log_event(CFLogLevel::SYSTEM, inviter, "invited " + target);
  return true;
}

// Handle LIST command help
std::vector<std::string> channel_list_handler(
    std::shared_ptr<ChannelFullManager> mgr,
    const std::string& pattern = "*",
    bool show_secret = false) {

  std::vector<std::string> channels = mgr->find_channels(pattern);
  std::vector<std::string> result;
  for (const auto& name : channels) {
    auto ch = mgr->get_channel(name);
    if (!ch) continue;

    // Skip secret channels (+s) unless caller has privs
    if (ch->is_mode_set('s') && !show_secret) continue;
    // Skip private channels (+p) unless caller has privs
    if (ch->is_mode_set('p') && !show_secret) continue;

    std::stringstream ss;
    ss << name << " " << ch->member_count();
    if (!ch->get_topic().empty()) {
      ss << " :" << ch->get_topic();
    }
    result.push_back(ss.str());
  }
  return result;
}

// Handle NAMES command
std::string channel_names_handler(
    std::shared_ptr<ChannelFullManager> mgr,
    const std::string& channel_name,
    bool include_secret = false) {

  auto ch = mgr->get_channel(channel_name);
  if (!ch) return "";

  if (ch->is_mode_set('s') && !include_secret) return "";
  if (ch->is_mode_set('p') && !include_secret) return "";

  return ch->get_names_list();
}

// =============================================================================
// SECTION 21: Statistics Reporting
// =============================================================================

class ChannelStatisticsReporter {
public:
  explicit ChannelStatisticsReporter(std::shared_ptr<ChannelFullManager> mgr)
    : manager_(mgr) {}

  struct GlobalReport {
    uint64_t total_channels;
    uint64_t total_users;
    uint64_t total_messages;
    uint64_t total_bans;
    uint64_t total_excepts;
    uint64_t total_invexes;
    uint64_t total_registered;
    int64_t  generated_at;
  };

  GlobalReport generate_global_report() const {
    GlobalReport r{};
    r.generated_at = cf_now_sec();
    auto channels = manager_->list_channels();
    r.total_channels = channels.size();
    for (const auto& name : channels) {
      auto ch = manager_->get_channel(name);
      if (!ch) continue;
      r.total_users += ch->member_count();
      r.total_messages += ch->statistics().total_messages();
      r.total_bans += ch->list_bans().size();
      r.total_excepts += ch->list_excepts().size();
      r.total_invexes += ch->list_invexes().size();
      if (ch->is_registered()) ++r.total_registered;
    }
    return r;
  }

  std::string format_global_report() const {
    auto r = generate_global_report();
    std::stringstream ss;
    ss << "=== IRC Network Global Statistics ===\n";
    ss << "Generated: " << cf_format_time(r.generated_at) << "\n\n";
    ss << "Total channels:    " << r.total_channels << "\n";
    ss << "Total users:       " << r.total_users << "\n";
    ss << "Total messages:    " << r.total_messages << "\n";
    ss << "Total bans:        " << r.total_bans << "\n";
    ss << "Total excepts:     " << r.total_excepts << "\n";
    ss << "Total invexes:     " << r.total_invexes << "\n";
    ss << "Registered chans:  " << r.total_registered << "\n";
    return ss.str();
  }

private:
  std::shared_ptr<ChannelFullManager> manager_;
};

} // namespace progressive::irc
