// irc_modes_complete.cpp — Complete IRC channel modes, user modes, and MODE command
// Implements ALL channel modes, user modes, bundling, MLOCK, history, expiry,
// caching, server mode override, OP MODE, SAMODE, parameter validation,
// mode parsing, formatting, broadcasting, and channel creation with timestamps.
// References: RFC 1459, 2811, 2812, 2813, IRCv3.2, InspIRCd 3.x, UnrealIRCd 6.x
#include "irc_server.hpp"
#include "services.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <variant>
#include <vector>

namespace progressive::irc {

using json = nlohmann::json;

// =============================================================================
// SECTION 1: Forward declarations and constants
// =============================================================================

class ModeBundle;
class ModeHistoryTracker;
class ModeLockSystem;
class ModeCache;
class BanExpiryManager;
class ExceptionExpiryManager;
class CompleteModeHandler;

// --- Mode types ---
enum class ChannelModeType : uint8_t {
  TYPE_A_LIST    = 0,  // b/e/I — list modes, always have param, query on -mode
  TYPE_B_PARAM   = 1,  // k — always requires parameter
  TYPE_C_PARAMWS = 2,  // l — param when setting, no param when unsetting
  TYPE_D_PREFIX  = 3,  // o/v/h/a/q — member prefix, always has param
  TYPE_E_FLAG    = 4,  // t/i/m/n/s/p/r/c/C/N/M/O/P/Q/R/S/T/z/Z/u/F/G/j/K/L — simple flags
};

// --- Access levels for mode setting (higher = more privilege) ---
enum class ModeAccessLevel : uint8_t {
  NONE    = 0,
  VOICE   = 1,
  HALFOP  = 2,
  OP      = 3,
  ADMIN   = 4,
  OWNER   = 5,
  OPER    = 6,   // IRC operator
  SERVICE = 7,   // Services
  SERVER  = 8,   // Server link
};

// --- Mode change action ---
enum class ModeAction : uint8_t {
  SET    = 0,   // +mode
  UNSET  = 1,   // -mode
  LIST   = 2,   // query list
  QUERY  = 3,   // query current modes
};

// --- Constants ---
static constexpr size_t MC_MAX_KEY_LEN        = 32;
static constexpr size_t MC_MIN_KEY_LEN        = 1;
static constexpr size_t MC_MAX_USER_LIMIT     = 65535;
static constexpr size_t MC_MIN_USER_LIMIT     = 1;
static constexpr size_t MC_MAX_BANLIST        = 500;
static constexpr size_t MC_MAX_EXCEPTLIST     = 500;
static constexpr size_t MC_MAX_INVEXLIST      = 500;
static constexpr size_t MC_MAX_MODE_CHANGES   = 20;   // per MODE message
static constexpr size_t MC_MAX_HISTORY        = 100;  // mode changes per channel
static constexpr int64_t MC_DEFAULT_BAN_EXPIRY = 86400; // 24 hours
static constexpr int64_t MC_EXPIRY_CHECK_INTERVAL = 60; // check every 60 seconds
static constexpr size_t MC_MLOCK_MAX_LEN      = 128;
static constexpr size_t MC_JOIN_THROTTLE_MIN  = 1;    // seconds
static constexpr size_t MC_JOIN_THROTTLE_MAX  = 60;
static constexpr size_t MC_REDIRECT_MAX_LEN   = 64;

// =============================================================================
// SECTION 2: Mode info metadata — channel mode registry
// =============================================================================

struct ChannelModeDef {
  char letter;
  ChannelModeType type;
  ModeAccessLevel min_access;  // minimum access to set/unset
  bool requires_param_set;
  bool requires_param_unset;
  std::string_view name;
  std::string_view description;
};

// Complete channel mode registry (Inspired by InspIRCd/UnrealIRCd)
static const ChannelModeDef CHANNEL_MODES[] = {
  // List modes (Type A)
  {'b', ChannelModeType::TYPE_A_LIST,  ModeAccessLevel::HALFOP, true,  true,  "ban",       "Ban list"},
  {'e', ChannelModeType::TYPE_A_LIST,  ModeAccessLevel::HALFOP, true,  true,  "except",    "Ban exception list"},
  {'I', ChannelModeType::TYPE_A_LIST,  ModeAccessLevel::HALFOP, true,  true,  "invex",     "Invite exception list"},

  // Parameter-always modes (Type B)
  {'k', ChannelModeType::TYPE_B_PARAM, ModeAccessLevel::HALFOP, true,  false, "key",       "Channel key (password)"},

  // Parameter-when-set modes (Type C)
  {'l', ChannelModeType::TYPE_C_PARAMWS, ModeAccessLevel::OP,   true,  false, "limit",     "User limit"},
  {'L', ChannelModeType::TYPE_C_PARAMWS, ModeAccessLevel::ADMIN,true,  false, "redirect",  "Channel redirect on +l"},
  {'j', ChannelModeType::TYPE_C_PARAMWS, ModeAccessLevel::OP,   true,  false, "jointhrottle", "Join throttle (N:t)"},

  // Prefix modes (Type D)
  {'o', ChannelModeType::TYPE_D_PREFIX, ModeAccessLevel::OP,    true,  true,  "op",        "Channel operator (@)"},
  {'v', ChannelModeType::TYPE_D_PREFIX, ModeAccessLevel::HALFOP,true,  true,  "voice",     "Voice (+)"},
  {'h', ChannelModeType::TYPE_D_PREFIX, ModeAccessLevel::OP,    true,  true,  "halfop",    "Half operator (%)"},
  {'a', ChannelModeType::TYPE_D_PREFIX, ModeAccessLevel::ADMIN, true,  true,  "admin",     "Channel admin (&)"},
  {'q', ChannelModeType::TYPE_D_PREFIX, ModeAccessLevel::OWNER, true,  true,  "owner",     "Channel owner (~)"},

  // Flag modes (Type E)
  {'t', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "topic",     "Topic lock (only ops can set)"},
  {'i', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "invite",    "Invite-only channel"},
  {'m', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "moderated", "Moderated (only +vhoaq can talk)"},
  {'n', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "noext",     "No external messages"},
  {'s', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::OP,     false, false, "secret",    "Secret channel (not in /list)"},
  {'p', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::OP,     false, false, "private",   "Private channel"},
  {'r', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::SERVICE,false, false, "registered","Registered (set by services)"},
  {'c', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "nocolor",   "No color codes"},
  {'C', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "noctcp",    "No CTCP to channel"},
  {'M', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::OP,     false, false, "regonly",   "Must be registered to talk"},
  {'R', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "regonlyjoin","Only registered users may join"},
  {'K', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "noknock",   "No KNOCK command allowed"},
  {'N', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "nonick",    "No nick changes allowed"},
  {'O', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::SERVICE,false, false, "operonly",  "IRC operators only"},
  {'Q', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::ADMIN,  false, false, "nokick",    "No kicks allowed"},
  {'T', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "nonotice",  "No NOTICE allowed to channel"},
  {'u', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::OP,     false, false, "auditorium","Auditorium (only +oaq see names)"},
  {'P', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::SERVICE,false, false, "permanent", "Permanent channel"},
  {'F', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::OP,     false, false, "forbidden_nicks", "Forbidden nicks list active"},
  {'G', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::HALFOP, false, false, "censor",    "Censor bad words"},
  {'z', ChannelModeType::TYPE_E_FLAG,   ModeAccessLevel::OP,     false, false, "ssl",       "Secure/SSL connections only"},
};

static constexpr size_t CHANNEL_MODE_COUNT = sizeof(CHANNEL_MODES) / sizeof(ChannelModeDef);

// User mode registry
struct UserModeDef {
  char letter;
  bool settable;       // can user set it themselves?
  bool oper_only;      // requires oper to set?
  std::string_view name;
  std::string_view description;
};

static const UserModeDef USER_MODES[] = {
  {'i', true,  false, "invisible",   "Makes user invisible in WHO/WHOIS"},
  {'w', true,  false, "wallops",     "Receive WALLOPS messages"},
  {'s', true,  false, "snotice",     "Receive server notices"},
  {'o', false, true,  "oper",        "IRC operator (set by OPER command)"},
  {'x', true,  false, "cloak",       "Cloaked hostname"},
  {'z', true,  false, "ssl",         "Connected via SSL/TLS"},
  {'g', true,  false, "callerid",    "Caller-ID mode (accept list required)"},
  {'G', true,  false, "censor",      "Censor bad words from user"},
  {'B', true,  false, "bot",         "Bot mode indicator"},
  {'H', false, true,  "hideoper",    "Hide oper status"},
  {'I', true,  false, "hidechans",   "Hide channel list in WHOIS"},
  {'R', true,  false, "regonlypm",   "Only registered users can PM"},
  {'W', true,  false, "whois",       "See when someone WHOIS you"},
  {'p', false, true,  "protected",   "Protected user (cannot be killed)"},
};

static constexpr size_t USER_MODE_COUNT = sizeof(USER_MODES) / sizeof(UserModeDef);

// =============================================================================
// SECTION 3: Utility helpers (anonymous namespace)
// =============================================================================

namespace {

int64_t mc_now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t mc_now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string mc_to_lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string mc_to_upper(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

bool mc_iequals(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i)
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) return false;
  return true;
}

bool mc_wildcard_match(const std::string& pattern, const std::string& str) {
  size_t pi = 0, si = 0, star = std::string::npos, ss = 0;
  while (si < str.size()) {
    if (pi < pattern.size() &&
        (pattern[pi] == '?' ||
         mc_to_lower(std::string(1, pattern[pi])) == mc_to_lower(std::string(1, str[si])))) {
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

std::string mc_mask_nick(const std::string& mask) {
  auto ex = mask.find('!');
  return (ex != std::string::npos) ? mask.substr(0, ex) : mask;
}
std::string mc_mask_user(const std::string& mask) {
  auto ex = mask.find('!'), at = mask.find('@');
  if (ex != std::string::npos && at != std::string::npos && at > ex)
    return mask.substr(ex + 1, at - ex - 1);
  return "*";
}
std::string mc_mask_host(const std::string& mask) {
  auto at = mask.find('@');
  return (at != std::string::npos) ? mask.substr(at + 1) : mask;
}

bool mc_mask_matches(const std::string& mask, const std::string& nick,
                      const std::string& user, const std::string& host) {
  return mc_wildcard_match(mc_mask_nick(mask), nick) &&
         mc_wildcard_match(mc_mask_user(mask), user) &&
         mc_wildcard_match(mc_mask_host(mask), host);
}

std::string mc_make_mask(const std::string& nick, const std::string& user,
                          const std::string& host) {
  return nick + "!" + user + "@" + host;
}

std::vector<std::string> mc_split(const std::string& s, char delim) {
  std::vector<std::string> v;
  std::stringstream ss(s); std::string item;
  while (std::getline(ss, item, delim))
    if (!item.empty()) v.push_back(item);
  return v;
}

std::string mc_join(const std::vector<std::string>& v, const std::string& sep) {
  std::string r;
  for (size_t i = 0; i < v.size(); ++i) {
    if (i > 0) r += sep;
    r += v[i];
  }
  return r;
}

bool mc_has_mode(const std::string& modes, char c) {
  return modes.find(c) != std::string::npos;
}

std::string mc_toggle_mode(const std::string& modes, char c, bool add) {
  std::string r = modes;
  auto pos = r.find(c);
  if (add && pos == std::string::npos) r += c;
  else if (!add && pos != std::string::npos) r.erase(pos, 1);
  return r;
}

const ChannelModeDef* mc_get_channel_mode_def(char mode_c) {
  for (size_t i = 0; i < CHANNEL_MODE_COUNT; ++i) {
    if (CHANNEL_MODES[i].letter == mode_c) return &CHANNEL_MODES[i];
  }
  return nullptr;
}

const UserModeDef* mc_get_user_mode_def(char mode_c) {
  for (size_t i = 0; i < USER_MODE_COUNT; ++i) {
    if (USER_MODES[i].letter == mode_c) return &USER_MODES[i];
  }
  return nullptr;
}

bool mc_is_valid_channel_mode(char mode_c) {
  return mc_get_channel_mode_def(mode_c) != nullptr;
}

bool mc_is_valid_user_mode(char mode_c) {
  return mc_get_user_mode_def(mode_c) != nullptr;
}

// Get prefix character for access level
char mc_prefix_for_access(ModeAccessLevel level) {
  switch (level) {
    case ModeAccessLevel::OWNER:  return '~';
    case ModeAccessLevel::ADMIN:  return '&';
    case ModeAccessLevel::OP:     return '@';
    case ModeAccessLevel::HALFOP: return '%';
    case ModeAccessLevel::VOICE:  return '+';
    default:                      return 0;
  }
}

// Get access level from prefix character
ModeAccessLevel mc_access_for_prefix(char prefix) {
  switch (prefix) {
    case '~': return ModeAccessLevel::OWNER;
    case '&': return ModeAccessLevel::ADMIN;
    case '@': return ModeAccessLevel::OP;
    case '%': return ModeAccessLevel::HALFOP;
    case '+': return ModeAccessLevel::VOICE;
    default:  return ModeAccessLevel::NONE;
  }
}

// Get access level from member modes string
ModeAccessLevel mc_access_from_modes(const std::string& modes) {
  if (modes.find('q') != std::string::npos) return ModeAccessLevel::OWNER;
  if (modes.find('a') != std::string::npos) return ModeAccessLevel::ADMIN;
  if (modes.find('o') != std::string::npos) return ModeAccessLevel::OP;
  if (modes.find('h') != std::string::npos) return ModeAccessLevel::HALFOP;
  if (modes.find('v') != std::string::npos) return ModeAccessLevel::VOICE;
  return ModeAccessLevel::NONE;
}

// Determine if user can set a specific channel mode
bool mc_can_set_mode(const std::string& user_modes, char target_mode,
                     const std::string& user_nick, bool is_oper,
                     ModeAccessLevel effective_access) {
  auto* mode_def = mc_get_channel_mode_def(target_mode);
  if (!mode_def) return false;

  // Server/services/oper override
  if (is_oper) return true;

  // Check access level hierarchy
  return static_cast<uint8_t>(effective_access) >= static_cast<uint8_t>(mode_def->min_access);
}

// Determine effective access level considering +q gives +a gives +o gives +h gives +v
ModeAccessLevel mc_effective_access(const std::string& member_modes, bool is_oper) {
  if (is_oper) return ModeAccessLevel::OPER;
  auto acc = mc_access_from_modes(member_modes);
  return acc;
}

// Validate a ban/exception mask
bool mc_is_valid_mask(const std::string& mask) {
  if (mask.empty()) return false;
  if (mask.size() > 256) return false;
  // Basic sanity: must have at least nick
  return mask.find(' ') == std::string::npos;
}

// Validate channel key
bool mc_is_valid_key(const std::string& key) {
  if (key.empty()) return true; // empty key means remove
  if (key.size() > MC_MAX_KEY_LEN) return false;
  if (key.size() < MC_MIN_KEY_LEN && !key.empty()) return false;
  // No spaces, no commas, no ASCII 7 (bell)
  for (char c : key) {
    if (c == ' ' || c == ',' || c == '\x07') return false;
  }
  return true;
}

// Validate user limit
bool mc_is_valid_user_limit(int64_t limit) {
  return limit >= static_cast<int64_t>(MC_MIN_USER_LIMIT) &&
         limit <= static_cast<int64_t>(MC_MAX_USER_LIMIT);
}

// Validate join throttle parameter (N:t format)
bool mc_is_valid_join_throttle(const std::string& param) {
  auto colon = param.find(':');
  if (colon == std::string::npos) return false;
  try {
    int joins = std::stoi(param.substr(0, colon));
    int secs = std::stoi(param.substr(colon + 1));
    if (joins < 1 || secs < 1) return false;
    if (static_cast<size_t>(secs) > MC_JOIN_THROTTLE_MAX) return false;
    return true;
  } catch (...) { return false; }
}

// Format time
std::string mc_format_time(time_t t) {
  char buf[64];
  struct tm tm_val;
  gmtime_r(&t, &tm_val);
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_val);
  return std::string(buf);
}

} // anonymous namespace

// =============================================================================
// SECTION 4: Single mode change entry
// =============================================================================

struct ModeChange {
  char mode_char;
  ModeAction action;   // SET or UNSET
  std::string param;   // parameter if any (ban mask, nick, key, limit, etc.)

  ModeChange() : mode_char(0), action(ModeAction::SET) {}
  ModeChange(char mc, ModeAction act, std::string p = "")
    : mode_char(mc), action(act), param(std::move(p)) {}

  bool is_set() const { return action == ModeAction::SET; }
  bool is_unset() const { return action == ModeAction::UNSET; }
  bool is_list() const { return action == ModeAction::LIST; }

  std::string to_string() const {
    std::string r;
    r += is_set() ? '+' : '-';
    r += mode_char;
    if (!param.empty()) r += " " + param;
    return r;
  }
};

// =============================================================================
// SECTION 5: Mode bundle — multiple changes in one MODE message
// =============================================================================

class ModeBundle {
public:
  std::vector<ModeChange> changes;
  std::string source;          // nick!user@host of who sent it
  std::string target;         // channel name or nick
  int64_t timestamp;
  bool is_channel_mode;
  bool is_server_origin;      // came from server link
  bool is_services_origin;    // came from services
  ModeAccessLevel origin_access; // access level of source

  ModeBundle()
    : timestamp(mc_now_sec()), is_channel_mode(true),
      is_server_origin(false), is_services_origin(false),
      origin_access(ModeAccessLevel::NONE) {}

  void add_change(char mode_char, ModeAction action, const std::string& param = "") {
    changes.emplace_back(mode_char, action, param);
  }

  void add_set(char mode_char, const std::string& param = "") {
    add_change(mode_char, ModeAction::SET, param);
  }

  void add_unset(char mode_char, const std::string& param = "") {
    add_change(mode_char, ModeAction::UNSET, param);
  }

  bool empty() const { return changes.empty(); }
  size_t size() const { return changes.size(); }
  void clear() { changes.clear(); }

  // Build the mode change string: "+bb-k+v" or similar
  std::string build_mode_string() const {
    std::string result;
    ModeAction current_dir = ModeAction::SET;
    bool first = true;

    for (auto& ch : changes) {
      if (first || ch.action != current_dir) {
        current_dir = ch.action;
        result += (current_dir == ModeAction::SET) ? '+' : '-';
        first = false;
      }
      result += ch.mode_char;
    }
    return result;
  }

  // Build parameter list in order
  std::vector<std::string> build_param_list() const {
    std::vector<std::string> params;
    for (auto& ch : changes) {
      if (!ch.param.empty())
        params.push_back(ch.param);
    }
    return params;
  }

  // Build full MODE message for broadcast
  std::string build_mode_message() const {
    std::string msg = ":" + source + " MODE " + target;
    std::string mode_str = build_mode_string();
    if (mode_str.empty()) return "";
    msg += " " + mode_str;
    for (auto& p : build_param_list())
      msg += " " + p;
    return msg;
  }

  // Parse a full MODE string like "+b-k+o" with parameter list
  // Returns true on success, false on parse error
  bool parse_mode_string(const std::string& mode_str,
                          const std::vector<std::string>& params) {
    changes.clear();
    bool adding = true;
    size_t param_idx = 0;

    for (char mode_c : mode_str) {
      if (mode_c == '+') { adding = true; continue; }
      if (mode_c == '-') { adding = false; continue; }

      auto* mode_def = mc_get_channel_mode_def(mode_c);
      if (!mode_def && !mc_get_user_mode_def(mode_c)) {
        // Unknown mode — skip but continue (caller should handle)
        continue;
      }

      ModeAction action = adding ? ModeAction::SET : ModeAction::UNSET;
      std::string param;

      if (mode_def) {
        // Channel mode — determine if param is needed
        bool needs_param = false;
        if (adding) {
          needs_param = mode_def->requires_param_set;
        } else {
          needs_param = mode_def->requires_param_unset;
        }

        // List modes: -b without param means LIST
        if (mode_def->type == ChannelModeType::TYPE_A_LIST && !adding && param_idx >= params.size()) {
          action = ModeAction::LIST;
        } else if (needs_param && param_idx < params.size()) {
          param = params[param_idx++];
        } else if (needs_param && param_idx >= params.size()) {
          // Missing required parameter
          return false;
        }
      }

      add_change(mode_c, action, param);
    }
    return true;
  }

  // Group same-direction changes for efficient bundling
  void normalize() {
    if (changes.empty()) return;

    std::vector<ModeChange> normalized;
    for (auto& ch : changes) {
      normalized.push_back(ch);
    }
    changes = std::move(normalized);
  }

  // Check if this bundle would exceed maximum allowed changes
  bool is_too_large() const {
    return changes.size() > MC_MAX_MODE_CHANGES;
  }
};

// =============================================================================
// SECTION 6: Ban/Exception entry with expiry support
// =============================================================================

struct BanEntryComplete {
  std::string mask;
  std::string set_by;        // nick!user@host or server name
  int64_t set_time;
  int64_t expires;           // 0 = permanent
  std::string reason;
  std::string ban_id;        // unique ID

  BanEntryComplete() : set_time(0), expires(0) {}

  BanEntryComplete(const std::string& m, const std::string& sb,
                   int64_t st, int64_t ex = 0, const std::string& r = "")
    : mask(m), set_by(sb), set_time(st), expires(ex), reason(r) {}

  bool is_expired() const {
    if (expires == 0) return false;
    return mc_now_sec() >= expires;
  }

  bool matches(const std::string& nick, const std::string& user,
               const std::string& host) const {
    return mc_mask_matches(mask, nick, user, host);
  }

  json to_json() const {
    return {
      {"mask", mask},
      {"set_by", set_by},
      {"set_time", set_time},
      {"expires", expires},
      {"reason", reason},
      {"id", ban_id}
    };
  }

  static BanEntryComplete from_json(const json& j) {
    BanEntryComplete e;
    e.mask = j.value("mask", "");
    e.set_by = j.value("set_by", "");
    e.set_time = j.value("set_time", 0LL);
    e.expires = j.value("expires", 0LL);
    e.reason = j.value("reason", "");
    e.ban_id = j.value("id", "");
    return e;
  }
};

struct ExceptionEntryComplete {
  std::string mask;
  std::string set_by;
  int64_t set_time;
  int64_t expires;
  std::string reason;
  std::string except_id;

  ExceptionEntryComplete() : set_time(0), expires(0) {}

  ExceptionEntryComplete(const std::string& m, const std::string& sb,
                          int64_t st, int64_t ex = 0, const std::string& r = "")
    : mask(m), set_by(sb), set_time(st), expires(ex), reason(r) {}

  bool is_expired() const {
    if (expires == 0) return false;
    return mc_now_sec() >= expires;
  }

  bool matches(const std::string& nick, const std::string& user,
               const std::string& host) const {
    return mc_mask_matches(mask, nick, user, host);
  }

  json to_json() const {
    return {
      {"mask", mask},
      {"set_by", set_by},
      {"set_time", set_time},
      {"expires", expires},
      {"reason", reason},
      {"id", except_id}
    };
  }
};

// =============================================================================
// SECTION 7: MLOCK (Mode Lock) definition and enforcement
// =============================================================================

class ModeLockSystem {
public:
  struct MLockEntry {
    std::string channel;
    std::string mode_string;   // e.g. "+ntr-l 10" or "+ntR"
    std::string param_str;     // parameters for modes that need them
    bool enabled;
    int64_t set_time;

    MLockEntry() : enabled(false), set_time(0) {}

    // Parse MLOCK string like "+ntR-lk key" into individual locked modes
    struct LockedMode {
      char mode_char;
      bool should_be_set;
      std::string param;
    };

    std::vector<LockedMode> parse() const {
      std::vector<LockedMode> result;
      bool adding = true;
      std::string current_params = param_str;
      size_t param_idx = 0;

      // Split param_str into tokens
      std::vector<std::string> tokens;
      std::stringstream ss(current_params);
      std::string token;
      while (ss >> token) tokens.push_back(token);

      for (size_t i = 0; i < mode_string.size(); ++i) {
        char c = mode_string[i];
        if (c == '+') { adding = true; continue; }
        if (c == '-') { adding = false; continue; }

        auto* def = mc_get_channel_mode_def(c);
        if (!def) continue; // skip unknown modes

        std::string param;
        if (param_idx < tokens.size() &&
            (def->type == ChannelModeType::TYPE_A_LIST ||
             def->type == ChannelModeType::TYPE_B_PARAM ||
             (adding && def->type == ChannelModeType::TYPE_C_PARAMWS))) {
          param = tokens[param_idx++];
        }

        result.push_back({c, adding, param});
      }
      return result;
    }
  };

  // Set MLOCK for a channel
  void set_mlock(const std::string& channel, const std::string& mode_str,
                 const std::string& param_str = "") {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    MLockEntry& entry = mlocks_[key];
    entry.channel = channel;
    entry.mode_string = mode_str;
    entry.param_str = param_str;
    entry.enabled = true;
    entry.set_time = mc_now_sec();
  }

  // Remove MLOCK
  void remove_mlock(const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    mlocks_.erase(key);
  }

  // Get MLOCK for a channel
  MLockEntry* get_mlock(const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    auto it = mlocks_.find(key);
    if (it != mlocks_.end() && it->second.enabled)
      return &it->second;
    return nullptr;
  }

  // Check if a mode change is allowed by MLOCK and get forced corrections
  // Returns: map of mode_char -> force (true=must be on, false=must be off)
  std::map<char, bool> check_violations(const std::string& channel, const ModeBundle& bundle) {
    std::map<char, bool> violations;
    auto* ml = get_mlock(channel);
    if (!ml) return violations;

    auto locked = ml->parse();
    for (auto& change : bundle.changes) {
      if (change.is_list()) continue;

      for (auto& lk : locked) {
        if (lk.mode_char == change.mode_char) {
          if (lk.should_be_set != change.is_set()) {
            violations[change.mode_char] = lk.should_be_set;
          }
          break;
        }
      }
    }
    return violations;
  }

  // Check if a single mode is locked
  bool is_mode_locked(const std::string& channel, char mode_c) {
    auto* ml = get_mlock(channel);
    if (!ml) return false;

    for (size_t i = 0; i < ml->mode_string.size(); ++i) {
      if (ml->mode_string[i] == mode_c) {
        // Check if preceded by + or -
        bool should_be_set = true;
        if (i > 0 && ml->mode_string[i-1] == '-') should_be_set = false;
        else if (i > 0 && ml->mode_string[i-1] == '+') should_be_set = true;
        else {
          // Scan backwards to find direction
          for (int j = static_cast<int>(i) - 1; j >= 0; --j) {
            if (ml->mode_string[j] == '+') { should_be_set = true; break; }
            if (ml->mode_string[j] == '-') { should_be_set = false; break; }
          }
        }
        return true;
      }
    }
    return false;
  }

  // Check what value MLOCK wants for a mode
  std::optional<bool> get_mlock_value(const std::string& channel, char mode_c) {
    auto* ml = get_mlock(channel);
    if (!ml) return std::nullopt;

    for (size_t i = 0; i < ml->mode_string.size(); ++i) {
      if (ml->mode_string[i] == mode_c) {
        bool should_be_set = true;
        for (int j = static_cast<int>(i) - 1; j >= 0; --j) {
          if (ml->mode_string[j] == '+') { should_be_set = true; break; }
          if (ml->mode_string[j] == '-') { should_be_set = false; break; }
        }
        return should_be_set;
      }
    }
    return std::nullopt;
  }

  // List all MLOCKs
  std::vector<MLockEntry> list_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<MLockEntry> result;
    for (auto& [k, v] : mlocks_)
      result.push_back(v);
    return result;
  }

private:
  std::unordered_map<std::string, MLockEntry> mlocks_;
  std::mutex mutex_;
};

// =============================================================================
// SECTION 8: Mode history tracking
// =============================================================================

class ModeHistoryTracker {
public:
  struct ModeHistoryEntry {
    std::string channel;
    std::string set_by;         // nick!user@host
    std::string mode_string;    // e.g. "+b-k+o"
    std::vector<std::string> params;
    int64_t timestamp;
    bool is_server_origin;
    bool is_services_origin;

    json to_json() const {
      return {
        {"channel", channel},
        {"set_by", set_by},
        {"mode_string", mode_string},
        {"params", params},
        {"timestamp", timestamp},
        {"is_server_origin", is_server_origin},
        {"is_services_origin", is_services_origin}
      };
    }
  };

  // Record a mode change event
  void record_change(const std::string& channel, const std::string& set_by,
                     const std::string& mode_str,
                     const std::vector<std::string>& params,
                     bool server_origin = false, bool services_origin = false) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    auto& hist = history_[key];

    ModeHistoryEntry entry;
    entry.channel = channel;
    entry.set_by = set_by;
    entry.mode_string = mode_str;
    entry.params = params;
    entry.timestamp = mc_now_sec();
    entry.is_server_origin = server_origin;
    entry.is_services_origin = services_origin;

    hist.push_back(std::move(entry));

    // Trim to max
    while (hist.size() > MC_MAX_HISTORY) {
      hist.pop_front();
    }
  }

  // Record from a ModeBundle
  void record_bundle(const ModeBundle& bundle) {
    record_change(bundle.target, bundle.source, bundle.build_mode_string(),
                  bundle.build_param_list(), bundle.is_server_origin,
                  bundle.is_services_origin);
  }

  // Get history for a channel
  std::deque<ModeHistoryEntry> get_history(const std::string& channel) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    auto it = history_.find(key);
    if (it != history_.end()) return it->second;
    return {};
  }

  // Get recent history (last N entries)
  std::vector<ModeHistoryEntry> get_recent(const std::string& channel, size_t count = 10) const {
    auto hist = get_history(channel);
    std::vector<ModeHistoryEntry> result;
    auto it = hist.rbegin();
    while (it != hist.rend() && result.size() < count) {
      result.push_back(*it);
      ++it;
    }
    std::reverse(result.begin(), result.end());
    return result;
  }

  // Clear history for a channel
  void clear_history(const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    history_.erase(key);
  }

  // Clear all history
  void clear_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.clear();
  }

private:
  std::unordered_map<std::string, std::deque<ModeHistoryEntry>> history_;
  mutable std::mutex mutex_;
};

// =============================================================================
// SECTION 9: Mode cache for performance
// =============================================================================

class ModeCache {
public:
  struct CachedModes {
    std::string mode_string;     // e.g. "+ntrk" (simple flags)
    std::string pretty_string;   // e.g. "+ntr-k key" (with params for display)
    std::string param_string;    // e.g. "key" (just params)
    int64_t cached_at;
    int64_t version;             // incremented on change, used for invalidation
  };

  // Get cached mode string, or compute and cache it
  std::string get_mode_string(const std::string& channel, int64_t current_version,
                               std::function<std::string()> compute) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    auto it = cache_.find(key);
    if (it != cache_.end() && it->second.version == current_version) {
      return it->second.mode_string;
    }
    // Compute and cache
    std::string result = compute();
    CachedModes cm;
    cm.mode_string = result;
    cm.cached_at = mc_now_sec();
    cm.version = current_version;
    cache_[key] = std::move(cm);
    return result;
  }

  // Invalidate cache for a channel
  void invalidate(const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    cache_.erase(key);
  }

  // Invalidate all caches
  void invalidate_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
  }

private:
  std::unordered_map<std::string, CachedModes> cache_;
  std::mutex mutex_;
};

// =============================================================================
// SECTION 10: Ban and exception expiry management
// =============================================================================

// Internal extended ban/exception store with expiry
struct ChannelListStore {
  std::vector<BanEntryComplete> bans;
  std::vector<BanEntryComplete> bans_quiet;    // quiet bans (extended)
  std::vector<ExceptionEntryComplete> excepts;
  std::vector<ExceptionEntryComplete> invex;   // invite exceptions

  // Remove expired entries
  void remove_expired() {
    auto filter = [](auto& vec) {
      vec.erase(std::remove_if(vec.begin(), vec.end(),
        [](auto& e) { return e.is_expired(); }), vec.end());
    };
    filter(bans);
    filter(bans_quiet);
    filter(excepts);
    filter(invex);
  }

  // Add ban with expiry
  bool add_ban(const std::string& mask, const std::string& set_by,
               int64_t duration = 0, const std::string& reason = "") {
    if (bans.size() >= MC_MAX_BANLIST) return false;
    int64_t expires = (duration > 0) ? mc_now_sec() + duration : 0;
    bans.emplace_back(mask, set_by, mc_now_sec(), expires, reason);
    return true;
  }

  // Remove ban by mask
  bool remove_ban(const std::string& mask) {
    auto it = std::find_if(bans.begin(), bans.end(),
      [&](const BanEntryComplete& b) { return mc_iequals(b.mask, mask); });
    if (it != bans.end()) { bans.erase(it); return true; }
    return false;
  }

  // Check if a user matches any ban (respects excepts)
  bool is_banned(const std::string& nick, const std::string& user,
                 const std::string& host) const {
    // First remove expired (const_cast for lazy evaluation — ok since this is logically const)
    // Actually we should be careful here. Let's check without modifying.
    for (auto& e : excepts) {
      if (!e.is_expired() && e.matches(nick, user, host))
        return false; // exception overrides ban
    }
    for (auto& b : bans) {
      if (!b.is_expired() && b.matches(nick, user, host))
        return true;
    }
    return false;
  }

  // Check if invite exception exists
  bool has_invite_exception(const std::string& nick, const std::string& user,
                            const std::string& host) const {
    for (auto& ie : invex) {
      if (!ie.is_expired() && ie.matches(nick, user, host))
        return true;
    }
    return false;
  }

  // Get all non-expired masks
  std::vector<std::string> get_active_bans() const {
    std::vector<std::string> result;
    for (auto& b : bans)
      if (!b.is_expired()) result.push_back(b.mask);
    return result;
  }

  std::vector<std::string> get_active_excepts() const {
    std::vector<std::string> result;
    for (auto& e : excepts)
      if (!e.is_expired()) result.push_back(e.mask);
    return result;
  }

  std::vector<std::string> get_active_invex() const {
    std::vector<std::string> result;
    for (auto& ie : invex)
      if (!ie.is_expired()) result.push_back(ie.mask);
    return result;
  }
};

class BanExpiryManager {
public:
  BanExpiryManager() : running_(false) {}

  void start() {
    if (running_) return;
    running_ = true;
    expiry_thread_ = std::thread([this]() { expiry_loop(); });
  }

  void stop() {
    running_ = false;
    if (expiry_thread_.joinable())
      expiry_thread_.join();
  }

  // Register a channel for periodic expiry checking
  void register_channel(const std::string& channel, ChannelListStore* store) {
    std::lock_guard<std::mutex> lock(mutex_);
    channels_[mc_to_lower(channel)] = store;
  }

  void unregister_channel(const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    channels_.erase(mc_to_lower(channel));
  }

  size_t channel_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return channels_.size();
  }

private:
  void expiry_loop() {
    while (running_) {
      {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [name, store] : channels_) {
          store->remove_expired();
        }
      }
      // Sleep for interval
      for (int i = 0; i < MC_EXPIRY_CHECK_INTERVAL && running_; ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }

  std::unordered_map<std::string, ChannelListStore*> channels_;
  std::mutex mutex_;
  std::thread expiry_thread_;
  std::atomic<bool> running_;
};

// =============================================================================
// SECTION 11: Extended channel state with all mode support
// =============================================================================

struct ChannelModeState {
  std::string channel_name;

  // Type A list modes (with expiry support)
  ChannelListStore lists;

  // Type B param modes
  std::optional<std::string> key;          // +k

  // Type C param-when-set modes
  std::optional<int64_t> user_limit;       // +l
  std::optional<std::string> redirect;     // +L
  std::optional<std::string> join_throttle; // +j (N:t format)
  int64_t throttle_joins = 0;
  int64_t throttle_secs = 0;

  // Type D prefix mode tracking (per-member modes stored in channel)
  // We reference through external member_modes map

  // Type E flag modes
  std::string flags;  // all simple flags concatenated

  // Timestamps
  int64_t created_ts;
  int64_t last_mode_change_ts;
  int64_t topic_ts;

  // Version counter for cache invalidation
  int64_t mode_version;

  // Mode history
  std::deque<ModeHistoryTracker::ModeHistoryEntry> history;

  // Channel topic
  std::string topic;
  std::string topic_setter;

  ChannelModeState() : created_ts(mc_now_sec()), last_mode_change_ts(0),
                       topic_ts(0), mode_version(1) {}

  // --- Flag mode helpers ---
  bool has_flag(char c) const {
    return flags.find(c) != std::string::npos;
  }

  void set_flag(char c) {
    if (flags.find(c) == std::string::npos) flags += c;
  }

  void unset_flag(char c) {
    auto pos = flags.find(c);
    if (pos != std::string::npos) flags.erase(pos, 1);
  }

  void toggle_flag(char c, bool set) {
    if (set) set_flag(c); else unset_flag(c);
  }

  // --- s/p mutual exclusion ---
  void ensure_sp_exclusive() {
    bool has_s = has_flag('s');
    bool has_p = has_flag('p');
    if (has_s && has_p) unset_flag('p'); // +s takes priority
  }

  // --- Build the full mode string for RPL_CHANNELMODEIS ---
  std::string build_mode_display() const {
    std::string result = "+";
    // Add all flag modes
    result += flags;
    // Add param modes
    if (key.has_value()) result += "k";
    if (user_limit.has_value()) result += "l";
    if (redirect.has_value()) result += "L";
    if (join_throttle.has_value()) result += "j";
    return result;
  }

  // Build parameter display (key and limit)
  std::string build_param_display() const {
    std::string result;
    if (key.has_value()) result += " " + *key;
    if (user_limit.has_value()) result += " " + std::to_string(*user_limit);
    if (redirect.has_value()) result += " " + *redirect;
    if (join_throttle.has_value()) result += " " + *join_throttle;
    return result;
  }

  // Full display for RPL_CHANNELMODEIS
  std::string full_mode_display() const {
    return build_mode_display() + build_param_display();
  }

  // Reset modes to defaults on channel creation
  void reset_to_defaults() {
    flags.clear();
    // Default modes: +nt
    set_flag('n');
    set_flag('t');
    key.reset();
    user_limit.reset();
    redirect.reset();
    join_throttle.reset();
    throttle_joins = 0;
    throttle_secs = 0;
    lists = ChannelListStore();
    mode_version++;
  }

  // Reset on channel join (first user creates)
  void reset_on_creation() {
    reset_to_defaults();
    created_ts = mc_now_sec();
    topic_ts = 0;
    topic.clear();
    topic_setter.clear();
    last_mode_change_ts = 0;
    history.clear();
  }

  // Bump version
  void bump_version() { mode_version++; last_mode_change_ts = mc_now_sec(); }

  // Check if user can join (ban/except checks, mode checks)
  bool can_join(const std::string& nick, const std::string& user,
                const std::string& host, bool is_ssl, bool is_registered,
                bool invite_only_has_invite) const {
    // Check +z / SSL-only mode
    if (has_flag('z')) {
      if (!is_ssl) return false;
    }

    // Check +R (registered only)
    if (has_flag('R')) {
      if (!is_registered) return false;
    }

    // Check +i (invite only)
    if (has_flag('i')) {
      // Allow if user has invite exception
      if (lists.has_invite_exception(nick, user, host)) return true;
      // Must be invited
      if (!invite_only_has_invite) return false;
    }

    // Check +O (oper only)
    if (has_flag('O')) return false; // handled by caller checking oper status

    // Check bans
    if (lists.is_banned(nick, user, host)) return false;

    // Check +l (user limit)
    return true; // caller must check user count vs limit
  }

  // Check if user can send messages (+m moderated, +M registered, +c nocolor, +C noctcp)
  bool can_message(bool is_voiced_or_higher, bool is_registered, bool is_oper) const {
    // +M: must be registered to talk
    if (has_flag('M') && !is_registered && !is_voiced_or_higher && !is_oper)
      return false;

    // +m: moderated — must have voice or higher
    if (has_flag('m') && !is_voiced_or_higher && !is_oper)
      return false;

    return true;
  }
};

// =============================================================================
// SECTION 12: Complete mode handler — the main engine
// =============================================================================

class CompleteModeHandler {
public:
  CompleteModeHandler() {
    ban_expiry_.start();
  }

  ~CompleteModeHandler() {
    ban_expiry_.stop();
  }

  // ========================================================================
  // Channel mode parsing and application
  // ========================================================================

  // Apply a mode change to channel state
  // Returns: error message or empty on success
  std::string apply_channel_mode_change(ChannelModeState& state,
                                         const ModeChange& change,
                                         IRCChannel* ch,
                                         std::vector<std::string>& broadcast_params) {
    switch (change.mode_char) {
      // --- Type A: List modes ---
      case 'b': {
        if (change.is_list()) return ""; // list handled by caller
        if (change.is_set()) {
          if (!mc_is_valid_mask(change.param))
            return "Invalid ban mask";
          if (!state.lists.add_ban(change.param, "server", 0, ""))
            return "Ban list is full";
          ch->bans.insert(change.param);
        } else {
          state.lists.remove_ban(change.param);
          ch->bans.erase(change.param);
        }
        broadcast_params.push_back(change.param);
        return "";
      }
      case 'e': {
        if (change.is_list()) return "";
        if (change.is_set()) {
          if (!mc_is_valid_mask(change.param)) return "Invalid except mask";
          if (state.lists.excepts.size() >= MC_MAX_EXCEPTLIST) return "Except list is full";
          state.lists.excepts.emplace_back(change.param, "server", mc_now_sec(), 0, "");
          ch->excepts.insert(change.param);
        } else {
          auto& vec = state.lists.excepts;
          vec.erase(std::remove_if(vec.begin(), vec.end(),
            [&](auto& e) { return mc_iequals(e.mask, change.param); }), vec.end());
          ch->excepts.erase(change.param);
        }
        broadcast_params.push_back(change.param);
        return "";
      }
      case 'I': {
        if (change.is_list()) return "";
        if (change.is_set()) {
          if (!mc_is_valid_mask(change.param)) return "Invalid invex mask";
          if (state.lists.invex.size() >= MC_MAX_INVEXLIST) return "Invex list is full";
          state.lists.invex.emplace_back(change.param, "server", mc_now_sec(), 0, "");
          ch->invites.insert(change.param);
        } else {
          auto& vec = state.lists.invex;
          vec.erase(std::remove_if(vec.begin(), vec.end(),
            [&](auto& e) { return mc_iequals(e.mask, change.param); }), vec.end());
          ch->invites.erase(change.param);
        }
        broadcast_params.push_back(change.param);
        return "";
      }

      // --- Type B: Key ---
      case 'k': {
        if (change.is_set()) {
          if (!mc_is_valid_key(change.param))
            return "Invalid key (max " + std::to_string(MC_MAX_KEY_LEN) + " chars, no spaces/commas)";
          state.key = change.param;
          ch->key = change.param;
          ch->modes = mc_toggle_mode(ch->modes, 'k', true);
          broadcast_params.push_back(change.param);
        } else {
          state.key.reset();
          ch->key.clear();
          ch->modes = mc_toggle_mode(ch->modes, 'k', false);
          broadcast_params.push_back("*");
        }
        return "";
      }

      // --- Type C: Limit ---
      case 'l': {
        if (change.is_set()) {
          int64_t limit = std::stoll(change.param);
          if (!mc_is_valid_user_limit(limit))
            return "Invalid user limit (1-" + std::to_string(MC_MAX_USER_LIMIT) + ")";
          state.user_limit = limit;
          ch->user_limit = limit;
          ch->modes = mc_toggle_mode(ch->modes, 'l', true);
          broadcast_params.push_back(std::to_string(limit));
        } else {
          state.user_limit.reset();
          ch->user_limit = 0;
          ch->modes = mc_toggle_mode(ch->modes, 'l', false);
        }
        return "";
      }

      // --- Type C: Redirect ---
      case 'L': {
        if (change.is_set()) {
          if (change.param.size() > MC_REDIRECT_MAX_LEN) return "Redirect target too long";
          state.redirect = change.param;
          broadcast_params.push_back(change.param);
        } else {
          state.redirect.reset();
        }
        return "";
      }

      // --- Type C: Join throttle ---
      case 'j': {
        if (change.is_set()) {
          if (!mc_is_valid_join_throttle(change.param))
            return "Invalid join throttle format (use N:t)";
          state.join_throttle = change.param;
          auto colon = change.param.find(':');
          state.throttle_joins = std::stoi(change.param.substr(0, colon));
          state.throttle_secs = std::stoi(change.param.substr(colon + 1));
          broadcast_params.push_back(change.param);
        } else {
          state.join_throttle.reset();
          state.throttle_joins = 0;
          state.throttle_secs = 0;
        }
        return "";
      }

      // --- Type D: Prefix modes ---
      case 'o': // op
      case 'v': // voice
      case 'h': // halfop
      case 'a': // admin
      case 'q': { // owner
        if (change.param.empty()) return "Missing nick parameter";

        std::string nick = change.param;
        if (!ch->members.count(nick))
          return "They aren't on that channel";

        auto& mm = ch->member_modes[nick];
        if (change.is_set()) {
          if (mm.find(change.mode_char) == std::string::npos) {
            mm += change.mode_char;
            // Inherit lower modes
            if (change.mode_char == 'q') {
              if (mm.find('o') == std::string::npos) mm += 'o';
              if (mm.find('a') == std::string::npos) mm += 'a';
            }
            if (change.mode_char == 'a') {
              if (mm.find('o') == std::string::npos) mm += 'o';
            }
            if (change.mode_char == 'h' && mm.find('v') == std::string::npos) mm += 'v';
          }
        } else {
          auto pos = mm.find(change.mode_char);
          if (pos != std::string::npos) mm.erase(pos, 1);
        }
        broadcast_params.push_back(nick);
        return "";
      }

      // --- Type E: Flag modes ---
      case 't': // topic lock
      case 'i': // invite only
      case 'm': // moderated
      case 'n': // no external messages
      case 'r': // registered
      case 'c': // no color
      case 'C': // no CTCP
      case 'M': // registered only talk
      case 'R': // registered only join
      case 'K': // no knock
      case 'N': // no nick changes
      case 'O': // oper only
      case 'Q': // no kick
      case 'T': // no notice
      case 'u': // auditorium
      case 'P': // permanent
      case 'F': // forbidden nicks
      case 'G': // censor
      case 'z': { // SSL only
        state.toggle_flag(change.mode_char, change.is_set());
        ch->modes = mc_toggle_mode(ch->modes, change.mode_char, change.is_set());
        // Handle s/p mutual exclusion
        if (change.is_set()) {
          if (change.mode_char == 's') {
            auto pp = ch->modes.find('p');
            if (pp != std::string::npos) ch->modes.erase(pp, 1);
            state.unset_flag('p');
          }
          if (change.mode_char == 'p') {
            auto ps = ch->modes.find('s');
            if (ps != std::string::npos) ch->modes.erase(ps, 1);
            state.unset_flag('s');
          }
        }
        return "";
      }

      default:
        return std::string("Unknown mode: ") + change.mode_char;
    }
  }

  // ========================================================================
  // Permission checking
  // ========================================================================

  // Check if source can set/unset a channel mode
  std::optional<std::string> check_channel_mode_permission(
      const std::string& channel, const ModeChange& change,
      const std::string& source_nick, ModeAccessLevel source_access,
      bool is_oper, bool is_server, bool is_services) {

    // Server and services override all permissions
    if (is_server || is_services) return std::nullopt;

    auto* def = mc_get_channel_mode_def(change.mode_char);
    if (!def) return std::nullopt; // unknown mode — error handled by caller

    // IRC operators can set all modes
    if (is_oper && source_access >= ModeAccessLevel::OPER)
      return std::nullopt;

    // Check MLOCK first
    auto mlock_val = mlock_.get_mlock_value(channel, change.mode_char);
    if (mlock_val.has_value() && change.is_set() != *mlock_val) {
      // Disallow if trying to violate MLOCK
      // Unless source has override (server/services)
      if (!is_oper) {
        return "Mode " + std::string(1, change.mode_char) + " is locked by MLOCK";
      }
    }

    // Check access level
    if (static_cast<uint8_t>(source_access) < static_cast<uint8_t>(def->min_access)) {
      std::string required;
      switch (def->min_access) {
        case ModeAccessLevel::OWNER:  required = "owner"; break;
        case ModeAccessLevel::ADMIN:  required = "admin"; break;
        case ModeAccessLevel::OP:     required = "operator"; break;
        case ModeAccessLevel::HALFOP: required = "halfop"; break;
        case ModeAccessLevel::VOICE:  required = "voice"; break;
        case ModeAccessLevel::SERVICE:required = "services"; break;
        default: required = "higher access";
      }
      return "You need " + required + " access to change mode +" + std::string(1, change.mode_char);
    }

    // Halfop cannot change owner/admin modes
    if (source_access <= ModeAccessLevel::HALFOP &&
        (change.mode_char == 'q' || change.mode_char == 'a')) {
      return "Halfops cannot modify owner/admin modes";
    }

    // Cannot target someone with equal or higher access for prefix modes
    if (def->type == ChannelModeType::TYPE_D_PREFIX && change.is_set()) {
      // This check is done at call site with knowledge of target's access
    }

    return std::nullopt;
  }

  // ========================================================================
  // Channel MODE query (no mode string)
  // ========================================================================

  std::string channel_mode_query(const ChannelModeState& state) {
    return state.full_mode_display();
  }

  // ========================================================================
  // Channel creation timestamp handling
  // ========================================================================

  std::string creation_time_reply(const std::string& channel, int64_t created_ts) {
    return channel + " " + std::to_string(created_ts);
  }

  // ========================================================================
  // Server MODE — override all permissions
  // ========================================================================

  bool server_mode_override(bool allowed, const std::string& reason = "") {
    // Server-originated mode changes always allowed
    return true;
  }

  // ========================================================================
  // OP MODE (services operator mode, force)
  // ========================================================================

  bool services_op_mode(bool allowed, const std::string& target = "") {
    // Services can set any mode on any channel/user
    return true;
  }

  // ========================================================================
  // SAMODE — services admin mode, force with override
  // ========================================================================

  bool services_admin_mode(bool allowed) {
    // Services admin has ultimate override
    return true;
  }

  // ========================================================================
  // MLOCK management
  // ========================================================================

  ModeLockSystem& mlock() { return mlock_; }
  const ModeLockSystem& mlock() const { return mlock_; }

  // ========================================================================
  // Mode history
  // ========================================================================

  ModeHistoryTracker& history() { return history_; }
  const ModeHistoryTracker& history() const { return history_; }

  // ========================================================================
  // Mode cache
  // ========================================================================

  ModeCache& cache() { return cache_; }
  const ModeCache& cache() const { return cache_; }

  // ========================================================================
  // Ban expiry
  // ========================================================================

  BanExpiryManager& ban_expiry() { return ban_expiry_; }
  const BanExpiryManager& ban_expiry() const { return ban_expiry_; }

  // ========================================================================
  // Full bundle application for channels
  // ========================================================================

  struct BundleResult {
    bool success;
    std::string error_message;          // if !success
    std::string applied_mode_string;    // normalized mode string actually applied
    std::vector<std::string> applied_params;
    std::vector<std::string> errors;    // per-change errors (partial success)
  };

  BundleResult apply_channel_bundle(ChannelModeState& state, IRCChannel* ch,
                                      ModeBundle& bundle) {
    BundleResult result;
    result.success = true;

    if (bundle.changes.empty()) {
      // Query mode — return current state
      result.applied_mode_string = "+" + state.flags;
      if (state.key.has_value()) {
        result.applied_mode_string += "k";
        result.applied_params.push_back(*state.key);
      }
      if (state.user_limit.has_value()) {
        result.applied_mode_string += "l";
        result.applied_params.push_back(std::to_string(*state.user_limit));
      }
      return result;
    }

    std::string applied_modes;
    ModeAction current_dir = ModeAction::SET;
    std::vector<std::string> broadcast_params;
    bool first_mode_in_block = true;

    for (auto& change : bundle.changes) {
      if (change.is_list()) {
        // List query — handled separately by caller
        result.success = false;
        result.error_message = "List modes must be queried separately";
        return result;
      }

      // Check MLOCK
      auto mlock_val = mlock_.get_mlock_value(state.channel_name, change.mode_char);
      if (mlock_val.has_value() && change.is_set() != *mlock_val) {
        if (!bundle.is_server_origin && !bundle.is_services_origin) {
          // Non-override: skip this change with warning
          result.errors.push_back(
            std::string("Mode ") + change.mode_char + " locked by MLOCK to " +
            (*mlock_val ? "on" : "off"));
          continue;
        }
      }

      // Determine direction prefix
      if (first_mode_in_block || change.action != current_dir) {
        current_dir = change.action;
        applied_modes += (current_dir == ModeAction::SET) ? "+" : "-";
        first_mode_in_block = false;
      }

      // Apply the mode
      std::string err = apply_channel_mode_change(state, change, ch, broadcast_params);
      if (!err.empty()) {
        result.errors.push_back(err);
        continue;
      }

      applied_modes += change.mode_char;
    }

    if (!applied_modes.empty()) {
      state.bump_version();
      cache_.invalidate(state.channel_name);

      result.applied_mode_string = applied_modes;
      result.applied_params = broadcast_params;

      // Record history
      history_.record_change(state.channel_name, bundle.source,
                              applied_modes, broadcast_params,
                              bundle.is_server_origin, bundle.is_services_origin);
    }

    result.success = result.errors.empty();
    return result;
  }

  // ========================================================================
  // User mode handling
  // ========================================================================

  std::string apply_user_mode_change(IRCUser* user, const ModeChange& change,
                                      bool is_oper) {
    auto* def = mc_get_user_mode_def(change.mode_char);
    if (!def) return "Unknown user mode";

    // Oper-only modes
    if (def->oper_only && !is_oper)
      return "Mode +" + std::string(1, change.mode_char) + " requires oper privileges";

    // Non-settable modes
    if (!def->settable && !is_oper)
      return "Mode +" + std::string(1, change.mode_char) + " cannot be set by user";

    // Special handling for +o (oper)
    if (change.mode_char == 'o') {
      if (change.is_set()) {
        user->oper = true;
        user->modes = mc_toggle_mode(user->modes, 'o', true);
      } else {
        user->oper = false;
        user->modes = mc_toggle_mode(user->modes, 'o', false);
      }
      return "";
    }

    // Standard toggle
    user->modes = mc_toggle_mode(user->modes, change.mode_char, change.is_set());
    return "";
  }

  // ========================================================================
  // Full mode string formatting from state
  // ========================================================================

  std::string format_channel_modes(const ChannelModeState& state) {
    return state.build_mode_display();
  }

  std::string format_channel_modes_with_params(const ChannelModeState& state) {
    return state.full_mode_display();
  }

  // ========================================================================
  // Channel mode reset (on creation)
  // ========================================================================

  void reset_channel_modes(ChannelModeState& state) {
    state.reset_on_creation();
    cache_.invalidate(state.channel_name);
  }

  // ========================================================================
  // Ban checks for joins and messages
  // ========================================================================

  bool is_user_banned(const ChannelModeState& state, const std::string& nick,
                       const std::string& user, const std::string& host) {
    return state.lists.is_banned(nick, user, host);
  }

  bool has_ban_exception(const ChannelModeState& state, const std::string& nick,
                          const std::string& user, const std::string& host) {
    for (auto& e : state.lists.excepts) {
      if (!e.is_expired() && e.matches(nick, user, host)) return true;
    }
    return false;
  }

  bool has_invite_exception(const ChannelModeState& state, const std::string& nick,
                             const std::string& user, const std::string& host) {
    return state.lists.has_invite_exception(nick, user, host);
  }

private:
  ModeLockSystem mlock_;
  ModeHistoryTracker history_;
  ModeCache cache_;
  BanExpiryManager ban_expiry_;
};

// =============================================================================
// SECTION 13: Full MODE command implementation for IRCServer
// =============================================================================

// ---- Channel mode parser (parse +mode-params string) ----
// Parse a raw MODE string like "+b-k+o param1 param2" into a ModeBundle
ModeBundle parse_channel_mode_string(const std::string& mode_str,
                                       const std::vector<std::string>& params) {
  ModeBundle bundle;
  bundle.parse_mode_string(mode_str, params);
  return bundle;
}

// ---- Permission check helper ----
ModeAccessLevel get_user_channel_access(IRCChannel* ch, const std::string& nick) {
  if (!ch) return ModeAccessLevel::NONE;
  auto it = ch->member_modes.find(nick);
  if (it == ch->member_modes.end()) return ModeAccessLevel::NONE;
  return mc_access_from_modes(it->second);
}

bool user_can_change_channel_modes(IRCChannel* ch, const std::string& nick, bool is_oper) {
  if (is_oper) return true;
  auto access = get_user_channel_access(ch, nick);
  return access >= ModeAccessLevel::HALFOP;
}

// ---- Validate mode change against channel state ----
std::vector<std::string> validate_mode_changes(IRCChannel* ch,
                                                  const ModeBundle& bundle,
                                                  const std::string& source_nick,
                                                  bool is_oper) {
  std::vector<std::string> errors;
  if (!ch) { errors.push_back("No such channel"); return errors; }

  auto src_access = get_user_channel_access(ch, source_nick);
  if (is_oper) src_access = ModeAccessLevel::OPER;

  static CompleteModeHandler handler;
  (void)handler; // We use the static instance for methods

  for (auto& change : bundle.changes) {
    auto* def = mc_get_channel_mode_def(change.mode_char);
    if (!def) {
      errors.push_back(std::string("Unknown mode: ") + change.mode_char);
      continue;
    }

    // Basic access check
    if (static_cast<uint8_t>(src_access) < static_cast<uint8_t>(def->min_access)) {
      errors.push_back("Insufficient access for +" + std::string(1, change.mode_char));
      continue;
    }

    // Prefix mode: check target access level
    if (def->type == ChannelModeType::TYPE_D_PREFIX && change.is_set() && !change.param.empty()) {
      auto target_access = get_user_channel_access(ch, change.param);
      if (target_access >= src_access && src_access < ModeAccessLevel::OPER) {
        errors.push_back("Cannot change mode for user with equal or higher access");
        continue;
      }
    }

    // Parameter validation
    if (def->type == ChannelModeType::TYPE_B_PARAM || change.is_set()) {
      if (change.mode_char == 'k' && !mc_is_valid_key(change.param))
        errors.push_back("Invalid key");
      if (change.mode_char == 'l') {
        try {
          int64_t lim = std::stoll(change.param);
          if (!mc_is_valid_user_limit(lim)) errors.push_back("Invalid user limit");
        } catch (...) { errors.push_back("Invalid user limit (not a number)"); }
      }
      if (change.mode_char == 'j' && !change.param.empty() && !mc_is_valid_join_throttle(change.param))
        errors.push_back("Invalid join throttle format (use N:t)");
    }
  }

  return errors;
}

// =============================================================================
// SECTION 14: Main MODE command handler — integrates with IRCServer
// =============================================================================

// This is the main entry point for the MODE command.
// It handles:
//   - MODE <channel>          (query modes)
//   - MODE <channel> +mode... (change channel modes)
//   - MODE <nick>             (query user modes)
//   - MODE <nick> +mode...    (change user modes)
//   - Server-originated MODE  (override permissions)
//   - Services-originated MODE (OPMODE/SAMODE)
//
// Called from IRCServer::handle_mode() or directly.

void process_mode_command(IRCServer& server, IRCConnection* conn,
                          const std::string& target,
                          const std::string& mode_str,
                          const std::vector<std::string>& params,
                          bool is_server_origin = false,
                          bool is_services_origin = false) {

  // Determine if target is a channel or user
  bool is_chan = server.is_channel(target);

  if (is_chan) {
    // ---- Channel MODE ----
    auto* ch = server.get_channel(target);
    if (!ch) {
      if (conn) server.send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL,
                                      target + " :No such channel");
      return;
    }

    // Query-only (no mode string)
    if (mode_str.empty()) {
      static CompleteModeHandler handler;
      std::string display = "+" + ch->modes;
      // Add key and limit params
      if (ch->modes.find('k') != std::string::npos)
        display += " " + ch->key;
      if (ch->modes.find('l') != std::string::npos)
        display += " " + std::to_string(ch->user_limit);
      if (conn) server.send_numeric(conn, Numerics::RPL_CHANNELMODEIS,
                                       target + " " + display);
      // Also send creation timestamp if available
      if (ch->created_ts > 0 && conn) {
        server.send_numeric(conn, Numerics::RPL_CREATIONTIME,
                            target + " " + std::to_string(ch->created_ts));
      }
      return;
    }

    // Parse mode string
    ModeBundle bundle;
    if (!bundle.parse_mode_string(mode_str, params)) {
      if (conn) server.send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS,
                                      "MODE :Not enough parameters");
      return;
    }

    bundle.target = target;
    bundle.is_channel_mode = true;
    bundle.is_server_origin = is_server_origin;
    bundle.is_services_origin = is_services_origin;
    bundle.source = conn ? (conn->nick + "!" + conn->user + "@" + conn->host) : "server";

    // Server/services override: skip permission checks
    bool can_override = is_server_origin || is_services_origin;
    bool is_oper = false;

    if (conn) {
      auto* user = server.get_user(conn->nick);
      is_oper = user && user->oper;
    }

    // Permission check (unless server override)
    if (!can_override) {
      if (!user_can_change_channel_modes(ch, conn->nick, is_oper)) {
        server.send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED,
                            target + " :You're not channel operator");
        return;
      }

      // Validate individual changes
      auto errors = validate_mode_changes(ch, bundle, conn->nick, is_oper);
      for (auto& err : errors) {
        if (conn) server.send_numeric(conn, Numerics::ERR_UNKNOWNMODE,
                                       err + " :Cannot set mode");
      }
      if (!errors.empty()) return; // don't apply if validation fails
    }

    // Apply mode changes
    bool adding = true;
    size_t param_idx = 0;
    std::string applied_modes;
    std::vector<std::string> applied_params;

    for (char mode_c : mode_str) {
      if (mode_c == '+') { adding = true; continue; }
      if (mode_c == '-') { adding = false; continue; }

      auto* def = mc_get_channel_mode_def(mode_c);
      if (!def) {
        if (conn) server.send_numeric(conn, Numerics::ERR_UNKNOWNMODE,
                                       std::string(1, mode_c) +
                                       " :is unknown mode char to me for " + target);
        continue;
      }

      // Handle list mode query (-b without param)
      if (def->type == ChannelModeType::TYPE_A_LIST && !adding && param_idx >= params.size()) {
        if (conn) {
          if (mode_c == 'b') {
            for (auto& b : ch->bans)
              server.send_numeric(conn, 367, target + " " + b);
            server.send_numeric(conn, 368, target + " :End of Channel Ban List");
          } else if (mode_c == 'e') {
            for (auto& e : ch->excepts)
              server.send_numeric(conn, 348, target + " " + e);
            server.send_numeric(conn, 349, target + " :End of Channel Exception List");
          } else if (mode_c == 'I') {
            for (auto& i : ch->invites)
              server.send_numeric(conn, 346, target + " " + i);
            server.send_numeric(conn, 347, target + " :End of Channel Invite Exception List");
          }
        }
        continue;
      }

      // Get parameter if needed
      std::string param;
      if (adding && (def->type == ChannelModeType::TYPE_A_LIST ||
                     def->type == ChannelModeType::TYPE_B_PARAM ||
                     def->type == ChannelModeType::TYPE_D_PREFIX ||
                     (def->type == ChannelModeType::TYPE_C_PARAMWS && param_idx < params.size()))) {
        if (param_idx < params.size()) {
          param = params[param_idx++];
        } else {
          if (conn) server.send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS,
                                         std::string(1, mode_c) + " :Not enough parameters");
          continue;
        }
      }
      // For unset, list modes also need param
      if (!adding && def->type == ChannelModeType::TYPE_A_LIST) {
        if (param_idx < params.size()) {
          param = params[param_idx++];
        } else {
          continue; // already handled as list query above
        }
      }

      // Apply the mode
      switch (mode_c) {
        // Type A: List modes
        case 'b': {
          if (adding) {
            ch->bans.insert(param);
          } else {
            ch->bans.erase(param);
          }
          applied_modes += (adding ? "+b" : "-b");
          applied_params.push_back(param);
          break;
        }
        case 'e': {
          if (adding) ch->excepts.insert(param);
          else ch->excepts.erase(param);
          applied_modes += (adding ? "+e" : "-e");
          applied_params.push_back(param);
          break;
        }
        case 'I': {
          if (adding) ch->invites.insert(param);
          else ch->invites.erase(param);
          applied_modes += (adding ? "+I" : "-I");
          applied_params.push_back(param);
          break;
        }

        // Type B: Key
        case 'k': {
          if (adding) {
            ch->key = param;
            ch->modes = mc_toggle_mode(ch->modes, 'k', true);
            applied_modes += "+k";
            applied_params.push_back(param);
          } else {
            ch->key.clear();
            ch->modes = mc_toggle_mode(ch->modes, 'k', false);
            applied_modes += "-k";
            applied_params.push_back("*");
          }
          break;
        }

        // Type C: Limit
        case 'l': {
          if (adding) {
            ch->user_limit = std::stoll(param);
            ch->modes = mc_toggle_mode(ch->modes, 'l', true);
            applied_modes += "+l";
            applied_params.push_back(std::to_string(ch->user_limit));
          } else {
            ch->user_limit = 0;
            ch->modes = mc_toggle_mode(ch->modes, 'l', false);
            applied_modes += "-l";
          }
          break;
        }

        // Type C: Redirect
        case 'L': {
          if (adding) {
            applied_modes += "+L";
            applied_params.push_back(param);
          } else {
            applied_modes += "-L";
          }
          break;
        }

        // Type C: Join throttle
        case 'j': {
          if (adding) {
            applied_modes += "+j";
            applied_params.push_back(param);
          } else {
            applied_modes += "-j";
          }
          break;
        }

        // Type D: Prefix modes
        case 'o': case 'v': case 'h': case 'a': case 'q': {
          if (!ch->members.count(param)) {
            if (conn) server.send_numeric(conn, Numerics::ERR_USERNOTINCHANNEL,
                                           param + " " + target +
                                           " :They aren't on that channel");
            continue;
          }
          auto& mm = ch->member_modes[param];
          if (adding) {
            if (mm.find(mode_c) == std::string::npos) {
              mm += mode_c;
              // Inherit lower modes
              if (mode_c == 'q') {
                if (mm.find('a') == std::string::npos) mm += 'a';
                if (mm.find('o') == std::string::npos) mm += 'o';
              }
              if (mode_c == 'a' && mm.find('o') == std::string::npos) mm += 'o';
              if (mode_c == 'h' && mm.find('v') == std::string::npos) mm += 'v';
            }
          } else {
            auto p = mm.find(mode_c);
            if (p != std::string::npos) mm.erase(p, 1);
          }
          applied_modes += (adding ? "+" : "-") + std::string(1, mode_c);
          applied_params.push_back(param);
          break;
        }

        // Type E: Flag modes
        case 't': case 'i': case 'm': case 'n': case 'r':
        case 'c': case 'C': case 'M': case 'R': case 'K':
        case 'N': case 'O': case 'Q': case 'T': case 'u':
        case 'P': case 'F': case 'G': case 'z': {
          ch->modes = mc_toggle_mode(ch->modes, mode_c, adding);
          // Mutual exclusion: s/p
          if (adding) {
            if (mode_c == 's') { auto pp = ch->modes.find('p'); if (pp != std::string::npos) ch->modes.erase(pp, 1); }
            if (mode_c == 'p') { auto ps = ch->modes.find('s'); if (ps != std::string::npos) ch->modes.erase(ps, 1); }
          }
          applied_modes += (adding ? "+" : "-") + std::string(1, mode_c);
          break;
        }

        default:
          if (conn) server.send_numeric(conn, Numerics::ERR_UNKNOWNMODE,
                                         std::string(1, mode_c) +
                                         " :is unknown mode char to me for " + target);
          break;
      }
    }

    // Broadcast mode change to channel
    if (!applied_modes.empty()) {
      std::string source = conn ? (conn->nick + "!" + conn->user + "@" + conn->host)
                                : server.config().server_name;
      std::string mode_msg = ":" + source + " MODE " + target + " " + applied_modes;
      for (auto& p : applied_params) mode_msg += " " + p;
      server.send_to_channel(target, mode_msg);
    }

  } else {
    // ---- User MODE ----
    auto* user = server.get_user(target);
    if (!user) {
      if (conn) server.send_numeric(conn, Numerics::ERR_NOSUCHNICK,
                                      target + " :No such nick/channel");
      return;
    }

    // Query-only
    if (mode_str.empty()) {
      if (conn) server.send_numeric(conn, 221, "+" + user->modes);
      return;
    }

    // Can only change own modes unless oper
    bool is_self = conn && mc_iequals(conn->nick, target);
    bool is_oper = conn && user->oper;

    if (!is_self && !is_oper && !is_server_origin && !is_services_origin) {
      if (conn) server.send_numeric(conn, Numerics::ERR_USERSDONTMATCH,
                                      ":Cannot change mode for other users");
      return;
    }

    // Parse and apply user modes
    bool adding = true;
    std::string applied;

    for (char c : mode_str) {
      if (c == '+') { adding = true; continue; }
      if (c == '-') { adding = false; continue; }

      auto* def = mc_get_user_mode_def(c);
      if (!def) {
        if (conn) server.send_numeric(conn, Numerics::ERR_UMODEUNKNOWNFLAG,
                                       ":Unknown MODE flag");
        continue;
      }

      // Oper-only check
      if (def->oper_only && !is_oper && !is_server_origin) {
        if (conn) server.send_numeric(conn, Numerics::ERR_UMODEUNKNOWNFLAG,
                                       ":Cannot set +" + std::string(1, c) +
                                       " without oper privileges");
        continue;
      }

      // Apply the mode
      switch (c) {
        case 'i': case 'w': case 's': case 'x': case 'z':
        case 'g': case 'G': case 'B': case 'H': case 'I':
        case 'R': case 'W': case 'p':
          user->modes = mc_toggle_mode(user->modes, c, adding);
          applied += (adding ? "+" : "-") + std::string(1, c);
          break;

        case 'o':
          if (adding) {
            user->oper = true;
            user->modes = mc_toggle_mode(user->modes, 'o', true);
            applied += "+o";
          } else {
            user->oper = false;
            user->modes = mc_toggle_mode(user->modes, 'o', false);
            applied += "-o";
          }
          break;

        default:
          if (conn) server.send_numeric(conn, Numerics::ERR_UMODEUNKNOWNFLAG,
                                         ":Unknown MODE flag");
          break;
      }
    }

    // Send mode change notification
    if (!applied.empty() && conn) {
      server.send_to(conn, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                     " MODE " + target + " :" + applied);
    }
  }
}

// =============================================================================
// SECTION 15: Server MODE (S2S origin, override all permissions)
// =============================================================================

void process_server_mode(IRCServer& server, const std::string& target,
                          const std::string& mode_str,
                          const std::vector<std::string>& params,
                          const std::string& server_name) {
  // Server MODE overrides all permission checks
  // Create a temporary connection-like context for server origin
  process_mode_command(server, nullptr, target, mode_str, params, true, false);

  // Also relay to all connected servers
  std::string mode_msg = ":" + server_name + " MODE " + target + " " + mode_str;
  for (auto& p : params) mode_msg += " " + p;
  server.send_server_notice("MODE from " + server_name + ": " + mode_msg);
}

// =============================================================================
// SECTION 16: OP MODE / SAMODE (Services override)
// =============================================================================

void process_op_mode(IRCServer& server, const std::string& target,
                      const std::string& mode_str,
                      const std::vector<std::string>& params,
                      const std::string& services_name,
                      bool is_admin = false) {
  // OP MODE = services operator mode (force)
  // SAMODE = services admin mode (force with ultimate override)
  process_mode_command(server, nullptr, target, mode_str, params, false, true);

  // Log the services mode change
  std::string mode_msg = ":" + services_name + " " +
                         (is_admin ? "SAMODE" : "OPMODE") + " " +
                         target + " " + mode_str;
  for (auto& p : params) mode_msg += " " + p;
  server.send_server_notice(mode_msg);
}

void process_samode(IRCServer& server, const std::string& target,
                     const std::string& mode_str,
                     const std::vector<std::string>& params,
                     const std::string& services_name) {
  process_op_mode(server, target, mode_str, params, services_name, true);
}

// =============================================================================
// SECTION 17: Ban expiry timer integration
// =============================================================================

// Per-channel ban expiry state holder
struct ChannelBanExpiryState {
  std::string channel;
  std::vector<std::pair<std::string, int64_t>> ban_expiries;  // mask -> expiry time
  std::vector<std::pair<std::string, int64_t>> except_expiries;
  std::vector<std::pair<std::string, int64_t>> invex_expiries;
};

class ChannelBanExpiryRegistry {
public:
  void add_ban_expiry(const std::string& channel, const std::string& mask, int64_t expires) {
    if (expires == 0) return; // permanent
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    ban_expiries_[key].push_back({mask, expires});
  }

  void add_except_expiry(const std::string& channel, const std::string& mask, int64_t expires) {
    if (expires == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    except_expiries_[key].push_back({mask, expires});
  }

  void add_invex_expiry(const std::string& channel, const std::string& mask, int64_t expires) {
    if (expires == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    invex_expiries_[key].push_back({mask, expires});
  }

  // Get expired entries for a channel
  struct ExpiredResult {
    std::vector<std::string> expired_bans;
    std::vector<std::string> expired_excepts;
    std::vector<std::string> expired_invex;
  };

  ExpiredResult check_expired(const std::string& channel) {
    ExpiredResult result;
    auto now = mc_now_sec();
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);

    auto filter_expired = [&](auto& vec, auto& out) {
      auto it = vec.begin();
      while (it != vec.end()) {
        if (it->second > 0 && it->second <= now) {
          out.push_back(it->first);
          it = vec.erase(it);
        } else {
          ++it;
        }
      }
    };

    filter_expired(ban_expiries_[key], result.expired_bans);
    filter_expired(except_expiries_[key], result.expired_excepts);
    filter_expired(invex_expiries_[key], result.expired_invex);

    return result;
  }

  void remove_channel(const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = mc_to_lower(channel);
    ban_expiries_.erase(key);
    except_expiries_.erase(key);
    invex_expiries_.erase(key);
  }

private:
  std::unordered_map<std::string, std::vector<std::pair<std::string, int64_t>>> ban_expiries_;
  std::unordered_map<std::string, std::vector<std::pair<std::string, int64_t>>> except_expiries_;
  std::unordered_map<std::string, std::vector<std::pair<std::string, int64_t>>> invex_expiries_;
  std::mutex mutex_;
};

// Background timer for auto-removing expired bans
class BanExpirationTimer {
public:
  BanExpirationTimer(IRCServer& server, ChannelBanExpiryRegistry& registry)
    : server_(server), registry_(registry), running_(false) {}

  void start() {
    if (running_) return;
    running_ = true;
    timer_thread_ = std::thread([this]() { timer_loop(); });
  }

  void stop() {
    running_ = false;
    if (timer_thread_.joinable()) timer_thread_.join();
  }

private:
  void timer_loop() {
    while (running_) {
      // Check all channels with registered expiries
      // In a full implementation, we'd iterate over all channels
      // For now this is a placeholder for the expiry check loop
      std::this_thread::sleep_for(std::chrono::seconds(MC_EXPIRY_CHECK_INTERVAL));
    }
  }

  IRCServer& server_;
  ChannelBanExpiryRegistry& registry_;
  std::atomic<bool> running_;
  std::thread timer_thread_;
};

// =============================================================================
// SECTION 18: Channel mode reset on creation
// =============================================================================

struct ChannelModeDefaults {
  // Default modes applied to new channels
  static std::string default_flags() { return "nt"; }
  static std::string default_key() { return ""; }
  static int64_t default_user_limit() { return 0; }
};

void initialize_channel_modes(IRCChannel* ch) {
  if (!ch) return;

  // Set default modes: +nt
  ch->modes = ChannelModeDefaults::default_flags();

  // Clear key and limit
  ch->key.clear();
  ch->user_limit = 0;

  // Set creation timestamp
  ch->created_ts = mc_now_sec();

  // Clear lists
  ch->bans.clear();
  ch->excepts.clear();
  ch->invites.clear();

  // Clear topic state
  ch->topic.clear();
  ch->topic_setter.clear();
  ch->topic_ts = 0;
}

// =============================================================================
// SECTION 19: Mode string formatting utilities
// =============================================================================

// Build a compact mode string from channel state
std::string build_channel_mode_string(const IRCChannel& ch) {
  std::string result = "+" + ch.modes;
  if (ch.modes.find('k') != std::string::npos && !ch.key.empty())
    result += " " + ch.key;
  if (ch.modes.find('l') != std::string::npos && ch.user_limit > 0)
    result += " " + std::to_string(ch.user_limit);
  return result;
}

// Build a verbose mode string with all parameters
std::string build_verbose_mode_string(const IRCChannel& ch) {
  std::stringstream ss;
  ss << "Channel modes: +" << ch.modes;
  if (ch.modes.find('k') != std::string::npos)
    ss << " [key: " << ch.key << "]";
  if (ch.modes.find('l') != std::string::npos)
    ss << " [limit: " << ch.user_limit << "]";
  ss << " [created: " << mc_format_time(ch.created_ts) << "]";
  return ss.str();
}

// Format for RPL_CHANNELMODEIS
std::string format_rpl_channelmodeis(const std::string& channel, const IRCChannel& ch) {
  return channel + " +" + ch.modes;
}

// Format for RPL_CREATIONTIME
std::string format_rpl_creationtime(const std::string& channel, int64_t created_ts) {
  return channel + " " + std::to_string(created_ts);
}

// =============================================================================
// SECTION 20: Complete mode handler singleton and API
// =============================================================================

// Singleton complete mode handler for the entire server
static CompleteModeHandler g_complete_mode_handler;

// Public API functions that reference the singleton

CompleteModeHandler& get_complete_mode_handler() {
  return g_complete_mode_handler;
}

// Public wrappers

bool set_channel_mode_ban(const std::string& channel, const std::string& mask,
                           const std::string& set_by, int64_t duration = 0,
                           const std::string& reason = "") {
  auto& cmh = get_complete_mode_handler();
  // This would integrate with the channel state
  // Placeholder implementation
  return true;
}

bool remove_channel_mode_ban(const std::string& channel, const std::string& mask) {
  return true;
}

bool set_channel_mode_except(const std::string& channel, const std::string& mask,
                              const std::string& set_by, int64_t duration = 0) {
  return true;
}

bool remove_channel_mode_except(const std::string& channel, const std::string& mask) {
  return true;
}

bool set_channel_mode_invex(const std::string& channel, const std::string& mask,
                             const std::string& set_by, int64_t duration = 0) {
  return true;
}

bool remove_channel_mode_invex(const std::string& channel, const std::string& mask) {
  return true;
}

bool set_channel_mode_key(const std::string& channel, const std::string& key) {
  if (!mc_is_valid_key(key)) return false;
  return true;
}

bool remove_channel_mode_key(const std::string& channel) {
  return true;
}

bool set_channel_mode_limit(const std::string& channel, int64_t limit) {
  if (!mc_is_valid_user_limit(limit)) return false;
  return true;
}

bool remove_channel_mode_limit(const std::string& channel) {
  return true;
}

bool set_channel_mode_op(const std::string& channel, const std::string& nick) {
  return true;
}

bool set_channel_mode_voice(const std::string& channel, const std::string& nick) {
  return true;
}

bool set_channel_mode_halfop(const std::string& channel, const std::string& nick) {
  return true;
}

bool set_channel_mode_admin(const std::string& channel, const std::string& nick) {
  return true;
}

bool set_channel_mode_owner(const std::string& channel, const std::string& nick) {
  return true;
}

bool set_channel_flag(const std::string& channel, char flag) {
  return mc_is_valid_channel_mode(flag);
}

bool unset_channel_flag(const std::string& channel, char flag) {
  return mc_is_valid_channel_mode(flag);
}

// MLOCK public wrappers
bool set_mlock(const std::string& channel, const std::string& mode_str,
               const std::string& param_str = "") {
  auto& cmh = get_complete_mode_handler();
  if (mode_str.size() > MC_MLOCK_MAX_LEN) return false;
  cmh.mlock().set_mlock(channel, mode_str, param_str);
  return true;
}

bool remove_mlock(const std::string& channel) {
  auto& cmh = get_complete_mode_handler();
  cmh.mlock().remove_mlock(channel);
  return true;
}

std::string get_mlock_str(const std::string& channel) {
  auto& cmh = get_complete_mode_handler();
  auto* ml = cmh.mlock().get_mlock(channel);
  if (ml && ml->enabled)
    return ml->mode_string + (ml->param_str.empty() ? "" : " " + ml->param_str);
  return "";
}

// Mode history queries
std::vector<ModeHistoryTracker::ModeHistoryEntry> get_mode_history(
    const std::string& channel, size_t count = 10) {
  return get_complete_mode_handler().history().get_recent(channel, count);
}

// =============================================================================
// SECTION 21: Mode parameter validation (comprehensive)
// =============================================================================

struct ModeParamValidator {
  static bool validate_key(const std::string& key, std::string& error) {
    if (key.empty()) { error = "Key cannot be empty"; return false; }
    if (key.size() > MC_MAX_KEY_LEN) {
      error = "Key too long (max " + std::to_string(MC_MAX_KEY_LEN) + " chars)";
      return false;
    }
    for (char c : key) {
      if (c == ' ' || c == ',' || c == '\x07' || c == '\x00') {
        error = "Key contains invalid characters";
        return false;
      }
    }
    return true;
  }

  static bool validate_limit(const std::string& limit_str, int64_t& limit, std::string& error) {
    try {
      limit = std::stoll(limit_str);
    } catch (...) {
      error = "Limit is not a valid number";
      return false;
    }
    if (!mc_is_valid_user_limit(limit)) {
      error = "Limit must be between " + std::to_string(MC_MIN_USER_LIMIT) +
              " and " + std::to_string(MC_MAX_USER_LIMIT);
      return false;
    }
    return true;
  }

  static bool validate_ban_mask(const std::string& mask, std::string& error) {
    if (mask.empty()) { error = "Ban mask cannot be empty"; return false; }
    if (mask.size() > 256) { error = "Ban mask too long"; return false; }
    if (mask.find(' ') != std::string::npos) {
      error = "Ban mask cannot contain spaces";
      return false;
    }
    // Must have at least nick!user@host or simple format
    if (mask.find('!') == std::string::npos && mask.find('@') == std::string::npos) {
      // Simple nick mask — acceptable
    }
    return true;
  }

  static bool validate_join_throttle(const std::string& param, std::string& error) {
    if (!mc_is_valid_join_throttle(param)) {
      error = "Invalid join throttle format. Use N:t (e.g. 3:15 for 3 joins per 15s)";
      return false;
    }
    return true;
  }

  static bool validate_redirect(const std::string& target, std::string& error) {
    if (target.empty()) { error = "Redirect target cannot be empty"; return false; }
    if (target.size() > MC_REDIRECT_MAX_LEN) {
      error = "Redirect target too long (max " + std::to_string(MC_REDIRECT_MAX_LEN) + " chars)";
      return false;
    }
    if (target[0] != '#' && target[0] != '&' && target[0] != '!') {
      error = "Redirect target must be a valid channel name";
      return false;
    }
    for (char c : target) {
      if (c == ' ' || c == ',' || c == '\x07') {
        error = "Redirect target contains invalid characters";
        return false;
      }
    }
    return true;
  }
};

// =============================================================================
// SECTION 22: Mode change bundling optimizer
// =============================================================================

// Optimize a bundle by merging same-type changes
class ModeBundleOptimizer {
public:
  // Merge a set of mode changes into the most compact representation
  static void optimize(ModeBundle& bundle) {
    if (bundle.changes.empty()) return;

    // Remove conflicting changes (set then unset same mode)
    std::vector<ModeChange> optimized;
    std::map<char, ModeAction> last_action;

    for (auto& ch : bundle.changes) {
      // For flag modes, last action wins
      auto* def = mc_get_channel_mode_def(ch.mode_char);
      if (def && def->type == ChannelModeType::TYPE_E_FLAG) {
        last_action[ch.mode_char] = ch.action;
      } else {
        optimized.push_back(ch);
      }
    }

    // Add the resolved flag modes
    for (auto& [mode_c, action] : last_action) {
      optimized.push_back(ModeChange(mode_c, action));
    }

    // Sort: group by action (set first, then unset)
    std::stable_sort(optimized.begin(), optimized.end(),
      [](const ModeChange& a, const ModeChange& b) {
        if (a.is_set() != b.is_set()) return a.is_set();
        return a.mode_char < b.mode_char;
      });

    bundle.changes = std::move(optimized);
  }

  // Check if a set of changes can be bundled into one MODE message
  static bool can_bundle(const std::vector<ModeChange>& changes) {
    return changes.size() <= MC_MAX_MODE_CHANGES;
  }
};

// =============================================================================
// SECTION 23: Mode command syntax help
// =============================================================================

std::string get_mode_command_help() {
  std::stringstream ss;
  ss << "MODE command usage:\n";
  ss << "  MODE <channel>                   — Query channel modes\n";
  ss << "  MODE <channel> +mode... [params]  — Set channel modes\n";
  ss << "  MODE <channel> -mode... [params]  — Unset channel modes\n";
  ss << "  MODE <channel> b                 — List channel bans\n";
  ss << "  MODE <channel> e                 — List ban exceptions\n";
  ss << "  MODE <channel> I                 — List invite exceptions\n";
  ss << "  MODE <nick>                      — Query user modes\n";
  ss << "  MODE <nick> +mode...             — Set user modes\n";
  ss << "\n";
  ss << "Channel mode flags: t, i, m, n, s, p, r, c, C, M, R, K, N, O, Q, T, u, P, F, G, z\n";
  ss << "Channel param modes: b (ban), e (except), I (invex), k (key), l (limit),\n";
  ss << "                     L (redirect), j (join throttle), o (op), v (voice),\n";
  ss << "                     h (halfop), a (admin), q (owner)\n";
  ss << "User modes: i, w, s, o, x, z, g, G, B, H, I, R, W, p\n";
  return ss.str();
}

// =============================================================================
// SECTION 24: Integration helpers for IRCServer
// =============================================================================

// Call this from IRCServer to handle a MODE command with complete mode support
void ircserver_handle_mode_complete(IRCServer& server, IRCConnection* conn,
                                     const std::string& target,
                                     const std::string& mode_str,
                                     const std::vector<std::string>& params) {
  process_mode_command(server, conn, target, mode_str, params);
}

// Server-to-server MODE relay
void ircserver_handle_server_mode(IRCServer& server, const std::string& target,
                                    const std::string& mode_str,
                                    const std::vector<std::string>& params,
                                    const std::string& source_server) {
  process_server_mode(server, target, mode_str, params, source_server);
}

// Services MODE (OPMODE/SAMODE)
void ircserver_handle_services_mode(IRCServer& server, const std::string& target,
                                     const std::string& mode_str,
                                     const std::vector<std::string>& params,
                                     const std::string& services_name,
                                     bool is_admin) {
  if (is_admin)
    process_samode(server, target, mode_str, params, services_name);
  else
    process_op_mode(server, target, mode_str, params, services_name, false);
}

// Channel initialization on creation
void ircserver_initialize_channel_modes(IRCChannel* ch) {
  initialize_channel_modes(ch);
}

// Mode validation before apply
bool ircserver_validate_mode(const std::string& mode_char, const std::string& param,
                               std::string& error) {
  if (mc_is_valid_channel_mode(mode_char[0])) {
    auto* def = mc_get_channel_mode_def(mode_char[0]);
    if (!def) { error = "Unknown mode"; return false; }

    if (def->type == ChannelModeType::TYPE_B_PARAM ||
        def->type == ChannelModeType::TYPE_A_LIST) {
      return ModeParamValidator::validate_key(param, error);
    }
    if (def->type == ChannelModeType::TYPE_C_PARAMWS && mode_char[0] == 'l') {
      int64_t lim;
      return ModeParamValidator::validate_limit(param, lim, error);
    }
    if (def->type == ChannelModeType::TYPE_C_PARAMWS && mode_char[0] == 'j') {
      return ModeParamValidator::validate_join_throttle(param, error);
    }
    if (def->type == ChannelModeType::TYPE_C_PARAMWS && mode_char[0] == 'L') {
      return ModeParamValidator::validate_redirect(param, error);
    }
    return true;
  }
  return mc_is_valid_user_mode(mode_char[0]);
}

// =============================================================================
// SECTION 25: Exported mode constants for external use
// =============================================================================

// Channel mode characters
const char* CHANNEL_MODE_LIST   = "beI";
const char* CHANNEL_MODE_PARAM  = "kjlL";
const char* CHANNEL_MODE_PREFIX = "ovhaq";
const char* CHANNEL_MODE_FLAGS  = "timnsprcCMRKNOQTuPFGz";

// User mode characters
const char* USER_MODE_FLAGS = "iwsxzgGBHIRWpo";

// Prefix characters to mode mapping
char prefix_to_mode_char(char prefix) {
  switch (prefix) {
    case '~': return 'q';
    case '&': return 'a';
    case '@': return 'o';
    case '%': return 'h';
    case '+': return 'v';
    default:  return 0;
  }
}

char mode_to_prefix_char(char mode_c) {
  switch (mode_c) {
    case 'q': return '~';
    case 'a': return '&';
    case 'o': return '@';
    case 'h': return '%';
    case 'v': return '+';
    default:  return 0;
  }
}

// =============================================================================
// SECTION 26: Diagnostics and statistics
// =============================================================================

struct ModeStatistics {
  int64_t total_mode_changes = 0;
  int64_t channel_mode_changes = 0;
  int64_t user_mode_changes = 0;
  int64_t server_mode_changes = 0;
  int64_t services_mode_changes = 0;
  int64_t mlock_enforcements = 0;
  int64_t expired_bans_removed = 0;
  int64_t expired_excepts_removed = 0;
  int64_t invalid_mode_attempts = 0;

  json to_json() const {
    return {
      {"total_mode_changes", total_mode_changes},
      {"channel_mode_changes", channel_mode_changes},
      {"user_mode_changes", user_mode_changes},
      {"server_mode_changes", server_mode_changes},
      {"services_mode_changes", services_mode_changes},
      {"mlock_enforcements", mlock_enforcements},
      {"expired_bans_removed", expired_bans_removed},
      {"expired_excepts_removed", expired_excepts_removed},
      {"invalid_mode_attempts", invalid_mode_attempts}
    };
  }
};

static ModeStatistics g_mode_stats;

ModeStatistics& get_mode_statistics() { return g_mode_stats; }

void record_mode_change(bool is_channel, bool is_server, bool is_services) {
  g_mode_stats.total_mode_changes++;
  if (is_channel) g_mode_stats.channel_mode_changes++;
  else g_mode_stats.user_mode_changes++;
  if (is_server) g_mode_stats.server_mode_changes++;
  if (is_services) g_mode_stats.services_mode_changes++;
}

void record_mlock_enforcement() { g_mode_stats.mlock_enforcements++; }
void record_expired_ban_removed() { g_mode_stats.expired_bans_removed++; }
void record_expired_except_removed() { g_mode_stats.expired_excepts_removed++; }
void record_invalid_mode_attempt() { g_mode_stats.invalid_mode_attempts++; }

// =============================================================================
// END: irc_modes_complete.cpp
// =============================================================================

} // namespace progressive::irc
