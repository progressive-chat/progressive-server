// ============================================================================
// server_acls.cpp — Matrix Server ACLs, Server Blocking, IP Range Checking,
//   ACL Enforcement, Allow/Deny Lists, and Server Quarantine
//
// Implements:
//   - m.room.server_acl: Parse server ACL state events (allow_ip_literals,
//     allow, deny lists), check if server is allowed to participate in room
//   - Server blocking: Admin block/unblock remote servers, block by IP range
//     (CIDR), block by server name (glob/wildcard), block by port
//   - IP range checking: CIDR matching (IPv4/IPv6), subnet containment,
//     efficient radix tree (Patricia trie) for large rule sets
//   - Server ACL enforcement: Filter federation requests by server ACL,
//     prevent events from denied servers, prevent invites to blocked servers,
//     filter /send transactions, enforce on incoming PDUs
//   - Allow list / deny list management: Add/remove servers from lists,
//     list current state, bulk import (CSV/JSON), export, persistence
//   - Server quarantine: Quarantine entire servers (block all traffic),
//     quarantine bypass for specific rooms (allowlisted rooms),
//     quarantine levels (soft/hard), auto-quarantine on abuse detection
//
// Equivalent to:
//   synapse/events/server_acl.py
//   synapse/federation/federation_server.py (ACL enforcement hooks)
//   synapse/handlers/room_member.py (invite ACL checks)
//   synapse/handlers/federation.py (incoming event ACL filtering)
//   synapse/storage/databases/main/room.py (ACL storage queries)
//   synapse/api/filtering.py (ACL-based filtering)
//
// Target: 2500+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <atomic>
#include <bitset>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <nlohmann/json.hpp>

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
class CIDRAddress;
class CIDRPrefix;
class CIDRMatcher;
class IPRadixTree;
class ServerBlock;
class ServerBlockList;
class ServerBlockManager;
class ServerACLRules;
class ServerACLParser;
class ServerACLChecker;
class ServerACLEnforcer;
class AllowDenyList;
class AllowDenyManager;
class ServerQuarantineEntry;
class ServerQuarantineManager;
class FederationACLFilter;
class InviteACLChecker;
class ServerACLConfig;

// ============================================================================
// Enums and Constants
// ============================================================================

// Result of a server ACL check
enum class ACLResult : uint8_t {
  ALLOWED = 0,       // Server is explicitly or implicitly allowed
  DENIED = 1,        // Server is explicitly denied
  NOT_LISTED = 2,    // Server is not in any list (default-deny or default-allow)
  QUARANTINED = 3,   // Server is in quarantine
  ERROR = 4          // Error during check
};

const char* acl_result_to_string(ACLResult r) {
  switch (r) {
    case ACLResult::ALLOWED:     return "allowed";
    case ACLResult::DENIED:      return "denied";
    case ACLResult::NOT_LISTED:  return "not_listed";
    case ACLResult::QUARANTINED: return "quarantined";
    case ACLResult::ERROR:       return "error";
    default:                     return "unknown";
  }
}

// Quarantine severity levels
enum class QuarantineLevel : uint8_t {
  SOFT = 0,  // Allow existing rooms, block new invites and joins
  HARD = 1,  // Block all traffic, no exceptions
  READ_ONLY = 2  // Allow reading history but block all writes
};

const char* quarantine_level_to_string(QuarantineLevel level) {
  switch (level) {
    case QuarantineLevel::SOFT:      return "soft";
    case QuarantineLevel::HARD:      return "hard";
    case QuarantineLevel::READ_ONLY: return "read_only";
    default:                         return "unknown";
  }
}

QuarantineLevel quarantine_level_from_string(const std::string& s) {
  if (s == "soft")      return QuarantineLevel::SOFT;
  if (s == "hard")      return QuarantineLevel::HARD;
  if (s == "read_only") return QuarantineLevel::READ_ONLY;
  return QuarantineLevel::SOFT;
}

// Block type categorization
enum class BlockType : uint8_t {
  SERVER_NAME = 0,        // Exact server name match
  SERVER_NAME_GLOB = 1,   // Glob/wildcard server name match
  IP_ADDRESS = 2,         // Exact IP address
  IP_RANGE_CIDR = 3,      // CIDR range
  DOMAIN_SUFFIX = 4,      // Domain suffix (e.g., *.evil.com)
  PORT = 5,               // Block by port
  FINGERPRINT = 6         // Block by TLS certificate fingerprint
};

const char* block_type_to_string(BlockType t) {
  switch (t) {
    case BlockType::SERVER_NAME:      return "server_name";
    case BlockType::SERVER_NAME_GLOB: return "server_name_glob";
    case BlockType::IP_ADDRESS:       return "ip_address";
    case BlockType::IP_RANGE_CIDR:    return "ip_range_cidr";
    case BlockType::DOMAIN_SUFFIX:    return "domain_suffix";
    case BlockType::PORT:             return "port";
    case BlockType::FINGERPRINT:      return "fingerprint";
    default:                          return "unknown";
  }
}

// ACL default policy
enum class ACLDefaultPolicy : uint8_t {
  ALLOW = 0,  // Default-allow: only deny-listed servers are blocked
  DENY = 1    // Default-deny: only allow-listed servers are permitted
};

// ============================================================================
// Anonymous namespace — Internal helpers
// ============================================================================
namespace {

// ---- Timestamp helpers ----

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

std::string iso8601_now() {
  auto t = std::time(nullptr);
  std::tm tm;
  gmtime_r(&t, &tm);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return std::string(buf);
}

// ---- String utilities ----

std::string to_lower(const std::string& s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return r;
}

std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& str, char delim) {
  std::vector<std::string> result;
  std::istringstream iss(str);
  std::string item;
  while (std::getline(iss, item, delim)) {
    std::string trimmed = trim(item);
    if (!trimmed.empty()) result.push_back(trimmed);
  }
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

bool str_contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

bool str_starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool str_ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Simple glob matching (supports * and ?)
bool glob_match(const std::string& pattern, const std::string& text) {
  size_t p = 0, t = 0;
  size_t star_p = std::string::npos, match_t = 0;

  while (t < text.size()) {
    if (p < pattern.size() && pattern[p] == '*') {
      star_p = p;
      match_t = t;
      p++;
    } else if (p < pattern.size() &&
               (pattern[p] == '?' || pattern[p] == text[t])) {
      p++;
      t++;
    } else if (star_p != std::string::npos) {
      p = star_p + 1;
      match_t++;
      t = match_t;
    } else {
      return false;
    }
  }

  while (p < pattern.size() && pattern[p] == '*') p++;
  return p == pattern.size();
}

// ---- Server name helpers ----

// Validate Matrix server name (RFC 952/1123 hostname with optional port)
bool is_valid_server_name(const std::string& name) {
  if (name.empty() || name.size() > 255) return false;

  // Check for port
  std::string hostname = name;
  size_t colon = hostname.rfind(':');
  if (colon != std::string::npos) {
    std::string port_str = hostname.substr(colon + 1);
    hostname = hostname.substr(0, colon);
    if (port_str.empty()) return false;
    for (char c : port_str) {
      if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    int port_num = std::stoi(port_str);
    if (port_num < 1 || port_num > 65535) return false;
  }

  // Hostname validation
  if (hostname.empty() || hostname.size() > 253) return false;
  for (size_t i = 0; i < hostname.size(); ++i) {
    char c = hostname[i];
    if (c == '.') {
      if (i == 0 || i == hostname.size() - 1) return false;
      continue;
    }
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
      return false;
    }
  }
  return true;
}

// Normalize server name (lowercase, strip default port)
std::string normalize_server_name(const std::string& name) {
  std::string lower = to_lower(name);
  if (str_ends_with(lower, ":8448")) {
    lower = lower.substr(0, lower.size() - 5);
  }
  return lower;
}

// ---- IPv4/IPv6 parsing helpers ----

std::optional<uint32_t> parse_ipv4(const std::string& addr) {
  struct in_addr result;
  if (inet_pton(AF_INET, addr.c_str(), &result) == 1) {
    return ntohl(result.s_addr);
  }
  return std::nullopt;
}

struct IPv6Addr {
  uint64_t high;
  uint64_t low;

  bool operator==(const IPv6Addr& other) const {
    return high == other.high && low == other.low;
  }

  bool operator<(const IPv6Addr& other) const {
    if (high != other.high) return high < other.high;
    return low < other.low;
  }

  std::string to_string() const {
    uint8_t bytes[16];
    for (int i = 0; i < 8; ++i) {
      bytes[i] = (high >> (56 - i * 8)) & 0xFF;
      bytes[i + 8] = (low >> (56 - i * 8)) & 0xFF;
    }
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, bytes, buf, sizeof(buf));
    return std::string(buf);
  }
};

std::optional<IPv6Addr> parse_ipv6(const std::string& addr) {
  struct in6_addr result;
  if (inet_pton(AF_INET6, addr.c_str(), &result) == 1) {
    IPv6Addr ip;
    ip.high = 0;
    ip.low = 0;
    for (int i = 0; i < 8; ++i) {
      ip.high = (ip.high << 8) | result.s6_addr[i];
    }
    for (int i = 8; i < 16; ++i) {
      ip.low = (ip.low << 8) | result.s6_addr[i];
    }
    return ip;
  }
  return std::nullopt;
}

// ---- IP range / CIDR helpers ----

// Compute the subnet mask for IPv4 given prefix length
uint32_t ipv4_netmask(uint8_t prefix_len) {
  if (prefix_len == 0) return 0;
  if (prefix_len >= 32) return 0xFFFFFFFF;
  return 0xFFFFFFFF << (32 - prefix_len);
}

// Apply netmask to IPv4 address
uint32_t ipv4_apply_mask(uint32_t addr, uint8_t prefix_len) {
  return addr & ipv4_netmask(prefix_len);
}

// Apply netmask to IPv6 address
IPv6Addr ipv6_apply_mask(const IPv6Addr& addr, uint8_t prefix_len) {
  if (prefix_len >= 128) return addr;
  IPv6Addr result = addr;
  if (prefix_len == 0) {
    result.high = 0;
    result.low = 0;
  } else if (prefix_len <= 64) {
    uint64_t mask = (prefix_len == 64) ? 0xFFFFFFFFFFFFFFFFULL :
                     (0xFFFFFFFFFFFFFFFFULL << (64 - prefix_len));
    result.high &= mask;
    result.low = 0;
  } else {
    result.high = 0xFFFFFFFFFFFFFFFFULL;
    uint64_t mask = 0xFFFFFFFFFFFFFFFFULL << (128 - prefix_len);
    result.low &= mask;
  }
  return result;
}

// Check if an IPv4 is within a CIDR range
bool ipv4_in_cidr(uint32_t addr, uint32_t network, uint8_t prefix_len) {
  return ipv4_apply_mask(addr, prefix_len) == ipv4_apply_mask(network, prefix_len);
}

// Check if an IPv6 is within a CIDR range
bool ipv6_in_cidr(const IPv6Addr& addr, const IPv6Addr& network, uint8_t prefix_len) {
  return ipv6_apply_mask(addr, prefix_len) == ipv6_apply_mask(network, prefix_len);
}

// Parse CIDR notation (e.g., "192.168.1.0/24" or "2001:db8::/32")
struct ParsedCIDR {
  bool is_ipv6{false};
  uint32_t ipv4_addr{0};
  IPv6Addr ipv6_addr{};
  uint8_t prefix_len{0};
  bool valid{false};
};

ParsedCIDR parse_cidr(const std::string& cidr_str) {
  ParsedCIDR result;
  size_t slash = cidr_str.find('/');
  if (slash == std::string::npos) return result;

  std::string addr_part = trim(cidr_str.substr(0, slash));
  std::string prefix_part = trim(cidr_str.substr(slash + 1));

  if (addr_part.empty() || prefix_part.empty()) return result;

  // Parse prefix length
  try {
    int plen = std::stoi(prefix_part);
    if (plen < 0 || plen > 128) return result;
    result.prefix_len = static_cast<uint8_t>(plen);
  } catch (...) {
    return result;
  }

  // Parse address
  auto ipv4 = parse_ipv4(addr_part);
  if (ipv4.has_value()) {
    if (result.prefix_len > 32) return result;
    result.is_ipv6 = false;
    result.ipv4_addr = ipv4.value();
    result.valid = true;
    return result;
  }

  auto ipv6 = parse_ipv6(addr_part);
  if (ipv6.has_value()) {
    result.is_ipv6 = true;
    result.ipv6_addr = ipv6.value();
    result.valid = true;
    return result;
  }

  return result;
}

// Format CIDR back to string
std::string format_cidr(const ParsedCIDR& cidr) {
  if (!cidr.valid) return "invalid";
  std::string addr;
  if (cidr.is_ipv6) {
    addr = cidr.ipv6_addr.to_string();
  } else {
    struct in_addr ia;
    ia.s_addr = htonl(cidr.ipv4_addr);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ia, buf, sizeof(buf));
    addr = buf;
  }
  return addr + "/" + std::to_string(cidr.prefix_len);
}

// ---- Hash combine utility ----
size_t hash_combine(size_t seed, size_t val) {
  return seed ^ (val + 0x9e3779b9 + (seed << 6) + (seed >> 2));
}

} // anonymous namespace

// ============================================================================
// CIDRAddress — Unified IPv4/IPv6 address representation
// ============================================================================
class CIDRAddress {
public:
  enum class Family { NONE, IPv4, IPv6 };

  CIDRAddress() : family_(Family::NONE), ipv4_(0), ipv6_({0, 0}) {}

  explicit CIDRAddress(uint32_t ipv4) : family_(Family::IPv4), ipv4_(ipv4), ipv6_({0, 0}) {}

  explicit CIDRAddress(const IPv6Addr& ipv6) : family_(Family::IPv6), ipv4_(0), ipv6_(ipv6) {}

  static std::optional<CIDRAddress> parse(const std::string& addr_str) {
    auto ipv4 = parse_ipv4(addr_str);
    if (ipv4.has_value()) return CIDRAddress(ipv4.value());

    auto ipv6 = parse_ipv6(addr_str);
    if (ipv6.has_value()) return CIDRAddress(ipv6.value());

    return std::nullopt;
  }

  Family family() const { return family_; }
  bool is_ipv4() const { return family_ == Family::IPv4; }
  bool is_ipv6() const { return family_ == Family::IPv6; }
  bool is_valid() const { return family_ != Family::NONE; }

  uint32_t ipv4() const { return ipv4_; }
  const IPv6Addr& ipv6() const { return ipv6_; }

  std::string to_string() const {
    if (family_ == Family::IPv4) {
      struct in_addr ia;
      ia.s_addr = htonl(ipv4_);
      char buf[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &ia, buf, sizeof(buf));
      return std::string(buf);
    }
    if (family_ == Family::IPv6) {
      return ipv6_.to_string();
    }
    return "0.0.0.0";
  }

  bool operator==(const CIDRAddress& other) const {
    if (family_ != other.family_) return false;
    if (family_ == Family::IPv4) return ipv4_ == other.ipv4_;
    if (family_ == Family::IPv6) return ipv6_ == other.ipv6_;
    return false;
  }

  bool operator<(const CIDRAddress& other) const {
    if (family_ != other.family_) return static_cast<int>(family_) < static_cast<int>(other.family_);
    if (family_ == Family::IPv4) return ipv4_ < other.ipv4_;
    if (family_ == Family::IPv6) return ipv6_ < other.ipv6_;
    return false;
  }

  size_t hash() const {
    if (family_ == Family::IPv4) return std::hash<uint32_t>{}(ipv4_);
    if (family_ == Family::IPv6) {
      return hash_combine(std::hash<uint64_t>{}(ipv6_.high),
                          std::hash<uint64_t>{}(ipv6_.low));
    }
    return 0;
  }

  CIDRAddress apply_mask(uint8_t prefix_len) const {
    if (family_ == Family::IPv4) {
      return CIDRAddress(ipv4_apply_mask(ipv4_, prefix_len));
    }
    if (family_ == Family::IPv6) {
      return CIDRAddress(ipv6_apply_mask(ipv6_, prefix_len));
    }
    return *this;
  }

private:
  Family family_;
  uint32_t ipv4_;
  IPv6Addr ipv6_;
};

// ============================================================================
// CIDRPrefix — A CIDR range (address + prefix length)
// ============================================================================
class CIDRPrefix {
public:
  CIDRPrefix() : valid_(false), prefix_len_(0) {}

  CIDRPrefix(const CIDRAddress& addr, uint8_t prefix_len)
    : address_(addr), prefix_len_(prefix_len), valid_(true) {
    normalize();
  }

  static std::optional<CIDRPrefix> parse(const std::string& cidr_str) {
    auto parsed = parse_cidr(cidr_str);
    if (!parsed.valid) return std::nullopt;

    CIDRAddress addr;
    if (parsed.is_ipv6) {
      addr = CIDRAddress(parsed.ipv6_addr);
    } else {
      addr = CIDRAddress(parsed.ipv4_addr);
    }
    return CIDRPrefix(addr, parsed.prefix_len);
  }

  bool is_valid() const { return valid_; }
  const CIDRAddress& address() const { return address_; }
  CIDRAddress network() const { return address_.apply_mask(prefix_len_); }
  uint8_t prefix_len() const { return prefix_len_; }

  bool contains(const CIDRAddress& addr) const {
    if (!valid_ || !addr.is_valid()) return false;
    if (address_.family() != addr.family()) return false;

    auto masked_network = network();
    auto masked_addr = addr.apply_mask(prefix_len_);
    return masked_network == masked_addr;
  }

  bool contains(const std::string& addr_str) const {
    auto addr = CIDRAddress::parse(addr_str);
    return addr.has_value() && contains(addr.value());
  }

  // Check if this prefix is contained within another prefix
  bool contained_by(const CIDRPrefix& other) const {
    if (!valid_ || !other.valid_) return false;
    if (prefix_len_ < other.prefix_len_) return false;
    auto my_net = network();
    return other.contains(my_net);
  }

  std::string to_string() const {
    return address_.to_string() + "/" + std::to_string(prefix_len_);
  }

  bool operator==(const CIDRPrefix& other) const {
    return valid_ == other.valid_ &&
           prefix_len_ == other.prefix_len_ &&
           address_.apply_mask(prefix_len_) == other.address_.apply_mask(prefix_len_);
  }

  bool operator<(const CIDRPrefix& other) const {
    auto my_net = network();
    auto other_net = other.network();
    if (my_net < other_net) return true;
    if (other_net < my_net) return false;
    return prefix_len_ < other.prefix_len_;
  }

  size_t hash() const {
    return hash_combine(network().hash(), std::hash<uint8_t>{}(prefix_len_));
  }

private:
  void normalize() {
    address_ = address_.apply_mask(prefix_len_);
  }

  CIDRAddress address_;
  uint8_t prefix_len_;
  bool valid_;
};

// ============================================================================
// CIDRMatcher — Efficient CIDR matching for allow/deny lists
// ============================================================================
class CIDRMatcher {
public:
  CIDRMatcher() = default;

  void add_prefix(const CIDRPrefix& prefix) {
    if (!prefix.is_valid()) return;
    std::lock_guard<std::mutex> lock(mutex_);
    prefixes_.push_back(prefix);
    // Sort and dedup on next match
    needs_sort_ = true;
  }

  void add_prefix(const std::string& cidr_str) {
    auto prefix = CIDRPrefix::parse(cidr_str);
    if (prefix.has_value()) add_prefix(prefix.value());
  }

  void remove_prefix(const CIDRPrefix& prefix) {
    std::lock_guard<std::mutex> lock(mutex_);
    prefixes_.erase(
      std::remove_if(prefixes_.begin(), prefixes_.end(),
        [&prefix](const CIDRPrefix& p) { return p == prefix; }),
      prefixes_.end());
  }

  bool matches(const std::string& addr_str) const {
    auto addr = CIDRAddress::parse(addr_str);
    if (!addr.has_value()) return false;
    return matches(addr.value());
  }

  bool matches(const CIDRAddress& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    ensure_sorted();
    return match_internal(addr);
  }

  // Find all matching prefixes
  std::vector<CIDRPrefix> matching_prefixes(const CIDRAddress& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    ensure_sorted();
    std::vector<CIDRPrefix> result;
    for (const auto& prefix : prefixes_) {
      if (prefix.contains(addr)) {
        result.push_back(prefix);
      }
    }
    return result;
  }

  // Get most specific matching prefix
  std::optional<CIDRPrefix> most_specific_match(const CIDRAddress& addr) const {
    std::lock_guard<std::mutex> lock(mutex_);
    ensure_sorted();
    std::optional<CIDRPrefix> best;
    for (const auto& prefix : prefixes_) {
      if (prefix.contains(addr)) {
        if (!best.has_value() || prefix.prefix_len() > best->prefix_len()) {
          best = prefix;
        }
      }
    }
    return best;
  }

  size_t prefix_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return prefixes_.size();
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    prefixes_.clear();
    needs_sort_ = false;
  }

  std::vector<CIDRPrefix> all_prefixes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return prefixes_;
  }

private:
  void ensure_sorted() const {
    if (needs_sort_) {
      std::sort(prefixes_.begin(), prefixes_.end());
      prefixes_.erase(
        std::unique(prefixes_.begin(), prefixes_.end()),
        prefixes_.end());
      needs_sort_ = false;
    }
  }

  bool match_internal(const CIDRAddress& addr) const {
    for (const auto& prefix : prefixes_) {
      if (prefix.contains(addr)) return true;
    }
    return false;
  }

  mutable std::vector<CIDRPrefix> prefixes_;
  mutable bool needs_sort_{false};
  mutable std::mutex mutex_;
};

// ============================================================================
// IPRadixTree — Patricia trie for efficient IP prefix matching at scale
// ============================================================================
class IPRadixTree {
public:
  IPRadixTree() {
    root_v4_ = std::make_unique<RadixNode>();
    root_v6_ = std::make_unique<RadixNode>();
  }

  void insert(const CIDRPrefix& prefix) {
    if (!prefix.is_valid()) return;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    const CIDRAddress& addr = prefix.network();
    uint8_t plen = prefix.prefix_len();

    if (addr.is_ipv4()) {
      insert_v4(root_v4_.get(), addr.ipv4(), plen, 0);
    } else if (addr.is_ipv6()) {
      insert_v6(root_v6_.get(), addr.ipv6(), plen, 0);
    }
  }

  void remove(const CIDRPrefix& prefix) {
    if (!prefix.is_valid()) return;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    const CIDRAddress& addr = prefix.network();
    uint8_t plen = prefix.prefix_len();

    if (addr.is_ipv4()) {
      remove_v4(root_v4_.get(), addr.ipv4(), plen, 0);
    } else if (addr.is_ipv6()) {
      remove_v6(root_v6_.get(), addr.ipv6(), plen, 0);
    }
  }

  bool contains(const CIDRAddress& addr) const {
    if (!addr.is_valid()) return false;
    std::shared_lock<std::shared_mutex> lock(mutex_);

    if (addr.is_ipv4()) {
      return lookup_v4(root_v4_.get(), addr.ipv4(), 0);
    }
    return lookup_v6(root_v6_.get(), addr.ipv6(), 0);
  }

  bool contains(const std::string& addr_str) const {
    auto addr = CIDRAddress::parse(addr_str);
    return addr.has_value() && contains(addr.value());
  }

  size_t size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return count_nodes(root_v4_.get()) + count_nodes(root_v6_.get());
  }

  void clear() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    root_v4_ = std::make_unique<RadixNode>();
    root_v6_ = std::make_unique<RadixNode>();
  }

  // Dump all prefixes stored in the trie
  std::vector<CIDRPrefix> dump_prefixes() const {
    std::vector<CIDRPrefix> result;
    std::shared_lock<std::shared_mutex> lock(mutex_);
    collect_prefixes_v4(root_v4_.get(), 0, 0, result);
    collect_prefixes_v6(root_v6_.get(), IPv6Addr{0, 0}, 0, result);
    return result;
  }

private:
  struct RadixNode {
    std::unique_ptr<RadixNode> left;   // bit = 0
    std::unique_ptr<RadixNode> right;  // bit = 1
    bool is_terminal{false};

    bool has_children() const { return left || right; }
  };

  static uint32_t get_bit_v4(uint32_t addr, uint8_t pos) {
    return (addr >> (31 - pos)) & 1;
  }

  static uint64_t get_bit_v6_high(const IPv6Addr& addr, uint8_t pos) {
    return (addr.high >> (63 - pos)) & 1;
  }

  static uint64_t get_bit_v6_low(const IPv6Addr& addr, uint8_t pos) {
    return (addr.low >> (63 - pos)) & 1;
  }

  void insert_v4(RadixNode* node, uint32_t addr, uint8_t prefix_len, uint8_t depth) {
    if (depth >= prefix_len) {
      node->is_terminal = true;
      return;
    }

    uint32_t bit = get_bit_v4(addr, depth);
    auto& child = bit ? node->right : node->left;
    if (!child) child = std::make_unique<RadixNode>();
    insert_v4(child.get(), addr, prefix_len, depth + 1);

    // Collapse: if only one child and not terminal, optional optimization
  }

  void insert_v6(RadixNode* node, const IPv6Addr& addr, uint8_t prefix_len, uint8_t depth) {
    if (depth >= prefix_len) {
      node->is_terminal = true;
      return;
    }

    uint64_t bit;
    if (depth < 64) {
      bit = get_bit_v6_high(addr, depth);
    } else {
      bit = get_bit_v6_low(addr, depth - 64);
    }

    auto& child = bit ? node->right : node->left;
    if (!child) child = std::make_unique<RadixNode>();
    insert_v6(child.get(), addr, prefix_len, depth + 1);
  }

  bool lookup_v4(const RadixNode* node, uint32_t addr, uint8_t depth) const {
    if (!node) return false;
    if (node->is_terminal) return true;

    uint32_t bit = get_bit_v4(addr, depth);
    const auto& child = bit ? node->right : node->left;
    if (!child) return false;
    return lookup_v4(child.get(), addr, depth + 1);
  }

  bool lookup_v6(const RadixNode* node, const IPv6Addr& addr, uint8_t depth) const {
    if (!node) return false;
    if (node->is_terminal) return true;
    if (depth >= 128) return false;

    uint64_t bit;
    if (depth < 64) {
      bit = get_bit_v6_high(addr, depth);
    } else {
      bit = get_bit_v6_low(addr, depth - 64);
    }

    const auto& child = bit ? node->right : node->left;
    if (!child) return false;
    return lookup_v6(child.get(), addr, depth + 1);
  }

  bool remove_v4(RadixNode* node, uint32_t addr, uint8_t prefix_len, uint8_t depth) {
    if (!node) return false;

    if (depth >= prefix_len) {
      bool was_terminal = node->is_terminal;
      node->is_terminal = false;
      return was_terminal && !node->has_children();
    }

    uint32_t bit = get_bit_v4(addr, depth);
    auto& child = bit ? node->right : node->left;
    if (!child) return false;

    if (remove_v4(child.get(), addr, prefix_len, depth + 1)) {
      child.reset();
    }
    return !node->is_terminal && !node->has_children();
  }

  bool remove_v6(RadixNode* node, const IPv6Addr& addr, uint8_t prefix_len, uint8_t depth) {
    if (!node) return false;

    if (depth >= prefix_len) {
      bool was_terminal = node->is_terminal;
      node->is_terminal = false;
      return was_terminal && !node->has_children();
    }

    uint64_t bit;
    if (depth < 64) {
      bit = get_bit_v6_high(addr, depth);
    } else {
      bit = get_bit_v6_low(addr, depth - 64);
    }

    auto& child = bit ? node->right : node->left;
    if (!child) return false;

    if (remove_v6(child.get(), addr, prefix_len, depth + 1)) {
      child.reset();
    }
    return !node->is_terminal && !node->has_children();
  }

  size_t count_nodes(const RadixNode* node) const {
    if (!node) return 0;
    return (node->is_terminal ? 1 : 0) +
           count_nodes(node->left.get()) +
           count_nodes(node->right.get());
  }

  void collect_prefixes_v4(const RadixNode* node, uint32_t addr, uint8_t depth,
                            std::vector<CIDRPrefix>& out) const {
    if (!node) return;
    if (node->is_terminal) {
      out.push_back(CIDRPrefix(CIDRAddress(addr), depth));
    }
    uint32_t left_addr = addr;
    uint32_t right_addr = addr | (1u << (31 - depth));
    collect_prefixes_v4(node->left.get(), left_addr, depth + 1, out);
    collect_prefixes_v4(node->right.get(), right_addr, depth + 1, out);
  }

  void collect_prefixes_v6(const RadixNode* node, const IPv6Addr& addr, uint8_t depth,
                            std::vector<CIDRPrefix>& out) const {
    if (!node) return;
    if (node->is_terminal) {
      out.push_back(CIDRPrefix(CIDRAddress(addr), depth));
    }

    IPv6Addr left_addr = addr;
    IPv6Addr right_addr = addr;
    if (depth < 64) {
      right_addr.high |= (1ULL << (63 - depth));
    } else if (depth < 128) {
      right_addr.low |= (1ULL << (127 - depth));
    }

    collect_prefixes_v6(node->left.get(), left_addr, depth + 1, out);
    collect_prefixes_v6(node->right.get(), right_addr, depth + 1, out);
  }

  std::unique_ptr<RadixNode> root_v4_;
  std::unique_ptr<RadixNode> root_v6_;
  mutable std::shared_mutex mutex_;
};

// ============================================================================
// ServerBlock — Individual server block entry
// ============================================================================
class ServerBlock {
public:
  ServerBlock() : id_(next_id_++) {}

  ServerBlock(BlockType type, const std::string& pattern)
    : id_(next_id_++), type_(type), pattern_(to_lower(pattern)),
      created_at_(now_sec()), enabled_(true) {}

  int64_t id() const { return id_; }
  BlockType type() const { return type_; }
  const std::string& pattern() const { return pattern_; }
  const std::string& reason() const { return reason_; }
  int64_t created_at() const { return created_at_; }
  int64_t expires_at() const { return expires_at_; }
  bool enabled() const { return enabled_; }
  const std::string& created_by() const { return created_by_; }

  void set_reason(const std::string& reason) { reason_ = reason; }
  void set_created_by(const std::string& user) { created_by_ = user; }
  void set_enabled(bool enabled) { enabled_ = enabled; }
  void set_expires_at(int64_t ts) { expires_at_ = ts; }

  bool is_expired() const {
    if (expires_at_ == 0) return false;
    return now_sec() > expires_at_;
  }

  // Check if this block matches a server name
  bool matches_server_name(const std::string& name) const {
    if (!enabled_) return false;
    if (is_expired()) return false;
    std::string lower = to_lower(name);

    switch (type_) {
      case BlockType::SERVER_NAME:
        return lower == pattern_;

      case BlockType::SERVER_NAME_GLOB:
        return glob_match(pattern_, lower);

      case BlockType::DOMAIN_SUFFIX:
        return str_ends_with(lower, pattern_) &&
               (lower.size() == pattern_.size() ||
                lower[lower.size() - pattern_.size() - 1] == '.');

      case BlockType::FINGERPRINT:
        // Fingerprint matching is done separately with the actual cert
        return false;

      default:
        return false;
    }
  }

  json to_json() const {
    return {
      {"id", id_},
      {"type", block_type_to_string(type_)},
      {"pattern", pattern_},
      {"reason", reason_},
      {"enabled", enabled_},
      {"created_at", created_at_},
      {"expires_at", expires_at_},
      {"created_by", created_by_}
    };
  }

  static ServerBlock from_json(const json& j) {
    BlockType type = BlockType::SERVER_NAME;
    if (j.contains("type")) {
      std::string t = j["type"].get<std::string>();
      if (t == "server_name_glob")      type = BlockType::SERVER_NAME_GLOB;
      else if (t == "ip_address")       type = BlockType::IP_ADDRESS;
      else if (t == "ip_range_cidr")    type = BlockType::IP_RANGE_CIDR;
      else if (t == "domain_suffix")    type = BlockType::DOMAIN_SUFFIX;
      else if (t == "port")             type = BlockType::PORT;
      else if (t == "fingerprint")      type = BlockType::FINGERPRINT;
    }

    ServerBlock block(type, j.value("pattern", ""));
    if (j.contains("reason")) block.set_reason(j["reason"].get<std::string>());
    if (j.contains("enabled")) block.set_enabled(j["enabled"].get<bool>());
    if (j.contains("created_by")) block.set_created_by(j["created_by"].get<std::string>());
    if (j.contains("expires_at")) block.set_expires_at(j["expires_at"].get<int64_t>());
    return block;
  }

private:
  int64_t id_;
  BlockType type_;
  std::string pattern_;
  std::string reason_;
  int64_t created_at_{0};
  int64_t expires_at_{0};
  bool enabled_{true};
  std::string created_by_;
  static std::atomic<int64_t> next_id_;
};

std::atomic<int64_t> ServerBlock::next_id_{1};

// ============================================================================
// ServerBlockList — Collection of server blocks with efficient lookup
// ============================================================================
class ServerBlockList {
public:
  ServerBlockList() = default;

  // Add a block
  int64_t add_block(const ServerBlock& block) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    blocks_[block.id()] = block;
    reindex_block(block);
    return block.id();
  }

  // Remove a block by ID
  bool remove_block(int64_t id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = blocks_.find(id);
    if (it == blocks_.end()) return false;
    deindex_block(it->second);
    blocks_.erase(it);
    return true;
  }

  // Enable/disable a block
  bool set_enabled(int64_t id, bool enabled) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = blocks_.find(id);
    if (it == blocks_.end()) return false;
    deindex_block(it->second);
    it->second.set_enabled(enabled);
    reindex_block(it->second);
    return true;
  }

  // Check if a server name is blocked
  bool is_server_blocked(const std::string& server_name) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    // Check exact name match
    if (exact_names_.count(to_lower(server_name)) > 0) return true;

    // Check glob patterns
    std::string lower = to_lower(server_name);
    for (const auto& glob : glob_patterns_) {
      if (glob_match(glob, lower)) return true;
    }

    // Check domain suffix
    for (const auto& suffix : domain_suffixes_) {
      if (str_ends_with(lower, suffix) &&
          (lower.size() == suffix.size() ||
           lower[lower.size() - suffix.size() - 1] == '.')) {
        return true;
      }
    }

    return false;
  }

  // Check if an IP is blocked
  bool is_ip_blocked(const std::string& ip_addr) const {
    return ip_matcher_.matches(ip_addr);
  }

  // Get all blocks
  std::vector<ServerBlock> all_blocks() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<ServerBlock> result;
    result.reserve(blocks_.size());
    for (const auto& [id, block] : blocks_) {
      result.push_back(block);
    }
    return result;
  }

  // Get a specific block
  std::optional<ServerBlock> get_block(int64_t id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = blocks_.find(id);
    if (it == blocks_.end()) return std::nullopt;
    return it->second;
  }

  size_t block_count() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return blocks_.size();
  }

  // Remove expired blocks
  size_t purge_expired() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t removed = 0;
    auto it = blocks_.begin();
    while (it != blocks_.end()) {
      if (it->second.is_expired()) {
        deindex_block(it->second);
        it = blocks_.erase(it);
        removed++;
      } else {
        ++it;
      }
    }
    return removed;
  }

  // Bulk import from JSON
  size_t import_json(const json& j) {
    size_t count = 0;
    if (j.is_array()) {
      for (const auto& entry : j) {
        ServerBlock block = ServerBlock::from_json(entry);
        add_block(block);
        count++;
      }
    }
    return count;
  }

  // Export to JSON
  json export_json() const {
    json result = json::array();
    for (const auto& block : all_blocks()) {
      result.push_back(block.to_json());
    }
    return result;
  }

  void clear() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    blocks_.clear();
    exact_names_.clear();
    glob_patterns_.clear();
    domain_suffixes_.clear();
    ip_matcher_.clear();
  }

private:
  void reindex_block(const ServerBlock& block) {
    if (!block.enabled() || block.is_expired()) return;

    switch (block.type()) {
      case BlockType::SERVER_NAME:
        exact_names_.insert(block.pattern());
        break;
      case BlockType::SERVER_NAME_GLOB:
        glob_patterns_.insert(block.pattern());
        break;
      case BlockType::DOMAIN_SUFFIX:
        domain_suffixes_.insert(block.pattern());
        break;
      case BlockType::IP_RANGE_CIDR:
        ip_matcher_.add_prefix(block.pattern());
        break;
      case BlockType::IP_ADDRESS: {
        auto addr = CIDRAddress::parse(block.pattern());
        if (addr.has_value()) {
          uint8_t plen = addr->is_ipv4() ? 32 : 128;
          ip_matcher_.add_prefix(CIDRPrefix(addr.value(), plen));
        }
        break;
      }
      default:
        break;
    }
  }

  void deindex_block(const ServerBlock& block) {
    switch (block.type()) {
      case BlockType::SERVER_NAME:
        exact_names_.erase(block.pattern());
        break;
      case BlockType::SERVER_NAME_GLOB:
        glob_patterns_.erase(block.pattern());
        break;
      case BlockType::DOMAIN_SUFFIX:
        domain_suffixes_.erase(block.pattern());
        break;
      // IP ranges are harder to deindex from CIDRMatcher; we rebuild on import
      default:
        break;
    }
  }

  std::unordered_map<int64_t, ServerBlock> blocks_;
  std::unordered_set<std::string> exact_names_;
  std::unordered_set<std::string> glob_patterns_;
  std::unordered_set<std::string> domain_suffixes_;
  CIDRMatcher ip_matcher_;
  mutable std::shared_mutex mutex_;
};

// ============================================================================
// ServerBlockManager — Admin interface for server blocking
// ============================================================================
class ServerBlockManager {
public:
  ServerBlockManager();  // Defined after ServerQuarantineManager

  // ---- Block management ----

  int64_t block_server(const std::string& server_name, const std::string& reason = "",
                        const std::string& admin_user = "", int64_t expires_at = 0) {
    std::string normalized = normalize_server_name(server_name);
    ServerBlock block(BlockType::SERVER_NAME, normalized);
    block.set_reason(reason);
    block.set_created_by(admin_user);
    if (expires_at > 0) block.set_expires_at(expires_at);

    int64_t id = block_list_.add_block(block);
    log_block_action("blocked", normalized, reason, admin_user);
    return id;
  }

  int64_t block_by_glob(const std::string& pattern, const std::string& reason = "",
                         const std::string& admin_user = "", int64_t expires_at = 0) {
    ServerBlock block(BlockType::SERVER_NAME_GLOB, to_lower(pattern));
    block.set_reason(reason);
    block.set_created_by(admin_user);
    if (expires_at > 0) block.set_expires_at(expires_at);

    int64_t id = block_list_.add_block(block);
    log_block_action("blocked_glob", pattern, reason, admin_user);
    return id;
  }

  int64_t block_by_ip(const std::string& ip_addr, const std::string& reason = "",
                       const std::string& admin_user = "", int64_t expires_at = 0) {
    auto addr = CIDRAddress::parse(ip_addr);
    ServerBlock block(BlockType::IP_ADDRESS, addr.has_value() ? addr->to_string() : ip_addr);
    block.set_reason(reason);
    block.set_created_by(admin_user);
    if (expires_at > 0) block.set_expires_at(expires_at);

    int64_t id = block_list_.add_block(block);
    log_block_action("blocked_ip", ip_addr, reason, admin_user);
    return id;
  }

  int64_t block_by_cidr(const std::string& cidr, const std::string& reason = "",
                         const std::string& admin_user = "", int64_t expires_at = 0) {
    auto prefix = CIDRPrefix::parse(cidr);
    ServerBlock block(BlockType::IP_RANGE_CIDR, prefix.has_value() ? prefix->to_string() : cidr);
    block.set_reason(reason);
    block.set_created_by(admin_user);
    if (expires_at > 0) block.set_expires_at(expires_at);

    int64_t id = block_list_.add_block(block);
    log_block_action("blocked_cidr", cidr, reason, admin_user);
    return id;
  }

  int64_t block_by_domain_suffix(const std::string& suffix, const std::string& reason = "",
                                  const std::string& admin_user = "", int64_t expires_at = 0) {
    std::string normalized = to_lower(suffix);
    if (str_starts_with(normalized, ".")) normalized = normalized.substr(1);

    ServerBlock block(BlockType::DOMAIN_SUFFIX, normalized);
    block.set_reason(reason);
    block.set_created_by(admin_user);
    if (expires_at > 0) block.set_expires_at(expires_at);

    int64_t id = block_list_.add_block(block);
    log_block_action("blocked_domain_suffix", suffix, reason, admin_user);
    return id;
  }

  int64_t block_by_fingerprint(const std::string& fingerprint, const std::string& reason = "",
                                const std::string& admin_user = "", int64_t expires_at = 0) {
    ServerBlock block(BlockType::FINGERPRINT, fingerprint);
    block.set_reason(reason);
    block.set_created_by(admin_user);
    if (expires_at > 0) block.set_expires_at(expires_at);

    int64_t id = block_list_.add_block(block);
    log_block_action("blocked_fingerprint", fingerprint, reason, admin_user);
    return id;
  }

  // ---- Unblock ----

  bool unblock(int64_t block_id) {
    auto block = block_list_.get_block(block_id);
    if (!block.has_value()) return false;

    bool removed = block_list_.remove_block(block_id);
    if (removed) {
      log_block_action("unblocked", block->pattern(), block->reason(), "admin");
    }
    return removed;
  }

  bool unblock_server(const std::string& server_name) {
    std::string normalized = normalize_server_name(server_name);
    for (const auto& block : block_list_.all_blocks()) {
      if (block.type() == BlockType::SERVER_NAME &&
          to_lower(block.pattern()) == normalized &&
          block.enabled()) {
        return block_list_.remove_block(block.id());
      }
    }
    return false;
  }

  // ---- Lookup ----

  bool is_blocked(const std::string& server_name) const;  // Defined after ServerQuarantineManager

  bool is_ip_blocked(const std::string& ip_addr) const {
    return block_list_.is_ip_blocked(ip_addr);
  }

  std::vector<ServerBlock> find_blocks_by_server(const std::string& server_name) const {
    std::vector<ServerBlock> result;
    for (const auto& block : block_list_.all_blocks()) {
      if (block.matches_server_name(server_name)) {
        result.push_back(block);
      }
    }
    return result;
  }

  // ---- List operations ----

  json list_blocks(const std::string& filter_type = "all",
                    int offset = 0, int limit = 100) const {
    auto all = block_list_.all_blocks();
    std::vector<ServerBlock> filtered;

    for (const auto& block : all) {
      if (filter_type == "all" ||
          block_type_to_string(block.type()) == filter_type) {
        filtered.push_back(block);
      }
    }

    // Apply pagination
    json result = json::array();
    size_t start = std::min(static_cast<size_t>(offset), filtered.size());
    size_t end = std::min(start + static_cast<size_t>(limit), filtered.size());
    for (size_t i = start; i < end; ++i) {
      result.push_back(filtered[i].to_json());
    }

    return {
      {"blocks", result},
      {"total", filtered.size()},
      {"offset", offset},
      {"limit", limit}
    };
  }

  size_t block_count() const {
    return block_list_.block_count();
  }

  // Bulk operations
  size_t bulk_block_servers(const std::vector<std::string>& servers,
                             const std::string& reason, const std::string& admin_user) {
    size_t count = 0;
    for (const auto& server : servers) {
      block_server(server, reason, admin_user);
      count++;
    }
    return count;
  }

  size_t bulk_block_cidrs(const std::vector<std::string>& cidrs,
                           const std::string& reason, const std::string& admin_user) {
    size_t count = 0;
    for (const auto& cidr : cidrs) {
      block_by_cidr(cidr, reason, admin_user);
      count++;
    }
    return count;
  }

  // Import/Export
  json export_blocks() const {
    return block_list_.export_json();
  }

  size_t import_blocks(const json& j) {
    return block_list_.import_json(j);
  }

  // Maintenance
  size_t purge_expired() {
    size_t removed = block_list_.purge_expired();
    if (removed > 0) {
      std::cout << "[ServerBlockManager] Purged " << removed
                << " expired server blocks" << std::endl;
    }
    return removed;
  }

  void clear_all() {
    block_list_.clear();
  }

  // Access to quarantine manager
  ServerQuarantineManager& quarantine() { return *quarantine_mgr_; }
  const ServerQuarantineManager& quarantine() const { return *quarantine_mgr_; }

private:
  void log_block_action(const std::string& action, const std::string& target,
                         const std::string& reason, const std::string& admin_user) {
    std::cout << "[" << iso8601_now() << "] ServerBlockManager: "
              << action << " target=" << target
              << (reason.empty() ? "" : " reason=\"" + reason + "\"")
              << (admin_user.empty() ? "" : " by=" + admin_user)
              << std::endl;
  }

  ServerBlockList block_list_;
  std::unique_ptr<ServerQuarantineManager> quarantine_mgr_;
};

// ============================================================================
// ServerACLRules — Parsed m.room.server_acl state event
// ============================================================================
class ServerACLRules {
public:
  ServerACLRules() : allow_ip_literals_(false) {}

  // Parse from a state event content dict
  static ServerACLRules from_event_content(const json& content) {
    ServerACLRules rules;

    // Parse allow_ip_literals (default: false)
    if (content.contains("allow_ip_literals")) {
      rules.allow_ip_literals_ = content["allow_ip_literals"].get<bool>();
    }

    // Parse allow list
    if (content.contains("allow") && content["allow"].is_array()) {
      for (const auto& entry : content["allow"]) {
        if (entry.is_string()) {
          rules.allow_list_.push_back(normalize_server_name(entry.get<std::string>()));
        }
      }
    }

    // Parse deny list
    if (content.contains("deny") && content["deny"].is_array()) {
      for (const auto& entry : content["deny"]) {
        if (entry.is_string()) {
          rules.deny_list_.push_back(normalize_server_name(entry.get<std::string>()));
        }
      }
    }

    return rules;
  }

  // Serialize back to event content JSON
  json to_event_content() const {
    json allow_arr = json::array();
    for (const auto& s : allow_list_) allow_arr.push_back(s);

    json deny_arr = json::array();
    for (const auto& s : deny_list_) deny_arr.push_back(s);

    return {
      {"allow_ip_literals", allow_ip_literals_},
      {"allow", allow_arr},
      {"deny", deny_arr}
    };
  }

  // ---- Accessors ----

  bool allow_ip_literals() const { return allow_ip_literals_; }
  const std::vector<std::string>& allow_list() const { return allow_list_; }
  const std::vector<std::string>& deny_list() const { return deny_list_; }

  void set_allow_ip_literals(bool val) { allow_ip_literals_ = val; }

  void set_allow_list(const std::vector<std::string>& list) {
    allow_list_.clear();
    for (const auto& s : list) {
      allow_list_.push_back(normalize_server_name(s));
    }
  }

  void set_deny_list(const std::vector<std::string>& list) {
    deny_list_.clear();
    for (const auto& s : list) {
      deny_list_.push_back(normalize_server_name(s));
    }
  }

  // ---- Rule checks ----

  // Check if a server is allowed to participate in this room
  // Returns the ACL result based on the rules
  ACLResult check_server(const std::string& server_name) const {
    std::string normalized = normalize_server_name(server_name);

    // Check if it's an IP literal
    if (is_ip_literal(normalized)) {
      if (allow_ip_literals_) {
        // IP literals explicitly allowed — check against lists
        return check_against_lists(normalized);
      }
      // IP literals not allowed
      return ACLResult::DENIED;
    }

    // Non-IP server: check against lists
    return check_against_lists(normalized);
  }

  // Quick check: is the server denied?
  bool is_server_denied(const std::string& server_name) const {
    return check_server(server_name) == ACLResult::DENIED;
  }

  // Quick check: is the server allowed?
  bool is_server_allowed(const std::string& server_name) const {
    auto result = check_server(server_name);
    return result == ACLResult::ALLOWED || result == ACLResult::NOT_LISTED;
  }

  bool is_empty() const {
    return allow_list_.empty() && deny_list_.empty();
  }

  // Merge with another ruleset (newer event wins for overlapping entries)
  void merge(const ServerACLRules& other) {
    allow_ip_literals_ = other.allow_ip_literals_;
    allow_list_ = other.allow_list_;
    deny_list_ = other.deny_list_;
  }

  std::string summary() const {
    std::ostringstream ss;
    ss << "ServerACLRules(allow_ip_literals=" << (allow_ip_literals_ ? "true" : "false")
       << ", allow_count=" << allow_list_.size()
       << ", deny_count=" << deny_list_.size() << ")";
    return ss.str();
  }

private:
  // Check if a server name looks like an IP literal
  static bool is_ip_literal(const std::string& name) {
    // Check if it's an IPv4 literal: digits and dots only
    bool looks_like_ipv4 = true;
    int dot_count = 0;
    for (char c : name) {
      if (c == '.') {
        dot_count++;
      } else if (!std::isdigit(static_cast<unsigned char>(c))) {
        looks_like_ipv4 = false;
        break;
      }
    }
    if (looks_like_ipv4 && dot_count == 3) return true;

    // Check if it's an IPv6 literal
    if (name.find(':') != std::string::npos) {
      auto parsed = parse_ipv6(name);
      if (parsed.has_value()) return true;
    }

    return false;
  }

  ACLResult check_against_lists(const std::string& normalized_name) const {
    // First check deny list (deny takes precedence)
    for (const auto& denied : deny_list_) {
      if (matches_rule(denied, normalized_name)) {
        return ACLResult::DENIED;
      }
    }

    // Then check allow list
    for (const auto& allowed : allow_list_) {
      if (matches_rule(allowed, normalized_name)) {
        return ACLResult::ALLOWED;
      }
    }

    // If there's no allow list, everything not denied is allowed
    if (allow_list_.empty()) {
      return ACLResult::ALLOWED;
    }

    // If there is an allow list, everything not in it is denied
    return ACLResult::DENIED;
  }

  // Check if a server name matches a rule entry (supports * wildcard)
  static bool matches_rule(const std::string& rule, const std::string& name) {
    if (rule == "*") return true;
    if (rule == name) return true;
    if (str_contains(rule, "*") || str_contains(rule, "?")) {
      return glob_match(rule, name);
    }
    return false;
  }

  bool allow_ip_literals_;
  std::vector<std::string> allow_list_;
  std::vector<std::string> deny_list_;
};

// ============================================================================
// ServerACLParser — Parse and manage server ACL state events
// ============================================================================
class ServerACLParser {
public:
  ServerACLParser() = default;

  // Parse a raw m.room.server_acl event
  std::optional<ServerACLRules> parse_event(const json& event) {
    try {
      if (!event.contains("type") || event["type"].get<std::string>() != "m.room.server_acl") {
        return std::nullopt;
      }

      if (!event.contains("content")) {
        return std::nullopt;
      }

      const auto& content = event["content"];
      ServerACLRules rules = ServerACLRules::from_event_content(content);

      // Validate the rules don't have obvious issues
      auto validation = validate_rules(rules);
      if (!validation.valid) {
        log_parse_error(validation.error);
        // Still return the rules — will be handled by caller
      }

      return rules;
    } catch (const std::exception& e) {
      log_parse_error(std::string("Exception: ") + e.what());
      return std::nullopt;
    }
  }

  // Validate a rules structure
  struct ValidationResult {
    bool valid{true};
    std::string error;
  };

  ValidationResult validate_rules(const ServerACLRules& rules) {
    ValidationResult result;

    // Check for duplicate entries
    std::unordered_set<std::string> seen_allow;
    for (const auto& server : rules.allow_list()) {
      if (seen_allow.count(server) > 0) {
        result.valid = false;
        result.error = "Duplicate server in allow list: " + server;
        return result;
      }
      seen_allow.insert(server);

      // Validate server name
      if (!is_valid_server_name(server) && !is_wildcard_rule(server)) {
        result.valid = false;
        result.error = "Invalid server name in allow list: " + server;
        return result;
      }
    }

    std::unordered_set<std::string> seen_deny;
    for (const auto& server : rules.deny_list()) {
      if (seen_deny.count(server) > 0) {
        result.valid = false;
        result.error = "Duplicate server in deny list: " + server;
        return result;
      }
      seen_deny.insert(server);

      if (!is_valid_server_name(server) && !is_wildcard_rule(server)) {
        result.valid = false;
        result.error = "Invalid server name in deny list: " + server;
        return result;
      }

      // Check for conflict: same server in both lists
      if (seen_allow.count(server) > 0) {
        result.valid = false;
        result.error = "Server appears in both allow and deny lists: " + server;
        return result;
      }
    }

    // Warn if both lists are empty (no-op ACL)
    if (rules.allow_list().empty() && rules.deny_list().empty()) {
      result.valid = false;
      result.error = "Server ACL has no allow or deny entries — no-op";
    }

    return result;
  }

  // Create a new ACL event content from rules
  json make_event_content(const ServerACLRules& rules) {
    return rules.to_event_content();
  }

  // History tracking
  struct ACLHistoryEntry {
    int64_t timestamp;
    std::string event_id;
    std::string sender;
    ServerACLRules rules;
    std::string change_summary;
  };

  void record_acl_change(const std::string& room_id, const std::string& event_id,
                          const std::string& sender, const ServerACLRules& old_rules,
                          const ServerACLRules& new_rules) {
    std::lock_guard<std::mutex> lock(history_mutex_);

    ACLHistoryEntry entry;
    entry.timestamp = now_sec();
    entry.event_id = event_id;
    entry.sender = sender;
    entry.rules = new_rules;
    entry.change_summary = diff_rules(old_rules, new_rules);

    history_[room_id].push_back(entry);

    // Cap history per room
    if (history_[room_id].size() > max_history_per_room_) {
      history_[room_id].erase(history_[room_id].begin());
    }
  }

  std::vector<ACLHistoryEntry> get_history(const std::string& room_id) const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    auto it = history_.find(room_id);
    if (it == history_.end()) return {};
    return it->second;
  }

  void set_max_history(size_t max) { max_history_per_room_ = max; }

private:
  static bool is_wildcard_rule(const std::string& rule) {
    return rule == "*" || str_contains(rule, "*") || str_contains(rule, "?");
  }

  static void log_parse_error(const std::string& msg) {
    std::cerr << "[ServerACLParser] Error: " << msg << std::endl;
  }

  std::string diff_rules(const ServerACLRules& old, const ServerACLRules& new_rules) const {
    std::ostringstream ss;

    if (old.allow_ip_literals() != new_rules.allow_ip_literals()) {
      ss << "allow_ip_literals: " << (old.allow_ip_literals() ? "true" : "false")
         << " -> " << (new_rules.allow_ip_literals() ? "true" : "false") << "; ";
    }

    auto old_allow = old.allow_list();
    auto new_allow = new_rules.allow_list();
    std::sort(old_allow.begin(), old_allow.end());
    std::sort(new_allow.begin(), new_allow.end());

    std::vector<std::string> added_allow, removed_allow;
    std::set_difference(new_allow.begin(), new_allow.end(),
                         old_allow.begin(), old_allow.end(),
                         std::back_inserter(added_allow));
    std::set_difference(old_allow.begin(), old_allow.end(),
                         new_allow.begin(), new_allow.end(),
                         std::back_inserter(removed_allow));

    if (!added_allow.empty()) {
      ss << "added_allow=" << join(added_allow, ",") << "; ";
    }
    if (!removed_allow.empty()) {
      ss << "removed_allow=" << join(removed_allow, ",") << "; ";
    }

    auto old_deny = old.deny_list();
    auto new_deny = new_rules.deny_list();
    std::sort(old_deny.begin(), old_deny.end());
    std::sort(new_deny.begin(), new_deny.end());

    std::vector<std::string> added_deny, removed_deny;
    std::set_difference(new_deny.begin(), new_deny.end(),
                         old_deny.begin(), old_deny.end(),
                         std::back_inserter(added_deny));
    std::set_difference(old_deny.begin(), old_deny.end(),
                         new_deny.begin(), new_deny.end(),
                         std::back_inserter(removed_deny));

    if (!added_deny.empty()) {
      ss << "added_deny=" << join(added_deny, ",") << "; ";
    }
    if (!removed_deny.empty()) {
      ss << "removed_deny=" << join(removed_deny, ",") << "; ";
    }

    auto s = ss.str();
    return s.empty() ? "no effective change" : s;
  }

  mutable std::mutex history_mutex_;
  std::unordered_map<std::string, std::vector<ACLHistoryEntry>> history_;
  size_t max_history_per_room_{50};
};

// ============================================================================
// ServerACLChecker — Check server participation in rooms based on ACL rules
// ============================================================================
class ServerACLChecker {
public:
  ServerACLChecker() = default;

  // Set ACL rules for a room (called when state changes)
  void set_room_rules(const std::string& room_id, const ServerACLRules& rules) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    room_rules_[room_id] = rules;
  }

  // Remove ACL rules for a room
  void remove_room_rules(const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    room_rules_.erase(room_id);
  }

  // Check if a server can participate in a room
  ACLResult can_participate(const std::string& room_id, const std::string& server_name) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    // First check global blocks / quarantine
    auto quarantine_result = check_global_blocks(server_name);
    if (quarantine_result != ACLResult::ALLOWED &&
        quarantine_result != ACLResult::NOT_LISTED) {
      return quarantine_result;
    }

    // Check room-specific ACL
    auto it = room_rules_.find(room_id);
    if (it != room_rules_.end()) {
      return it->second.check_server(server_name);
    }

    // No ACL = allowed
    return ACLResult::ALLOWED;
  }

  // Check if a server is fully denied (not even read)
  bool is_denied(const std::string& room_id, const std::string& server_name) const {
    return can_participate(room_id, server_name) == ACLResult::DENIED;
  }

  // Check multiple servers
  std::map<std::string, ACLResult> check_multiple(
      const std::string& room_id,
      const std::vector<std::string>& server_names) const {
    std::map<std::string, ACLResult> results;
    for (const auto& name : server_names) {
      results[name] = can_participate(room_id, name);
    }
    return results;
  }

  // Get the rules for a room
  std::optional<ServerACLRules> get_room_rules(const std::string& room_id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = room_rules_.find(room_id);
    if (it == room_rules_.end()) return std::nullopt;
    return it->second;
  }

  // Get all rooms with ACL rules
  std::vector<std::string> rooms_with_acls() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<std::string> rooms;
    rooms.reserve(room_rules_.size());
    for (const auto& [room_id, _] : room_rules_) {
      rooms.push_back(room_id);
    }
    return rooms;
  }

  // Clear all cached rules
  void clear() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    room_rules_.clear();
  }

  // Set global block manager reference
  void set_block_manager(ServerBlockManager* mgr) {
    block_manager_ = mgr;
  }

  // Set quarantine manager reference
  void set_quarantine_manager(ServerQuarantineManager* mgr) {
    quarantine_manager_ = mgr;
  }

  // Statistics
  size_t room_count() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return room_rules_.size();
  }

private:
  ACLResult check_global_blocks(const std::string& server_name) const {
    // Check quarantine first (highest priority)
    if (quarantine_manager_ != nullptr) {
      auto quarantine = quarantine_manager_->check_quarantine(server_name);
      if (quarantine) {
        switch (quarantine->level) {
          case QuarantineLevel::HARD:
            return ACLResult::QUARANTINED;
          case QuarantineLevel::SOFT:
            // Soft quarantine = denied for new rooms, check room-specific bypass
            return ACLResult::QUARANTINED;
          case QuarantineLevel::READ_ONLY:
            return ACLResult::DENIED;
        }
      }
    }

    // Check block list
    if (block_manager_ != nullptr && block_manager_->is_blocked(server_name)) {
      return ACLResult::DENIED;
    }

    return ACLResult::ALLOWED;
  }

  std::unordered_map<std::string, ServerACLRules> room_rules_;
  mutable std::shared_mutex mutex_;
  ServerBlockManager* block_manager_{nullptr};
  ServerQuarantineManager* quarantine_manager_{nullptr};
};

// ============================================================================
// ServerACLEnforcer — Enforce ACL rules on federation traffic
// ============================================================================
class ServerACLEnforcer {
public:
  ServerACLEnforcer() = default;

  // ---- Federation request filtering ----

  // Check an incoming federation /send transaction
  struct TransactionCheckResult {
    bool allowed{true};
    std::string denied_server;
    std::string reason;
    json filtered_pdus;  // PDUs after filtering
  };

  TransactionCheckResult filter_transaction(
      const std::string& origin_server,
      const json& transaction_body) {

    TransactionCheckResult result;

    // Check if the origin server is blocked
    if (block_mgr_ && block_mgr_->is_blocked(origin_server)) {
      result.allowed = false;
      result.denied_server = origin_server;
      result.reason = "Origin server is blocked: " + origin_server;
      return result;
    }

    // Check quarantine
    if (quarantine_mgr_) {
      auto q = quarantine_mgr_->check_quarantine(origin_server);
      if (q && q->level == QuarantineLevel::HARD) {
        result.allowed = false;
        result.denied_server = origin_server;
        result.reason = "Origin server is in hard quarantine: " + origin_server;
        return result;
      }
    }

    // Filter individual PDUs
    if (transaction_body.contains("pdus") && transaction_body["pdus"].is_array()) {
      json filtered = json::array();
      for (const auto& pdu : transaction_body["pdus"]) {
        if (!should_drop_pdu(origin_server, pdu)) {
          filtered.push_back(pdu);
        }
      }
      result.filtered_pdus = filtered;
    }

    // Filter EDUs
    if (transaction_body.contains("edus") && transaction_body["edus"].is_array()) {
      json filtered = json::array();
      for (const auto& edu : transaction_body["edus"]) {
        if (!should_drop_edu(origin_server, edu)) {
          filtered.push_back(edu);
        }
      }
      result.filtered_pdus["edus"] = filtered;
    }

    return result;
  }

  // Check if a server can send events to a room
  bool can_send_to_room(const std::string& server_name, const std::string& room_id) const {
    auto result = checker_.can_participate(room_id, server_name);
    return result == ACLResult::ALLOWED || result == ACLResult::NOT_LISTED;
  }

  // Check if a server can read events from a room
  bool can_read_room(const std::string& server_name, const std::string& room_id) const {
    auto result = checker_.can_participate(room_id, server_name);
    return result != ACLResult::QUARANTINED && result != ACLResult::ERROR;
  }

  // Check if a server can be invited to a room
  bool can_invite_to_room(const std::string& server_name, const std::string& room_id) const {
    auto result = checker_.can_participate(room_id, server_name);
    return result == ACLResult::ALLOWED || result == ACLResult::NOT_LISTED;
  }

  // ---- Event filtering helpers ----

  // Determine if a PDU (Persistent Data Unit) should be dropped
  bool should_drop_pdu(const std::string& origin_server, const json& pdu) {
    // Check global blocks
    if (block_mgr_ && block_mgr_->is_blocked(origin_server)) return true;

    // Check quarantine
    if (quarantine_mgr_) {
      auto q = quarantine_mgr_->check_quarantine(origin_server);
      if (q && q->level == QuarantineLevel::HARD) return true;
    }

    // Check room ACL if room_id is present
    if (pdu.contains("room_id")) {
      std::string room_id = pdu["room_id"].get<std::string>();
      auto result = checker_.can_participate(room_id, origin_server);
      if (result == ACLResult::DENIED || result == ACLResult::QUARANTINED) return true;

      // For invitations, also check target server
      if (pdu.contains("type") && pdu["type"].get<std::string>() == "m.room.member" &&
          pdu.contains("content") && pdu["content"].contains("membership") &&
          pdu["content"]["membership"].get<std::string>() == "invite") {
        if (pdu.contains("state_key")) {
          std::string target_user = pdu["state_key"].get<std::string>();
          std::string target_server = extract_server_from_mxid(target_user);
          if (!target_server.empty() && checker_.is_denied(room_id, target_server)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  // Determine if an EDU (Ephemeral Data Unit) should be dropped
  bool should_drop_edu(const std::string& origin_server, const json& edu) {
    // Check global blocks and quarantine
    if (block_mgr_ && block_mgr_->is_blocked(origin_server)) return true;

    if (quarantine_mgr_) {
      auto q = quarantine_mgr_->check_quarantine(origin_server);
      if (q && q->level == QuarantineLevel::HARD) return true;
    }

    return false;
  }

  // ---- Configuration ----

  void set_block_manager(ServerBlockManager* mgr) {
    block_mgr_ = mgr;
    checker_.set_block_manager(mgr);
  }

  void set_quarantine_manager(ServerQuarantineManager* mgr) {
    quarantine_mgr_ = mgr;
    checker_.set_quarantine_manager(mgr);
  }

  void set_room_rules(const std::string& room_id, const ServerACLRules& rules) {
    checker_.set_room_rules(room_id, rules);
  }

  void remove_room_rules(const std::string& room_id) {
    checker_.remove_room_rules(room_id);
  }

  ServerACLChecker& checker() { return checker_; }

private:
  static std::string extract_server_from_mxid(const std::string& mxid) {
    if (str_starts_with(mxid, "@")) {
      size_t colon = mxid.find(':');
      if (colon != std::string::npos) {
        return mxid.substr(colon + 1);
      }
    }
    return "";
  }

  ServerACLChecker checker_;
  ServerBlockManager* block_mgr_{nullptr};
  ServerQuarantineManager* quarantine_mgr_{nullptr};
};

// ============================================================================
// AllowDenyList — Per-room allow/deny list management
// ============================================================================
class AllowDenyList {
public:
  AllowDenyList() = default;

  // ---- Allow list ----

  void add_to_allow(const std::string& server) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    allow_set_.insert(normalize_server_name(server));
  }

  void remove_from_allow(const std::string& server) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    allow_set_.erase(normalize_server_name(server));
  }

  bool is_allowed(const std::string& server) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return allow_set_.count(normalize_server_name(server)) > 0;
  }

  // ---- Deny list ----

  void add_to_deny(const std::string& server) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    std::string normalized = normalize_server_name(server);
    deny_set_.insert(normalized);
    // Remove from allow set if present (deny takes precedence)
    allow_set_.erase(normalized);
  }

  void remove_from_deny(const std::string& server) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    deny_set_.erase(normalize_server_name(server));
  }

  bool is_denied(const std::string& server) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return deny_set_.count(normalize_server_name(server)) > 0;
  }

  // ---- Combined check ----

  ACLResult check(const std::string& server) const {
    std::string normalized = normalize_server_name(server);
    std::shared_lock<std::shared_mutex> lock(mutex_);

    // Deny takes precedence
    if (deny_set_.count(normalized) > 0) return ACLResult::DENIED;

    if (allow_set_.count(normalized) > 0) return ACLResult::ALLOWED;

    // Not in any list
    if (allow_set_.empty()) return ACLResult::ALLOWED;  // Default-allow
    return ACLResult::DENIED;  // Default-deny when allow list exists
  }

  // ---- List operations ----

  std::vector<std::string> allow_servers() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return std::vector<std::string>(allow_set_.begin(), allow_set_.end());
  }

  std::vector<std::string> deny_servers() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return std::vector<std::string>(deny_set_.begin(), deny_set_.end());
  }

  size_t allow_count() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return allow_set_.size();
  }

  size_t deny_count() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return deny_set_.size();
  }

  void clear() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    allow_set_.clear();
    deny_set_.clear();
  }

  // Bulk operations
  void bulk_add_allow(const std::vector<std::string>& servers) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    for (const auto& server : servers) {
      allow_set_.insert(normalize_server_name(server));
    }
  }

  void bulk_add_deny(const std::vector<std::string>& servers) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    for (const auto& server : servers) {
      std::string normalized = normalize_server_name(server);
      deny_set_.insert(normalized);
      allow_set_.erase(normalized);
    }
  }

  // ---- Persistence ----

  json to_json() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return {
      {"allow", json(std::vector<std::string>(allow_set_.begin(), allow_set_.end()))},
      {"deny", json(std::vector<std::string>(deny_set_.begin(), deny_set_.end()))}
    };
  }

  void from_json(const json& j) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    clear();

    if (j.contains("allow") && j["allow"].is_array()) {
      for (const auto& s : j["allow"]) {
        if (s.is_string()) allow_set_.insert(normalize_server_name(s.get<std::string>()));
      }
    }

    if (j.contains("deny") && j["deny"].is_array()) {
      for (const auto& s : j["deny"]) {
        if (s.is_string()) deny_set_.insert(normalize_server_name(s.get<std::string>()));
      }
    }
  }

private:
  std::unordered_set<std::string> allow_set_;
  std::unordered_set<std::string> deny_set_;
  mutable std::shared_mutex mutex_;
};

// ============================================================================
// AllowDenyManager — Per-server catalog of room-specific allow/deny lists
// ============================================================================
class AllowDenyManager {
public:
  AllowDenyManager() = default;

  // Get or create allow/deny list for a room
  AllowDenyList& for_room(const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    return room_lists_[room_id];
  }

  // Allow a server in a room
  void allow_server(const std::string& room_id, const std::string& server) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    room_lists_[room_id].add_to_allow(server);
  }

  // Deny a server in a room
  void deny_server(const std::string& room_id, const std::string& server) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    room_lists_[room_id].add_to_deny(server);
  }

  // Remove a server from allow list
  void un_allow_server(const std::string& room_id, const std::string& server) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = room_lists_.find(room_id);
    if (it != room_lists_.end()) {
      it->second.remove_from_allow(server);
    }
  }

  // Remove a server from deny list
  void un_deny_server(const std::string& room_id, const std::string& server) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = room_lists_.find(room_id);
    if (it != room_lists_.end()) {
      it->second.remove_from_deny(server);
    }
  }

  // Check a server in a room
  ACLResult check(const std::string& room_id, const std::string& server) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = room_lists_.find(room_id);
    if (it == room_lists_.end()) return ACLResult::NOT_LISTED;
    return it->second.check(server);
  }

  // Get lists for a room
  std::optional<json> get_room_lists(const std::string& room_id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = room_lists_.find(room_id);
    if (it == room_lists_.end()) return std::nullopt;
    return it->second.to_json();
  }

  // Set lists for a room from JSON
  void set_room_lists(const std::string& room_id, const json& j) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    room_lists_[room_id].from_json(j);
  }

  // Remove a room's lists
  void remove_room(const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    room_lists_.erase(room_id);
  }

  // List all rooms with lists
  std::vector<std::string> managed_rooms() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<std::string> rooms;
    rooms.reserve(room_lists_.size());
    for (const auto& [room_id, _] : room_lists_) {
      rooms.push_back(room_id);
    }
    return rooms;
  }

  // Bulk import (CSV format: room_id,action,server)
  size_t import_csv(const std::string& csv_content) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t count = 0;

    std::istringstream stream(csv_content);
    std::string line;
    bool first = true;

    while (std::getline(stream, line)) {
      if (first) { first = false; continue; }  // Skip header

      auto parts = split(line, ',');
      if (parts.size() >= 3) {
        std::string room_id = trim(parts[0]);
        std::string action = to_lower(trim(parts[1]));
        std::string server = trim(parts[2]);

        if (action == "allow") {
          room_lists_[room_id].add_to_allow(server);
          count++;
        } else if (action == "deny") {
          room_lists_[room_id].add_to_deny(server);
          count++;
        }
      }
    }

    return count;
  }

  // Export all lists as JSON
  json export_all() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::object();
    for (const auto& [room_id, list] : room_lists_) {
      result[room_id] = list.to_json();
    }
    return result;
  }

  // Import all lists from JSON
  void import_all(const json& j) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    for (auto it = j.begin(); it != j.end(); ++it) {
      room_lists_[it.key()].from_json(it.value());
    }
  }

  size_t room_count() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return room_lists_.size();
  }

  void clear_all() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    room_lists_.clear();
  }

private:
  std::unordered_map<std::string, AllowDenyList> room_lists_;
  mutable std::shared_mutex mutex_;
};

// ============================================================================
// ServerQuarantineEntry — Quarantine state for a single server
// ============================================================================
class ServerQuarantineEntry {
public:
  ServerQuarantineEntry() = default;

  ServerQuarantineEntry(const std::string& server, QuarantineLevel level,
                         const std::string& reason = "", int64_t until = 0)
    : server_name_(normalize_server_name(server)), level_(level),
      reason_(reason), quarantined_at_(now_sec()),
      quarantine_until_(until), active_(true) {}

  const std::string& server_name() const { return server_name_; }
  QuarantineLevel level() const { return level_; }
  const std::string& reason() const { return reason_; }
  int64_t quarantined_at() const { return quarantined_at_; }
  int64_t quarantine_until() const { return quarantine_until_; }
  bool active() const { return active_; }

  void set_level(QuarantineLevel level) { level_ = level; }
  void set_active(bool active) { active_ = active; }
  void set_quarantine_until(int64_t until) { quarantine_until_ = until; }

  bool is_expired() const {
    if (quarantine_until_ == 0) return false;  // Permanent
    return now_sec() > quarantine_until_;
  }

  // ---- Bypass rooms ----
  // Specific rooms that are exempt from quarantine for this server

  void add_bypass_room(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(bypass_mutex_);
    bypass_rooms_.insert(room_id);
  }

  void remove_bypass_room(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(bypass_mutex_);
    bypass_rooms_.erase(room_id);
  }

  bool is_room_bypassed(const std::string& room_id) const {
    std::lock_guard<std::mutex> lock(bypass_mutex_);
    return bypass_rooms_.count(room_id) > 0;
  }

  std::vector<std::string> bypass_rooms() const {
    std::lock_guard<std::mutex> lock(bypass_mutex_);
    return std::vector<std::string>(bypass_rooms_.begin(), bypass_rooms_.end());
  }

  json to_json() const {
    return {
      {"server_name", server_name_},
      {"level", quarantine_level_to_string(level_)},
      {"reason", reason_},
      {"quarantined_at", quarantined_at_},
      {"quarantine_until", quarantine_until_},
      {"active", active_},
      {"bypass_rooms", bypass_rooms()}
    };
  }

  static ServerQuarantineEntry from_json(const json& j) {
    ServerQuarantineEntry entry;
    entry.server_name_ = normalize_server_name(j.value("server_name", ""));
    entry.level_ = quarantine_level_from_string(j.value("level", "soft"));
    entry.reason_ = j.value("reason", "");
    entry.quarantined_at_ = j.value("quarantined_at", 0);
    entry.quarantine_until_ = j.value("quarantine_until", 0);
    entry.active_ = j.value("active", true);

    if (j.contains("bypass_rooms") && j["bypass_rooms"].is_array()) {
      for (const auto& room : j["bypass_rooms"]) {
        if (room.is_string()) entry.bypass_rooms_.insert(room.get<std::string>());
      }
    }

    return entry;
  }

private:
  std::string server_name_;
  QuarantineLevel level_{QuarantineLevel::SOFT};
  std::string reason_;
  int64_t quarantined_at_{0};
  int64_t quarantine_until_{0};  // 0 = permanent
  bool active_{true};
  std::unordered_set<std::string> bypass_rooms_;
  mutable std::mutex bypass_mutex_;
};

// ============================================================================
// ServerQuarantineManager — Manage quarantine for remote servers
// ============================================================================
class ServerQuarantineManager {
public:
  ServerQuarantineManager() = default;

  // ---- Quarantine operations ----

  void quarantine_server(const std::string& server_name,
                          QuarantineLevel level = QuarantineLevel::SOFT,
                          const std::string& reason = "",
                          int64_t duration_sec = 0) {
    std::lock_guard<std::shared_mutex> lock(mutex_);

    std::string normalized = normalize_server_name(server_name);
    int64_t until = (duration_sec > 0) ? now_sec() + duration_sec : 0;

    ServerQuarantineEntry entry(normalized, level, reason, until);
    entries_[normalized] = entry;

    log_quarantine_action("quarantined", normalized, level, reason, duration_sec);
  }

  void unquarantine_server(const std::string& server_name) {
    std::lock_guard<std::shared_mutex> lock(mutex_);

    std::string normalized = normalize_server_name(server_name);
    auto it = entries_.find(normalized);
    if (it != entries_.end()) {
      it->second.set_active(false);
      log_quarantine_action("unquarantined", normalized, it->second.level(), "", 0);
    }
  }

  void remove_quarantine(const std::string& server_name) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    entries_.erase(normalize_server_name(server_name));
  }

  // ---- Quarantine check ----

  struct QuarantineCheckResult {
    bool is_quarantined{false};
    QuarantineLevel level{QuarantineLevel::SOFT};
    std::string reason;
    bool is_permanent{true};
    int64_t remaining_sec{0};
    std::vector<std::string> bypass_rooms;
  };

  std::optional<QuarantineCheckResult> check_quarantine(
      const std::string& server_name,
      const std::string& room_id = "") const {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string normalized = normalize_server_name(server_name);

    auto it = entries_.find(normalized);
    if (it == entries_.end() || !it->second.active()) {
      return std::nullopt;
    }

    const auto& entry = it->second;

    // Check expiration
    if (entry.is_expired()) {
      return std::nullopt;  // Expired quarantine, treat as not quarantined
    }

    // Check room bypass
    if (!room_id.empty() && entry.is_room_bypassed(room_id)) {
      return std::nullopt;  // Room is bypassed
    }

    QuarantineCheckResult result;
    result.is_quarantined = true;
    result.level = entry.level();
    result.reason = entry.reason();
    result.bypass_rooms = entry.bypass_rooms();

    if (entry.quarantine_until() == 0) {
      result.is_permanent = true;
      result.remaining_sec = -1;
    } else {
      result.is_permanent = false;
      result.remaining_sec = std::max<int64_t>(0, entry.quarantine_until() - now_sec());
    }

    return result;
  }

  bool is_quarantined(const std::string& server_name,
                       const std::string& room_id = "") const {
    auto result = check_quarantine(server_name, room_id);
    return result.has_value() && result->is_quarantined;
  }

  // ---- Bypass management ----

  void add_bypass_room(const std::string& server_name, const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    std::string normalized = normalize_server_name(server_name);
    auto it = entries_.find(normalized);
    if (it != entries_.end()) {
      it->second.add_bypass_room(room_id);
    }
  }

  void remove_bypass_room(const std::string& server_name, const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    std::string normalized = normalize_server_name(server_name);
    auto it = entries_.find(normalized);
    if (it != entries_.end()) {
      it->second.remove_bypass_room(room_id);
    }
  }

  // ---- Listing ----

  std::vector<ServerQuarantineEntry> all_quarantined() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<ServerQuarantineEntry> result;
    result.reserve(entries_.size());
    for (const auto& [name, entry] : entries_) {
      if (entry.active() && !entry.is_expired()) {
        result.push_back(entry);
      }
    }
    return result;
  }

  json list_quarantined_json() const {
    auto entries = all_quarantined();
    json result = json::array();
    for (const auto& entry : entries) {
      result.push_back(entry.to_json());
    }
    return {
      {"quarantined", result},
      {"total", entries.size()}
    };
  }

  size_t quarantine_count() const {
    return all_quarantined().size();
  }

  // ---- Maintenance ----

  size_t purge_expired() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t removed = 0;
    auto it = entries_.begin();
    while (it != entries_.end()) {
      if (it->second.is_expired()) {
        log_quarantine_action("expired", it->first, it->second.level(), "", 0);
        it = entries_.erase(it);
        removed++;
      } else {
        ++it;
      }
    }
    return removed;
  }

  // ---- Bulk operations ----

  void bulk_quarantine(const std::vector<std::string>& servers,
                        QuarantineLevel level, const std::string& reason) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    for (const auto& server : servers) {
      std::string normalized = normalize_server_name(server);
      int64_t until = 0;  // Permanent by default for bulk
      entries_[normalized] = ServerQuarantineEntry(normalized, level, reason, until);
    }
  }

  void bulk_unquarantine(const std::vector<std::string>& servers) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    for (const auto& server : servers) {
      std::string normalized = normalize_server_name(server);
      auto it = entries_.find(normalized);
      if (it != entries_.end()) {
        it->second.set_active(false);
      }
    }
  }

  // ---- Persistence ----

  json export_json() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::array();
    for (const auto& [name, entry] : entries_) {
      result.push_back(entry.to_json());
    }
    return result;
  }

  size_t import_json(const json& j) {
    if (!j.is_array()) return 0;
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& entry_json : j) {
      auto entry = ServerQuarantineEntry::from_json(entry_json);
      entries_[entry.server_name()] = entry;
      count++;
    }
    return count;
  }

  void clear() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    entries_.clear();
  }

private:
  void log_quarantine_action(const std::string& action, const std::string& target,
                              QuarantineLevel level, const std::string& reason,
                              int64_t duration_sec) {
    std::cout << "[" << iso8601_now() << "] ServerQuarantine: "
              << action << " server=" << target
              << " level=" << quarantine_level_to_string(level)
              << (reason.empty() ? "" : " reason=\"" + reason + "\"")
              << (duration_sec > 0 ? " duration=" + std::to_string(duration_sec) + "s" : " permanent")
              << std::endl;
  }

  std::unordered_map<std::string, ServerQuarantineEntry> entries_;
  mutable std::shared_mutex mutex_;
};

// ============================================================================
// FederationACLFilter — Filters federation traffic through ACL rules
// ============================================================================
class FederationACLFilter {
public:
  FederationACLFilter() = default;

  // ---- Incoming request filter ----

  struct FilterResult {
    bool accepted{true};
    int http_status{200};
    std::string error_code;
    std::string error_message;
    json filtered_body;
  };

  // Filter an incoming /send (transaction) request
  FilterResult filter_send_transaction(
      const std::string& origin_server,
      const std::string& remote_addr,
      const json& body) {

    FilterResult result;

    // 1. IP-based block check
    if (!remote_addr.empty() && block_manager_ &&
        block_manager_->is_ip_blocked(remote_addr)) {
      result.accepted = false;
      result.http_status = 403;
      result.error_code = "M_FORBIDDEN";
      result.error_message = "IP address is blocked: " + remote_addr;
      return result;
    }

    // 2. Server name block check
    if (block_manager_ && block_manager_->is_blocked(origin_server)) {
      result.accepted = false;
      result.http_status = 403;
      result.error_code = "M_FORBIDDEN";
      result.error_message = "Server is blocked: " + origin_server;
      return result;
    }

    // 3. Quarantine check
    if (quarantine_manager_) {
      auto q = quarantine_manager_->check_quarantine(origin_server);
      if (q && q->level == QuarantineLevel::HARD) {
        result.accepted = false;
        result.http_status = 403;
        result.error_code = "M_FORBIDDEN";
        result.error_message = "Server is in quarantine: " + origin_server;
        return result;
      }
    }

    // 4. Per-PDU ACL enforcement
    auto txn_result = enforcer_.filter_transaction(origin_server, body);
    if (!txn_result.allowed) {
      result.accepted = false;
      result.http_status = 403;
      result.error_code = "M_FORBIDDEN";
      result.error_message = txn_result.reason;
      return result;
    }

    result.filtered_body = txn_result.filtered_pdus;
    return result;
  }

  // Filter an incoming /invite request
  FilterResult filter_invite(const std::string& origin_server,
                              const std::string& room_id,
                              const std::string& invitee_server) {

    FilterResult result;

    // Check origin
    if (!enforcer_.can_send_to_room(origin_server, room_id)) {
      result.accepted = false;
      result.http_status = 403;
      result.error_code = "M_FORBIDDEN";
      result.error_message = "Origin server " + origin_server +
                              " is not allowed in room " + room_id;
      return result;
    }

    // Check invitee (target server)
    if (!invitee_server.empty() &&
        !enforcer_.can_invite_to_room(invitee_server, room_id)) {
      result.accepted = false;
      result.http_status = 403;
      result.error_code = "M_FORBIDDEN";
      result.error_message = "Server " + invitee_server +
                              " is not allowed in room " + room_id;
      return result;
    }

    return result;
  }

  // Filter an incoming /query request
  FilterResult filter_query(const std::string& origin_server,
                             const std::string& remote_addr) {
    FilterResult result;

    if (!remote_addr.empty() && block_manager_ &&
        block_manager_->is_ip_blocked(remote_addr)) {
      result.accepted = false;
      result.http_status = 403;
      result.error_code = "M_FORBIDDEN";
      result.error_message = "IP address is blocked: " + remote_addr;
      return result;
    }

    if (block_manager_ && block_manager_->is_blocked(origin_server)) {
      result.accepted = false;
      result.http_status = 403;
      result.error_code = "M_FORBIDDEN";
      result.error_message = "Server is blocked: " + origin_server;
      return result;
    }

    return result;
  }

  // Filter incoming /get_missing_events request
  FilterResult filter_get_missing_events(const std::string& origin_server,
                                          const std::string& room_id) {
    FilterResult result;

    if (!enforcer_.can_read_room(origin_server, room_id)) {
      result.accepted = false;
      result.http_status = 403;
      result.error_code = "M_FORBIDDEN";
      result.error_message = "Server " + origin_server +
                              " is denied access to room " + room_id;
      return result;
    }

    return result;
  }

  // Filter incoming /state request
  FilterResult filter_state_request(const std::string& origin_server,
                                     const std::string& room_id) {
    FilterResult result;

    if (!enforcer_.can_read_room(origin_server, room_id)) {
      result.accepted = false;
      result.http_status = 403;
      result.error_code = "M_FORBIDDEN";
      result.error_message = "Server " + origin_server +
                              " is denied access to state for room " + room_id;
      return result;
    }

    return result;
  }

  // ---- Configuration ----

  void set_block_manager(ServerBlockManager* mgr) {
    block_manager_ = mgr;
    enforcer_.set_block_manager(mgr);
  }

  void set_quarantine_manager(ServerQuarantineManager* mgr) {
    quarantine_manager_ = mgr;
    enforcer_.set_quarantine_manager(mgr);
  }

  void set_room_rules(const std::string& room_id, const ServerACLRules& rules) {
    enforcer_.set_room_rules(room_id, rules);
  }

  void remove_room_rules(const std::string& room_id) {
    enforcer_.remove_room_rules(room_id);
  }

  ServerACLEnforcer& enforcer() { return enforcer_; }

  // Statistics
  struct ACLStats {
    size_t total_checks{0};
    size_t blocked_count{0};
    size_t allowed_count{0};
    size_t quarantined_count{0};
    int64_t last_check_time{0};
  };

  void record_check(bool blocked, bool quarantined) {
    stats_.total_checks++;
    if (blocked) stats_.blocked_count++;
    else if (quarantined) stats_.quarantined_count++;
    else stats_.allowed_count++;
    stats_.last_check_time = now_ms();
  }

  ACLStats get_stats() const {
    return stats_;
  }

  void reset_stats() {
    stats_ = ACLStats{};
  }

private:
  ServerACLEnforcer enforcer_;
  ServerBlockManager* block_manager_{nullptr};
  ServerQuarantineManager* quarantine_manager_{nullptr};
  ACLStats stats_;
};

// ============================================================================
// InviteACLChecker — Check invite validity against server ACLs
// ============================================================================
class InviteACLChecker {
public:
  InviteACLChecker() = default;

  // Check if an invite from a remote server should be accepted
  struct InviteCheckResult {
    bool allowed{true};
    std::string denied_reason;
    std::string matched_rule;
  };

  InviteCheckResult check_incoming_invite(
      const std::string& room_id,
      const std::string& inviter_server,
      const std::string& invitee_user_id,
      const std::string& invitee_server) {

    InviteCheckResult result;

    // Check if inviter's server is allowed in the room
    auto inviter_result = checker_.can_participate(room_id, inviter_server);
    if (inviter_result == ACLResult::DENIED) {
      result.allowed = false;
      result.denied_reason = "Inviter server " + inviter_server +
                              " is denied in room " + room_id;
      result.matched_rule = "room_acl_deny";
      return result;
    }

    // Check if invitee's server is allowed in the room
    auto invitee_result = checker_.can_participate(room_id, invitee_server);
    if (invitee_result == ACLResult::DENIED) {
      result.allowed = false;
      result.denied_reason = "Invitee server " + invitee_server +
                              " is denied in room " + room_id;
      result.matched_rule = "room_acl_deny";
      return result;
    }

    // Check quarantine
    if (quarantine_manager_) {
      auto q = quarantine_manager_->check_quarantine(inviter_server, room_id);
      if (q) {
        result.allowed = false;
        result.denied_reason = "Inviter server " + inviter_server +
                                " is quarantined";
        result.matched_rule = "quarantine";
        return result;
      }

      q = quarantine_manager_->check_quarantine(invitee_server, room_id);
      if (q) {
        result.allowed = false;
        result.denied_reason = "Invitee server " + invitee_server +
                                " is quarantined";
        result.matched_rule = "quarantine";
        return result;
      }
    }

    return result;
  }

  // Check if an outgoing invite should be sent
  InviteCheckResult check_outgoing_invite(
      const std::string& room_id,
      const std::string& target_server) {

    InviteCheckResult result;

    // Check block list
    if (block_manager_ && block_manager_->is_blocked(target_server)) {
      result.allowed = false;
      result.denied_reason = "Target server " + target_server + " is blocked";
      result.matched_rule = "server_block";
      return result;
    }

    // Check quarantine
    if (quarantine_manager_) {
      auto q = quarantine_manager_->check_quarantine(target_server);
      if (q && q->level == QuarantineLevel::HARD) {
        result.allowed = false;
        result.denied_reason = "Target server " + target_server +
                                " is in hard quarantine";
        result.matched_rule = "quarantine";
        return result;
      }
    }

    // Check room ACL
    auto acl_result = checker_.can_participate(room_id, target_server);
    if (acl_result == ACLResult::DENIED) {
      result.allowed = false;
      result.denied_reason = "Target server " + target_server +
                              " is denied in room " + room_id;
      result.matched_rule = "room_acl_deny";
      return result;
    }

    return result;
  }

  // Set dependencies
  void set_block_manager(ServerBlockManager* mgr) { block_manager_ = mgr; }
  void set_quarantine_manager(ServerQuarantineManager* mgr) { quarantine_manager_ = mgr; }

  void set_room_rules(const std::string& room_id, const ServerACLRules& rules) {
    checker_.set_room_rules(room_id, rules);
  }

private:
  ServerACLChecker checker_;
  ServerBlockManager* block_manager_{nullptr};
  ServerQuarantineManager* quarantine_manager_{nullptr};
};

// ============================================================================
// ServerACLConfig — Configuration management for server ACL subsystem
// ============================================================================
class ServerACLConfig {
public:
  ServerACLConfig() {
    set_defaults();
  }

  void set_defaults() {
    enabled_ = true;
    default_policy_ = ACLDefaultPolicy::ALLOW;
    auto_purge_interval_sec_ = 3600;       // 1 hour
    max_blocks_ = 100000;
    max_quarantined_ = 10000;
    log_level_ = LogLevel::WARN;
    persistence_path_ = "/var/lib/progressive/acls";
    enable_ip_range_checking_ = true;
    enable_server_name_glob_ = true;
    enable_domain_suffix_blocking_ = true;
    enable_fingerprint_blocking_ = false;
    auto_quarantine_on_abuse_ = false;
    abuse_threshold_blocked_count_ = 10;
    abuse_threshold_window_sec_ = 300;      // 5 minutes
  }

  // Load from YAML/node config
  void load_from_json(const json& config) {
    if (config.contains("server_acls")) {
      const auto& acls = config["server_acls"];

      enabled_ = acls.value("enabled", enabled_);

      if (acls.contains("default_policy")) {
        std::string policy = acls["default_policy"].get<std::string>();
        default_policy_ = (policy == "deny") ? ACLDefaultPolicy::DENY : ACLDefaultPolicy::ALLOW;
      }

      auto_purge_interval_sec_ = acls.value("auto_purge_interval_sec", auto_purge_interval_sec_);
      max_blocks_ = acls.value("max_blocks", max_blocks_);
      max_quarantined_ = acls.value("max_quarantined", max_quarantined_);

      if (acls.contains("log_level")) {
        log_level_ = parse_log_level(acls["log_level"].get<std::string>());
      }

      persistence_path_ = acls.value("persistence_path", persistence_path_);
      enable_ip_range_checking_ = acls.value("enable_ip_range_checking", enable_ip_range_checking_);
      enable_server_name_glob_ = acls.value("enable_server_name_glob", enable_server_name_glob_);
      enable_domain_suffix_blocking_ = acls.value("enable_domain_suffix_blocking", enable_domain_suffix_blocking_);
      enable_fingerprint_blocking_ = acls.value("enable_fingerprint_blocking", enable_fingerprint_blocking_);
      auto_quarantine_on_abuse_ = acls.value("auto_quarantine_on_abuse", auto_quarantine_on_abuse_);
      abuse_threshold_blocked_count_ = acls.value("abuse_threshold_blocked_count", abuse_threshold_blocked_count_);
      abuse_threshold_window_sec_ = acls.value("abuse_threshold_window_sec", abuse_threshold_window_sec_);
    }
  }

  json to_json() const {
    return {
      {"server_acls", {
        {"enabled", enabled_},
        {"default_policy", default_policy_ == ACLDefaultPolicy::DENY ? "deny" : "allow"},
        {"auto_purge_interval_sec", auto_purge_interval_sec_},
        {"max_blocks", max_blocks_},
        {"max_quarantined", max_quarantined_},
        {"log_level", log_level_to_string(log_level_)},
        {"persistence_path", persistence_path_},
        {"enable_ip_range_checking", enable_ip_range_checking_},
        {"enable_server_name_glob", enable_server_name_glob_},
        {"enable_domain_suffix_blocking", enable_domain_suffix_blocking_},
        {"enable_fingerprint_blocking", enable_fingerprint_blocking_},
        {"auto_quarantine_on_abuse", auto_quarantine_on_abuse_},
        {"abuse_threshold_blocked_count", abuse_threshold_blocked_count_},
        {"abuse_threshold_window_sec", abuse_threshold_window_sec_}
      }}
    };
  }

  // Accessors
  bool enabled() const { return enabled_; }
  ACLDefaultPolicy default_policy() const { return default_policy_; }
  int64_t auto_purge_interval_sec() const { return auto_purge_interval_sec_; }
  size_t max_blocks() const { return max_blocks_; }
  size_t max_quarantined() const { return max_quarantined_; }
  enum class LogLevel { DEBUG, INFO, WARN, ERROR };
  LogLevel log_level() const { return log_level_; }
  const std::string& persistence_path() const { return persistence_path_; }
  bool enable_ip_range_checking() const { return enable_ip_range_checking_; }
  bool enable_server_name_glob() const { return enable_server_name_glob_; }
  bool enable_domain_suffix_blocking() const { return enable_domain_suffix_blocking_; }
  bool enable_fingerprint_blocking() const { return enable_fingerprint_blocking_; }
  bool auto_quarantine_on_abuse() const { return auto_quarantine_on_abuse_; }
  int abuse_threshold_blocked_count() const { return abuse_threshold_blocked_count_; }
  int64_t abuse_threshold_window_sec() const { return abuse_threshold_window_sec_; }

  void set_enabled(bool v) { enabled_ = v; }
  void set_persistence_path(const std::string& p) { persistence_path_ = p; }

private:
  static const char* log_level_to_string(LogLevel level) {
    switch (level) {
      case LogLevel::DEBUG: return "debug";
      case LogLevel::INFO:  return "info";
      case LogLevel::WARN:  return "warn";
      case LogLevel::ERROR: return "error";
      default:              return "warn";
    }
  }

  static LogLevel parse_log_level(const std::string& s) {
    if (s == "debug") return LogLevel::DEBUG;
    if (s == "info")  return LogLevel::INFO;
    if (s == "error") return LogLevel::ERROR;
    return LogLevel::WARN;
  }

  bool enabled_{true};
  ACLDefaultPolicy default_policy_{ACLDefaultPolicy::ALLOW};
  int64_t auto_purge_interval_sec_{3600};
  size_t max_blocks_{100000};
  size_t max_quarantined_{10000};
  LogLevel log_level_{LogLevel::WARN};
  std::string persistence_path_;
  bool enable_ip_range_checking_{true};
  bool enable_server_name_glob_{true};
  bool enable_domain_suffix_blocking_{true};
  bool enable_fingerprint_blocking_{false};
  bool auto_quarantine_on_abuse_{false};
  int abuse_threshold_blocked_count_{10};
  int64_t abuse_threshold_window_sec_{300};
};

// ============================================================================
// ServerACLSystem — Top-level system combining all ACL functionality
// ============================================================================
class ServerACLSystem {
public:
  ServerACLSystem() = default;

  bool init(const json& config = json::object()) {
    config_.load_from_json(config);

    // Wire up dependencies
    acl_filter_.set_block_manager(&block_manager_);
    acl_filter_.set_quarantine_manager(&block_manager_.quarantine());
    invite_checker_.set_block_manager(&block_manager_);
    invite_checker_.set_quarantine_manager(&block_manager_.quarantine());

    std::cout << "[ServerACLSystem] Initialized (enabled="
              << (config_.enabled() ? "true" : "false")
              << ", default_policy="
              << (config_.default_policy() == ACLDefaultPolicy::DENY ? "deny" : "allow")
              << ")" << std::endl;

    return true;
  }

  // ---- Access to subsystems ----

  ServerBlockManager& blocks() { return block_manager_; }
  ServerQuarantineManager& quarantine() { return block_manager_.quarantine(); }
  FederationACLFilter& federation_filter() { return acl_filter_; }
  InviteACLChecker& invite_checker() { return invite_checker_; }
  ServerACLParser& parser() { return parser_; }
  ServerACLChecker& checker() { return acl_filter_.enforcer().checker(); }
  AllowDenyManager& allow_deny() { return allow_deny_mgr_; }
  ServerACLConfig& config() { return config_; }

  // ---- Convenience methods ----

  // Process a new m.room.server_acl event
  bool handle_acl_event(const std::string& room_id, const json& event) {
    auto rules = parser_.parse_event(event);
    if (!rules.has_value()) return false;

    // Get old rules for history
    auto old_rules = checker().get_room_rules(room_id);

    // Save history
    std::string event_id = event.value("event_id", "");
    std::string sender = event.value("sender", "");
    parser_.record_acl_change(room_id, event_id, sender,
                               old_rules.value_or(ServerACLRules()),
                               rules.value());

    // Update the checker and enforcer
    acl_filter_.set_room_rules(room_id, rules.value());

    return true;
  }

  // Block a server (admin API)
  json admin_block_server(const std::string& server, const std::string& reason,
                           const std::string& admin_user) {
    int64_t id = block_manager_.block_server(server, reason, admin_user);
    auto block = block_manager_.get_block(id);
    return {
      {"success", true},
      {"block_id", id},
      {"block", block.has_value() ? block->to_json() : json(nullptr)}
    };
  }

  // Unblock a server (admin API)
  json admin_unblock_server(const std::string& server, const std::string& admin_user) {
    bool removed = block_manager_.unblock_server(server);
    return {
      {"success", removed},
      {"server", server},
      {"action", "unblock"}
    };
  }

  // Quarantine a server (admin API)
  json admin_quarantine_server(const std::string& server, const std::string& level,
                                const std::string& reason, int64_t duration_sec) {
    QuarantineLevel qlevel = quarantine_level_from_string(level);
    block_manager_.quarantine().quarantine_server(server, qlevel, reason, duration_sec);

    return {
      {"success", true},
      {"server", server},
      {"level", level},
      {"duration_sec", duration_sec}
    };
  }

  // Check a server (admin API)
  json admin_check_server(const std::string& server, const std::string& room_id) {
    bool blocked = block_manager_.is_blocked(server);
    auto quarantine = block_manager_.quarantine().check_quarantine(server, room_id);
    ACLResult acl_result = ACLResult::NOT_LISTED;

    if (!room_id.empty()) {
      acl_result = checker().can_participate(room_id, server);
    }

    return {
      {"server", server},
      {"blocked", blocked},
      {"quarantined", quarantine.has_value()},
      {"quarantine", quarantine.has_value() ? json({
        {"level", quarantine_level_to_string(quarantine->level)},
        {"reason", quarantine->reason},
        {"permanent", quarantine->is_permanent},
        {"remaining_sec", quarantine->remaining_sec}
      }) : json(nullptr)},
      {"acl_result", acl_result_to_string(acl_result)}
    };
  }

  // Maintenance task (call periodically)
  json run_maintenance() {
    size_t purged_blocks = block_manager_.purge_expired();
    size_t purged_quarantines = block_manager_.quarantine().purge_expired();

    return {
      {"purged_expired_blocks", purged_blocks},
      {"purged_expired_quarantines", purged_quarantines},
      {"active_blocks", block_manager_.block_count()},
      {"active_quarantines", block_manager_.quarantine().quarantine_count()},
      {"rooms_with_acls", checker().room_count()}
    };
  }

  // Persist state to disk
  bool save_state() {
    try {
      fs::path base_path(config_.persistence_path());
      fs::create_directories(base_path);

      // Save blocks
      {
        json blocks = block_manager_.export_blocks();
        std::ofstream out(base_path / "server_blocks.json");
        out << blocks.dump(2);
      }

      // Save quarantine
      {
        json quarantine = block_manager_.quarantine().export_json();
        std::ofstream out(base_path / "server_quarantine.json");
        out << quarantine.dump(2);
      }

      // Save allow/deny lists
      {
        json lists = allow_deny_mgr_.export_all();
        std::ofstream out(base_path / "allow_deny_lists.json");
        out << lists.dump(2);
      }

      std::cout << "[ServerACLSystem] State saved to " << base_path.string() << std::endl;
      return true;
    } catch (const std::exception& e) {
      std::cerr << "[ServerACLSystem] Failed to save state: " << e.what() << std::endl;
      return false;
    }
  }

  // Load state from disk
  bool load_state() {
    try {
      fs::path base_path(config_.persistence_path());
      if (!fs::exists(base_path)) {
        std::cout << "[ServerACLSystem] No saved state at " << base_path.string() << std::endl;
        return true;  // Not an error
      }

      // Load blocks
      {
        fs::path path = base_path / "server_blocks.json";
        if (fs::exists(path)) {
          std::ifstream in(path);
          json j;
          in >> j;
          block_manager_.import_blocks(j);
          std::cout << "[ServerACLSystem] Loaded blocks from " << path.string() << std::endl;
        }
      }

      // Load quarantine
      {
        fs::path path = base_path / "server_quarantine.json";
        if (fs::exists(path)) {
          std::ifstream in(path);
          json j;
          in >> j;
          block_manager_.quarantine().import_json(j);
          std::cout << "[ServerACLSystem] Loaded quarantine state from " << path.string() << std::endl;
        }
      }

      // Load allow/deny lists
      {
        fs::path path = base_path / "allow_deny_lists.json";
        if (fs::exists(path)) {
          std::ifstream in(path);
          json j;
          in >> j;
          allow_deny_mgr_.import_all(j);
          std::cout << "[ServerACLSystem] Loaded allow/deny lists from " << path.string() << std::endl;
        }
      }

      return true;
    } catch (const std::exception& e) {
      std::cerr << "[ServerACLSystem] Failed to load state: " << e.what() << std::endl;
      return false;
    }
  }

private:
  ServerBlockManager block_manager_;
  FederationACLFilter acl_filter_;
  InviteACLChecker invite_checker_;
  ServerACLParser parser_;
  AllowDenyManager allow_deny_mgr_;
  ServerACLConfig config_;
};

} // namespace progressive

// ============================================================================
// Out-of-line definitions (needed because ServerQuarantineManager was
// forward-declared when ServerBlockManager was defined)
// ============================================================================
namespace progressive {

ServerBlockManager::ServerBlockManager()
  : quarantine_mgr_(std::make_unique<ServerQuarantineManager>()) {}

bool ServerBlockManager::is_blocked(const std::string& server_name) const {
  auto action = quarantine_mgr_->check_quarantine(server_name);
  if (action && action->level == QuarantineLevel::HARD) return true;

  return block_list_.is_server_blocked(server_name);
}

} // namespace progressive
