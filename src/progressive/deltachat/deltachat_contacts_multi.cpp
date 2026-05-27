// deltachat_contacts_multi.cpp - DeltaChat contact import/export, address book sync,
// and multi-account management. 3000+ lines.
#include "deltachat.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace progressive::deltachat {
using json = nlohmann::json;

// ============================================================================
// Forward declarations for internal helpers
// ============================================================================
static std::string base64_encode(const std::string& data);
static std::string base64_decode(const std::string& data);
static std::string sha256(const std::string& data);
static std::string md5_hex(const std::string& data);
static std::string hex_encode(const std::string& data);
static std::string hex_decode(const std::string& hex);
static std::string url_encode(const std::string& s);
static std::string url_decode(const std::string& s);
static std::string trim(const std::string& s);
static std::string to_lower(const std::string& s);
static std::string to_upper(const std::string& s);
static std::vector<std::string> split(const std::string& s, char delim);
static std::vector<std::string> split_lines(const std::string& s);
static std::string join(const std::vector<std::string>& parts, const std::string& delim);
static bool starts_with(const std::string& s, const std::string& prefix);
static bool ends_with(const std::string& s, const std::string& suffix);
static std::string replace_all(std::string s, const std::string& from, const std::string& to);
static int64_t nms();
static std::string gen_token(int len = 32);
static std::string format_rfc2822_date(time_t t);
static std::string generate_avatar_color(const std::string& addr);
static bool valid_email(const std::string& addr);
static std::string escape_vcard_field(const std::string& s);
static std::string unescape_vcard_field(const std::string& s);
static std::string normalize_email(const std::string& addr);
static std::string extract_name_from_email(const std::string& addr);
static std::string levenshtein_normalize(const std::string& s);

// ============================================================================
// Internal helpers implementation
// ============================================================================
static int64_t nms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

static std::string gen_token(int len) {
  static const char cs[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(nms() + std::hash<std::thread::id>{}(std::this_thread::get_id()));
  std::uniform_int_distribution<> d(0, 61);
  std::string t(len, 'A');
  for (auto& c : t) c = cs[d(rng)];
  return t;
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

static std::string to_upper(const std::string& s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(), ::toupper);
  return r;
}

static std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> parts;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) parts.push_back(item);
  return parts;
}

static std::vector<std::string> split_lines(const std::string& s) {
  return split(s, '\n');
}

static std::string join(const std::vector<std::string>& parts,
                         const std::string& delim) {
  if (parts.empty()) return "";
  std::string r = parts[0];
  for (size_t i = 1; i < parts.size(); ++i) r += delim + parts[i];
  return r;
}

static bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

static bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static std::string replace_all(std::string s, const std::string& from,
                                const std::string& to) {
  size_t pos = 0;
  while ((pos = s.find(from, pos)) != std::string::npos) {
    s.replace(pos, from.length(), to);
    pos += to.length();
  }
  return s;
}

static bool valid_email(const std::string& addr) {
  static const std::regex email_re(
      R"(^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$)");
  return std::regex_match(addr, email_re);
}

static std::string normalize_email(const std::string& addr) {
  return to_lower(trim(addr));
}

static std::string extract_name_from_email(const std::string& addr) {
  auto at = addr.find('@');
  if (at == std::string::npos) return addr;
  return addr.substr(0, at);
}

static std::string levenshtein_normalize(const std::string& s) {
  std::string r = to_lower(trim(s));
  r.erase(std::remove_if(r.begin(), r.end(),
                          [](char c) { return !std::isalnum(c); }),
          r.end());
  return r;
}

// ============================================================================
// Base64 implementation
// ============================================================================
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const std::string& data) {
  std::string out;
  int val = 0, valb = -6;
  for (unsigned char c : data) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(base64_chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4) out.push_back('=');
  return out;
}

static std::string base64_decode(const std::string& data) {
  std::string out;
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;
  int val = 0, valb = -8;
  for (unsigned char c : data) {
    if (T[c] == -1) break;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

// ============================================================================
// SHA-256 implementation
// ============================================================================
static std::string sha256(const std::string& data) {
  // Simple SHA-256 implementation for checksums
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  static const uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  std::vector<uint8_t> padded(data.begin(), data.end());
  uint64_t bit_len = data.size() * 8;
  padded.push_back(0x80);
  while ((padded.size() + 8) % 64 != 0) padded.push_back(0x00);
  for (int i = 7; i >= 0; --i)
    padded.push_back((bit_len >> (i * 8)) & 0xFF);

  for (size_t chunk = 0; chunk < padded.size(); chunk += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
      w[i] = ((uint32_t)padded[chunk + i * 4] << 24) |
             ((uint32_t)padded[chunk + i * 4 + 1] << 16) |
             ((uint32_t)padded[chunk + i * 4 + 2] << 8) |
             ((uint32_t)padded[chunk + i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
      uint32_t s0 = (w[i - 15] >> 7 | w[i - 15] << 25) ^
                    (w[i - 15] >> 18 | w[i - 15] << 14) ^ (w[i - 15] >> 3);
      uint32_t s1 = (w[i - 2] >> 17 | w[i - 2] << 15) ^
                    (w[i - 2] >> 19 | w[i - 2] << 13) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
      uint32_t S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^
                    (e >> 25 | e << 7);
      uint32_t ch = (e & f) ^ ((~e) & g);
      uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
      uint32_t S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^
                    (a >> 22 | a << 10);
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t temp2 = S0 + maj;
      hh = g; g = f; f = e; e = d + temp1;
      d = c; c = b; b = a; a = temp1 + temp2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  std::stringstream ss;
  for (int i = 0; i < 8; ++i)
    ss << std::hex << std::setfill('0') << std::setw(8) << h[i];
  return ss.str();
}

static std::string md5_hex(const std::string& data) {
  // Simplified checksum using sha256 truncated for vCard UID generation
  return sha256(data + "md5salt").substr(0, 32);
}

static std::string hex_encode(const std::string& data) {
  static const char hex_chars[] = "0123456789abcdef";
  std::string out;
  for (unsigned char c : data) {
    out.push_back(hex_chars[c >> 4]);
    out.push_back(hex_chars[c & 0x0F]);
  }
  return out;
}

static std::string hex_decode(const std::string& hex) {
  std::string out;
  for (size_t i = 0; i + 1 < hex.length(); i += 2) {
    int high = hex[i] >= 'a' ? hex[i] - 'a' + 10
                : hex[i] >= 'A' ? hex[i] - 'A' + 10
                : hex[i] - '0';
    int low = hex[i + 1] >= 'a' ? hex[i + 1] - 'a' + 10
                : hex[i + 1] >= 'A' ? hex[i + 1] - 'A' + 10
                : hex[i + 1] - '0';
    out.push_back((high << 4) | low);
  }
  return out;
}

static std::string url_encode(const std::string& s) {
  static const char hex[] = "0123456789ABCDEF";
  std::string out;
  for (char c : s) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
      out += c;
    else {
      out += '%';
      out += hex[(c >> 4) & 0xF];
      out += hex[c & 0xF];
    }
  }
  return out;
}

static std::string url_decode(const std::string& s) {
  std::string out;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%' && i + 2 < s.size()) {
      int val = 0;
      for (int j = 1; j <= 2; ++j) {
        char c = s[i + j];
        val <<= 4;
        if (c >= '0' && c <= '9') val += c - '0';
        else if (c >= 'a' && c <= 'f') val += c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') val += c - 'A' + 10;
      }
      out.push_back((char)val);
      i += 2;
    } else if (s[i] == '+') {
      out.push_back(' ');
    } else {
      out.push_back(s[i]);
    }
  }
  return out;
}

static std::string format_rfc2822_date(time_t t) {
  char buf[64];
  struct tm tm_buf;
  gmtime_r(&t, &tm_buf);
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000", &tm_buf);
  return std::string(buf);
}

static std::string escape_vcard_field(const std::string& s) {
  std::string r = s;
  r = replace_all(r, "\\", "\\\\");
  r = replace_all(r, ";", "\\;");
  r = replace_all(r, ",", "\\,");
  r = replace_all(r, "\n", "\\n");
  r = replace_all(r, "\r", "\\r");
  return r;
}

static std::string unescape_vcard_field(const std::string& s) {
  std::string r = s;
  r = replace_all(r, "\\n", "\n");
  r = replace_all(r, "\\r", "\r");
  r = replace_all(r, "\\,", ",");
  r = replace_all(r, "\\;", ";");
  r = replace_all(r, "\\\\", "\\");
  return r;
}

static std::string generate_avatar_color(const std::string& addr) {
  auto h = std::hash<std::string>{}(addr);
  int r = (h & 0xFF0000) >> 16;
  int g = (h & 0x00FF00) >> 8;
  int b = (h & 0x0000FF);
  // Make colors vibrant: ensure at least one component is bright
  int max_c = std::max({r, g, b});
  if (max_c < 128) {
    r = r * 180 / max_c;
    g = g * 180 / max_c;
    b = b * 180 / max_c;
  }
  // Make colors darker for readability
  r = r * 70 / 100;
  g = g * 70 / 100;
  b = b * 70 / 100;
  char buf[8];
  snprintf(buf, sizeof(buf), "#%02x%02x%02x", r & 0xFF, g & 0xFF, b & 0xFF);
  return std::string(buf);
}

// ============================================================================
// Contact extended data structures
// ============================================================================
struct ContactExtended {
  uint32_t id{0};
  std::string nickname;         // Nickname/alias
  std::string private_notes;    // Private notes about contact
  bool is_favorite{false};      // Favorite contact
  int64_t added_at{0};          // When contact was added
  int64_t last_interaction{0};  // Last message interaction timestamp
  int interaction_count{0};     // Number of interactions
  std::string avatar_cache_path; // Local cache path for avatar
  int64_t avatar_cache_time{0};  // When avatar was cached
  std::string phone_number;      // Phone number (for address book sync)
  std::string organization;      // Company/organization
  std::string title;             // Job title
  std::string source;            // Where contact came from ("manual","addressbook","chat","import")
  int online_status{0};          // 0=offline, 1=online, 2=away, 3=busy
  int64_t online_since{0};       // When came online
  std::vector<std::string> group_tags; // Custom group tags
  int verification_level{0};     // 0=unverified, 1=verified, 2=bidirectional
  int64_t verification_time{0};  // When verified
  std::string verification_method; // "autocrypt","qr","manual"
  bool auto_connect{false};      // Auto-connect via Autocrypt
};

// ============================================================================
// Account data structure for multi-account management
// ============================================================================
struct AccountInfo {
  uint32_t account_id{0};
  std::string dbfile;
  std::string display_name;
  std::string email_addr;
  bool active{false};
  bool configured{false};
  int64_t created_at{0};
  int64_t last_fetch{0};
  int64_t next_fetch{0};
  int fetch_interval_seconds{300};  // Default 5 minutes
  int message_count{0};
  int chat_count{0};
  int contact_count{0};
  std::string backup_path;
  int64_t last_backup{0};
  std::string device_id;
  std::string device_name;
  bool fetch_in_background{true};
  bool notifications_enabled{true};
  int unread_count{0};
  std::string avatar_path;
  std::string status_message;
  bool archive_on_other_devices{false};
  int64_t sync_timestamp{0};
};

// ============================================================================
// Address book entry (for system address book sync)
// ============================================================================
struct AddressBookEntry {
  std::string name;
  std::string email;
  std::string phone;
  std::string organization;
  std::string title;
  std::string avatar_path;
  int64_t last_modified{0};
  std::string source_id;  // System-specific ID
};

// ============================================================================
// Import result
// ============================================================================
struct ImportResult {
  int total_imported{0};
  int total_skipped{0};
  int total_merged{0};
  int total_errors{0};
  int total_updated{0};
  std::vector<uint32_t> imported_ids;
  std::vector<std::string> errors;
};

// ============================================================================
// Contact import from address book (Feature 1)
// ============================================================================
ImportResult DeltaChat::import_contacts_from_address_book(
    const std::vector<AddressBookEntry>& entries,
    bool overwrite_existing,
    bool deduplicate) {

  ImportResult result;
  int64_t import_time = nms();

  // Build lookup maps for existing contacts
  std::unordered_map<std::string, uint32_t> email_to_id;
  std::unordered_map<std::string, uint32_t> phone_to_id;
  for (const auto& [id, c] : contacts_) {
    if (!c.addr.empty())
      email_to_id[normalize_email(c.addr)] = id;
  }

  // First pass: identify all entries and their match status
  struct EntryMatch {
    AddressBookEntry entry;
    uint32_t matched_id{0};
    bool is_new{true};
    bool is_duplicate{false};
    uint32_t duplicate_of{0};
  };

  std::vector<EntryMatch> matches;
  matches.reserve(entries.size());

  for (const auto& entry : entries) {
    EntryMatch m;
    m.entry = entry;

    if (entry.email.empty() && entry.phone.empty()) {
      result.total_skipped++;
      continue;
    }

    // Check if email already exists
    if (!entry.email.empty()) {
      auto norm = normalize_email(entry.email);
      if (email_to_id.count(norm)) {
        m.matched_id = email_to_id[norm];
        m.is_new = false;
      }
    }

    // Check phone if no email match
    if (m.is_new && !entry.phone.empty()) {
      if (phone_to_id.count(entry.phone)) {
        m.matched_id = phone_to_id[entry.phone];
        m.is_new = false;
      }
    }

    if (m.is_new && deduplicate) {
      // Check for duplicate entries within the import batch
      for (size_t j = 0; j < matches.size(); ++j) {
        auto& prev = matches[j];
        if (!prev.entry.email.empty() && !entry.email.empty() &&
            normalize_email(prev.entry.email) == normalize_email(entry.email)) {
          m.is_duplicate = true;
          m.duplicate_of = j;
          break;
        }
      }
    }

    matches.push_back(m);
  }

  // Second pass: perform the import
  std::set<size_t> processed_duplicates;
  for (size_t i = 0; i < matches.size(); ++i) {
    auto& m = matches[i];

    if (m.is_duplicate) {
      result.total_merged++;
      // Merge data into the primary entry
      if (m.duplicate_of < matches.size()) {
        auto& primary = matches[m.duplicate_of];
        if (primary.entry.phone.empty() && !m.entry.phone.empty())
          primary.entry.phone = m.entry.phone;
        if (primary.entry.organization.empty() && !m.entry.organization.empty())
          primary.entry.organization = m.entry.organization;
        if (primary.entry.title.empty() && !m.entry.title.empty())
          primary.entry.title = m.entry.title;
        if (primary.entry.avatar_path.empty() && !m.entry.avatar_path.empty())
          primary.entry.avatar_path = m.entry.avatar_path;
      }
      continue;
    }

    if (!m.is_new && !overwrite_existing) {
      // Update existing contact with non-empty fields only
      auto it = contacts_.find(m.matched_id);
      if (it != contacts_.end()) {
        if (!m.entry.name.empty()) it->second.name = m.entry.name;
        result.total_updated++;
      }
      continue;
    }

    if (!m.is_new && overwrite_existing) {
      // Full overwrite of existing contact
      auto it = contacts_.find(m.matched_id);
      if (it != contacts_.end()) {
        it->second.name = m.entry.name.empty() ? it->second.name : m.entry.name;
        it->second.addr = m.entry.email.empty() ? it->second.addr : m.entry.email;
        it->second.status = m.entry.title;
        result.total_updated++;
        result.imported_ids.push_back(m.matched_id);
      }
      continue;
    }

    // Create new contact
    if (m.is_new) {
      std::string name = m.entry.name.empty()
                             ? extract_name_from_email(m.entry.email)
                             : m.entry.name;
      std::string addr = m.entry.email;

      if (addr.empty()) {
        // No email, skip
        result.total_skipped++;
        continue;
      }

      uint32_t new_id = gen_id();
      DcContact c;
      c.id = new_id;
      c.name = name;
      c.display_name = name;
      c.addr = addr;
      c.color = generate_avatar_color(addr);
      c.last_seen = 0;
      c.verified = 0;
      c.blocked = 0;
      contacts_[new_id] = c;

      // Store extended info
      ContactExtended ext;
      ext.id = new_id;
      ext.phone_number = m.entry.phone;
      ext.organization = m.entry.organization;
      ext.title = m.entry.title;
      ext.added_at = import_time;
      ext.source = "addressbook";
      ext.verification_level = 0;
      if (!m.entry.avatar_path.empty()) {
        ext.avatar_cache_path = m.entry.avatar_path;
        ext.avatar_cache_time = import_time;
      }
      contact_extended_[new_id] = ext;

      email_to_id[normalize_email(addr)] = new_id;
      if (!m.entry.phone.empty())
        phone_to_id[m.entry.phone] = new_id;

      result.total_imported++;
      result.imported_ids.push_back(new_id);
    }
  }

  return result;
}

// ============================================================================
// Contact export to vCard/VCF (Feature 2)
// ============================================================================
std::string DeltaChat::export_contacts_to_vcard(
    const std::vector<uint32_t>& contact_ids,
    bool include_private_fields,
    bool include_avatars) {

  std::stringstream vcf;
  vcf << "BEGIN:VCARD\r\n";
  vcf << "VERSION:3.0\r\n";
  vcf << "PRODID:-//DeltaChat//Contact Export//EN\r\n";

  std::vector<uint32_t> ids = contact_ids;
  if (ids.empty()) {
    // Export all contacts
    ids.reserve(contacts_.size());
    for (const auto& [id, c] : contacts_) ids.push_back(id);
  }

  for (auto cid : ids) {
    auto it = contacts_.find(cid);
    if (it == contacts_.end()) continue;

    const auto& c = it->second;
    vcf << "BEGIN:VCARD\r\n";
    vcf << "VERSION:3.0\r\n";

    // Generate unique UID
    std::string uid = md5_hex(c.addr + std::to_string(cid) + "deltachat");
    vcf << "UID:" << uid << "\r\n";

    // Name
    if (!c.name.empty())
      vcf << "FN:" << escape_vcard_field(c.name) << "\r\n";

    // Display name
    if (!c.display_name.empty() && c.display_name != c.name)
      vcf << "NICKNAME:" << escape_vcard_field(c.display_name) << "\r\n";

    // Email
    if (!c.addr.empty()) {
      std::string type_str = "INTERNET";
      vcf << "EMAIL;TYPE=" << type_str << ":"
          << escape_vcard_field(c.addr) << "\r\n";
    }

    // Auth name
    if (!c.auth_name.empty())
      vcf << "X-AUTH-NAME:" << escape_vcard_field(c.auth_name) << "\r\n";

    // Status
    if (!c.status.empty())
      vcf << "NOTE:" << escape_vcard_field(c.status) << "\r\n";

    // Color
    if (!c.color.empty())
      vcf << "X-COLOR:" << escape_vcard_field(c.color) << "\r\n";

    // DeltaChat-specific fields
    vcf << "X-DELTACHAT-ID:" << cid << "\r\n";
    vcf << "X-VERIFICATION-LEVEL:" << c.verified << "\r\n";

    if (c.blocked)
      vcf << "X-BLOCKED:1\r\n";

    if (c.last_seen > 0)
      vcf << "X-LAST-SEEN:" << c.last_seen << "\r\n";

    // Extended contact fields (if include_private_fields)
    if (include_private_fields) {
      auto ext_it = contact_extended_.find(cid);
      if (ext_it != contact_extended_.end()) {
        const auto& ext = ext_it->second;
        if (!ext.nickname.empty())
          vcf << "X-NICKNAME:" << escape_vcard_field(ext.nickname) << "\r\n";
        if (!ext.phone_number.empty())
          vcf << "TEL;TYPE=CELL:" << escape_vcard_field(ext.phone_number)
              << "\r\n";
        if (!ext.organization.empty())
          vcf << "ORG:" << escape_vcard_field(ext.organization) << "\r\n";
        if (!ext.title.empty())
          vcf << "TITLE:" << escape_vcard_field(ext.title) << "\r\n";
        if (!ext.private_notes.empty())
          vcf << "X-PRIVATE-NOTES:"
              << escape_vcard_field(ext.private_notes) << "\r\n";
        if (ext.is_favorite)
          vcf << "X-FAVORITE:1\r\n";
        if (!ext.group_tags.empty())
          vcf << "X-GROUP-TAGS:"
              << escape_vcard_field(join(ext.group_tags, ",")) << "\r\n";
      }
    }

    // Avatar (base64 encoded inline if include_avatars)
    if (include_avatars && !c.profile_image.empty()) {
      std::ifstream img_file(c.profile_image, std::ios::binary);
      if (img_file.good()) {
        std::string img_data((std::istreambuf_iterator<char>(img_file)),
                              std::istreambuf_iterator<char>());
        if (!img_data.empty()) {
          std::string b64 = base64_encode(img_data);
          std::string ext = c.profile_image.substr(
              c.profile_image.find_last_of('.') + 1);
          std::string mime = "image/" + (ext == "png" ? "png"
                                          : ext == "jpg" ? "jpeg"
                                          : ext == "gif" ? "gif"
                                          : ext == "webp" ? "webp"
                                          : ext == "svg" ? "svg+xml"
                                                         : "jpeg");
          vcf << "PHOTO;ENCODING=b;TYPE=" << mime << ":" << b64 << "\r\n";
        }
      }
    }

    vcf << "END:VCARD\r\n";
  }

  vcf << "END:VCARD\r\n";
  return vcf.str();
}

// ============================================================================
// Import contacts from vCard/VCF string (Feature 2 companion)
// ============================================================================
ImportResult DeltaChat::import_contacts_from_vcard(
    const std::string& vcard_data,
    bool overwrite_existing,
    bool deduplicate) {

  ImportResult result;
  int64_t import_time = nms();

  // Parse vCard data - find individual vCards
  std::string data = vcard_data;
  // Normalize line endings
  data = replace_all(data, "\r\n", "\n");
  data = replace_all(data, "\r", "\n");

  // Find positions of all vCards
  std::vector<size_t> begin_positions;
  std::vector<size_t> end_positions;
  size_t pos = 0;

  while (true) {
    pos = data.find("BEGIN:VCARD", pos);
    if (pos == std::string::npos) break;
    begin_positions.push_back(pos);
    pos += 11;  // Skip "BEGIN:VCARD"
  }

  for (size_t i = 0; i < begin_positions.size(); ++i) {
    size_t start = begin_positions[i];
    size_t end_search = start + 11;

    // Skip the outer vCard wrapper (first BEGIN:VCARD without UID)
    if (i == 0 && begin_positions.size() > 1) {
      // Check if this is the outermost wrapper
      size_t next_begin = (i + 1 < begin_positions.size())
                              ? begin_positions[i + 1]
                              : std::string::npos;
      size_t vcard_end = data.find("END:VCARD", end_search);
      // If the next BEGIN:VCARD is before END:VCARD, this is a wrapper
      if (next_begin != std::string::npos && vcard_end != std::string::npos &&
          next_begin < vcard_end)
        continue;  // Skip wrapper
    }

    size_t vcard_end = data.find("END:VCARD", end_search);
    if (vcard_end == std::string::npos) continue;

    std::string vcard = data.substr(start, vcard_end - start + 10);

    // Parse fields from this vCard
    std::string fn, email, phone, org, title, nickname, notes, color;
    std::string x_auth_name, x_blocked, x_verification;
    std::string x_last_seen, x_favorite, x_group_tags;
    std::string photo_b64, photo_type;
    uint32_t existing_id = 0;
    int verification_level = 0;

    auto lines = split_lines(vcard);
    std::string current_field;

    // Rejoin folded lines (vCard line folding)
    std::string line;
    for (size_t li = 0; li < lines.size(); ++li) {
      const auto& l = lines[li];
      if (l.empty()) continue;

      if ((li + 1) < lines.size() &&
          (lines[li + 1].size() > 0 &&
           (lines[li + 1][0] == ' ' || lines[li + 1][0] == '\t'))) {
        // Folded line continuation
        line += l;
        while ((li + 1) < lines.size() &&
               (lines[li + 1].size() > 0 &&
                (lines[li + 1][0] == ' ' || lines[li + 1][0] == '\t'))) {
          li++;
          line += lines[li].substr(1);
        }
      } else {
        line = l;
      }

      // Parse the (possibly unfolded) line
      auto colon = line.find(':');
      if (colon == std::string::npos) continue;
      std::string key = line.substr(0, colon);
      std::string value = line.substr(colon + 1);

      // Handle type parameters
      std::string base_key = key;
      auto semicolon = key.find(';');
      if (semicolon != std::string::npos) {
        base_key = key.substr(0, semicolon);
      }

      base_key = to_upper(trim(base_key));

      if (base_key == "FN" || base_key == "N") {
        if (fn.empty()) fn = unescape_vcard_field(trim(value));
      } else if (base_key == "EMAIL") {
        if (email.empty()) email = unescape_vcard_field(trim(value));
      } else if (base_key == "TEL") {
        if (phone.empty()) phone = unescape_vcard_field(trim(value));
      } else if (base_key == "ORG") {
        org = unescape_vcard_field(trim(value));
      } else if (base_key == "TITLE") {
        title = unescape_vcard_field(trim(value));
      } else if (base_key == "NICKNAME") {
        nickname = unescape_vcard_field(trim(value));
      } else if (base_key == "NOTE") {
        notes += (notes.empty() ? "" : "\n") + unescape_vcard_field(trim(value));
      } else if (base_key == "X-COLOR") {
        color = unescape_vcard_field(trim(value));
      } else if (base_key == "X-AUTH-NAME") {
        x_auth_name = unescape_vcard_field(trim(value));
      } else if (base_key == "X-DELTACHAT-ID") {
        try { existing_id = std::stoul(value); }
        catch (...) { existing_id = 0; }
      } else if (base_key == "X-VERIFICATION-LEVEL") {
        try { verification_level = std::stoi(value); }
        catch (...) { verification_level = 0; }
      } else if (base_key == "X-BLOCKED") {
        x_blocked = trim(value);
      } else if (base_key == "X-LAST-SEEN") {
        x_last_seen = trim(value);
      } else if (base_key == "X-NICKNAME") {
        nickname = unescape_vcard_field(trim(value));
      } else if (base_key == "X-PRIVATE-NOTES") {
        notes = unescape_vcard_field(trim(value));
      } else if (base_key == "X-FAVORITE") {
        x_favorite = trim(value);
      } else if (base_key == "X-GROUP-TAGS") {
        x_group_tags = unescape_vcard_field(trim(value));
      } else if (base_key == "PHOTO") {
        // Extract encoding and type
        auto enc_pos = key.find("ENCODING=b");
        if (enc_pos != std::string::npos) {
          photo_b64 = trim(value);
        }
        auto type_pos = key.find("TYPE=");
        if (type_pos != std::string::npos) {
          photo_type = key.substr(type_pos + 5);
          auto sc = photo_type.find(';');
          if (sc != std::string::npos)
            photo_type = photo_type.substr(0, sc);
        }
      }
    }

    // Now create the contact
    if (email.empty()) {
      result.total_skipped++;
      result.errors.push_back("No email in vCard for: " + fn);
      continue;
    }

    // Check if contact already exists
    bool exists = false;
    uint32_t matched_id = 0;
    std::string norm = normalize_email(email);

    if (existing_id > 0 && contacts_.count(existing_id)) {
      exists = true;
      matched_id = existing_id;
    } else {
      for (const auto& [id, c] : contacts_) {
        if (normalize_email(c.addr) == norm) {
          exists = true;
          matched_id = id;
          break;
        }
      }
    }

    if (exists && !overwrite_existing) {
      result.total_skipped++;
      continue;
    }

    if (exists && overwrite_existing) {
      auto& c = contacts_[matched_id];
      if (!fn.empty()) { c.name = fn; c.display_name = fn; }
      if (!color.empty()) c.color = color;
      if (!x_auth_name.empty()) c.auth_name = x_auth_name;
      if (!notes.empty()) c.status = notes;
      c.verified = verification_level;
      if (x_blocked == "1") c.blocked = 1;

      auto& ext = contact_extended_[matched_id];
      ext.id = matched_id;
      if (!nickname.empty()) ext.nickname = nickname;
      if (!phone.empty()) ext.phone_number = phone;
      if (!org.empty()) ext.organization = org;
      if (!title.empty()) ext.title = title;
      if (!notes.empty()) ext.private_notes = notes;
      if (x_favorite == "1") ext.is_favorite = true;
      if (!x_group_tags.empty())
        ext.group_tags = split(x_group_tags, ',');
      ext.verification_level = verification_level;
      ext.source = "vcard_import";

      result.total_updated++;
      result.imported_ids.push_back(matched_id);
      continue;
    }

    // Create new contact
    uint32_t new_id = gen_id();
    DcContact c;
    c.id = new_id;
    c.name = fn.empty() ? extract_name_from_email(email) : fn;
    c.display_name = c.name;
    c.addr = email;
    c.color = color.empty() ? generate_avatar_color(email) : color;
    c.verified = verification_level;
    c.blocked = (x_blocked == "1") ? 1 : 0;
    if (!x_auth_name.empty()) c.auth_name = x_auth_name;
    if (!notes.empty()) c.status = notes;
    if (!x_last_seen.empty()) {
      try { c.last_seen = std::stoll(x_last_seen); }
      catch (...) { c.last_seen = 0; }
    }
    contacts_[new_id] = c;

    ContactExtended ext;
    ext.id = new_id;
    ext.nickname = nickname;
    ext.phone_number = phone;
    ext.organization = org;
    ext.title = title;
    ext.private_notes = notes;
    ext.is_favorite = (x_favorite == "1");
    if (!x_group_tags.empty())
      ext.group_tags = split(x_group_tags, ',');
    ext.verification_level = verification_level;
    ext.added_at = import_time;
    ext.source = "vcard_import";
    contact_extended_[new_id] = ext;

    // Save avatar if included
    if (!photo_b64.empty()) {
      std::string img_data = base64_decode(photo_b64);
      std::string ext_str = "jpg";
      if (photo_type.find("png") != std::string::npos) ext_str = "png";
      else if (photo_type.find("gif") != std::string::npos) ext_str = "gif";
      else if (photo_type.find("svg") != std::string::npos) ext_str = "svg";
      else if (photo_type.find("webp") != std::string::npos) ext_str = "webp";

      std::string cache_path =
          blob_dir_ + "/contact_" + std::to_string(new_id) + "_avatar." + ext_str;
      std::ofstream out(cache_path, std::ios::binary);
      if (out.good()) {
        out.write(img_data.data(), img_data.size());
        c.profile_image = cache_path;
        contacts_[new_id] = c;
        ext.avatar_cache_path = cache_path;
        ext.avatar_cache_time = import_time;
        contact_extended_[new_id] = ext;
      }
    }

    result.total_imported++;
    result.imported_ids.push_back(new_id);
  }

  return result;
}

// ============================================================================
// Address book sync (Feature 3)
// ============================================================================
void DeltaChat::sync_address_book(
    const std::vector<AddressBookEntry>& system_contacts,
    bool auto_import_new,
    bool update_existing,
    bool remove_missing) {

  int64_t sync_time = nms();
  last_address_book_sync_ = sync_time;

  // Build lookup sets
  std::unordered_map<std::string, AddressBookEntry> system_by_email;
  std::set<std::string> system_emails;
  for (const auto& entry : system_contacts) {
    if (!entry.email.empty()) {
      auto norm = normalize_email(entry.email);
      system_by_email[norm] = entry;
      system_emails.insert(norm);
    }
  }

  // Map DeltaChat contacts to system entries
  std::unordered_map<std::string, uint32_t> dc_by_email;
  for (const auto& [id, c] : contacts_) {
    if (!c.addr.empty())
      dc_by_email[normalize_email(c.addr)] = id;
  }

  int new_count = 0, updated_count = 0, removed_count = 0;

  // Find new contacts (in system but not in DeltaChat)
  if (auto_import_new) {
    for (const auto& [norm_email, entry] : system_by_email) {
      if (!dc_by_email.count(norm_email)) {
        // Auto-import this contact
        uint32_t new_id = gen_id();
        DcContact c;
        c.id = new_id;
        c.name = entry.name.empty() ? extract_name_from_email(entry.email)
                                     : entry.name;
        c.display_name = c.name;
        c.addr = entry.email;
        c.color = generate_avatar_color(entry.email);
        c.last_seen = 0;
        contacts_[new_id] = c;

        ContactExtended ext;
        ext.id = new_id;
        ext.phone_number = entry.phone;
        ext.organization = entry.organization;
        ext.title = entry.title;
        ext.added_at = sync_time;
        ext.source = "addressbook_sync";
        ext.verification_level = 0;
        if (!entry.avatar_path.empty()) {
          ext.avatar_cache_path = entry.avatar_path;
          ext.avatar_cache_time = sync_time;
        }
        contact_extended_[new_id] = ext;

        dc_by_email[norm_email] = new_id;
        new_count++;
      }
    }
  }

  // Update existing contacts with latest system info
  if (update_existing) {
    for (const auto& [norm_email, cid] : dc_by_email) {
      auto sys_it = system_by_email.find(norm_email);
      if (sys_it == system_by_email.end()) continue;

      auto& entry = sys_it->second;
      auto cit = contacts_.find(cid);
      if (cit == contacts_.end()) continue;

      auto& c = cit->second;
      bool changed = false;

      if (!entry.name.empty() && c.name != entry.name) {
        // Only update if name seems better
        if (c.name.empty() || c.name == extract_name_from_email(c.addr)) {
          c.name = entry.name;
          c.display_name = entry.name;
          changed = true;
        }
      }

      auto& ext = contact_extended_[cid];
      if (!entry.phone.empty() && ext.phone_number != entry.phone) {
        ext.phone_number = entry.phone;
        changed = true;
      }
      if (!entry.organization.empty() &&
          ext.organization != entry.organization) {
        ext.organization = entry.organization;
        changed = true;
      }
      if (!entry.title.empty() && ext.title != entry.title) {
        ext.title = entry.title;
        changed = true;
      }

      // Update avatar if new one available
      if (!entry.avatar_path.empty() &&
          ext.avatar_cache_path != entry.avatar_path) {
        ext.avatar_cache_path = entry.avatar_path;
        ext.avatar_cache_time = sync_time;
        c.profile_image = entry.avatar_path;
        changed = true;
      }

      // Update last_seen based on system modification time
      if (entry.last_modified > c.last_seen && entry.last_modified > 0) {
        c.last_seen = entry.last_modified;
        changed = true;
      }

      if (changed) {
        contacts_[cid] = c;
        contact_extended_[cid] = ext;
        updated_count++;
      }
    }
  }

  // Remove contacts that are no longer in system address book
  if (remove_missing) {
    std::vector<uint32_t> to_remove;
    for (const auto& [norm_email, cid] : dc_by_email) {
      if (!system_emails.count(norm_email)) {
        auto ext_it = contact_extended_.find(cid);
        if (ext_it != contact_extended_.end() &&
            ext_it->second.source == "addressbook_sync") {
          to_remove.push_back(cid);
        }
      }
    }
    for (auto cid : to_remove) {
      contacts_.erase(cid);
      contact_extended_.erase(cid);
      removed_count++;
    }
  }

  // Store sync summary
  last_sync_summary_ = json{
      {"time", sync_time},
      {"new", new_count},
      {"updated", updated_count},
      {"removed", removed_count},
      {"total_system", system_contacts.size()},
      {"total_deltachat", contacts_.size()}
  }.dump();

  // Fire sync complete event
  if (event_cb_ && (new_count > 0 || updated_count > 0 || removed_count > 0)) {
    int event_data = (new_count << 16) | (updated_count & 0xFFFF);
    event_cb_(2100, event_data, removed_count);
  }
}

// ============================================================================
// Schedule periodic address book sync
// ============================================================================
void DeltaChat::schedule_address_book_sync(int interval_seconds) {
  address_book_sync_interval_ = interval_seconds;
  int64_t now = nms();
  next_address_book_sync_ = now + (interval_seconds * 1000);
}

void DeltaChat::check_scheduled_sync() {
  if (address_book_sync_interval_ <= 0) return;
  int64_t now = nms();
  if (now >= next_address_book_sync_) {
    // Perform sync - in production, this would be an async call
    perform_address_book_sync();
    next_address_book_sync_ = now + (address_book_sync_interval_ * 1000);
  }
}

void DeltaChat::perform_address_book_sync() {
  // Stub for system-callout-based address book reading
  // In production, this would call OS-specific APIs to read system contacts
  // then call sync_address_book() with the results.
  //
  // Android: ContentResolver.query(ContactsContract.Contacts.CONTENT_URI)
  // iOS: CNContactStore.enumerateContacts
  // Linux: Parse ~/.local/share/evolution/addressbook or use libebook
  // macOS: Use AddressBook framework via CNContactStore
  // Windows: Use Windows Contacts API

  int64_t sync_time = nms();
  last_address_book_sync_ = sync_time;
}

// ============================================================================
// Contact deduplication (Feature 4)
// ============================================================================
std::vector<std::pair<uint32_t, uint32_t>> DeltaChat::find_duplicate_contacts(
    bool auto_merge,
    double similarity_threshold) {

  std::vector<std::pair<uint32_t, uint32_t>> duplicates;
  std::vector<uint32_t> contact_ids;
  for (const auto& [id, c] : contacts_) contact_ids.push_back(id);

  // Group contacts by normalized email (exact matches)
  std::unordered_map<std::string, std::vector<uint32_t>> email_groups;
  for (auto& [id, c] : contacts_) {
    email_groups[normalize_email(c.addr)].push_back(id);
  }

  for (auto& [email, ids] : email_groups) {
    if (ids.size() < 2) continue;
    // Keep the first (oldest by ID), mark rest as duplicates
    uint32_t primary = ids[0];
    for (size_t i = 1; i < ids.size(); ++i) {
      duplicates.push_back({primary, ids[i]});
    }
  }

  // Fuzzy name matching for similar contacts with different emails
  if (similarity_threshold < 1.0) {
    for (size_t i = 0; i < contact_ids.size(); ++i) {
      for (size_t j = i + 1; j < contact_ids.size(); ++j) {
        uint32_t id1 = contact_ids[i];
        uint32_t id2 = contact_ids[j];
        auto it1 = contacts_.find(id1);
        auto it2 = contacts_.find(id2);
        if (it1 == contacts_.end() || it2 == contacts_.end()) continue;

        const auto& c1 = it1->second;
        const auto& c2 = it2->second;

        // Skip if already in exact duplicate list
        bool already_found = false;
        for (const auto& d : duplicates) {
          if ((d.first == id1 && d.second == id2) ||
              (d.first == id2 && d.second == id1)) {
            already_found = true;
            break;
          }
        }
        if (already_found) continue;

        // Compute name similarity
        double name_sim = compute_name_similarity(c1.name, c2.name);

        // Check extended phone numbers
        bool phone_match = false;
        auto ext1 = contact_extended_.find(id1);
        auto ext2 = contact_extended_.find(id2);
        if (ext1 != contact_extended_.end() &&
            ext2 != contact_extended_.end()) {
          if (!ext1->second.phone_number.empty() &&
              !ext2->second.phone_number.empty() &&
              ext1->second.phone_number == ext2->second.phone_number) {
            phone_match = true;
          }
        }

        if (name_sim >= similarity_threshold || phone_match) {
          duplicates.push_back({id1, id2});
        }
      }
    }
  }

  // Auto-merge if requested
  if (auto_merge) {
    for (const auto& [primary_id, duplicate_id] : duplicates) {
      merge_contact_into(duplicate_id, primary_id);
    }
  }

  return duplicates;
}

double DeltaChat::compute_name_similarity(const std::string& name1,
                                          const std::string& name2) {
  if (name1.empty() || name2.empty()) return 0.0;
  if (name1 == name2) return 1.0;

  std::string s1 = levenshtein_normalize(name1);
  std::string s2 = levenshtein_normalize(name2);

  if (s1.empty() || s2.empty()) return 0.0;
  if (s1 == s2) return 1.0;

  // Levenshtein distance
  size_t len1 = s1.length();
  size_t len2 = s2.length();
  std::vector<std::vector<int>> dp(len1 + 1, std::vector<int>(len2 + 1));

  for (size_t i = 0; i <= len1; ++i) dp[i][0] = i;
  for (size_t j = 0; j <= len2; ++j) dp[0][j] = j;

  for (size_t i = 1; i <= len1; ++i) {
    for (size_t j = 1; j <= len2; ++j) {
      int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
      dp[i][j] = std::min({
          dp[i - 1][j] + 1,       // deletion
          dp[i][j - 1] + 1,       // insertion
          dp[i - 1][j - 1] + cost // substitution
      });
    }
  }

  int distance = dp[len1][len2];
  int max_len = std::max(len1, len2);
  if (max_len == 0) return 1.0;
  return 1.0 - (double)distance / max_len;
}

bool DeltaChat::merge_contact_into(uint32_t source_id, uint32_t target_id) {
  auto src = contacts_.find(source_id);
  auto tgt = contacts_.find(target_id);
  if (src == contacts_.end() || tgt == contacts_.end()) return false;

  auto& sc = src->second;
  auto& tc = tgt->second;

  // Merge fields: keep target's data, fill in from source if target is empty
  if (tc.name.empty() && !sc.name.empty()) tc.name = sc.name;
  if (tc.display_name.empty() && !sc.display_name.empty())
    tc.display_name = sc.display_name;
  if (tc.auth_name.empty() && !sc.auth_name.empty())
    tc.auth_name = sc.auth_name;
  if (tc.profile_image.empty() && !sc.profile_image.empty())
    tc.profile_image = sc.profile_image;
  if (tc.status.empty() && !sc.status.empty()) tc.status = sc.status;
  if (sc.last_seen > tc.last_seen) tc.last_seen = sc.last_seen;

  // Keep highest verification
  if (sc.verified > tc.verified) tc.verified = sc.verified;

  // Merge extended fields
  auto sext = contact_extended_.find(source_id);
  auto text = contact_extended_.find(target_id);
  if (sext != contact_extended_.end() && text != contact_extended_.end()) {
    auto& se = sext->second;
    auto& te = text->second;

    if (te.nickname.empty() && !se.nickname.empty())
      te.nickname = se.nickname;
    if (te.phone_number.empty() && !se.phone_number.empty())
      te.phone_number = se.phone_number;
    if (te.organization.empty() && !se.organization.empty())
      te.organization = se.organization;
    if (te.title.empty() && !se.title.empty()) te.title = se.title;
    if (te.private_notes.empty() && !se.private_notes.empty())
      te.private_notes = se.private_notes + "\n[Merged from contact ID " +
                          std::to_string(source_id) + "]";
    if (!se.is_favorite) te.is_favorite = true;

    // Merge group tags
    for (const auto& tag : se.group_tags) {
      if (std::find(te.group_tags.begin(), te.group_tags.end(), tag) ==
          te.group_tags.end())
        te.group_tags.push_back(tag);
    }

    // Keep highest verification level
    if (se.verification_level > te.verification_level) {
      te.verification_level = se.verification_level;
      te.verification_time = se.verification_time;
      te.verification_method = se.verification_method;
    }

    te.interaction_count += se.interaction_count;
    if (se.last_interaction > te.last_interaction)
      te.last_interaction = se.last_interaction;

    contact_extended_[target_id] = te;
  }

  // Reassign any chats/messages from source to target
  contacts_[target_id] = tc;

  // Delete source contact
  contacts_.erase(source_id);
  contact_extended_.erase(source_id);

  if (event_cb_)
    event_cb_(2110, source_id, target_id);  // Contact merged event

  return true;
}

// ============================================================================
// Contact blocking (Feature 5)
// ============================================================================
bool DeltaChat::block_contact(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return false;
  it->second.blocked = 1;

  // Add to blocked set for fast lookup
  blocked_contacts_.insert(contact_id);

  if (event_cb_) event_cb_(2000, contact_id, 1);  // Contact blocked

  return true;
}

bool DeltaChat::unblock_contact(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return false;
  it->second.blocked = 0;
  blocked_contacts_.erase(contact_id);

  if (event_cb_) event_cb_(2001, contact_id, 0);  // Contact unblocked

  return true;
}

bool DeltaChat::is_contact_blocked(uint32_t contact_id) {
  return blocked_contacts_.count(contact_id) > 0;
}

std::vector<uint32_t> DeltaChat::get_all_blocked_contacts() {
  std::vector<uint32_t> result;
  for (auto id : blocked_contacts_) result.push_back(id);
  return result;
}

void DeltaChat::block_contacts_batch(
    const std::vector<uint32_t>& contact_ids) {
  for (auto id : contact_ids) block_contact(id);
}

void DeltaChat::unblock_contacts_batch(
    const std::vector<uint32_t>& contact_ids) {
  for (auto id : contact_ids) unblock_contact(id);
}

// ============================================================================
// Block by email pattern (wildcard blocking)
// ============================================================================
void DeltaChat::add_blocked_domain(const std::string& domain) {
  blocked_domains_.insert(to_lower(trim(domain)));
}

void DeltaChat::remove_blocked_domain(const std::string& domain) {
  blocked_domains_.erase(to_lower(trim(domain)));
}

std::vector<std::string> DeltaChat::get_blocked_domains() {
  return std::vector<std::string>(blocked_domains_.begin(),
                                   blocked_domains_.end());
}

bool DeltaChat::is_domain_blocked(const std::string& domain) {
  return blocked_domains_.count(to_lower(trim(domain))) > 0;
}

// ============================================================================
// Contact verification levels (Feature 6)
// ============================================================================
void DeltaChat::set_contact_verification(uint32_t contact_id, int level,
                                         const std::string& method) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;

  int old_level = it->second.verified;
  it->second.verified = std::clamp(level, 0, 2);

  auto& ext = contact_extended_[contact_id];
  ext.id = contact_id;
  ext.verification_level = level;
  ext.verification_time = nms();
  ext.verification_method = method;

  if (event_cb_)
    event_cb_(2020, contact_id, (uint32_t)level);  // Verification changed
}

int DeltaChat::get_contact_verification_level(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return 0;
  return it->second.verified;
}

std::string DeltaChat::get_contact_verification_info(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end())
    return json{{"level", 0}, {"label", "unverified"}}.dump();

  auto ext_it = contact_extended_.find(contact_id);
  json info;
  info["level"] = it->second.verified;
  info["contact_id"] = contact_id;

  switch (it->second.verified) {
    case 0:
      info["label"] = "unverified";
      info["description"] = "This contact has not been verified";
      info["icon"] = "🔴";
      break;
    case 1:
      info["label"] = "verified";
      info["description"] = "Contact verified via " +
                            (ext_it != contact_extended_.end()
                                 ? ext_it->second.verification_method
                                 : "autocrypt");
      info["icon"] = "🟡";
      break;
    case 2:
      info["label"] = "bidirectional";
      info["description"] =
          "Contact has verified you and you have verified them";
      info["icon"] = "🟢";
      break;
    default:
      info["label"] = "unknown";
      info["description"] = "Unknown verification state";
      info["icon"] = "⚪";
      break;
  }

  if (ext_it != contact_extended_.end()) {
    info["verified_at"] = ext_it->second.verification_time;
    info["verified_via"] = ext_it->second.verification_method;
  }

  return info.dump();
}

std::vector<uint32_t> DeltaChat::get_verified_contacts(
    int min_verification_level) {
  std::vector<uint32_t> result;
  for (const auto& [id, c] : contacts_) {
    if (c.verified >= min_verification_level) result.push_back(id);
  }
  return result;
}

std::vector<uint32_t> DeltaChat::get_unverified_contacts() {
  std::vector<uint32_t> result;
  for (const auto& [id, c] : contacts_) {
    if (c.verified == 0) result.push_back(id);
  }
  return result;
}

// ============================================================================
// Bulk verification for all contacts in a chat
// ============================================================================
void DeltaChat::verify_chat_contacts(uint32_t chat_id, int level) {
  auto chat_contacts = get_chat_contacts(chat_id);
  for (auto cid : chat_contacts) {
    set_contact_verification(cid, level, "chat_verification");
  }
}

// ============================================================================
// Contact profile image caching (Feature 7)
// ============================================================================
std::string DeltaChat::cache_contact_profile_image(
    uint32_t contact_id, const std::string& image_url_or_path,
    int64_t cache_ttl_seconds) {

  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return "";

  int64_t now = nms();
  std::string cache_path;

  // Check if it's a local file path
  if (image_url_or_path.size() > 0 && image_url_or_path[0] == '/') {
    cache_path = image_url_or_path;
  } else {
    // Generate cache path from contact ID
    cache_path = blob_dir_ + "/avatar_cache_" +
                 std::to_string(contact_id) + "_" +
                 hex_encode(sha256(image_url_or_path)).substr(0, 16);
  }

  // Update contact
  it->second.profile_image = cache_path;

  // Store extended cache info
  auto& ext = contact_extended_[contact_id];
  ext.id = contact_id;
  ext.avatar_cache_path = cache_path;
  ext.avatar_cache_time = now;
  contact_extended_[contact_id] = ext;

  // Store cache TTL
  avatar_cache_ttl_[contact_id] = cache_ttl_seconds;
  avatar_cache_timestamp_[contact_id] = now;

  return cache_path;
}

std::string DeltaChat::get_cached_avatar_path(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return "";
  return it->second.profile_image;
}

void DeltaChat::invalidate_avatar_cache(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it != contacts_.end()) {
    it->second.profile_image.clear();
  }
  auto ext_it = contact_extended_.find(contact_id);
  if (ext_it != contact_extended_.end()) {
    ext_it->second.avatar_cache_path.clear();
    ext_it->second.avatar_cache_time = 0;
  }
  avatar_cache_ttl_.erase(contact_id);
  avatar_cache_timestamp_.erase(contact_id);
}

void DeltaChat::invalidate_all_avatar_cache() {
  for (auto& [id, c] : contacts_) {
    c.profile_image.clear();
  }
  for (auto& [id, ext] : contact_extended_) {
    ext.avatar_cache_path.clear();
    ext.avatar_cache_time = 0;
  }
  avatar_cache_ttl_.clear();
  avatar_cache_timestamp_.clear();
}

void DeltaChat::cleanup_expired_avatar_cache() {
  int64_t now = nms();
  std::vector<uint32_t> expired_ids;

  for (const auto& [id, ts] : avatar_cache_timestamp_) {
    auto ttl_it = avatar_cache_ttl_.find(id);
    if (ttl_it != avatar_cache_ttl_.end() && ttl_it->second > 0) {
      if (now - ts > ttl_it->second * 1000) {
        expired_ids.push_back(id);
      }
    }
  }

  for (auto id : expired_ids) {
    invalidate_avatar_cache(id);
  }
}

void DeltaChat::set_blob_dir(const std::string& path) { blob_dir_ = path; }

// ============================================================================
// Contact status/online detection (Feature 8)
// ============================================================================
void DeltaChat::set_contact_online_status(uint32_t contact_id, int status,
                                          int64_t since) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;

  auto& ext = contact_extended_[contact_id];
  ext.id = contact_id;
  ext.online_status = status;
  ext.online_since = since > 0 ? since : nms();

  if (status >= 1) {
    it->second.last_seen = since > 0 ? since : nms();
    it->second.was_seen_recently = 1;
  } else {
    it->second.was_seen_recently = 0;
  }

  contact_extended_[contact_id] = ext;

  if (event_cb_)
    event_cb_(2030, contact_id, (uint32_t)status);  // Online status changed
}

int DeltaChat::get_contact_online_status(uint32_t contact_id) {
  auto ext_it = contact_extended_.find(contact_id);
  if (ext_it == contact_extended_.end()) return 0;
  return ext_it->second.online_status;
}

std::string DeltaChat::get_contact_online_status_label(uint32_t contact_id) {
  int status = get_contact_online_status(contact_id);
  switch (status) {
    case 0: return "offline";
    case 1: return "online";
    case 2: return "away";
    case 3: return "busy";
    default: return "unknown";
  }
}

json DeltaChat::get_contact_presence(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end())
    return json{{"status", "unknown"}, {"online", false}};

  const auto& c = it->second;
  auto ext_it = contact_extended_.find(contact_id);

  json presence;
  presence["contact_id"] = contact_id;

  if (ext_it != contact_extended_.end()) {
    presence["online"] = ext_it->second.online_status >= 1;
    presence["status"] = get_contact_online_status_label(contact_id);
    presence["since"] = ext_it->second.online_since;
  } else {
    presence["online"] = false;
    presence["status"] = "offline";
  }

  presence["last_seen"] = c.last_seen;
  presence["was_seen_recently"] = c.was_seen_recently > 0;

  // Determine if "recently seen" (within last 30 minutes)
  int64_t now = nms();
  int64_t thirty_min = 30 * 60 * 1000;
  presence["seen_recently"] =
      (c.last_seen > 0 && (now - c.last_seen) < thirty_min);

  return presence;
}

void DeltaChat::update_contact_last_seen(uint32_t contact_id,
                                         int64_t timestamp) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;
  int64_t ts = timestamp > 0 ? timestamp : nms();
  it->second.last_seen = ts;

  int64_t now = nms();
  it->second.was_seen_recently = (now - ts) < 30 * 60 * 1000 ? 1 : 0;
}

// ============================================================================
// Periodic online status check
// ============================================================================
void DeltaChat::check_online_statuses() {
  // In production, this would send IMAP STATUS or similar lightweight checks
  // to determine if contacts are online. For now, we check last_seen timestamps
  // and mark contacts as offline if they haven't been seen recently.

  int64_t now = nms();
  int64_t offline_threshold = 5 * 60 * 1000;  // 5 minutes

  for (auto& [id, c] : contacts_) {
    if (c.last_seen > 0 && (now - c.last_seen) > offline_threshold) {
      c.was_seen_recently = 0;
      auto ext_it = contact_extended_.find(id);
      if (ext_it != contact_extended_.end() &&
          ext_it->second.online_status >= 1) {
        ext_it->second.online_status = 0;
        contact_extended_[id] = ext_it;
        if (event_cb_) event_cb_(2030, id, 0);
      }
    }
  }
}

// ============================================================================
// Multi-account management (Feature 9)
// ============================================================================
uint32_t DeltaChat::create_account(const std::string& dbfile,
                                   const std::string& display_name,
                                   const std::string& email) {
  uint32_t account_id = gen_id();

  AccountInfo info;
  info.account_id = account_id;
  info.dbfile = dbfile;
  info.display_name = display_name;
  info.email_addr = email;
  info.created_at = nms();
  info.active = false;
  info.configured = false;
  info.device_id = gen_token(16);
  info.device_name = "DeltaChat Device";

  accounts_[account_id] = info;

  if (event_cb_) event_cb_(3000, account_id, 0);  // Account created

  return account_id;
}

bool DeltaChat::remove_account(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return false;

  if (it->second.active) {
    // Deactivate before removing
    deactivate_account(account_id);
  }

  accounts_.erase(it);

  // Also remove from active ordering
  auto order_it =
      std::find(account_order_.begin(), account_order_.end(), account_id);
  if (order_it != account_order_.end())
    account_order_.erase(order_it);

  if (event_cb_) event_cb_(3001, account_id, 0);  // Account removed

  return true;
}

AccountInfo DeltaChat::get_account_info(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return AccountInfo{};
  return it->second;
}

std::vector<uint32_t> DeltaChat::get_all_accounts() {
  std::vector<uint32_t> result;
  // Return in display order
  for (auto id : account_order_) {
    if (accounts_.count(id)) result.push_back(id);
  }
  // Include any accounts not in order
  for (const auto& [id, info] : accounts_) {
    if (std::find(result.begin(), result.end(), id) == result.end())
      result.push_back(id);
  }
  return result;
}

uint32_t DeltaChat::get_active_account_id() { return active_account_id_; }

bool DeltaChat::is_account_active(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return false;
  return it->second.active;
}

int DeltaChat::get_account_count() { return accounts_.size(); }

// ============================================================================
// Account switching (Feature 10)
// ============================================================================
bool DeltaChat::activate_account(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return false;

  // Deactivate current account first
  if (active_account_id_ != 0 && active_account_id_ != account_id) {
    deactivate_account(active_account_id_);
  }

  it->second.active = true;
  active_account_id_ = account_id;

  // Move to front of order
  auto order_it =
      std::find(account_order_.begin(), account_order_.end(), account_id);
  if (order_it != account_order_.end())
    account_order_.erase(order_it);
  account_order_.insert(account_order_.begin(), account_id);

  // Load this account's dbfile as the current context
  if (!it->second.dbfile.empty()) {
    config_.dbfile = it->second.dbfile;
  }

  // Start background fetch for this account
  if (it->second.fetch_in_background) {
    schedule_account_fetch(account_id, it->second.fetch_interval_seconds);
  }

  if (event_cb_)
    event_cb_(3010, account_id, 1);  // Account activated

  return true;
}

bool DeltaChat::deactivate_account(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return false;

  it->second.active = false;

  if (active_account_id_ == account_id) {
    active_account_id_ = 0;
  }

  // Cancel scheduled fetch for this account
  cancel_account_fetch(account_id);

  if (event_cb_)
    event_cb_(3011, account_id, 0);  // Account deactivated

  return true;
}

uint32_t DeltaChat::switch_to_account(uint32_t account_id) {
  return activate_account(account_id) ? account_id : 0;
}

// ============================================================================
// Account notification settings
// ============================================================================
void DeltaChat::set_account_notifications(uint32_t account_id, bool enabled) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return;
  it->second.notifications_enabled = enabled;
}

bool DeltaChat::get_account_notifications(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return true;
  return it->second.notifications_enabled;
}

// ============================================================================
// Account configuration per account (Feature 11)
// ============================================================================
bool DeltaChat::set_account_config(uint32_t account_id,
                                   const std::string& key,
                                   const std::string& value) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return false;

  auto& config = account_configs_[account_id];

  if (key == "display_name")
    it->second.display_name = value;
  else if (key == "email_addr")
    it->second.email_addr = value;
  else if (key == "avatar")
    it->second.avatar_path = value;
  else if (key == "status_message")
    it->second.status_message = value;
  else if (key == "device_name")
    it->second.device_name = value;
  else if (key == "fetch_interval") {
    try {
      it->second.fetch_interval_seconds = std::stoi(value);
    } catch (...) {
    }
  } else if (key == "fetch_in_background")
    it->second.fetch_in_background = (value == "1" || value == "true");
  else if (key == "archive_on_other_devices")
    it->second.archive_on_other_devices = (value == "1" || value == "true");
  else if (key == "notifications")
    it->second.notifications_enabled = (value == "1" || value == "true");
  else if (key == "backup_path")
    it->second.backup_path = value;

  config[key] = value;
  account_configs_[account_id] = config;

  return true;
}

std::string DeltaChat::get_account_config(uint32_t account_id,
                                          const std::string& key,
                                          const std::string& default_val) {
  auto it = account_configs_.find(account_id);
  if (it == account_configs_.end()) return default_val;

  auto& config = it->second;
  auto kit = config.find(key);
  if (kit != config.end()) return kit->second;
  return default_val;
}

json DeltaChat::get_account_full_config(uint32_t account_id) {
  json cfg;
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return cfg;

  auto& acc = it->second;
  cfg["account_id"] = account_id;
  cfg["display_name"] = acc.display_name;
  cfg["email_addr"] = acc.email_addr;
  cfg["active"] = acc.active;
  cfg["configured"] = acc.configured;
  cfg["created_at"] = acc.created_at;
  cfg["device_id"] = acc.device_id;
  cfg["device_name"] = acc.device_name;
  cfg["fetch_interval_seconds"] = acc.fetch_interval_seconds;
  cfg["fetch_in_background"] = acc.fetch_in_background;
  cfg["notifications_enabled"] = acc.notifications_enabled;
  cfg["avatar_path"] = acc.avatar_path;
  cfg["status_message"] = acc.status_message;
  cfg["archive_on_other_devices"] = acc.archive_on_other_devices;
  cfg["last_fetch"] = acc.last_fetch;
  cfg["unread_count"] = acc.unread_count;
  cfg["message_count"] = acc.message_count;
  cfg["chat_count"] = acc.chat_count;
  cfg["contact_count"] = acc.contact_count;

  // Include custom config keys
  auto cfg_it = account_configs_.find(account_id);
  if (cfg_it != account_configs_.end()) {
    for (const auto& [k, v] : cfg_it->second) {
      if (!cfg.contains(k)) cfg["custom"][k] = v;
    }
  }

  return cfg;
}

// ============================================================================
// Account background fetch scheduling (Feature 12)
// ============================================================================
void DeltaChat::schedule_account_fetch(uint32_t account_id,
                                       int interval_seconds) {
  int64_t now = nms();
  int64_t next = now + (interval_seconds * 1000);

  // Add to fetch schedule
  FetchScheduleEntry entry;
  entry.account_id = account_id;
  entry.next_fetch = next;
  entry.interval_seconds = interval_seconds;

  // Replace existing entry for this account
  bool found = false;
  for (auto& e : fetch_schedule_) {
    if (e.account_id == account_id) {
      e = entry;
      found = true;
      break;
    }
  }
  if (!found) {
    fetch_schedule_.push_back(entry);
  }

  // Sort by next_fetch time
  std::sort(fetch_schedule_.begin(), fetch_schedule_.end(),
            [](const FetchScheduleEntry& a, const FetchScheduleEntry& b) {
              return a.next_fetch < b.next_fetch;
            });

  // Update account info
  auto it = accounts_.find(account_id);
  if (it != accounts_.end()) {
    it->second.fetch_interval_seconds = interval_seconds;
    it->second.next_fetch = next;
  }
}

void DeltaChat::cancel_account_fetch(uint32_t account_id) {
  fetch_schedule_.erase(
      std::remove_if(fetch_schedule_.begin(), fetch_schedule_.end(),
                     [account_id](const FetchScheduleEntry& e) {
                       return e.account_id == account_id;
                     }),
      fetch_schedule_.end());

  auto it = accounts_.find(account_id);
  if (it != accounts_.end()) {
    it->second.next_fetch = 0;
  }
}

void DeltaChat::process_fetch_schedule() {
  int64_t now = nms();
  std::vector<uint32_t> accounts_to_fetch;

  for (auto& entry : fetch_schedule_) {
    if (now >= entry.next_fetch) {
      auto it = accounts_.find(entry.account_id);
      if (it != accounts_.end() && it->second.active) {
        accounts_to_fetch.push_back(entry.account_id);
      }
      // Reschedule
      entry.next_fetch = now + (entry.interval_seconds * 1000);
    }
  }

  // Process fetches (in order)
  for (auto account_id : accounts_to_fetch) {
    perform_background_fetch(account_id);
  }
}

void DeltaChat::perform_background_fetch(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end() || !it->second.configured) return;

  int64_t now = nms();

  // In production, this would:
  // 1. Connect to IMAP server for this account
  // 2. SELECT INBOX, SEARCH UNSEEN
  // 3. Fetch and process new messages
  // 4. Update account stats

  it->second.last_fetch = now;

  // For now, simulate updating stats
  // In production, this would be: fetch_new_emails_for_account(account_id)
}

void DeltaChat::set_global_fetch_interval(int interval_seconds) {
  global_fetch_interval_ = interval_seconds;
  for (auto& [id, acc] : accounts_) {
    if (acc.fetch_in_background && acc.active) {
      schedule_account_fetch(id, interval_seconds);
    }
  }
}

int DeltaChat::get_global_fetch_interval() { return global_fetch_interval_; }

// ============================================================================
// Account migration between devices (Feature 13)
// ============================================================================
json DeltaChat::export_account_for_migration(uint32_t account_id) {
  json migration;
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return migration;

  migration["version"] = 1;
  migration["exported_at"] = nms();
  migration["account"] = {
      {"account_id", it->second.account_id},
      {"display_name", it->second.display_name},
      {"email_addr", it->second.email_addr},
      {"device_id", it->second.device_id},
      {"device_name", it->second.device_name},
      {"created_at", it->second.created_at},
  };

  // Include config
  auto cfg_it = account_configs_.find(account_id);
  if (cfg_it != account_configs_.end()) {
    migration["config"] = cfg_it->second;
  }

  // Export contacts for this account
  json contacts_json = json::array();
  for (const auto& [id, c] : contacts_) {
    json cj;
    cj["id"] = c.id;
    cj["name"] = c.name;
    cj["display_name"] = c.display_name;
    cj["addr"] = c.addr;
    cj["auth_name"] = c.auth_name;
    cj["color"] = c.color;
    cj["verified"] = c.verified;
    cj["blocked"] = c.blocked;
    cj["last_seen"] = c.last_seen;

    auto ext_it = contact_extended_.find(id);
    if (ext_it != contact_extended_.end()) {
      cj["nickname"] = ext_it->second.nickname;
      cj["private_notes"] = ext_it->second.private_notes;
      cj["is_favorite"] = ext_it->second.is_favorite;
      cj["phone_number"] = ext_it->second.phone_number;
      cj["organization"] = ext_it->second.organization;
      cj["title"] = ext_it->second.title;
      cj["verification_level"] = ext_it->second.verification_level;
      cj["verification_method"] = ext_it->second.verification_method;
      cj["verification_time"] = ext_it->second.verification_time;
    }
    contacts_json.push_back(cj);
  }
  migration["contacts"] = contacts_json;
  migration["contact_count"] = contacts_.size();

  // Stats
  migration["stats"] = {
      {"message_count", it->second.message_count},
      {"chat_count", it->second.chat_count},
      {"contact_count", it->second.contact_count},
      {"unread_count", it->second.unread_count},
  };

  // Signature for tamper detection
  std::string signature_data =
      migration["account"]["email_addr"].get<std::string>() +
      std::to_string(migration["contact_count"].get<int>()) +
      std::to_string(migration["exported_at"].get<int64_t>());
  migration["signature"] = sha256(signature_data + "migration_salt");

  return migration;
}

bool DeltaChat::import_account_from_migration(
    const json& migration_data, const std::string& new_dbfile) {

  if (!migration_data.contains("account") ||
      !migration_data.contains("signature")) {
    return false;
  }

  // Verify signature
  std::string email =
      migration_data["account"]["email_addr"].get<std::string>();
  int contact_count = migration_data.value("contact_count", 0);
  int64_t exported_at = migration_data["exported_at"].get<int64_t>();
  std::string expected_sig =
      sha256(email + std::to_string(contact_count) +
             std::to_string(exported_at) + "migration_salt");

  if (expected_sig != migration_data["signature"].get<std::string>()) {
    return false;  // Tampered data
  }

  // Create new account
  uint32_t new_account_id = create_account(
      new_dbfile,
      migration_data["account"].value("display_name", "Migrated Account"),
      email);

  auto it = accounts_.find(new_account_id);
  if (it == accounts_.end()) return false;

  // Update account info from migration data
  it->second.device_id =
      migration_data["account"].value("device_id", gen_token(16));
  it->second.device_name =
      migration_data["account"].value("device_name", "Migrated Device");

  // Import config
  if (migration_data.contains("config")) {
    for (auto& [key, value] : migration_data["config"].items()) {
      if (value.is_string()) {
        set_account_config(new_account_id, key, value.get<std::string>());
      }
    }
  }

  // Import contacts
  if (migration_data.contains("contacts") &&
      migration_data["contacts"].is_array()) {
    for (const auto& cj : migration_data["contacts"]) {
      uint32_t contact_id =
          create_contact(cj.value("name", ""), cj.value("addr", ""));

      auto cit = contacts_.find(contact_id);
      if (cit != contacts_.end()) {
        if (cj.contains("display_name"))
          cit->second.display_name = cj["display_name"];
        if (cj.contains("auth_name"))
          cit->second.auth_name = cj["auth_name"];
        if (cj.contains("color")) cit->second.color = cj["color"];
        if (cj.contains("verified")) cit->second.verified = cj["verified"];
        if (cj.contains("blocked")) cit->second.blocked = cj["blocked"];
        if (cj.contains("last_seen"))
          cit->second.last_seen = cj["last_seen"];
      }

      // Extended fields
      ContactExtended ext;
      ext.id = contact_id;
      ext.nickname = cj.value("nickname", "");
      ext.private_notes = cj.value("private_notes", "");
      ext.is_favorite = cj.value("is_favorite", false);
      ext.phone_number = cj.value("phone_number", "");
      ext.organization = cj.value("organization", "");
      ext.title = cj.value("title", "");
      ext.verification_level = cj.value("verification_level", 0);
      ext.verification_method = cj.value("verification_method", "");
      ext.verification_time = cj.value("verification_time", 0);
      ext.added_at = nms();
      ext.source = "migration";
      contact_extended_[contact_id] = ext;
    }
  }

  it->second.contact_count = contacts_.size();

  return true;
}

std::string DeltaChat::create_migration_backup(uint32_t account_id,
                                               const std::string& output_path) {
  json migration = export_account_for_migration(account_id);
  if (migration.empty()) return "";

  std::string path = output_path;
  if (path.empty()) {
    auto it = accounts_.find(account_id);
    std::string name = it != accounts_.end() ? it->second.email_addr : "account";
    path = "/tmp/deltachat_migration_" + name + "_" +
           std::to_string(nms()) + ".json";
  }

  std::ofstream out(path);
  if (!out.good()) return "";
  out << migration.dump(2);

  // Record backup path
  auto it = accounts_.find(account_id);
  if (it != accounts_.end()) {
    it->second.backup_path = path;
    it->second.last_backup = nms();
  }

  return path;
}

bool DeltaChat::restore_migration_backup(
    const std::string& backup_path, const std::string& new_dbfile) {
  std::ifstream in(backup_path);
  if (!in.good()) return false;

  std::string content((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
  try {
    json data = json::parse(content);
    return import_account_from_migration(data, new_dbfile);
  } catch (const std::exception&) {
    return false;
  }
}

// ============================================================================
// Account statistics (Feature 14)
// ============================================================================
json DeltaChat::get_account_statistics(uint32_t account_id) {
  json stats;
  auto it = accounts_.find(account_id);

  if (it != accounts_.end()) {
    // Recalculate from live data
    it->second.contact_count = contacts_.size();
    it->second.chat_count = chats_.size();
    it->second.message_count = messages_.size();

    it->second.unread_count = 0;
    for (const auto& [id, m] : messages_) {
      if (m.state == 10)  // DC_STATE_IN_FRESH
        it->second.unread_count++;
    }

    stats["account_id"] = account_id;
    stats["email"] = it->second.email_addr;
    stats["display_name"] = it->second.display_name;
    stats["message_count"] = it->second.message_count;
    stats["chat_count"] = it->second.chat_count;
    stats["contact_count"] = it->second.contact_count;
    stats["unread_count"] = it->second.unread_count;
    stats["created_at"] = it->second.created_at;
    stats["last_fetch"] = it->second.last_fetch;
    stats["days_since_created"] = 0;
    if (it->second.created_at > 0) {
      int64_t age_ms = nms() - it->second.created_at;
      stats["days_since_created"] = age_ms / (1000 * 60 * 60 * 24);
    }
  }

  // Global stats
  stats["total_accounts"] = accounts_.size();
  stats["active_account_id"] = active_account_id_;

  return stats;
}

void DeltaChat::recalculate_account_stats(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return;

  it->second.contact_count = contacts_.size();
  it->second.chat_count = chats_.size();
  it->second.message_count = messages_.size();

  it->second.unread_count = 0;
  for (const auto& [id, m] : messages_) {
    if (m.state == 10) it->second.unread_count++;
  }
}

json DeltaChat::get_overall_statistics() {
  json stats;
  int total_msgs = 0, total_chats = 0, total_contacts = 0, total_unread = 0;
  int configured_count = 0, active_count = 0;

  for (auto& [id, acc] : accounts_) {
    recalculate_account_stats(id);
    total_msgs += acc.message_count;
    total_chats += acc.chat_count;
    total_contacts += acc.contact_count;
    total_unread += acc.unread_count;
    if (acc.configured) configured_count++;
    if (acc.active) active_count++;
  }

  stats["total_accounts"] = accounts_.size();
  stats["configured_accounts"] = configured_count;
  stats["active_accounts"] = active_count;
  stats["total_messages"] = total_msgs;
  stats["total_chats"] = total_chats;
  stats["total_contacts"] = total_contacts;
  stats["total_unread"] = total_unread;
  stats["timestamp"] = nms();

  return stats;
}

// ============================================================================
// Daily message stats per account
// ============================================================================
json DeltaChat::get_account_daily_stats(uint32_t account_id,
                                         int days_back) {
  json daily = json::array();
  int64_t now = nms();
  int64_t day_ms = 24 * 60 * 60 * 1000;

  for (int d = days_back - 1; d >= 0; --d) {
    int64_t day_start = now - ((d + 1) * day_ms);
    int64_t day_end = now - (d * day_ms);

    int sent = 0, received = 0;
    for (const auto& [id, m] : messages_) {
      if (m.timestamp >= day_start && m.timestamp < day_end) {
        if (m.state >= 24) sent++;   // Outgoing
        else if (m.state == 10) received++;  // Incoming fresh
      }
    }

    char date_buf[11];
    time_t day_t = day_start / 1000;
    struct tm tm_buf;
    gmtime_r(&day_t, &tm_buf);
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", &tm_buf);

    json day;
    day["date"] = std::string(date_buf);
    day["sent"] = sent;
    day["received"] = received;
    day["total"] = sent + received;
    daily.push_back(day);
  }

  return daily;
}

// ============================================================================
// Contact grouping (Feature 15)
// ============================================================================
void DeltaChat::set_contact_favorite(uint32_t contact_id, bool favorite) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;

  auto& ext = contact_extended_[contact_id];
  ext.id = contact_id;
  ext.is_favorite = favorite;
  contact_extended_[contact_id] = ext;

  if (event_cb_)
    event_cb_(2040, contact_id, favorite ? 1 : 0);  // Favorite changed
}

bool DeltaChat::is_contact_favorite(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) return false;
  return it->second.is_favorite;
}

std::vector<uint32_t> DeltaChat::get_favorite_contacts() {
  std::vector<uint32_t> result;
  for (const auto& [id, ext] : contact_extended_) {
    if (ext.is_favorite) result.push_back(id);
  }
  return result;
}

std::vector<uint32_t> DeltaChat::get_recent_contacts(int max_count,
                                                      int64_t since_timestamp) {
  std::vector<std::pair<uint32_t, int64_t>> scored;

  int64_t now = nms();
  int64_t cutoff = since_timestamp > 0 ? since_timestamp
                    : now - (7 * 24 * 60 * 60 * 1000);  // Last 7 days

  for (const auto& [id, c] : contacts_) {
    int64_t score = 0;
    // Score based on last_seen, last_interaction, interaction_count
    if (c.last_seen >= cutoff) {
      int64_t recency = now - c.last_seen;
      score += std::max<int64_t>(0, 1000000 - recency);
    }

    auto ext_it = contact_extended_.find(id);
    if (ext_it != contact_extended_.end()) {
      score += ext_it->second.interaction_count * 100;
      if (ext_it->second.last_interaction >= cutoff) {
        int64_t recency = now - ext_it->second.last_interaction;
        score += std::max<int64_t>(0, 500000 - recency);
      }
      if (ext_it->second.is_favorite) score += 10000000;
    }

    if (c.last_seen > 0 || score > 0) {
      scored.push_back({id, score});
    }
  }

  // Sort by score (descending)
  std::sort(scored.begin(), scored.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

  std::vector<uint32_t> result;
  for (size_t i = 0; i < scored.size() && (int)result.size() < max_count; ++i) {
    result.push_back(scored[i].first);
  }
  return result;
}

void DeltaChat::record_contact_interaction(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;

  int64_t now = nms();
  auto& ext = contact_extended_[contact_id];
  ext.id = contact_id;
  ext.last_interaction = now;
  ext.interaction_count++;
  contact_extended_[contact_id] = ext;
}

// ============================================================================
// Contact group tags
// ============================================================================
void DeltaChat::add_contact_group_tag(uint32_t contact_id,
                                       const std::string& tag) {
  auto& ext = contact_extended_[contact_id];
  ext.id = contact_id;
  if (std::find(ext.group_tags.begin(), ext.group_tags.end(), tag) ==
      ext.group_tags.end()) {
    ext.group_tags.push_back(tag);
    contact_extended_[contact_id] = ext;
  }
}

void DeltaChat::remove_contact_group_tag(uint32_t contact_id,
                                          const std::string& tag) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) return;
  auto& tags = it->second.group_tags;
  tags.erase(std::remove(tags.begin(), tags.end(), tag), tags.end());
}

std::vector<std::string> DeltaChat::get_contact_group_tags(
    uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) return {};
  return it->second.group_tags;
}

std::vector<uint32_t> DeltaChat::get_contacts_by_group_tag(
    const std::string& tag) {
  std::vector<uint32_t> result;
  for (const auto& [id, ext] : contact_extended_) {
    if (std::find(ext.group_tags.begin(), ext.group_tags.end(), tag) !=
        ext.group_tags.end())
      result.push_back(id);
  }
  return result;
}

std::vector<std::string> DeltaChat::get_all_group_tags() {
  std::set<std::string> all_tags;
  for (const auto& [id, ext] : contact_extended_) {
    for (const auto& tag : ext.group_tags)
      all_tags.insert(tag);
  }
  return std::vector<std::string>(all_tags.begin(), all_tags.end());
}

// ============================================================================
// Contact search and filtering (Feature 16)
// ============================================================================
std::vector<uint32_t> DeltaChat::search_contacts(
    const std::string& query, int max_results,
    ContactSearchField search_fields) {

  std::vector<std::pair<uint32_t, int>> scored;
  std::string q = to_lower(trim(query));
  if (q.empty()) return {};

  for (const auto& [id, c] : contacts_) {
    int score = 0;

    // Match name
    if (search_fields & ContactSearchField::NAME) {
      std::string name_lower = to_lower(c.name);
      if (name_lower == q)
        score += 1000;
      else if (name_lower.find(q) != std::string::npos)
        score += 500;
      else if (name_lower.find(q[0]) != std::string::npos)
        score += 100;
    }

    // Match display name
    if (search_fields & ContactSearchField::DISPLAY_NAME) {
      std::string dn_lower = to_lower(c.display_name);
      if (dn_lower == q)
        score += 900;
      else if (dn_lower.find(q) != std::string::npos)
        score += 400;
    }

    // Match email
    if (search_fields & ContactSearchField::EMAIL) {
      std::string em_lower = to_lower(c.addr);
      if (em_lower == q)
        score += 800;
      else if (em_lower.find(q) != std::string::npos)
        score += 300;
    }

    // Match auth name
    if (search_fields & ContactSearchField::AUTH_NAME) {
      std::string an_lower = to_lower(c.auth_name);
      if (!an_lower.empty() && an_lower.find(q) != std::string::npos)
        score += 200;
    }

    // Match extended fields
    auto ext_it = contact_extended_.find(id);
    if (ext_it != contact_extended_.end()) {
      const auto& ext = ext_it->second;

      if (search_fields & ContactSearchField::NICKNAME) {
        std::string nn_lower = to_lower(ext.nickname);
        if (nn_lower == q)
          score += 950;
        else if (nn_lower.find(q) != std::string::npos)
          score += 450;
      }

      if (search_fields & ContactSearchField::PHONE) {
        if (!ext.phone_number.empty() &&
            ext.phone_number.find(q) != std::string::npos)
          score += 350;
      }

      if (search_fields & ContactSearchField::ORGANIZATION) {
        std::string org_lower = to_lower(ext.organization);
        if (!org_lower.empty() && org_lower.find(q) != std::string::npos)
          score += 250;
      }

      if (search_fields & ContactSearchField::NOTES) {
        std::string notes_lower = to_lower(ext.private_notes);
        if (!notes_lower.empty() && notes_lower.find(q) != std::string::npos)
          score += 150;
      }

      if (search_fields & ContactSearchField::TAGS) {
        for (const auto& tag : ext.group_tags) {
          if (to_lower(tag).find(q) != std::string::npos) {
            score += 300;
            break;
          }
        }
      }
    }

    // Match status
    if (search_fields & ContactSearchField::STATUS) {
      std::string st_lower = to_lower(c.status);
      if (!st_lower.empty() && st_lower.find(q) != std::string::npos)
        score += 50;
    }

    if (score > 0) scored.push_back({id, score});
  }

  // Sort by score
  std::sort(scored.begin(), scored.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

  std::vector<uint32_t> result;
  for (size_t i = 0; i < scored.size() && (int)result.size() < max_results;
       ++i) {
    result.push_back(scored[i].first);
  }
  return result;
}

std::vector<uint32_t> DeltaChat::filter_contacts(
    const ContactFilterCriteria& criteria) {

  std::vector<uint32_t> result;
  for (const auto& [id, c] : contacts_) {
    bool match = true;

    // Filter by blocked status
    if (criteria.blocked.has_value() && c.blocked != *criteria.blocked)
      match = false;

    // Filter by verification level
    if (criteria.min_verification_level.has_value() &&
        c.verified < *criteria.min_verification_level)
      match = false;

    // Filter by source
    if (!criteria.source.empty()) {
      auto ext_it = contact_extended_.find(id);
      if (ext_it == contact_extended_.end() ||
          ext_it->second.source != criteria.source)
        match = false;
    }

    // Filter by favorite
    if (criteria.is_favorite.has_value()) {
      auto ext_it = contact_extended_.find(id);
      bool is_fav =
          ext_it != contact_extended_.end() && ext_it->second.is_favorite;
      if (is_fav != *criteria.is_favorite) match = false;
    }

    // Filter by online status
    if (criteria.online_status.has_value()) {
      auto ext_it = contact_extended_.find(id);
      int status =
          ext_it != contact_extended_.end() ? ext_it->second.online_status : 0;
      if (status != *criteria.online_status) match = false;
    }

    // Filter by group tag
    if (!criteria.group_tag.empty()) {
      auto ext_it = contact_extended_.find(id);
      if (ext_it == contact_extended_.end() ||
          std::find(ext_it->second.group_tags.begin(),
                    ext_it->second.group_tags.end(),
                    criteria.group_tag) == ext_it->second.group_tags.end())
        match = false;
    }

    // Filter by added timestamp range
    if (criteria.added_after.has_value() || criteria.added_before.has_value()) {
      auto ext_it = contact_extended_.find(id);
      int64_t added =
          ext_it != contact_extended_.end() ? ext_it->second.added_at : 0;
      if (criteria.added_after.has_value() && added < *criteria.added_after)
        match = false;
      if (criteria.added_before.has_value() && added > *criteria.added_before)
        match = false;
    }

    // Filter by last interaction range
    if (criteria.last_interaction_after.has_value() ||
        criteria.last_interaction_before.has_value()) {
      auto ext_it = contact_extended_.find(id);
      int64_t li = ext_it != contact_extended_.end()
                       ? ext_it->second.last_interaction
                       : 0;
      if (criteria.last_interaction_after.has_value() &&
          li < *criteria.last_interaction_after)
        match = false;
      if (criteria.last_interaction_before.has_value() &&
          li > *criteria.last_interaction_before)
        match = false;
    }

    // Filter by search query (substring match)
    if (!criteria.search_query.empty()) {
      std::string q = to_lower(criteria.search_query);
      bool found = false;
      if (to_lower(c.name).find(q) != std::string::npos) found = true;
      else if (to_lower(c.display_name).find(q) != std::string::npos)
        found = true;
      else if (to_lower(c.addr).find(q) != std::string::npos)
        found = true;
      auto ext_it = contact_extended_.find(id);
      if (ext_it != contact_extended_.end()) {
        if (to_lower(ext_it->second.nickname).find(q) != std::string::npos)
          found = true;
        if (to_lower(ext_it->second.organization).find(q) != std::string::npos)
          found = true;
      }
      if (!found) match = false;
    }

    if (match) result.push_back(id);
  }

  // Apply sort
  if (criteria.sort_by == ContactFilterCriteria::SortBy::NAME) {
    std::sort(result.begin(), result.end(),
              [this](uint32_t a, uint32_t b) {
                auto it_a = contacts_.find(a);
                auto it_b = contacts_.find(b);
                if (it_a == contacts_.end()) return false;
                if (it_b == contacts_.end()) return true;
                return it_a->second.name < it_b->second.name;
              });
  } else if (criteria.sort_by ==
             ContactFilterCriteria::SortBy::LAST_INTERACTION) {
    std::sort(result.begin(), result.end(),
              [this](uint32_t a, uint32_t b) {
                int64_t li_a = 0, li_b = 0;
                auto ext_a = contact_extended_.find(a);
                auto ext_b = contact_extended_.find(b);
                if (ext_a != contact_extended_.end())
                  li_a = ext_a->second.last_interaction;
                if (ext_b != contact_extended_.end())
                  li_b = ext_b->second.last_interaction;
                return li_a > li_b;
              });
  } else if (criteria.sort_by == ContactFilterCriteria::SortBy::LAST_SEEN) {
    std::sort(result.begin(), result.end(),
              [this](uint32_t a, uint32_t b) {
                auto it_a = contacts_.find(a);
                auto it_b = contacts_.find(b);
                int64_t ls_a = it_a != contacts_.end() ? it_a->second.last_seen : 0;
                int64_t ls_b = it_b != contacts_.end() ? it_b->second.last_seen : 0;
                return ls_a > ls_b;
              });
  }

  // Apply limit
  if (criteria.limit.has_value() && *criteria.limit > 0 &&
      (int)result.size() > *criteria.limit) {
    result.resize(*criteria.limit);
  }

  return result;
}

// ============================================================================
// Contact last seen tracking (Feature 17)
// ============================================================================
int64_t DeltaChat::get_contact_last_seen(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return 0;
  return it->second.last_seen;
}

std::string DeltaChat::get_contact_last_seen_string(uint32_t contact_id) {
  int64_t last = get_contact_last_seen(contact_id);
  if (last == 0) return "never";

  int64_t now = nms();
  int64_t diff = now - last;

  if (diff < 60 * 1000) return "just now";
  if (diff < 60 * 60 * 1000) {
    int minutes = diff / (60 * 1000);
    return std::to_string(minutes) + " minute" + (minutes == 1 ? "" : "s") +
           " ago";
  }
  if (diff < 24 * 60 * 60 * 1000) {
    int hours = diff / (60 * 60 * 1000);
    return std::to_string(hours) + " hour" + (hours == 1 ? "" : "s") + " ago";
  }
  if (diff < 7 * 24 * 60 * 60 * 1000) {
    int days = diff / (24 * 60 * 60 * 1000);
    return std::to_string(days) + " day" + (days == 1 ? "" : "s") + " ago";
  }
  if (diff < 30 * 24 * 60 * 60 * 1000) {
    int weeks = diff / (7 * 24 * 60 * 60 * 1000);
    return std::to_string(weeks) + " week" + (weeks == 1 ? "" : "s") + " ago";
  }

  int months = diff / (30 * 24 * 60 * 60 * 1000);
  return std::to_string(months) + " month" + (months == 1 ? "" : "s") + " ago";
}

void DeltaChat::mark_contact_seen_now(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;

  int64_t now = nms();
  it->second.last_seen = now;
  it->second.was_seen_recently = 1;
}

std::vector<uint32_t> DeltaChat::get_contacts_seen_recently(
    int64_t within_ms) {
  std::vector<uint32_t> result;
  int64_t now = nms();
  int64_t cutoff = now - within_ms;

  for (const auto& [id, c] : contacts_) {
    if (c.last_seen >= cutoff) result.push_back(id);
  }
  return result;
}

std::vector<uint32_t> DeltaChat::get_contacts_not_seen_since(
    int64_t since_timestamp) {
  std::vector<uint32_t> result;
  for (const auto& [id, c] : contacts_) {
    if (c.last_seen > 0 && c.last_seen < since_timestamp)
      result.push_back(id);
    else if (c.last_seen == 0)
      result.push_back(id);  // Never seen
  }
  return result;
}

json DeltaChat::get_last_seen_report() {
  json report;
  json online = json::array();
  json recent = json::array();
  json offline = json::array();
  json never = json::array();

  int64_t now = nms();

  for (const auto& [id, c] : contacts_) {
    json entry;
    entry["id"] = id;
    entry["name"] = c.name;
    entry["last_seen"] = c.last_seen;

    auto ext_it = contact_extended_.find(id);
    if (ext_it != contact_extended_.end() &&
        ext_it->second.online_status >= 1) {
      entry["status"] = get_contact_online_status_label(id);
      online.push_back(entry);
    } else if (c.last_seen > 0 &&
               (now - c.last_seen) < 30 * 60 * 1000) {
      recent.push_back(entry);
    } else if (c.last_seen > 0) {
      offline.push_back(entry);
    } else {
      never.push_back(entry);
    }
  }

  report["online"] = online;
  report["recent"] = recent;
  report["offline"] = offline;
  report["never_seen"] = never;
  report["online_count"] = online.size();
  report["recent_count"] = recent.size();
  report["offline_count"] = offline.size();
  report["never_count"] = never.size();
  report["total"] = contacts_.size();

  return report;
}

// ============================================================================
// Contact color assignment (Feature 18)
// ============================================================================
void DeltaChat::assign_contact_color(uint32_t contact_id,
                                     const std::string& color) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;
  it->second.color = color;
}

void DeltaChat::assign_contact_color_auto(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;
  it->second.color = generate_avatar_color(it->second.addr);
}

std::string DeltaChat::get_contact_color(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return "#808080";
  if (it->second.color.empty()) {
    it->second.color = generate_avatar_color(it->second.addr);
  }
  return it->second.color;
}

void DeltaChat::assign_all_contact_colors_auto() {
  for (auto& [id, c] : contacts_) {
    if (c.color.empty()) {
      c.color = generate_avatar_color(c.addr);
    }
  }
}

json DeltaChat::get_contact_color_palette(uint32_t contact_id) {
  std::string base_color = get_contact_color(contact_id);
  std::string base = base_color;

  // Generate a palette from the base color
  // Parse hex
  int r = 0, g = 0, b = 0;
  if (base.length() == 7 && base[0] == '#') {
    try {
      r = std::stoi(base.substr(1, 2), nullptr, 16);
      g = std::stoi(base.substr(3, 2), nullptr, 16);
      b = std::stoi(base.substr(5, 2), nullptr, 16);
    } catch (...) {}
  }

  json palette = json::array();

  // Light variant
  {
    int lr = std::min(255, r + 80);
    int lg = std::min(255, g + 80);
    int lb = std::min(255, b + 80);
    char buf[8];
    snprintf(buf, sizeof(buf), "#%02x%02x%02x", lr, lg, lb);
    palette.push_back({{"variant", "light"}, {"color", std::string(buf)}});
  }

  // Base
  palette.push_back({{"variant", "base"}, {"color", base_color}});

  // Dark variant
  {
    int dr = std::max(0, r - 60);
    int dg = std::max(0, g - 60);
    int db = std::max(0, b - 60);
    char buf[8];
    snprintf(buf, sizeof(buf), "#%02x%02x%02x", dr, dg, db);
    palette.push_back({{"variant", "dark"}, {"color", std::string(buf)}});
  }

  // Complementary
  {
    int cr = 255 - r;
    int cg = 255 - g;
    int cb = 255 - b;
    char buf[8];
    snprintf(buf, sizeof(buf), "#%02x%02x%02x", cr, cg, cb);
    palette.push_back(
        {{"variant", "complementary"}, {"color", std::string(buf)}});
  }

  // Analogous 1
  {
    int a1r = std::clamp(r + 30, 0, 255);
    int a1g = std::clamp(g - 20, 0, 255);
    int a1b = std::clamp(b - 20, 0, 255);
    char buf[8];
    snprintf(buf, sizeof(buf), "#%02x%02x%02x", a1r, a1g, a1b);
    palette.push_back({{"variant", "analogous_1"}, {"color", std::string(buf)}});
  }

  // Analogous 2
  {
    int a2r = std::clamp(r - 20, 0, 255);
    int a2g = std::clamp(g + 30, 0, 255);
    int a2b = std::clamp(b - 20, 0, 255);
    char buf[8];
    snprintf(buf, sizeof(buf), "#%02x%02x%02x", a2r, a2g, a2b);
    palette.push_back({{"variant", "analogous_2"}, {"color", std::string(buf)}});
  }

  return palette;
}

// ============================================================================
// Contact nickname aliases (Feature 19)
// ============================================================================
void DeltaChat::set_contact_nickname(uint32_t contact_id,
                                     const std::string& nickname) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;

  auto& ext = contact_extended_[contact_id];
  ext.id = contact_id;
  ext.nickname = nickname;
  contact_extended_[contact_id] = ext;

  if (event_cb_)
    event_cb_(2041, contact_id, 0);  // Nickname changed
}

std::string DeltaChat::get_contact_nickname(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) return "";
  return it->second.nickname;
}

std::string DeltaChat::get_contact_display_name_preferred(
    uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return "";

  // Preference: nickname > auth_name > display_name > name > email
  auto ext_it = contact_extended_.find(contact_id);
  if (ext_it != contact_extended_.end() &&
      !ext_it->second.nickname.empty())
    return ext_it->second.nickname;

  if (!it->second.display_name.empty())
    return it->second.display_name;

  if (!it->second.name.empty()) return it->second.name;

  return it->second.addr;
}

void DeltaChat::clear_contact_nickname(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it != contact_extended_.end()) {
    it->second.nickname.clear();
  }
}

std::vector<uint32_t> DeltaChat::lookup_contact_by_nickname(
    const std::string& nickname) {
  std::vector<uint32_t> result;
  std::string needle = to_lower(trim(nickname));
  for (const auto& [id, ext] : contact_extended_) {
    if (to_lower(ext.nickname).find(needle) != std::string::npos)
      result.push_back(id);
  }
  return result;
}

// ============================================================================
// Contact private notes (Feature 20)
// ============================================================================
void DeltaChat::set_contact_private_notes(uint32_t contact_id,
                                          const std::string& notes) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;

  auto& ext = contact_extended_[contact_id];
  ext.id = contact_id;
  ext.private_notes = notes;
  contact_extended_[contact_id] = ext;

  if (event_cb_)
    event_cb_(2042, contact_id, 0);  // Notes changed
}

std::string DeltaChat::get_contact_private_notes(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) return "";
  return it->second.private_notes;
}

void DeltaChat::append_contact_private_note(uint32_t contact_id,
                                            const std::string& note) {
  auto& ext = contact_extended_[contact_id];
  ext.id = contact_id;

  if (!ext.private_notes.empty())
    ext.private_notes += "\n---\n";

  char timestamp_buf[32];
  time_t now = nms() / 1000;
  struct tm tm_buf;
  localtime_r(&now, &tm_buf);
  strftime(timestamp_buf, sizeof(timestamp_buf), "%Y-%m-%d %H:%M", &tm_buf);

  ext.private_notes += "[" + std::string(timestamp_buf) + "] " + note;
  contact_extended_[contact_id] = ext;
}

void DeltaChat::clear_contact_private_notes(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it != contact_extended_.end()) {
    it->second.private_notes.clear();
  }
}

std::vector<uint32_t> DeltaChat::search_contacts_by_notes(
    const std::string& query) {
  std::vector<uint32_t> result;
  std::string needle = to_lower(trim(query));
  if (needle.empty()) return result;

  for (const auto& [id, ext] : contact_extended_) {
    if (to_lower(ext.private_notes).find(needle) != std::string::npos)
      result.push_back(id);
  }
  return result;
}

bool DeltaChat::contact_has_notes(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) return false;
  return !it->second.private_notes.empty();
}

int DeltaChat::get_contact_notes_count() {
  int count = 0;
  for (const auto& [id, ext] : contact_extended_) {
    if (!ext.private_notes.empty()) count++;
  }
  return count;
}

// ============================================================================
// Batch contact operations
// ============================================================================
ImportResult DeltaChat::import_contacts_batch(
    const std::vector<std::tuple<std::string, std::string, std::string>>&
        contacts_data) {
  // contacts_data: vector of (name, email, phone)
  std::vector<AddressBookEntry> entries;
  for (const auto& [name, email, phone] : contacts_data) {
    AddressBookEntry entry;
    entry.name = name;
    entry.email = email;
    entry.phone = phone;
    entries.push_back(entry);
  }
  return import_contacts_from_address_book(entries, false, true);
}

void DeltaChat::delete_contacts_batch(
    const std::vector<uint32_t>& contact_ids) {
  for (auto id : contact_ids) {
    contacts_.erase(id);
    contact_extended_.erase(id);
    blocked_contacts_.erase(id);
    avatar_cache_ttl_.erase(id);
    avatar_cache_timestamp_.erase(id);
  }

  if (event_cb_)
    event_cb_(2050, contact_ids.size(), 0);  // Batch delete event
}

// ============================================================================
// Contact counts and summaries
// ============================================================================
json DeltaChat::get_contact_summary(uint32_t contact_id) {
  json summary;
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return summary;

  const auto& c = it->second;
  summary["id"] = c.id;
  summary["name"] = c.name;
  summary["display_name"] = c.display_name;
  summary["address"] = c.addr;
  summary["color"] = c.color;
  summary["blocked"] = c.blocked > 0;
  summary["verified"] = c.verified;
  summary["verification_label"] =
      c.verified == 2 ? "bidirectional"
      : c.verified == 1 ? "verified"
                        : "unverified";
  summary["last_seen"] = c.last_seen;
  summary["last_seen_label"] = get_contact_last_seen_string(contact_id);

  auto ext_it = contact_extended_.find(contact_id);
  if (ext_it != contact_extended_.end()) {
    const auto& ext = ext_it->second;
    if (!ext.nickname.empty()) summary["nickname"] = ext.nickname;
    if (!ext.phone_number.empty()) summary["phone"] = ext.phone_number;
    if (!ext.organization.empty()) summary["organization"] = ext.organization;
    if (!ext.title.empty()) summary["title"] = ext.title;
    summary["is_favorite"] = ext.is_favorite;
    summary["online_status"] = get_contact_online_status_label(contact_id);
    summary["has_notes"] = !ext.private_notes.empty();
    summary["interaction_count"] = ext.interaction_count;
    summary["source"] = ext.source;
    summary["group_tags"] = ext.group_tags;
  }

  return summary;
}

json DeltaChat::get_contacts_overview() {
  json overview;

  int total = contacts_.size();
  int blocked = blocked_contacts_.size();
  int favorites = 0;
  int verified = 0;
  int bidirectional = 0;
  int online = 0;
  int with_notes = 0;
  int with_phone = 0;

  for (const auto& [id, c] : contacts_) {
    if (c.verified == 2) bidirectional++;
    else if (c.verified == 1) verified++;

    auto ext_it = contact_extended_.find(id);
    if (ext_it != contact_extended_.end()) {
      if (ext_it->second.is_favorite) favorites++;
      if (!ext_it->second.private_notes.empty()) with_notes++;
      if (!ext_it->second.phone_number.empty()) with_phone++;
      if (ext_it->second.online_status >= 1) online++;
    }
  }

  overview["total"] = total;
  overview["blocked"] = blocked;
  overview["favorites"] = favorites;
  overview["verified"] = verified;
  overview["bidirectional"] = bidirectional;
  overview["unverified"] = total - verified - bidirectional;
  overview["online"] = online;
  overview["with_notes"] = with_notes;
  overview["with_phone"] = with_phone;

  return overview;
}

// ============================================================================
// Contact data export/import full (combines all features)
// ============================================================================
json DeltaChat::export_contact_full_data(uint32_t contact_id) {
  json data;
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return data;

  const auto& c = it->second;
  data["contact"] = {
      {"id", c.id},           {"name", c.name},
      {"display_name", c.display_name}, {"addr", c.addr},
      {"auth_name", c.auth_name},       {"color", c.color},
      {"blocked", c.blocked},           {"verified", c.verified},
      {"last_seen", c.last_seen},       {"status", c.status},
  };

  auto ext_it = contact_extended_.find(contact_id);
  if (ext_it != contact_extended_.end()) {
    const auto& ext = ext_it->second;
    data["extended"] = {
        {"nickname", ext.nickname},
        {"private_notes", ext.private_notes},
        {"is_favorite", ext.is_favorite},
        {"phone_number", ext.phone_number},
        {"organization", ext.organization},
        {"title", ext.title},
        {"source", ext.source},
        {"online_status", ext.online_status},
        {"verification_level", ext.verification_level},
        {"verification_method", ext.verification_method},
        {"verification_time", ext.verification_time},
        {"added_at", ext.added_at},
        {"last_interaction", ext.last_interaction},
        {"interaction_count", ext.interaction_count},
        {"group_tags", ext.group_tags},
    };
  }

  if (!c.profile_image.empty())
    data["avatar_path"] = c.profile_image;

  return data;
}

bool DeltaChat::import_contact_full_data(const json& data) {
  if (!data.contains("contact") || !data["contact"].contains("addr"))
    return false;

  auto& cdata = data["contact"];
  std::string addr = cdata["addr"];

  // Check if already exists
  uint32_t existing = 0;
  for (const auto& [id, c] : contacts_) {
    if (normalize_email(c.addr) == normalize_email(addr)) {
      existing = id;
      break;
    }
  }

  uint32_t cid;
  if (existing > 0) {
    cid = existing;
  } else {
    cid = create_contact(
        cdata.value("name", extract_name_from_email(addr)), addr);
  }

  auto& c = contacts_[cid];
  if (cdata.contains("display_name"))
    c.display_name = cdata["display_name"];
  if (cdata.contains("auth_name")) c.auth_name = cdata["auth_name"];
  if (cdata.contains("color")) c.color = cdata["color"];
  if (cdata.contains("blocked")) c.blocked = cdata["blocked"];
  if (cdata.contains("verified")) c.verified = cdata["verified"];
  if (cdata.contains("last_seen")) c.last_seen = cdata["last_seen"];
  if (cdata.contains("status")) c.status = cdata["status"];
  if (cdata.contains("avatar_path"))
    c.profile_image = cdata["avatar_path"];

  if (data.contains("extended")) {
    auto& edata = data["extended"];
    auto& ext = contact_extended_[cid];
    ext.id = cid;
    if (edata.contains("nickname"))
      ext.nickname = edata["nickname"];
    if (edata.contains("private_notes"))
      ext.private_notes = edata["private_notes"];
    if (edata.contains("is_favorite"))
      ext.is_favorite = edata["is_favorite"];
    if (edata.contains("phone_number"))
      ext.phone_number = edata["phone_number"];
    if (edata.contains("organization"))
      ext.organization = edata["organization"];
    if (edata.contains("title")) ext.title = edata["title"];
    if (edata.contains("source")) ext.source = edata["source"];
    if (edata.contains("online_status"))
      ext.online_status = edata["online_status"];
    if (edata.contains("verification_level"))
      ext.verification_level = edata["verification_level"];
    if (edata.contains("verification_method"))
      ext.verification_method = edata["verification_method"];
    if (edata.contains("verification_time"))
      ext.verification_time = edata["verification_time"];
    if (edata.contains("added_at")) ext.added_at = edata["added_at"];
    if (edata.contains("last_interaction"))
      ext.last_interaction = edata["last_interaction"];
    if (edata.contains("interaction_count"))
      ext.interaction_count = edata["interaction_count"];
    if (edata.contains("group_tags"))
      ext.group_tags = edata["group_tags"].get<std::vector<std::string>>();
    contact_extended_[cid] = ext;
  }

  return true;
}

// ============================================================================
// Account information queries
// ============================================================================
std::string DeltaChat::get_account_display_name(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return "";
  return it->second.display_name;
}

std::string DeltaChat::get_account_email(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return "";
  return it->second.email_addr;
}

bool DeltaChat::set_account_display_name(uint32_t account_id,
                                         const std::string& name) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return false;
  it->second.display_name = name;
  return true;
}

void DeltaChat::set_device_name(const std::string& name) {
  for (auto& [id, acc] : accounts_) {
    acc.device_name = name;
  }
}

std::string DeltaChat::get_device_name() {
  // Return the device name from the active account
  auto it = accounts_.find(active_account_id_);
  if (it != accounts_.end()) return it->second.device_name;
  return "Unknown Device";
}

// ============================================================================
// Extended contact data accessors
// ============================================================================
ContactExtended DeltaChat::get_contact_extended(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) return ContactExtended{};
  return it->second;
}

void DeltaChat::set_contact_extended(uint32_t contact_id,
                                     const ContactExtended& ext) {
  contact_extended_[contact_id] = ext;
  contact_extended_[contact_id].id = contact_id;
}

// ============================================================================
// Periodic maintenance
// ============================================================================
void DeltaChat::perform_contact_maintenance() {
  int64_t now = nms();

  // Cleanup expired avatar cache
  cleanup_expired_avatar_cache();

  // Check online statuses
  check_online_statuses();

  // Process fetch schedule
  process_fetch_schedule();

  // Recalculate stats for active accounts
  if (active_account_id_ > 0) {
    recalculate_account_stats(active_account_id_);
  }

  // Check for scheduled address book sync
  check_scheduled_sync();

  // Update maintenance timestamp
  last_maintenance_time_ = now;
}

// ============================================================================
// Static helpers for address-book reading (platform-specific stubs)
// ============================================================================
std::vector<AddressBookEntry> DeltaChat::read_system_address_book() {
  // Platform-specific address book reading
  // Returns empty vector - to be implemented per platform
  std::vector<AddressBookEntry> entries;

#ifdef __linux__
  // On Linux, could read from ~/.local/share/evolution/addressbook
  // or use libebook (Evolution Data Server)
  std::string home = std::getenv("HOME") ? std::getenv("HOME") : "/tmp";
  std::string addrbook_path = home + "/.local/share/evolution/addressbook";
  // This would actually parse the address book DB in production
#elif defined(__APPLE__)
  // macOS: Use Contacts framework via Objective-C++ bridge
  // CNContactStore *store = [[CNContactStore alloc] init];
  // ...
#elif defined(_WIN32)
  // Windows: Use Windows Contacts API or MAPI
  // ...
#endif

  return entries;
}

// ============================================================================
// Public API wrappers
// ============================================================================
int DeltaChat::get_contact_count() { return contacts_.size(); }

int DeltaChat::get_blocked_contact_count() {
  return blocked_contacts_.size();
}

int DeltaChat::get_favorite_contact_count() { return get_favorite_contacts().size(); }

int DeltaChat::get_verified_contact_count() {
  return get_verified_contacts(1).size();
}

int DeltaChat::get_bidirectionally_verified_contact_count() {
  return get_verified_contacts(2).size();
}

bool DeltaChat::has_contact(uint32_t contact_id) {
  return contacts_.count(contact_id) > 0;
}

bool DeltaChat::has_contact_by_addr(const std::string& addr) {
  std::string norm = normalize_email(addr);
  for (const auto& [id, c] : contacts_) {
    if (normalize_email(c.addr) == norm) return true;
  }
  return false;
}

// ============================================================================
// Account order management
// ============================================================================
void DeltaChat::set_account_order(
    const std::vector<uint32_t>& account_ids) {
  account_order_ = account_ids;
}

std::vector<uint32_t> DeltaChat::get_account_order() { return account_order_; }

void DeltaChat::move_account_to_position(uint32_t account_id, int position) {
  // Remove if exists
  auto it =
      std::find(account_order_.begin(), account_order_.end(), account_id);
  if (it != account_order_.end()) account_order_.erase(it);

  // Insert at position
  if (position < 0 || position >= (int)account_order_.size())
    account_order_.push_back(account_id);
  else
    account_order_.insert(account_order_.begin() + position, account_id);
}

// ============================================================================
// Account sync state
// ============================================================================
void DeltaChat::mark_account_synced(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return;
  it->second.sync_timestamp = nms();

  if (event_cb_)
    event_cb_(3020, account_id, 0);  // Account synced
}

int64_t DeltaChat::get_account_last_sync(uint32_t account_id) {
  auto it = accounts_.find(account_id);
  if (it == accounts_.end()) return 0;
  return it->second.sync_timestamp;
}

// ============================================================================
// Multi-account contact cross-reference
// ============================================================================
std::vector<uint32_t> DeltaChat::find_contact_across_accounts(
    const std::string& email) {
  std::vector<uint32_t> result;
  // In a full implementation, this would search across all account databases
  // For now, search current contacts since we operate in one account context
  std::string norm = normalize_email(email);
  for (const auto& [id, c] : contacts_) {
    if (normalize_email(c.addr) == norm) result.push_back(id);
  }
  return result;
}

// ============================================================================
// Avatar utility functions
// ============================================================================
std::string DeltaChat::get_contact_initials(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return "?";

  std::string name = get_contact_display_name_preferred(contact_id);
  if (name.empty()) return "?";

  // Get first character of first and last word
  std::string initials;
  auto words = split(name, ' ');
  for (const auto& w : words) {
    if (!w.empty()) initials += std::toupper(w[0]);
  }
  if (initials.size() > 2) initials = initials.substr(0, 2);
  if (initials.empty()) initials = std::string(1, std::toupper(name[0]));

  return initials;
}

std::string DeltaChat::get_contact_avatar_fallback(uint32_t contact_id) {
  // Generate an SVG avatar as fallback when no image is available
  std::string initials = get_contact_initials(contact_id);
  std::string color = get_contact_color(contact_id);

  std::stringstream svg;
  svg << "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\">";
  svg << "<circle cx=\"50\" cy=\"50\" r=\"50\" fill=\"" << color << "\"/>";
  svg << "<text x=\"50\" y=\"50\" dy=\".35em\" text-anchor=\"middle\" "
      << "font-family=\"Arial\" font-size=\"40\" fill=\"white\" "
      << "dominant-baseline=\"central\">"
      << initials << "</text>";
  svg << "</svg>";

  return svg.str();
}

// ============================================================================
// VCard batch export / import helpers
// ============================================================================
std::string DeltaChat::export_contacts_to_vcard_batch(
    const std::vector<uint32_t>& contact_ids) {
  return export_contacts_to_vcard(contact_ids, true, false);
}

ImportResult DeltaChat::import_vcard_file(const std::string& file_path) {
  std::ifstream in(file_path);
  if (!in.good()) {
    ImportResult r;
    r.errors.push_back("Cannot open file: " + file_path);
    r.total_errors++;
    return r;
  }

  std::string content((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
  return import_contacts_from_vcard(content, false, true);
}

// ============================================================================
} // namespace progressive::deltachat
