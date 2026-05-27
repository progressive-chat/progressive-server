// deltachat_addressbook.cpp - DeltaChat address book sync, vCard import/export,
// contact deduplication, fuzzy search, and contact lifecycle management. 3500+ lines.
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
static int levenshtein_distance(const std::string& a, const std::string& b);
static std::string fold_vcard_line(const std::string& line, size_t max_len = 75);
static std::string unfold_vcard_lines(const std::string& data);
static std::string parse_vcard_param(const std::string& field, const std::string& param);
static std::string format_date_iso8601(time_t t);
static time_t parse_date_iso8601(const std::string& s);
static std::string format_date_vcard(time_t t);
static bool is_whitespace_or_empty(const std::string& s);
static std::string strip_bom(const std::string& s);
static std::string normalize_phone(const std::string& phone);
static std::string normalize_text_for_search(const std::string& s);
static std::string soundex(const std::string& s);
static std::string metaphone(const std::string& s);
static double cosine_similarity(const std::vector<int>& a, const std::vector<int>& b);
static std::vector<int> ngram_vector(const std::string& s, int n);

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

static int levenshtein_distance(const std::string& a, const std::string& b) {
  const size_t m = a.size(), n = b.size();
  std::vector<int> prev(n + 1), curr(n + 1);
  for (size_t j = 0; j <= n; ++j) prev[j] = j;
  for (size_t i = 1; i <= m; ++i) {
    curr[0] = i;
    for (size_t j = 1; j <= n; ++j) {
      int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
      curr[j] = std::min({prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost});
    }
    prev.swap(curr);
  }
  return prev[n];
}

static bool is_whitespace_or_empty(const std::string& s) {
  return s.find_first_not_of(" \t\r\n") == std::string::npos;
}

static std::string strip_bom(const std::string& s) {
  if (s.size() >= 3 && (unsigned char)s[0] == 0xEF &&
      (unsigned char)s[1] == 0xBB && (unsigned char)s[2] == 0xBF)
    return s.substr(3);
  if (s.size() >= 2 && (unsigned char)s[0] == 0xFE &&
      (unsigned char)s[1] == 0xFF)
    return s.substr(2);
  if (s.size() >= 2 && (unsigned char)s[0] == 0xFF &&
      (unsigned char)s[1] == 0xFE)
    return s.substr(2);
  return s;
}

static std::string normalize_phone(const std::string& phone) {
  std::string r;
  for (char c : phone) {
    if (c == '+' || std::isdigit(c)) r += c;
  }
  return r;
}

static std::string normalize_text_for_search(const std::string& s) {
  return levenshtein_normalize(s);
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
  int max_c = std::max({r, g, b});
  if (max_c < 128 && max_c > 0) {
    r = r * 180 / max_c;
    g = g * 180 / max_c;
    b = b * 180 / max_c;
  }
  r = r * 70 / 100;
  g = g * 70 / 100;
  b = b * 70 / 100;
  char buf[8];
  snprintf(buf, sizeof(buf), "#%02x%02x%02x", r & 0xFF, g & 0xFF, b & 0xFF);
  return std::string(buf);
}

// ============================================================================
// vCard line folding/unfolding
// ============================================================================
static std::string fold_vcard_line(const std::string& line, size_t max_len) {
  if (line.size() <= max_len) return line + "\r\n";
  std::string result;
  result += line.substr(0, max_len) + "\r\n";
  for (size_t i = max_len; i < line.size(); i += max_len - 1) {
    result += " ";
    result += line.substr(i, max_len - 1);
    result += "\r\n";
  }
  return result;
}

static std::string unfold_vcard_lines(const std::string& data) {
  std::string result;
  bool prev_cr = false;
  for (size_t i = 0; i < data.size(); ++i) {
    if (prev_cr && data[i] == '\n') {
      prev_cr = false;
      if (i + 1 < data.size() && (data[i + 1] == ' ' || data[i + 1] == '\t')) {
        ++i; // skip the folding whitespace
        continue;
      }
    }
    prev_cr = (data[i] == '\r');
    result += data[i];
  }
  return result;
}

static std::string parse_vcard_param(const std::string& field,
                                      const std::string& param) {
  std::string key = ";" + param + "=";
  auto pos = field.find(key);
  if (pos == std::string::npos) return "";
  pos += key.size();
  auto end = field.find(';', pos);
  if (end == std::string::npos) end = field.find(':', pos);
  if (end == std::string::npos) end = field.size();
  return field.substr(pos, end - pos);
}

// ============================================================================
// Date formatting helpers
// ============================================================================
static std::string format_date_iso8601(time_t t) {
  char buf[32];
  struct tm tm_buf;
  gmtime_r(&t, &tm_buf);
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
  return std::string(buf);
}

static time_t parse_date_iso8601(const std::string& s) {
  struct tm tm_buf = {};
  if (s.size() >= 10) {
    sscanf(s.c_str(), "%4d-%2d-%2d", &tm_buf.tm_year, &tm_buf.tm_mon, &tm_buf.tm_mday);
    tm_buf.tm_year -= 1900;
    tm_buf.tm_mon -= 1;
  }
  if (s.size() >= 19) {
    sscanf(s.c_str() + 11, "%2d:%2d:%2d",
           &tm_buf.tm_hour, &tm_buf.tm_min, &tm_buf.tm_sec);
  }
  return timegm(&tm_buf);
}

static std::string format_date_vcard(time_t t) {
  char buf[32];
  struct tm tm_buf;
  gmtime_r(&t, &tm_buf);
  strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm_buf);
  return std::string(buf);
}

// ============================================================================
// Soundex implementation (for fuzzy name matching)
// ============================================================================
static std::string soundex(const std::string& s) {
  if (s.empty()) return "";
  std::string r;
  r += std::toupper(s[0]);
  static const char mapping[] = {
      0,1,2,3,0,1,2,0,0,2,2,4,5,5,0,1,2,6,2,3,0,1,0,2,0,2};
  char prev = 0;
  for (size_t i = 1; i < s.size() && r.size() < 4; ++i) {
    char c = std::toupper(s[i]);
    if (c >= 'A' && c <= 'Z') {
      char code = mapping[c - 'A'];
      if (code != 0 && code != prev) {
        r += ('0' + code);
        prev = code;
      }
    }
  }
  while (r.size() < 4) r += '0';
  return r;
}

// ============================================================================
// Metaphone implementation (for fuzzy name matching)
// ============================================================================
static std::string metaphone(const std::string& s) {
  if (s.empty()) return "";
  std::string r = to_upper(s);
  // Simplified metaphone: drop vowels (except leading), map common patterns
  std::string out;
  if (!r.empty()) out += r[0];
  for (size_t i = 1; i < r.size(); ++i) {
    char c = r[i];
    if (c == 'A' || c == 'E' || c == 'I' || c == 'O' || c == 'U') continue;
    if (c == 'B') out += 'B';
    else if (c == 'C') { if (i+1 < r.size() && (r[i+1]=='E'||r[i+1]=='I'||r[i+1]=='Y')) out += 'S'; else out += 'K'; }
    else if (c == 'D') out += 'T';
    else if (c == 'F') out += 'F';
    else if (c == 'G') out += 'K';
    else if (c == 'H') { if (i>0 && r[i-1]!='C'&&r[i-1]!='S'&&r[i-1]!='P'&&r[i-1]!='T'&&r[i-1]!='G') out += 'H'; }
    else if (c == 'J') out += 'J';
    else if (c == 'K') out += 'K';
    else if (c == 'L') out += 'L';
    else if (c == 'M') out += 'M';
    else if (c == 'N') out += 'N';
    else if (c == 'P') out += 'P';
    else if (c == 'Q') out += 'K';
    else if (c == 'R') out += 'R';
    else if (c == 'S') out += 'S';
    else if (c == 'T') out += 'T';
    else if (c == 'V') out += 'F';
    else if (c == 'W') out += 'W';
    else if (c == 'X') out += "KS";
    else if (c == 'Y') out += 'Y';
    else if (c == 'Z') out += 'S';
  }
  // Remove duplicates
  std::string dedup;
  char last = 0;
  for (char c : out) {
    if (c != last) dedup += c;
    last = c;
  }
  if (dedup.size() > 12) dedup = dedup.substr(0, 12);
  return dedup;
}

// ============================================================================
// N-gram vector for fuzzy search
// ============================================================================
static std::vector<int> ngram_vector(const std::string& s, int n) {
  std::unordered_map<std::string, int> counts;
  for (size_t i = 0; i + n <= s.size(); ++i) {
    counts[s.substr(i, n)]++;
  }
  std::vector<int> vec;
  for (const auto& [ngram, count] : counts) {
    vec.push_back(count);
  }
  return vec;
}

static double cosine_similarity(const std::vector<int>& a, const std::vector<int>& b) {
  if (a.empty() || b.empty()) return 0.0;
  size_t max_sz = std::max(a.size(), b.size());
  double dot = 0.0, mag_a = 0.0, mag_b = 0.0;
  for (size_t i = 0; i < max_sz; ++i) {
    int va = (i < a.size()) ? a[i] : 0;
    int vb = (i < b.size()) ? b[i] : 0;
    dot += va * vb;
    mag_a += va * va;
    mag_b += vb * vb;
  }
  if (mag_a == 0.0 || mag_b == 0.0) return 0.0;
  return dot / (std::sqrt(mag_a) * std::sqrt(mag_b));
}

// ============================================================================
// Address book data structures
// ============================================================================
struct AddressBookEntry {
  std::string system_id;       // Platform-specific unique ID
  std::string display_name;
  std::string first_name;
  std::string last_name;
  std::string nickname;
  std::string organization;
  std::string title;
  std::string department;
  std::vector<std::string> emails;
  std::vector<std::string> email_labels;  // "HOME","WORK","OTHER"
  std::vector<std::string> phone_numbers;
  std::vector<std::string> phone_labels;  // "CELL","HOME","WORK"
  std::vector<std::string> addresses;     // formatted postal addresses
  std::vector<std::string> address_labels;
  std::string photo_data;        // base64-encoded photo
  std::string photo_mime_type;
  std::string birthday;          // "YYYY-MM-DD"
  std::string anniversary;       // "YYYY-MM-DD"
  std::string notes;
  std::string url;
  std::vector<std::string> group_labels;  // groups/categories
  int64_t created_at{0};
  int64_t modified_at{0};
  bool is_deleted{false};
  std::string etag;              // change detection hash
};

struct VCardContact {
  std::string uid;
  std::string full_name;
  std::string given_name;       // first name
  std::string family_name;      // last name
  std::string middle_name;
  std::string name_prefix;      // Mr., Mrs., Dr.
  std::string name_suffix;      // Jr., Sr., III
  std::string nickname;
  std::string organization;
  std::string title;
  std::string role;
  std::string department;
  struct Email { std::string addr; std::string type; };
  struct Phone { std::string number; std::string type; };
  struct Address {
    std::string po_box; std::string extended; std::string street;
    std::string city; std::string region; std::string postal_code;
    std::string country; std::string type;
  };
  struct Photo { std::string data; std::string mime_type; std::string uri; };
  struct Date { int year{0}; int month{0}; int day{0}; std::string type; };
  std::vector<Email> emails;
  std::vector<Phone> phones;
  std::vector<Address> addresses;
  std::vector<Photo> photos;
  std::vector<Date> dates;          // BDAY, ANNIVERSARY
  std::string notes;
  std::string url;
  std::vector<std::string> categories;
  std::string rev;                  // revision timestamp
  std::string prodid;
  std::string source;
  time_t revision_time{0};
  int version{3};                   // vCard version (3 or 4)
};

struct ContactMergeCandidate {
  uint32_t contact_a;
  uint32_t contact_b;
  double confidence;              // 0.0 to 1.0
  std::string match_reason;       // "email", "phone", "name", etc.
  bool auto_merge{false};         // high-confidence auto-merge
};

struct SyncState {
  std::string last_etag;           // HTTP etag for remote sync
  int64_t last_sync_time{0};
  int64_t next_sync_time{0};
  int sync_interval_seconds{300};  // Default 5 minutes
  int total_contacts_in_source{0};
  int contacts_added{0};
  int contacts_updated{0};
  int contacts_deleted{0};
  int contacts_merged{0};
  int contacts_skipped{0};
  bool is_running{false};
  bool needs_full_rescan{false};
  bool sync_on_wifi_only{true};
  std::string source_path;         // OS address book path
  std::string last_error;
  int consecutive_errors{0};
  int max_consecutive_errors{5};
};

struct RecentContact {
  uint32_t contact_id;
  int64_t last_interaction;
  int interaction_count;
  int priority_score;             // computed score for ordering
};

struct FavoriteGroup {
  std::string group_name;
  std::vector<uint32_t> contact_ids;
  int sort_order{0};
  int64_t created_at{0};
  int64_t modified_at{0};
};

struct ContactNote {
  uint32_t contact_id;
  std::string note_id;
  std::string content;
  int64_t created_at{0};
  int64_t modified_at{0};
  std::string color_tag;          // optional color coding
  bool pinned{false};
};

struct AddressBookSnapshot {
  std::unordered_map<std::string, AddressBookEntry> entries;  // keyed by system_id
  int64_t snapshot_time{0};
  std::string snapshot_hash;
};

// ============================================================================
// Address book scan manager (Feature 1: Address book scanning)
// ============================================================================
class AddressBookScanner {
public:
  struct ScannerConfig {
    std::vector<std::string> search_paths; // system address book locations
    bool scan_evolution{true};     // Linux Evolution Data Server
    bool scan_macos_contacts{true}; // macOS Contacts.app
    bool scan_windows_contacts{true}; // Windows Contacts
    bool scan_vcf_directory{true}; // plain .vcf files in directory
    std::string vcf_directory;
    int max_entries{10000};
    int scan_interval_seconds{300};
    bool follow_symlinks{false};
    bool include_groups{true};
    bool include_photos{true};
    int max_photo_size_bytes{1048576}; // 1MB max
  };

  AddressBookScanner() = default;

  void configure(const ScannerConfig& cfg) {
    std::lock_guard lock(mutex_);
    config_ = cfg;
  }

  // Scan all configured address book sources
  std::vector<AddressBookEntry> scan_all() {
    std::lock_guard lock(mutex_);
    std::vector<AddressBookEntry> all_entries;

    // Scan VCF directory
    if (config_.scan_vcf_directory && !config_.vcf_directory.empty()) {
      auto vcf_entries = scan_vcf_directory(config_.vcf_directory);
      all_entries.insert(all_entries.end(), vcf_entries.begin(), vcf_entries.end());
    }

    // Platform-specific scanning
    auto platform_entries = scan_platform_address_book();
    all_entries.insert(all_entries.end(), platform_entries.begin(), platform_entries.end());

    // Deduplicate by system_id
    std::unordered_map<std::string, AddressBookEntry> dedup;
    for (auto& e : all_entries) {
      if (dedup.find(e.system_id) == dedup.end() ||
          e.modified_at > dedup[e.system_id].modified_at) {
        dedup[e.system_id] = e;
      }
    }

    all_entries.clear();
    for (auto& [id, entry] : dedup) {
      all_entries.push_back(entry);
      if ((int)all_entries.size() >= config_.max_entries) break;
    }

    last_scan_time_ = nms();
    last_scan_count_ = all_entries.size();
    return all_entries;
  }

  // Scan a directory of .vcf files
  std::vector<AddressBookEntry> scan_vcf_directory(const std::string& dir) {
    std::vector<AddressBookEntry> entries;
    // In production, this would use filesystem API to list .vcf files
    // and parse each one via the vCard parser
    last_scan_path_ = dir;
    return entries;
  }

  // Platform-specific address book reading
  std::vector<AddressBookEntry> scan_platform_address_book() {
    std::vector<AddressBookEntry> entries;

#if defined(__linux__)
    if (config_.scan_evolution) {
      entries = scan_evolution_data_server();
    }
#elif defined(__APPLE__)
    if (config_.scan_macos_contacts) {
      entries = scan_macos_contacts_framework();
    }
#elif defined(_WIN32)
    if (config_.scan_windows_contacts) {
      entries = scan_windows_contacts_api();
    }
#endif

    return entries;
  }

  // Linux Evolution Data Server scanning
  std::vector<AddressBookEntry> scan_evolution_data_server() {
    std::vector<AddressBookEntry> entries;
    std::string home = std::getenv("HOME") ? std::getenv("HOME") : "/tmp";
    // Evolution address book DB locations
    std::vector<std::string> paths = {
      home + "/.local/share/evolution/addressbook",
      home + "/.local/share/evolution/contacts",
      home + "/.cache/evolution/addressbook",
    };
    // In production, would use libebook / EDS API to enumerate contacts
    last_scan_path_ = join(paths, ":");
    return entries;
  }

  // macOS Contacts framework scanning
  std::vector<AddressBookEntry> scan_macos_contacts_framework() {
    std::vector<AddressBookEntry> entries;
    // Would use CNContactStore in production
    last_scan_path_ = "CNContactStore";
    return entries;
  }

  // Windows Contacts API scanning
  std::vector<AddressBookEntry> scan_windows_contacts_api() {
    std::vector<AddressBookEntry> entries;
    // Would use Windows Contacts API or MAPI in production
    last_scan_path_ = "WindowsContacts";
    return entries;
  }

  int64_t get_last_scan_time() const { return last_scan_time_; }
  size_t get_last_scan_count() const { return last_scan_count_; }
  std::string get_last_scan_path() const { return last_scan_path_; }

private:
  ScannerConfig config_;
  std::mutex mutex_;
  int64_t last_scan_time_{0};
  size_t last_scan_count_{0};
  std::string last_scan_path_;
};

// ============================================================================
// Singleton scanner instance
// ============================================================================
static AddressBookScanner g_address_book_scanner;

// ============================================================================
// vCard parser: Feature 2 (parse vCard 3.0 and 4.0)
// ============================================================================
class VCardParser {
public:
  VCardParser() = default;

  // Parse a complete vCard string (may contain multiple vCards)
  std::vector<VCardContact> parse_vcards(const std::string& data) {
    std::vector<VCardContact> contacts;

    // Strip BOM if present
    std::string cleaned = strip_bom(data);

    // Unfold lines (RFC 2425, RFC 6350)
    std::string unfolded = unfold_vcard_lines(cleaned);

    // Split into individual vCards
    std::vector<std::string> vcard_blocks;
    size_t start = 0;
    while (true) {
      auto begin_pos = unfolded.find("BEGIN:VCARD", start);
      if (begin_pos == std::string::npos) break;
      auto end_pos = unfolded.find("END:VCARD", begin_pos);
      if (end_pos == std::string::npos) break;
      end_pos = unfolded.find("\n", end_pos);
      if (end_pos == std::string::npos) end_pos = unfolded.size();
      vcard_blocks.push_back(unfolded.substr(begin_pos, end_pos - begin_pos));
      start = end_pos;
    }

    for (const auto& block : vcard_blocks) {
      try {
        auto contact = parse_single_vcard(block);
        contacts.push_back(contact);
      } catch (...) {
        // Skip malformed vCards
        continue;
      }
    }

    return contacts;
  }

  // Parse a single vCard into a VCardContact structure
  VCardContact parse_single_vcard(const std::string& block) {
    VCardContact contact;

    // Split into lines
    auto lines = split(block, '\n');
    std::vector<std::string> clean_lines;
    for (auto& l : lines) {
      l = trim(l);
      if (!l.empty() && l.back() == '\r') l.pop_back();
      if (!l.empty()) clean_lines.push_back(l);
    }

    // Detect version
    for (const auto& line : clean_lines) {
      if (starts_with(to_upper(line), "VERSION:")) {
        std::string ver = trim(line.substr(8));
        if (ver == "4.0" || starts_with(ver, "4")) contact.version = 4;
        else contact.version = 3;
        break;
      }
    }

    // Parse all fields
    for (const auto& line : clean_lines) {
      parse_vcard_field(line, contact);
    }

    // Build full name from components if not set
    if (contact.full_name.empty()) {
      contact.full_name = build_full_name(contact);
    }

    return contact;
  }

  // Parse a single vCard field line
  void parse_vcard_field(const std::string& line, VCardContact& contact) {
    auto colon = line.find(':');
    if (colon == std::string::npos) return;

    std::string field_name = line.substr(0, colon);
    std::string value = line.substr(colon + 1);

    // Parse parameters from field name
    std::string field_key;
    auto semi = field_name.find(';');
    if (semi != std::string::npos) {
      field_key = field_name.substr(0, semi);
    } else {
      field_key = field_name;
    }
    field_key = to_upper(field_key);

    // Extract TYPE parameter
    auto type_param = parse_vcard_param(field_name, "TYPE");
    if (type_param.empty()) type_param = parse_vcard_param(field_name, "type");

    // Unescape value
    value = unescape_vcard_field(value);

    // Dispatch by field type
    if (field_key == "FN" || field_key == "FULLNAME") {
      contact.full_name = trim(value);
    } else if (field_key == "N") {
      parse_vcard_n_field(value, contact);
    } else if (field_key == "NICKNAME") {
      contact.nickname = trim(value);
    } else if (field_key == "ORG") {
      parse_vcard_org_field(value, contact);
    } else if (field_key == "TITLE") {
      contact.title = trim(value);
    } else if (field_key == "ROLE") {
      contact.role = trim(value);
    } else if (field_key == "EMAIL") {
      VCardContact::Email email;
      email.addr = trim(value);
      email.type = to_upper(type_param);
      contact.emails.push_back(email);
    } else if (field_key == "TEL" || field_key == "PHONE") {
      VCardContact::Phone phone;
      phone.number = trim(value);
      phone.type = to_upper(type_param);
      if (phone.type.empty()) phone.type = "VOICE";
      contact.phones.push_back(phone);
    } else if (field_key == "ADR" || field_key == "ADDRESS") {
      auto addr = parse_vcard_adr_field(value);
      addr.type = to_upper(type_param);
      contact.addresses.push_back(addr);
    } else if (field_key == "PHOTO") {
      auto photo = parse_vcard_photo_field(value, field_name);
      contact.photos.push_back(photo);
    } else if (field_key == "BDAY" || field_key == "BIRTHDAY") {
      auto date = parse_vcard_date_field(value);
      date.type = "BIRTHDAY";
      contact.dates.push_back(date);
    } else if (field_key == "ANNIVERSARY") {
      auto date = parse_vcard_date_field(value);
      date.type = "ANNIVERSARY";
      contact.dates.push_back(date);
    } else if (field_key == "NOTE") {
      contact.notes = trim(value);
    } else if (field_key == "URL") {
      contact.url = trim(value);
    } else if (field_key == "CATEGORIES" || field_key == "CATEGORY") {
      auto cats = split(value, ',');
      for (auto& c : cats) {
        std::string cat = trim(c);
        if (!cat.empty()) contact.categories.push_back(cat);
      }
    } else if (field_key == "UID") {
      contact.uid = trim(value);
    } else if (field_key == "REV") {
      contact.rev = trim(value);
      contact.revision_time = parse_vcard_timestamp(value);
    } else if (field_key == "PRODID") {
      contact.prodid = trim(value);
    } else if (field_key == "SOURCE") {
      contact.source = trim(value);
    } else if (field_key == "X-SOCIALPROFILE" || field_key == "IMPP") {
      // Skip instant messaging for now
    } else if (starts_with(field_key, "X-")) {
      // Custom extended fields: store if needed
    }
  }

  // Parse N (name) field: "LastName;FirstName;MiddleName;Prefix;Suffix"
  void parse_vcard_n_field(const std::string& value, VCardContact& contact) {
    auto parts = split(value, ';');
    if (parts.size() > 0) contact.family_name = trim(parts[0]);
    if (parts.size() > 1) contact.given_name = trim(parts[1]);
    if (parts.size() > 2) contact.middle_name = trim(parts[2]);
    if (parts.size() > 3) contact.name_prefix = trim(parts[3]);
    if (parts.size() > 4) contact.name_suffix = trim(parts[4]);
  }

  // Parse ORG field: "Organization;Department"
  void parse_vcard_org_field(const std::string& value, VCardContact& contact) {
    auto parts = split(value, ';');
    if (parts.size() > 0) contact.organization = trim(parts[0]);
    if (parts.size() > 1) contact.department = trim(parts[1]);
  }

  // Parse ADR field: "PO Box;Extended;Street;City;Region;Postal;Country"
  VCardContact::Address parse_vcard_adr_field(const std::string& value) {
    VCardContact::Address addr;
    auto parts = split(value, ';');
    if (parts.size() > 0) addr.po_box = trim(parts[0]);
    if (parts.size() > 1) addr.extended = trim(parts[1]);
    if (parts.size() > 2) addr.street = trim(parts[2]);
    if (parts.size() > 3) addr.city = trim(parts[3]);
    if (parts.size() > 4) addr.region = trim(parts[4]);
    if (parts.size() > 5) addr.postal_code = trim(parts[5]);
    if (parts.size() > 6) addr.country = trim(parts[6]);
    return addr;
  }

  // Parse PHOTO field
  VCardContact::Photo parse_vcard_photo_field(const std::string& value,
                                                const std::string& field_name) {
    VCardContact::Photo photo;
    auto encoding = to_upper(parse_vcard_param(field_name, "ENCODING"));
    auto mime = parse_vcard_param(field_name, "MEDIATYPE");
    if (mime.empty()) mime = parse_vcard_param(field_name, "TYPE");

    if (encoding == "BASE64" || encoding == "B") {
      photo.data = base64_decode(trim(value));
      photo.mime_type = mime.empty() ? "image/jpeg" : mime;
    } else if (starts_with(to_upper(trim(value)), "HTTP")) {
      photo.uri = trim(value);
    } else {
      // Assume binary/base64 data
      photo.data = value;
      photo.mime_type = mime.empty() ? "image/jpeg" : mime;
    }

    return photo;
  }

  // Parse a date field (BDAY, ANNIVERSARY)
  VCardContact::Date parse_vcard_date_field(const std::string& value) {
    VCardContact::Date date;
    std::string v = trim(value);

    // Handle value=date: or value=date-time: prefix in vCard 4
    if (starts_with(v, "date:")) v = v.substr(5);
    else if (starts_with(v, "date-time:")) v = v.substr(10);
    else if (starts_with(v, "text:")) v = v.substr(5);

    // Parse formats: YYYYMMDD, YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS
    if (v.size() >= 8 && std::isdigit(v[0])) {
      if (v[4] == '-') {
        // ISO format
        date.year = std::stoi(v.substr(0, 4));
        if (v.size() >= 7) date.month = std::stoi(v.substr(5, 2));
        if (v.size() >= 10) date.day = std::stoi(v.substr(8, 2));
      } else {
        // Compact format
        date.year = std::stoi(v.substr(0, 4));
        if (v.size() >= 6) date.month = std::stoi(v.substr(4, 2));
        if (v.size() >= 8) date.day = std::stoi(v.substr(6, 2));
      }
    }

    return date;
  }

  // Parse vCard timestamp
  time_t parse_vcard_timestamp(const std::string& value) {
    return parse_date_iso8601(trim(value));
  }

  // Build full name from components
  std::string build_full_name(const VCardContact& contact) {
    std::string name;
    if (!contact.name_prefix.empty()) name += contact.name_prefix + " ";
    if (!contact.given_name.empty()) name += contact.given_name + " ";
    if (!contact.middle_name.empty()) name += contact.middle_name + " ";
    if (!contact.family_name.empty()) name += contact.family_name;
    if (!contact.name_suffix.empty()) name += " " + contact.name_suffix;
    name = trim(name);
    if (name.empty()) name = contact.nickname;
    if (name.empty() && !contact.emails.empty()) {
      name = extract_name_from_email(contact.emails[0].addr);
    }
    return name;
  }

private:
  int max_entries_{10000};
};

// ============================================================================
// vCard generator: Feature 3 (create vCard from contact data)
// ============================================================================
class VCardGenerator {
public:
  VCardGenerator() = default;

  // Generate a single vCard 3.0 string
  std::string generate_vcard3(const VCardContact& contact) {
    std::stringstream ss;

    ss << "BEGIN:VCARD\r\n";
    ss << "VERSION:3.0\r\n";
    if (!contact.prodid.empty())
      ss << "PRODID:" << escape_vcard_field(contact.prodid) << "\r\n";
    else
      ss << "PRODID:-//DeltaChat//AddressBook//EN\r\n";

    if (!contact.uid.empty())
      ss << "UID:" << escape_vcard_field(contact.uid) << "\r\n";

    // Full name
    if (!contact.full_name.empty())
      ss << "FN:" << escape_vcard_field(contact.full_name) << "\r\n";

    // Structured name
    ss << "N:" << escape_vcard_field(contact.family_name) << ";"
       << escape_vcard_field(contact.given_name) << ";"
       << escape_vcard_field(contact.middle_name) << ";"
       << escape_vcard_field(contact.name_prefix) << ";"
       << escape_vcard_field(contact.name_suffix) << "\r\n";

    if (!contact.nickname.empty())
      ss << "NICKNAME:" << escape_vcard_field(contact.nickname) << "\r\n";

    if (!contact.organization.empty()) {
      ss << "ORG:" << escape_vcard_field(contact.organization);
      if (!contact.department.empty())
        ss << ";" << escape_vcard_field(contact.department);
      ss << "\r\n";
    }

    if (!contact.title.empty())
      ss << "TITLE:" << escape_vcard_field(contact.title) << "\r\n";

    if (!contact.role.empty())
      ss << "ROLE:" << escape_vcard_field(contact.role) << "\r\n";

    // Emails
    for (const auto& email : contact.emails) {
      ss << "EMAIL";
      if (!email.type.empty()) ss << ";TYPE=" << email.type;
      ss << ":" << escape_vcard_field(email.addr) << "\r\n";
    }

    // Phones
    for (const auto& phone : contact.phones) {
      ss << "TEL";
      if (!phone.type.empty()) ss << ";TYPE=" << phone.type;
      ss << ":" << escape_vcard_field(phone.number) << "\r\n";
    }

    // Addresses
    for (const auto& addr : contact.addresses) {
      ss << "ADR";
      if (!addr.type.empty()) ss << ";TYPE=" << addr.type;
      ss << ":" << escape_vcard_field(addr.po_box) << ";"
         << escape_vcard_field(addr.extended) << ";"
         << escape_vcard_field(addr.street) << ";"
         << escape_vcard_field(addr.city) << ";"
         << escape_vcard_field(addr.region) << ";"
         << escape_vcard_field(addr.postal_code) << ";"
         << escape_vcard_field(addr.country) << "\r\n";
    }

    // Photos
    for (const auto& photo : contact.photos) {
      if (!photo.uri.empty()) {
        ss << "PHOTO;VALUE=URI:" << escape_vcard_field(photo.uri) << "\r\n";
      } else if (!photo.data.empty()) {
        std::string b64 = base64_encode(photo.data);
        ss << "PHOTO;ENCODING=BASE64";
        if (!photo.mime_type.empty())
          ss << ";TYPE=" << photo.mime_type;
        ss << ":" << fold_vcard_line(b64);
      }
    }

    // Dates
    for (const auto& date : contact.dates) {
      char buf[16];
      snprintf(buf, sizeof(buf), "%04d%02d%02d", date.year, date.month, date.day);
      if (date.type == "BIRTHDAY")
        ss << "BDAY:" << buf << "\r\n";
      else if (date.type == "ANNIVERSARY")
        ss << "ANNIVERSARY:" << buf << "\r\n";
    }

    if (!contact.notes.empty())
      ss << "NOTE:" << escape_vcard_field(contact.notes) << "\r\n";

    if (!contact.url.empty())
      ss << "URL:" << escape_vcard_field(contact.url) << "\r\n";

    // Categories
    if (!contact.categories.empty()) {
      ss << "CATEGORIES:";
      for (size_t i = 0; i < contact.categories.size(); ++i) {
        if (i > 0) ss << ",";
        ss << escape_vcard_field(contact.categories[i]);
      }
      ss << "\r\n";
    }

    if (!contact.rev.empty())
      ss << "REV:" << contact.rev << "\r\n";

    ss << "END:VCARD\r\n";
    return ss.str();
  }

  // Generate vCard 4.0 (RFC 6350)
  std::string generate_vcard4(const VCardContact& contact) {
    std::stringstream ss;

    ss << "BEGIN:VCARD\r\n";
    ss << "VERSION:4.0\r\n";
    if (!contact.prodid.empty())
      ss << "PRODID:" << escape_vcard_field(contact.prodid) << "\r\n";
    else
      ss << "PRODID:-//DeltaChat//AddressBook//EN\r\n";

    if (!contact.uid.empty())
      ss << "UID:" << escape_vcard_field(contact.uid) << "\r\n";

    // FN is required in vCard 4.0
    std::string fn = contact.full_name.empty()
        ? build_full_name_v4(contact) : contact.full_name;
    ss << "FN:" << escape_vcard_field(fn) << "\r\n";

    // Structured name
    ss << "N:" << escape_vcard_field(contact.family_name) << ";"
       << escape_vcard_field(contact.given_name) << ";"
       << escape_vcard_field(contact.middle_name) << ";"
       << escape_vcard_field(contact.name_prefix) << ";"
       << escape_vcard_field(contact.name_suffix) << "\r\n";

    if (!contact.nickname.empty())
      ss << "NICKNAME:" << escape_vcard_field(contact.nickname) << "\r\n";

    if (!contact.organization.empty())
      ss << "ORG:" << escape_vcard_field(contact.organization) << "\r\n";

    if (!contact.title.empty())
      ss << "TITLE:" << escape_vcard_field(contact.title) << "\r\n";

    if (!contact.role.empty())
      ss << "ROLE:" << escape_vcard_field(contact.role) << "\r\n";

    for (const auto& email : contact.emails) {
      ss << "EMAIL";
      if (!email.type.empty()) ss << ";TYPE=" << email.type;
      ss << ":" << escape_vcard_field(email.addr) << "\r\n";
    }

    for (const auto& phone : contact.phones) {
      ss << "TEL";
      if (!phone.type.empty()) ss << ";TYPE=" << phone.type;
      ss << ":" << escape_vcard_field(phone.number) << "\r\n";
    }

    for (const auto& addr : contact.addresses) {
      ss << "ADR";
      if (!addr.type.empty()) ss << ";TYPE=" << addr.type;
      ss << ";LABEL=\"" << escape_vcard_field(format_address_label(addr)) << "\"";
      ss << ":" << escape_vcard_field(addr.po_box) << ";"
         << escape_vcard_field(addr.extended) << ";"
         << escape_vcard_field(addr.street) << ";"
         << escape_vcard_field(addr.city) << ";"
         << escape_vcard_field(addr.region) << ";"
         << escape_vcard_field(addr.postal_code) << ";"
         << escape_vcard_field(addr.country) << "\r\n";
    }

    for (const auto& photo : contact.photos) {
      if (!photo.uri.empty()) {
        ss << "PHOTO;VALUE=URI:" << escape_vcard_field(photo.uri) << "\r\n";
      } else if (!photo.data.empty()) {
        ss << "PHOTO;MEDIATYPE=" << (photo.mime_type.empty() ? "image/jpeg" : photo.mime_type)
           << ";ENCODING=B:data:" << photo.mime_type << ";base64,"
           << base64_encode(photo.data) << "\r\n";
      }
    }

    for (const auto& date : contact.dates) {
      char buf[32];
      snprintf(buf, sizeof(buf), "%04d%02d%02d", date.year, date.month, date.day);
      std::string type = (date.type == "ANNIVERSARY") ? "ANNIVERSARY" : "BDAY";
      ss << type << ":date:" << buf << "\r\n";
    }

    if (!contact.notes.empty())
      ss << "NOTE:" << escape_vcard_field(contact.notes) << "\r\n";

    if (!contact.url.empty())
      ss << "URL:" << escape_vcard_field(contact.url) << "\r\n";

    if (!contact.categories.empty()) {
      ss << "CATEGORIES:";
      for (size_t i = 0; i < contact.categories.size(); ++i) {
        if (i > 0) ss << ",";
        ss << escape_vcard_field(contact.categories[i]);
      }
      ss << "\r\n";
    }

    if (!contact.rev.empty())
      ss << "REV:" << contact.rev << "\r\n";

    ss << "END:VCARD\r\n";
    return ss.str();
  }

  // Generate multiple vCards as one string
  std::string generate_vcards(const std::vector<VCardContact>& contacts, int version = 3) {
    std::stringstream ss;
    for (const auto& c : contacts) {
      if (version == 4)
        ss << generate_vcard4(c);
      else
        ss << generate_vcard3(c);
      ss << "\r\n";
    }
    return ss.str();
  }

private:
  std::string build_full_name_v4(const VCardContact& contact) {
    std::string name;
    if (!contact.name_prefix.empty()) name += contact.name_prefix + " ";
    if (!contact.given_name.empty()) name += contact.given_name + " ";
    if (!contact.family_name.empty()) name += contact.family_name;
    if (!contact.name_suffix.empty()) name += " " + contact.name_suffix;
    if (trim(name).empty() && !contact.emails.empty())
      name = extract_name_from_email(contact.emails[0].addr);
    return trim(name);
  }

  std::string format_address_label(const VCardContact::Address& addr) {
    std::string label;
    if (!addr.street.empty()) label += addr.street + "\n";
    if (!addr.extended.empty()) label += addr.extended + "\n";
    if (!addr.city.empty()) label += addr.city;
    if (!addr.region.empty()) label += ", " + addr.region;
    if (!addr.postal_code.empty()) label += " " + addr.postal_code;
    if (!addr.country.empty()) label += "\n" + addr.country;
    return label;
  }
};

// ============================================================================
// vCard to AddressBookEntry conversion
// ============================================================================
static AddressBookEntry vcard_to_entry(const VCardContact& vcard) {
  AddressBookEntry entry;
  entry.display_name = vcard.full_name;
  entry.first_name = vcard.given_name;
  entry.last_name = vcard.family_name;
  entry.nickname = vcard.nickname;
  entry.organization = vcard.organization;
  entry.title = vcard.title;
  entry.system_id = vcard.uid.empty() ? sha256(vcard.full_name + vcard.organization) : vcard.uid;

  for (const auto& e : vcard.emails) {
    entry.emails.push_back(e.addr);
    entry.email_labels.push_back(e.type.empty() ? "OTHER" : e.type);
  }

  for (const auto& p : vcard.phones) {
    entry.phone_numbers.push_back(p.number);
    entry.phone_labels.push_back(p.type.empty() ? "VOICE" : p.type);
  }

  for (const auto& a : vcard.addresses) {
    std::string formatted = a.street + "\n" + a.city + ", " + a.region + " " + a.postal_code;
    entry.addresses.push_back(trim(formatted));
    entry.address_labels.push_back(a.type.empty() ? "HOME" : a.type);
  }

  for (const auto& p : vcard.photos) {
    if (!p.data.empty()) {
      entry.photo_data = base64_encode(p.data);
      entry.photo_mime_type = p.mime_type;
      break;
    }
  }

  for (const auto& d : vcard.dates) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d", d.year, d.month, d.day);
    if (d.type == "BIRTHDAY") entry.birthday = buf;
    else if (d.type == "ANNIVERSARY") entry.anniversary = buf;
  }

  entry.notes = vcard.notes;
  entry.url = vcard.url;
  entry.group_labels = vcard.categories;

  return entry;
}

// ============================================================================
// Contact import from address book: Feature 4
// ============================================================================
DeltaChat::AddressBookImportResult DeltaChat::import_from_address_book(
    const std::vector<AddressBookEntry>& entries,
    const ImportOptions& options) {

  AddressBookImportResult result;
  result.start_time = nms();

  // Build lookup maps for existing contacts
  std::unordered_map<std::string, uint32_t> email_to_id;
  std::unordered_map<std::string, uint32_t> phone_to_id;
  std::unordered_map<std::string, uint32_t> name_to_id;

  for (const auto& [id, c] : contacts_) {
    if (!c.addr.empty()) {
      email_to_id[normalize_email(c.addr)] = id;
    }
  }
  for (const auto& [id, c] : contacts_) {
    if (!c.name.empty()) {
      name_to_id[levenshtein_normalize(c.name)] = id;
    }
  }

  for (const auto& entry : entries) {
    if (result.total_processed >= options.max_contacts) break;

    // Skip entries without any identifiable info
    if (entry.emails.empty() && entry.phone_numbers.empty() &&
        entry.display_name.empty()) {
      result.total_skipped++;
      continue;
    }

    uint32_t matched_id = 0;
    std::string match_type;

    // Try to find existing contact
    for (const auto& email : entry.emails) {
      auto norm = normalize_email(email);
      if (email_to_id.count(norm)) {
        matched_id = email_to_id[norm];
        match_type = "email:" + email;
        break;
      }
    }

    if (!matched_id && !entry.phone_numbers.empty()) {
      for (const auto& phone : entry.phone_numbers) {
        auto norm = normalize_phone(phone);
        if (phone_to_id.count(norm)) {
          matched_id = phone_to_id[norm];
          match_type = "phone:" + phone;
          break;
        }
      }
    }

    if (!matched_id && !entry.display_name.empty()) {
      auto norm_name = levenshtein_normalize(entry.display_name);
      auto it = name_to_id.find(norm_name);
      if (it != name_to_id.end() && options.merge_by_name) {
        // Verify with fuzzy threshold
        int dist = levenshtein_distance(norm_name,
            levenshtein_normalize(contacts_[it->second].name));
        double max_len = std::max(norm_name.size(),
            levenshtein_normalize(contacts_[it->second].name).size());
        if (max_len > 0 && (1.0 - dist / max_len) >= options.name_match_threshold) {
          matched_id = it->second;
          match_type = "name:" + entry.display_name;
        }
      }
    }

    if (matched_id > 0) {
      // Update existing contact
      if (options.update_existing) {
        update_contact_from_entry(matched_id, entry, options.overwrite_fields);
        result.total_updated++;
        result.updated_ids.push_back(matched_id);
      } else {
        result.total_skipped++;
      }
    } else {
      // Create new contact
      uint32_t new_id = create_contact_from_entry(entry);
      if (new_id > 0) {
        result.total_imported++;
        result.imported_ids.push_back(new_id);

        // Update lookup maps
        for (const auto& email : entry.emails) {
          email_to_id[normalize_email(email)] = new_id;
        }
        if (!entry.display_name.empty()) {
          name_to_id[levenshtein_normalize(entry.display_name)] = new_id;
        }
      } else {
        result.total_errors++;
        result.errors.push_back("Failed to create contact: " + entry.display_name);
      }
    }

    result.total_processed++;
  }

  result.end_time = nms();
  result.duration_ms = result.end_time - result.start_time;
  return result;
}

// ============================================================================
// Create contact from address book entry
// ============================================================================
uint32_t DeltaChat::create_contact_from_entry(const AddressBookEntry& entry) {
  uint32_t id = gen_id();

  DcContact contact;
  contact.id = id;
  contact.name = entry.display_name;
  if (contact.name.empty() && !entry.first_name.empty()) {
    contact.name = entry.first_name + " " + entry.last_name;
    contact.name = trim(contact.name);
  }
  if (contact.name.empty() && !entry.emails.empty()) {
    contact.name = extract_name_from_email(entry.emails[0]);
  }

  // Set primary email
  if (!entry.emails.empty()) {
    contact.addr = entry.emails[0];
  }

  contact.display_name = contact.name;
  contact.color = generate_avatar_color(contact.addr.empty() ? contact.name : contact.addr);
  contact.last_seen = nms();

  // Handle photo
  if (!entry.photo_data.empty()) {
    contact.profile_image = entry.photo_data; // base64 encoded
    // In production, would save to blobdir and set profile_image path
  }

  contacts_[id] = contact;

  // Store extended contact info
  ContactExtended ext;
  ext.id = id;
  ext.nickname = entry.nickname;
  ext.organization = entry.organization;
  ext.title = entry.title;
  ext.phone_number = entry.phone_numbers.empty() ? "" : entry.phone_numbers[0];
  ext.source = "addressbook";
  ext.added_at = nms();
  ext.group_tags = entry.group_labels;
  contact_extended_[id] = ext;

  return id;
}

// ============================================================================
// Update existing contact from address book entry
// ============================================================================
void DeltaChat::update_contact_from_entry(uint32_t contact_id,
                                           const AddressBookEntry& entry,
                                           const OverwriteFields& fields) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return;

  DcContact& c = it->second;

  if (fields.name) {
    if (!entry.display_name.empty()) {
      c.name = entry.display_name;
      c.display_name = entry.display_name;
    }
  }

  if (fields.email && !entry.emails.empty()) {
    c.addr = entry.emails[0];
  }

  if (fields.photo && !entry.photo_data.empty()) {
    c.profile_image = entry.photo_data;
  }

  // Update extended info
  auto ext_it = contact_extended_.find(contact_id);
  if (ext_it != contact_extended_.end()) {
    ContactExtended& ext = ext_it->second;
    if (fields.organization) ext.organization = entry.organization;
    if (fields.title) ext.title = entry.title;
    if (fields.nickname) ext.nickname = entry.nickname;
    if (fields.phone && !entry.phone_numbers.empty())
      ext.phone_number = entry.phone_numbers[0];
    if (fields.tags) ext.group_tags = entry.group_labels;
  }
}

// ============================================================================
// AddressBookEntry to DcContact conversion helper
// ============================================================================
DcContact DeltaChat::addressbook_entry_to_dc_contact(const AddressBookEntry& entry) {
  DcContact c;
  c.name = entry.display_name;
  c.display_name = entry.display_name;
  c.addr = entry.emails.empty() ? "" : entry.emails[0];
  c.color = generate_avatar_color(c.addr.empty() ? c.name : c.addr);
  if (!entry.photo_data.empty()) c.profile_image = entry.photo_data;
  return c;
}

// ============================================================================
// Contact merge/deduplication: Feature 5 (merge by email, phone, name)
// ============================================================================
std::vector<ContactMergeCandidate> DeltaChat::find_merge_candidates(
    double threshold) {

  std::vector<ContactMergeCandidate> candidates;
  std::vector<uint32_t> contact_ids;
  for (const auto& [id, c] : contacts_) {
    contact_ids.push_back(id);
  }

  for (size_t i = 0; i < contact_ids.size(); ++i) {
    for (size_t j = i + 1; j < contact_ids.size(); ++j) {
      uint32_t id_a = contact_ids[i];
      uint32_t id_b = contact_ids[j];

      const auto& ca = contacts_[id_a];
      const auto& cb = contacts_[id_b];

      ContactMergeCandidate candidate;
      candidate.contact_a = id_a;
      candidate.contact_b = id_b;
      candidate.confidence = compute_merge_confidence(id_a, id_b);
      candidate.match_reason = compute_merge_reason(id_a, id_b);
      candidate.auto_merge = candidate.confidence >= 0.95;

      if (candidate.confidence >= threshold) {
        candidates.push_back(candidate);
      }
    }
  }

  // Sort by confidence descending
  std::sort(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) {
              return a.confidence > b.confidence;
            });

  return candidates;
}

double DeltaChat::compute_merge_confidence(uint32_t id_a, uint32_t id_b) {
  const auto& ca = contacts_[id_a];
  const auto& cb = contacts_[id_b];

  double score = 0.0;
  int factors = 0;

  // Factor 1: Same normalized email (high confidence)
  std::string email_a = normalize_email(ca.addr);
  std::string email_b = normalize_email(cb.addr);
  if (!email_a.empty() && !email_b.empty() && email_a == email_b) {
    score += 0.90;
    factors++;
  }

  // Factor 2: Same phone number
  auto ext_a = contact_extended_.find(id_a);
  auto ext_b = contact_extended_.find(id_b);
  if (ext_a != contact_extended_.end() && ext_b != contact_extended_.end()) {
    std::string phone_a = normalize_phone(ext_a->second.phone_number);
    std::string phone_b = normalize_phone(ext_b->second.phone_number);
    if (!phone_a.empty() && !phone_b.empty() && phone_a == phone_b) {
      score += 0.85;
      factors++;
    }
  }

  // Factor 3: Similar name
  std::string name_a = levenshtein_normalize(ca.name);
  std::string name_b = levenshtein_normalize(cb.name);
  if (!name_a.empty() && !name_b.empty()) {
    int dist = levenshtein_distance(name_a, name_b);
    double max_len = std::max(name_a.size(), name_b.size());
    if (max_len > 0) {
      double name_sim = 1.0 - (double)dist / max_len;
      if (name_sim > 0.6) {
        score += name_sim * 0.5;
        factors++;
      }
    }
  }

  // Factor 4: Same organization
  if (ext_a != contact_extended_.end() && ext_b != contact_extended_.end()) {
    std::string org_a = levenshtein_normalize(ext_a->second.organization);
    std::string org_b = levenshtein_normalize(ext_b->second.organization);
    if (!org_a.empty() && !org_b.empty() && org_a == org_b) {
      score += 0.30;
      factors++;
    }
  }

  if (factors == 0) return 0.0;
  return score / factors;
}

std::string DeltaChat::compute_merge_reason(uint32_t id_a, uint32_t id_b) {
  const auto& ca = contacts_[id_a];
  const auto& cb = contacts_[id_b];

  std::vector<std::string> reasons;

  if (!ca.addr.empty() && !cb.addr.empty() &&
      normalize_email(ca.addr) == normalize_email(cb.addr)) {
    reasons.push_back("same email");
  }

  auto ext_a = contact_extended_.find(id_a);
  auto ext_b = contact_extended_.find(id_b);
  if (ext_a != contact_extended_.end() && ext_b != contact_extended_.end()) {
    if (!ext_a->second.phone_number.empty() &&
        !ext_b->second.phone_number.empty() &&
        normalize_phone(ext_a->second.phone_number) == normalize_phone(ext_b->second.phone_number)) {
      reasons.push_back("same phone");
    }
  }

  std::string name_a = levenshtein_normalize(ca.name);
  std::string name_b = levenshtein_normalize(cb.name);
  if (!name_a.empty() && !name_b.empty()) {
    int dist = levenshtein_distance(name_a, name_b);
    double max_len = std::max(name_a.size(), name_b.size());
    if (max_len > 0 && (1.0 - dist / max_len) > 0.8) {
      reasons.push_back("similar name");
    }
  }

  if (reasons.empty()) reasons.push_back("unknown");
  return join(reasons, ", ");
}

uint32_t DeltaChat::merge_contacts(uint32_t id_a, uint32_t id_b) {
  auto it_a = contacts_.find(id_a);
  auto it_b = contacts_.find(id_b);
  if (it_a == contacts_.end() || it_b == contacts_.end()) return 0;

  DcContact& keep = it_a->second;
  DcContact& discard = it_b->second;

  // Keep the longer name
  if (discard.name.size() > keep.name.size()) {
    keep.name = discard.name;
  }
  if (discard.display_name.size() > keep.display_name.size()) {
    keep.display_name = discard.display_name;
  }

  // Keep the better email
  if (keep.addr.empty() && !discard.addr.empty()) {
    keep.addr = discard.addr;
  }

  // Keep profile image if keeping contact doesn't have one
  if (keep.profile_image.empty() && !discard.profile_image.empty()) {
    keep.profile_image = discard.profile_image;
  }

  // Merge extended info
  auto ext_a = contact_extended_.find(id_a);
  auto ext_b = contact_extended_.find(id_b);

  if (ext_a != contact_extended_.end() && ext_b != contact_extended_.end()) {
    ContactExtended& ea = ext_a->second;
    ContactExtended& eb = ext_b->second;

    if (ea.phone_number.empty()) ea.phone_number = eb.phone_number;
    if (ea.organization.empty()) ea.organization = eb.organization;
    if (ea.title.empty()) ea.title = eb.title;
    if (ea.nickname.empty()) ea.nickname = eb.nickname;

    // Merge group tags
    for (const auto& tag : eb.group_tags) {
      if (std::find(ea.group_tags.begin(), ea.group_tags.end(), tag) ==
          ea.group_tags.end()) {
        ea.group_tags.push_back(tag);
      }
    }

    // Use earliest added_at
    if (eb.added_at > 0 && (ea.added_at == 0 || eb.added_at < ea.added_at)) {
      ea.added_at = eb.added_at;
    }

    // Accumulate interaction count
    ea.interaction_count += eb.interaction_count;
    ea.last_interaction = std::max(ea.last_interaction, eb.last_interaction);
  }

  // Remove the discarded contact
  contacts_.erase(it_b);
  contact_extended_.erase(id_b);

  return id_a;
}

// ============================================================================
// Feature 6: Contact field extraction (name, email, phone, address, org, photo)
// ============================================================================
DeltaChat::ExtractedContactFields DeltaChat::extract_contact_fields(
    const VCardContact& vcard) {

  ExtractedContactFields fields;

  // Extract names
  fields.full_name = vcard.full_name;
  fields.first_name = vcard.given_name;
  fields.last_name = vcard.family_name;
  fields.middle_name = vcard.middle_name;
  fields.name_prefix = vcard.name_prefix;
  fields.name_suffix = vcard.name_suffix;
  fields.nickname = vcard.nickname;

  // Extract emails
  for (const auto& e : vcard.emails) {
    fields.emails.push_back({e.addr, e.type});
  }

  // Extract phones
  for (const auto& p : vcard.phones) {
    fields.phone_numbers.push_back({p.number, p.type});
  }

  // Extract addresses
  for (const auto& a : vcard.addresses) {
    ContactAddress addr;
    addr.street = a.street;
    addr.city = a.city;
    addr.region = a.region;
    addr.postal_code = a.postal_code;
    addr.country = a.country;
    addr.po_box = a.po_box;
    addr.extended = a.extended;
    addr.type = a.type;
    addr.formatted = format_address_single(a);
    fields.addresses.push_back(addr);
  }

  // Extract organization
  fields.organization = vcard.organization;
  fields.department = vcard.department;
  fields.title = vcard.title;
  fields.role = vcard.role;

  // Extract photos
  for (const auto& p : vcard.photos) {
    ContactPhoto photo;
    photo.data = p.data;
    photo.mime_type = p.mime_type;
    photo.uri = p.uri;
    fields.photos.push_back(photo);
  }

  // Extract dates
  for (const auto& d : vcard.dates) {
    ContactDate date;
    date.year = d.year;
    date.month = d.month;
    date.day = d.day;
    date.type = d.type;
    fields.dates.push_back(date);
  }

  // Extract other fields
  fields.notes = vcard.notes;
  fields.url = vcard.url;
  fields.uid = vcard.uid;
  fields.categories = vcard.categories;

  return fields;
}

std::string DeltaChat::format_address_single(const VCardContact::Address& addr) {
  std::string result;
  if (!addr.street.empty()) result += addr.street;
  if (!addr.extended.empty()) {
    if (!result.empty()) result += "\n";
    result += addr.extended;
  }
  if (!addr.city.empty()) {
    if (!result.empty()) result += "\n";
    result += addr.city;
    if (!addr.region.empty()) result += ", " + addr.region;
    if (!addr.postal_code.empty()) result += " " + addr.postal_code;
  }
  if (!addr.country.empty()) {
    if (!result.empty()) result += "\n";
    result += addr.country;
  }
  return result;
}

// ============================================================================
// Feature 7: Address book change detection (detect new/modified/deleted)
// ============================================================================
DeltaChat::AddressBookChanges DeltaChat::detect_changes(
    const std::vector<AddressBookEntry>& current_entries,
    const AddressBookSnapshot& previous_snapshot) {

  AddressBookChanges changes;
  int64_t now = nms();

  // Build maps for quick lookup
  std::unordered_map<std::string, AddressBookEntry> current_map;
  for (const auto& e : current_entries) {
    current_map[e.system_id] = e;
  }

  // Find new and modified entries
  for (const auto& [sys_id, entry] : current_map) {
    auto prev = previous_snapshot.entries.find(sys_id);
    if (prev == previous_snapshot.entries.end()) {
      // New entry
      changes.added.push_back(entry);
    } else {
      // Check if modified
      std::string current_hash = compute_entry_hash(entry);
      std::string prev_hash = compute_entry_hash(prev->second);
      if (current_hash != prev_hash) {
        changes.modified.push_back({prev->second, entry});
      }
      changes.unchanged.push_back(entry);
    }
  }

  // Find deleted entries
  for (const auto& [sys_id, entry] : previous_snapshot.entries) {
    if (current_map.find(sys_id) == current_map.end()) {
      changes.deleted.push_back(entry);
    }
  }

  changes.detection_time = now;
  return changes;
}

std::string DeltaChat::compute_entry_hash(const AddressBookEntry& entry) {
  std::stringstream ss;
  ss << entry.display_name << "|"
     << entry.first_name << "|"
     << entry.last_name << "|"
     << entry.nickname << "|"
     << entry.organization << "|"
     << entry.title << "|"
     << join(entry.emails, ",") << "|"
     << join(entry.phone_numbers, ",") << "|"
     << join(entry.addresses, "|") << "|"
     << entry.notes << "|"
     << entry.modified_at;
  return sha256(ss.str());
}

AddressBookSnapshot DeltaChat::create_snapshot(
    const std::vector<AddressBookEntry>& entries) {
  AddressBookSnapshot snapshot;
  snapshot.snapshot_time = nms();
  for (const auto& e : entries) {
    snapshot.entries[e.system_id] = e;
  }
  snapshot.snapshot_hash = sha256(std::to_string(snapshot.snapshot_time));
  return snapshot;
}

// ============================================================================
// Feature 8: Address book periodic sync
// ============================================================================
DeltaChat::SyncResult DeltaChat::sync_address_book(const SyncOptions& options) {
  SyncResult result;
  result.start_time = nms();

  if (sync_state_.is_running) {
    result.status = "already_running";
    result.message = "Sync already in progress";
    return result;
  }

  sync_state_.is_running = true;

  try {
    // Step 1: Scan current address book
    auto current_entries = scan_address_book_contents(options.source_path);

    // Step 2: Create snapshot if no previous exists
    if (previous_snapshot_.entries.empty()) {
      previous_snapshot_ = create_snapshot(current_entries);
      sync_state_.total_contacts_in_source = current_entries.size();
      sync_state_.needs_full_rescan = false;
    }

    // Step 3: Detect changes
    auto changes = detect_changes(current_entries, previous_snapshot_);

    // Step 4: Process additions
    if (!changes.added.empty()) {
      ImportOptions import_opts;
      import_opts.update_existing = options.update_existing;
      import_opts.overwrite_fields = options.overwrite_fields;
      import_opts.max_contacts = options.max_contacts_per_sync;

      auto import_result = import_from_address_book(changes.added, import_opts);
      result.contacts_added = import_result.total_imported;
      result.contacts_updated = import_result.total_updated;
      result.errors.insert(result.errors.end(),
                           import_result.errors.begin(),
                           import_result.errors.end());
    }

    // Step 5: Process modifications
    if (!changes.modified.empty()) {
      for (const auto& [old_entry, new_entry] : changes.modified) {
        // Find the corresponding contact and update it
        std::string norm_email = new_entry.emails.empty() ? "" : normalize_email(new_entry.emails[0]);
        uint32_t found_id = 0;

        if (!norm_email.empty()) {
          for (const auto& [id, c] : contacts_) {
            if (normalize_email(c.addr) == norm_email) {
              found_id = id;
              break;
            }
          }
        }

        if (found_id > 0 && options.update_existing) {
          update_contact_from_entry(found_id, new_entry, options.overwrite_fields);
          result.contacts_updated++;
        }
      }
    }

    // Step 6: Process deletions
    if (!changes.deleted.empty() && options.handle_deletions) {
      for (const auto& entry : changes.deleted) {
        for (auto it = contacts_.begin(); it != contacts_.end(); ++it) {
          if (!it->second.addr.empty() && !entry.emails.empty() &&
              normalize_email(it->second.addr) == normalize_email(entry.emails[0])) {
            // Mark as deleted or remove depending on options
            if (options.delete_orphaned_contacts) {
              contacts_.erase(it);
              result.contacts_deleted++;
            }
            break;
          }
        }
      }
    }

    // Step 7: Update snapshot
    previous_snapshot_ = create_snapshot(current_entries);
    sync_state_.last_sync_time = nms();
    sync_state_.total_contacts_in_source = current_entries.size();
    sync_state_.contacts_added += result.contacts_added;
    sync_state_.contacts_updated += result.contacts_updated;
    sync_state_.contacts_deleted += result.contacts_deleted;
    sync_state_.consecutive_errors = 0;

    result.status = "success";
    result.message = "Sync completed successfully";
  } catch (const std::exception& e) {
    result.status = "error";
    result.message = std::string("Sync error: ") + e.what();
    result.errors.push_back(e.what());
    sync_state_.last_error = e.what();
    sync_state_.consecutive_errors++;
  }

  result.end_time = nms();
  result.duration_ms = result.end_time - result.start_time;
  sync_state_.is_running = false;
  sync_state_.needs_full_rescan = result.contacts_added > 100;

  return result;
}

void DeltaChat::schedule_next_sync(int interval_seconds) {
  sync_state_.sync_interval_seconds = interval_seconds;
  sync_state_.next_sync_time = nms() + (int64_t)interval_seconds * 1000;
}

bool DeltaChat::is_sync_due() {
  if (sync_state_.next_sync_time == 0) return true;
  return nms() >= sync_state_.next_sync_time;
}

std::vector<AddressBookEntry> DeltaChat::scan_address_book_contents(
    const std::string& source_path) {
  // Use the global scanner
  AddressBookScanner::ScannerConfig cfg;
  cfg.vcf_directory = source_path;
  g_address_book_scanner.configure(cfg);
  return g_address_book_scanner.scan_all();
}

// ============================================================================
// Feature 9: Contact photo extraction from vCard
// ============================================================================
DeltaChat::ContactPhoto DeltaChat::extract_photo_from_vcard(const VCardContact& vcard) {
  ContactPhoto photo;

  for (const auto& p : vcard.photos) {
    if (!p.data.empty()) {
      photo.data = p.data;
      photo.mime_type = p.mime_type.empty() ? "image/jpeg" : p.mime_type;
      return photo;
    }
    if (!p.uri.empty()) {
      photo.uri = p.uri;
      return photo;
    }
  }

  return photo;
}

std::vector<DeltaChat::ContactPhoto> DeltaChat::extract_all_photos_from_vcard(
    const VCardContact& vcard) {
  std::vector<ContactPhoto> photos;

  for (const auto& p : vcard.photos) {
    ContactPhoto photo;
    photo.data = p.data;
    photo.mime_type = p.mime_type;
    photo.uri = p.uri;
    photos.push_back(photo);
  }

  return photos;
}

bool DeltaChat::save_contact_photo(uint32_t contact_id,
                                    const std::string& photo_data,
                                    const std::string& mime_type) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return false;

  // Determine file extension from MIME type
  std::string ext = ".jpg";
  if (mime_type == "image/png") ext = ".png";
  else if (mime_type == "image/gif") ext = ".gif";
  else if (mime_type == "image/webp") ext = ".webp";
  else if (mime_type == "image/bmp") ext = ".bmp";

  // Save to blobdir
  std::string blobdir = config_.dbfile;
  auto last_slash = blobdir.find_last_of("/\\");
  if (last_slash != std::string::npos) blobdir = blobdir.substr(0, last_slash);
  blobdir += "/blobs/";

  std::string filename = blobdir + "contact_" + std::to_string(contact_id) + ext;

  // Write file
  std::ofstream out(filename, std::ios::binary);
  if (!out) return false;
  out.write(photo_data.data(), photo_data.size());
  out.close();

  it->second.profile_image = filename;

  // Update cache info
  auto ext_it = contact_extended_.find(contact_id);
  if (ext_it != contact_extended_.end()) {
    ext_it->second.avatar_cache_path = filename;
    ext_it->second.avatar_cache_time = nms();
  }

  return true;
}

// ============================================================================
// Feature 10: Contact group/label import
// ============================================================================
DeltaChat::GroupImportResult DeltaChat::import_contact_groups(
    const std::vector<AddressBookEntry>& entries) {

  GroupImportResult result;

  // Build map of group name -> list of entries
  std::map<std::string, std::vector<AddressBookEntry>> groups;

  for (const auto& entry : entries) {
    if (entry.group_labels.empty()) {
      // Put unlabeled contacts in "Imported" group
      groups["Imported"].push_back(entry);
    } else {
      for (const auto& label : entry.group_labels) {
        if (!label.empty()) {
          groups[label].push_back(entry);
        }
      }
    }
  }

  // Create or update groups
  for (auto& [group_name, group_entries] : groups) {
    FavoriteGroup group;
    group.group_name = group_name;
    group.created_at = nms();
    group.modified_at = nms();

    for (const auto& entry : group_entries) {
      // Find or create contact for this entry
      uint32_t contact_id = 0;
      if (!entry.emails.empty()) {
        std::string norm = normalize_email(entry.emails[0]);
        for (const auto& [id, c] : contacts_) {
          if (normalize_email(c.addr) == norm) {
            contact_id = id;
            break;
          }
        }
      }

      if (contact_id == 0) {
        // Try to create
        contact_id = create_contact_from_entry(entry);
        if (contact_id > 0) result.contacts_created++;
      }

      if (contact_id > 0) {
        group.contact_ids.push_back(contact_id);
        result.contacts_assigned++;
      }
    }

    // Add group tags to contacts
    for (auto cid : group.contact_ids) {
      auto ext_it = contact_extended_.find(cid);
      if (ext_it != contact_extended_.end()) {
        if (std::find(ext_it->second.group_tags.begin(),
                      ext_it->second.group_tags.end(),
                      group_name) == ext_it->second.group_tags.end()) {
          ext_it->second.group_tags.push_back(group_name);
        }
      }
    }

    favorite_groups_[group_name] = group;
    result.groups_created++;
  }

  return result;
}

std::vector<std::string> DeltaChat::get_contact_group_labels(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it != contact_extended_.end()) {
    return it->second.group_tags;
  }
  return {};
}

bool DeltaChat::add_contact_to_group(uint32_t contact_id,
                                      const std::string& group_name) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) return false;

  auto& tags = it->second.group_tags;
  if (std::find(tags.begin(), tags.end(), group_name) == tags.end()) {
    tags.push_back(group_name);
  }

  // Update favorite group
  if (favorite_groups_.count(group_name)) {
    auto& group = favorite_groups_[group_name];
    if (std::find(group.contact_ids.begin(), group.contact_ids.end(), contact_id) ==
        group.contact_ids.end()) {
      group.contact_ids.push_back(contact_id);
      group.modified_at = nms();
    }
  }

  return true;
}

bool DeltaChat::remove_contact_from_group(uint32_t contact_id,
                                           const std::string& group_name) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) return false;

  auto& tags = it->second.group_tags;
  tags.erase(std::remove(tags.begin(), tags.end(), group_name), tags.end());

  if (favorite_groups_.count(group_name)) {
    auto& group = favorite_groups_[group_name];
    group.contact_ids.erase(
        std::remove(group.contact_ids.begin(), group.contact_ids.end(), contact_id),
        group.contact_ids.end());
    group.modified_at = nms();
  }

  return true;
}

// ============================================================================
// Feature 11: Contact export as vCard file
// ============================================================================
std::string DeltaChat::export_contacts_vcard(const std::vector<uint32_t>& contact_ids,
                                               int vcard_version) {
  VCardGenerator generator;
  std::vector<VCardContact> vcards;

  for (auto id : contact_ids) {
    auto vcard = contact_to_vcard(id);
    if (!vcard.full_name.empty() || !vcard.emails.empty()) {
      vcards.push_back(vcard);
    }
  }

  return generator.generate_vcards(vcards, vcard_version);
}

std::string DeltaChat::export_all_contacts_vcard(int vcard_version) {
  std::vector<uint32_t> all_ids;
  for (const auto& [id, c] : contacts_) {
    all_ids.push_back(id);
  }
  return export_contacts_vcard(all_ids, vcard_version);
}

bool DeltaChat::save_vcard_to_file(const std::string& vcard_data,
                                    const std::string& filepath) {
  std::ofstream out(filepath, std::ios::binary);
  if (!out) return false;
  out << vcard_data;
  out.close();
  return true;
}

VCardContact DeltaChat::contact_to_vcard(uint32_t contact_id) {
  VCardContact vcard;

  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return vcard;

  const auto& c = it->second;

  vcard.uid = "dc-contact-" + std::to_string(contact_id);
  vcard.full_name = c.name.empty() ? c.display_name : c.name;

  // Split name into components
  auto name_parts = split(c.name.empty() ? c.display_name : c.name, ' ');
  if (name_parts.size() >= 2) {
    vcard.family_name = name_parts.back();
    name_parts.pop_back();
    vcard.given_name = join(name_parts, " ");
  } else if (name_parts.size() == 1) {
    vcard.given_name = name_parts[0];
  }

  // Add email
  if (!c.addr.empty()) {
    VCardContact::Email email;
    email.addr = c.addr;
    email.type = "OTHER";
    vcard.emails.push_back(email);
  }

  // Add extended info
  auto ext_it = contact_extended_.find(contact_id);
  if (ext_it != contact_extended_.end()) {
    const auto& ext = ext_it->second;
    vcard.organization = ext.organization;
    vcard.title = ext.title;
    vcard.nickname = ext.nickname;

    if (!ext.phone_number.empty()) {
      VCardContact::Phone phone;
      phone.number = ext.phone_number;
      phone.type = "CELL";
      vcard.phones.push_back(phone);
    }

    vcard.categories = ext.group_tags;

    // Notes
    std::string notes;
    if (!ext.private_notes.empty()) notes += ext.private_notes + "\n";
    // Add contact notes
    auto note_it = contact_notes_.find(contact_id);
    if (note_it != contact_notes_.end()) {
      for (const auto& note : note_it->second) {
        notes += "[" + format_date_iso8601(note.created_at / 1000) + "] " +
                 note.content + "\n";
      }
    }
    vcard.notes = trim(notes);
  }

  // Add photo if available
  if (!c.profile_image.empty()) {
    VCardContact::Photo photo;
    // Try to read file
    std::ifstream img(c.profile_image, std::ios::binary);
    if (img) {
      std::stringstream buf;
      buf << img.rdbuf();
      photo.data = buf.str();
      // Detect MIME type from extension
      if (ends_with(c.profile_image, ".png")) photo.mime_type = "image/png";
      else if (ends_with(c.profile_image, ".gif")) photo.mime_type = "image/gif";
      else photo.mime_type = "image/jpeg";
      vcard.photos.push_back(photo);
    }
  }

  vcard.rev = format_date_vcard(time(nullptr));
  return vcard;
}

// ============================================================================
// Feature 12: Contact export as CSV file
// ============================================================================
std::string DeltaChat::export_contacts_csv(const std::vector<uint32_t>& contact_ids) {
  std::stringstream csv;

  // CSV header
  csv << "ID,Name,DisplayName,Email,Phone,Organization,Title,Nickname,"
      << "Notes,Categories,Favorite,Birthday,Source,LastSeen,Created\n";

  for (auto id : contact_ids) {
    csv << export_single_contact_csv(id);
  }

  return csv.str();
}

std::string DeltaChat::export_all_contacts_csv() {
  std::vector<uint32_t> all_ids;
  for (const auto& [id, c] : contacts_) {
    all_ids.push_back(id);
  }
  return export_contacts_csv(all_ids);
}

std::string DeltaChat::export_single_contact_csv(uint32_t contact_id) {
  std::stringstream row;

  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return "";

  const auto& c = it->second;

  // ID
  row << c.id << ",";

  // Name (escape commas with quotes)
  row << "\"" << escape_csv_field(c.name) << "\",";
  row << "\"" << escape_csv_field(c.display_name) << "\",";
  row << "\"" << escape_csv_field(c.addr) << "\",";

  // Phone
  std::string phone;
  auto ext_it = contact_extended_.find(contact_id);
  if (ext_it != contact_extended_.end()) {
    phone = ext_it->second.phone_number;
  }
  row << "\"" << escape_csv_field(phone) << "\",";

  // Extended fields
  if (ext_it != contact_extended_.end()) {
    const auto& ext = ext_it->second;
    row << "\"" << escape_csv_field(ext.organization) << "\",";
    row << "\"" << escape_csv_field(ext.title) << "\",";
    row << "\"" << escape_csv_field(ext.nickname) << "\",";
    row << "\"" << escape_csv_field(ext.private_notes) << "\",";
    row << "\"" << escape_csv_field(join(ext.group_tags, ";")) << "\",";
    row << (ext.is_favorite ? "Yes" : "No") << ",";
    row << "\"\",";
    row << "\"" << escape_csv_field(ext.source) << "\",";
    row << c.last_seen << ",";
    row << ext.added_at;
  } else {
    row << ",,,,,,,";
  }

  row << "\n";
  return row.str();
}

std::string DeltaChat::escape_csv_field(const std::string& field) {
  return replace_all(field, "\"", "\"\"");
}

bool DeltaChat::save_csv_to_file(const std::string& csv_data,
                                  const std::string& filepath) {
  std::ofstream out(filepath);
  if (!out) return false;
  out << csv_data;
  out.close();
  return true;
}

// ============================================================================
// CSV import (parse CSV back to contacts)
// ============================================================================
std::vector<AddressBookEntry> DeltaChat::parse_csv_contacts(
    const std::string& csv_data) {

  std::vector<AddressBookEntry> entries;
  auto lines = split_lines(csv_data);
  if (lines.empty()) return entries;

  // Parse header
  std::vector<std::string> headers = parse_csv_line(lines[0]);

  // Map column indices
  int idx_id = -1, idx_name = -1, idx_display = -1, idx_email = -1;
  int idx_phone = -1, idx_org = -1, idx_title = -1, idx_nickname = -1;
  int idx_notes = -1, idx_categories = -1, idx_source = -1;

  for (size_t i = 0; i < headers.size(); ++i) {
    std::string h = to_lower(trim(headers[i]));
    if (h == "id") idx_id = i;
    else if (h == "name") idx_name = i;
    else if (h == "displayname") idx_display = i;
    else if (h == "email") idx_email = i;
    else if (h == "phone") idx_phone = i;
    else if (h == "organization") idx_org = i;
    else if (h == "title") idx_title = i;
    else if (h == "nickname") idx_nickname = i;
    else if (h == "notes") idx_notes = i;
    else if (h == "categories") idx_categories = i;
    else if (h == "source") idx_source = i;
  }

  // Parse data rows
  for (size_t line_no = 1; line_no < lines.size(); ++line_no) {
    auto fields = parse_csv_line(lines[line_no]);
    if (fields.empty()) continue;

    AddressBookEntry entry;
    if (idx_id >= 0 && idx_id < (int)fields.size()) entry.system_id = trim(fields[idx_id]);
    if (idx_name >= 0 && idx_name < (int)fields.size()) entry.display_name = trim(fields[idx_name]);
    if (idx_email >= 0 && idx_email < (int)fields.size()) {
      std::string email = trim(fields[idx_email]);
      if (!email.empty()) entry.emails.push_back(email);
      entry.email_labels.push_back("OTHER");
    }
    if (idx_phone >= 0 && idx_phone < (int)fields.size()) {
      std::string phone = trim(fields[idx_phone]);
      if (!phone.empty()) entry.phone_numbers.push_back(phone);
      entry.phone_labels.push_back("CELL");
    }
    if (idx_org >= 0 && idx_org < (int)fields.size()) entry.organization = trim(fields[idx_org]);
    if (idx_title >= 0 && idx_title < (int)fields.size()) entry.title = trim(fields[idx_title]);
    if (idx_nickname >= 0 && idx_nickname < (int)fields.size()) entry.nickname = trim(fields[idx_nickname]);
    if (idx_notes >= 0 && idx_notes < (int)fields.size()) entry.notes = trim(fields[idx_notes]);
    if (idx_categories >= 0 && idx_categories < (int)fields.size()) {
      auto cats = split(trim(fields[idx_categories]), ';');
      for (auto& cat : cats) {
        std::string c = trim(cat);
        if (!c.empty()) entry.group_labels.push_back(c);
      }
    }

    if (entry.system_id.empty())
      entry.system_id = sha256(entry.display_name + join(entry.emails, ","));
    entry.modified_at = nms();

    if (!entry.display_name.empty() || !entry.emails.empty()) {
      entries.push_back(entry);
    }
  }

  return entries;
}

std::vector<std::string> DeltaChat::parse_csv_line(const std::string& line) {
  std::vector<std::string> fields;
  std::string field;
  bool in_quotes = false;

  for (size_t i = 0; i < line.size(); ++i) {
    char c = line[i];
    if (in_quotes) {
      if (c == '"') {
        if (i + 1 < line.size() && line[i + 1] == '"') {
          field += '"';
          ++i;
        } else {
          in_quotes = false;
        }
      } else {
        field += c;
      }
    } else {
      if (c == '"') {
        in_quotes = true;
      } else if (c == ',') {
        fields.push_back(field);
        field.clear();
      } else {
        field += c;
      }
    }
  }
  fields.push_back(field);
  return fields;
}

// ============================================================================
// Feature 13: Contacts backup/restore
// ============================================================================
DeltaChat::BackupResult DeltaChat::backup_contacts(const std::string& backup_path) {
  BackupResult result;
  result.start_time = nms();

  try {
    json backup_json;

    // Backup contact list
    backup_json["version"] = 1;
    backup_json["created_at"] = nms();
    backup_json["contact_count"] = contacts_.size();

    json contacts_arr = json::array();
    for (const auto& [id, c] : contacts_) {
      json contact_obj;
      contact_obj["id"] = c.id;
      contact_obj["name"] = c.name;
      contact_obj["display_name"] = c.display_name;
      contact_obj["addr"] = c.addr;
      contact_obj["auth_name"] = c.auth_name;
      contact_obj["status"] = c.status;
      contact_obj["color"] = c.color;
      contact_obj["blocked"] = c.blocked;
      contact_obj["verified"] = c.verified;
      contact_obj["last_seen"] = c.last_seen;

      // Extended fields
      auto ext_it = contact_extended_.find(id);
      if (ext_it != contact_extended_.end()) {
        const auto& ext = ext_it->second;
        contact_obj["nickname"] = ext.nickname;
        contact_obj["organization"] = ext.organization;
        contact_obj["title"] = ext.title;
        contact_obj["phone_number"] = ext.phone_number;
        contact_obj["source"] = ext.source;
        contact_obj["is_favorite"] = ext.is_favorite;
        contact_obj["added_at"] = ext.added_at;
        contact_obj["last_interaction"] = ext.last_interaction;
        contact_obj["interaction_count"] = ext.interaction_count;
        contact_obj["group_tags"] = ext.group_tags;
        contact_obj["private_notes"] = ext.private_notes;
        contact_obj["online_status"] = ext.online_status;
        contact_obj["verification_level"] = ext.verification_level;
        contact_obj["verification_time"] = ext.verification_time;
        contact_obj["verification_method"] = ext.verification_method;
      }

      // Include photo data (base64)
      if (!c.profile_image.empty()) {
        std::ifstream img(c.profile_image, std::ios::binary);
        if (img) {
          std::stringstream buf;
          buf << img.rdbuf();
          contact_obj["profile_image_base64"] = base64_encode(buf.str());
        }
      }

      contacts_arr.push_back(contact_obj);
    }
    backup_json["contacts"] = contacts_arr;

    // Backup favorite groups
    json groups_arr = json::array();
    for (const auto& [name, group] : favorite_groups_) {
      json group_obj;
      group_obj["name"] = name;
      group_obj["contact_ids"] = group.contact_ids;
      group_obj["sort_order"] = group.sort_order;
      group_obj["created_at"] = group.created_at;
      group_obj["modified_at"] = group.modified_at;
      groups_arr.push_back(group_obj);
    }
    backup_json["favorite_groups"] = groups_arr;

    // Backup contact notes
    json notes_arr = json::array();
    for (const auto& [cid, notes] : contact_notes_) {
      for (const auto& note : notes) {
        json note_obj;
        note_obj["contact_id"] = note.contact_id;
        note_obj["note_id"] = note.note_id;
        note_obj["content"] = note.content;
        note_obj["created_at"] = note.created_at;
        note_obj["modified_at"] = note.modified_at;
        note_obj["color_tag"] = note.color_tag;
        note_obj["pinned"] = note.pinned;
        notes_arr.push_back(note_obj);
      }
    }
    backup_json["contact_notes"] = notes_arr;

    // Backup recent contacts
    json recent_arr = json::array();
    for (const auto& rc : recent_contacts_) {
      json rc_obj;
      rc_obj["contact_id"] = rc.contact_id;
      rc_obj["last_interaction"] = rc.last_interaction;
      rc_obj["interaction_count"] = rc.interaction_count;
      recent_arr.push_back(rc_obj);
    }
    backup_json["recent_contacts"] = recent_arr;

    // Backup birthdays
    json birthdays_arr = json::array();
    for (const auto& [cid, bday] : contact_birthdays_) {
      json bday_obj;
      bday_obj["contact_id"] = cid;
      bday_obj["birthday"] = bday.birthday;
      bday_obj["anniversary"] = bday.anniversary;
      bday_obj["reminder_days"] = bday.reminder_days;
      bday_obj["last_reminded"] = bday.last_reminded;
      birthdays_arr.push_back(bday_obj);
    }
    backup_json["birthdays"] = birthdays_arr;

    // Write to file
    std::ofstream out(backup_path);
    if (!out) {
      result.success = false;
      result.error_message = "Failed to open backup file: " + backup_path;
      result.end_time = nms();
      return result;
    }
    out << backup_json.dump(2);
    out.close();

    result.success = true;
    result.filename = backup_path;
    result.contacts_backed_up = contacts_.size();
    result.file_size_bytes = backup_json.dump().size();
  } catch (const std::exception& e) {
    result.success = false;
    result.error_message = std::string("Backup error: ") + e.what();
  }

  result.end_time = nms();
  result.duration_ms = result.end_time - result.start_time;
  return result;
}

DeltaChat::RestoreResult DeltaChat::restore_contacts(const std::string& backup_path,
                                                       bool merge_with_existing) {
  RestoreResult result;
  result.start_time = nms();

  try {
    std::ifstream in(backup_path);
    if (!in) {
      result.success = false;
      result.error_message = "Failed to open backup file: " + backup_path;
      return result;
    }

    json backup_json;
    in >> backup_json;
    in.close();

    int version = backup_json.value("version", 1);

    if (!merge_with_existing) {
      // Clear existing contacts
      contacts_.clear();
      contact_extended_.clear();
      favorite_groups_.clear();
      contact_notes_.clear();
      recent_contacts_.clear();
      contact_birthdays_.clear();
    }

    // Restore contacts
    if (backup_json.contains("contacts")) {
      for (const auto& obj : backup_json["contacts"]) {
        DcContact c;
        c.id = obj.value("id", gen_id());
        c.name = obj.value("name", "");
        c.display_name = obj.value("display_name", "");
        c.addr = obj.value("addr", "");
        c.auth_name = obj.value("auth_name", "");
        c.status = obj.value("status", "");
        c.color = obj.value("color", "");
        c.blocked = obj.value("blocked", 0);
        c.verified = obj.value("verified", 0);
        c.last_seen = obj.value("last_seen", (int64_t)0);

        if (merge_with_existing && contacts_.count(c.id)) {
          // Skip or merge logic
          continue;
        }

        contacts_[c.id] = c;
        result.contacts_restored++;

        // Restore extended info
        ContactExtended ext;
        ext.id = c.id;
        ext.nickname = obj.value("nickname", "");
        ext.organization = obj.value("organization", "");
        ext.title = obj.value("title", "");
        ext.phone_number = obj.value("phone_number", "");
        ext.source = obj.value("source", "backup");
        ext.is_favorite = obj.value("is_favorite", false);
        ext.added_at = obj.value("added_at", (int64_t)0);
        ext.last_interaction = obj.value("last_interaction", (int64_t)0);
        ext.interaction_count = obj.value("interaction_count", 0);
        ext.private_notes = obj.value("private_notes", "");
        ext.online_status = obj.value("online_status", 0);
        ext.verification_level = obj.value("verification_level", 0);
        ext.verification_time = obj.value("verification_time", (int64_t)0);
        ext.verification_method = obj.value("verification_method", "");

        if (obj.contains("group_tags") && obj["group_tags"].is_array()) {
          for (const auto& tag : obj["group_tags"]) {
            ext.group_tags.push_back(tag.get<std::string>());
          }
        }

        // Restore photo
        if (obj.contains("profile_image_base64")) {
          std::string img_data = base64_decode(obj["profile_image_base64"].get<std::string>());
          if (!img_data.empty()) {
            std::string blobdir = config_.dbfile;
            auto last_slash = blobdir.find_last_of("/\\");
            if (last_slash != std::string::npos) blobdir = blobdir.substr(0, last_slash);
            blobdir += "/blobs/";
            std::string filename = blobdir + "contact_" + std::to_string(c.id) + ".jpg";
            std::ofstream img_out(filename, std::ios::binary);
            if (img_out) {
              img_out.write(img_data.data(), img_data.size());
              img_out.close();
              ext.avatar_cache_path = filename;
              ext.avatar_cache_time = nms();
            }
          }
        }

        contact_extended_[c.id] = ext;
      }
    }

    // Restore favorite groups
    if (backup_json.contains("favorite_groups")) {
      for (const auto& obj : backup_json["favorite_groups"]) {
        FavoriteGroup group;
        group.group_name = obj["name"].get<std::string>();
        group.sort_order = obj.value("sort_order", 0);
        group.created_at = obj.value("created_at", (int64_t)0);
        group.modified_at = obj.value("modified_at", (int64_t)0);
        if (obj.contains("contact_ids") && obj["contact_ids"].is_array()) {
          for (const auto& cid : obj["contact_ids"]) {
            group.contact_ids.push_back(cid.get<uint32_t>());
          }
        }
        favorite_groups_[group.group_name] = group;
        result.groups_restored++;
      }
    }

    // Restore contact notes
    if (backup_json.contains("contact_notes")) {
      for (const auto& obj : backup_json["contact_notes"]) {
        ContactNote note;
        note.contact_id = obj["contact_id"].get<uint32_t>();
        note.note_id = obj.value("note_id", gen_token(16));
        note.content = obj.value("content", "");
        note.created_at = obj.value("created_at", (int64_t)0);
        note.modified_at = obj.value("modified_at", (int64_t)0);
        note.color_tag = obj.value("color_tag", "");
        note.pinned = obj.value("pinned", false);
        contact_notes_[note.contact_id].push_back(note);
        result.notes_restored++;
      }
    }

    // Restore recent contacts
    if (backup_json.contains("recent_contacts")) {
      for (const auto& obj : backup_json["recent_contacts"]) {
        RecentContact rc;
        rc.contact_id = obj["contact_id"].get<uint32_t>();
        rc.last_interaction = obj.value("last_interaction", (int64_t)0);
        rc.interaction_count = obj.value("interaction_count", 0);
        rc.priority_score = compute_priority_score(rc);
        recent_contacts_.push_back(rc);
      }
    }

    // Restore birthdays
    if (backup_json.contains("birthdays")) {
      for (const auto& obj : backup_json["birthdays"]) {
        BirthdayEntry bday;
        bday.birthday = obj.value("birthday", "");
        bday.anniversary = obj.value("anniversary", "");
        bday.reminder_days = obj.value("reminder_days", 0);
        bday.last_reminded = obj.value("last_reminded", (int64_t)0);
        contact_birthdays_[obj["contact_id"].get<uint32_t>()] = bday;
        result.birthdays_restored++;
      }
    }

    result.success = true;
  } catch (const std::exception& e) {
    result.success = false;
    result.error_message = std::string("Restore error: ") + e.what();
  }

  result.end_time = nms();
  result.duration_ms = result.end_time - result.start_time;
  return result;
}

// ============================================================================
// Feature 14: Contact favorites management
// ============================================================================
bool DeltaChat::set_contact_favorite(uint32_t contact_id, bool favorite) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) {
    // Create extended info if not exists
    ContactExtended ext;
    ext.id = contact_id;
    ext.is_favorite = favorite;
    ext.added_at = nms();
    contact_extended_[contact_id] = ext;
    return true;
  }

  it->second.is_favorite = favorite;
  return true;
}

bool DeltaChat::is_contact_favorite(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it != contact_extended_.end()) {
    return it->second.is_favorite;
  }
  return false;
}

std::vector<uint32_t> DeltaChat::get_favorite_contacts() {
  std::vector<uint32_t> favorites;
  for (const auto& [id, ext] : contact_extended_) {
    if (ext.is_favorite && contacts_.count(id)) {
      favorites.push_back(id);
    }
  }
  return favorites;
}

int DeltaChat::toggle_contact_favorite(uint32_t contact_id) {
  auto it = contact_extended_.find(contact_id);
  if (it == contact_extended_.end()) {
    set_contact_favorite(contact_id, true);
    return 1;
  }
  it->second.is_favorite = !it->second.is_favorite;
  return it->second.is_favorite ? 1 : 0;
}

// ============================================================================
// Favorite groups (Feature 10 continuation)
// ============================================================================
bool DeltaChat::create_favorite_group(const std::string& group_name) {
  if (favorite_groups_.count(group_name)) return false;

  FavoriteGroup group;
  group.group_name = group_name;
  group.sort_order = favorite_groups_.size();
  group.created_at = nms();
  group.modified_at = nms();
  favorite_groups_[group_name] = group;
  return true;
}

bool DeltaChat::delete_favorite_group(const std::string& group_name) {
  return favorite_groups_.erase(group_name) > 0;
}

std::vector<std::string> DeltaChat::get_favorite_group_names() {
  std::vector<std::string> names;
  for (const auto& [name, group] : favorite_groups_) {
    names.push_back(name);
  }
  return names;
}

std::vector<uint32_t> DeltaChat::get_contacts_in_group(const std::string& group_name) {
  auto it = favorite_groups_.find(group_name);
  if (it != favorite_groups_.end()) {
    return it->second.contact_ids;
  }
  return {};
}

bool DeltaChat::reorder_favorite_groups(const std::vector<std::string>& ordered_names) {
  for (size_t i = 0; i < ordered_names.size(); ++i) {
    auto it = favorite_groups_.find(ordered_names[i]);
    if (it != favorite_groups_.end()) {
      it->second.sort_order = (int)i;
    }
  }
  return true;
}

// ============================================================================
// Feature 15: Recent contacts tracking
// ============================================================================
void DeltaChat::record_contact_interaction(uint32_t contact_id) {
  int64_t now = nms();

  // Update recent contacts list
  bool found = false;
  for (auto& rc : recent_contacts_) {
    if (rc.contact_id == contact_id) {
      rc.last_interaction = now;
      rc.interaction_count++;
      rc.priority_score = compute_priority_score(rc);
      found = true;
      break;
    }
  }

  if (!found) {
    RecentContact rc;
    rc.contact_id = contact_id;
    rc.last_interaction = now;
    rc.interaction_count = 1;
    rc.priority_score = compute_priority_score(rc);
    recent_contacts_.push_back(rc);
  }

  // Update extended info
  auto it = contact_extended_.find(contact_id);
  if (it != contact_extended_.end()) {
    it->second.last_interaction = now;
    it->second.interaction_count++;
  }

  // Update the contact itself
  auto cit = contacts_.find(contact_id);
  if (cit != contacts_.end()) {
    cit->second.last_seen = now;
    cit->second.was_seen_recently = 1;
  }

  // Trim recent contacts list to maximum size
  trim_recent_contacts();
}

void DeltaChat::trim_recent_contacts() {
  constexpr int max_recent = 200;
  if ((int)recent_contacts_.size() <= max_recent) return;

  // Sort by priority score descending
  std::sort(recent_contacts_.begin(), recent_contacts_.end(),
            [](const auto& a, const auto& b) {
              return a.priority_score > b.priority_score;
            });

  recent_contacts_.resize(max_recent);
}

int DeltaChat::compute_priority_score(const RecentContact& rc) {
  int64_t now = nms();
  // Score decays over time: recent interactions score higher
  int64_t age_hours = (now - rc.last_interaction) / (1000 * 3600);

  double recency_factor = 1.0;
  if (age_hours > 0) {
    recency_factor = std::exp(-0.01 * age_hours); // Exponential decay
  }

  double freq_factor = std::log1p(rc.interaction_count);
  return (int)(recency_factor * freq_factor * 100);
}

std::vector<uint32_t> DeltaChat::get_recent_contacts(int limit) {
  std::vector<RecentContact> sorted = recent_contacts_;
  std::sort(sorted.begin(), sorted.end(),
            [](const auto& a, const auto& b) {
              return a.priority_score > b.priority_score;
            });

  std::vector<uint32_t> result;
  for (const auto& rc : sorted) {
    if (contacts_.count(rc.contact_id)) {
      result.push_back(rc.contact_id);
      if ((int)result.size() >= limit) break;
    }
  }
  return result;
}

int DeltaChat::get_recent_contact_count() {
  return (int)recent_contacts_.size();
}

void DeltaChat::clear_recent_contacts() {
  recent_contacts_.clear();
}

// ============================================================================
// Feature 16: Contact search with fuzzy matching
// ============================================================================
std::vector<uint32_t> DeltaChat::search_contacts_fuzzy(const std::string& query,
                                                         int max_results,
                                                         double min_score) {
  std::vector<std::pair<uint32_t, double>> scored;

  std::string q = normalize_text_for_search(query);
  if (q.empty()) return {};

  for (const auto& [id, c] : contacts_) {
    double best_score = 0.0;

    // Score name match
    if (!c.name.empty()) {
      double name_score = fuzzy_match_score(q, normalize_text_for_search(c.name));
      best_score = std::max(best_score, name_score * 1.5); // Name is more important
    }

    // Score display name match
    if (!c.display_name.empty() && c.display_name != c.name) {
      double display_score = fuzzy_match_score(q, normalize_text_for_search(c.display_name));
      best_score = std::max(best_score, display_score * 1.2);
    }

    // Score email match
    if (!c.addr.empty()) {
      double email_score = fuzzy_match_score(q, normalize_text_for_search(c.addr));
      best_score = std::max(best_score, email_score * 1.0);
    }

    // Score extended info
    auto ext_it = contact_extended_.find(id);
    if (ext_it != contact_extended_.end()) {
      const auto& ext = ext_it->second;

      if (!ext.nickname.empty()) {
        double nick_score = fuzzy_match_score(q, normalize_text_for_search(ext.nickname));
        best_score = std::max(best_score, nick_score * 1.3);
      }

      if (!ext.organization.empty()) {
        double org_score = fuzzy_match_score(q, normalize_text_for_search(ext.organization));
        best_score = std::max(best_score, org_score * 0.8);
      }

      if (!ext.phone_number.empty()) {
        double phone_score = fuzzy_match_score(q, normalize_phone(ext.phone_number));
        best_score = std::max(best_score, phone_score * 1.1);
      }
    }

    if (best_score >= min_score) {
      scored.push_back({id, best_score});
    }
  }

  // Sort by score descending
  std::sort(scored.begin(), scored.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

  // Return top results
  std::vector<uint32_t> results;
  for (const auto& [id, score] : scored) {
    results.push_back(id);
    if ((int)results.size() >= max_results) break;
  }
  return results;
}

double DeltaChat::fuzzy_match_score(const std::string& query, const std::string& target) {
  if (query.empty() || target.empty()) return 0.0;

  // Method 1: Prefix match (highest priority)
  if (starts_with(target, query)) return 1.0;

  // Method 2: Contains match
  if (target.find(query) != std::string::npos) return 0.9;

  // Method 3: Levenshtein similarity
  std::string q_norm = levenshtein_normalize(query);
  std::string t_norm = levenshtein_normalize(target);

  int dist = levenshtein_distance(q_norm, t_norm);
  int max_len = std::max(q_norm.size(), t_norm.size());
  if (max_len == 0) return 0.0;

  double levenshtein_score = 1.0 - (double)dist / max_len;

  // Method 4: N-gram cosine similarity for longer strings
  double ngram_score = 0.0;
  if (q_norm.size() >= 3 && t_norm.size() >= 3) {
    int n = std::min(3, (int)std::min(q_norm.size(), t_norm.size()));
    auto q_vec = ngram_vector(q_norm, n);
    auto t_vec = ngram_vector(t_norm, n);
    ngram_score = cosine_similarity(q_vec, t_vec);
  }

  // Method 5: Soundex match
  double soundex_score = 0.0;
  if (query.size() >= 2 && target.size() >= 2) {
    if (soundex(query) == soundex(target)) soundex_score = 0.7;
  }

  // Method 6: Initials match (e.g., "JD" matches "John Doe")
  double initials_score = fuzzy_match_initials(query, target);

  // Combine scores with weights
  double combined = std::max({
    levenshtein_score * 0.6,
    ngram_score * 0.5,
    soundex_score,
    initials_score * 0.8
  });

  return std::min(1.0, combined);
}

double DeltaChat::fuzzy_match_initials(const std::string& query,
                                         const std::string& target) {
  if (query.size() < 2 || target.size() < 2) return 0.0;

  // Extract initials from target name
  std::string target_initials;
  auto parts = split(target, ' ');
  for (const auto& part : parts) {
    if (!part.empty()) target_initials += std::toupper(part[0]);
  }

  std::string q_upper = to_upper(query);

  if (target_initials == q_upper) return 1.0;
  if (target_initials.size() >= 2 && q_upper.size() >= 2) {
    if (target_initials.substr(0, 2) == q_upper.substr(0, 2)) return 0.9;
  }

  return 0.0;
}

// ============================================================================
// Feature 17: Contact name formatting (first last, last first)
// ============================================================================
std::string DeltaChat::format_contact_name(uint32_t contact_id,
                                              NameFormat format) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return "";

  const auto& c = it->second;
  std::string full_name = c.name.empty() ? c.display_name : c.name;
  auto parts = split(full_name, ' ');

  if (parts.size() < 2) return full_name;

  switch (format) {
    case NameFormat::FIRST_LAST:
      return full_name;
    case NameFormat::LAST_FIRST:
      return parts.back() + ", " + join(
          std::vector<std::string>(parts.begin(), parts.end() - 1), " ");
    case NameFormat::LAST_ONLY:
      return parts.back();
    case NameFormat::FIRST_ONLY:
      return parts.front();
    case NameFormat::INITIALS_LAST: {
      std::string initials;
      for (size_t i = 0; i < parts.size() - 1; ++i) {
        if (!parts[i].empty()) initials += std::toupper(parts[i][0]);
        initials += ". ";
      }
      return initials + parts.back();
    }
    case NameFormat::LAST_INITIALS: {
      std::string initials;
      for (size_t i = 0; i < parts.size() - 1; ++i) {
        if (!parts[i].empty()) initials += std::toupper(parts[i][0]);
        initials += ". ";
      }
      return parts.back() + ", " + initials;
    }
    default:
      return full_name;
  }
}

std::string DeltaChat::format_contact_name_ex(const std::string& full_name,
                                                NameFormat format) {
  auto parts = split(full_name, ' ');
  if (parts.size() < 2) return full_name;

  switch (format) {
    case NameFormat::FIRST_LAST: return full_name;
    case NameFormat::LAST_FIRST:
      return parts.back() + ", " + join(
          std::vector<std::string>(parts.begin(), parts.end() - 1), " ");
    case NameFormat::LAST_ONLY: return parts.back();
    case NameFormat::FIRST_ONLY: return parts.front();
    case NameFormat::INITIALS_LAST: {
      std::string initials;
      for (size_t i = 0; i < parts.size() - 1; ++i) {
        if (!parts[i].empty()) initials += std::toupper(parts[i][0]);
        initials += ". ";
      }
      return initials + parts.back();
    }
    default: return full_name;
  }
}

// ============================================================================
// Feature 18: Contact initials generation (for avatar fallback)
// ============================================================================
std::string DeltaChat::generate_contact_initials(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return "";

  return generate_initials_from_name(it->second.name.empty()
                                      ? it->second.display_name
                                      : it->second.name);
}

std::string DeltaChat::generate_initials_from_name(const std::string& name) {
  std::string trimmed = trim(name);
  if (trimmed.empty()) return "?";

  auto parts = split(trimmed, ' ');

  // Remove empty parts
  parts.erase(std::remove_if(parts.begin(), parts.end(),
                              [](const auto& p) { return p.empty(); }),
              parts.end());

  if (parts.empty()) return "?";

  std::string initials;
  if (parts.size() == 1) {
    // Single name: first character
    if (!parts[0].empty()) initials += std::toupper(parts[0][0]);
  } else if (parts.size() == 2) {
    // Two names: first char of each
    if (!parts[0].empty()) initials += std::toupper(parts[0][0]);
    if (!parts[1].empty()) initials += std::toupper(parts[1][0]);
  } else {
    // More than two: first char of first and last
    if (!parts[0].empty()) initials += std::toupper(parts[0][0]);
    if (!parts.back().empty()) initials += std::toupper(parts.back()[0]);
  }

  // Ensure at least one character
  if (initials.empty()) initials = "?";

  return initials;
}

std::string DeltaChat::generate_avatar_svg(const std::string& initials,
                                             const std::string& color) {
  std::stringstream svg;
  svg << "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\">";
  svg << "<rect width=\"100\" height=\"100\" rx=\"50\" ry=\"50\" fill=\""
      << color << "\"/>";
  svg << "<text x=\"50\" y=\"50\" dy=\".35em\" text-anchor=\"middle\" "
      << "fill=\"white\" font-family=\"Arial, sans-serif\" font-size=\"40\" "
      << "font-weight=\"bold\">" << initials << "</text>";
  svg << "</svg>";
  return svg.str();
}

// ============================================================================
// Feature 19: Contact birthday/anniversary tracking
// ============================================================================
bool DeltaChat::set_contact_birthday(uint32_t contact_id,
                                       const std::string& birthday_iso) {
  auto& bday = contact_birthdays_[contact_id];
  bday.birthday = birthday_iso;
  return true;
}

bool DeltaChat::set_contact_anniversary(uint32_t contact_id,
                                          const std::string& anniversary_iso) {
  auto& bday = contact_birthdays_[contact_id];
  bday.anniversary = anniversary_iso;
  return true;
}

std::string DeltaChat::get_contact_birthday(uint32_t contact_id) {
  auto it = contact_birthdays_.find(contact_id);
  if (it != contact_birthdays_.end()) return it->second.birthday;
  return "";
}

std::string DeltaChat::get_contact_anniversary(uint32_t contact_id) {
  auto it = contact_birthdays_.find(contact_id);
  if (it != contact_birthdays_.end()) return it->second.anniversary;
  return "";
}

std::vector<uint32_t> DeltaChat::get_contacts_with_upcoming_birthdays(
    int days_ahead) {

  std::vector<uint32_t> result;
  time_t now = time(nullptr);
  struct tm now_tm;
  localtime_r(&now, &now_tm);

  for (const auto& [cid, bday] : contact_birthdays_) {
    if (bday.birthday.empty()) continue;

    // Parse birthday
    int year, month, day;
    if (sscanf(bday.birthday.c_str(), "%d-%d-%d", &year, &month, &day) < 3) {
      if (sscanf(bday.birthday.c_str(), "%4d%2d%2d", &year, &month, &day) < 3) {
        continue;
      }
    }

    // Calculate days until next birthday
    struct tm bday_tm = {};
    bday_tm.tm_year = now_tm.tm_year;
    bday_tm.tm_mon = month - 1;
    bday_tm.tm_mday = day;

    time_t bday_time = mktime(&bday_tm);
    if (bday_time < now) {
      // Already passed this year, check next year
      bday_tm.tm_year++;
      bday_time = mktime(&bday_tm);
    }

    double diff_secs = difftime(bday_time, now);
    int diff_days = (int)(diff_secs / (24 * 3600));

    if (diff_days >= 0 && diff_days <= days_ahead) {
      result.push_back(cid);
    }
  }

  return result;
}

std::vector<uint32_t> DeltaChat::get_contacts_with_upcoming_anniversaries(
    int days_ahead) {

  std::vector<uint32_t> result;
  time_t now = time(nullptr);
  struct tm now_tm;
  localtime_r(&now, &now_tm);

  for (const auto& [cid, bday] : contact_birthdays_) {
    if (bday.anniversary.empty()) continue;

    int year, month, day;
    if (sscanf(bday.anniversary.c_str(), "%d-%d-%d", &year, &month, &day) < 3) {
      if (sscanf(bday.anniversary.c_str(), "%4d%2d%2d", &year, &month, &day) < 3) {
        continue;
      }
    }

    struct tm anniv_tm = {};
    anniv_tm.tm_year = now_tm.tm_year;
    anniv_tm.tm_mon = month - 1;
    anniv_tm.tm_mday = day;

    time_t anniv_time = mktime(&anniv_tm);
    if (anniv_time < now) {
      anniv_tm.tm_year++;
      anniv_time = mktime(&anniv_tm);
    }

    double diff_secs = difftime(anniv_time, now);
    int diff_days = (int)(diff_secs / (24 * 3600));

    if (diff_days >= 0 && diff_days <= days_ahead) {
      result.push_back(cid);
    }
  }

  return result;
}

int DeltaChat::get_days_until_birthday(uint32_t contact_id) {
  auto it = contact_birthdays_.find(contact_id);
  if (it == contact_birthdays_.end() || it->second.birthday.empty()) return -1;

  return compute_days_until_date(it->second.birthday);
}

int DeltaChat::get_days_until_anniversary(uint32_t contact_id) {
  auto it = contact_birthdays_.find(contact_id);
  if (it == contact_birthdays_.end() || it->second.anniversary.empty()) return -1;

  return compute_days_until_date(it->second.anniversary);
}

int DeltaChat::compute_days_until_date(const std::string& date_iso) {
  int year, month, day;
  if (sscanf(date_iso.c_str(), "%d-%d-%d", &year, &month, &day) < 3) {
    if (sscanf(date_iso.c_str(), "%4d%2d%2d", &year, &month, &day) < 3) {
      return -1;
    }
  }

  time_t now = time(nullptr);
  struct tm now_tm;
  localtime_r(&now, &now_tm);

  struct tm target_tm = {};
  target_tm.tm_year = now_tm.tm_year;
  target_tm.tm_mon = month - 1;
  target_tm.tm_mday = day;

  time_t target_time = mktime(&target_tm);
  if (target_time < now) {
    target_tm.tm_year++;
    target_time = mktime(&target_tm);
  }

  return (int)(difftime(target_time, now) / (24 * 3600));
}

bool DeltaChat::set_birthday_reminder(uint32_t contact_id, int days_before) {
  auto it = contact_birthdays_.find(contact_id);
  if (it == contact_birthdays_.end()) {
    BirthdayEntry entry;
    entry.reminder_days = days_before;
    contact_birthdays_[contact_id] = entry;
    return true;
  }
  it->second.reminder_days = days_before;
  return true;
}

// ============================================================================
// Feature 20: Contact notes management
// ============================================================================
std::string DeltaChat::add_contact_note(uint32_t contact_id,
                                          const std::string& content) {
  ContactNote note;
  note.contact_id = contact_id;
  note.note_id = gen_token(16);
  note.content = content;
  note.created_at = nms();
  note.modified_at = nms();

  contact_notes_[contact_id].push_back(note);
  return note.note_id;
}

bool DeltaChat::update_contact_note(uint32_t contact_id,
                                      const std::string& note_id,
                                      const std::string& new_content) {
  auto it = contact_notes_.find(contact_id);
  if (it == contact_notes_.end()) return false;

  for (auto& note : it->second) {
    if (note.note_id == note_id) {
      note.content = new_content;
      note.modified_at = nms();
      return true;
    }
  }
  return false;
}

bool DeltaChat::delete_contact_note(uint32_t contact_id,
                                      const std::string& note_id) {
  auto it = contact_notes_.find(contact_id);
  if (it == contact_notes_.end()) return false;

  auto& notes = it->second;
  auto note_it = std::find_if(notes.begin(), notes.end(),
                               [&](const ContactNote& n) {
                                 return n.note_id == note_id;
                               });
  if (note_it != notes.end()) {
    notes.erase(note_it);
    if (notes.empty()) contact_notes_.erase(contact_id);
    return true;
  }
  return false;
}

std::vector<ContactNote> DeltaChat::get_contact_notes(uint32_t contact_id) {
  auto it = contact_notes_.find(contact_id);
  if (it != contact_notes_.end()) {
    return it->second;
  }
  return {};
}

ContactNote DeltaChat::get_contact_note(uint32_t contact_id,
                                          const std::string& note_id) {
  auto it = contact_notes_.find(contact_id);
  if (it != contact_notes_.end()) {
    for (const auto& note : it->second) {
      if (note.note_id == note_id) return note;
    }
  }
  return {};
}

bool DeltaChat::pin_contact_note(uint32_t contact_id,
                                   const std::string& note_id,
                                   bool pinned) {
  auto it = contact_notes_.find(contact_id);
  if (it == contact_notes_.end()) return false;

  for (auto& note : it->second) {
    if (note.note_id == note_id) {
      note.pinned = pinned;
      return true;
    }
  }
  return false;
}

bool DeltaChat::set_contact_note_color(uint32_t contact_id,
                                         const std::string& note_id,
                                         const std::string& color_tag) {
  auto it = contact_notes_.find(contact_id);
  if (it == contact_notes_.end()) return false;

  for (auto& note : it->second) {
    if (note.note_id == note_id) {
      note.color_tag = color_tag;
      return true;
    }
  }
  return false;
}

int DeltaChat::get_contact_note_count(uint32_t contact_id) {
  auto it = contact_notes_.find(contact_id);
  if (it != contact_notes_.end()) return (int)it->second.size();
  return 0;
}

// ============================================================================
// VCard import from file
// ============================================================================
DeltaChat::AddressBookImportResult DeltaChat::import_vcard_file(
    const std::string& filepath,
    const ImportOptions& options) {

  AddressBookImportResult result;

  std::ifstream in(filepath, std::ios::binary);
  if (!in) {
    result.errors.push_back("Failed to open file: " + filepath);
    result.total_errors = 1;
    return result;
  }

  std::stringstream buf;
  buf << in.rdbuf();
  std::string data = buf.str();
  in.close();

  VCardParser parser;
  auto vcards = parser.parse_vcards(data);

  std::vector<AddressBookEntry> entries;
  for (const auto& vcard : vcards) {
    entries.push_back(vcard_to_entry(vcard));
  }

  return import_from_address_book(entries, options);
}

// ============================================================================
// VCard export to file
// ============================================================================
bool DeltaChat::export_vcard_file(const std::string& filepath,
                                    const std::vector<uint32_t>& contact_ids,
                                    int vcard_version) {
  std::string vcard_data = export_contacts_vcard(contact_ids, vcard_version);
  return save_vcard_to_file(vcard_data, filepath);
}

// ============================================================================
// Contact count and statistics
// ============================================================================
json DeltaChat::get_address_book_statistics() {
  json stats;

  stats["total_contacts"] = contacts_.size();
  stats["favorite_contacts"] = get_favorite_contacts().size();
  stats["recent_contacts"] = recent_contacts_.size();
  stats["total_groups"] = favorite_groups_.size();

  int with_email = 0, with_phone = 0, with_photo = 0, with_birthday = 0;
  for (const auto& [id, c] : contacts_) {
    if (!c.addr.empty()) with_email++;
    if (!c.profile_image.empty()) with_photo++;
  }
  for (const auto& [id, ext] : contact_extended_) {
    if (!ext.phone_number.empty()) with_phone++;
  }
  for (const auto& [id, bday] : contact_birthdays_) {
    if (!bday.birthday.empty()) with_birthday++;
  }

  stats["contacts_with_email"] = with_email;
  stats["contacts_with_phone"] = with_phone;
  stats["contacts_with_photo"] = with_photo;
  stats["contacts_with_birthday"] = with_birthday;

  stats["last_sync_time"] = sync_state_.last_sync_time;
  stats["last_sync_contacts_added"] = sync_state_.contacts_added;
  stats["last_sync_contacts_updated"] = sync_state_.contacts_updated;
  stats["last_sync_contacts_deleted"] = sync_state_.contacts_deleted;

  stats["total_notes"] = 0;
  for (const auto& [id, notes] : contact_notes_) {
    stats["total_notes"] = stats["total_notes"].get<int>() + notes.size();
  }

  return stats;
}

// ============================================================================
// Address book settings
// ============================================================================
void DeltaChat::set_address_book_sync_interval(int seconds) {
  sync_state_.sync_interval_seconds = std::max(60, seconds);
  sync_state_.next_sync_time = nms() + (int64_t)sync_state_.sync_interval_seconds * 1000;
}

int DeltaChat::get_address_book_sync_interval() {
  return sync_state_.sync_interval_seconds;
}

void DeltaChat::set_address_book_sync_enabled(bool enabled) {
  sync_enabled_ = enabled;
  if (enabled) {
    sync_state_.next_sync_time = nms() + (int64_t)sync_state_.sync_interval_seconds * 1000;
  }
}

bool DeltaChat::is_address_book_sync_enabled() {
  return sync_enabled_;
}

// ============================================================================
// Batch operations
// ============================================================================
DeltaChat::BatchResult DeltaChat::batch_delete_contacts(
    const std::vector<uint32_t>& contact_ids) {

  BatchResult result;
  for (auto id : contact_ids) {
    if (contacts_.erase(id) > 0) {
      contact_extended_.erase(id);
      contact_notes_.erase(id);
      contact_birthdays_.erase(id);
      result.success_count++;
    } else {
      result.failure_count++;
    }
  }
  return result;
}

DeltaChat::BatchResult DeltaChat::batch_set_favorite(
    const std::vector<uint32_t>& contact_ids, bool favorite) {

  BatchResult result;
  for (auto id : contact_ids) {
    if (set_contact_favorite(id, favorite)) {
      result.success_count++;
    } else {
      result.failure_count++;
    }
  }
  return result;
}

DeltaChat::BatchResult DeltaChat::batch_add_to_group(
    const std::vector<uint32_t>& contact_ids, const std::string& group_name) {

  BatchResult result;
  for (auto id : contact_ids) {
    if (add_contact_to_group(id, group_name)) {
      result.success_count++;
    } else {
      result.failure_count++;
    }
  }
  return result;
}

// ============================================================================
// Contact deduplication cleanup
// ============================================================================
DeltaChat::DeduplicationResult DeltaChat::deduplicate_all_contacts(
    double auto_merge_threshold) {

  DeduplicationResult result;
  result.start_time = nms();

  auto candidates = find_merge_candidates(auto_merge_threshold);

  for (const auto& candidate : candidates) {
    if (candidate.auto_merge || candidate.confidence >= auto_merge_threshold) {
      uint32_t merged = merge_contacts(candidate.contact_a, candidate.contact_b);
      if (merged > 0) {
        result.merged_count++;
      }
    } else {
      result.suggested_count++;
      result.pending_merges.push_back(candidate);
    }
  }

  result.end_time = nms();
  result.duration_ms = result.end_time - result.start_time;
  return result;
}

// ============================================================================
// Contact validity checks
// ============================================================================
bool DeltaChat::is_valid_contact(const AddressBookEntry& entry) {
  // A contact is valid if it has at least a name or an email or a phone
  if (!entry.display_name.empty()) return true;
  if (!entry.emails.empty()) {
    for (const auto& email : entry.emails) {
      if (valid_email(email)) return true;
    }
  }
  if (!entry.phone_numbers.empty()) {
    for (const auto& phone : entry.phone_numbers) {
      if (normalize_phone(phone).size() >= 7) return true;
    }
  }
  return false;
}

// ============================================================================
// Address book directory monitoring (for live change detection)
// ============================================================================
void DeltaChat::start_address_book_watcher() {
  address_book_watcher_running_ = true;
  // In production, would use inotify (Linux), FSEvents (macOS),
  // or ReadDirectoryChangesW (Windows) to watch for file changes
}

void DeltaChat::stop_address_book_watcher() {
  address_book_watcher_running_ = false;
}

bool DeltaChat::is_address_book_watcher_running() {
  return address_book_watcher_running_;
}

// ============================================================================
// System address book entry retrieval
// ============================================================================
std::vector<AddressBookEntry> DeltaChat::get_system_address_book_entries() {
  return g_address_book_scanner.scan_all();
}

// ============================================================================
// Full address book rescan
// ============================================================================
DeltaChat::SyncResult DeltaChat::rescan_address_book() {
  sync_state_.needs_full_rescan = true;
  previous_snapshot_.entries.clear(); // Force full re-scan

  SyncOptions opts;
  opts.update_existing = true;
  opts.handle_deletions = true;
  opts.delete_orphaned_contacts = false;
  opts.max_contacts_per_sync = 0; // unlimited

  return sync_address_book(opts);
}

// ============================================================================
// Address book conflict resolution
// ============================================================================
uint32_t DeltaChat::resolve_contact_conflict(
    const AddressBookEntry& local_entry,
    const AddressBookEntry& remote_entry,
    ConflictResolutionStrategy strategy) {

  switch (strategy) {
    case ConflictResolutionStrategy::KEEP_LOCAL: {
      // Find existing local contact
      for (const auto& [id, c] : contacts_) {
        if (!local_entry.emails.empty() && !c.addr.empty() &&
            normalize_email(c.addr) == normalize_email(local_entry.emails[0])) {
          return id;
        }
      }
      return create_contact_from_entry(local_entry);
    }

    case ConflictResolutionStrategy::KEEP_REMOTE: {
      // Remove local, use remote
      for (auto it = contacts_.begin(); it != contacts_.end(); ++it) {
        if (!local_entry.emails.empty() && !it->second.addr.empty() &&
            normalize_email(it->second.addr) == normalize_email(local_entry.emails[0])) {
          contacts_.erase(it);
          break;
        }
      }
      return create_contact_from_entry(remote_entry);
    }

    case ConflictResolutionStrategy::MERGE_FIELDS: {
      // Merge: keep local, but fill in missing fields from remote
      uint32_t found_id = 0;
      for (const auto& [id, c] : contacts_) {
        if (!local_entry.emails.empty() && !c.addr.empty() &&
            normalize_email(c.addr) == normalize_email(local_entry.emails[0])) {
          found_id = id;
          break;
        }
      }

      if (found_id == 0) {
        return create_contact_from_entry(remote_entry);
      }

      // Merge missing fields
      auto& c = contacts_[found_id];
      if (c.name.empty() && !remote_entry.display_name.empty())
        c.name = remote_entry.display_name;
      if (c.display_name.empty() && !remote_entry.display_name.empty())
        c.display_name = remote_entry.display_name;

      auto ext_it = contact_extended_.find(found_id);
      if (ext_it != contact_extended_.end()) {
        auto& ext = ext_it->second;
        if (ext.organization.empty() && !remote_entry.organization.empty())
          ext.organization = remote_entry.organization;
        if (ext.title.empty() && !remote_entry.title.empty())
          ext.title = remote_entry.title;
        if (ext.phone_number.empty() && !remote_entry.phone_numbers.empty())
          ext.phone_number = remote_entry.phone_numbers[0];
      }

      return found_id;
    }

    case ConflictResolutionStrategy::CREATE_DUPLICATE:
    default: {
      // Create a separate contact
      AddressBookEntry dup = remote_entry;
      dup.display_name = remote_entry.display_name + " (remote)";
      return create_contact_from_entry(dup);
    }
  }
}

// ============================================================================
// Privacy: encrypt/decrypt contact notes
// ============================================================================
std::string DeltaChat::encrypt_contact_notes(uint32_t contact_id,
                                               const std::string& encryption_key) {
  auto it = contact_notes_.find(contact_id);
  if (it == contact_notes_.end()) return "";

  json notes_json = json::array();
  for (const auto& note : it->second) {
    json note_obj;
    note_obj["note_id"] = note.note_id;
    note_obj["content"] = note.content;
    note_obj["created_at"] = note.created_at;
    note_obj["modified_at"] = note.modified_at;
    note_obj["color_tag"] = note.color_tag;
    note_obj["pinned"] = note.pinned;
    notes_json.push_back(note_obj);
  }

  std::string plain = notes_json.dump();
  // Simple XOR encryption with key (for production, use proper AES)
  std::string encrypted;
  for (size_t i = 0; i < plain.size(); ++i) {
    encrypted += plain[i] ^ encryption_key[i % encryption_key.size()];
  }
  return base64_encode(encrypted);
}

bool DeltaChat::decrypt_contact_notes(uint32_t contact_id,
                                        const std::string& encrypted_data,
                                        const std::string& encryption_key) {
  std::string decoded = base64_decode(encrypted_data);
  std::string plain;
  for (size_t i = 0; i < decoded.size(); ++i) {
    plain += decoded[i] ^ encryption_key[i % encryption_key.size()];
  }

  try {
    json notes_json = json::parse(plain);
    contact_notes_[contact_id].clear();
    for (const auto& obj : notes_json) {
      ContactNote note;
      note.contact_id = contact_id;
      note.note_id = obj["note_id"].get<std::string>();
      note.content = obj["content"].get<std::string>();
      note.created_at = obj["created_at"].get<int64_t>();
      note.modified_at = obj["modified_at"].get<int64_t>();
      note.color_tag = obj.value("color_tag", "");
      note.pinned = obj.value("pinned", false);
      contact_notes_[contact_id].push_back(note);
    }
    return true;
  } catch (...) {
    return false;
  }
}

// ============================================================================
// Contact export/import progress callbacks
// ============================================================================
void DeltaChat::set_import_progress_callback(ProgressCallback cb) {
  import_progress_callback_ = std::move(cb);
}

void DeltaChat::set_export_progress_callback(ProgressCallback cb) {
  export_progress_callback_ = std::move(cb);
}

void DeltaChat::report_import_progress(int current, int total,
                                         const std::string& status) {
  if (import_progress_callback_) {
    import_progress_callback_(current, total, status);
  }
}

void DeltaChat::report_export_progress(int current, int total,
                                         const std::string& status) {
  if (export_progress_callback_) {
    export_progress_callback_(current, total, status);
  }
}

// ============================================================================
// Contact suggestions (for autocomplete, based on frequency and recency)
// ============================================================================
std::vector<uint32_t> DeltaChat::suggest_contacts(const std::string& partial,
                                                    int max_results) {
  std::vector<std::pair<uint32_t, double>> scored;

  for (const auto& [id, c] : contacts_) {
    double score = 0.0;

    // Name match
    if (!c.name.empty()) {
      auto pos = to_lower(c.name).find(to_lower(partial));
      if (pos == 0) score += 3.0;
      else if (pos != std::string::npos) score += 1.5;
    }

    // Email match
    if (!c.addr.empty()) {
      auto pos = to_lower(c.addr).find(to_lower(partial));
      if (pos == 0) score += 2.5;
      else if (pos != std::string::npos) score += 1.0;
    }

    // Recency boost
    for (const auto& rc : recent_contacts_) {
      if (rc.contact_id == id) {
        score += (double)rc.priority_score / 100.0;
        break;
      }
    }

    // Favorite boost
    if (is_contact_favorite(id)) score += 2.0;

    if (score > 0.0) {
      scored.push_back({id, score});
    }
  }

  std::sort(scored.begin(), scored.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

  std::vector<uint32_t> result;
  for (const auto& [id, score] : scored) {
    result.push_back(id);
    if ((int)result.size() >= max_results) break;
  }
  return result;
}

// ============================================================================
// Export contacts as JSON
// ============================================================================
json DeltaChat::export_contacts_json(const std::vector<uint32_t>& contact_ids) {
  json j = json::array();

  for (auto id : contact_ids) {
    auto it = contacts_.find(id);
    if (it == contacts_.end()) continue;

    const auto& c = it->second;
    json contact_obj;
    contact_obj["id"] = c.id;
    contact_obj["name"] = c.name;
    contact_obj["display_name"] = c.display_name;
    contact_obj["email"] = c.addr;
    contact_obj["color"] = c.color;
    contact_obj["last_seen"] = c.last_seen;
    contact_obj["is_favorite"] = is_contact_favorite(id);
    contact_obj["initials"] = generate_contact_initials(id);

    auto ext_it = contact_extended_.find(id);
    if (ext_it != contact_extended_.end()) {
      const auto& ext = ext_it->second;
      contact_obj["nickname"] = ext.nickname;
      contact_obj["organization"] = ext.organization;
      contact_obj["title"] = ext.title;
      contact_obj["phone"] = ext.phone_number;
      contact_obj["group_tags"] = ext.group_tags;
      contact_obj["source"] = ext.source;
      contact_obj["interaction_count"] = ext.interaction_count;
      contact_obj["last_interaction"] = ext.last_interaction;
    }

    auto bday_it = contact_birthdays_.find(id);
    if (bday_it != contact_birthdays_.end()) {
      contact_obj["birthday"] = bday_it->second.birthday;
      contact_obj["anniversary"] = bday_it->second.anniversary;
    }

    json notes_arr = json::array();
    auto note_it = contact_notes_.find(id);
    if (note_it != contact_notes_.end()) {
      for (const auto& note : note_it->second) {
        json note_obj;
        note_obj["note_id"] = note.note_id;
        note_obj["content"] = note.content;
        note_obj["created_at"] = note.created_at;
        note_obj["pinned"] = note.pinned;
        note_obj["color_tag"] = note.color_tag;
        notes_arr.push_back(note_obj);
      }
    }
    contact_obj["notes"] = notes_arr;

    j.push_back(contact_obj);
  }

  return j;
}

// ============================================================================
// Import contacts from JSON
// ============================================================================
DeltaChat::AddressBookImportResult DeltaChat::import_contacts_json(
    const json& j,
    const ImportOptions& options) {

  std::vector<AddressBookEntry> entries;

  for (const auto& obj : j) {
    AddressBookEntry entry;
    entry.display_name = obj.value("name", obj.value("display_name", ""));
    if (obj.contains("email")) {
      std::string email = obj["email"].get<std::string>();
      if (!email.empty()) {
        entry.emails.push_back(email);
        entry.email_labels.push_back("OTHER");
      }
    }
    if (obj.contains("phone")) {
      std::string phone = obj["phone"].get<std::string>();
      if (!phone.empty()) {
        entry.phone_numbers.push_back(phone);
        entry.phone_labels.push_back("CELL");
      }
    }
    entry.organization = obj.value("organization", "");
    entry.title = obj.value("title", "");
    entry.nickname = obj.value("nickname", "");

    if (obj.contains("group_tags") && obj["group_tags"].is_array()) {
      for (const auto& tag : obj["group_tags"]) {
        entry.group_labels.push_back(tag.get<std::string>());
      }
    }

    entry.notes = obj.value("notes", "");
    entry.system_id = obj.value("id", sha256(entry.display_name + join(entry.emails, ",")));

    entries.push_back(entry);
  }

  return import_from_address_book(entries, options);
}

// ============================================================================
// Duplicate detection report
// ============================================================================
json DeltaChat::get_duplicate_report(double threshold) {
  json report;
  auto candidates = find_merge_candidates(threshold);

  report["total_candidates"] = candidates.size();
  report["total_contacts"] = contacts_.size();
  report["threshold"] = threshold;

  json pairs = json::array();
  for (const auto& cand : candidates) {
    json pair;
    pair["contact_a"] = cand.contact_a;
    pair["contact_b"] = cand.contact_b;
    pair["confidence"] = cand.confidence;
    pair["reason"] = cand.match_reason;
    pair["auto_merge"] = cand.auto_merge;
    pair["name_a"] = contacts_.count(cand.contact_a) ? contacts_[cand.contact_a].name : "";
    pair["name_b"] = contacts_.count(cand.contact_b) ? contacts_[cand.contact_b].name : "";
    pair["email_a"] = contacts_.count(cand.contact_a) ? contacts_[cand.contact_a].addr : "";
    pair["email_b"] = contacts_.count(cand.contact_b) ? contacts_[cand.contact_b].addr : "";
    pairs.push_back(pair);
  }
  report["pairs"] = pairs;

  return report;
}

// ============================================================================
// Initialize the DeltaChat address book subsystem
// ============================================================================
void DeltaChat::init_address_book_subsystem() {
  sync_state_ = SyncState();
  sync_state_.sync_interval_seconds = 300;
  sync_state_.next_sync_time = nms() + 300000;
  sync_state_.last_sync_time = 0;
  sync_enabled_ = false;
  address_book_watcher_running_ = false;

  previous_snapshot_ = AddressBookSnapshot();
  last_maintenance_time_ = nms();
}

// ============================================================================
// Periodic maintenance
// ============================================================================
void DeltaChat::perform_address_book_maintenance() {
  int64_t now = nms();

  // Check if sync is due
  if (sync_enabled_ && is_sync_due()) {
    SyncOptions opts;
    opts.update_existing = true;
    opts.handle_deletions = true;
    opts.delete_orphaned_contacts = false;
    sync_address_book(opts);
  }

  // Trim recent contacts if needed
  trim_recent_contacts();

  // Update maintenance timestamp
  last_maintenance_time_ = now;
}

// ============================================================================
// Get address book sync state (for UI)
// ============================================================================
json DeltaChat::get_sync_state_json() {
  json state;
  state["is_running"] = sync_state_.is_running;
  state["last_sync_time"] = sync_state_.last_sync_time;
  state["next_sync_time"] = sync_state_.next_sync_time;
  state["sync_interval_seconds"] = sync_state_.sync_interval_seconds;
  state["total_contacts_in_source"] = sync_state_.total_contacts_in_source;
  state["contacts_added"] = sync_state_.contacts_added;
  state["contacts_updated"] = sync_state_.contacts_updated;
  state["contacts_deleted"] = sync_state_.contacts_deleted;
  state["last_error"] = sync_state_.last_error;
  state["needs_full_rescan"] = sync_state_.needs_full_rescan;
  state["enabled"] = sync_enabled_;
  state["watcher_running"] = address_book_watcher_running_;
  return state;
}

// ============================================================================
// Build complete address book from vCards
// ============================================================================
std::vector<AddressBookEntry> DeltaChat::parse_vcard_string(const std::string& vcard_data) {
  VCardParser parser;
  auto vcards = parser.parse_vcards(vcard_data);
  std::vector<AddressBookEntry> entries;
  for (const auto& vcard : vcards) {
    entries.push_back(vcard_to_entry(vcard));
  }
  return entries;
}

// ============================================================================
// Full-text search across all contact fields
// ============================================================================
std::vector<uint32_t> DeltaChat::full_text_search_contacts(const std::string& query,
                                                              int max_results) {
  std::string q = to_lower(trim(query));
  if (q.empty()) return {};

  std::vector<std::pair<uint32_t, int>> scored; // id, hit count

  for (const auto& [id, c] : contacts_) {
    int hits = 0;

    // Search all fields
    auto search_field = [&](const std::string& field, int weight) {
      std::string lower = to_lower(field);
      size_t pos = 0;
      while ((pos = lower.find(q, pos)) != std::string::npos) {
        hits += weight;
        pos += q.size();
      }
    };

    search_field(c.name, 5);
    search_field(c.display_name, 4);
    search_field(c.addr, 3);
    search_field(c.status, 1);

    auto ext_it = contact_extended_.find(id);
    if (ext_it != contact_extended_.end()) {
      search_field(ext_it->second.nickname, 3);
      search_field(ext_it->second.organization, 2);
      search_field(ext_it->second.title, 2);
      search_field(ext_it->second.phone_number, 2);
      search_field(ext_it->second.private_notes, 1);
      for (const auto& tag : ext_it->second.group_tags) {
        search_field(tag, 1);
      }
    }

    if (hits > 0) {
      scored.push_back({id, hits});
    }
  }

  std::sort(scored.begin(), scored.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

  std::vector<uint32_t> result;
  for (const auto& [id, score] : scored) {
    result.push_back(id);
    if ((int)result.size() >= max_results) break;
  }
  return result;
}

// ============================================================================
// Contact block/unblock from address book
// ============================================================================
bool DeltaChat::block_imported_contact(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return false;
  it->second.blocked = 1;
  return true;
}

bool DeltaChat::unblock_imported_contact(uint32_t contact_id) {
  auto it = contacts_.find(contact_id);
  if (it == contacts_.end()) return false;
  it->second.blocked = 0;
  return true;
}

std::vector<uint32_t> DeltaChat::get_blocked_imported_contacts() {
  std::vector<uint32_t> blocked;
  for (const auto& [id, c] : contacts_) {
    if (c.blocked) blocked.push_back(id);
  }
  return blocked;
}

// ============================================================================
// Merge specific pair of contacts (manual merge trigger)
// ============================================================================
uint32_t DeltaChat::manual_merge_contacts(uint32_t id_a, uint32_t id_b,
                                             bool keep_a) {
  if (keep_a) {
    return merge_contacts(id_a, id_b);
  } else {
    return merge_contacts(id_b, id_a);
  }
}

} // namespace progressive::deltachat
