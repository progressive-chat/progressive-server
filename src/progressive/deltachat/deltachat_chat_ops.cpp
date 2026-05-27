// deltachat_chat_ops.cpp - DeltaChat full message processing pipeline & chat operations
// Implements: incoming pipeline, outgoing pipeline, chat detection/creation,
// member management, threading, quoting, ephemeral messages, read receipts,
// dedup, contact import, chat list ordering, trash/delete, archive, pin,
// mute, chat colors, and draft message handling.
//
// References DeltaChat core class from deltachat.hpp
#include "deltachat.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Conditional includes for real SMTP/IMAP/MIME
#if defined(DC_USE_CURL)
#include <curl/curl.h>
#endif
#if defined(DC_USE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#endif

namespace progressive::deltachat {

using json = nlohmann::json;

// ============================================================================
// Internal forward declarations & helpers
// ============================================================================

namespace {

// Thread-safe time helper
int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// Token generation (for Message-IDs, etc.)
static const char kAlphanum[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

std::string gen_token(size_t len = 32) {
  static thread_local std::mt19937_64 rng(
      std::chrono::steady_clock::now().time_since_epoch().count());
  std::uniform_int_distribution<size_t> dist(0, sizeof(kAlphanum) - 2);
  std::string out(len, '\0');
  for (auto& c : out) c = kAlphanum[dist(rng)];
  return out;
}

std::string gen_message_id(const std::string& domain) {
  return "<" + gen_token(16) + "." + std::to_string(now_ms()) + "@" + domain +
         ">";
}

// MIME header parsing helpers
std::string extract_header(const std::string& headers,
                           const std::string& name) {
  std::string search = name + ":";
  size_t pos = 0;
  while (pos < headers.size()) {
    size_t found = headers.find(search, pos);
    if (found == std::string::npos) return "";
    // Check if it's at the start of a line
    if (found == 0 || headers[found - 1] == '\n') {
      found += search.size();
      while (found < headers.size() && headers[found] == ' ') found++;
      size_t end = headers.find('\n', found);
      if (end == std::string::npos) end = headers.size();
      std::string val = headers.substr(found, end - found);
      // Trim trailing \r
      if (!val.empty() && val.back() == '\r') val.pop_back();
      return val;
    }
    pos = found + 1;
  }
  return "";
}

// MIME header folding: unwrap continuation lines
std::string unwrap_header_value(const std::string& raw) {
  std::string out;
  out.reserve(raw.size());
  for (size_t i = 0; i < raw.size(); i++) {
    if (raw[i] == '\r' && i + 1 < raw.size() && raw[i + 1] == '\n') {
      if (i + 2 < raw.size() && (raw[i + 2] == ' ' || raw[i + 2] == '\t')) {
        i += 2;  // skip CRLF + whitespace, continue line
        continue;
      }
    }
    if (raw[i] == '\n' && i + 1 < raw.size() &&
        (raw[i + 1] == ' ' || raw[i + 1] == '\t')) {
      i += 1;  // skip LF + whitespace
      continue;
    }
    out.push_back(raw[i]);
  }
  return out;
}

// Fold a long header line (RFC 5322: 78 char soft limit)
std::string fold_header(const std::string& name, const std::string& value,
                        size_t soft_limit = 74) {
  if (name.size() + value.size() + 2 <= soft_limit + 4) {
    return name + ": " + value + "\r\n";
  }
  std::string out = name + ": ";
  size_t pos = 0;
  bool first = true;
  while (pos < value.size()) {
    if (!first) out += " ";
    size_t chunk = soft_limit - (first ? name.size() + 2 : 1);
    if (pos + chunk >= value.size()) {
      out += value.substr(pos);
      break;
    }
    // Try to break at whitespace
    size_t break_at = pos + chunk;
    while (break_at > pos && value[break_at] != ' ') break_at--;
    if (break_at == pos) break_at = pos + chunk;  // no space, force break
    out += value.substr(pos, break_at - pos);
    if (break_at < value.size()) out += "\r\n";
    pos = break_at;
    while (pos < value.size() && value[pos] == ' ') pos++;
    first = false;
  }
  out += "\r\n";
  return out;
}

// Address parsing: extract email address from "Display Name <addr>" format
std::string extract_addr(const std::string& raw) {
  size_t lt = raw.find('<');
  size_t gt = raw.find('>');
  if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
    return raw.substr(lt + 1, gt - lt - 1);
  }
  // Plain email
  auto trimmed = raw;
  while (!trimmed.empty() && trimmed.front() == ' ') trimmed.erase(0, 1);
  while (!trimmed.empty() && trimmed.back() == ' ') trimmed.pop_back();
  return trimmed;
}

std::string extract_display_name(const std::string& raw) {
  size_t lt = raw.find('<');
  if (lt != std::string::npos) {
    auto name = raw.substr(0, lt);
    while (!name.empty() && name.back() == ' ') name.pop_back();
    if (!name.empty() && name.front() == '"' && name.back() == '"')
      name = name.substr(1, name.size() - 2);
    return name;
  }
  return raw;
}

// Base64 encoding / decoding (simple implementation)
static const char kBase64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  int val = 0, valb = -6;
  for (unsigned char c : data) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(kBase64[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    out.push_back(kBase64[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4) out.push_back('=');
  return out;
}

std::string base64_decode(const std::string& data) {
  std::string out;
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++) T[(unsigned char)kBase64[i]] = i;
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

// Chunked quoted-printable encode
std::string qp_encode(const std::string& data, size_t line_len = 76) {
  std::string out;
  size_t col = 0;
  for (unsigned char c : data) {
    bool encode = (c < 32 || c == '=' || c > 126);
    auto flush = [&](const std::string& s) {
      for (char ch : s) {
        if (col >= line_len) {
          out += "=\r\n";
          col = 0;
        }
        out += ch;
        col++;
      }
    };
    if (c == '\r' && col > 0) {
      out += "\r\n";
      col = 0;
    } else if (c == '\n' && col > 0) {
      out += "\r\n";
      col = 0;
    } else if (encode) {
      char buf[4];
      snprintf(buf, sizeof(buf), "=%02X", c);
      flush(buf);
    } else {
      flush(std::string(1, (char)c));
    }
  }
  return out;
}

// ==========================================================================
// MIME message structure
// ==========================================================================
struct MimePart {
  std::string content_type;         // e.g. "text/plain; charset=utf-8"
  std::string content_transfer_encoding;  // "7bit", "base64", "quoted-printable"
  std::string content_disposition;  // e.g. "attachment; filename=\"...\""
  std::string content_id;
  std::map<std::string, std::string> extra_headers;
  std::string body;           // decoded body
  std::string raw_body;       // encoded body (for forwarding)
  std::vector<MimePart> subparts;
  bool is_multipart = false;
  std::string multipart_boundary;
};

struct ParsedMime {
  std::string raw_headers;
  std::map<std::string, std::string> headers;
  std::string subject;
  std::string from;
  std::string to;
  std::string cc;
  std::string date;
  std::string message_id;
  std::string in_reply_to;
  std::string references;
  std::string chat_group_id;
  std::string chat_group_name;
  std::string chat_group_name_changed;
  std::string chat_group_member_added;
  std::string chat_group_member_removed;
  std::string chat_user_avatar;
  std::string chat_ephemeral_timer;
  std::string autocrypt_header;
  std::string autocrypt_setup_message;
  std::string mdn_receipt_to;       // Disposition-Notification-To
  std::string content_type;
  MimePart root_part;
  std::string raw_body;
  std::string decoded_text;
  bool is_encrypted = false;
  bool is_signed = false;
  std::string decrypted_text;
  std::string decrypted_mime;       // full MIME after decryption
};

// ==========================================================================
// Chat Ops internal state
// ==========================================================================
// We maintain an internal cache for chat operations that extends
// DeltaChat's in-memory stores with operational state.

struct ChatOpsState {
  // Trash
  std::set<uint32_t> trash_folder;            // chat_ids in trash
  std::unordered_map<uint32_t, int64_t> trash_timestamp;

  // Archive
  std::set<uint32_t> archived_chats;

  // Pin
  std::set<uint32_t> pinned_chats;
  std::unordered_map<uint32_t, int64_t> pin_timestamp;

  // Mute
  std::unordered_map<uint32_t, int64_t> muted_until;  // timestamp until muted

  // Chat colors
  std::unordered_map<uint32_t, std::string> chat_colors;

  // Drafts
  std::unordered_map<uint32_t, std::string> drafts;  // chat_id -> draft text

  // Ephemeral countdown per message
  std::unordered_map<uint32_t, int64_t>
      ephemeral_expiry;  // msg_id -> expiry timestamp ms

  // Read receipts: map msg_id -> set of contact_ids that sent MDN
  std::unordered_map<uint32_t, std::set<uint32_t>> read_receipts;

  // Sent message tracking for dedup (message_id -> internal_msg_id)
  std::unordered_map<std::string, uint32_t> sent_message_ids;

  // Thread mapping: parent message_id -> set of child msg_ids
  std::unordered_map<std::string, std::vector<uint32_t>> thread_children;

  // Chat member tracking: chat_id -> set of contact_ids
  std::unordered_map<uint32_t, std::set<uint32_t>> chat_members;

  // Notification counts: chat_id -> unread count
  std::unordered_map<uint32_t, int> notification_counts;

  // Mutex for thread safety
  std::recursive_mutex mtx;

  // Last cleanup timestamp
  int64_t last_cleanup_ts = 0;
};

// Singleton-like instance (owned by the translation unit)
static ChatOpsState g_state;

// Color palette for automatic chat color assignment
static const char* kColorPalette[] = {
    "#E53935",  // Red
    "#1E88E5",  // Blue
    "#43A047",  // Green
    "#FB8C00",  // Orange
    "#8E24AA",  // Purple
    "#00ACC1",  // Cyan
    "#F4511E",  // Deep Orange
    "#3949AB",  // Indigo
    "#00897B",  // Teal
    "#C0CA33",  // Lime
    "#6D4C41",  // Brown
    "#546E7A",  // Blue Grey
    "#D81B60",  // Pink
    "#5E35B1",  // Deep Purple
    "#039BE5",  // Light Blue
    "#7CB342",  // Light Green
};
static constexpr size_t kColorPaletteSize =
    sizeof(kColorPalette) / sizeof(kColorPalette[0]);

// ==========================================================================
// Lock helpers
// ==========================================================================
#define CHATOPS_LOCK() std::lock_guard<std::recursive_mutex> _lk(g_state.mtx)

// ==========================================================================
// Section 1: Incoming Message Processing Pipeline
// ==========================================================================
// Pipeline stages: Fetch -> Parse -> Decrypt -> Detect Chat -> Store -> Notify
// ==========================================================================

// --------------------------------------------------------------------------
// Stage 1: Parse raw MIME message into ParsedMime structure
// --------------------------------------------------------------------------
ParsedMime parse_raw_mime(const std::string& raw) {
  ParsedMime pm;

  // Split headers from body
  size_t header_end = raw.find("\r\n\r\n");
  if (header_end == std::string::npos)
    header_end = raw.find("\n\n");
  if (header_end == std::string::npos) {
    pm.raw_headers = raw;
    return pm;
  }

  pm.raw_headers =
      raw.substr(0, header_end + (raw[header_end] == '\r' ? 4 : 2));
  pm.raw_body = raw.substr(
      header_end + (raw[header_end] == '\r' ? 4 : 2));

  // Parse individual headers
  std::string header_block = pm.raw_headers;
  // Normalize line endings
  for (size_t i = 0; i < header_block.size(); i++) {
    if (header_block[i] == '\n' && (i == 0 || header_block[i - 1] != '\r')) {
      header_block.insert(i, "\r");
      i++;
    }
  }

  size_t pos = 0;
  std::string current_header_name;
  std::string current_header_value;
  bool in_continuation = false;

  while (pos < header_block.size()) {
    size_t eol = header_block.find("\r\n", pos);
    if (eol == std::string::npos) break;

    std::string line = header_block.substr(pos, eol - pos);
    pos = eol + 2;

    // Check if continuation line (starts with space or tab)
    if (!line.empty() && (line[0] == ' ' || line[0] == '\t') &&
        in_continuation) {
      // Unwrap continuation
      while (!line.empty() && (line[0] == ' ' || line[0] == '\t'))
        line.erase(0, 1);
      current_header_value += " " + line;
      continue;
    }

    // Finalize previous header
    if (!current_header_name.empty() && in_continuation) {
      pm.headers[current_header_name] = current_header_value;
    }

    // Parse new header
    size_t colon = line.find(':');
    if (colon == std::string::npos) {
      in_continuation = false;
      continue;  // skip malformed line
    }

    current_header_name = line.substr(0, colon);
    // Lowercase for case-insensitive lookup
    std::string lower_name = current_header_name;
    for (auto& c : lower_name) c = (char)std::tolower((unsigned char)c);

    current_header_value = line.substr(colon + 1);
    while (!current_header_value.empty() && current_header_value.front() == ' ')
      current_header_value.erase(0, 1);
    while (!current_header_value.empty() && current_header_value.back() == '\r')
      current_header_value.pop_back();

    pm.headers[lower_name] = current_header_value;
    in_continuation = true;
  }
  // Finalize last header
  if (!current_header_name.empty() && in_continuation) {
    pm.headers[current_header_name] = current_header_value;
  }

  // Extract standard headers
  pm.subject = extract_header(pm.raw_headers, "Subject");
  pm.from = extract_header(pm.raw_headers, "From");
  pm.to = extract_header(pm.raw_headers, "To");
  pm.cc = extract_header(pm.raw_headers, "Cc");
  pm.date = extract_header(pm.raw_headers, "Date");
  pm.message_id = extract_header(pm.raw_headers, "Message-ID");
  pm.in_reply_to = extract_header(pm.raw_headers, "In-Reply-To");
  pm.references = extract_header(pm.raw_headers, "References");
  pm.content_type = extract_header(pm.raw_headers, "Content-Type");

  // DeltaChat-specific headers
  pm.chat_group_id = extract_header(pm.raw_headers, "Chat-Group-ID");
  pm.chat_group_name = extract_header(pm.raw_headers, "Chat-Group-Name");
  pm.chat_group_name_changed =
      extract_header(pm.raw_headers, "Chat-Group-Name-Changed");
  pm.chat_group_member_added =
      extract_header(pm.raw_headers, "Chat-Group-Member-Added");
  pm.chat_group_member_removed =
      extract_header(pm.raw_headers, "Chat-Group-Member-Removed");
  pm.chat_user_avatar = extract_header(pm.raw_headers, "Chat-User-Avatar");
  pm.chat_ephemeral_timer =
      extract_header(pm.raw_headers, "Chat-Ephemeral-Timer");
  pm.autocrypt_header = extract_header(pm.raw_headers, "Autocrypt");
  pm.autocrypt_setup_message =
      extract_header(pm.raw_headers, "Autocrypt-Setup-Message");
  pm.mdn_receipt_to =
      extract_header(pm.raw_headers, "Disposition-Notification-To");

  // Parse body content type and decode
  pm.root_part.content_type = pm.content_type;
  pm.root_part.body = pm.raw_body;

  // Parse multipart boundaries
  if (pm.content_type.find("multipart/") == 0) {
    pm.root_part.is_multipart = true;
    std::string boundary_str = "boundary=";
    size_t bp = pm.content_type.find(boundary_str);
    if (bp != std::string::npos) {
      bp += boundary_str.size();
      if (bp < pm.content_type.size() && pm.content_type[bp] == '"') {
        bp++;
        size_t be = pm.content_type.find('"', bp);
        if (be != std::string::npos)
          pm.root_part.multipart_boundary = pm.content_type.substr(bp, be - bp);
      } else {
        size_t be = pm.content_type.find(';', bp);
        if (be == std::string::npos) be = pm.content_type.size();
        pm.root_part.multipart_boundary = pm.content_type.substr(bp, be - bp);
        // trim trailing whitespace
        while (!pm.root_part.multipart_boundary.empty() &&
               pm.root_part.multipart_boundary.back() == ' ')
          pm.root_part.multipart_boundary.pop_back();
      }
    }

    // Parse sub-parts
    if (!pm.root_part.multipart_boundary.empty()) {
      std::string delim = "--" + pm.root_part.multipart_boundary;
      size_t part_start = pm.raw_body.find(delim);
      if (part_start != std::string::npos) {
        part_start += delim.size();
        if (part_start < pm.raw_body.size() &&
            pm.raw_body[part_start] == '\r')
          part_start++;
        if (part_start < pm.raw_body.size() &&
            pm.raw_body[part_start] == '\n')
          part_start++;

        while (part_start < pm.raw_body.size()) {
          size_t next_delim = pm.raw_body.find(delim, part_start);
          if (next_delim == std::string::npos) break;

          std::string part_raw =
              pm.raw_body.substr(part_start, next_delim - part_start);

          MimePart sub;
          // Parse sub-part headers
          size_t sub_header_end = part_raw.find("\r\n\r\n");
          if (sub_header_end == std::string::npos)
            sub_header_end = part_raw.find("\n\n");
          if (sub_header_end != std::string::npos) {
            std::string sub_headers =
                part_raw.substr(0, sub_header_end);
            std::string sub_body = part_raw.substr(
                sub_header_end +
                (part_raw[sub_header_end] == '\r' ? 4 : 2));

            sub.content_type =
                extract_header(sub_headers, "Content-Type");
            sub.content_transfer_encoding =
                extract_header(sub_headers, "Content-Transfer-Encoding");
            sub.content_disposition =
                extract_header(sub_headers, "Content-Disposition");
            sub.content_id = extract_header(sub_headers, "Content-ID");
            sub.raw_body = sub_body;

            // Decode based on transfer encoding
            std::string te = sub.content_transfer_encoding;
            for (auto& c : te) c = (char)std::tolower((unsigned char)c);
            if (te == "base64") {
              sub.body = base64_decode(sub_body);
            } else if (te.find("quoted-printable") != std::string::npos) {
              // Simple QP decode
              std::string decoded;
              for (size_t i = 0; i < sub_body.size(); i++) {
                if (sub_body[i] == '=' && i + 2 < sub_body.size() &&
                    sub_body[i + 1] == '\r' && sub_body[i + 2] == '\n') {
                  i += 2;  // soft line break
                } else if (sub_body[i] == '=' && i + 1 < sub_body.size() &&
                           sub_body[i + 1] == '\n') {
                  i += 1;  // soft line break (no \r)
                } else if (sub_body[i] == '=' && i + 2 < sub_body.size()) {
                  // hex encoded char
                  int hi = sub_body[i + 1], lo = sub_body[i + 2];
                  auto hex = [](int c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    return 0;
                  };
                  decoded.push_back((char)(hex(hi) * 16 + hex(lo)));
                  i += 2;
                } else {
                  decoded.push_back(sub_body[i]);
                }
              }
              sub.body = decoded;
            } else {
              sub.body = sub_body;
            }

            pm.root_part.subparts.push_back(std::move(sub));
          }

          // Move past delimiter
          part_start = next_delim + delim.size();
          // Check for "--" terminator
          if (part_start < pm.raw_body.size() &&
              pm.raw_body[part_start] == '-' &&
              part_start + 1 < pm.raw_body.size() &&
              pm.raw_body[part_start + 1] == '-') {
            break;
          }
          if (part_start < pm.raw_body.size() &&
              pm.raw_body[part_start] == '\r')
            part_start++;
          if (part_start < pm.raw_body.size() &&
              pm.raw_body[part_start] == '\n')
            part_start++;
        }
      }
    }
  }

  // Extract decoded text from the first text/plain part
  // Walk subparts to find text/plain
  std::function<void(const MimePart&)> extract_text =
      [&](const MimePart& p) {
        if (!pm.decoded_text.empty()) return;
        if (p.content_type.find("text/plain") != std::string::npos) {
          pm.decoded_text = p.body;
          return;
        }
        for (auto& sub : p.subparts) {
          extract_text(sub);
          if (!pm.decoded_text.empty()) return;
        }
      };
  if (pm.root_part.is_multipart) {
    for (auto& sub : pm.root_part.subparts) {
      extract_text(sub);
      if (!pm.decoded_text.empty()) break;
    }
  } else if (pm.content_type.find("text/plain") != std::string::npos) {
    pm.decoded_text = pm.root_part.body;
  }

  return pm;
}

// --------------------------------------------------------------------------
// Stage 2: Decrypt Autocrypt/PGP encrypted messages
// --------------------------------------------------------------------------
struct DecryptResult {
  bool success = false;
  std::string plaintext;      // decrypted message text
  std::string full_mime;      // full MIME after decryption
  bool was_encrypted = false;
  bool was_signed = false;
  std::string signer_fpr;     // fingerprint of signer if signed
};

DecryptResult decrypt_incoming_message(DeltaChat& dc, const ParsedMime& pm) {
  DecryptResult r;

  // Check if encrypted
  if (pm.content_type.find("multipart/encrypted") != std::string::npos ||
      pm.autocrypt_header.find("keydata=") != std::string::npos) {
    r.was_encrypted = true;
  }

  // Check for PGP/MIME encryption (multipart/encrypted with protocol="application/pgp-encrypted")
  if (pm.root_part.is_multipart) {
    for (auto& sub : pm.root_part.subparts) {
      if (sub.content_type.find("application/pgp-encrypted") !=
          std::string::npos) {
        r.was_encrypted = true;
        break;
      }
      if (sub.content_type.find("application/octet-stream") !=
              std::string::npos &&
          (sub.content_disposition.find("encrypted.asc") !=
               std::string::npos ||
           sub.content_disposition.find("pgp") != std::string::npos)) {
        r.was_encrypted = true;
        break;
      }
    }
  }

  // If it's Autocrypt encrypted, look for the encrypted payload
  if (!pm.autocrypt_header.empty()) {
    r.was_encrypted = true;
    // Parse Autocrypt header: addr=a; prefer-encrypt=mutual; keydata=...
    std::string keydata;
    size_t kp = pm.autocrypt_header.find("keydata=");
    if (kp != std::string::npos) {
      keydata = pm.autocrypt_header.substr(kp + 8);
      // Remove trailing params
      size_t semi = keydata.find(';');
      if (semi != std::string::npos) keydata = keydata.substr(0, semi);
    }
  }

  // For PGP/MIME inline encrypted messages (-----BEGIN PGP MESSAGE-----)
  // or Autocrypt encrypted payload
  bool found_pgp_msg = false;
  std::string pgp_data;

  // Check in decoded text
  if (pm.decoded_text.find("-----BEGIN PGP MESSAGE-----") !=
      std::string::npos) {
    found_pgp_msg = true;
    pgp_data = pm.decoded_text;
  }

  // Check in subparts for application/pgp-encrypted
  if (!found_pgp_msg) {
    for (auto& sub : pm.root_part.subparts) {
      if (sub.body.find("-----BEGIN PGP MESSAGE-----") != std::string::npos) {
        found_pgp_msg = true;
        pgp_data = sub.body;
        break;
      }
    }
  }

  if (found_pgp_msg) {
    r.was_encrypted = true;

#if defined(DC_USE_OPENSSL)
    // Attempt decryption with OpenSSL
    // In production this would use GnuPG or OpenSSL EVP_PKEY decrypt
    // For now, extract the PGP message and attempt basic key-based decryption
    size_t begin = pgp_data.find("-----BEGIN PGP MESSAGE-----");
    size_t end = pgp_data.find("-----END PGP MESSAGE-----");
    if (begin != std::string::npos && end != std::string::npos) {
      end += strlen("-----END PGP MESSAGE-----");
      std::string armored = pgp_data.substr(begin, end - begin);

      // Look for Version header inside PGP block
      // Real impl would base64-decode, then decrypt with recipient key
      // Stub: attempt base64 decode of the body between markers
      size_t blank_line = armored.find("\n\n");
      if (blank_line == std::string::npos) blank_line = armored.find("\r\n\r\n");
      if (blank_line != std::string::npos) {
        std::string b64_body = armored.substr(
            blank_line + (armored[blank_line] == '\r' ? 4 : 2));
        // Remove checksum line (starts with '=')
        size_t csum = b64_body.rfind("\n=");
        if (csum != std::string::npos) b64_body = b64_body.substr(0, csum);
        // Remove whitespace
        b64_body.erase(std::remove_if(b64_body.begin(), b64_body.end(),
                                       [](char c) {
                                         return c == '\r' || c == '\n' ||
                                                c == ' ' || c == '\t';
                                       }),
                       b64_body.end());

        std::string decoded = base64_decode(b64_body);

        // If we have a key configured, attempt real decryption
        std::string priv_key = dc.get_config("self_private_key");
        if (!priv_key.empty()) {
          // OpenSSL EVP decryption would go here
          // r.plaintext = openssl_pgp_decrypt(decoded, priv_key);
          r.plaintext = decoded;  // placeholder
          r.success = !r.plaintext.empty();
        } else {
          // No key available, store as encrypted
          r.plaintext = "[Encrypted message - unable to decrypt]";
          r.success = false;
        }
      }
    }
#else
    r.plaintext = "[Encrypted message - OpenSSL not available]";
    r.success = false;
#endif

    // Check for PGP signed message
    if (r.plaintext.find("-----BEGIN PGP SIGNED MESSAGE-----") !=
        std::string::npos) {
      r.was_signed = true;
      size_t sig_start =
          r.plaintext.find("-----BEGIN PGP SIGNED MESSAGE-----");
      size_t sig_end =
          r.plaintext.find("-----END PGP SIGNATURE-----");
      if (sig_start != std::string::npos && sig_end != std::string::npos) {
        // Extract actual message between hash lines and signature
        size_t hash_end = r.plaintext.find("\n\n", sig_start);
        if (hash_end == std::string::npos)
          hash_end = r.plaintext.find("\r\n\r\n", sig_start);
        if (hash_end != std::string::npos) {
          std::string signed_text = r.plaintext.substr(
              hash_end + (r.plaintext[hash_end] == '\r' ? 4 : 2),
              sig_end - hash_end - 4);
          r.plaintext = signed_text;
        }
      }
    }
  } else if (!pm.autocrypt_header.empty() && !r.was_encrypted) {
    // Autocrypt header present but no encrypted payload
    // This is a normal message with Autocrypt key advertisement
    r.was_encrypted = false;
    r.plaintext = pm.decoded_text;
    r.success = true;
  } else {
    // Not encrypted at all
    r.plaintext = pm.decoded_text;
    r.success = true;
  }

  return r;
}

// --------------------------------------------------------------------------
// Stage 3: Detect which chat a message belongs to
// --------------------------------------------------------------------------
struct ChatDetectionResult {
  uint32_t chat_id = 0;
  bool is_new_chat = false;
  bool is_group = false;
  std::string group_id;      // Chat-Group-ID value
  std::string group_name;
  std::vector<uint32_t> member_ids;
  int chat_type = 0;         // 100 = group, 110 = 1:1 single
};

ChatDetectionResult detect_chat(DeltaChat& dc, const ParsedMime& pm,
                                const std::string& from_addr) {
  ChatDetectionResult r;

  // Check for Chat-Group-ID header (identifies group chats)
  if (!pm.chat_group_id.empty()) {
    r.group_id = pm.chat_group_id;
    r.is_group = true;
    // Look up existing chat by group ID
    uint32_t existing = dc.get_chat_id_by_grpid(pm.chat_group_id);
    if (existing > 0) {
      r.chat_id = existing;
    } else {
      r.is_new_chat = true;
    }
  }

  // Check for Chat-Group-Name header (group name suggestion)
  if (!pm.chat_group_name.empty()) {
    r.group_name = pm.chat_group_name;
  }

  // If no group ID, this is a 1:1 chat
  if (r.group_id.empty()) {
    r.is_group = false;
    r.chat_type = 110;
    // Look up contact by from_addr
    uint32_t contact_id = dc.lookup_contact_id_by_addr(from_addr);
    if (contact_id == 0) {
      // Auto-create contact
      std::string display_name = extract_display_name(pm.from);
      contact_id = dc.create_contact(display_name, from_addr);
    }
    // Find or create 1:1 chat
    uint32_t chat_id = dc.get_chat_id_by_contact_id(contact_id);
    if (chat_id == 0) {
      r.is_new_chat = true;
    } else {
      r.chat_id = chat_id;
    }
    r.member_ids.push_back(contact_id);
  }

  return r;
}

// --------------------------------------------------------------------------
// Stage 4: Store the message in the database / in-memory store
// --------------------------------------------------------------------------
uint32_t store_incoming_message(DeltaChat& dc, const ParsedMime& pm,
                                const DecryptResult& dr,
                                const ChatDetectionResult& cdr,
                                const std::string& from_addr,
                                uint32_t contact_id) {
  CHATOPS_LOCK();

  // Dedup: check if this Message-ID was already processed
  if (!pm.message_id.empty()) {
    auto it = g_state.sent_message_ids.find(pm.message_id);
    if (it != g_state.sent_message_ids.end()) {
      // This is our own message (Bcc-Self)
      return it->second;  // Return existing msg id
    }
  }

  // Determine message flags
  int flags = 0;
  if (dr.was_encrypted) flags |= 0x04;   // DC_FM_ENC
  if (dr.was_signed) flags |= 0x08;      // DC_FM_SIGNED

  // Determine message state
  int state = 10;  // DC_STATE_IN_FRESH (incoming fresh)

  // Determine chat_id
  uint32_t chat_id = cdr.chat_id;
  if (chat_id == 0 && cdr.is_new_chat) {
    // Create the chat now
    if (cdr.is_group) {
      chat_id = dc.create_group_chat(false, cdr.group_name);
      DcChat chat = dc.get_chat(chat_id);
      chat.grpid = cdr.group_id;
      chat.type = 100;  // DC_CHAT_TYPE_GROUP
      // We can't set grpid back through public API, so store internally
      // In production, this would update the DB
    } else {
      chat_id = dc.create_chat_by_contact_id(cdr.member_ids.empty()
                                                 ? contact_id
                                                 : cdr.member_ids[0]);
    }
  }

  // Parse timestamp from Date header
  int64_t ts = now_ms();
  if (!pm.date.empty()) {
    // Try to parse RFC 5322 date
    // Example: "Thu, 21 Dec 2024 16:01:07 +0000"
    struct tm tm = {};
    std::string ds = pm.date;
    // Simple parse: find day, month, year, time
    // This is simplified - production would use a real date parser
    size_t comma = ds.find(',');
    if (comma != std::string::npos) ds = ds.substr(comma + 1);
    while (!ds.empty() && ds.front() == ' ') ds.erase(0, 1);

    // Parse "21 Dec 2024 16:01:07 +0000"
    int day = 1, year = 2024, hour = 0, min = 0, sec = 0;
    char mon_str[4] = {};
    if (sscanf(ds.c_str(), "%d %3s %d %d:%d:%d", &day, mon_str, &year, &hour,
               &min, &sec) >= 3) {
      static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
      int mon = 0;
      for (int i = 0; i < 12; i++) {
        if (strcasecmp(mon_str, months[i]) == 0) {
          mon = i;
          break;
        }
      }
      tm.tm_mday = day;
      tm.tm_mon = mon;
      tm.tm_year = year - 1900;
      tm.tm_hour = hour;
      tm.tm_min = min;
      tm.tm_sec = sec;
      time_t t = timegm(&tm);
      if (t != (time_t)-1) ts = (int64_t)t * 1000;
    }
  }

  // Build message text
  std::string text = dr.plaintext;
  if (text.empty()) text = pm.decoded_text;

  // Create the message via DeltaChat API
  // We'll build a DcMessage manually for completeness
  DcMessage msg;
  msg.id = dc.send_msg(chat_id, text);
  msg.chat_id = (int)chat_id;
  msg.from_id = (int)contact_id;
  msg.timestamp = ts;
  msg.sort_timestamp = ts;
  msg.received_timestamp = now_ms();
  msg.flags = flags;
  msg.state = state;
  msg.text = text;
  msg.rfc724_mid = pm.message_id;
  msg.subject = pm.subject;
  msg.mime_headers = pm.raw_headers;
  msg.mime_in_reply_to = pm.in_reply_to;
  msg.mime_references = pm.references;

  // Check for ephemeral timer
  if (!pm.chat_ephemeral_timer.empty()) {
    int64_t timer_sec = 0;
    try {
      timer_sec = std::stoll(pm.chat_ephemeral_timer);
    } catch (...) {
    }
    if (timer_sec > 0) {
      msg.ephemeral_timestamp = now_ms() + timer_sec * 1000;
      g_state.ephemeral_expiry[msg.id] = msg.ephemeral_timestamp;
    }
  }

  // Store in DeltaChat (Update the message that send_msg created)
  // In production, this would update the DB record

  // Track sent messages for dedup
  if (!pm.message_id.empty()) {
    g_state.sent_message_ids[pm.message_id] = msg.id;
  }

  // Update notification count
  g_state.notification_counts[chat_id]++;

  return msg.id;
}

// --------------------------------------------------------------------------
// Stage 5: Trigger notification callbacks
// --------------------------------------------------------------------------
void notify_incoming_message(DeltaChat& dc, uint32_t chat_id, uint32_t msg_id,
                             const std::string& from_addr) {
  CHATOPS_LOCK();

  int fresh_cnt = 0;
  auto it = g_state.notification_counts.find(chat_id);
  if (it != g_state.notification_counts.end()) fresh_cnt = it->second;

  // DC_EVENT_INCOMING_MSG = 2005
  if (dc.event_cb_) {
    dc.event_cb_(2005, chat_id, msg_id);
  }

  // DC_EVENT_MSGS_CHANGED = 1020
  if (dc.event_cb_) {
    dc.event_cb_(1020, chat_id, msg_id);
  }

  // DC_EVENT_FRESH_MSGS_CHANGED = 3000
  if (dc.event_cb_) {
    dc.event_cb_(3000, chat_id, msg_id);
  }
}

// --------------------------------------------------------------------------
// Full incoming pipeline entry point
// --------------------------------------------------------------------------
uint32_t process_incoming_message(DeltaChat& dc, const std::string& raw_mime) {
  // Stage 1: Parse
  ParsedMime pm = parse_raw_mime(raw_mime);

  // Extract sender address
  std::string from_addr = extract_addr(pm.from);

  // Stage 1.5: Sent message dedup check
  {
    CHATOPS_LOCK();
    // Check Bcc-Self: if this message was sent by us, skip it
    bool bcc_self = dc.get_config("bcc_self") == "1";
    std::string self_addr = dc.get_config("addr");
    if (!self_addr.empty() && from_addr == self_addr && bcc_self) {
      // This is our own message coming back via Bcc
      // Mark it as seen and don't notify
      auto sit = g_state.sent_message_ids.find(pm.message_id);
      if (sit != g_state.sent_message_ids.end()) {
        return sit->second;  // Already tracked
      }
    }
  }

  // Stage 2: Decrypt
  DecryptResult dr = decrypt_incoming_message(dc, pm);

  // Stage 3: Detect chat
  ChatDetectionResult cdr = detect_chat(dc, pm, from_addr);

  // Lookup or create contact for sender
  uint32_t contact_id = dc.lookup_contact_id_by_addr(from_addr);
  if (contact_id == 0) {
    std::string display_name = extract_display_name(pm.from);
    contact_id = dc.create_contact(display_name, from_addr);
    // Section 13: Contact import from incoming messages
    // Import additional info: display name, profile image if available
    if (!display_name.empty() && display_name != from_addr) {
      dc.set_contact_name(contact_id, display_name);
    }
    // Check for Chat-User-Avatar header
    if (!pm.chat_user_avatar.empty()) {
      dc.set_contact_profile_image(contact_id, pm.chat_user_avatar);
    }
  }

  // Stage 4: Store
  uint32_t msg_id =
      store_incoming_message(dc, pm, dr, cdr, from_addr, contact_id);

  // Section 5: Member addition/removal detection
  if (!pm.chat_group_member_added.empty()) {
    process_member_added(dc, cdr.chat_id, pm.chat_group_member_added);
  }
  if (!pm.chat_group_member_removed.empty()) {
    process_member_removed(dc, cdr.chat_id, pm.chat_group_member_removed);
  }

  // Section 6: Group name changes
  if (!pm.chat_group_name_changed.empty()) {
    process_group_name_change(dc, cdr.chat_id, pm.chat_group_name_changed);
  }

  // Section 7: Group avatar changes
  if (!pm.chat_user_avatar.empty() && cdr.is_group) {
    process_avatar_change(dc, cdr.chat_id, pm.chat_user_avatar, contact_id);
  }

  // Section 8: Message threading
  if (!pm.in_reply_to.empty() || !pm.references.empty()) {
    track_message_thread(dc, msg_id, pm.in_reply_to, pm.references,
                         pm.message_id);
  }

  // Section 11: Read receipt processing
  if (!pm.mdn_receipt_to.empty()) {
    generate_mdn_receipt(dc, msg_id, pm.mdn_receipt_to, pm.message_id);
  }

  // Stage 5: Notify
  notify_incoming_message(dc, cdr.chat_id, msg_id, from_addr);

  return msg_id;
}

// ============================================================================
// Section 2: Outgoing Message Pipeline
// ============================================================================
// Pipeline: Compose -> Encrypt -> Sign -> MIME build -> SMTP send -> Copy to Sent
// ============================================================================

// --------------------------------------------------------------------------
// Stage 1: Compose the message
// --------------------------------------------------------------------------
struct ComposedMessage {
  uint32_t chat_id = 0;
  std::string text;
  std::string subject;
  std::string quoted_text;       // quoted message (for replies)
  std::string quoted_msg_id;     // Message-ID being quoted
  std::string in_reply_to;
  std::string references;
  int64_t ephemeral_timer = 0;   // seconds
  bool is_bot = false;
  std::vector<std::string> recipients;
  std::vector<std::string> attachment_paths;
  std::string parent_chat_group_id;  // Chat-Group-ID of group
  std::string self_addr;
  std::string display_name;
};

ComposedMessage compose_outgoing_message(
    DeltaChat& dc, uint32_t chat_id, const std::string& text,
    const std::string& quoted_msg_id) {
  ComposedMessage cm;
  cm.chat_id = chat_id;
  cm.text = text;
  cm.self_addr = dc.get_config("addr");
  cm.display_name = dc.get_config("display_name");

  // Get chat info
  DcChat chat = dc.get_chat(chat_id);
  cm.parent_chat_group_id = chat.grpid;

  // Check ephemeral timer for the chat
  if (chat.ephemeral_duration > 0) {
    cm.ephemeral_timer = chat.ephemeral_duration;
  }

  // Get recipients for this chat
  std::vector<uint32_t> contacts = dc.get_chat_contacts(chat_id);
  for (uint32_t cid : contacts) {
    DcContact c = dc.get_contact(cid);
    if (!c.addr.empty() && c.addr != cm.self_addr) {
      cm.recipients.push_back(c.addr);
    }
  }

  // Handle quoting
  if (!quoted_msg_id.empty()) {
    try {
      uint32_t qmid = (uint32_t)std::stoul(quoted_msg_id);
      DcMessage quoted = dc.get_msg(qmid);
      if (quoted.id != 0) {
        cm.quoted_msg_id = quoted.rfc724_mid;
        cm.in_reply_to = quoted.rfc724_mid;

        // Format quoted text
        std::string qtext = quoted.text;
        // Truncate long quoted text
        if (qtext.size() > 500) {
          qtext = qtext.substr(0, 497) + "...";
        }
        // Add quote marker
        std::istringstream qss(qtext);
        std::string qline;
        std::string formatted_quote;
        while (std::getline(qss, qline)) {
          formatted_quote += "> " + qline + "\n";
        }

        // Get sender name
        DcContact qsender = dc.get_contact(quoted.from_id);
        std::string qname = qsender.display_name.empty() ? qsender.addr
                                                           : qsender.display_name;

        cm.quoted_text = qname + " wrote:\n" + formatted_quote;
        cm.text = cm.text + "\n\n" + cm.quoted_text;

        // Build references header
        cm.references = quoted.mime_references;
        if (!cm.references.empty()) cm.references += " ";
        cm.references += quoted.rfc724_mid;
      }
    } catch (...) {
      // Invalid quoted_msg_id, ignore
    }
  }

  return cm;
}

// --------------------------------------------------------------------------
// Stage 2: Encrypt the message (Autocrypt / PGP)
// --------------------------------------------------------------------------
std::string encrypt_outgoing_message(DeltaChat& dc, const ComposedMessage& cm) {
  std::string result = cm.text;

  // Check if encryption is enabled
  std::string e2ee = dc.get_config("e2ee_enabled");
  bool encrypt = (e2ee == "1");

  if (!encrypt) return result;

  // Determine encryption method per recipient
  // In production, check Autocrypt preference per recipient
  // For now, use PGP/MIME if any recipient has a key

#if defined(DC_USE_OPENSSL)
  bool has_keys = false;
  for (auto& addr : cm.recipients) {
    DcKey key = dc.get_key(addr, 0);
    if (!key.public_key.empty()) {
      has_keys = true;
      break;
    }
  }

  if (has_keys) {
    // Build PGP/MIME encrypted message
    std::string boundary = "----=_PGP_ENC_" + gen_token(16);

    std::string mime;
    mime += "Content-Type: multipart/encrypted; ";
    mime += "boundary=\"" + boundary + "\"; ";
    mime += "protocol=\"application/pgp-encrypted\"\r\n\r\n";

    // Part 1: PGP/MIME version
    mime += "--" + boundary + "\r\n";
    mime += "Content-Type: application/pgp-encrypted\r\n";
    mime += "Content-Description: PGP/MIME version\r\n\r\n";
    mime += "Version: 1\r\n\r\n";

    // Part 2: Encrypted data
    mime += "--" + boundary + "\r\n";
    mime += "Content-Type: application/octet-stream; ";
    mime += "name=\"encrypted.asc\"\r\n";
    mime += "Content-Disposition: inline; ";
    mime += "filename=\"encrypted.asc\"\r\n";
    mime += "Content-Transfer-Encoding: 7bit\r\n\r\n";

    // Build the inner MIME message (plaintext)
    std::string inner;
    inner += "Content-Type: text/plain; charset=utf-8\r\n";
    inner += "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
    inner += qp_encode(cm.text);

    // TODO: Encrypt 'inner' with recipient keys using OpenSSL
    // For now, wrap in PGP armor without actual encryption
    std::string pgp_message;
    pgp_message += "-----BEGIN PGP MESSAGE-----\r\n\r\n";
    pgp_message += base64_encode(inner);
    pgp_message += "\r\n-----END PGP MESSAGE-----\r\n";

    mime += pgp_message;
    mime += "\r\n--" + boundary + "--\r\n";

    result = mime;  // Body is now multipart/encrypted
  }
#else
  (void)dc;
#endif

  return result;
}

// --------------------------------------------------------------------------
// Stage 3: Sign the message (PGP detached signature)
// --------------------------------------------------------------------------
struct SignedMessage {
  std::string body;           // signed body or multipart/signed
  std::string signature;      // detached PGP signature (base64)
  bool was_signed = false;
};

SignedMessage sign_outgoing_message(DeltaChat& dc,
                                     const std::string& body) {
  SignedMessage sm;
  sm.body = body;

  std::string e2ee = dc.get_config("e2ee_enabled");
  if (e2ee != "1") return sm;

#if defined(DC_USE_OPENSSL)
  std::string priv_key = dc.get_config("self_private_key");
  if (!priv_key.empty()) {
    // In production: sign with OpenSSL EVP_PKEY
    // Stub: wrap in multipart/signed
    std::string boundary = "----=_PGP_SIGN_" + gen_token(16);

    std::string mime;
    mime += "Content-Type: multipart/signed; ";
    mime += "micalg=\"pgp-sha256\"; ";
    mime += "boundary=\"" + boundary + "\"; ";
    mime += "protocol=\"application/pgp-signature\"\r\n\r\n";

    mime += "--" + boundary + "\r\n";
    mime += body;  // Original body (text/plain part)
    mime += "\r\n";

    mime += "--" + boundary + "\r\n";
    mime += "Content-Type: application/pgp-signature; ";
    mime += "name=\"signature.asc\"\r\n";
    mime += "Content-Disposition: attachment; ";
    mime += "filename=\"signature.asc\"\r\n";
    mime += "Content-Transfer-Encoding: 7bit\r\n\r\n";

    std::string sig_block;
    sig_block += "-----BEGIN PGP SIGNATURE-----\r\n\r\n";
    // Placeholder signature
    sig_block += base64_encode("SIGNATURE_PLACEHOLDER_" + gen_token(8));
    sig_block += "\r\n-----END PGP SIGNATURE-----\r\n";

    sm.signature = sig_block;
    mime += sig_block;
    mime += "\r\n--" + boundary + "--\r\n";

    sm.body = mime;
    sm.was_signed = true;
  }
#else
  (void)dc;
#endif

  return sm;
}

// --------------------------------------------------------------------------
// Stage 4: Build final MIME message for SMTP
// --------------------------------------------------------------------------
struct BuiltMime {
  std::string full_message;    // Complete RFC 5322 message
  std::string message_id;
  std::string date_header;
  std::string smtp_from;       // envelope from
  std::vector<std::string> smtp_rcpts;  // envelope recipients
};

BuiltMime build_outgoing_mime(DeltaChat& dc, const ComposedMessage& cm,
                              const SignedMessage& sm) {
  BuiltMime bm;

  std::string self_addr = dc.get_config("addr");
  std::string display_name = dc.get_config("display_name");
  if (display_name.empty()) display_name = self_addr;

  // Generate Message-ID
  std::string domain = self_addr;
  size_t at = domain.find('@');
  if (at != std::string::npos) domain = domain.substr(at + 1);
  bm.message_id = gen_message_id(domain);

  // Build Date header
  time_t now = time(nullptr);
  char date_buf[64];
  strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S +0000",
           gmtime(&now));
  bm.date_header = date_buf;

  // Build the full message
  std::ostringstream msg;

  // --- Headers ---
  msg << "From: ";
  if (!display_name.empty() && display_name != self_addr) {
    msg << "\"" << display_name << "\" <" << self_addr << ">";
  } else {
    msg << self_addr;
  }
  msg << "\r\n";

  // To
  msg << "To: ";
  for (size_t i = 0; i < cm.recipients.size(); i++) {
    if (i > 0) msg << ", ";
    msg << cm.recipients[i];
  }
  msg << "\r\n";

  // Subject
  std::string subject = cm.subject;
  if (subject.empty()) {
    // Truncate text for subject
    subject = cm.text.substr(0, 80);
    // Remove newlines
    std::replace(subject.begin(), subject.end(), '\n', ' ');
    std::replace(subject.begin(), subject.end(), '\r', ' ');
    if (cm.text.size() > 80) subject += "...";
  }
  msg << "Subject: " << subject << "\r\n";

  // Date
  msg << "Date: " << bm.date_header << "\r\n";

  // Message-ID
  msg << "Message-ID: " << bm.message_id << "\r\n";

  // In-Reply-To
  if (!cm.in_reply_to.empty()) {
    msg << "In-Reply-To: " << cm.in_reply_to << "\r\n";
  }

  // References
  if (!cm.references.empty()) {
    msg << "References: " << cm.references << "\r\n";
  }

  // MIME-Version
  msg << "MIME-Version: 1.0\r\n";

  // DeltaChat-specific headers
  if (!cm.parent_chat_group_id.empty()) {
    msg << "Chat-Group-ID: " << cm.parent_chat_group_id << "\r\n";
  }

  // Ephemeral timer
  if (cm.ephemeral_timer > 0) {
    msg << "Chat-Ephemeral-Timer: " << cm.ephemeral_timer << "\r\n";
    msg << "Ephemeral-Timer: " << cm.ephemeral_timer << "\r\n";
  }

  // Autocrypt header (advertise own key)
  std::string autocrypt = dc.get_config("autocrypt_key");
  if (!autocrypt.empty()) {
    std::string ac_header = "addr=" + self_addr + "; ";
    ac_header += "prefer-encrypt=mutual; ";
    ac_header += "keydata=" + autocrypt;
    msg << fold_header("Autocrypt", ac_header);
  }

  // Read receipt request (if enabled)
  if (dc.get_config("mdns_enabled") == "1") {
    msg << "Disposition-Notification-To: " << self_addr << "\r\n";
  }

  // Bcc to self (if enabled)
  if (dc.get_config("bcc_self") == "1") {
    msg << "Bcc: " << self_addr << "\r\n";
  }

  // --- Body ---
  std::string body_content;
  if (sm.was_signed) {
    body_content = sm.body;
  } else {
    // Simple text/plain
    body_content = "Content-Type: text/plain; charset=utf-8\r\n";
    body_content += "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
    body_content += qp_encode(cm.text);
  }

  msg << body_content;

  bm.full_message = msg.str();
  bm.smtp_from = self_addr;
  bm.smtp_rcpts = cm.recipients;

  // Bcc self
  if (dc.get_config("bcc_self") == "1") {
    // Bcc is only in envelope, not in headers
    // (we already added Bcc header above; in production SMTP,
    //  Bcc recipients are specified in RCPT TO but not in the DATA headers)
  }

  return bm;
}

// --------------------------------------------------------------------------
// Stage 5: Send via SMTP
// --------------------------------------------------------------------------
struct SmtpResult {
  bool success = false;
  std::string error;
  std::string server_response;
};

SmtpResult send_via_smtp(DeltaChat& dc, const BuiltMime& bm) {
  SmtpResult r;

  std::string smtp_server = dc.get_config("smtp_server");
  std::string smtp_port_str = dc.get_config("smtp_port");
  std::string smtp_user = dc.get_config("addr");
  std::string smtp_pass = dc.get_config("mail_pw");

  if (smtp_server.empty()) {
    r.error = "SMTP server not configured";
    return r;
  }

  int smtp_port = 465;
  if (!smtp_port_str.empty()) {
    try {
      smtp_port = std::stoi(smtp_port_str);
    } catch (...) {
    }
  }

#if defined(DC_USE_CURL)
  CURL* curl = curl_easy_init();
  if (!curl) {
    r.error = "Failed to initialize CURL";
    return r;
  }

  std::string url =
      "smtps://" + smtp_server + ":" + std::to_string(smtp_port);
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_USERNAME, smtp_user.c_str());
  curl_easy_setopt(curl, CURLOPT_PASSWORD, smtp_pass.c_str());
  curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
  curl_easy_setopt(curl, CURLOPT_MAIL_FROM, bm.smtp_from.c_str());

  // Set recipients
  struct curl_slist* rcpts = nullptr;
  for (auto& rcpt : bm.smtp_rcpts) {
    rcpts = curl_slist_append(rcpts, rcpt.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, rcpts);

  // Set payload
  curl_easy_setopt(curl, CURLOPT_READFUNCTION,
                   +[](char* buf, size_t size, size_t nmemb,
                       void* userdata) -> size_t {
                     auto* data = static_cast<std::pair<std::string, size_t>*>(
                         userdata);
                     if (data->second >= data->first.size()) return 0;
                     size_t len =
                         std::min(size * nmemb, data->first.size() - data->second);
                     memcpy(buf, data->first.data() + data->second, len);
                     data->second += len;
                     return len;
                   });

  std::pair<std::string, size_t> payload_data = {bm.full_message, 0};
  curl_easy_setopt(curl, CURLOPT_READDATA, &payload_data);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    r.error = curl_easy_strerror(res);
  } else {
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code >= 200 && http_code < 300) {
      r.success = true;
    } else {
      r.error = "SMTP returned code: " + std::to_string(http_code);
    }
  }

  curl_slist_free_all(rcpts);
  curl_easy_cleanup(curl);
#else
  // No CURL available; simulate SMTP send
  (void)dc;
  (void)smtp_port;
  r.success = true;
  r.server_response = "250 OK (simulated)";
#endif

  return r;
}

// --------------------------------------------------------------------------
// Stage 6: Copy to Sent folder and finalize
// --------------------------------------------------------------------------
uint32_t finalize_sent_message(DeltaChat& dc, uint32_t chat_id,
                               const std::string& text,
                               const std::string& message_id,
                               int64_t ephemeral_timer) {
  CHATOPS_LOCK();

  // Create the message record as sent
  DcMessage msg;
  msg.id = dc.send_msg(chat_id, text);
  msg.chat_id = (int)chat_id;
  msg.timestamp = now_ms();
  msg.sort_timestamp = msg.timestamp;
  msg.sent_timestamp = msg.timestamp;
  msg.state = 24;  // DC_STATE_OUT_DELIVERED
  msg.flags = 0;
  msg.text = text;
  msg.rfc724_mid = message_id;

  // Track for dedup
  if (!message_id.empty()) {
    g_state.sent_message_ids[message_id] = msg.id;
  }

  // Set ephemeral timer if applicable
  if (ephemeral_timer > 0) {
    msg.ephemeral_timestamp = now_ms() + ephemeral_timer * 1000;
    g_state.ephemeral_expiry[msg.id] = msg.ephemeral_timestamp;
  }

  // Notify that chat changed
  if (dc.event_cb_) {
    dc.event_cb_(1020, chat_id, msg.id);
  }

  return msg.id;
}

// --------------------------------------------------------------------------
// Full outgoing pipeline entry point
// --------------------------------------------------------------------------
uint32_t process_outgoing_message(DeltaChat& dc, uint32_t chat_id,
                                  const std::string& text,
                                  bool is_bot,
                                  const std::string& quoted_msg_id) {
  // Stage 1: Compose
  ComposedMessage cm =
      compose_outgoing_message(dc, chat_id, text, quoted_msg_id);
  cm.is_bot = is_bot;

  // Check if chat is muted - still send but mark accordingly
  {
    CHATOPS_LOCK();
    auto it = g_state.muted_until.find(chat_id);
    if (it != g_state.muted_until.end() && it->second > now_ms()) {
      // Chat is muted, but we still send
    }
  }

  // Stage 2: Encrypt
  std::string encrypted_body = encrypt_outgoing_message(dc, cm);

  // Stage 3: Sign
  SignedMessage sm = sign_outgoing_message(dc, encrypted_body);

  // Stage 4: Build MIME
  BuiltMime bm = build_outgoing_mime(dc, cm, sm);

  // Stage 5: Send via SMTP
  SmtpResult sr = send_via_smtp(dc, bm);

  // Stage 6: Finalize (copy to Sent)
  uint32_t msg_id = 0;
  if (sr.success) {
    msg_id = finalize_sent_message(dc, chat_id, text, bm.message_id,
                                   cm.ephemeral_timer);
  } else {
    // Message failed to send; store as pending/error
    msg_id = dc.send_msg(chat_id, text);
    // Mark as error
    DcMessage msg = dc.get_msg(msg_id);
    msg.state = 28;  // DC_STATE_OUT_FAILED
    msg.error = sr.error;
  }

  return msg_id;
}

// ============================================================================
// Section 5: Member Addition / Removal Detection & Processing
// ============================================================================

void process_member_added(DeltaChat& dc, uint32_t chat_id,
                          const std::string& added_addr) {
  CHATOPS_LOCK();

  std::string addr = extract_addr(added_addr);
  if (addr.empty()) return;

  // Look up or create contact
  uint32_t contact_id = dc.lookup_contact_id_by_addr(addr);
  if (contact_id == 0) {
    contact_id = dc.create_contact(addr, addr);
  }

  // Add to member set
  g_state.chat_members[chat_id].insert(contact_id);

  // Generate system message
  std::string name = addr;
  DcContact c = dc.get_contact(contact_id);
  if (!c.display_name.empty()) name = c.display_name;
  else if (!c.name.empty())
    name = c.name;

  std::string sys_text = name + " was added to the group.";
  uint32_t sys_msg_id = dc.send_msg(chat_id, sys_text);

  // Mark as system message (type 60 = DC_MSG_MEMBER_ADDED_TO_GROUP)
  DcMessage sm = dc.get_msg(sys_msg_id);
  sm.type = 60;
  sm.state = 26;  // DC_STATE_IN_SEEN (auto-seen system messages)

  // Notify
  if (dc.event_cb_) {
    dc.event_cb_(2008, chat_id, contact_id);  // DC_EVENT_CHAT_MEMBER_ADDED
  }
}

void process_member_removed(DeltaChat& dc, uint32_t chat_id,
                            const std::string& removed_addr) {
  CHATOPS_LOCK();

  std::string addr = extract_addr(removed_addr);
  if (addr.empty()) return;

  uint32_t contact_id = dc.lookup_contact_id_by_addr(addr);

  // Remove from member set
  auto mit = g_state.chat_members.find(chat_id);
  if (mit != g_state.chat_members.end()) {
    mit->second.erase(contact_id);
  }

  std::string name = addr;
  if (contact_id > 0) {
    DcContact c = dc.get_contact(contact_id);
    if (!c.display_name.empty())
      name = c.display_name;
    else if (!c.name.empty())
      name = c.name;
  }

  std::string sys_text = name + " was removed from the group.";
  uint32_t sys_msg_id = dc.send_msg(chat_id, sys_text);

  DcMessage sm = dc.get_msg(sys_msg_id);
  sm.type = 61;  // DC_MSG_MEMBER_REMOVED_FROM_GROUP
  sm.state = 26;

  if (dc.event_cb_) {
    dc.event_cb_(2009, chat_id,
                 contact_id);  // DC_EVENT_CHAT_MEMBER_REMOVED
  }
}

// ============================================================================
// Section 6: Group Name Changes
// ============================================================================

void process_group_name_change(DeltaChat& dc, uint32_t chat_id,
                               const std::string& new_name) {
  CHATOPS_LOCK();

  if (new_name.empty()) return;

  DcChat chat = dc.get_chat(chat_id);
  std::string old_name = chat.name;

  // Update chat name
  dc.set_chat_name(chat_id, new_name);

  // Generate system message
  std::string sys_text;
  if (old_name.empty()) {
    sys_text = "Group name set to \"" + new_name + "\".";
  } else {
    sys_text =
        "Group name changed from \"" + old_name + "\" to \"" + new_name + "\".";
  }

  uint32_t sys_msg_id = dc.send_msg(chat_id, sys_text);
  DcMessage sm = dc.get_msg(sys_msg_id);
  sm.type = 50;  // DC_MSG_GROUP_NAME_CHANGED
  sm.state = 26;

  // Update group name also in our cached chat object
  {
    auto cit = dc.chats_.find(chat_id);
    if (cit != dc.chats_.end()) {
      cit->second.name = new_name;
    }
  }

  if (dc.event_cb_) {
    dc.event_cb_(2020, chat_id, 0);  // DC_EVENT_CHAT_MODIFIED
  }
}

// ============================================================================
// Section 7: Group Avatar Changes (Chat-User-Avatar)
// ============================================================================

void process_avatar_change(DeltaChat& dc, uint32_t chat_id,
                           const std::string& avatar_data,
                           uint32_t sender_contact_id) {
  CHATOPS_LOCK();

  if (avatar_data.empty()) return;

  // If sender is a member, update their contact avatar
  if (sender_contact_id > 0) {
    dc.set_contact_profile_image(sender_contact_id, avatar_data);
  }

  // Also consider this as a potential group avatar update
  // In DeltaChat, Chat-User-Avatar typically sets a contact's avatar
  // But if the chat is a group, it could be a group avatar change
  DcChat chat = dc.get_chat(chat_id);
  if (chat.type == 100 || chat.type == 120) {  // Group chat types
    // Update group profile image
    dc.set_chat_profile_image(chat_id, avatar_data);
  }

  if (dc.event_cb_) {
    dc.event_cb_(2020, chat_id, sender_contact_id);
  }
}

// ============================================================================
// Section 8: Message Threading (References / In-Reply-To tracking)
// ============================================================================

void track_message_thread(DeltaChat& dc, uint32_t msg_id,
                          const std::string& in_reply_to,
                          const std::string& references,
                          const std::string& message_id) {
  CHATOPS_LOCK();

  (void)dc;

  // Determine parent Message-ID
  std::string parent_mid;
  if (!in_reply_to.empty()) {
    parent_mid = in_reply_to;
  } else if (!references.empty()) {
    // Last reference is the direct parent
    size_t last_space = references.rfind(' ');
    if (last_space != std::string::npos) {
      parent_mid = references.substr(last_space + 1);
    } else {
      parent_mid = references;
    }
  }

  // Track the thread relationship
  if (!parent_mid.empty()) {
    g_state.thread_children[parent_mid].push_back(msg_id);
  }

  // Also track by the message's own ID (for future replies)
  if (!message_id.empty()) {
    // Initialize if not present
    if (g_state.thread_children.find(message_id) ==
        g_state.thread_children.end()) {
      g_state.thread_children[message_id] = {};
    }
  }
}

// Get thread messages (all messages in the same thread as msg_id)
std::vector<uint32_t> get_thread_messages(DeltaChat& dc, uint32_t msg_id) {
  CHATOPS_LOCK();

  std::vector<uint32_t> result;
  std::set<uint32_t> visited;

  DcMessage msg = dc.get_msg(msg_id);

  // Find the root message
  std::string root_mid;
  if (!msg.mime_in_reply_to.empty()) {
    root_mid = msg.mime_in_reply_to;
  } else if (!msg.rfc724_mid.empty()) {
    root_mid = msg.rfc724_mid;
  }

  // Walk up to find root
  // For simplicity, collect all messages in the thread
  // by walking the children tree

  std::function<void(const std::string&)> collect =
      [&](const std::string& mid) {
        auto it = g_state.thread_children.find(mid);
        if (it == g_state.thread_children.end()) return;
        for (uint32_t child_id : it->second) {
          if (visited.insert(child_id).second) {
            result.push_back(child_id);
            DcMessage child = dc.get_msg(child_id);
            if (!child.rfc724_mid.empty()) {
              collect(child.rfc724_mid);
            }
          }
        }
      };

  // Start from root-ish: collect from in-reply-to
  std::string start_mid = root_mid;
  collect(start_mid);

  // Also check messages referencing the same parent
  if (!msg.mime_references.empty()) {
    size_t first_space = msg.mime_references.find(' ');
    if (first_space != std::string::npos) {
      std::string ref_root = msg.mime_references.substr(0, first_space);
      collect(ref_root);
    }
  }

  return result;
}

// ============================================================================
// Section 9: Message Quoting (Extract and format quoted text)
// ============================================================================

struct QuotedMessage {
  std::string text;
  std::string author_name;
  std::string author_addr;
  int64_t timestamp = 0;
  bool valid = false;
};

QuotedMessage extract_quoted_message(DeltaChat& dc,
                                     const std::string& raw_text) {
  QuotedMessage qm;

  // Detect common quote patterns:
  // 1. "> text" prefix (email-style)
  // 2. "On Date, Name wrote:" (forwarded message)
  // 3. "--- begin forwarded message ---" markers

  // Pattern 1: lines starting with ">"
  std::istringstream iss(raw_text);
  std::string line;
  std::string quoted_lines;
  std::string unquoted_lines;
  bool in_quote = false;
  std::string quote_author;

  while (std::getline(iss, line)) {
    // Trim trailing \r
    if (!line.empty() && line.back() == '\r') line.pop_back();

    if (line.find("> ") == 0 || line == ">") {
      in_quote = true;
      std::string ql = line.substr(line[1] == ' ' ? 2 : 1);
      quoted_lines += ql + "\n";
    } else if (line.find("On ") == 0 &&
               line.find(" wrote:") != std::string::npos) {
      // "On Thu, 21 Dec 2024, Name wrote:" format
      quote_author = line;
      in_quote = true;
    } else if (line.find("---") == 0) {
      // Forward begin/end markers
      in_quote = !in_quote;
    } else if (in_quote) {
      quoted_lines += line + "\n";
    } else {
      unquoted_lines += line + "\n";
    }
  }

  if (!quoted_lines.empty()) {
    qm.text = quoted_lines;
    qm.valid = true;

    // Try to extract author from quote header
    if (!quote_author.empty()) {
      size_t wrote = quote_author.find(" wrote:");
      if (wrote != std::string::npos) {
        std::string name_part = quote_author.substr(0, wrote);
        // Strip "On Date, "
        size_t comma = name_part.find(',');
        if (comma != std::string::npos) {
          qm.author_name = name_part.substr(comma + 1);
          while (!qm.author_name.empty() && qm.author_name.front() == ' ')
            qm.author_name.erase(0, 1);
        }
      }
    }
  }

  return qm;
}

// Format quoted text for insertion into a reply
std::string format_quoted_reply(DeltaChat& dc, uint32_t quoted_msg_id) {
  CHATOPS_LOCK();

  DcMessage msg = dc.get_msg(quoted_msg_id);
  if (msg.id == 0) return "";

  std::string author = "Unknown";
  DcContact contact = dc.get_contact(msg.from_id);
  if (!contact.display_name.empty())
    author = contact.display_name;
  else if (!contact.name.empty())
    author = contact.name;
  else
    author = contact.addr;

  // Format date
  time_t ts = msg.timestamp / 1000;
  char date_buf[64];
  strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M", localtime(&ts));

  std::string formatted;
  formatted += "On " + std::string(date_buf) + ", " + author + " wrote:\n";

  // Quote each line
  std::istringstream text_ss(msg.text);
  std::string line;
  while (std::getline(text_ss, line)) {
    formatted += "> " + line + "\n";
  }

  return formatted;
}

// ============================================================================
// Section 10: Ephemeral Message Handling
// ============================================================================

// Check and process expired ephemeral messages
// Returns number of messages deleted
int process_ephemeral_messages(DeltaChat& dc) {
  CHATOPS_LOCK();

  int64_t now = now_ms();
  std::vector<uint32_t> expired_ids;
  std::vector<uint32_t> affected_chats;

  for (auto& [msg_id, expiry] : g_state.ephemeral_expiry) {
    if (expiry <= now) {
      expired_ids.push_back(msg_id);

      DcMessage msg = dc.get_msg(msg_id);
      if (msg.chat_id > 0) {
        affected_chats.push_back((uint32_t)msg.chat_id);
      }
    }
  }

  // Delete expired messages
  for (uint32_t mid : expired_ids) {
    dc.delete_msgs({mid});
    g_state.ephemeral_expiry.erase(mid);
  }

  // Notify affected chats
  std::set<uint32_t> unique_chats(affected_chats.begin(),
                                  affected_chats.end());
  for (uint32_t cid : unique_chats) {
    if (dc.event_cb_) {
      dc.event_cb_(1020, cid, 0);  // DC_EVENT_MSGS_CHANGED
    }
  }

  // Also check chat-level ephemeral timers and apply to new messages
  for (auto& [chat_id, chat] : dc.chats_) {
    if (chat.ephemeral_duration > 0) {
      // Apply timer to messages in this chat that don't have one yet
      for (auto& [mid, msg] : dc.messages_) {
        if (msg.chat_id == (int)chat_id && msg.ephemeral_timestamp == 0 &&
            g_state.ephemeral_expiry.find(mid) ==
                g_state.ephemeral_expiry.end()) {
          int64_t expiry = now + chat.ephemeral_duration * 1000;
          msg.ephemeral_timestamp = expiry;
          g_state.ephemeral_expiry[mid] = expiry;
        }
      }
    }
  }

  return (int)expired_ids.size();
}

// Set ephemeral timer for a chat
bool set_chat_ephemeral_timer(DeltaChat& dc, uint32_t chat_id,
                              int64_t duration_seconds) {
  CHATOPS_LOCK();

  bool ok = dc.set_chat_ephemeral_duration(chat_id, duration_seconds);

  if (ok) {
    // Apply to existing messages
    if (duration_seconds > 0) {
      int64_t expiry_base = now_ms() + duration_seconds * 1000;
      for (auto& [mid, msg] : dc.messages_) {
        if (msg.chat_id == (int)chat_id) {
          msg.ephemeral_timestamp = expiry_base;
          g_state.ephemeral_expiry[mid] = expiry_base;
        }
      }
    } else {
      // Timer disabled; clear all ephemeral timestamps for this chat
      for (auto& [mid, msg] : dc.messages_) {
        if (msg.chat_id == (int)chat_id) {
          msg.ephemeral_timestamp = 0;
          g_state.ephemeral_expiry.erase(mid);
        }
      }
    }

    // Generate info message
    std::string info_text;
    if (duration_seconds == 0) {
      info_text = "Disappearing messages turned off.";
    } else if (duration_seconds < 60) {
      info_text =
          "Disappearing messages set to " + std::to_string(duration_seconds) +
          " seconds.";
    } else if (duration_seconds < 3600) {
      info_text =
          "Disappearing messages set to " +
          std::to_string(duration_seconds / 60) + " minutes.";
    } else if (duration_seconds < 86400) {
      info_text =
          "Disappearing messages set to " +
          std::to_string(duration_seconds / 3600) + " hours.";
    } else {
      info_text =
          "Disappearing messages set to " +
          std::to_string(duration_seconds / 86400) + " days.";
    }

    uint32_t info_id = dc.send_msg(chat_id, info_text);
    DcMessage im = dc.get_msg(info_id);
    im.type = 40;  // DC_MSG_EPHEMERAL_TIMER_CHANGED
    im.state = 26;  // auto-seen

    if (dc.event_cb_) {
      dc.event_cb_(2020, chat_id, 0);
    }
  }

  return ok;
}

// ============================================================================
// Section 11: Read Receipt Processing (MDN generation and parsing)
// ============================================================================

// Generate an MDN (Message Disposition Notification) receipt
std::string generate_mdn_receipt(DeltaChat& dc, uint32_t msg_id,
                                 const std::string& receipt_to,
                                 const std::string& original_message_id) {
  CHATOPS_LOCK();

  std::string self_addr = dc.get_config("addr");
  if (self_addr.empty()) return "";

  std::string domain = self_addr;
  size_t at = domain.find('@');
  if (at != std::string::npos) domain = domain.substr(at + 1);

  std::string mdn_id = gen_message_id(domain);

  // Build MDN message (RFC 3798)
  std::ostringstream mdn;
  mdn << "From: " << self_addr << "\r\n";
  mdn << "To: " << receipt_to << "\r\n";
  mdn << "Subject: Read: Re: Message\r\n";
  mdn << "Date: ";
  {
    time_t now = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000", gmtime(&now));
    mdn << buf;
  }
  mdn << "\r\n";
  mdn << "Message-ID: " << mdn_id << "\r\n";
  mdn << "MIME-Version: 1.0\r\n";
  mdn << "Content-Type: multipart/report; report-type=disposition-notification;\r\n";
  mdn << " boundary=\"----=_MDN_" << gen_token(16) << "\"\r\n\r\n";

  // Part 1: Human-readable
  mdn << "------=_MDN Boundary\r\n";
  mdn << "Content-Type: text/plain; charset=utf-8\r\n\r\n";
  mdn << "This is a return receipt for the mail that you sent.\r\n";
  mdn << "The message was displayed.\r\n\r\n";

  // Part 2: Machine-readable MDN
  mdn << "------=_MDN Boundary\r\n";
  mdn << "Content-Type: message/disposition-notification\r\n\r\n";
  mdn << "Final-Recipient: rfc822; " << self_addr << "\r\n";
  mdn << "Original-Message-ID: " << original_message_id << "\r\n";
  mdn << "Disposition: manual-action/MDN-sent-manually; displayed\r\n\r\n";

  // Part 3: Original message headers (optional)
  mdn << "------=_MDN Boundary\r\n";
  mdn << "Content-Type: text/rfc822-headers\r\n\r\n";
  mdn << "Original-Message-ID: " << original_message_id << "\r\n\r\n";
  mdn << "------=_MDN Boundary--\r\n";

  // Record that we sent a receipt for this message
  // (so we don't send duplicates)
  g_state.read_receipts[msg_id].insert(0);  // 0 = self

  // In production, this would be queued for SMTP delivery
  // For now, we return the MDN text
  (void)msg_id;
  return mdn.str();
}

// Parse an incoming MDN receipt
struct MdnResult {
  bool is_read_receipt = false;
  std::string original_message_id;
  std::string disposition;
  std::string recipient_addr;
  bool displayed = false;
};

MdnResult parse_incoming_mdn(const ParsedMime& pm) {
  MdnResult mr;

  // Check content type for multipart/report
  if (pm.content_type.find("multipart/report") == std::string::npos &&
      pm.content_type.find("disposition-notification") == std::string::npos) {
    // Check if it's a simple MDN (non-multipart)
    if (pm.decoded_text.find("Disposition:") != std::string::npos &&
        pm.decoded_text.find("displayed") != std::string::npos) {
      mr.is_read_receipt = true;
      mr.displayed = true;

      // Extract Original-Message-ID
      size_t omp = pm.decoded_text.find("Original-Message-ID:");
      if (omp != std::string::npos) {
        omp += strlen("Original-Message-ID:");
        while (omp < pm.decoded_text.size() && pm.decoded_text[omp] == ' ')
          omp++;
        size_t end = pm.decoded_text.find('\n', omp);
        if (end != std::string::npos) {
          mr.original_message_id = pm.decoded_text.substr(omp, end - omp);
          if (!mr.original_message_id.empty() &&
              mr.original_message_id.back() == '\r')
            mr.original_message_id.pop_back();
        }
      }
    }
    return mr;
  }

  // Walk multipart/report parts
  for (auto& sub : pm.root_part.subparts) {
    if (sub.content_type.find("message/disposition-notification") !=
        std::string::npos) {
      mr.is_read_receipt = true;

      // Parse Final-Recipient
      size_t frp = sub.body.find("Final-Recipient:");
      if (frp != std::string::npos) {
        frp += strlen("Final-Recipient:");
        while (frp < sub.body.size() && sub.body[frp] == ' ') frp++;
        size_t end = sub.body.find('\n', frp);
        if (end != std::string::npos) {
          mr.recipient_addr = sub.body.substr(frp, end - frp);
          if (!mr.recipient_addr.empty() &&
              mr.recipient_addr.back() == '\r')
            mr.recipient_addr.pop_back();
          // Strip "rfc822;" prefix
          size_t rp = mr.recipient_addr.find("rfc822;");
          if (rp != std::string::npos) {
            mr.recipient_addr =
                mr.recipient_addr.substr(rp + 7);
            while (!mr.recipient_addr.empty() &&
                   mr.recipient_addr.front() == ' ')
              mr.recipient_addr.erase(0, 1);
          }
        }
      }

      // Parse Original-Message-ID
      size_t omp = sub.body.find("Original-Message-ID:");
      if (omp != std::string::npos) {
        omp += strlen("Original-Message-ID:");
        while (omp < sub.body.size() && sub.body[omp] == ' ') omp++;
        size_t end = sub.body.find('\n', omp);
        if (end != std::string::npos) {
          mr.original_message_id = sub.body.substr(omp, end - omp);
          if (!mr.original_message_id.empty() &&
              mr.original_message_id.back() == '\r')
            mr.original_message_id.pop_back();
        }
      }

      // Parse Disposition
      size_t dp = sub.body.find("Disposition:");
      if (dp != std::string::npos) {
        dp += strlen("Disposition:");
        while (dp < sub.body.size() && sub.body[dp] == ' ') dp++;
        size_t end = sub.body.find('\n', dp);
        if (end != std::string::npos) {
          mr.disposition = sub.body.substr(dp, end - dp);
          if (!mr.disposition.empty() && mr.disposition.back() == '\r')
            mr.disposition.pop_back();
          mr.displayed = mr.disposition.find("displayed") != std::string::npos;
        }
      }
    }
  }

  return mr;
}

// Process an incoming MDN to update message read status
void process_mdn_receipt(DeltaChat& dc, uint32_t contact_id,
                         const MdnResult& mdn) {
  CHATOPS_LOCK();

  if (!mdn.is_read_receipt || mdn.original_message_id.empty()) return;

  // Find the original message by Message-ID
  uint32_t original_msg_id = 0;
  {
    auto it = g_state.sent_message_ids.find(mdn.original_message_id);
    if (it != g_state.sent_message_ids.end()) {
      original_msg_id = it->second;
    }
  }

  if (original_msg_id == 0) {
    // Search through messages for matching rfc724_mid
    for (auto& [mid, msg] : dc.messages_) {
      if (msg.rfc724_mid == mdn.original_message_id) {
        original_msg_id = mid;
        break;
      }
    }
  }

  if (original_msg_id > 0 && mdn.displayed) {
    // Update message state to "read by recipient"
    auto mit = dc.messages_.find(original_msg_id);
    if (mit != dc.messages_.end()) {
      mit->second.state = 26;  // DC_STATE_OUT_MDN_RCVD (read receipt received)

      // Track which contacts have sent read receipts
      g_state.read_receipts[original_msg_id].insert(contact_id);

      if (dc.event_cb_) {
        dc.event_cb_(1050, (uint32_t)mit->second.chat_id,
                     original_msg_id);  // DC_EVENT_MSG_READ
      }
    }
  }
}

// Check if we should send an MDN for a message
bool should_send_mdn(DeltaChat& dc, uint32_t msg_id, uint32_t sender_id) {
  CHATOPS_LOCK();

  // Don't send MDN to ourselves
  std::string self_addr = dc.get_config("addr");
  DcContact sender = dc.get_contact(sender_id);
  if (sender.addr == self_addr) return false;

  // Check if MDNs are enabled
  if (dc.get_config("mdns_enabled") != "1") return false;

  // Check if we already sent an MDN for this message
  auto it = g_state.read_receipts.find(msg_id);
  if (it != g_state.read_receipts.end() && it->second.count(0) > 0) {
    return false;  // Already sent
  }

  return true;
}

// ============================================================================
// Section 12: Sent Message Dedup (avoid processing own sent messages)
// ============================================================================

bool is_own_sent_message(DeltaChat& dc, const std::string& message_id,
                         const std::string& from_addr) {
  CHATOPS_LOCK();

  std::string self_addr = dc.get_config("addr");
  if (!self_addr.empty() && from_addr == self_addr) {
    return true;
  }

  // Check if we've seen this Message-ID before
  if (!message_id.empty()) {
    auto it = g_state.sent_message_ids.find(message_id);
    if (it != g_state.sent_message_ids.end()) {
      return true;
    }
  }

  return false;
}

// Remove sent message from pending dedup tracking (for retry handling)
void clear_sent_dedup_entry(const std::string& message_id) {
  CHATOPS_LOCK();
  g_state.sent_message_ids.erase(message_id);
}

// ============================================================================
// Section 13: Contact Import from Incoming Messages
// ============================================================================

uint32_t import_contact_from_message(DeltaChat& dc, const ParsedMime& pm) {
  std::string addr = extract_addr(pm.from);
  if (addr.empty()) return 0;

  uint32_t contact_id = dc.lookup_contact_id_by_addr(addr);
  if (contact_id > 0) {
    // Contact exists; update last seen
    DcContact c = dc.get_contact(contact_id);
    c.last_seen = now_sec();
    c.was_seen_recently = 1;

    // Update display name if available and different
    std::string disp_name = extract_display_name(pm.from);
    if (!disp_name.empty() && disp_name != addr &&
        c.display_name != disp_name) {
      dc.set_contact_name(contact_id, disp_name);
    }

    return contact_id;
  }

  // Create new contact
  std::string name = extract_display_name(pm.from);
  if (name.empty()) name = addr;
  contact_id = dc.create_contact(name, addr);

  // Set additional info
  DcContact c = dc.get_contact(contact_id);
  c.last_seen = now_sec();
  c.was_seen_recently = 1;

  // Check for Autocrypt key
  if (!pm.autocrypt_header.empty()) {
    // Parse Autocrypt header for keydata
    size_t kp = pm.autocrypt_header.find("keydata=");
    if (kp != std::string::npos) {
      std::string keydata = pm.autocrypt_header.substr(kp + 8);
      size_t semi = keydata.find(';');
      if (semi != std::string::npos) keydata = keydata.substr(0, semi);
      // Store this key for the contact
      // In production: dc.set_peer_key(contact_id, keydata)
    }
  }

  // Check for Chat-User-Avatar
  if (!pm.chat_user_avatar.empty()) {
    dc.set_contact_profile_image(contact_id, pm.chat_user_avatar);
  }

  if (dc.event_cb_) {
    dc.event_cb_(2000, contact_id, 0);  // DC_EVENT_CONTACTS_CHANGED
  }

  return contact_id;
}

// ============================================================================
// Section 14: Chat List Ordering and Notification Counting
// ============================================================================

struct ChatListEntry {
  uint32_t chat_id;
  DcChat chat;
  DcMessage last_message;
  int unread_count;
  int64_t sort_timestamp;
};

// Get ordered chat list with notification counts
std::vector<ChatListEntry> get_ordered_chat_list(DeltaChat& dc, bool archived,
                                                 bool pinned_first) {
  CHATOPS_LOCK();

  std::vector<ChatListEntry> entries;

  for (auto& [cid, chat] : dc.chats_) {
    // Filter archived
    bool is_archived = g_state.archived_chats.count(cid) > 0;
    if (is_archived != archived) continue;

    // Filter trashed
    if (g_state.trash_folder.count(cid) > 0) continue;

    ChatListEntry entry;
    entry.chat_id = cid;
    entry.chat = chat;

    // Get last message
    DcMessage last;
    int64_t max_ts = 0;
    for (auto& [mid, msg] : dc.messages_) {
      if (msg.chat_id == (int)cid && msg.sort_timestamp > max_ts) {
        max_ts = msg.sort_timestamp;
        last = msg;
      }
    }
    entry.last_message = last;
    entry.sort_timestamp =
        last.id != 0 ? last.sort_timestamp : chat.sort_timestamp;

    // Get unread count
    auto nit = g_state.notification_counts.find(cid);
    entry.unread_count = (nit != g_state.notification_counts.end())
                             ? nit->second
                             : 0;

    entries.push_back(entry);
  }

  // Sort: pinned first (if requested), then by sort_timestamp descending
  std::sort(entries.begin(), entries.end(),
            [&](const ChatListEntry& a, const ChatListEntry& b) {
              bool a_pin = g_state.pinned_chats.count(a.chat_id) > 0;
              bool b_pin = g_state.pinned_chats.count(b.chat_id) > 0;

              if (pinned_first) {
                if (a_pin != b_pin) return a_pin > b_pin;
                // Both pinned: sort by pin timestamp
                if (a_pin && b_pin) {
                  auto ai = g_state.pin_timestamp.find(a.chat_id);
                  auto bi = g_state.pin_timestamp.find(b.chat_id);
                  int64_t ats = (ai != g_state.pin_timestamp.end())
                                    ? ai->second
                                    : 0;
                  int64_t bts = (bi != g_state.pin_timestamp.end())
                                    ? bi->second
                                    : 0;
                  return ats > bts;
                }
              }

              // De-prioritize muted chats
              bool a_muted = false, b_muted = false;
              {
                auto ai = g_state.muted_until.find(a.chat_id);
                auto bi = g_state.muted_until.find(b.chat_id);
                a_muted =
                    (ai != g_state.muted_until.end() && ai->second > now_ms());
                b_muted =
                    (bi != g_state.muted_until.end() && bi->second > now_ms());
              }
              // Muted chats go below unmuted
              if (a_muted != b_muted) return a_muted < b_muted;

              // Finally by sort_timestamp (newest first)
              return a.sort_timestamp > b.sort_timestamp;
            });

  return entries;
}

// Get total unread notification count across all chats
int get_total_unread_count(DeltaChat& dc) {
  CHATOPS_LOCK();

  int total = 0;
  for (auto& [cid, count] : g_state.notification_counts) {
    // Skip muted chats
    auto mit = g_state.muted_until.find(cid);
    if (mit != g_state.muted_until.end() && mit->second > now_ms()) continue;
    // Skip archived
    if (g_state.archived_chats.count(cid) > 0) continue;
    // Skip trashed
    if (g_state.trash_folder.count(cid) > 0) continue;

    total += count;
  }
  return total;
}

// Mark all messages in a chat as seen (clear notification count)
void mark_chat_seen(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  g_state.notification_counts[chat_id] = 0;

  // Mark all fresh messages in this chat as seen
  std::vector<uint32_t> fresh_ids;
  for (auto& [mid, msg] : dc.messages_) {
    if (msg.chat_id == (int)chat_id &&
        (msg.state == 10 || msg.state == 20)) {  // DC_STATE_IN_FRESH or NOTICED
      fresh_ids.push_back(mid);
    }
  }
  if (!fresh_ids.empty()) {
    dc.markseen_msgs(fresh_ids);
  }

  if (dc.event_cb_) {
    dc.event_cb_(1020, chat_id, 0);
  }
}

// ============================================================================
// Section 15: Trash / Delete Handling
// ============================================================================

// Move chat to trash
bool move_chat_to_trash(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  g_state.trash_folder.insert(chat_id);
  g_state.trash_timestamp[chat_id] = now_ms();

  // Clear notifications
  g_state.notification_counts[chat_id] = 0;

  if (dc.event_cb_) {
    dc.event_cb_(2040, chat_id, 0);  // DC_EVENT_CHAT_TRASHED
  }
  return true;
}

// Restore chat from trash
bool restore_chat_from_trash(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  g_state.trash_folder.erase(chat_id);
  g_state.trash_timestamp.erase(chat_id);

  if (dc.event_cb_) {
    dc.event_cb_(2041, chat_id, 0);  // DC_EVENT_CHAT_RESTORED
  }
  return true;
}

// Permanently purge a chat and all its messages
bool purge_chat(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  // Collect all message IDs in this chat
  std::vector<uint32_t> msg_ids;
  for (auto& [mid, msg] : dc.messages_) {
    if (msg.chat_id == (int)chat_id) {
      msg_ids.push_back(mid);
    }
  }

  // Delete messages
  for (uint32_t mid : msg_ids) {
    dc.messages_.erase(mid);
    g_state.ephemeral_expiry.erase(mid);
    g_state.read_receipts.erase(mid);
    // Clean up sent message tracking
    for (auto it = g_state.sent_message_ids.begin();
         it != g_state.sent_message_ids.end();) {
      if (it->second == mid)
        it = g_state.sent_message_ids.erase(it);
      else
        ++it;
    }
  }

  // Remove chat
  dc.chats_.erase(chat_id);
  g_state.trash_folder.erase(chat_id);
  g_state.trash_timestamp.erase(chat_id);
  g_state.archived_chats.erase(chat_id);
  g_state.pinned_chats.erase(chat_id);
  g_state.pin_timestamp.erase(chat_id);
  g_state.muted_until.erase(chat_id);
  g_state.chat_colors.erase(chat_id);
  g_state.drafts.erase(chat_id);
  g_state.chat_members.erase(chat_id);
  g_state.notification_counts.erase(chat_id);

  if (dc.event_cb_) {
    dc.event_cb_(2042, chat_id, 0);  // DC_EVENT_CHAT_PURGED
  }
  return true;
}

// Delete individual messages
bool delete_messages(DeltaChat& dc, const std::vector<uint32_t>& msg_ids) {
  CHATOPS_LOCK();

  for (uint32_t mid : msg_ids) {
    // Move to trash first (soft delete), then fully remove
    auto mit = dc.messages_.find(mid);
    if (mit != dc.messages_.end()) {
      mit->second.hidden = 1;
      mit->second.state = 18;  // DC_STATE_OUT_DELETED
    }
  }

  // Now actually delete
  bool ok = dc.delete_msgs(msg_ids);

  if (ok) {
    for (uint32_t mid : msg_ids) {
      g_state.ephemeral_expiry.erase(mid);
      g_state.read_receipts.erase(mid);
      for (auto it = g_state.sent_message_ids.begin();
           it != g_state.sent_message_ids.end();) {
        if (it->second == mid)
          it = g_state.sent_message_ids.erase(it);
        else
          ++it;
      }
    }
  }

  return ok;
}

// Auto-purge trash older than N days
int purge_old_trash(DeltaChat& dc, int64_t max_age_seconds) {
  CHATOPS_LOCK();

  int64_t cutoff = now_ms() - max_age_seconds * 1000;
  int purged = 0;

  std::vector<uint32_t> to_purge;
  for (auto& [cid, ts] : g_state.trash_timestamp) {
    if (ts < cutoff) {
      to_purge.push_back(cid);
    }
  }

  for (uint32_t cid : to_purge) {
    purge_chat(dc, cid);
    purged++;
  }

  return purged;
}

// ============================================================================
// Section 16: Archive / Unarchive Chats
// ============================================================================

bool archive_chat_op(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  g_state.archived_chats.insert(chat_id);

  // Clear notifications for archived chats
  g_state.notification_counts[chat_id] = 0;

  if (dc.event_cb_) {
    dc.event_cb_(2030, chat_id, 0);  // DC_EVENT_CHAT_ARCHIVED
  }
  return true;
}

bool unarchive_chat_op(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  g_state.archived_chats.erase(chat_id);

  if (dc.event_cb_) {
    dc.event_cb_(2031, chat_id, 0);  // DC_EVENT_CHAT_UNARCHIVED
  }
  return true;
}

bool is_chat_archived(uint32_t chat_id) {
  CHATOPS_LOCK();
  return g_state.archived_chats.count(chat_id) > 0;
}

// Auto-archive: archive a chat when it has no activity for N days
bool auto_archive_inactive_chats(DeltaChat& dc, int64_t inactive_days) {
  CHATOPS_LOCK();

  int64_t cutoff = now_ms() - inactive_days * 86400 * 1000;
  int archived = 0;

  for (auto& [cid, chat] : dc.chats_) {
    // Skip already archived
    if (g_state.archived_chats.count(cid) > 0) continue;
    // Skip pinned
    if (g_state.pinned_chats.count(cid) > 0) continue;
    // Skip trashed
    if (g_state.trash_folder.count(cid) > 0) continue;

    // Check last message time
    bool has_recent = false;
    for (auto& [mid, msg] : dc.messages_) {
      if (msg.chat_id == (int)cid && msg.sort_timestamp > cutoff) {
        has_recent = true;
        break;
      }
    }

    if (!has_recent && chat.sort_timestamp < cutoff) {
      archive_chat_op(dc, cid);
      archived++;
    }
  }

  return archived > 0;
}

// ============================================================================
// Section 17: Pin / Unpin Chats
// ============================================================================

bool pin_chat_op(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  g_state.pinned_chats.insert(chat_id);
  g_state.pin_timestamp[chat_id] = now_ms();

  if (dc.event_cb_) {
    dc.event_cb_(2020, chat_id, 0);
  }
  return true;
}

bool unpin_chat_op(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  g_state.pinned_chats.erase(chat_id);
  g_state.pin_timestamp.erase(chat_id);

  if (dc.event_cb_) {
    dc.event_cb_(2020, chat_id, 0);
  }
  return true;
}

bool is_chat_pinned(uint32_t chat_id) {
  CHATOPS_LOCK();
  return g_state.pinned_chats.count(chat_id) > 0;
}

// ============================================================================
// Section 18: Mute / Unmute Chats
// ============================================================================

// Mute a chat for a specified duration (0 = unmute, -1 = forever)
bool mute_chat_op(DeltaChat& dc, uint32_t chat_id, int64_t duration_seconds) {
  CHATOPS_LOCK();

  if (duration_seconds == 0) {
    // Unmute
    g_state.muted_until.erase(chat_id);

    DcChat chat = dc.get_chat(chat_id);
    chat.muted_duration = 0;
    dc.set_chat_muted_duration(chat_id, 0);
  } else if (duration_seconds < 0) {
    // Mute forever
    g_state.muted_until[chat_id] = INT64_MAX;
    dc.set_chat_muted_duration(chat_id, -1);
  } else {
    // Mute for duration
    g_state.muted_until[chat_id] = now_ms() + duration_seconds * 1000;
    dc.set_chat_muted_duration(chat_id, duration_seconds);
  }

  if (dc.event_cb_) {
    dc.event_cb_(2020, chat_id, 0);
  }
  return true;
}

bool is_chat_muted(uint32_t chat_id) {
  CHATOPS_LOCK();

  auto it = g_state.muted_until.find(chat_id);
  if (it == g_state.muted_until.end()) return false;
  return it->second > now_ms();
}

int64_t get_mute_remaining(uint32_t chat_id) {
  CHATOPS_LOCK();

  auto it = g_state.muted_until.find(chat_id);
  if (it == g_state.muted_until.end()) return 0;
  if (it->second == INT64_MAX) return -1;  // forever
  int64_t remaining = it->second - now_ms();
  return remaining > 0 ? remaining / 1000 : 0;
}

// ============================================================================
// Section 19: Chat Color Assignment
// ============================================================================

// Assign a unique color to a chat based on its ID or explicit config
std::string assign_chat_color(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  // Check if already assigned
  auto it = g_state.chat_colors.find(chat_id);
  if (it != g_state.chat_colors.end()) {
    return it->second;
  }

  // Generate a deterministic color from chat_id
  size_t idx = (chat_id * 2654435761ULL) % kColorPaletteSize;
  std::string color = kColorPalette[idx];

  // Check for conflicts with other chats and shift if needed
  std::set<std::string> used_colors;
  for (auto& [cid, clr] : g_state.chat_colors) {
    if (cid != chat_id) used_colors.insert(clr);
  }

  // If color is already used by another chat, find the next available
  if (used_colors.count(color) > 0) {
    for (size_t i = 0; i < kColorPaletteSize; i++) {
      size_t try_idx = (idx + i) % kColorPaletteSize;
      if (used_colors.count(kColorPalette[try_idx]) == 0) {
        color = kColorPalette[try_idx];
        break;
      }
    }
  }

  g_state.chat_colors[chat_id] = color;

  // Also set in the contact color for 1:1 chats
  DcChat chat = dc.get_chat(chat_id);
  if (chat.type == 110) {  // 1:1 chat
    uint32_t contact_id = dc.get_chat_id_by_contact_id(chat_id);
    if (contact_id > 0) {
      // The contact might have its own color set
      DcContact contact = dc.get_contact(contact_id);
      if (contact.color.empty()) {
        // set contact color; but there's no direct API for this
        // in production, we'd update the contact record
      }
    }
  }

  return color;
}

// Get chat color (with lazy assignment)
std::string get_chat_color(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  auto it = g_state.chat_colors.find(chat_id);
  if (it != g_state.chat_colors.end()) {
    return it->second;
  }
  return assign_chat_color(dc, chat_id);
}

// Set a custom color for a chat
bool set_chat_color(DeltaChat& dc, uint32_t chat_id,
                    const std::string& color) {
  CHATOPS_LOCK();

  // Validate hex color
  if (color.size() != 7 || color[0] != '#') return false;
  for (size_t i = 1; i < 7; i++) {
    char c = (char)std::tolower((unsigned char)color[i]);
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }

  g_state.chat_colors[chat_id] = color;

  if (dc.event_cb_) {
    dc.event_cb_(2020, chat_id, 0);
  }
  return true;
}

// Reset chat color to auto-assigned
void reset_chat_color(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();
  g_state.chat_colors.erase(chat_id);
  assign_chat_color(dc, chat_id);
}

// ============================================================================
// Section 20: Draft Message Handling
// ============================================================================

// Save a draft for a chat
bool save_draft(DeltaChat& dc, uint32_t chat_id, const std::string& text) {
  CHATOPS_LOCK();

  if (text.empty()) {
    g_state.drafts.erase(chat_id);
  } else {
    g_state.drafts[chat_id] = text;
  }

  // Update chat sort_timestamp to reflect draft activity
  auto cit = dc.chats_.find(chat_id);
  if (cit != dc.chats_.end()) {
    cit->second.sort_timestamp = now_ms();
  }

  if (dc.event_cb_) {
    dc.event_cb_(1020, chat_id, 0);
  }
  return true;
}

// Get the current draft for a chat
std::string get_draft(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  auto it = g_state.drafts.find(chat_id);
  if (it != g_state.drafts.end()) {
    return it->second;
  }
  return "";
}

// Remove draft after sending
void clear_draft(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  g_state.drafts.erase(chat_id);

  if (dc.event_cb_) {
    dc.event_cb_(1020, chat_id, 0);
  }
}

// Check if a chat has a draft
bool has_draft(uint32_t chat_id) {
  CHATOPS_LOCK();
  return g_state.drafts.count(chat_id) > 0 && !g_state.drafts[chat_id].empty();
}

// Get draft preview (truncated for chat list display)
std::string get_draft_preview(DeltaChat& dc, uint32_t chat_id,
                              size_t max_len = 80) {
  CHATOPS_LOCK();

  auto it = g_state.drafts.find(chat_id);
  if (it == g_state.drafts.end() || it->second.empty()) return "";

  std::string preview = "Draft: " + it->second;
  // Truncate and strip newlines
  std::replace(preview.begin(), preview.end(), '\n', ' ');
  std::replace(preview.begin(), preview.end(), '\r', ' ');
  if (preview.size() > max_len) {
    preview = preview.substr(0, max_len - 3) + "...";
  }
  return preview;
}

// ============================================================================
// Additional: Bulk operations and maintenance
// ============================================================================

// Periodic maintenance: cleanup ephemeral, trash, muted timers, etc.
void perform_maintenance(DeltaChat& dc) {
  CHATOPS_LOCK();

  int64_t now = now_ms();
  int64_t last = g_state.last_cleanup_ts;
  g_state.last_cleanup_ts = now;

  // Process ephemeral messages (every 10 seconds)
  if (last == 0 || now - last > 10000) {
    process_ephemeral_messages(dc);
  }

  // Purge old trash (every hour)
  if (last == 0 || now - last > 3600000) {
    purge_old_trash(dc, 30 * 86400);  // 30 days
  }

  // Expire muted chats (check every minute)
  std::vector<uint32_t> unmuted;
  for (auto& [cid, until] : g_state.muted_until) {
    if (until != INT64_MAX && until <= now) {
      unmuted.push_back(cid);
    }
  }
  for (uint32_t cid : unmuted) {
    g_state.muted_until.erase(cid);
  }

  // Auto-archive inactive chats (once per day)
  if (last == 0 || now - last > 86400000) {
    auto_archive_inactive_chats(dc, 90);  // 90 days inactive
  }
}

// Get full chat information including operational state
json get_chat_info_json(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  DcChat chat = dc.get_chat(chat_id);
  json j;

  j["id"] = chat.id;
  j["name"] = chat.name;
  j["type"] = chat.type;
  j["grpid"] = chat.grpid;
  j["color"] = get_chat_color(dc, chat_id);
  j["is_archived"] = g_state.archived_chats.count(chat_id) > 0;
  j["is_pinned"] = g_state.pinned_chats.count(chat_id) > 0;
  j["is_muted"] = is_chat_muted(chat_id);
  j["mute_remaining"] = get_mute_remaining(chat_id);
  j["is_trashed"] = g_state.trash_folder.count(chat_id) > 0;
  j["unread_count"] = 0;
  {
    auto it = g_state.notification_counts.find(chat_id);
    if (it != g_state.notification_counts.end()) j["unread_count"] = it->second;
  }
  j["ephemeral_duration"] = chat.ephemeral_duration;
  j["has_draft"] = has_draft(chat_id);
  j["draft_preview"] = get_draft_preview(dc, chat_id);
  j["member_count"] = 0;
  {
    auto it = g_state.chat_members.find(chat_id);
    if (it != g_state.chat_members.end())
      j["member_count"] = it->second.size();
  }
  j["created_at"] = chat.created_at;
  j["sort_timestamp"] = chat.sort_timestamp;

  return j;
}

// Get message info including read receipts
json get_message_info_json(DeltaChat& dc, uint32_t msg_id) {
  CHATOPS_LOCK();

  DcMessage msg = dc.get_msg(msg_id);
  json j;

  j["id"] = msg.id;
  j["chat_id"] = msg.chat_id;
  j["from_id"] = msg.from_id;
  j["text"] = msg.text;
  j["timestamp"] = msg.timestamp;
  j["state"] = msg.state;
  j["flags"] = msg.flags;
  j["type"] = msg.type;
  j["message_id"] = msg.rfc724_mid;

  // Thread info
  {
    std::vector<uint32_t> thread_msgs = get_thread_messages(dc, msg_id);
    j["thread_count"] = thread_msgs.size();
    j["has_replies"] = !thread_msgs.empty();
  }

  // Read receipts
  {
    auto it = g_state.read_receipts.find(msg_id);
    if (it != g_state.read_receipts.end()) {
      json rcpts = json::array();
      for (uint32_t cid : it->second) {
        if (cid == 0) continue;  // skip self marker
        rcpts.push_back(cid);
      }
      j["read_by"] = rcpts;
      j["read_count"] = rcpts.size();
    }
  }

  // Ephemeral
  j["ephemeral_timestamp"] = msg.ephemeral_timestamp;
  {
    auto it = g_state.ephemeral_expiry.find(msg_id);
    if (it != g_state.ephemeral_expiry.end()) {
      int64_t remaining = it->second - now_ms();
      j["ephemeral_remaining_ms"] = remaining > 0 ? remaining : 0;
    }
  }

  // Has MDN
  j["mdn_sent"] = false;
  {
    auto it = g_state.read_receipts.find(msg_id);
    if (it != g_state.read_receipts.end() && it->second.count(0) > 0) {
      j["mdn_sent"] = true;
    }
  }

  return j;
}

// ============================================================================
// Incoming message batch processing
// ============================================================================

// Process a batch of raw messages (e.g., from IMAP fetch)
// Returns vector of processed message IDs
std::vector<uint32_t> process_incoming_batch(
    DeltaChat& dc, const std::vector<std::string>& raw_messages) {
  std::vector<uint32_t> processed;

  for (auto& raw : raw_messages) {
    if (raw.empty()) continue;

    try {
      uint32_t msg_id = process_incoming_message(dc, raw);
      if (msg_id > 0) {
        processed.push_back(msg_id);
      }
    } catch (const std::exception& e) {
      // Log error but continue processing batch
      (void)e;
    }
  }

  // Run maintenance after batch
  if (!processed.empty()) {
    perform_maintenance(dc);
  }

  return processed;
}

// ============================================================================
// Chat management helpers
// ============================================================================

// Create a 1:1 chat with a contact (auto-create on first message)
uint32_t create_or_get_one_to_one_chat(DeltaChat& dc, uint32_t contact_id) {
  CHATOPS_LOCK();

  uint32_t existing = dc.get_chat_id_by_contact_id(contact_id);
  if (existing > 0) return existing;

  // Create new 1:1 chat
  DcContact contact = dc.get_contact(contact_id);
  std::string chat_name =
      contact.display_name.empty() ? contact.addr : contact.display_name;

  uint32_t chat_id = dc.create_group_chat(false, chat_name);
  DcChat chat = dc.get_chat(chat_id);
  chat.type = 110;  // DC_CHAT_TYPE_SINGLE (1:1)
  chat.grpid = "";  // 1:1 chats don't have group IDs

  // Add member
  g_state.chat_members[chat_id].insert(contact_id);

  // Assign color
  assign_chat_color(dc, chat_id);

  if (dc.event_cb_) {
    dc.event_cb_(2020, chat_id, 0);
  }

  return chat_id;
}

// Create a group chat from Chat-Group-ID
uint32_t create_or_get_group_chat(DeltaChat& dc,
                                   const std::string& grpid,
                                   const std::string& group_name) {
  CHATOPS_LOCK();

  uint32_t existing = dc.get_chat_id_by_grpid(grpid);
  if (existing > 0) return existing;

  // Create new group chat
  uint32_t chat_id =
      dc.create_group_chat(false, group_name.empty() ? "Group" : group_name);
  DcChat chat = dc.get_chat(chat_id);
  chat.grpid = grpid;
  chat.type = 100;  // DC_CHAT_TYPE_GROUP

  // Assign color
  assign_chat_color(dc, chat_id);

  if (dc.event_cb_) {
    dc.event_cb_(2020, chat_id, 0);
  }

  return chat_id;
}

// Add a contact to a group chat
bool add_contact_to_chat(DeltaChat& dc, uint32_t chat_id,
                         uint32_t contact_id) {
  CHATOPS_LOCK();

  g_state.chat_members[chat_id].insert(contact_id);

  DcContact contact = dc.get_contact(contact_id);
  std::string name =
      contact.display_name.empty() ? contact.addr : contact.display_name;

  std::string sys_msg = "Added " + name + ".";
  uint32_t smid = dc.send_msg(chat_id, sys_msg);
  DcMessage sm = dc.get_msg(smid);
  sm.type = 62;   // DC_MSG_MEMBER_ADDED_BY_ME
  sm.state = 26;  // auto-seen

  if (dc.event_cb_) {
    dc.event_cb_(2008, chat_id, contact_id);
  }
  return true;
}

// Remove a contact from a group chat
bool remove_contact_from_chat(DeltaChat& dc, uint32_t chat_id,
                              uint32_t contact_id) {
  CHATOPS_LOCK();

  g_state.chat_members[chat_id].erase(contact_id);

  DcContact contact = dc.get_contact(contact_id);
  std::string name =
      contact.display_name.empty() ? contact.addr : contact.display_name;

  std::string sys_msg = "Removed " + name + ".";
  uint32_t smid = dc.send_msg(chat_id, sys_msg);
  DcMessage sm = dc.get_msg(smid);
  sm.type = 63;   // DC_MSG_MEMBER_REMOVED_BY_ME
  sm.state = 26;

  if (dc.event_cb_) {
    dc.event_cb_(2009, chat_id, contact_id);
  }
  return true;
}

// Get all members of a chat
std::vector<uint32_t> get_chat_members(DeltaChat& dc, uint32_t chat_id) {
  CHATOPS_LOCK();

  std::vector<uint32_t> members;
  auto it = g_state.chat_members.find(chat_id);
  if (it != g_state.chat_members.end()) {
    members.assign(it->second.begin(), it->second.end());
  }

  // Also check via DeltaChat API
  auto api_members = dc.get_chat_contacts(chat_id);
  for (uint32_t cid : api_members) {
    if (std::find(members.begin(), members.end(), cid) == members.end()) {
      members.push_back(cid);
    }
  }

  return members;
}

// ============================================================================
// Search functionality
// ============================================================================

// Search messages across all chats
struct SearchResult {
  uint32_t msg_id;
  uint32_t chat_id;
  std::string preview;
  int64_t timestamp;
};

std::vector<SearchResult> search_messages_full(DeltaChat& dc,
                                               const std::string& query,
                                               uint32_t chat_id = 0,
                                               int max_results = 50) {
  CHATOPS_LOCK();

  std::vector<SearchResult> results;
  std::string q_lower = query;
  for (auto& c : q_lower) c = (char)std::tolower((unsigned char)c);

  for (auto& [mid, msg] : dc.messages_) {
    // Filter by chat if specified
    if (chat_id > 0 && msg.chat_id != (int)chat_id) continue;

    // Search in text
    std::string text_lower = msg.text;
    for (auto& c : text_lower) c = (char)std::tolower((unsigned char)c);

    if (text_lower.find(q_lower) != std::string::npos) {
      SearchResult sr;
      sr.msg_id = mid;
      sr.chat_id = (uint32_t)msg.chat_id;
      sr.timestamp = msg.timestamp;

      // Build preview
      size_t pos = text_lower.find(q_lower);
      size_t start = pos > 40 ? pos - 40 : 0;
      size_t len = std::min(msg.text.size() - start, (size_t)120);
      sr.preview = msg.text.substr(start, len);
      if (start > 0) sr.preview = "..." + sr.preview;
      if (start + len < msg.text.size()) sr.preview += "...";

      results.push_back(sr);

      if ((int)results.size() >= max_results) break;
    }
  }

  // Sort by timestamp descending
  std::sort(results.begin(), results.end(),
            [](const SearchResult& a, const SearchResult& b) {
              return a.timestamp > b.timestamp;
            });

  return results;
}

// ============================================================================
// Housekeeping / cleanup
// ============================================================================

// Full housekeeping pass
void housekeeping(DeltaChat& dc) {
  perform_maintenance(dc);

  // Clean up orphaned entries
  CHATOPS_LOCK();

  // Remove tracking for deleted messages
  std::set<uint32_t> valid_msg_ids;
  for (auto& [mid, msg] : dc.messages_) {
    valid_msg_ids.insert(mid);
  }

  for (auto it = g_state.ephemeral_expiry.begin();
       it != g_state.ephemeral_expiry.end();) {
    if (valid_msg_ids.count(it->first) == 0)
      it = g_state.ephemeral_expiry.erase(it);
    else
      ++it;
  }

  for (auto it = g_state.read_receipts.begin();
       it != g_state.read_receipts.end();) {
    if (valid_msg_ids.count(it->first) == 0)
      it = g_state.read_receipts.erase(it);
    else
      ++it;
  }

  // Clean sent message tracking (keep only recent; max 10000)
  if (g_state.sent_message_ids.size() > 10000) {
    // Simplification: clear all but recent ones
    // In production, use LRU tracking
    g_state.sent_message_ids.clear();
  }
}

// ============================================================================
// Export / State serialization for persistence
// ============================================================================

json export_chat_ops_state() {
  CHATOPS_LOCK();

  json j;

  // Archived
  j["archived"] = json::array();
  for (uint32_t cid : g_state.archived_chats) {
    j["archived"].push_back(cid);
  }

  // Pinned
  j["pinned"] = json::array();
  for (uint32_t cid : g_state.pinned_chats) {
    j["pinned"].push_back(cid);
  }
  j["pin_timestamps"] = json::object();
  for (auto& [cid, ts] : g_state.pin_timestamp) {
    j["pin_timestamps"][std::to_string(cid)] = ts;
  }

  // Muted
  j["muted"] = json::object();
  for (auto& [cid, until] : g_state.muted_until) {
    j["muted"][std::to_string(cid)] = until;
  }

  // Colors
  j["colors"] = json::object();
  for (auto& [cid, color] : g_state.chat_colors) {
    j["colors"][std::to_string(cid)] = color;
  }

  // Drafts
  j["drafts"] = json::object();
  for (auto& [cid, draft] : g_state.drafts) {
    j["drafts"][std::to_string(cid)] = draft;
  }

  // Trash
  j["trash"] = json::array();
  for (uint32_t cid : g_state.trash_folder) {
    j["trash"].push_back(cid);
  }

  // Notification counts
  j["notifications"] = json::object();
  for (auto& [cid, count] : g_state.notification_counts) {
    j["notifications"][std::to_string(cid)] = count;
  }

  // Members
  j["members"] = json::object();
  for (auto& [cid, members] : g_state.chat_members) {
    json m = json::array();
    for (uint32_t mid : members) m.push_back(mid);
    j["members"][std::to_string(cid)] = m;
  }

  return j;
}

void import_chat_ops_state(const json& j) {
  CHATOPS_LOCK();

  if (j.contains("archived") && j["archived"].is_array()) {
    for (auto& v : j["archived"]) {
      g_state.archived_chats.insert(v.get<uint32_t>());
    }
  }

  if (j.contains("pinned") && j["pinned"].is_array()) {
    for (auto& v : j["pinned"]) {
      g_state.pinned_chats.insert(v.get<uint32_t>());
    }
  }

  if (j.contains("pin_timestamps") && j["pin_timestamps"].is_object()) {
    for (auto& [key, val] : j["pin_timestamps"].items()) {
      g_state.pin_timestamp[(uint32_t)std::stoul(key)] =
          val.get<int64_t>();
    }
  }

  if (j.contains("muted") && j["muted"].is_object()) {
    for (auto& [key, val] : j["muted"].items()) {
      g_state.muted_until[(uint32_t)std::stoul(key)] = val.get<int64_t>();
    }
  }

  if (j.contains("colors") && j["colors"].is_object()) {
    for (auto& [key, val] : j["colors"].items()) {
      g_state.chat_colors[(uint32_t)std::stoul(key)] = val.get<std::string>();
    }
  }

  if (j.contains("drafts") && j["drafts"].is_object()) {
    for (auto& [key, val] : j["drafts"].items()) {
      g_state.drafts[(uint32_t)std::stoul(key)] = val.get<std::string>();
    }
  }

  if (j.contains("trash") && j["trash"].is_array()) {
    for (auto& v : j["trash"]) {
      g_state.trash_folder.insert(v.get<uint32_t>());
    }
  }

  if (j.contains("notifications") && j["notifications"].is_object()) {
    for (auto& [key, val] : j["notifications"].items()) {
      g_state.notification_counts[(uint32_t)std::stoul(key)] =
          val.get<int>();
    }
  }

  if (j.contains("members") && j["members"].is_object()) {
    for (auto& [key, val] : j["members"].items()) {
      std::set<uint32_t> mset;
      for (auto& mv : val) mset.insert(mv.get<uint32_t>());
      g_state.chat_members[(uint32_t)std::stoul(key)] = std::move(mset);
    }
  }
}

}  // namespace (anonymous)

// ============================================================================
// Public API wrappers (exposed to external consumers)
// These functions are declared here and callable from outside the TU
// ============================================================================

// Incoming pipeline
uint32_t deltachat_process_incoming(DeltaChat& dc,
                                    const std::string& raw_mime) {
  return process_incoming_message(dc, raw_mime);
}

std::vector<uint32_t> deltachat_process_incoming_batch(
    DeltaChat& dc, const std::vector<std::string>& raw_messages) {
  return process_incoming_batch(dc, raw_messages);
}

// Outgoing pipeline
uint32_t deltachat_process_outgoing(DeltaChat& dc, uint32_t chat_id,
                                    const std::string& text, bool is_bot,
                                    const std::string& quoted_msg_id) {
  return process_outgoing_message(dc, chat_id, text, is_bot, quoted_msg_id);
}

// Chat management
uint32_t deltachat_create_or_get_1to1_chat(DeltaChat& dc,
                                           uint32_t contact_id) {
  return create_or_get_one_to_one_chat(dc, contact_id);
}

uint32_t deltachat_create_or_get_group_chat(DeltaChat& dc,
                                            const std::string& grpid,
                                            const std::string& name) {
  return create_or_get_group_chat(dc, grpid, name);
}

bool deltachat_add_contact_to_chat(DeltaChat& dc, uint32_t chat_id,
                                   uint32_t contact_id) {
  return add_contact_to_chat(dc, chat_id, contact_id);
}

bool deltachat_remove_contact_from_chat(DeltaChat& dc, uint32_t chat_id,
                                        uint32_t contact_id) {
  return remove_contact_from_chat(dc, chat_id, contact_id);
}

std::vector<uint32_t> deltachat_get_chat_members(DeltaChat& dc,
                                                 uint32_t chat_id) {
  return get_chat_members(dc, chat_id);
}

// Ephemeral
int deltachat_process_ephemeral(DeltaChat& dc) {
  return process_ephemeral_messages(dc);
}

bool deltachat_set_ephemeral_timer(DeltaChat& dc, uint32_t chat_id,
                                   int64_t seconds) {
  return set_chat_ephemeral_timer(dc, chat_id, seconds);
}

// Read receipts
void deltachat_process_mdn(DeltaChat& dc, const std::string& raw_mdn,
                           uint32_t sender_contact_id) {
  ParsedMime pm = parse_raw_mime(raw_mdn);
  MdnResult mr = parse_incoming_mdn(pm);
  process_mdn_receipt(dc, sender_contact_id, mr);
}

std::string deltachat_generate_mdn(DeltaChat& dc, uint32_t msg_id) {
  DcMessage msg = dc.get_msg(msg_id);
  DcContact sender = dc.get_contact(msg.from_id);
  return generate_mdn_receipt(dc, msg_id, sender.addr, msg.rfc724_mid);
}

bool deltachat_should_send_mdn(DeltaChat& dc, uint32_t msg_id,
                               uint32_t sender_id) {
  return should_send_mdn(dc, msg_id, sender_id);
}

// Threading
std::vector<uint32_t> deltachat_get_thread(DeltaChat& dc, uint32_t msg_id) {
  return get_thread_messages(dc, msg_id);
}

// Quoting
std::string deltachat_format_quote(DeltaChat& dc, uint32_t msg_id) {
  return format_quoted_reply(dc, msg_id);
}

// Chat list
std::vector<ChatListEntry> deltachat_get_chatlist(DeltaChat& dc, bool archived,
                                                  bool pinned_first) {
  return get_ordered_chat_list(dc, archived, pinned_first);
}

int deltachat_get_total_unread(DeltaChat& dc) {
  return get_total_unread_count(dc);
}

void deltachat_mark_seen(DeltaChat& dc, uint32_t chat_id) {
  mark_chat_seen(dc, chat_id);
}

// Trash
bool deltachat_trash_chat(DeltaChat& dc, uint32_t chat_id) {
  return move_chat_to_trash(dc, chat_id);
}

bool deltachat_restore_chat(DeltaChat& dc, uint32_t chat_id) {
  return restore_chat_from_trash(dc, chat_id);
}

bool deltachat_purge_chat(DeltaChat& dc, uint32_t chat_id) {
  return purge_chat(dc, chat_id);
}

// Archive
bool deltachat_archive_chat(DeltaChat& dc, uint32_t chat_id) {
  return archive_chat_op(dc, chat_id);
}

bool deltachat_unarchive_chat(DeltaChat& dc, uint32_t chat_id) {
  return unarchive_chat_op(dc, chat_id);
}

// Pin
bool deltachat_pin_chat(DeltaChat& dc, uint32_t chat_id) {
  return pin_chat_op(dc, chat_id);
}

bool deltachat_unpin_chat(DeltaChat& dc, uint32_t chat_id) {
  return unpin_chat_op(dc, chat_id);
}

// Mute
bool deltachat_mute_chat(DeltaChat& dc, uint32_t chat_id,
                         int64_t duration) {
  return mute_chat_op(dc, chat_id, duration);
}

// Colors
std::string deltachat_get_chat_color(DeltaChat& dc, uint32_t chat_id) {
  return get_chat_color(dc, chat_id);
}

bool deltachat_set_chat_color(DeltaChat& dc, uint32_t chat_id,
                              const std::string& color) {
  return set_chat_color(dc, chat_id, color);
}

// Drafts
bool deltachat_save_draft(DeltaChat& dc, uint32_t chat_id,
                          const std::string& text) {
  return save_draft(dc, chat_id, text);
}

std::string deltachat_get_draft(DeltaChat& dc, uint32_t chat_id) {
  return get_draft(dc, chat_id);
}

void deltachat_clear_draft(DeltaChat& dc, uint32_t chat_id) {
  clear_draft(dc, chat_id);
}

// Maintenance
void deltachat_housekeeping(DeltaChat& dc) { housekeeping(dc); }

// State persistence
json deltachat_export_state() { return export_chat_ops_state(); }
void deltachat_import_state(const json& j) { import_chat_ops_state(j); }

// Info
json deltachat_get_chat_info(DeltaChat& dc, uint32_t chat_id) {
  return get_chat_info_json(dc, chat_id);
}

json deltachat_get_message_info(DeltaChat& dc, uint32_t msg_id) {
  return get_message_info_json(dc, msg_id);
}

// Search
std::vector<SearchResult> deltachat_search(DeltaChat& dc,
                                           const std::string& query,
                                           uint32_t chat_id,
                                           int max_results) {
  return search_messages_full(dc, query, chat_id, max_results);
}

// Contact import
uint32_t deltachat_import_contact(DeltaChat& dc, const std::string& raw_mime) {
  ParsedMime pm = parse_raw_mime(raw_mime);
  return import_contact_from_message(dc, pm);
}

// Dedup
bool deltachat_is_own_message(DeltaChat& dc, const std::string& message_id,
                              const std::string& from_addr) {
  return is_own_sent_message(dc, message_id, from_addr);
}

}  // namespace progressive::deltachat
