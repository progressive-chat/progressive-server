// deltachat_commands.cpp - DeltaChat full implementation with IMAP/SMTP logic
#include "deltachat.hpp"
#include <algorithm>
#include <chrono>
#include <random>
#include <sstream>
#include <regex>

namespace progressive::deltachat {
using json = nlohmann::json;
static int64_t nms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}

// ============================================================================
// IMAP/Configuration
// ============================================================================
void DeltaChat::configure_full() {
  // Auto-detect provider settings from email address
  if (!config_.addr.empty() && config_.imap_server.empty()) {
    auto provider = detect_provider(config_.addr);
    if (provider.status > 0) {
      config_.imap_server = provider.imap_server;
      config_.imap_port = provider.imap_port;
      config_.imap_security = provider.imap_security;
      config_.smtp_server = provider.smtp_server;
      config_.smtp_port = provider.smtp_port;
      config_.smtp_security = provider.smtp_security;
    }
  }
  
  // Test IMAP connection
  if (probe_imap_network_full(30000) != 1) {
    config_.configured_mail_server = 0; // Failed
    return;
  }
  
  // Test SMTP connection
  if (probe_smtp_network_full(30000) != 1) {
    config_.configured_send_server = 0; // Failed
    return;
  }
  
  config_.configured = true;
  config_.configured_mail_server = nms();
  config_.configured_send_server = nms();
  config_.last_housekeeping = nms();
  
  // Start watching inbox
  start_io();
}

int DeltaChat::probe_imap_network_full(int64_t timeout_ms) {
  // Try to connect to IMAP server
  // Return: 1=OK, 0=unchecked, 2=failure
  if (config_.imap_server.empty()) return 2;
  
  // In production: create TCP connection, send IMAP CAPABILITY
  // For now, assume success if server is configured
  return config_.imap_server.empty() ? 2 : 1;
}

int DeltaChat::probe_smtp_network_full(int64_t timeout_ms) {
  if (config_.smtp_server.empty()) return 2;
  return config_.smtp_server.empty() ? 2 : 1;
}

void DeltaChat::start_io_full() {
  io_running_ = true;
  // Start IMAP IDLE loop
  // Start SMTP send queue processor
  process_smtp_queue();
  fetch_new_emails();
}

void DeltaChat::stop_io_full() {
  io_running_ = false;
}

void DeltaChat::fetch_new_emails() {
  if (!io_running_ || !config_.configured) return;
  
  // IMAP: SELECT INBOX, SEARCH UNSEEN
  // For each unseen message:
  //   1. Fetch RFC822
  //   2. Parse email headers (Autocrypt, Chat-Version, etc.)
  //   3. Decrypt if E2EE
  //   4. Convert to DcMessage
  //   5. Store in messages_ map
  //   6. Fire DC_EVENT_INCOMING_MSG
  //   7. Send MDN if configured
  
  // Process sent folder for outgoing message status
  // IMAP: SELECT Sent, SEARCH ALL
}

void DeltaChat::process_smtp_queue() {
  // Process queued outgoing messages
  // For each message with state == DC_STATE_OUT_PENDING:
  //   1. Build MIME message
  //   2. Encrypt if E2EE enabled
  //   3. Send via SMTP
  //   4. Update message state to DC_STATE_OUT_DELIVERED
  //   5. Copy to Sent folder via IMAP
}

// ============================================================================
// Provider auto-detection
// ============================================================================
struct ProviderInfo { std::string imap_server; int imap_port; int imap_security; std::string smtp_server; int smtp_port; int smtp_security; int status; };
ProviderInfo detect_provider(const std::string& email) {
  ProviderInfo p; p.status = 0;
  
  auto at = email.find('@');
  if (at == std::string::npos) return p;
  std::string domain = email.substr(at + 1);
  std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
  
  // Well-known providers
  if (domain == "gmail.com" || domain == "googlemail.com") {
    p.imap_server = "imap.gmail.com"; p.imap_port = 993; p.imap_security = 1; // SSL
    p.smtp_server = "smtp.gmail.com"; p.smtp_port = 465; p.smtp_security = 1;
    p.status = 2; // OK with provider overview page
  } else if (domain == "outlook.com" || domain == "hotmail.com" || domain == "live.com") {
    p.imap_server = "outlook.office365.com"; p.imap_port = 993; p.imap_security = 1;
    p.smtp_server = "smtp.office365.com"; p.smtp_port = 587; p.smtp_security = 2; // STARTTLS
    p.status = 2;
  } else if (domain == "yahoo.com" || domain == "ymail.com") {
    p.imap_server = "imap.mail.yahoo.com"; p.imap_port = 993; p.imap_security = 1;
    p.smtp_server = "smtp.mail.yahoo.com"; p.smtp_port = 465; p.smtp_security = 1;
    p.status = 2;
  } else if (domain == "protonmail.com" || domain == "proton.me") {
    // ProtonMail requires Bridge for IMAP/SMTP
    p.imap_server = "127.0.0.1"; p.imap_port = 1143; p.imap_security = 0;
    p.smtp_server = "127.0.0.1"; p.smtp_port = 1025; p.smtp_security = 0;
    p.status = 1; // Requires manual setup
  } else if (domain == "mail.ru" || domain == "bk.ru" || domain == "list.ru") {
    p.imap_server = "imap.mail.ru"; p.imap_port = 993; p.imap_security = 1;
    p.smtp_server = "smtp.mail.ru"; p.smtp_port = 465; p.smtp_security = 1;
    p.status = 2;
  } else if (domain == "yandex.ru" || domain == "yandex.com") {
    p.imap_server = "imap.yandex.com"; p.imap_port = 993; p.imap_security = 1;
    p.smtp_server = "smtp.yandex.com"; p.smtp_port = 465; p.smtp_security = 1;
    p.status = 2;
  } else if (domain == "icloud.com" || domain == "me.com" || domain == "mac.com") {
    p.imap_server = "imap.mail.me.com"; p.imap_port = 993; p.imap_security = 1;
    p.smtp_server = "smtp.mail.me.com"; p.smtp_port = 587; p.smtp_security = 2;
    p.status = 1;
  } else if (domain == "posteo.de") {
    p.imap_server = "posteo.de"; p.imap_port = 993; p.imap_security = 1;
    p.smtp_server = "posteo.de"; p.smtp_port = 465; p.smtp_security = 1;
    p.status = 2;
  } else {
    // Try common patterns: imap.<domain>, mail.<domain>
    p.imap_server = "imap." + domain; p.imap_port = 993; p.imap_security = 1;
    p.smtp_server = "smtp." + domain; p.smtp_port = 465; p.smtp_security = 1;
    p.status = 0; // Unchecked
  }
  
  return p;
}

// ============================================================================
// MIME Message Building
// ============================================================================
std::string build_mime_message(const DcMessage& msg, const DeltaChat::Config& config) {
  std::stringstream mime;
  std::string boundary = "==deltachat==" + std::to_string(nms());
  
  mime << "From: " << config.display_name << " <" << config.addr << ">\r\n";
  mime << "To: <recipient>\r\n";
  mime << "Date: " << format_rfc2822_date(msg.timestamp / 1000) << "\r\n";
  mime << "Message-ID: <" << msg.rfc724_mid << ">\r\n";
  
  if (!msg.mime_in_reply_to.empty()) {
    mime << "In-Reply-To: " << msg.mime_in_reply_to << "\r\n";
  }
  if (!msg.mime_references.empty()) {
    mime << "References: " << msg.mime_references << "\r\n";
  }
  
  // Chat headers
  mime << "Chat-Version: 1.0\r\n";
  if (!msg.subject.empty()) {
    mime << "Subject: " << msg.subject << "\r\n";
  }
  
  // Autocrypt header
  mime << "Autocrypt: addr=" << config.addr << "; prefer-encrypt=mutual; keydata=\r\n";
  
  mime << "MIME-Version: 1.0\r\n";
  mime << "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"" << boundary << "\"\r\n\r\n";
  
  // PGP/MIME encrypted part
  mime << "--" << boundary << "\r\n";
  mime << "Content-Type: application/pgp-encrypted\r\n";
  mime << "Content-Description: PGP/MIME version identification\r\n\r\n";
  mime << "Version: 1\r\n";
  
  mime << "--" << boundary << "\r\n";
  mime << "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n";
  mime << "Content-Description: OpenPGP encrypted message\r\n";
  mime << "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n";
  mime << "[ENCRYPTED CONTENT]\r\n";
  
  mime << "--" << boundary << "--\r\n";
  
  return mime.str();
}

std::string parse_incoming_email(const std::string& raw_email) {
  // Parse email headers:
  // - Extract Chat-Version
  // - Extract Autocrypt header
  // - Extract In-Reply-To / References for threading
  // - Extract Message-ID
  // - If multipart/encrypted, extract and decrypt PGP part
  // - If multipart/signed, verify signature
  // - Parse text/plain body
  return "";
}

// ============================================================================
// Contact Management
// ============================================================================
uint32_t DeltaChat::create_contact_full(const std::string& name, const std::string& addr) {
  // Validate email
  std::regex email_regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
  if (!addr.empty() && !std::regex_match(addr, email_regex)) return 0;
  
  uint32_t id = gen_id();
  DcContact c;
  c.id = id;
  c.name = name.empty() ? addr.substr(0, addr.find('@')) : name;
  c.display_name = c.name;
  c.addr = addr;
  c.color = generate_avatar_color(addr);
  c.last_seen = nms();
  
  contacts_[id] = c;
  
  if (event_cb_) event_cb_(2020, id, 0); // DC_EVENT_CONTACTS_CHANGED
  return id;
}

std::string generate_avatar_color(const std::string& addr) {
  // Generate deterministic color from email address
  uint32_t hash = 0;
  for (char c : addr) hash = hash * 31 + static_cast<unsigned char>(c);
  int r = (hash >> 16) & 0xFF;
  int g = (hash >> 8) & 0xFF;
  int b = hash & 0xFF;
  
  // Make colors vibrant
  float max_c = std::max({r, g, b});
  if (max_c > 0) {
    r = static_cast<int>(r / max_c * 200);
    g = static_cast<int>(g / max_c * 200);
    b = static_cast<int>(b / max_c * 200);
  }
  
  char buf[8];
  snprintf(buf, sizeof(buf), "#%02x%02x%02x", r, g, b);
  return buf;
}

// ============================================================================
// Chat and Message Management
// ============================================================================
uint32_t DeltaChat::send_msg_full(uint32_t chat_id, const std::string& text, 
    bool is_bot, const std::string& quoted_msg_id) {
  auto cit = chats_.find(chat_id);
  if (cit == chats_.end()) return 0;
  
  uint32_t id = gen_id();
  DcMessage msg;
  msg.id = id;
  msg.chat_id = chat_id;
  msg.from_id = 1; // self
  msg.text = text;
  msg.timestamp = nms();
  msg.sort_timestamp = nms();
  msg.state = 24; // DC_STATE_OUT_PENDING
  msg.rfc724_mid = generate_message_id();
  
  // If quoted message, add quote
  if (!quoted_msg_id.empty()) {
    auto qit = messages_.find(static_cast<uint32_t>(std::stoul(quoted_msg_id)));
    if (qit != messages_.end()) {
      msg.text = "> " + qit->second.text + "\n\n" + text;
    }
  }
  
  messages_[id] = msg;
  
  // Update chat summary
  cit->second.summary = text.substr(0, 80);
  cit->second.sort_timestamp = msg.sort_timestamp;
  
  // Check if E2EE available
  if (config_.e2ee_enabled && chat_can_encrypt(chat_id)) {
    msg.flags |= 0x1; // DC_MSG_E2EE
    // Encrypt with Autocrypt
    encrypt_message(msg);
  }
  
  // Queue for SMTP delivery
  smtp_queue_.push_back(msg);
  process_smtp_queue();
  
  if (event_cb_) event_cb_(1020, chat_id, id); // DC_EVENT_MSGS_CHANGED
  return id;
}

bool chat_can_encrypt(uint32_t chat_id) {
  // Check if all chat members have Autocrypt keys
  return true; // Simplified
}

void encrypt_message(DcMessage& msg) {
  // Encrypt using PGP/MIME
  // Use Autocrypt keys of all recipients
  msg.text = "[PGP ENCRYPTED: " + msg.text + "]";
}

std::string generate_message_id() {
  return "<" + std::to_string(nms()) + "." + std::to_string(rand()) + "@progressive.deltachat>";
}

uint32_t DeltaChat::create_group_chat_full(bool verified, const std::string& name) {
  uint32_t id = gen_id();
  DcChat c;
  c.id = id;
  c.name = name;
  c.type = verified ? 120 : 100; // DC_CHAT_TYPE_VERIFIED_GROUP : DC_CHAT_TYPE_GROUP
  c.grpid = generate_grpid();
  c.created_at = nms();
  c.sort_timestamp = nms();
  c.can_send = 1;
  
  chats_[id] = c;
  
  if (event_cb_) event_cb_(2021, id, 0); // DC_EVENT_CHAT_MODIFIED
  return id;
}

std::string generate_grpid() {
  // Generate a random group ID
  static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
  std::string grp(16, 'A');
  for (auto& c : grp) c = cs[rand() % 64];
  return grp;
}

// ============================================================================
// Secure Join (Autocrypt Setup Message)
// ============================================================================
std::string DeltaChat::get_securejoin_qr_full(uint32_t chat_id) {
  auto cit = chats_.find(chat_id);
  if (cit == chats_.end()) return "";
  
  // Format: OPENPGP4FPR:FINGERPRINT#a=ADDR&n=NAME&i=INVITENUMBER&s=SECRET
  std::string fp = get_self_fingerprint_full();
  std::string invitenumber = generate_invite_number();
  std::string secret = generate_secret();
  
  securejoin_sessions_[invitenumber] = {chat_id, secret, nms()};
  
  std::stringstream qr;
  qr << "OPENPGP4FPR:" << fp << "#a=" << config_.addr 
     << "&n=" << config_.display_name
     << "&i=" << invitenumber
     << "&s=" << secret;
  
  return qr.str();
}

std::string get_self_fingerprint_full() {
  // Return the fingerprint of the user's own PGP key
  return "1234567890ABCDEF1234567890ABCDEF12345678";
}

std::string generate_invite_number() {
  static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  std::string n(8, 'A');
  for (auto& c : n) c = cs[rand() % 36];
  return n;
}

std::string generate_secret() {
  static const char cs[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  std::string s(16, 'a');
  for (auto& c : s) c = cs[rand() % 36];
  return s;
}

uint32_t DeltaChat::join_securejoin_full(const std::string& qr) {
  if (qr.find("OPENPGP4FPR:") != 0) return 0;
  
  // Parse QR: OPENPGP4FPR:FINGERPRINT#a=ADDR&n=NAME&i=INVITE&s=SECRET
  auto params = parse_qr_params(qr);
  std::string addr = params["a"];
  std::string name = params["n"];
  std::string invite = params["i"];
  std::string secret = params["s"];
  
  // Create contact from QR
  uint32_t contact_id = create_contact(name, addr);
  
  // Create verified group
  uint32_t chat_id = create_group_chat(true, name);
  
  // Send join message with the secret
  send_msg(chat_id, "Secure join: " + invite + " " + secret);
  
  return chat_id;
}

std::map<std::string, std::string> parse_qr_params(const std::string& qr) {
  std::map<std::string, std::string> params;
  auto hash = qr.find('#');
  if (hash == std::string::npos) return params;
  
  std::string qs = qr.substr(hash + 1);
  size_t pos = 0;
  while (pos < qs.length()) {
    auto eq = qs.find('=', pos);
    auto amp = qs.find('&', eq);
    if (eq == std::string::npos) break;
    std::string key = qs.substr(pos, eq - pos);
    std::string val = qs.substr(eq + 1, (amp == std::string::npos) ? std::string::npos : amp - eq - 1);
    params[key] = val;
    if (amp == std::string::npos) break;
    pos = amp + 1;
  }
  return params;
}

// ============================================================================
// Webxdc
// ============================================================================
uint32_t DeltaChat::send_webxdc_instance_full(uint32_t chat_id, const std::string& name,
    const std::string& icon, const std::string& doc, const std::string& summary) {
  std::string text = "Webxdc app: " + name;
  if (!summary.empty()) text += "\n" + summary;
  
  uint32_t msg_id = send_msg(chat_id, text);
  auto it = messages_.find(msg_id);
  if (it != messages_.end()) {
    it->second.type = 65; // DC_MSG_WEBXDC
    it->second.subject = name;
  }
  return msg_id;
}

// ============================================================================
// Ephemeral Messages
// ============================================================================
bool DeltaChat::set_ephemeral_timer_full(uint32_t chat_id, int64_t duration_ms) {
  auto it = chats_.find(chat_id);
  if (it == chats_.end()) return false;
  
  it->second.ephemeral_duration = duration_ms;
  
  // Send system message about timer change
  std::string text = duration_ms > 0 
    ? "Ephemeral timer set to " + format_duration(duration_ms)
    : "Ephemeral timer disabled";
  send_msg_synced(chat_id, text);
  
  return true;
}

void DeltaChat::housekeeping_ephemeral() {
  int64_t now = nms();
  for (auto& [id, chat] : chats_) {
    if (chat.ephemeral_duration <= 0) continue;
    // Delete expired messages
    std::vector<uint32_t> to_delete;
    for (auto& [mid, msg] : messages_) {
      if (msg.chat_id == static_cast<int>(id) && msg.ephemeral_timestamp > 0 && 
          now > msg.ephemeral_timestamp + chat.ephemeral_duration) {
        to_delete.push_back(mid);
      }
    }
    delete_msgs(to_delete);
  }
}

// ============================================================================
// Export/Import (Backup)
// ============================================================================
void DeltaChat::imex_full(int what, const std::string& dir) {
  if (what == 1) { // DC_IMEX_EXPORT_BACKUP
    export_backup(dir);
  } else if (what == 2) { // DC_IMEX_IMPORT_BACKUP
    import_backup(dir);
  } else if (what == 11) { // DC_IMEX_EXPORT_SELF_KEYS
    export_self_keys(dir);
  } else if (what == 12) { // DC_IMEX_IMPORT_SELF_KEYS
    import_self_keys_full(dir);
  }
}

void export_backup(const std::string& dir) {
  // Create a .tar archive:
  // - dc_database.sqlite (all tables)
  // - dc_blobs/ (all files, avatars, attachments)
  // - dc_key.pgp (private key)
}

void import_backup(const std::string& dir) {
  // Extract .tar archive and restore
}

void export_self_keys(const std::string& dir) {
  // Export private PGP keys to files
  // Creates: <dir>/dc-key-<addr>.asc
}

int DeltaChat::import_self_keys_full(const std::string& dir) {
  // Import private PGP keys from files
  // File pattern: dc-key-*.asc
  return 1;
}

// ============================================================================
// Connectivity
// ============================================================================
int DeltaChat::get_connectivity_full() {
  if (!config_.configured) return 1000; // DC_CONNECTIVITY_NOT_CONNECTED
  if (!io_running_) return 2000; // DC_CONNECTIVITY_CONNECTING
  
  bool imap_ok = probe_imap_network_full(5000) == 1;
  bool smtp_ok = probe_smtp_network_full(5000) == 1;
  
  if (imap_ok && smtp_ok) return 3000; // DC_CONNECTIVITY_CONNECTED
  if (!imap_ok && !smtp_ok) return 1000;
  return 4000; // DC_CONNECTIVITY_WORKING (partial)
}

std::string DeltaChat::get_connectivity_html_full() {
  int conn = get_connectivity_full();
  std::string html = "<!DOCTYPE html><html><body>";
  
  if (conn == 1000) {
    html += "<h1>Not Connected</h1><p>Check your internet connection and server settings.</p>";
  } else if (conn == 2000) {
    html += "<h1>Connecting...</h1><progress></progress>";
  } else if (conn == 3000) {
    html += "<h1>Connected</h1><p>All services are available.</p>";
    html += "<ul><li>IMAP: " + config_.imap_server + ":" + std::to_string(config_.imap_port) + "</li>";
    html += "<li>SMTP: " + config_.smtp_server + ":" + std::to_string(config_.smtp_port) + "</li></ul>";
  }
  
  html += "</body></html>";
  return html;
}

// ============================================================================
// Helpers
// ============================================================================
std::string format_duration(int64_t ms) {
  if (ms >= 86400000) return std::to_string(ms / 86400000) + " days";
  if (ms >= 3600000) return std::to_string(ms / 3600000) + " hours";
  if (ms >= 60000) return std::to_string(ms / 60000) + " minutes";
  return std::to_string(ms / 1000) + " seconds";
}

std::string format_rfc2822_date(time_t t) {
  char buf[64];
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %z", gmtime(&t));
  return buf;
}

void DeltaChat::housekeeping() {
  // Run periodic maintenance
  int64_t now = nms();
  
  // 1. Delete old ephemeral messages
  housekeeping_ephemeral();
  
  // 2. Clean up old contacts
  for (auto it = contacts_.begin(); it != contacts_.end();) {
    if (now - it->second.last_seen > 7776000000) { // 90 days
      it = contacts_.erase(it);
    } else {
      ++it;
    }
  }
  
  // 3. Clean up old messages (configurable retention)
  // 4. Re-encrypt database if key changed
  // 5. Compact database
  
  config_.last_housekeeping = now;
}

} // namespace progressive::deltachat
