#include "email_identity.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <iomanip>
#include <map>
#include <mutex>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_map>

#include <nlohmann/json.hpp>

#include "../json.hpp"
#include "../storage/database.hpp"
#include "../util/base64.hpp"
#include "../util/log.hpp"
#include "../util/random.hpp"
#include "../util/time.hpp"
#include "../util/token.hpp"

// ---------------------------------------------------------------------------
// Low-level socket helpers (POSIX)
// ---------------------------------------------------------------------------
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace progressive::auth {

// ============================================================================
// Constants
// ============================================================================

static constexpr const char* kEmailIdentityTag = "email_identity";
static constexpr int kDefaultSmtpPort = 587;
static constexpr int kDefaultSmtpTlsPort = 465;
static constexpr int kDkimKeyBits = 2048;
static constexpr int kMaxRetries = 5;
static constexpr int kRetryBaseDelaySec = 10;
static constexpr int kEmailTokenExpirySec = 3600;        // 1 hour
static constexpr int kMsisdnTokenExpirySec = 600;        // 10 minutes
static constexpr int kSessionExpirySec = 86400;          // 24 hours
static constexpr int kRateLimitWindowSec = 60;
static constexpr int kMaxEmailsPerWindow = 10;
static constexpr int kMaxEmailsPerAddressPerWindow = 3;
static constexpr int kBounceThreshold = 3;
static constexpr int kMsisdnCodeLength = 6;
static constexpr int kRecaptchaTimeoutSec = 30;
static constexpr int kHttpTimeoutSec = 30;
static constexpr size_t kMaxQueueSize = 10000;

// ============================================================================
// Internal helper: simple URL-encode
// ============================================================================
namespace {

std::string url_encode(std::string_view src) {
  std::ostringstream out;
  out << std::hex << std::uppercase;
  for (unsigned char c : src) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out << static_cast<char>(c);
    } else {
      out << '%' << std::setw(2) << std::setfill('0')
          << static_cast<int>(c);
    }
  }
  return out.str();
}

std::string html_escape(std::string_view src) {
  std::string out;
  out.reserve(src.size());
  for (char c : src) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out += c; break;
    }
  }
  return out;
}

std::string to_hex(const unsigned char* data, size_t len) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    out << std::setw(2) << static_cast<int>(data[i]);
  }
  return out.str();
}

std::string hex_decode(std::string_view hex) {
  std::string out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    unsigned int byte;
    std::string byte_str(hex.substr(i, 2));
    byte = static_cast<unsigned int>(std::stoul(byte_str, nullptr, 16));
    out += static_cast<char>(byte);
  }
  return out;
}

std::string hmac_sha256(std::string_view key, std::string_view data) {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int result_len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(),
       result, &result_len);
  return std::string(reinterpret_cast<char*>(result), result_len);
}

uint64_t generate_nonce() {
  return util::random_uint64();
}

std::string iso8601_now() {
  return util::iso8601();
}

uint64_t now_ms_stamp() {
  return util::now_ms();
}

bool is_valid_email(std::string_view email) {
  // Simple RFC 5322-ish validation
  static const std::regex email_re(
      R"(^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$)");
  return std::regex_match(std::string(email), email_re);
}

bool is_valid_msisdn(std::string_view phone) {
  // E.164-ish validation: + followed by 7 to 15 digits
  static const std::regex msisdn_re(R"(^\+\d{7,15}$)");
  return std::regex_match(std::string(phone), msisdn_re);
}

std::string now_rfc2822() {
  auto t = std::time(nullptr);
  std::tm tm;
  gmtime_r(&t, &tm);
  char buf[64];
  static const char* days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char* months[] = {
      "Jan", "Feb", "Mar", "Apr", "May", "Jun",
      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  snprintf(buf, sizeof(buf), "%s, %02d %s %04d %02d:%02d:%02d +0000",
           days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon],
           tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
  return std::string(buf);
}

std::string generate_boundary() {
  std::string b = util::random_token(24);
  return "----=_NextPart_" + b;
}

}  // anonymous namespace

// ============================================================================
// EmailAddress
// ============================================================================

EmailAddress::EmailAddress(std::string address, std::string display)
    : address_(std::move(address)), display_name_(std::move(display)) {}

const std::string& EmailAddress::address() const { return address_; }
const std::string& EmailAddress::display_name() const { return display_name_; }

std::string EmailAddress::formatted() const {
  if (display_name_.empty()) return address_;
  return display_name_ + " <" + address_ + ">";
}

// ============================================================================
// EmailTemplate
// ============================================================================

EmailTemplate::EmailTemplate(std::string subject, std::string text_body,
                             std::string html_body)
    : subject_(std::move(subject)),
      text_body_(std::move(text_body)),
      html_body_(std::move(html_body)) {}

const std::string& EmailTemplate::subject() const { return subject_; }
const std::string& EmailTemplate::text_body() const { return text_body_; }
const std::string& EmailTemplate::html_body() const { return html_body_; }

void EmailTemplate::set_variable(const std::string& key,
                                 const std::string& value) {
  variables_[key] = value;
}

std::string EmailTemplate::render_subject() const {
  return render(subject_);
}

std::string EmailTemplate::render_text() const {
  return render(text_body_);
}

std::string EmailTemplate::render_html() const {
  return render(html_body_);
}

std::string EmailTemplate::render(std::string_view tpl) const {
  std::string result(tpl);
  for (const auto& [key, value] : variables_) {
    std::string placeholder = "{{" + key + "}}";
    size_t pos = 0;
    while ((pos = result.find(placeholder, pos)) != std::string::npos) {
      result.replace(pos, placeholder.size(), value);
      pos += value.size();
    }
  }
  return result;
}

// ============================================================================
// Localization: English (default) + basic i18n support
// ============================================================================

namespace {

struct LocaleStrings {
  std::string password_reset_subject;
  std::string password_reset_title;
  std::string password_reset_body;
  std::string email_verify_subject;
  std::string email_verify_title;
  std::string email_verify_body;
  std::string invite_subject;
  std::string invite_title;
  std::string invite_body;
  std::string digest_subject;
  std::string digest_title;
  std::string digest_body;
  std::string unsubscribe_text;
  std::string unsubscribe_link_text;
  std::string footer_text;
};

LocaleStrings make_english() {
  return {
    /* password_reset_subject */ "Reset your Matrix password",
    /* password_reset_title  */ "Password Reset Request",
    /* password_reset_body   */ "Hello {{display_name}},\n\n"
        "A request to reset the password for your Matrix account "
        "{{user_id}} has been received.\n\n"
        "If you made this request, please click the link below to "
        "set a new password:\n\n{{reset_link}}\n\n"
        "This link will expire in {{expiry_hours}} hour(s).\n\n"
        "If you did NOT request a password reset, you can safely "
        "ignore this email.\n\n"
        "---\n{{server_name}}",
    /* email_verify_subject  */ "Verify your email address",
    /* email_verify_title    */ "Email Verification",
    /* email_verify_body     */ "Hello {{display_name}},\n\n"
        "Please verify your email address by clicking the link "
        "below:\n\n{{verify_link}}\n\n"
        "This link will expire in {{expiry_hours}} hour(s).\n\n"
        "If you did not register this email, you can safely "
        "ignore this message.\n\n"
        "---\n{{server_name}}",
    /* invite_subject        */ "{{inviter_name}} invited you to Matrix",
    /* invite_title          */ "You're invited to Matrix!",
    /* invite_body           */ "Hello,\n\n"
        "{{inviter_name}} ({{inviter_id}}) has invited you to "
        "join Matrix on {{server_name}}.\n\n"
        "Get started: {{invite_link}}\n\n"
        "Room: {{room_name}}\n\n"
        "---\n{{server_name}}",
    /* digest_subject        */ "You have {{unread_count}} unread messages",
    /* digest_title          */ "Missed Messages Digest",
    /* digest_body           */ "Hello {{display_name}},\n\n"
        "You have {{unread_count}} unread messages across "
        "{{room_count}} room(s).\n\n"
        "{{room_summary}}\n\n"
        "---\n{{server_name}}\n\n"
        "{{unsubscribe_link}}",
    /* unsubscribe_text      */ "Unsubscribe from these notifications",
    /* unsubscribe_link_text */ "Unsubscribe",
    /* footer_text           */ "This is an automated message from "
        "{{server_name}}. Please do not reply."
  };
}

LocaleStrings make_french() {
  auto s = make_english();
  s.password_reset_subject = "Réinitialiser votre mot de passe Matrix";
  s.password_reset_title  = "Demande de réinitialisation";
  s.password_reset_body   = "Bonjour {{display_name}},\n\n"
      "Une demande de réinitialisation du mot de passe pour votre "
      "compte Matrix {{user_id}} a été reçue.\n\n"
      "Si vous êtes à l'origine de cette demande, cliquez sur le lien "
      "ci-dessous :\n\n{{reset_link}}\n\n"
      "Ce lien expire dans {{expiry_hours}} heure(s).\n\n"
      "Si vous n'avez PAS demandé de réinitialisation, ignorez cet email.\n\n"
      "---\n{{server_name}}";
  s.email_verify_subject = "Vérifiez votre adresse email";
  s.email_verify_title = "Vérification d'email";
  s.email_verify_body = "Bonjour {{display_name}},\n\n"
      "Veuillez vérifier votre adresse email en cliquant sur le lien "
      "ci-dessous :\n\n{{verify_link}}\n\n"
      "Ce lien expire dans {{expiry_hours}} heure(s).\n\n"
      "Si vous n'avez pas enregistré cette adresse, ignorez ce message.\n\n"
      "---\n{{server_name}}";
  s.invite_subject = "{{inviter_name}} vous invite sur Matrix";
  s.invite_title = "Vous êtes invité sur Matrix !";
  s.invite_body = "Bonjour,\n\n"
      "{{inviter_name}} ({{inviter_id}}) vous invite à rejoindre Matrix "
      "sur {{server_name}}.\n\n"
      "Commencer : {{invite_link}}\n\n"
      "Salon : {{room_name}}\n\n"
      "---\n{{server_name}}";
  s.digest_subject = "Vous avez {{unread_count}} messages non lus";
  s.digest_title = "Résumé des messages manqués";
  s.digest_body = "Bonjour {{display_name}},\n\n"
      "Vous avez {{unread_count}} messages non lus dans "
      "{{room_count}} salon(s).\n\n"
      "{{room_summary}}\n\n"
      "---\n{{server_name}}\n\n"
      "{{unsubscribe_link}}";
  s.unsubscribe_text = "Se désabonner de ces notifications";
  s.unsubscribe_link_text = "Se désabonner";
  return s;
}

LocaleStrings make_german() {
  auto s = make_english();
  s.password_reset_subject = "Matrix-Passwort zurücksetzen";
  s.password_reset_title  = "Passwort-Zurücksetzung";
  s.password_reset_body   = "Hallo {{display_name}},\n\n"
      "Eine Anfrage zum Zurücksetzen des Passworts für Ihr Matrix-Konto "
      "{{user_id}} wurde empfangen.\n\n"
      "Klicken Sie auf den folgenden Link, um ein neues Passwort "
      "festzulegen:\n\n{{reset_link}}\n\n"
      "Dieser Link läuft in {{expiry_hours}} Stunde(n) ab.\n\n"
      "Falls Sie diese Anfrage NICHT gestellt haben, ignorieren Sie "
      "diese E-Mail.\n\n"
      "---\n{{server_name}}";
  s.email_verify_subject = "E-Mail-Adresse bestätigen";
  s.email_verify_title = "E-Mail-Bestätigung";
  s.email_verify_body = "Hallo {{display_name}},\n\n"
      "Bitte bestätigen Sie Ihre E-Mail-Adresse mit folgendem Link:\n\n"
      "{{verify_link}}\n\n"
      "Dieser Link läuft in {{expiry_hours}} Stunde(n) ab.\n\n"
      "---\n{{server_name}}";
  s.invite_subject = "{{inviter_name}} hat Sie zu Matrix eingeladen";
  s.invite_title = "Matrix-Einladung";
  s.invite_body = "Hallo,\n\n"
      "{{inviter_name}} ({{inviter_id}}) hat Sie zu Matrix auf "
      "{{server_name}} eingeladen.\n\n"
      "Los geht's: {{invite_link}}\n\n"
      "Raum: {{room_name}}\n\n"
      "---\n{{server_name}}";
  s.digest_subject = "Sie haben {{unread_count}} ungelesene Nachrichten";
  s.digest_title = "Verpasste Nachrichten";
  s.digest_body = "Hallo {{display_name}},\n\n"
      "Sie haben {{unread_count}} ungelesene Nachrichten in "
      "{{room_count}} Raum/Räumen.\n\n"
      "{{room_summary}}\n\n"
      "---\n{{server_name}}\n\n"
      "{{unsubscribe_link}}";
  s.unsubscribe_text = "Von Benachrichtigungen abmelden";
  s.unsubscribe_link_text = "Abmelden";
  return s;
}

LocaleStrings make_spanish() {
  auto s = make_english();
  s.password_reset_subject = "Restablecer su contraseña de Matrix";
  s.password_reset_title  = "Restablecimiento de contraseña";
  s.password_reset_body   = "Hola {{display_name}},\n\n"
      "Se ha recibido una solicitud para restablecer la contraseña de "
      "su cuenta Matrix {{user_id}}.\n\n"
      "Haga clic en el siguiente enlace para establecer una nueva "
      "contraseña:\n\n{{reset_link}}\n\n"
      "Este enlace caduca en {{expiry_hours}} hora(s).\n\n"
      "Si NO solicitó esto, ignore este correo.\n\n"
      "---\n{{server_name}}";
  s.email_verify_subject = "Verifique su dirección de correo";
  s.email_verify_title = "Verificación de correo";
  s.email_verify_body = "Hola {{display_name}},\n\n"
      "Verifique su correo haciendo clic en:\n\n{{verify_link}}\n\n"
      "Este enlace caduca en {{expiry_hours}} hora(s).\n\n"
      "---\n{{server_name}}";
  s.invite_subject = "{{inviter_name}} te ha invitado a Matrix";
  s.invite_title = "¡Invitación a Matrix!";
  s.invite_body = "Hola,\n\n"
      "{{inviter_name}} ({{inviter_id}}) te ha invitado a Matrix en "
      "{{server_name}}.\n\n"
      "Empieza aquí: {{invite_link}}\n\n"
      "Sala: {{room_name}}\n\n"
      "---\n{{server_name}}";
  s.digest_subject = "Tienes {{unread_count}} mensajes sin leer";
  s.digest_title = "Resumen de mensajes";
  s.digest_body = "Hola {{display_name}},\n\n"
      "Tienes {{unread_count}} mensajes sin leer en "
      "{{room_count}} sala(s).\n\n"
      "{{room_summary}}\n\n"
      "---\n{{server_name}}\n\n"
      "{{unsubscribe_link}}";
  s.unsubscribe_text = "Cancelar suscripción";
  s.unsubscribe_link_text = "Cancelar suscripción";
  return s;
}

const std::unordered_map<std::string, LocaleStrings> kLocales = {
  {"en", make_english()},
  {"fr", make_french()},
  {"de", make_german()},
  {"es", make_spanish()},
};

const LocaleStrings& get_locale(const std::string& lang) {
  auto it = kLocales.find(lang);
  if (it != kLocales.end()) return it->second;
  // Fallback to first 2 chars
  std::string short_lang = lang.substr(0, 2);
  auto it2 = kLocales.find(short_lang);
  if (it2 != kLocales.end()) return it2->second;
  return kLocales.at("en");
}

}  // anonymous namespace

// ============================================================================
// RateLimiter
// ============================================================================

RateLimiter::RateLimiter(int window_secs, int max_total, int max_per_address)
    : window_secs_(window_secs),
      max_total_(max_total),
      max_per_address_(max_per_address) {}

bool RateLimiter::allow(std::string_view address) {
  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(mutex_);
  prune(now);

  std::string addr(address);
  int64_t addr_count = per_address_[addr].size();

  if (addr_count >= max_per_address_) return false;
  if (static_cast<int64_t>(timestamps_.size()) >= max_total_) return false;

  timestamps_.push_back(now);
  per_address_[addr].push_back(now);
  return true;
}

void RateLimiter::prune(std::chrono::steady_clock::time_point now) {
  auto cutoff = now - std::chrono::seconds(window_secs_);

  while (!timestamps_.empty() && timestamps_.front() < cutoff) {
    timestamps_.pop_front();
  }

  auto addr_it = per_address_.begin();
  while (addr_it != per_address_.end()) {
    auto& q = addr_it->second;
    while (!q.empty() && q.front() < cutoff) {
      q.pop_front();
    }
    if (q.empty()) {
      addr_it = per_address_.erase(addr_it);
    } else {
      ++addr_it;
    }
  }
}

int64_t RateLimiter::remaining(std::string_view address) const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::string addr(address);
  auto it = per_address_.find(addr);
  int64_t used = (it != per_address_.end()) ? it->second.size() : 0;
  int64_t per_addr_rem = max_per_address_ - used;
  int64_t total_rem = max_total_ - static_cast<int64_t>(timestamps_.size());
  return std::min(per_addr_rem, total_rem);
}

// ============================================================================
// SmtpError
// ============================================================================

SmtpError::SmtpError(int code, std::string msg, bool retryable)
    : code_(code), message_(std::move(msg)), retryable_(retryable) {}

int SmtpError::code() const { return code_; }
const std::string& SmtpError::message() const { return message_; }
bool SmtpError::is_retryable() const { return retryable_; }

const char* SmtpError::what() const noexcept { return message_.c_str(); }

// ============================================================================
// SmtpConnection
// ============================================================================

struct SmtpConnection::Impl {
  std::string host;
  int port = kDefaultSmtpPort;
  bool use_tls = false;
  int fd = -1;
  bool connected = false;
  std::string read_buffer;

  ~Impl() {
    if (fd >= 0) {
      close(fd);
      fd = -1;
    }
  }
};

SmtpConnection::SmtpConnection(std::string smtp_host, int smtp_port,
                                bool tls, std::string helo_name)
    : host_(std::move(smtp_host)),
      port_(smtp_port),
      use_tls_(tls),
      helo_name_(std::move(helo_name)),
      impl_(std::make_unique<Impl>()) {
  impl_->host = host_;
  impl_->port = port_;
  impl_->use_tls = use_tls_;
}

SmtpConnection::~SmtpConnection() {
  try { disconnect(); } catch (...) {}
}

void SmtpConnection::connect() {
  if (impl_->connected) return;

  struct addrinfo hints {};
  struct addrinfo* res = nullptr;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  std::string port_str = std::to_string(impl_->port);
  int gaierr = getaddrinfo(impl_->host.c_str(), port_str.c_str(),
                            &hints, &res);
  if (gaierr != 0) {
    throw SmtpError(421,
        "DNS resolution failed for " + impl_->host + ": " +
        std::string(gai_strerror(gaierr)), true);
  }

  // Try each address
  struct addrinfo* rp = nullptr;
  for (rp = res; rp != nullptr; rp = rp->ai_next) {
    impl_->fd = socket(rp->ai_family, rp->ai_sockstream, rp->ai_protocol);
    if (impl_->fd < 0) continue;

    if (::connect(impl_->fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;  // success
    }

    close(impl_->fd);
    impl_->fd = -1;
  }

  freeaddrinfo(res);

  if (impl_->fd < 0) {
    throw SmtpError(421, "Could not connect to SMTP server " + host_ +
        ":" + std::to_string(port_), true);
  }

  // Set socket timeout
  struct timeval tv;
  tv.tv_sec = 30;
  tv.tv_usec = 0;
  setsockopt(impl_->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(impl_->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  // Read greeting
  auto greeting = read_response();
  if (greeting.first < 200 || greeting.first >= 300) {
    disconnect();
    throw SmtpError(greeting.first,
        "SMTP greeting error: " + greeting.second, false);
  }

  // EHLO
  send_command("EHLO " + helo_name_);
  auto ehlo = read_response();
  if (ehlo.first < 200 || ehlo.first >= 300) {
    // Try HELO fallback
    send_command("HELO " + helo_name_);
    auto helo = read_response();
    if (helo.first < 200 || helo.first >= 300) {
      disconnect();
      throw SmtpError(helo.first,
          "EHLO/HELO failed: " + helo.second, false);
    }
  }

  // STARTTLS if requested
  if (impl_->use_tls && !use_tls_) {
    // We skip actual TLS negotiation here; in production you'd use OpenSSL
    // For now we assume the server supports it or the connection is already TLS
    send_command("STARTTLS");
    auto tls_resp = read_response();
    if (tls_resp.first != 220) {
      progressive::log::warn(kEmailIdentityTag,
          "STARTTLS not supported by " + host_);
    }
  }

  impl_->connected = true;

  progressive::log::info(kEmailIdentityTag,
      "Connected to SMTP server " + host_ + ":" + std::to_string(port_));
}

void SmtpConnection::disconnect() {
  if (!impl_->connected) return;
  try {
    send_command("QUIT");
    read_response();
  } catch (...) {}
  if (impl_->fd >= 0) {
    close(impl_->fd);
    impl_->fd = -1;
  }
  impl_->connected = false;
}

bool SmtpConnection::is_connected() const {
  return impl_->connected;
}

void SmtpConnection::authenticate(std::string_view username,
                                   std::string_view password) {
  if (!impl_->connected) connect();

  std::string auth_plain = std::string(username) + "\0" +
      std::string(username) + "\0" + std::string(password);
  std::string encoded = util::base64::encode(auth_plain);

  send_command("AUTH PLAIN " + encoded);
  auto resp = read_response();

  if (resp.first == 535) {
    throw SmtpError(535, "SMTP authentication failed", false);
  }
  if (resp.first == 334) {
    // Server wants more; send empty line
    send_command("");
    resp = read_response();
  }
  if (resp.first < 200 || resp.first >= 300) {
    throw SmtpError(resp.first,
        "SMTP AUTH error: " + resp.second, false);
  }
}

void SmtpConnection::send_mail(const EmailAddress& from,
                                const std::vector<EmailAddress>& to,
                                const std::vector<EmailAddress>& cc,
                                const std::vector<EmailAddress>& bcc,
                                std::string_view subject,
                                std::string_view text_body,
                                std::string_view html_body,
                                const std::string& dkim_header) {
  if (!impl_->connected) connect();

  // MAIL FROM
  send_command("MAIL FROM:<" + from.address() + ">");
  auto mf = read_response();
  if (mf.first < 200 || mf.first >= 300) {
    throw SmtpError(mf.first, "MAIL FROM error: " + mf.second, false);
  }

  // Collect all recipients
  std::vector<EmailAddress> all_rcpt = to;
  all_rcpt.insert(all_rcpt.end(), cc.begin(), cc.end());
  all_rcpt.insert(all_rcpt.end(), bcc.begin(), bcc.end());

  for (const auto& rcpt : all_rcpt) {
    send_command("RCPT TO:<" + rcpt.address() + ">");
    auto rt = read_response();
    if (rt.first < 200 || rt.first >= 300) {
      throw SmtpError(rt.first,
          "RCPT TO <" + rcpt.address() + "> error: " + rt.second, false);
    }
  }

  // DATA
  send_command("DATA");
  auto data_resp = read_response();
  if (data_resp.first != 354) {
    throw SmtpError(data_resp.first,
        "DATA command error: " + data_resp.second, false);
  }

  // Build MIME message
  std::string boundary = generate_boundary();
  std::string message_id = "<" + util::random_token(16) + "@" + helo_name_ + ">";

  std::ostringstream msg;
  msg << "Message-ID: " << message_id << "\r\n";
  msg << "Date: " << now_rfc2822() << "\r\n";
  msg << "From: " << from.formatted() << "\r\n";

  // To
  msg << "To: ";
  for (size_t i = 0; i < to.size(); ++i) {
    if (i > 0) msg << ", ";
    msg << to[i].formatted();
  }
  msg << "\r\n";

  // Cc
  if (!cc.empty()) {
    msg << "Cc: ";
    for (size_t i = 0; i < cc.size(); ++i) {
      if (i > 0) msg << ", ";
      msg << cc[i].formatted();
    }
    msg << "\r\n";
  }

  msg << "Subject: =?UTF-8?B?"
      << util::base64::encode(std::string(subject))
      << "?=\r\n";

  msg << "MIME-Version: 1.0\r\n";
  msg << "Content-Type: multipart/alternative; boundary=\"" << boundary
      << "\"\r\n";

  // DKIM header if provided
  if (!dkim_header.empty()) {
    msg << dkim_header;
    if (dkim_header.back() != '\n') msg << "\r\n";
  }

  msg << "\r\n";

  // Text part
  msg << "--" << boundary << "\r\n";
  msg << "Content-Type: text/plain; charset=\"UTF-8\"\r\n";
  msg << "Content-Transfer-Encoding: base64\r\n";
  msg << "\r\n";
  msg << util::base64::encode(std::string(text_body)) << "\r\n";
  msg << "\r\n";

  // HTML part
  msg << "--" << boundary << "\r\n";
  msg << "Content-Type: text/html; charset=\"UTF-8\"\r\n";
  msg << "Content-Transfer-Encoding: base64\r\n";
  msg << "\r\n";
  msg << util::base64::encode(std::string(html_body)) << "\r\n";
  msg << "\r\n";

  // Closing boundary
  msg << "--" << boundary << "--\r\n";
  msg << "\r\n.\r\n";

  std::string msg_str = msg.str();

  // Dot-stuffing: escape lines starting with "."
  std::string stuffed;
  stuffed.reserve(msg_str.size() + 512);
  std::istringstream stream(msg_str);
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line[0] == '.') {
      stuffed += '.';
    }
    stuffed += line + "\r\n";
  }

  // Send the message data
  if (send(impl_->fd, stuffed.data(), stuffed.size(), 0) < 0) {
    throw SmtpError(451, "Failed to send message data", true);
  }

  auto done = read_response();
  if (done.first < 200 || done.first >= 300) {
    throw SmtpError(done.first,
        "Message sending failed: " + done.second, false);
  }

  progressive::log::info(kEmailIdentityTag,
      "Email sent to " + to[0].address() +
      (to.size() > 1 ? " (+" + std::to_string(to.size() - 1) + " more)" : ""));
}

void SmtpConnection::send_command(const std::string& cmd) {
  std::string line = cmd + "\r\n";
  if (send(impl_->fd, line.data(), line.size(), 0) < 0) {
    throw SmtpError(451,
        "Failed to send SMTP command: " + cmd, true);
  }
}

std::pair<int, std::string> SmtpConnection::read_response() {
  std::string full_response;
  char buf[4096];

  while (true) {
    ssize_t n = recv(impl_->fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
      throw SmtpError(451, "SMTP connection lost during read", true);
    }
    buf[n] = '\0';
    full_response += buf;

    // SMTP multiline responses: lines after the last begin with "XXX "
    // (space, not dash). Check if we have a complete response.
    if (full_response.size() >= 4 && full_response[3] == ' ') {
      // Check if this is the last line of a potentially multi-line response
      size_t last_crlf = full_response.rfind("\r\n");
      if (last_crlf == std::string::npos) {
        // Single line
        break;
      }
      // Check if the line starting after last_crlf+2 has a space at pos 3
      size_t line_start = last_crlf + 2;
      if (line_start + 3 < full_response.size() &&
          full_response[line_start + 3] == ' ') {
        break;
      }
      // If we haven't seen CRLF at all, and it's short, might be complete
      if (last_crlf == std::string::npos) break;
    }

    // Safety: if response starts with a complete single line
    if (full_response.size() >= 3 && full_response[3] == ' ' &&
        (full_response.find("\r\n") != std::string::npos ||
         full_response.size() < 512)) {
      break;
    }
  }

  // Parse code
  int code = 0;
  if (full_response.size() >= 3) {
    code = std::stoi(full_response.substr(0, 3));
  }

  // Extract message (strip CRLF, codes)
  std::string msg;
  std::istringstream lines(full_response);
  std::string line;
  while (std::getline(lines, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.size() >= 4) {
      msg += line.substr(4) + " ";
    }
  }
  if (!msg.empty()) msg.pop_back();  // trailing space

  return {code, msg};
}

// ============================================================================
// DkimSigner
// ============================================================================

struct DkimSigner::Impl {
  std::string domain;
  std::string selector;
  std::string private_key_pem;
  EVP_PKEY* pkey = nullptr;

  ~Impl() {
    if (pkey) EVP_PKEY_free(pkey);
  }
};

DkimSigner::DkimSigner(std::string domain, std::string selector,
                        std::string private_key_pem)
    : impl_(std::make_unique<Impl>()) {
  impl_->domain = std::move(domain);
  impl_->selector = std::move(selector);
  impl_->private_key_pem = std::move(private_key_pem);

  // Parse private key
  BIO* bio = BIO_new_mem_buf(impl_->private_key_pem.data(),
                              static_cast<int>(impl_->private_key_pem.size()));
  if (!bio) {
    throw std::runtime_error("DKIM: Failed to create BIO for private key");
  }
  impl_->pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!impl_->pkey) {
    throw std::runtime_error("DKIM: Failed to parse private key PEM");
  }
}

DkimSigner::~DkimSigner() = default;

std::string DkimSigner::sign(const std::string& headers,
                              const std::string& body) const {
  // Build DKIM-Signature header (simplified)
  std::string timestamp = std::to_string(std::time(nullptr));

  // Canonicalize body (simple algorithm)
  std::string canonical_body;
  canonical_body.reserve(body.size());
  for (char c : body) {
    if (c == '\r') continue;  // strip CR for simple canonicalization
    canonical_body += c;
  }
  // Ensure trailing CRLF
  if (canonical_body.size() < 2 ||
      canonical_body.substr(canonical_body.size() - 2) != "\r\n") {
    canonical_body += "\r\n";
  }

  // Compute body hash (SHA-256, base64)
  unsigned char body_hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(canonical_body.data()),
         canonical_body.size(), body_hash);
  std::string bh = util::base64::encode(
      std::string_view(reinterpret_cast<const char*>(body_hash),
                       SHA256_DIGEST_LENGTH));

  // Sign the headers
  // In a full implementation we'd canonicalize and hash selected headers.
  // Here we sign the concatenation of the headers and body hash.
  std::string to_sign = headers + "\r\n" + bh;

  unsigned char sig_buf[512];
  size_t sig_len = sizeof(sig_buf);

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_SignInit(ctx, EVP_sha256());
  EVP_SignUpdate(ctx, to_sign.data(), to_sign.size());
  EVP_SignFinal(ctx, sig_buf, reinterpret_cast<unsigned int*>(&sig_len),
                impl_->pkey);
  EVP_MD_CTX_free(ctx);

  std::string signature_b64 = util::base64::encode(
      std::string_view(reinterpret_cast<const char*>(sig_buf), sig_len));

  // Build the DKIM-Signature header
  std::ostringstream dkim;
  dkim << "DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple;\r\n"
       << "  d=" << impl_->domain << ";\r\n"
       << "  s=" << impl_->selector << ";\r\n"
       << "  t=" << timestamp << ";\r\n"
       << "  bh=" << bh << ";\r\n"
       << "  h=from:to:subject:date:message-id;\r\n"
       << "  b=" << signature_b64;

  return dkim.str();
}

DkimSigner DkimSigner::generate(const std::string& domain,
                                 const std::string& selector) {
  // Generate RSA key pair
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(pctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, kDkimKeyBits);

  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_keygen(pctx, &pkey);
  EVP_PKEY_CTX_free(pctx);

  // Export private key as PEM
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

  char* pem_data = nullptr;
  long pem_len = BIO_get_mem_data(bio, &pem_data);
  std::string pem_str(pem_data, static_cast<size_t>(pem_len));

  BIO_free(bio);
  EVP_PKEY_free(pkey);

  return DkimSigner(domain, selector, pem_str);
}

// ============================================================================
// EmailQueue entry
// ============================================================================

struct QueuedEmail {
  std::string id;
  EmailAddress from;
  std::vector<EmailAddress> to;
  std::vector<EmailAddress> cc;
  std::vector<EmailAddress> bcc;
  std::string subject;
  std::string text_body;
  std::string html_body;
  int retry_count = 0;
  uint64_t created_at = 0;
  uint64_t next_retry_at = 0;
};

// ============================================================================
// EmailQueue
// ============================================================================

struct EmailQueue::Impl {
  SmtpConfig config;
  std::unique_ptr<DkimSigner> dkim_signer;
  std::deque<QueuedEmail> queue;
  std::mutex mutex;
  std::condition_variable cv;
  std::thread worker;
  std::atomic<bool> running{false};
  std::atomic<bool> stop_requested{false};
  std::unordered_map<std::string, std::string> bounce_errors;
  std::mutex bounce_mutex;
};

EmailQueue::EmailQueue(SmtpConfig config, std::unique_ptr<DkimSigner> dkim)
    : impl_(std::make_unique<Impl>()) {
  impl_->config = std::move(config);
  impl_->dkim_signer = std::move(dkim);
}

EmailQueue::~EmailQueue() {
  stop();
}

void EmailQueue::start() {
  if (impl_->running.exchange(true)) return;
  impl_->stop_requested = false;
  impl_->worker = std::thread(&EmailQueue::worker_loop, this);
}

void EmailQueue::stop() {
  impl_->stop_requested = true;
  impl_->cv.notify_all();
  if (impl_->worker.joinable()) {
    impl_->worker.join();
  }
  impl_->running = false;
}

std::string EmailQueue::enqueue(const EmailAddress& from,
                                 const std::vector<EmailAddress>& to,
                                 std::string_view subject,
                                 std::string_view text_body,
                                 std::string_view html_body) {
  return enqueue(from, to, {}, {}, subject, text_body, html_body);
}

std::string EmailQueue::enqueue(const EmailAddress& from,
                                 const std::vector<EmailAddress>& to,
                                 const std::vector<EmailAddress>& cc,
                                 const std::vector<EmailAddress>& bcc,
                                 std::string_view subject,
                                 std::string_view text_body,
                                 std::string_view html_body) {
  QueuedEmail qe;
  qe.id = util::random_token(16);
  qe.from = from;
  qe.to = to;
  qe.cc = cc;
  qe.bcc = bcc;
  qe.subject = std::string(subject);
  qe.text_body = std::string(text_body);
  qe.html_body = std::string(html_body);
  qe.created_at = now_ms_stamp();
  qe.next_retry_at = now_ms_stamp();

  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->queue.size() >= kMaxQueueSize) {
      throw std::runtime_error("Email queue is full");
    }
    impl_->queue.push_back(qe);
  }
  impl_->cv.notify_all();

  return qe.id;
}

size_t EmailQueue::queue_size() const {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->queue.size();
}

void EmailQueue::record_bounce(const std::string& message_id,
                                const std::string& error) {
  std::lock_guard<std::mutex> lock(impl_->bounce_mutex);
  impl_->bounce_errors[message_id] = error;
}

std::vector<std::pair<std::string, std::string>>
EmailQueue::get_recent_bounces() const {
  std::lock_guard<std::mutex> lock(impl_->bounce_mutex);
  std::vector<std::pair<std::string, std::string>> result;
  for (const auto& [mid, err] : impl_->bounce_errors) {
    result.emplace_back(mid, err);
  }
  return result;
}

void EmailQueue::worker_loop() {
  progressive::log::info(kEmailIdentityTag, "Email worker thread started");

  while (!impl_->stop_requested) {
    QueuedEmail qe;
    bool has_item = false;

    {
      std::unique_lock<std::mutex> lock(impl_->mutex);
      impl_->cv.wait_for(lock, std::chrono::seconds(2), [this] {
        return impl_->stop_requested.load() || !impl_->queue.empty();
      });

      if (impl_->stop_requested) break;
      if (impl_->queue.empty()) continue;

      // Find the next item ready for (re)try
      uint64_t now = now_ms_stamp();
      for (auto it = impl_->queue.begin(); it != impl_->queue.end(); ++it) {
        if (it->next_retry_at <= now) {
          qe = *it;
          impl_->queue.erase(it);
          has_item = true;
          break;
        }
      }
    }

    if (!has_item) continue;

    // Attempt to send
    try {
      SmtpConnection conn(impl_->config.host, impl_->config.port,
                          impl_->config.use_tls, impl_->config.helo_name);

      conn.connect();

      if (!impl_->config.username.empty()) {
        conn.authenticate(impl_->config.username, impl_->config.password);
      }

      // DKIM signing
      std::string dkim_header;
      if (impl_->dkim_signer) {
        std::string headers = "from:" + qe.from.address() +
            ":to:" + qe.to[0].address() +
            ":subject:" + qe.subject;
        dkim_header = impl_->dkim_signer->sign(headers, qe.html_body);
      }

      conn.send_mail(qe.from, qe.to, qe.cc, qe.bcc,
                     qe.subject, qe.text_body, qe.html_body, dkim_header);

      progressive::log::info(kEmailIdentityTag,
          "Email queued item " + qe.id + " sent successfully");

    } catch (const SmtpError& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Failed to send email " + qe.id + ": " + e.message());

      if (e.is_retryable() && qe.retry_count < kMaxRetries) {
        qe.retry_count++;
        int delay = kRetryBaseDelaySec * (1 << (qe.retry_count - 1));
        qe.next_retry_at = now_ms_stamp() + delay * 1000;

        progressive::log::info(kEmailIdentityTag,
            "Retrying email " + qe.id + " in " +
            std::to_string(delay) + "s (attempt " +
            std::to_string(qe.retry_count + 1) + "/" +
            std::to_string(kMaxRetries + 1) + ")");

        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->queue.push_back(qe);
      } else {
        progressive::log::error(kEmailIdentityTag,
            "Email " + qe.id + " permanently failed: " + e.message());
        record_bounce(qe.id, e.message());
      }
    } catch (const std::exception& e) {
      progressive::log::error(kEmailIdentityTag,
          "Unexpected error sending email " + qe.id + ": " + e.what());
      record_bounce(qe.id, e.what());
    }
  }

  progressive::log::info(kEmailIdentityTag, "Email worker thread stopped");
}

// ============================================================================
// BounceHandler
// ============================================================================

struct BounceHandler::Impl {
  std::unordered_map<std::string, int> bounce_counts;  // email -> count
  std::set<std::string> suppressed;                     // suppressed emails
  mutable std::mutex mutex;
  int threshold = kBounceThreshold;
};

BounceHandler::BounceHandler(int threshold) : impl_(std::make_unique<Impl>()) {
  impl_->threshold = threshold;
}

BounceHandler::~BounceHandler() = default;

void BounceHandler::record_bounce(std::string_view email,
                                   std::string_view reason) {
  std::string email_str(email);
  std::lock_guard<std::mutex> lock(impl_->mutex);

  impl_->bounce_counts[email_str]++;

  progressive::log::warn(kEmailIdentityTag,
      "Bounce recorded for " + email_str + ": " +
      std::string(reason) + " (count=" +
      std::to_string(impl_->bounce_counts[email_str]) + ")");

  if (impl_->bounce_counts[email_str] >= impl_->threshold) {
    impl_->suppressed.insert(email_str);
    progressive::log::warn(kEmailIdentityTag,
        "Suppressing email " + email_str + " due to " +
        std::to_string(impl_->bounce_counts[email_str]) + " bounces");
  }
}

void BounceHandler::record_complaint(std::string_view email) {
  std::string email_str(email);
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->suppressed.insert(email_str);
  progressive::log::warn(kEmailIdentityTag,
      "Suppressing email " + email_str + " due to abuse complaint");
}

bool BounceHandler::is_suppressed(std::string_view email) const {
  std::string email_str(email);
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->suppressed.find(email_str) != impl_->suppressed.end();
}

int BounceHandler::bounce_count(std::string_view email) const {
  std::string email_str(email);
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto it = impl_->bounce_counts.find(email_str);
  return (it != impl_->bounce_counts.end()) ? it->second : 0;
}

void BounceHandler::clear_bounces(std::string_view email) {
  std::string email_str(email);
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->bounce_counts.erase(email_str);
  impl_->suppressed.erase(email_str);
}

void BounceHandler::clear_all() {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  impl_->bounce_counts.clear();
  impl_->suppressed.clear();
}

// ============================================================================
// IdentityServerClient
// ============================================================================

struct IdentityServerClient::Impl {
  std::string base_url;
  std::string access_token;
  int timeout_secs = kHttpTimeoutSec;
};

IdentityServerClient::IdentityServerClient(std::string base_url)
    : impl_(std::make_unique<Impl>()) {
  // Ensure base_url doesn't have trailing slash
  if (!base_url.empty() && base_url.back() == '/') {
    base_url.pop_back();
  }
  impl_->base_url = std::move(base_url);
}

IdentityServerClient::~IdentityServerClient() = default;

void IdentityServerClient::set_access_token(std::string_view token) {
  impl_->access_token = std::string(token);
}

void IdentityServerClient::set_timeout(int seconds) {
  impl_->timeout_secs = seconds;
}

const std::string& IdentityServerClient::base_url() const {
  return impl_->base_url;
}

nlohmann::json IdentityServerClient::lookup_3pid(std::string_view medium,
                                                   std::string_view address) {
  // GET /_matrix/identity/v2/lookup?medium=EMAIL&address=user@example.com
  std::string path = "/_matrix/identity/v2/lookup?medium=" +
      url_encode(medium) + "&address=" + url_encode(address);
  return get_request(path);
}

nlohmann::json IdentityServerClient::lookup_hash(const std::string& pepper,
                                                   std::string_view algorithm,
                                                   const std::string& hash_value) {
  // POST /_matrix/identity/v2/lookup
  nlohmann::json body;
  body["algorithm"] = algorithm;
  body["pepper"] = pepper;
  body["addresses"] = nlohmann::json::array({hash_value});

  return post_request("/_matrix/identity/v2/lookup", body);
}

nlohmann::json IdentityServerClient::bulk_lookup(
    const std::string& pepper, std::string_view algorithm,
    const std::vector<std::string>& hash_values) {
  nlohmann::json body;
  body["algorithm"] = algorithm;
  body["pepper"] = pepper;
  body["addresses"] = hash_values;

  return post_request("/_matrix/identity/v2/lookup", body);
}

nlohmann::json IdentityServerClient::request_token(std::string_view medium,
                                                     std::string_view address,
                                                     std::string_view client_secret,
                                                     int send_attempt) {
  // POST /_matrix/identity/v2/validate/email/requestToken
  // or POST /_matrix/identity/v2/validate/msisdn/requestToken
  std::string path = "/_matrix/identity/v2/validate/" +
      std::string(medium) + "/requestToken";

  nlohmann::json body;
  body["client_secret"] = client_secret;
  body["address"] = address;
  body["send_attempt"] = send_attempt;

  return post_request(path, body);
}

nlohmann::json IdentityServerClient::submit_token(
    std::string_view medium, std::string_view token,
    std::string_view client_secret, std::string_view sid) {
  // POST /_matrix/identity/v2/validate/email/submitToken
  std::string path = "/_matrix/identity/v2/validate/" +
      std::string(medium) + "/submitToken";

  nlohmann::json body;
  body["token"] = token;
  body["client_secret"] = client_secret;
  body["sid"] = sid;

  return post_request(path, body);
}

nlohmann::json IdentityServerClient::bind_3pid(std::string_view medium,
                                                 std::string_view address,
                                                 std::string_view mxid) {
  // POST /_matrix/identity/v2/3pid/bind
  nlohmann::json body;
  body["medium"] = medium;
  body["address"] = address;
  body["mxid"] = mxid;

  return post_request("/_matrix/identity/v2/3pid/bind", body);
}

nlohmann::json IdentityServerClient::unbind_3pid(std::string_view medium,
                                                   std::string_view address) {
  // POST /_matrix/identity/v2/3pid/unbind
  nlohmann::json body;
  body["medium"] = medium;
  body["address"] = address;

  return post_request("/_matrix/identity/v2/3pid/unbind", body);
}

nlohmann::json IdentityServerClient::get_terms_of_service() {
  return get_request("/_matrix/identity/v2/terms");
}

nlohmann::json IdentityServerClient::accept_terms_of_service(
    const std::string& user_accepts) {
  nlohmann::json body;
  body["user_accepts"] = user_accepts;
  return post_request("/_matrix/identity/v2/terms", body);
}

nlohmann::json IdentityServerClient::validate_ephemeral_key(
    std::string_view public_key) {
  nlohmann::json body;
  body["public_key"] = public_key;
  return post_request("/_matrix/identity/v2/pubkey/validate", body);
}

nlohmann::json IdentityServerClient::get_server_info() {
  return get_request("/_matrix/identity/v2/info");
}

nlohmann::json IdentityServerClient::store_invite(
    std::string_view medium, std::string_view address,
    std::string_view room_id, std::string_view sender,
    std::string_view room_name) {
  nlohmann::json body;
  body["medium"] = medium;
  body["address"] = address;
  body["room_id"] = room_id;
  body["sender"] = sender;
  body["room_name"] = room_name;
  return post_request("/_matrix/identity/v2/store-invite", body);
}

nlohmann::json IdentityServerClient::get_request(const std::string& path) {
  std::string response = http_get(path);
  try {
    return nlohmann::json::parse(response);
  } catch (const nlohmann::json::parse_error& e) {
    progressive::log::error(kEmailIdentityTag,
        "Failed to parse identity server response: " + std::string(e.what()));
    return {{"errcode", "M_UNKNOWN"}, {"error", "Invalid JSON response"}};
  }
}

nlohmann::json IdentityServerClient::post_request(const std::string& path,
                                                    const nlohmann::json& body) {
  std::string body_str = body.dump();
  std::string response = http_post(path, body_str);
  try {
    return nlohmann::json::parse(response);
  } catch (const nlohmann::json::parse_error& e) {
    progressive::log::error(kEmailIdentityTag,
        "Failed to parse identity server response: " + std::string(e.what()));
    return {{"errcode", "M_UNKNOWN"}, {"error", "Invalid JSON response"}};
  }
}

std::string IdentityServerClient::http_get(const std::string& path) {
  // Parse URL to get host and port
  std::string url = impl_->base_url;
  std::string scheme = "https";
  std::string host;
  int port = 443;

  if (url.find("https://") == 0) {
    url = url.substr(8);
    scheme = "https";
    port = 443;
  } else if (url.find("http://") == 0) {
    url = url.substr(7);
    scheme = "http";
    port = 80;
  }

  size_t colon = url.find(':');
  size_t slash = url.find('/');
  if (colon != std::string::npos && (slash == std::string::npos || colon < slash)) {
    host = url.substr(0, colon);
    port = std::stoi(url.substr(colon + 1, slash - colon - 1));
  } else if (slash != std::string::npos) {
    host = url.substr(0, slash);
  } else {
    host = url;
  }

  // Build HTTP request
  std::ostringstream req;
  req << "GET " << path << " HTTP/1.1\r\n";
  req << "Host: " << host << "\r\n";
  req << "User-Agent: Progressive-Matrix/1.0\r\n";
  req << "Accept: application/json\r\n";
  if (!impl_->access_token.empty()) {
    req << "Authorization: Bearer " << impl_->access_token << "\r\n";
  }
  req << "Connection: close\r\n";
  req << "\r\n";

  return http_send_recv(host, port, req.str());
}

std::string IdentityServerClient::http_post(const std::string& path,
                                              const std::string& body) {
  std::string url = impl_->base_url;
  std::string scheme = "https";
  std::string host;
  int port = 443;

  if (url.find("https://") == 0) {
    url = url.substr(8);
    scheme = "https";
    port = 443;
  } else if (url.find("http://") == 0) {
    url = url.substr(7);
    scheme = "http";
    port = 80;
  }

  size_t colon = url.find(':');
  size_t slash = url.find('/');
  if (colon != std::string::npos && (slash == std::string::npos || colon < slash)) {
    host = url.substr(0, colon);
    port = std::stoi(url.substr(colon + 1, slash - colon - 1));
  } else if (slash != std::string::npos) {
    host = url.substr(0, slash);
  } else {
    host = url;
  }

  std::ostringstream req;
  req << "POST " << path << " HTTP/1.1\r\n";
  req << "Host: " << host << "\r\n";
  req << "User-Agent: Progressive-Matrix/1.0\r\n";
  req << "Accept: application/json\r\n";
  req << "Content-Type: application/json\r\n";
  req << "Content-Length: " << body.size() << "\r\n";
  if (!impl_->access_token.empty()) {
    req << "Authorization: Bearer " << impl_->access_token << "\r\n";
  }
  req << "Connection: close\r\n";
  req << "\r\n";
  req << body;

  return http_send_recv(host, port, req.str());
}

std::string IdentityServerClient::http_send_recv(const std::string& host,
                                                   int port,
                                                   const std::string& request) {
  struct addrinfo hints {};
  struct addrinfo* res = nullptr;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  std::string port_str = std::to_string(port);
  int gaierr = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
  if (gaierr != 0 || res == nullptr) {
    throw std::runtime_error(
        "DNS resolution failed for " + host + ": " + gai_strerror(gaierr));
  }

  int fd = -1;
  struct addrinfo* rp = nullptr;
  for (rp = res; rp != nullptr; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_sockstream, rp->ai_protocol);
    if (fd < 0) continue;
    if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);

  if (fd < 0) {
    throw std::runtime_error("Could not connect to " + host + ":" + port_str);
  }

  // Set timeout
  struct timeval tv;
  tv.tv_sec = impl_->timeout_secs;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  // Send request
  ssize_t sent = send(fd, request.data(), request.size(), 0);
  if (sent < 0) {
    close(fd);
    throw std::runtime_error("Failed to send HTTP request");
  }

  // Read response
  std::string response;
  char buf[8192];
  while (true) {
    ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) break;
    buf[n] = '\0';
    response += buf;
  }
  close(fd);

  // Extract body from HTTP response (skip headers)
  size_t body_start = response.find("\r\n\r\n");
  if (body_start == std::string::npos) {
    throw std::runtime_error("Invalid HTTP response - no header/body separator");
  }

  std::string body = response.substr(body_start + 4);

  // Handle chunked encoding (simplified)
  size_t chunked_check = response.find("Transfer-Encoding: chunked");
  if (chunked_check != std::string::npos &&
      chunked_check < body_start) {
    std::string dechunked;
    std::istringstream body_stream(body);
    std::string chunk_line;
    while (std::getline(body_stream, chunk_line)) {
      if (!chunk_line.empty() && chunk_line.back() == '\r')
        chunk_line.pop_back();
      if (chunk_line.empty()) continue;
      size_t chunk_size = std::stoul(chunk_line, nullptr, 16);
      if (chunk_size == 0) break;
      std::string chunk_data(chunk_size, '\0');
      body_stream.read(&chunk_data[0], static_cast<std::streamsize>(chunk_size));
      dechunked += chunk_data;
      // consume trailing CRLF
      std::string crlf;
      std::getline(body_stream, crlf);
    }
    body = dechunked;
  }

  return body;
}

// ============================================================================
// ReCaptchaVerifier
// ============================================================================

struct ReCaptchaVerifier::Impl {
  std::string site_key;
  std::string secret_key;
  std::string verify_url = "https://www.google.com/recaptcha/api/siteverify";
};

ReCaptchaVerifier::ReCaptchaVerifier(std::string site_key,
                                      std::string secret_key)
    : impl_(std::make_unique<Impl>()) {
  impl_->site_key = std::move(site_key);
  impl_->secret_key = std::move(secret_key);
}

ReCaptchaVerifier::~ReCaptchaVerifier() = default;

const std::string& ReCaptchaVerifier::site_key() const {
  return impl_->site_key;
}

bool ReCaptchaVerifier::verify(std::string_view response_token,
                                std::string_view remote_ip) {
  if (impl_->secret_key.empty()) {
    // No secret key configured; skip verification
    return true;
  }

  // Parse verify URL
  std::string url = impl_->verify_url;
  std::string host;
  std::string path;
  int port = 443;

  if (url.find("https://") == 0) {
    url = url.substr(8);
    port = 443;
  } else if (url.find("http://") == 0) {
    url = url.substr(7);
    port = 80;
  }

  size_t slash = url.find('/');
  if (slash != std::string::npos) {
    host = url.substr(0, slash);
    path = url.substr(slash);
  } else {
    host = url;
    path = "/";
  }

  // Build POST body
  std::string post_body = "secret=" + url_encode(impl_->secret_key) +
      "&response=" + url_encode(response_token);
  if (!remote_ip.empty()) {
    post_body += "&remoteip=" + url_encode(remote_ip);
  }

  std::ostringstream req;
  req << "POST " << path << " HTTP/1.1\r\n";
  req << "Host: " << host << "\r\n";
  req << "User-Agent: Progressive-Matrix/1.0\r\n";
  req << "Content-Type: application/x-www-form-urlencoded\r\n";
  req << "Content-Length: " << post_body.size() << "\r\n";
  req << "Connection: close\r\n";
  req << "\r\n";
  req << post_body;

  // Use IdentityServerClient's HTTP helper by creating a temporary client
  try {
    // Direct socket approach
    struct addrinfo hints {};
    struct addrinfo* res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    int gaierr = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (gaierr != 0 || res == nullptr) {
      progressive::log::warn(kEmailIdentityTag, "reCAPTCHA DNS failure");
      return false;
    }

    int fd = -1;
    for (struct addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
      fd = socket(rp->ai_family, rp->ai_sockstream, rp->ai_protocol);
      if (fd < 0) continue;
      if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
      close(fd);
      fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
      progressive::log::warn(kEmailIdentityTag, "reCAPTCHA connect failure");
      return false;
    }

    struct timeval tv;
    tv.tv_sec = kRecaptchaTimeoutSec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    std::string req_str = req.str();
    if (send(fd, req_str.data(), req_str.size(), 0) < 0) {
      close(fd);
      return false;
    }

    std::string response;
    char buf[4096];
    while (true) {
      ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
      if (n <= 0) break;
      buf[n] = '\0';
      response += buf;
    }
    close(fd);

    size_t body_start = response.find("\r\n\r\n");
    if (body_start == std::string::npos) return false;

    auto json_resp = nlohmann::json::parse(response.substr(body_start + 4));
    return json_resp.value("success", false);

  } catch (const std::exception& e) {
    progressive::log::error(kEmailIdentityTag,
        "reCAPTCHA verification error: " + std::string(e.what()));
    return false;
  }
}

// ============================================================================
// EmailIdentity - main class
// ============================================================================

struct EmailIdentity::Impl {
  storage::DatabasePool& db;
  std::unique_ptr<IdentityServerClient> identity_client;
  std::unique_ptr<EmailQueue> email_queue;
  std::unique_ptr<BounceHandler> bounce_handler;
  std::unique_ptr<DkimSigner> dkim_signer;
  std::unique_ptr<ReCaptchaVerifier> recaptcha;
  RateLimiter rate_limiter;
  std::string server_name;
  std::string default_language;
  std::string base_url;
  std::string smtp_from_address;
  std::string smtp_from_name;
  bool email_configured = false;

  // In-memory session storage: sid -> session info
  struct SessionInfo {
    std::string sid;
    std::string medium;           // "email" or "msisdn"
    std::string address;
    std::string client_secret;
    std::string token;
    std::string mxid;             // matrix user ID if bound
    std::string next_link;
    uint64_t created_at;
    uint64_t expires_at;
    int send_attempt = 0;
    bool validated = false;
    bool bound = false;
  };
  std::unordered_map<std::string, SessionInfo> sessions;
  std::mutex sessions_mutex;

  // MSISDN session store
  struct MsisdnSession {
    std::string sid;
    std::string msisdn;
    std::string client_secret;
    std::string code;             // verification code
    int send_attempt = 0;
    uint64_t created_at;
    uint64_t expires_at;
    bool validated = false;
  };
  std::unordered_map<std::string, MsisdnSession> msisdn_sessions;
  std::mutex msisdn_mutex;

  // Unsubscribe tokens
  struct UnsubscribeInfo {
    std::string token;
    std::string email;
    bool active = true;
    uint64_t created_at;
  };
  std::unordered_map<std::string, UnsubscribeInfo> unsubscribes;
  std::mutex unsub_mutex;

  explicit Impl(storage::DatabasePool& database) : db(database),
      rate_limiter(kRateLimitWindowSec, kMaxEmailsPerWindow,
                   kMaxEmailsPerAddressPerWindow) {}
};

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

EmailIdentity::EmailIdentity(storage::DatabasePool& db)
    : impl_(std::make_unique<Impl>(db)) {
  impl_->default_language = "en";
  impl_->server_name = "matrix.local";
}

EmailIdentity::~EmailIdentity() = default;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

void EmailIdentity::configure_smtp(const SmtpConfig& config,
                                    std::unique_ptr<DkimSigner> dkim) {
  impl_->smtp_from_address = config.from_address;
  impl_->smtp_from_name = config.from_name;
  impl_->email_queue = std::make_unique<EmailQueue>(config, std::move(dkim));
  impl_->email_configured = true;
}

void EmailIdentity::configure_identity_server(
    std::unique_ptr<IdentityServerClient> client) {
  impl_->identity_client = std::move(client);
}

void EmailIdentity::configure_recaptcha(
    std::unique_ptr<ReCaptchaVerifier> recaptcha) {
  impl_->recaptcha = std::move(recaptcha);
}

void EmailIdentity::configure_bounce_handler(std::unique_ptr<BounceHandler> bh) {
  impl_->bounce_handler = std::move(bh);
}

void EmailIdentity::set_server_name(const std::string& name) {
  impl_->server_name = name;
}

void EmailIdentity::set_base_url(const std::string& url) {
  impl_->base_url = url;
}

void EmailIdentity::set_default_language(const std::string& lang) {
  impl_->default_language = lang;
}

void EmailIdentity::start() {
  if (impl_->email_queue) {
    impl_->email_queue->start();
  }
  progressive::log::info(kEmailIdentityTag, "EmailIdentity started");
}

void EmailIdentity::stop() {
  if (impl_->email_queue) {
    impl_->email_queue->stop();
  }
  progressive::log::info(kEmailIdentityTag, "EmailIdentity stopped");
}

// ---------------------------------------------------------------------------
// Email template factory methods
// ---------------------------------------------------------------------------

EmailTemplate EmailIdentity::make_password_reset_template(
    std::string_view user_id, std::string_view display_name,
    std::string_view reset_link, int expiry_hours,
    const std::string& language) const {
  const auto& loc = get_locale(language.empty() ?
      impl_->default_language : language);

  std::string html_body = build_html_email(
      loc.password_reset_title,
      "<p>Hello " + html_escape(display_name) + ",</p>"
      "<p>A request to reset the password for your Matrix account "
      "<strong>" + html_escape(user_id) + "</strong> has been received.</p>"
      "<p>If you made this request, please click the button below to "
      "set a new password:</p>"
      "<p style=\"text-align:center;margin:24px 0\">"
      "<a href=\"" + html_escape(reset_link) + "\" "
      "style=\"background:#0dbd8b;color:#fff;padding:12px 32px;"
      "text-decoration:none;border-radius:6px;font-size:16px\">"
      "Reset Password</a></p>"
      "<p>Or copy and paste this link into your browser:</p>"
      "<p><small>" + html_escape(reset_link) + "</small></p>"
      "<p>This link will expire in " + std::to_string(expiry_hours) +
      " hour(s).</p>"
      "<p>If you did NOT request a password reset, you can safely "
      "ignore this email.</p>");

  EmailTemplate tpl(loc.password_reset_subject,
                    loc.password_reset_body, html_body);
  tpl.set_variable("display_name", std::string(display_name));
  tpl.set_variable("user_id", std::string(user_id));
  tpl.set_variable("reset_link", std::string(reset_link));
  tpl.set_variable("expiry_hours", std::to_string(expiry_hours));
  tpl.set_variable("server_name", impl_->server_name);
  return tpl;
}

EmailTemplate EmailIdentity::make_verify_template(
    std::string_view email, std::string_view display_name,
    std::string_view verify_link, int expiry_hours,
    const std::string& language) const {
  const auto& loc = get_locale(language.empty() ?
      impl_->default_language : language);

  std::string html_body = build_html_email(
      loc.email_verify_title,
      "<p>Hello " + html_escape(display_name) + ",</p>"
      "<p>Please verify your email address "
      "<strong>" + html_escape(email) + "</strong> by clicking "
      "the button below:</p>"
      "<p style=\"text-align:center;margin:24px 0\">"
      "<a href=\"" + html_escape(verify_link) + "\" "
      "style=\"background:#0dbd8b;color:#fff;padding:12px 32px;"
      "text-decoration:none;border-radius:6px;font-size:16px\">"
      "Verify Email</a></p>"
      "<p>Or copy and paste this link:</p>"
      "<p><small>" + html_escape(verify_link) + "</small></p>"
      "<p>This link will expire in " + std::to_string(expiry_hours) +
      " hour(s).</p>"
      "<p>If you did not register this email, you can safely "
      "ignore this message.</p>");

  EmailTemplate tpl(loc.email_verify_subject,
                    loc.email_verify_body, html_body);
  tpl.set_variable("display_name", std::string(display_name));
  tpl.set_variable("verify_link", std::string(verify_link));
  tpl.set_variable("expiry_hours", std::to_string(expiry_hours));
  tpl.set_variable("server_name", impl_->server_name);
  return tpl;
}

EmailTemplate EmailIdentity::make_invitation_template(
    std::string_view email, std::string_view inviter_name,
    std::string_view inviter_id, std::string_view room_name,
    std::string_view invite_link, const std::string& language) const {
  const auto& loc = get_locale(language.empty() ?
      impl_->default_language : language);

  std::string html_body = build_html_email(
      loc.invite_title,
      "<h2>You're invited to Matrix!</h2>"
      "<p><strong>" + html_escape(inviter_name) + "</strong> "
      "(" + html_escape(inviter_id) + ") has invited you to join "
      "the room <strong>" + html_escape(room_name) + "</strong> on "
      + html_escape(impl_->server_name) + ".</p>"
      "<p style=\"text-align:center;margin:24px 0\">"
      "<a href=\"" + html_escape(invite_link) + "\" "
      "style=\"background:#0dbd8b;color:#fff;padding:12px 32px;"
      "text-decoration:none;border-radius:6px;font-size:16px\">"
      "Join Now</a></p>"
      "<p>Or copy and paste: " + html_escape(invite_link) + "</p>");

  EmailTemplate tpl(loc.invite_subject, loc.invite_body, html_body);
  tpl.set_variable("inviter_name", std::string(inviter_name));
  tpl.set_variable("inviter_id", std::string(inviter_id));
  tpl.set_variable("room_name", std::string(room_name));
  tpl.set_variable("invite_link", std::string(invite_link));
  tpl.set_variable("server_name", impl_->server_name);
  return tpl;
}

EmailTemplate EmailIdentity::make_digest_template(
    std::string_view user_id, std::string_view display_name,
    int unread_count, int room_count,
    std::string_view room_summary, std::string_view unsubscribe_link,
    const std::string& language) const {
  const auto& loc = get_locale(language.empty() ?
      impl_->default_language : language);

  std::string html_body = build_html_email(
      loc.digest_title,
      "<p>Hello " + html_escape(display_name) + ",</p>"
      "<p>You have <strong>" + std::to_string(unread_count) +
      "</strong> unread messages across <strong>" +
      std::to_string(room_count) + "</strong> room(s).</p>"
      "<div style=\"background:#f5f5f5;padding:12px;border-radius:4px;"
      "margin:12px 0\">" + html_escape(room_summary) + "</div>"
      "<p style=\"margin-top:24px;font-size:12px;color:#999\">"
      "<a href=\"" + html_escape(unsubscribe_link) + "\">" +
      loc.unsubscribe_link_text + "</a></p>");

  EmailTemplate tpl(loc.digest_subject, loc.digest_body, html_body);
  tpl.set_variable("display_name", std::string(display_name));
  tpl.set_variable("user_id", std::string(user_id));
  tpl.set_variable("unread_count", std::to_string(unread_count));
  tpl.set_variable("room_count", std::to_string(room_count));
  tpl.set_variable("room_summary", std::string(room_summary));
  tpl.set_variable("unsubscribe_link", std::string(unsubscribe_link));
  tpl.set_variable("server_name", impl_->server_name);
  return tpl;
}

// ---------------------------------------------------------------------------
// Email template sending methods
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::send_password_reset_email(
    std::string_view email, std::string_view user_id,
    std::string_view display_name, std::string_view reset_token,
    int expiry_hours, const std::string& language) {

  if (!is_valid_email(email)) {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid email address"}};
  }

  if (impl_->bounce_handler && impl_->bounce_handler->is_suppressed(email)) {
    return {{"errcode", "M_UNKNOWN"}, {"error", "Email is suppressed"}};
  }

  std::string link = impl_->base_url + "/_matrix/client/v3/account/password/"
      "email/submitToken?token=" + std::string(reset_token) +
      "&client_secret=" + url_encode(reset_token) +
      "&sid=" + url_encode(reset_token);

  auto tpl = make_password_reset_template(user_id, display_name, link,
                                           expiry_hours, language);

  return send_template(email, display_name, tpl);
}

nlohmann::json EmailIdentity::send_verification_email(
    std::string_view email, std::string_view display_name,
    std::string_view token, std::string_view client_secret,
    std::string_view sid, int expiry_hours,
    const std::string& language) {

  if (!is_valid_email(email)) {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid email address"}};
  }

  std::string link = impl_->base_url + "/_matrix/client/v3/register/"
      "email/submitToken?token=" + std::string(token) +
      "&client_secret=" + url_encode(client_secret) +
      "&sid=" + url_encode(sid);

  auto tpl = make_verify_template(email, display_name, link,
                                   expiry_hours, language);

  return send_template(email, display_name, tpl);
}

nlohmann::json EmailIdentity::send_invitation_email(
    std::string_view email, std::string_view inviter_name,
    std::string_view inviter_id, std::string_view room_name,
    std::string_view invite_link, const std::string& language) {

  if (!is_valid_email(email)) {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid email address"}};
  }

  auto tpl = make_invitation_template(email, inviter_name, inviter_id,
                                       room_name, invite_link, language);

  return send_template(email, "", tpl);
}

nlohmann::json EmailIdentity::send_digest_email(
    std::string_view email, std::string_view user_id,
    std::string_view display_name, int unread_count, int room_count,
    std::string_view room_summary, const std::string& language) {

  if (!is_valid_email(email)) {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid email address"}};
  }

  std::string unsub_token = generate_unsubscribe_token(email);
  std::string unsub_link = impl_->base_url +
      "/_matrix/client/v3/notifications/unsubscribe?token=" + unsub_token;

  auto tpl = make_digest_template(user_id, display_name, unread_count,
                                   room_count, room_summary, unsub_link,
                                   language);

  return send_template(email, display_name, tpl);
}

// ---------------------------------------------------------------------------
// Password reset flow
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::request_password_reset(
    std::string_view email, std::string_view client_secret,
    int send_attempt) {

  if (!is_valid_email(email)) {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid email address"}};
  }

  // Rate limit check
  if (!impl_->rate_limiter.allow(email)) {
    return {{"errcode", "M_LIMIT_EXCEEDED"},
            {"error", "Too many requests. Please try again later."}};
  }

  // Check for existing sessions for this email to prevent abuse
  {
    std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
    uint64_t now = now_ms_stamp();
    int active_count = 0;
    for (const auto& [sid, info] : impl_->sessions) {
      if (info.address == std::string(email) && info.expires_at > now) {
        active_count++;
      }
    }
    if (active_count >= 3) {
      return {{"errcode", "M_LIMIT_EXCEEDED"},
              {"error", "Too many active sessions for this email"}};
    }
  }

  // Create session via identity server if configured
  std::string sid;
  if (impl_->identity_client) {
    try {
      auto resp = impl_->identity_client->request_token(
          "email", email, client_secret, send_attempt);
      if (resp.contains("sid")) {
        sid = resp["sid"].get<std::string>();
      }
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Identity server requestToken failed: " + std::string(e.what()));
      // Fall through - generate local session
    }
  }

  // Generate local session if no identity server or it failed
  if (sid.empty()) {
    sid = util::random_token(24);
  }

  // Generate reset token
  std::string reset_token = util::random_token(32);

  // Store session
  {
    std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
    uint64_t now = now_ms_stamp();
    Impl::SessionInfo info;
    info.sid = sid;
    info.medium = "email";
    info.address = std::string(email);
    info.client_secret = std::string(client_secret);
    info.token = reset_token;
    info.created_at = now;
    info.expires_at = now + kEmailTokenExpirySec * 1000;
    info.send_attempt = send_attempt;
    impl_->sessions[sid] = info;
  }

  // Store the reset token in the database
  try {
    impl_->db.simple_insert("password_reset_tokens", {
      {"token", reset_token},
      {"email", std::string(email)},
      {"client_secret", std::string(client_secret)},
      {"created_at", std::to_string(now_ms_stamp())},
      {"expires_at", std::to_string(now_ms_stamp() +
          kEmailTokenExpirySec * 1000)}
    });
  } catch (const std::exception& e) {
    progressive::log::warn(kEmailIdentityTag,
        "Failed to store password reset token: " + std::string(e.what()));
  }

  // Send the email
  send_password_reset_email(email, /*user_id=*/email,
      /*display_name=*/"", reset_token, kEmailTokenExpirySec / 3600,
      impl_->default_language);

  return {
    {"sid", sid},
    {"submit_url", impl_->base_url + "/_matrix/client/v3/account/password/"
     "email/submitToken"}
  };
}

nlohmann::json EmailIdentity::validate_password_reset_token(
    std::string_view token, std::string_view client_secret,
    std::string_view sid) {

  // Check local sessions first
  {
    std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
    auto it = impl_->sessions.find(std::string(sid));
    if (it != impl_->sessions.end()) {
      uint64_t now = now_ms_stamp();
      if (it->second.expires_at < now) {
        return {{"errcode", "M_UNKNOWN"},
                {"error", "Session expired"}};
      }
      if (it->second.token == token &&
          (client_secret.empty() ||
           it->second.client_secret == client_secret)) {
        it->second.validated = true;
        return {{"success", true}};
      }
    }
  }

  // Check database
  try {
    auto rows = impl_->db.simple_select_one("password_reset_tokens",
        {{"token", std::string(token)}}, {"email", "expires_at"});
    if (rows.has_value()) {
      uint64_t expires = std::stoull((*rows)["expires_at"]);
      if (now_ms_stamp() > expires) {
        return {{"errcode", "M_UNKNOWN"},
                {"error", "Token expired"}};
      }
      return {{"success", true}};
    }
  } catch (const std::exception& e) {
    // Not found in DB either
  }

  // Try identity server
  if (impl_->identity_client) {
    try {
      auto resp = impl_->identity_client->submit_token(
          "email", token, client_secret, sid);
      if (resp.value("success", false)) {
        return {{"success", true}};
      }
    } catch (const std::exception& e) {
      // Ignore
    }
  }

  return {{"errcode", "M_UNKNOWN"},
          {"error", "Invalid token or session"}};
}

// ---------------------------------------------------------------------------
// Email verification (3PID validate)
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::request_email_token(
    std::string_view email, std::string_view client_secret,
    int send_attempt, std::string_view next_link) {

  if (!is_valid_email(email)) {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid email address"}};
  }

  if (!impl_->rate_limiter.allow(email)) {
    return {{"errcode", "M_LIMIT_EXCEEDED"},
            {"error", "Too many requests. Please try again later."}};
  }

  // Create session
  std::string sid = util::random_token(24);
  std::string token = util::random_token(32);

  {
    std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
    uint64_t now = now_ms_stamp();
    Impl::SessionInfo info;
    info.sid = sid;
    info.medium = "email";
    info.address = std::string(email);
    info.client_secret = std::string(client_secret);
    info.token = token;
    info.created_at = now;
    info.expires_at = now + kEmailTokenExpirySec * 1000;
    info.send_attempt = send_attempt;
    info.next_link = std::string(next_link);
    impl_->sessions[sid] = info;
  }

  // Also try identity server
  if (impl_->identity_client) {
    try {
      auto resp = impl_->identity_client->request_token(
          "email", email, client_secret, send_attempt);
      // Use the identity server's sid if available
      if (resp.contains("sid")) {
        sid = resp["sid"].get<std::string>();
        // Update session with identity server sid
        std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
        auto it = impl_->sessions.find(sid);
        // Note: we stored under our local sid; could copy to new key
      }
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Identity server requestToken error: " + std::string(e.what()));
    }
  }

  // Send verification email
  send_verification_email(email, /*display_name=*/"", token, client_secret,
                           sid, kEmailTokenExpirySec / 3600,
                           impl_->default_language);

  // Store in database for persistence
  try {
    impl_->db.simple_insert("email_validations", {
      {"sid", sid},
      {"email", std::string(email)},
      {"client_secret", std::string(client_secret)},
      {"token", token},
      {"created_at", std::to_string(now_ms_stamp())},
      {"expires_at", std::to_string(now_ms_stamp() +
          kEmailTokenExpirySec * 1000)}
    });
  } catch (const std::exception& e) {
    progressive::log::warn(kEmailIdentityTag,
        "Failed to persist email validation: " + std::string(e.what()));
  }

  return {{"sid", sid}};
}

nlohmann::json EmailIdentity::validate_email_token(
    std::string_view token, std::string_view client_secret,
    std::string_view sid) {

  // Check local sessions
  {
    std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
    auto it = impl_->sessions.find(std::string(sid));
    if (it != impl_->sessions.end()) {
      uint64_t now = now_ms_stamp();
      if (it->second.expires_at < now) {
        return {{"errcode", "M_UNKNOWN"},
                {"error", "Session expired"}};
      }
      if (it->second.token == token &&
          (client_secret.empty() ||
           it->second.client_secret == client_secret)) {
        it->second.validated = true;
        return json_validate_success(*it);
      }
    }
  }

  // Check DB persistence
  try {
    auto rows = impl_->db.simple_select_one("email_validations",
        {{"token", std::string(token)}, {"sid", std::string(sid)}},
        {"email", "expires_at", "client_secret"});
    if (rows.has_value()) {
      uint64_t expires = std::stoull((*rows)["expires_at"]);
      if (now_ms_stamp() > expires) {
        return {{"errcode", "M_UNKNOWN"},
                {"error", "Token expired"}};
      }
      return {{"success", true}, {"medium", "email"}};
    }
  } catch (const std::exception& e) {
    // Not found
  }

  // Try identity server
  if (impl_->identity_client) {
    try {
      auto resp = impl_->identity_client->submit_token(
          "email", token, client_secret, sid);
      if (resp.value("success", false)) {
        return json_validate_success(
            {sid: std::string(sid), medium: "email",
             address: "", client_secret: std::string(client_secret),
             token: std::string(token),
             mxid: "", next_link: "",
             created_at: 0, expires_at: 0,
             send_attempt: 0, validated: true, bound: false});
      }
    } catch (const std::exception& e) {
      // Ignore
    }
  }

  return {{"errcode", "M_UNKNOWN"},
          {"error", "Invalid token or session"}};
}

// ---------------------------------------------------------------------------
// MSISDN (SMS) verification
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::request_msisdn_token(
    std::string_view msisdn, std::string_view client_secret,
    int send_attempt) {

  if (!is_valid_msisdn(msisdn)) {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid phone number. Use E.164 format (+1234567890)"}};
  }

  if (!impl_->rate_limiter.allow(msisdn)) {
    return {{"errcode", "M_LIMIT_EXCEEDED"},
            {"error", "Too many requests. Please try again later."}};
  }

  // Try identity server first
  if (impl_->identity_client) {
    try {
      auto resp = impl_->identity_client->request_token(
          "msisdn", msisdn, client_secret, send_attempt);
      if (resp.contains("sid")) {
        std::string sid = resp["sid"].get<std::string>();

        std::lock_guard<std::mutex> lock(impl_->msisdn_mutex);
        Impl::MsisdnSession ms;
        ms.sid = sid;
        ms.msisdn = std::string(msisdn);
        ms.client_secret = std::string(client_secret);
        ms.send_attempt = send_attempt;
        ms.created_at = now_ms_stamp();
        ms.expires_at = now_ms_stamp() + kMsisdnTokenExpirySec * 1000;

        impl_->msisdn_sessions[sid] = ms;

        return {{"sid", sid}};
      }
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Identity server MSISDN requestToken failed: " +
          std::string(e.what()));
    }
  }

  // Generate local session
  std::string sid = util::random_token(24);
  std::string code = generate_msisdn_code();

  {
    std::lock_guard<std::mutex> lock(impl_->msisdn_mutex);
    Impl::MsisdnSession ms;
    ms.sid = sid;
    ms.msisdn = std::string(msisdn);
    ms.client_secret = std::string(client_secret);
    ms.code = code;
    ms.send_attempt = send_attempt;
    ms.created_at = now_ms_stamp();
    ms.expires_at = now_ms_stamp() + kMsisdnTokenExpirySec * 1000;

    impl_->msisdn_sessions[sid] = ms;
  }

  // In production this would send an SMS via a provider.
  // For now we log the code and return the sid.
  progressive::log::info(kEmailIdentityTag,
      "MSISDN verification code for " + std::string(msisdn) +
      ": " + code + " (sid=" + sid + ")");

  return {{"sid", sid}};
}

nlohmann::json EmailIdentity::validate_msisdn_token(
    std::string_view token, std::string_view client_secret,
    std::string_view sid) {

  // Check local sessions
  {
    std::lock_guard<std::mutex> lock(impl_->msisdn_mutex);
    auto it = impl_->msisdn_sessions.find(std::string(sid));
    if (it != impl_->msisdn_sessions.end()) {
      uint64_t now = now_ms_stamp();
      if (it->second.expires_at < now) {
        return {{"errcode", "M_UNKNOWN"},
                {"error", "MSISDN session expired"}};
      }
      if (it->second.code == token &&
          (client_secret.empty() ||
           it->second.client_secret == client_secret)) {
        it->second.validated = true;
        return {
          {"success", true},
          {"medium", "msisdn"},
          {"address", it->second.msisdn}
        };
      }
    }
  }

  // Try identity server
  if (impl_->identity_client) {
    try {
      auto resp = impl_->identity_client->submit_token(
          "msisdn", token, client_secret, sid);
      if (resp.value("success", false)) {
        return {{"success", true}, {"medium", "msisdn"}};
      }
    } catch (const std::exception& e) {
      // Ignore
    }
  }

  return {{"errcode", "M_UNKNOWN"},
          {"error", "Invalid MSISDN token or session"}};
}

// ---------------------------------------------------------------------------
// Identity server: lookup, bind, unbind
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::lookup_3pid(std::string_view medium,
                                            std::string_view address) {
  if (medium != "email" && medium != "msisdn") {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid medium. Must be 'email' or 'msisdn'"}};
  }

  if (medium == "email" && !is_valid_email(address)) {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid email address"}};
  }
  if (medium == "msisdn" && !is_valid_msisdn(address)) {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid phone number"}};
  }

  if (impl_->identity_client) {
    try {
      return impl_->identity_client->lookup_3pid(medium, address);
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Identity server lookup failed: " + std::string(e.what()));
    }
  }

  // Local lookup via database (3pid associations)
  try {
    auto rows = impl_->db.simple_select_one("threepid_associations",
        {{"medium", std::string(medium)},
         {"address", std::string(address)}},
        {"mxid", "validated_at", "added_at"});
    if (rows.has_value()) {
      return {
        {"address", address},
        {"medium", medium},
        {"mxid", (*rows)["mxid"]},
        {"not_before", (*rows)["validated_at"]},
        {"not_after", "0"},
        {"ts", (*rows)["added_at"]},
        {"signatures", nlohmann::json::object()}
      };
    }
  } catch (const std::exception& e) {
    // Not found
  }

  return {{"errcode", "M_NOT_FOUND"},
          {"error", "No Matrix ID found for this 3PID"}};
}

nlohmann::json EmailIdentity::bulk_lookup_3pid(
    const std::string& pepper, std::string_view algorithm,
    const std::vector<std::string>& hash_values) {

  if (impl_->identity_client) {
    try {
      auto resp = impl_->identity_client->bulk_lookup(
          pepper, algorithm, hash_values);
      // Identity server returns mappings; we augment with local
      return resp;
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Bulk lookup via identity server failed: " +
          std::string(e.what()));
    }
  }

  // Local bulk lookup: hash each address with HMAC and match
  nlohmann::json result;
  result["mappings"] = nlohmann::json::array();

  try {
    // Query all known 3PID associations
    // In production this would use proper hashing; simplified here
    auto all_rows = impl_->db.execute("local_lookup",
        "SELECT medium, address, mxid FROM threepid_associations",
        {});

    for (const auto& row : all_rows) {
      std::string addr = row.value("address", "");
      // Hash the address with pepper
      std::string hashed = hmac_sha256(pepper, addr);
      std::string hashed_b64 = util::base64::encode(hashed);

      // Check if this hash is in the requested set
      for (const auto& hv : hash_values) {
        if (hv == hashed_b64) {
          nlohmann::json mapping;
          mapping["medium"] = row["medium"];
          mapping["address"] = addr;
          mapping["mxid"] = row["mxid"];
          result["mappings"].push_back(mapping);
          break;
        }
      }
    }
  } catch (const std::exception& e) {
    progressive::log::warn(kEmailIdentityTag,
        "Local bulk lookup failed: " + std::string(e.what()));
  }

  return result;
}

nlohmann::json EmailIdentity::bind_3pid(std::string_view medium,
                                          std::string_view address,
                                          std::string_view mxid) {
  if (medium != "email" && medium != "msisdn") {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid medium"}};
  }

  // Check that the 3PID is validated
  {
    std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
    bool validated = false;
    for (const auto& [sid, info] : impl_->sessions) {
      if (info.medium == medium && info.address == address &&
          info.validated) {
        validated = true;
        break;
      }
    }
    if (!validated) {
      return {{"errcode", "M_UNKNOWN"},
              {"error", "3PID must be validated before binding"}};
    }
  }

  // Store in local DB
  try {
    impl_->db.simple_upsert("threepid_associations",
        {{"medium", std::string(medium)},
         {"address", std::string(address)}},
        {{"mxid", std::string(mxid)},
         {"validated_at", std::to_string(now_ms_stamp())},
         {"added_at", std::to_string(now_ms_stamp())}});
  } catch (const std::exception& e) {
    progressive::log::error(kEmailIdentityTag,
        "Failed to persist 3PID bind: " + std::string(e.what()));
  }

  // Try identity server bind
  if (impl_->identity_client) {
    try {
      return impl_->identity_client->bind_3pid(medium, address, mxid);
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Identity server bind failed: " + std::string(e.what()));
    }
  }

  // Update session
  {
    std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
    for (auto& [sid, info] : impl_->sessions) {
      if (info.medium == medium && info.address == address) {
        info.bound = true;
        info.mxid = std::string(mxid);
      }
    }
  }

  return {{"success", true},
          {"medium", medium},
          {"address", address},
          {"mxid", mxid}};
}

nlohmann::json EmailIdentity::unbind_3pid(std::string_view medium,
                                            std::string_view address,
                                            std::string_view mxid) {
  if (medium != "email" && medium != "msisdn") {
    return {{"errcode", "M_INVALID_PARAM"},
            {"error", "Invalid medium"}};
  }

  // Remove from local DB
  try {
    std::map<std::string, std::string> keyvalues;
    keyvalues["medium"] = std::string(medium);
    keyvalues["address"] = std::string(address);
    if (!mxid.empty()) {
      keyvalues["mxid"] = std::string(mxid);
    }
    impl_->db.simple_delete_one("threepid_associations", keyvalues);
  } catch (const std::exception& e) {
    progressive::log::error(kEmailIdentityTag,
        "Failed to delete 3PID bind: " + std::string(e.what()));
  }

  // Try identity server unbind
  if (impl_->identity_client) {
    try {
      return impl_->identity_client->unbind_3pid(medium, address);
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Identity server unbind failed: " + std::string(e.what()));
    }
  }

  // Clean up sessions
  {
    std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
    auto it = impl_->sessions.begin();
    while (it != impl_->sessions.end()) {
      if (it->second.medium == medium && it->second.address == address) {
        it = impl_->sessions.erase(it);
      } else {
        ++it;
      }
    }
  }

  return {{"success", true}};
}

// ---------------------------------------------------------------------------
// 3PID management (CRUD operations)
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::add_3pid(std::string_view mxid,
                                         std::string_view medium,
                                         std::string_view address,
                                         std::string_view client_secret,
                                         int send_attempt) {
  if (medium == "email") {
    return request_email_token(address, client_secret, send_attempt);
  } else if (medium == "msisdn") {
    return request_msisdn_token(address, client_secret, send_attempt);
  }
  return {{"errcode", "M_INVALID_PARAM"},
          {"error", "Invalid medium"}};
}

nlohmann::json EmailIdentity::submit_3pid_token(
    std::string_view medium, std::string_view token,
    std::string_view client_secret, std::string_view sid) {
  if (medium == "email") {
    return validate_email_token(token, client_secret, sid);
  } else if (medium == "msisdn") {
    return validate_msisdn_token(token, client_secret, sid);
  }
  return {{"errcode", "M_INVALID_PARAM"},
          {"error", "Invalid medium"}};
}

nlohmann::json EmailIdentity::delete_3pid(std::string_view mxid,
                                            std::string_view medium,
                                            std::string_view address) {
  return unbind_3pid(medium, address, mxid);
}

nlohmann::json EmailIdentity::get_3pids(std::string_view mxid) {
  nlohmann::json result = nlohmann::json::array();

  try {
    auto rows = impl_->db.simple_select_list("threepid_associations",
        {{"mxid", std::string(mxid)}},
        {"medium", "address", "validated_at", "added_at"});

    for (const auto& row : rows) {
      nlohmann::json entry;
      entry["medium"] = row["medium"];
      entry["address"] = row["address"];
      entry["validated_at"] = std::stoull(row["validated_at"]);
      entry["added_at"] = std::stoull(row["added_at"]);
      result.push_back(entry);
    }
  } catch (const std::exception& e) {
    progressive::log::warn(kEmailIdentityTag,
        "Failed to list 3PIDs for " + std::string(mxid) + ": " +
        std::string(e.what()));
  }

  return {{"threepids", result}};
}

// ---------------------------------------------------------------------------
// Terms of Service
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::get_terms_of_service() {
  if (impl_->identity_client) {
    try {
      return impl_->identity_client->get_terms_of_service();
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Failed to get TOS from identity server: " +
          std::string(e.what()));
    }
  }

  // Return local TOS if configured
  return {
    {"policies", nlohmann::json::object()}
  };
}

nlohmann::json EmailIdentity::accept_terms_of_service(
    std::string_view mxid, const std::string& user_accepts) {
  try {
    // Store acceptance in DB
    impl_->db.simple_upsert("user_tos_acceptances",
        {{"mxid", std::string(mxid)}},
        {{"accepted_version", user_accepts},
         {"accepted_at", std::to_string(now_ms_stamp())}});
  } catch (const std::exception& e) {
    progressive::log::warn(kEmailIdentityTag,
        "Failed to record TOS acceptance: " + std::string(e.what()));
  }

  if (impl_->identity_client) {
    try {
      return impl_->identity_client->accept_terms_of_service(user_accepts);
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Failed to accept TOS on identity server: " +
          std::string(e.what()));
    }
  }

  return {{"success", true}};
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::get_session_info(std::string_view sid) {
  std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
  auto it = impl_->sessions.find(std::string(sid));
  if (it == impl_->sessions.end()) {
    return {{"errcode", "M_NOT_FOUND"},
            {"error", "Session not found"}};
  }

  const auto& info = it->second;
  return {
    {"sid", info.sid},
    {"medium", info.medium},
    {"address", info.address},
    {"validated", info.validated},
    {"bound", info.bound},
    {"created_at", info.created_at},
    {"expires_at", info.expires_at}
  };
}

void EmailIdentity::cleanup_expired_sessions() {
  uint64_t now = now_ms_stamp();

  // Clean email sessions
  {
    std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
    auto it = impl_->sessions.begin();
    while (it != impl_->sessions.end()) {
      if (it->second.expires_at < now) {
        it = impl_->sessions.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Clean MSISDN sessions
  {
    std::lock_guard<std::mutex> lock(impl_->msisdn_mutex);
    auto it = impl_->msisdn_sessions.begin();
    while (it != impl_->msisdn_sessions.end()) {
      if (it->second.expires_at < now) {
        it = impl_->sessions.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Clean up expired DB records
  try {
    impl_->db.execute("cleanup",
        "DELETE FROM email_validations WHERE expires_at < " +
        std::to_string(now), {});
    impl_->db.execute("cleanup",
        "DELETE FROM password_reset_tokens WHERE expires_at < " +
        std::to_string(now), {});
  } catch (const std::exception& e) {
    progressive::log::warn(kEmailIdentityTag,
        "Failed to clean up expired sessions: " + std::string(e.what()));
  }
}

size_t EmailIdentity::active_session_count() const {
  std::lock_guard<std::mutex> lock(impl_->sessions_mutex);
  return impl_->sessions.size();
}

// ---------------------------------------------------------------------------
// Unsubscribe management
// ---------------------------------------------------------------------------

std::string EmailIdentity::generate_unsubscribe_token(
    std::string_view email) {
  std::string token = util::random_token(32);

  Impl::UnsubscribeInfo info;
  info.token = token;
  info.email = std::string(email);
  info.active = false;
  info.created_at = now_ms_stamp();

  std::lock_guard<std::mutex> lock(impl_->unsub_mutex);
  impl_->unsubscribes[token] = info;

  return token;
}

bool EmailIdentity::process_unsubscribe(std::string_view token) {
  std::lock_guard<std::mutex> lock(impl_->unsub_mutex);
  auto it = impl_->unsubscribes.find(std::string(token));
  if (it == impl_->unsubscribes.end()) {
    return false;
  }

  it->second.active = true;

  // Suppress the email in bounce handler
  if (impl_->bounce_handler) {
    impl_->bounce_handler->record_complaint(it->second.email);
  }

  // Also store in DB
  try {
    impl_->db.simple_upsert("email_unsubscribes",
        {{"email", it->second.email}},
        {{"unsubscribed_at", std::to_string(now_ms_stamp())},
         {"token", std::string(token)}});
  } catch (const std::exception& e) {
    progressive::log::warn(kEmailIdentityTag,
        "Failed to persist unsubscribe: " + std::string(e.what()));
  }

  progressive::log::info(kEmailIdentityTag,
      "Email " + it->second.email + " unsubscribed");

  return true;
}

bool EmailIdentity::is_unsubscribed(std::string_view email) const {
  std::lock_guard<std::mutex> lock(impl_->unsub_mutex);
  for (const auto& [token, info] : impl_->unsubscribes) {
    if (info.email == email && info.active) return true;
  }

  // Check DB
  try {
    auto rows = impl_->db.simple_select_one("email_unsubscribes",
        {{"email", std::string(email)}}, {"unsubscribed_at"});
    if (rows.has_value()) return true;
  } catch (const std::exception& e) {
    // Not found
  }

  return false;
}

// ---------------------------------------------------------------------------
// Bounce / suppression management
// ---------------------------------------------------------------------------

void EmailIdentity::record_bounce(std::string_view email,
                                   std::string_view reason) {
  if (!impl_->bounce_handler) {
    impl_->bounce_handler = std::make_unique<BounceHandler>();
  }
  impl_->bounce_handler->record_bounce(email, reason);
}

void EmailIdentity::record_complaint(std::string_view email) {
  if (!impl_->bounce_handler) {
    impl_->bounce_handler = std::make_unique<BounceHandler>();
  }
  impl_->bounce_handler->record_complaint(email);
}

nlohmann::json EmailIdentity::get_bounce_status(
    std::string_view email) const {
  if (!impl_->bounce_handler) {
    return {{"bounces", 0}, {"suppressed", false}};
  }
  return {
    {"bounces", impl_->bounce_handler->bounce_count(email)},
    {"suppressed", impl_->bounce_handler->is_suppressed(email)}
  };
}

// ---------------------------------------------------------------------------
// reCAPTCHA verification
// ---------------------------------------------------------------------------

bool EmailIdentity::verify_recaptcha(std::string_view response_token,
                                      std::string_view remote_ip) {
  if (!impl_->recaptcha) {
    // No recaptcha configured, accept
    return true;
  }
  return impl_->recaptcha->verify(response_token, remote_ip);
}

nlohmann::json EmailIdentity::get_recaptcha_config() const {
  if (!impl_->recaptcha) {
    return {{"enabled", false}};
  }
  return {
    {"enabled", true},
    {"site_key", impl_->recaptcha->site_key()}
  };
}

// ---------------------------------------------------------------------------
// Email queue status
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::get_queue_status() const {
  if (!impl_->email_queue) {
    return {
      {"configured", false},
      {"queue_size", 0},
      {"bounces", nlohmann::json::array()}
    };
  }

  auto bounces = impl_->email_queue->get_recent_bounces();
  nlohmann::json bounces_json = nlohmann::json::array();
  for (const auto& [mid, err] : bounces) {
    bounces_json.push_back({{"message_id", mid}, {"error", err}});
  }

  return {
    {"configured", true},
    {"queue_size", impl_->email_queue->queue_size()},
    {"bounces", bounces_json}
  };
}

// ---------------------------------------------------------------------------
// Rate limit queries
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::get_rate_limit_status(
    std::string_view address) const {
  int remaining = impl_->rate_limiter.remaining(address);
  return {
    {"remaining", remaining},
    {"window_seconds", kRateLimitWindowSec},
    {"max_total", kMaxEmailsPerWindow},
    {"max_per_address", kMaxEmailsPerAddressPerWindow}
  };
}

// ---------------------------------------------------------------------------
// I18n language setting
// ---------------------------------------------------------------------------

std::vector<std::string> EmailIdentity::supported_languages() const {
  std::vector<std::string> langs;
  for (const auto& [code, loc] : kLocales) {
    langs.push_back(code);
  }
  return langs;
}

// ---------------------------------------------------------------------------
// Identity server info
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::get_identity_server_info() const {
  if (impl_->identity_client) {
    try {
      return impl_->identity_client->get_server_info();
    } catch (const std::exception& e) {
      progressive::log::warn(kEmailIdentityTag,
          "Failed to get identity server info: " + std::string(e.what()));
    }
  }

  return {
    {"connected", false},
    {"error", "No identity server configured"}
  };
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

nlohmann::json EmailIdentity::send_template(
    std::string_view email, std::string_view display_name,
    const EmailTemplate& tpl) {

  if (!impl_->email_queue) {
    return {{"errcode", "M_UNKNOWN"},
            {"error", "Email service not configured"}};
  }

  if (!impl_->rate_limiter.allow(email)) {
    return {{"errcode", "M_LIMIT_EXCEEDED"},
            {"error", "Rate limit exceeded"}};
  }

  if (impl_->bounce_handler && impl_->bounce_handler->is_suppressed(email)) {
    return {{"errcode", "M_UNKNOWN"},
            {"error", "This address has been suppressed"}};
  }

  EmailAddress from(impl_->smtp_from_address, impl_->smtp_from_name);
  std::vector<EmailAddress> to = {
    EmailAddress(std::string(email), std::string(display_name))
  };

  try {
    std::string msg_id = impl_->email_queue->enqueue(
        from, to, tpl.render_subject(),
        tpl.render_text(), tpl.render_html());
    return {{"success", true}, {"message_id", msg_id}};
  } catch (const std::exception& e) {
    return {{"errcode", "M_UNKNOWN"},
            {"error", std::string("Failed to queue email: ") + e.what()}};
  }
}

std::string EmailIdentity::build_html_email(
    std::string_view title, std::string_view content) const {
  std::ostringstream html;
  html << "<!DOCTYPE html>\n"
       << "<html lang=\"" << impl_->default_language << "\">\n"
       << "<head>\n"
       << "<meta charset=\"UTF-8\">\n"
       << "<meta name=\"viewport\" content=\"width=device-width, "
          "initial-scale=1.0\">\n"
       << "<title>" << html_escape(title) << "</title>\n"
       << "<style>\n"
       << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', "
          "Roboto, Helvetica, Arial, sans-serif; margin:0; padding:0; "
          "background:#f4f5f7; color:#333; }\n"
       << ".container { max-width:600px; margin:0 auto; "
          "background:#fff; border-radius:8px; overflow:hidden; "
          "box-shadow:0 2px 8px rgba(0,0,0,0.1); }\n"
       << ".header { background:#0dbd8b; color:#fff; padding:24px; "
          "text-align:center; }\n"
       << ".header h1 { margin:0; font-size:22px; font-weight:600; }\n"
       << ".body { padding:32px 24px; line-height:1.6; }\n"
       << ".footer { background:#f9f9f9; padding:16px 24px; font-size:12px; "
          "color:#999; text-align:center; border-top:1px solid #eee; }\n"
       << "</style>\n"
       << "</head>\n"
       << "<body style=\"padding:24px 0;\">\n"
       << "<div class=\"container\">\n"
       << "<div class=\"header\"><h1>" << html_escape(title)
       << "</h1></div>\n"
       << "<div class=\"body\">\n"
       << content << "\n"
       << "</div>\n"
       << "<div class=\"footer\">\n"
       << html_escape(impl_->server_name) << "<br>\n"
       << "This is an automated message. Please do not reply.\n"
       << "</div>\n"
       << "</div>\n"
       << "</body>\n"
       << "</html>";
  return html.str();
}

nlohmann::json EmailIdentity::json_validate_success(
    const Impl::SessionInfo& info) const {
  return {
    {"success", true},
    {"medium", info.medium},
    {"address", info.address},
    {"validated_at", info.created_at}
  };
}

std::string EmailIdentity::generate_msisdn_code() const {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, 9);
  std::string code;
  code.reserve(kMsisdnCodeLength);
  for (int i = 0; i < kMsisdnCodeLength; ++i) {
    code += static_cast<char>('0' + dist(gen));
  }
  return code;
}

// ============================================================================
// Free functions: i18n helpers
// ============================================================================

std::string get_localized_string(const std::string& key,
                                  const std::string& language) {
  const auto& loc = get_locale(language);

  if (key == "password_reset_subject") return loc.password_reset_subject;
  if (key == "password_reset_title") return loc.password_reset_title;
  if (key == "password_reset_body") return loc.password_reset_body;
  if (key == "email_verify_subject") return loc.email_verify_subject;
  if (key == "email_verify_title") return loc.email_verify_title;
  if (key == "email_verify_body") return loc.email_verify_body;
  if (key == "invite_subject") return loc.invite_subject;
  if (key == "invite_title") return loc.invite_title;
  if (key == "invite_body") return loc.invite_body;
  if (key == "digest_subject") return loc.digest_subject;
  if (key == "digest_title") return loc.digest_title;
  if (key == "digest_body") return loc.digest_body;
  if (key == "unsubscribe_text") return loc.unsubscribe_text;
  if (key == "unsubscribe_link_text") return loc.unsubscribe_link_text;
  if (key == "footer_text") return loc.footer_text;

  return "";
}

}  // namespace progressive::auth
