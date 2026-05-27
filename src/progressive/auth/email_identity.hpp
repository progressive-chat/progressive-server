#pragma once

#include <chrono>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../json.hpp"
#include "../storage/database.hpp"

namespace progressive::auth {

// ============================================================================
// EmailAddress
// ============================================================================
class EmailAddress {
public:
  EmailAddress(std::string address, std::string display = "");
  const std::string& address() const;
  const std::string& display_name() const;
  std::string formatted() const;

private:
  std::string address_;
  std::string display_name_;
};

// ============================================================================
// EmailTemplate
// ============================================================================
class EmailTemplate {
public:
  EmailTemplate(std::string subject, std::string text_body,
                std::string html_body);

  const std::string& subject() const;
  const std::string& text_body() const;
  const std::string& html_body() const;

  void set_variable(const std::string& key, const std::string& value);

  std::string render_subject() const;
  std::string render_text() const;
  std::string render_html() const;

private:
  std::string render(std::string_view tpl) const;

  std::string subject_;
  std::string text_body_;
  std::string html_body_;
  std::map<std::string, std::string> variables_;
};

// ============================================================================
// SmtpError
// ============================================================================
class SmtpError : public std::exception {
public:
  SmtpError(int code, std::string msg, bool retryable = false);
  int code() const;
  const std::string& message() const;
  bool is_retryable() const;
  const char* what() const noexcept override;

private:
  int code_;
  std::string message_;
  bool retryable_;
};

// ============================================================================
// SmtpConfig
// ============================================================================
struct SmtpConfig {
  std::string host;
  int port = 587;
  bool use_tls = true;
  std::string helo_name = "matrix.local";
  std::string username;
  std::string password;
  std::string from_address;
  std::string from_name;
};

// ============================================================================
// RateLimiter
// ============================================================================
class RateLimiter {
public:
  RateLimiter(int window_secs, int max_total, int max_per_address);
  bool allow(std::string_view address);
  int64_t remaining(std::string_view address) const;

private:
  void prune(std::chrono::steady_clock::time_point now);

  int window_secs_;
  int64_t max_total_;
  int64_t max_per_address_;
  std::deque<std::chrono::steady_clock::time_point> timestamps_;
  std::unordered_map<std::string,
      std::deque<std::chrono::steady_clock::time_point>> per_address_;
  mutable std::mutex mutex_;
};

// ============================================================================
// SmtpConnection
// ============================================================================
class SmtpConnection {
public:
  SmtpConnection(std::string smtp_host, int smtp_port, bool tls,
                 std::string helo_name);
  ~SmtpConnection();

  void connect();
  void disconnect();
  bool is_connected() const;

  void authenticate(std::string_view username, std::string_view password);

  void send_mail(const EmailAddress& from,
                 const std::vector<EmailAddress>& to,
                 const std::vector<EmailAddress>& cc,
                 const std::vector<EmailAddress>& bcc,
                 std::string_view subject,
                 std::string_view text_body,
                 std::string_view html_body,
                 const std::string& dkim_header);

private:
  void send_command(const std::string& cmd);
  std::pair<int, std::string> read_response();

  std::string host_;
  int port_;
  bool use_tls_;
  std::string helo_name_;
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ============================================================================
// DkimSigner
// ============================================================================
class DkimSigner {
public:
  DkimSigner(std::string domain, std::string selector,
             std::string private_key_pem);
  ~DkimSigner();

  std::string sign(const std::string& headers, const std::string& body) const;

  static DkimSigner generate(const std::string& domain,
                              const std::string& selector);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ============================================================================
// EmailQueue
// ============================================================================
class EmailQueue {
public:
  EmailQueue(SmtpConfig config, std::unique_ptr<DkimSigner> dkim);
  ~EmailQueue();

  void start();
  void stop();

  std::string enqueue(const EmailAddress& from,
                      const std::vector<EmailAddress>& to,
                      std::string_view subject,
                      std::string_view text_body,
                      std::string_view html_body);

  std::string enqueue(const EmailAddress& from,
                      const std::vector<EmailAddress>& to,
                      const std::vector<EmailAddress>& cc,
                      const std::vector<EmailAddress>& bcc,
                      std::string_view subject,
                      std::string_view text_body,
                      std::string_view html_body);

  size_t queue_size() const;

  void record_bounce(const std::string& message_id,
                     const std::string& error);
  std::vector<std::pair<std::string, std::string>>
  get_recent_bounces() const;

private:
  void worker_loop();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ============================================================================
// BounceHandler
// ============================================================================
class BounceHandler {
public:
  explicit BounceHandler(int threshold = 3);
  ~BounceHandler();

  void record_bounce(std::string_view email, std::string_view reason);
  void record_complaint(std::string_view email);
  bool is_suppressed(std::string_view email) const;
  int bounce_count(std::string_view email) const;
  void clear_bounces(std::string_view email);
  void clear_all();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ============================================================================
// IdentityServerClient
// ============================================================================
class IdentityServerClient {
public:
  explicit IdentityServerClient(std::string base_url);
  ~IdentityServerClient();

  void set_access_token(std::string_view token);
  void set_timeout(int seconds);

  const std::string& base_url() const;

  // Lookup endpoints
  nlohmann::json lookup_3pid(std::string_view medium,
                              std::string_view address);
  nlohmann::json lookup_hash(const std::string& pepper,
                              std::string_view algorithm,
                              const std::string& hash_value);
  nlohmann::json bulk_lookup(const std::string& pepper,
                              std::string_view algorithm,
                              const std::vector<std::string>& hash_values);

  // Token request/submit
  nlohmann::json request_token(std::string_view medium,
                                std::string_view address,
                                std::string_view client_secret,
                                int send_attempt);
  nlohmann::json submit_token(std::string_view medium,
                               std::string_view token,
                               std::string_view client_secret,
                               std::string_view sid);

  // Bind/unbind
  nlohmann::json bind_3pid(std::string_view medium, std::string_view address,
                            std::string_view mxid);
  nlohmann::json unbind_3pid(std::string_view medium,
                              std::string_view address);

  // Terms of service
  nlohmann::json get_terms_of_service();
  nlohmann::json accept_terms_of_service(const std::string& user_accepts);

  // Other
  nlohmann::json validate_ephemeral_key(std::string_view public_key);
  nlohmann::json get_server_info();
  nlohmann::json store_invite(std::string_view medium,
                               std::string_view address,
                               std::string_view room_id,
                               std::string_view sender,
                               std::string_view room_name);

private:
  nlohmann::json get_request(const std::string& path);
  nlohmann::json post_request(const std::string& path,
                               const nlohmann::json& body);
  std::string http_get(const std::string& path);
  std::string http_post(const std::string& path, const std::string& body);
  std::string http_send_recv(const std::string& host, int port,
                              const std::string& request);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ============================================================================
// ReCaptchaVerifier
// ============================================================================
class ReCaptchaVerifier {
public:
  ReCaptchaVerifier(std::string site_key, std::string secret_key);
  ~ReCaptchaVerifier();

  const std::string& site_key() const;
  bool verify(std::string_view response_token,
              std::string_view remote_ip = "");

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ============================================================================
// EmailIdentity - Main class for email notifications, templates, 3PID
// management, identity server integration, reCAPTCHA, and more
// ============================================================================
class EmailIdentity {
public:
  explicit EmailIdentity(storage::DatabasePool& db);
  ~EmailIdentity();

  // Lifecycle
  void start();
  void stop();

  // Configuration
  void configure_smtp(const SmtpConfig& config,
                      std::unique_ptr<DkimSigner> dkim = nullptr);
  void configure_identity_server(
      std::unique_ptr<IdentityServerClient> client);
  void configure_recaptcha(std::unique_ptr<ReCaptchaVerifier> recaptcha);
  void configure_bounce_handler(std::unique_ptr<BounceHandler> bh);
  void set_server_name(const std::string& name);
  void set_base_url(const std::string& url);
  void set_default_language(const std::string& lang);

  // ------------------------------------------------------------------------
  // Email template creation (returns fully populated EmailTemplate)
  // ------------------------------------------------------------------------
  EmailTemplate make_password_reset_template(
      std::string_view user_id, std::string_view display_name,
      std::string_view reset_link, int expiry_hours,
      const std::string& language = "") const;

  EmailTemplate make_verify_template(
      std::string_view email, std::string_view display_name,
      std::string_view verify_link, int expiry_hours,
      const std::string& language = "") const;

  EmailTemplate make_invitation_template(
      std::string_view email, std::string_view inviter_name,
      std::string_view inviter_id, std::string_view room_name,
      std::string_view invite_link,
      const std::string& language = "") const;

  EmailTemplate make_digest_template(
      std::string_view user_id, std::string_view display_name,
      int unread_count, int room_count,
      std::string_view room_summary, std::string_view unsubscribe_link,
      const std::string& language = "") const;

  // ------------------------------------------------------------------------
  // Send specific email types (template + enqueue)
  // ------------------------------------------------------------------------
  nlohmann::json send_password_reset_email(
      std::string_view email, std::string_view user_id,
      std::string_view display_name, std::string_view reset_token,
      int expiry_hours, const std::string& language = "");

  nlohmann::json send_verification_email(
      std::string_view email, std::string_view display_name,
      std::string_view token, std::string_view client_secret,
      std::string_view sid, int expiry_hours,
      const std::string& language = "");

  nlohmann::json send_invitation_email(
      std::string_view email, std::string_view inviter_name,
      std::string_view inviter_id, std::string_view room_name,
      std::string_view invite_link, const std::string& language = "");

  nlohmann::json send_digest_email(
      std::string_view email, std::string_view user_id,
      std::string_view display_name, int unread_count, int room_count,
      std::string_view room_summary, const std::string& language = "");

  // ------------------------------------------------------------------------
  // Password reset flow
  // ------------------------------------------------------------------------
  nlohmann::json request_password_reset(
      std::string_view email, std::string_view client_secret,
      int send_attempt = 1);
  nlohmann::json validate_password_reset_token(
      std::string_view token, std::string_view client_secret,
      std::string_view sid);

  // ------------------------------------------------------------------------
  // Email verification (3PID validate)
  // ------------------------------------------------------------------------
  nlohmann::json request_email_token(
      std::string_view email, std::string_view client_secret,
      int send_attempt, std::string_view next_link = "");
  nlohmann::json validate_email_token(
      std::string_view token, std::string_view client_secret,
      std::string_view sid);

  // ------------------------------------------------------------------------
  // MSISDN (SMS) verification
  // ------------------------------------------------------------------------
  nlohmann::json request_msisdn_token(
      std::string_view msisdn, std::string_view client_secret,
      int send_attempt = 1);
  nlohmann::json validate_msisdn_token(
      std::string_view token, std::string_view client_secret,
      std::string_view sid);

  // ------------------------------------------------------------------------
  // Identity server: lookup, bind, unbind
  // ------------------------------------------------------------------------
  nlohmann::json lookup_3pid(std::string_view medium,
                              std::string_view address);
  nlohmann::json bulk_lookup_3pid(
      const std::string& pepper, std::string_view algorithm,
      const std::vector<std::string>& hash_values);
  nlohmann::json bind_3pid(std::string_view medium,
                            std::string_view address,
                            std::string_view mxid);
  nlohmann::json unbind_3pid(std::string_view medium,
                              std::string_view address,
                              std::string_view mxid = "");

  // ------------------------------------------------------------------------
  // 3PID management (CRUD)
  // ------------------------------------------------------------------------
  nlohmann::json add_3pid(std::string_view mxid,
                           std::string_view medium,
                           std::string_view address,
                           std::string_view client_secret,
                           int send_attempt = 1);
  nlohmann::json submit_3pid_token(std::string_view medium,
                                    std::string_view token,
                                    std::string_view client_secret,
                                    std::string_view sid);
  nlohmann::json delete_3pid(std::string_view mxid,
                              std::string_view medium,
                              std::string_view address);
  nlohmann::json get_3pids(std::string_view mxid);

  // ------------------------------------------------------------------------
  // Terms of service
  // ------------------------------------------------------------------------
  nlohmann::json get_terms_of_service();
  nlohmann::json accept_terms_of_service(std::string_view mxid,
                                          const std::string& user_accepts);

  // ------------------------------------------------------------------------
  // Session management
  // ------------------------------------------------------------------------
  nlohmann::json get_session_info(std::string_view sid);
  void cleanup_expired_sessions();
  size_t active_session_count() const;

  // ------------------------------------------------------------------------
  // Unsubscribe management
  // ------------------------------------------------------------------------
  std::string generate_unsubscribe_token(std::string_view email);
  bool process_unsubscribe(std::string_view token);
  bool is_unsubscribed(std::string_view email) const;

  // ------------------------------------------------------------------------
  // Bounce / suppression management
  // ------------------------------------------------------------------------
  void record_bounce(std::string_view email, std::string_view reason);
  void record_complaint(std::string_view email);
  nlohmann::json get_bounce_status(std::string_view email) const;

  // ------------------------------------------------------------------------
  // reCAPTCHA verification
  // ------------------------------------------------------------------------
  bool verify_recaptcha(std::string_view response_token,
                        std::string_view remote_ip = "");
  nlohmann::json get_recaptcha_config() const;

  // ------------------------------------------------------------------------
  // Email queue status
  // ------------------------------------------------------------------------
  nlohmann::json get_queue_status() const;

  // ------------------------------------------------------------------------
  // Rate limit queries
  // ------------------------------------------------------------------------
  nlohmann::json get_rate_limit_status(std::string_view address) const;

  // ------------------------------------------------------------------------
  // I18n
  // ------------------------------------------------------------------------
  std::vector<std::string> supported_languages() const;

  // ------------------------------------------------------------------------
  // Identity server info
  // ------------------------------------------------------------------------
  nlohmann::json get_identity_server_info() const;

private:
  nlohmann::json send_template(std::string_view email,
                                std::string_view display_name,
                                const EmailTemplate& tpl);
  std::string build_html_email(std::string_view title,
                                std::string_view content) const;
  nlohmann::json json_validate_success(
      const struct Impl::SessionInfo& info) const;
  std::string generate_msisdn_code() const;

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Free function: i18n string lookup
// ============================================================================
std::string get_localized_string(const std::string& key,
                                  const std::string& language = "en");

}  // namespace progressive::auth
