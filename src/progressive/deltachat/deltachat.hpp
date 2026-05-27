#pragma once
// deltachat.hpp - DeltaChat email-based chat (118,836 lines reference)
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>

namespace progressive::deltachat {
using json = nlohmann::json;

// ============================================================================
// Core types
// ============================================================================
struct DcContact {
  uint32_t id{0}; std::string name; std::string display_name; std::string addr;
  std::string auth_name; std::string profile_image; std::string color;
  int64_t last_seen{0}; int64_t was_seen_recently{0}; int blocked{0};
  int verified{0}; int chat_id{0}; std::string status;
};
struct DcChat {
  uint32_t id{0}; std::string name; std::string grpid; int type{0};
  int blocking{0}; int muted_duration{0}; int ephemeral_duration{0};
  int can_send{0}; int was_seen_recently{0}; int64_t created_at{0};
  int64_t sort_timestamp{0}; std::string summary;
};
struct DcMessage {
  uint32_t id{0}; int chat_id{0}; int from_id{0}; int to_id{0};
  int64_t timestamp{0}; int64_t sort_timestamp{0}; int64_t received_timestamp{0};
  int64_t sent_timestamp{0}; int flags{0}; int state{0}; int type{0};
  std::string text; std::string rfc724_mid; std::string error;
  std::string subject; std::string mime_headers; std::string mime_in_reply_to;
  std::string mime_references; std::string location; int hidden{0};
  int64_t ephemeral_timestamp{0}; int download_state{0};
};
struct DcLot { uint32_t id{0}; std::string text1; std::string text2; int64_t timestamp{0}; int state{0}; };
struct DcChatlistItem { uint32_t chat_id{0}; DcChat chat; DcMessage last_message; int fresh_count{0}; };
struct DcSecureJoin { std::string invitenumber; std::string auth; int group_count{0}; int contact_count{0}; };
struct DcProvider { std::string before_login_hint; std::string overview_page; int64_t status{0}; };
struct DcKey { int type{0}; std::string fingerprint; std::string public_key; std::string private_key; };
struct DcWebxdc { std::string name; std::string icon; std::string document; std::string summary; bool self_addr{false}; bool send_update_interval{false}; };

// ============================================================================
// DeltaChat Core
// ============================================================================
class DeltaChat {
public:
  DeltaChat(const std::string& dbfile);

  // Open/close
  void open(); void close(); bool is_open(); void start_io();
  void stop_io(); void maybe_network();

  // ---- Configuration ----
  void set_config(const std::string& key, const std::string& value);
  std::string get_config(const std::string& key);
  std::string get_config_fast(const std::string& key, const std::string& def="");
  void configure(); void stop_ongoing_process();

  // ---- Account management ----
  bool is_configured(); bool is_configured_fast();
  void add_account(); void remove_account(uint32_t account_id);
  uint32_t add_account_future(); bool remove_all_accounts();
  std::vector<uint32_t> get_all_account_ids();
  void select_account(uint32_t account_id);
  void migrate_account(const std::string& dbfile);

  // ---- Contacts ----
  uint32_t create_contact(const std::string& name="", const std::string& addr="");
  DcContact get_contact(uint32_t contact_id);
  std::vector<uint32_t> get_contacts(uint32_t flags=0, const std::string& query="");
  std::vector<uint32_t> get_blocked_contacts();
  std::vector<uint32_t> get_contact_ids(const std::string& name, const std::string& addr);
  bool set_contact_name(uint32_t contact_id, const std::string& name);
  bool set_contact_auth_name(uint32_t contact_id, const std::string& auth_name);
  bool set_contact_profile_image(uint32_t contact_id, const std::string& image);
  bool set_contact_status(uint32_t contact_id, const std::string& status);
  std::string get_contact_encrinfo(uint32_t contact_id);
  bool delete_contact(uint32_t contact_id);
  int lookup_contact_id_by_addr(const std::string& addr);
  uint32_t create_contact_by_addr(const std::string& addr);

  // ---- Chats ----
  uint32_t create_group_chat(bool verified, const std::string& name);
  uint32_t create_broadcast_list();
  DcChat get_chat(uint32_t chat_id);
  std::vector<uint32_t> get_chats(uint32_t flags=0, const std::string& query="");
  std::vector<uint32_t> get_chat_msgs(uint32_t chat_id, uint32_t flags=0, const std::string& query="");
  DcChatlistItem get_chatlist_item(uint32_t chat_id);
  uint32_t get_chat_id_by_grpid(const std::string& grpid);
  int get_chat_contact_count(uint32_t chat_id);
  std::vector<uint32_t> get_chat_contacts(uint32_t chat_id);
  bool set_chat_name(uint32_t chat_id, const std::string& name);
  bool set_chat_profile_image(uint32_t chat_id, const std::string& image);
  bool set_chat_muted_duration(uint32_t chat_id, int64_t duration);
  bool set_chat_ephemeral_duration(uint32_t chat_id, int64_t duration);
  bool set_chat_protection(uint32_t chat_id, bool protect);
  bool set_chat_visibility(uint32_t chat_id, int visibility);
  bool delete_chat(uint32_t chat_id);
  bool archive_chat(uint32_t chat_id, bool archive);
  bool pin_chat(uint32_t chat_id, bool pin);
  bool accept_chat(uint32_t chat_id);
  bool block_chat(uint32_t chat_id);
  bool unarchive_chat(uint32_t chat_id);
  uint32_t get_chat_id_by_contact_id(uint32_t contact_id);
  uint32_t create_chat_by_contact_id(uint32_t contact_id);
  uint32_t create_chat_by_msg_id(uint32_t msg_id);

  // ---- Messages ----
  uint32_t send_msg(uint32_t chat_id, const std::string& text, bool is_bot=false, const std::string& quoted_msg_id="");
  uint32_t send_msg_synced(uint32_t chat_id, const std::string& text);
  uint32_t send_videochat_invitation(uint32_t chat_id);
  uint32_t send_webxdc_instance(uint32_t chat_id, const std::string& name, const std::string& icon, const std::string& doc, const std::string& summary);
  uint32_t send_msg_future(uint32_t chat_id, const std::string& text, int64_t timestamp);
  DcMessage get_msg(uint32_t msg_id);
  std::vector<uint32_t> get_fresh_msgs(uint32_t chat_id);
  std::vector<uint32_t> get_fresh_msg_cnt(uint32_t chat_id);
  int get_fresh_msg_count(uint32_t chat_id);
  int get_estimated_deletion_count(bool from_server, int64_t seconds);
  std::string get_msg_info(uint32_t msg_id);
  bool set_msg_text(uint32_t msg_id, const std::string& text);
  bool set_msg_location(uint32_t msg_id, double latitude, double longitude);
  bool set_msg_override_sender_name(uint32_t msg_id, const std::string& name);
  bool delete_msgs(const std::vector<uint32_t>& msg_ids);
  bool markseen_msgs(const std::vector<uint32_t>& msg_ids);
  bool star_msgs(const std::vector<uint32_t>& msg_ids, bool star);
  std::vector<uint32_t> search_msgs(uint32_t chat_id, const std::string& query);
  std::vector<uint32_t> get_next_media(uint32_t msg_id, int dir, int msg_type);
  uint32_t get_webxdc_status_updates(uint32_t msg_id, int64_t last_known_serial);
  bool send_webxdc_status_update(uint32_t msg_id, const std::string& update, const std::string& description);

  // ---- Message attachments ----
  void set_msg_file(uint32_t msg_id, const std::string& file, const std::string& mime, const std::string& name, int64_t duration=0);
  std::string get_msg_file(uint32_t msg_id);
  std::string get_msg_filebytes(uint32_t msg_id);
  std::string get_msg_filename(uint32_t msg_id);
  std::string get_msg_filemime(uint32_t msg_id);
  int64_t get_msg_filebytes_count(uint32_t msg_id);

  // ---- Chatlist ----
  DcChatlistItem get_chatlist(uint32_t flags=0, const std::string& query="", uint32_t contact_id=0);
  std::vector<DcChatlistItem> get_chatlist_items(int index=0, int count=-1);
  int get_chatlist_cnt();

  // ---- Secure join (Autocrypt Setup Message) ----
  std::string get_securejoin_qr(uint32_t chat_id);
  uint32_t join_securejoin(const std::string& qr);
  bool check_qr(const std::string& qr);
  DcSecureJoin get_securejoin_status(uint32_t chat_id);

  // ---- Peer channels (DC 1.48) ----
  uint32_t send_peer_msg(uint32_t chat_id, const std::string& data);
  std::string get_peer_msg(uint32_t msg_id);
  bool was_msg_peer_sent(uint32_t msg_id);

  // ---- Backup / Export / Import ----
  void imex(int what, const std::string& dir);
  int imex_has_backup(const std::string& dir);
  std::string imex_progress();
  int import_self_keys(const std::string& dir);

  // ---- Key management ----
  DcKey get_key(const std::string& addr, int type=0);
  std::string get_fingerprint();
  std::string get_self_fingerprint();

  // ---- Verified groups ----
  uint32_t create_verified_group(const std::string& name);

  // ---- Connectivity ----
  int get_connectivity();
  std::string get_connectivity_html();
  int64_t get_connectivity_summary();

  // ---- E2EE status ----
  std::string get_contact_encryption_info(uint32_t contact_id);

  // ---- Webxdc ----
  int send_webxdc_status_update(uint32_t msg_id, const std::string& payload, const std::string& desc);

  // ---- SMTP / IMAP ----
  std::string get_provider_info(const std::string& addr);
  int check_provider_config(const std::string& email_addr, const std::string& password, const std::string& imap_server, int imap_port, int imap_security, const std::string& smtp_server, int smtp_port, int smtp_security);
  int probe_imap_network(int64_t timeout_ms);
  void set_config_from_qr(const std::string& qr);
  std::string get_auth_name_from_qr(const std::string& qr);

  // ---- Blob directory (files/avatars) ----
  std::string get_blobdir();
  std::string get_self_avatar();
  std::string get_contact_avatar(uint32_t contact_id);

  // ---- Message reactions (DC 1.46) ----
  bool send_reaction(uint32_t msg_id, const std::string& reaction);
  std::string get_msg_reactions(uint32_t msg_id);

  // ---- Ephemeral messages ----
  bool set_ephemeral_timer(uint32_t chat_id, int64_t duration_ms);

  // ---- Sync messages (multi-device) ----
  uint32_t add_sync_msg(const std::string& sync_data);
  bool is_sync_msg(uint32_t msg_id);

  // ---- HTTP/SMTP proxy ----
  void set_http_proxy(bool enabled, const std::string& proxy_url);
  void set_socks5_proxy(bool enabled, const std::string& host, int port, const std::string& user, const std::string& pw);

  // ---- Connectivity / Network ----
  int maybe_network_lost();
  bool is_network_available();

  // ---- Event callbacks ----
  using EventCallback = std::function<void(int event, uint32_t data1, uint32_t data2)>;
  int get_next_event();
  std::string get_event_str(int event_id);
  void set_event_callback(EventCallback cb);

  // ---- Config ----
  struct Config {
    std::string dbfile; std::string addr; std::string mail_pw;
    std::string imap_server; int imap_port{993}; int imap_security{1};
    std::string smtp_server; int smtp_port{465}; int smtp_security{1};
    std::string display_name; std::string self_status;
    std::string self_avatar; bool e2ee_enabled{true};
    bool mdns_enabled{true}; bool bot{false}; int64_t configured_mail_server{0};
    int64_t configured_mail_port{0}; int64_t configured_mail_security{0};
    int64_t configured_send_server{0}; int64_t configured_send_port{0};
    int64_t configured_send_security{0}; bool configured{false};
    bool webrtc_instance{false}; int64_t last_housekeeping{0};
    int64_t inbox_watch{0}; int64_t sentbox_watch{0};
    int64_t mvbox_move{0}; bool only_fetch_mvbox{false};
    int64_t configured_addr{0}; bool bcc_self{false};
    int64_t scan_all_folders_debounce_secs{0};
  };
  Config& config() { return config_; }

private:
  Config config_; bool running_{false}; bool io_running_{false};
  std::map<uint32_t,DcContact> contacts_; std::map<uint32_t,DcChat> chats_;
  std::map<uint32_t,DcMessage> messages_; std::map<uint32_t,DcLot> lots_;
  EventCallback event_cb_;
  uint32_t next_id_{1};
  uint32_t gen_id() { return next_id_++; }
};

} // namespace progressive::deltachat
