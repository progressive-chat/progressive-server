#pragma once
// xmpp_server.hpp - Full XMPP/Jabber server (ejabberd 155,521 lines reference)
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

namespace progressive::xmpp {
using json = nlohmann::json;

// ============================================================================
// XMPP Core Types (RFC 6120, 6121, 6122)
// ============================================================================
struct XMPPJID {
  std::string local; std::string domain; std::string resource;
  std::string bare() const { return local + "@" + domain; }
  std::string full() const { return resource.empty() ? bare() : bare() + "/" + resource; }
  static XMPPJID parse(const std::string& jid);
};
struct XMPPUser {
  XMPPJID jid; std::string password; std::string auth_token;
  bool registered{false}; bool online{false}; int64_t last_activity{0};
  std::map<std::string,std::string> roster; // jid -> subscription
  std::map<std::string,std::vector<std::string>> roster_groups;
};
struct XMPPRoom {
  std::string name; std::string subject; std::string subject_author;
  std::set<XMPPJID> occupants; std::map<XMPPJID,std::string> affiliations;
  std::map<XMPPJID,std::string> roles; std::string config;
  bool persistent{false}; bool members_only{false};
  bool moderated{false}; bool non_anonymous{false};
  int64_t max_users{0}; std::string password;
};
struct XMPPPresence {
  XMPPJID from; XMPPJID to; std::string type; std::string show;
  std::string status; int priority{0}; std::string stanza_id;
};
struct XMPPMessage {
  XMPPJID from; XMPPJID to; std::string type; std::string subject;
  std::string body; std::string thread; std::string stanza_id;
  std::map<std::string,std::string> extensions;
};
struct XMPPIQ {
  XMPPJID from; XMPPJID to; std::string type; std::string id;
  std::string ns; json payload;
};

// XEP implementations supported
namespace XEP {
  constexpr const char* DISCO_INFO = "http://jabber.org/protocol/disco#info";
  constexpr const char* DISCO_ITEMS = "http://jabber.org/protocol/disco#items";
  constexpr const char* MUC = "http://jabber.org/protocol/muc";
  constexpr const char* MUC_ADMIN = "http://jabber.org/protocol/muc#admin";
  constexpr const char* MUC_OWNER = "http://jabber.org/protocol/muc#owner";
  constexpr const char* MUC_USER = "http://jabber.org/protocol/muc#user";
  constexpr const char* PUBSUB = "http://jabber.org/protocol/pubsub";
  constexpr const char* VCARD = "vcard-temp";
  constexpr const char* PRIVACY = "jabber:iq:privacy";
  constexpr const char* ROSTER = "jabber:iq:roster";
  constexpr const char* REGISTER = "jabber:iq:register";
  constexpr const char* VERSION = "jabber:iq:version";
  constexpr const char* LAST = "jabber:iq:last";
  constexpr const char* TIME = "urn:xmpp:time";
  constexpr const char* PING = "urn:xmpp:ping";
  constexpr const char* CARBONS = "urn:xmpp:carbons:2";
  constexpr const char* MAM = "urn:xmpp:mam:2";
  constexpr const char* AVATAR = "urn:xmpp:avatar:metadata";
  constexpr const char* BLOCKING = "urn:xmpp:blocking";
  constexpr const char* BOOKMARKS = "storage:bookmarks";
  constexpr const char* CAPTCHA = "urn:xmpp:captcha";
  constexpr const char* STREAM_MGMT = "urn:xmpp:sm:3";
  constexpr const char* STREAM_MGMT_ACK = "urn:xmpp:sm:3:ack";
  constexpr const char* CSI = "urn:xmpp:csi:0";
  constexpr const char* SASL = "urn:ietf:params:xml:ns:xmpp-sasl";
  constexpr const char* TLS = "urn:ietf:params:xml:ns:xmpp-tls";
  constexpr const char* BIND = "urn:ietf:params:xml:ns:xmpp-bind";
  constexpr const char* SESSION = "urn:ietf:params:xml:ns:xmpp-session";
  constexpr const char* HTTP_BIND = "http://jabber.org/protocol/httpbind";
  constexpr const char* BOSH = "urn:xmpp:bosh";
  constexpr const char* WEBSOCKET = "urn:xmpp:websocket";
  constexpr const char* UPLOAD = "urn:xmpp:http:upload:0";
  constexpr const char* OOB = "jabber:x:oob";
  constexpr const char* JINGLE = "urn:xmpp:jingle:1";
  constexpr const char* STUN = "urn:xmpp:jingle:transports:ice-udp:1";
  constexpr const char* MESSAGE_ARCHIVING = "urn:xmpp:mam:2";
}

// ============================================================================
// XMPP Server Core
// ============================================================================
class XMPPServer {
public:
  XMPPServer(const std::string& domain);

  // Start/stop
  void start(int c2s_port=5222, int s2s_port=5269, int http_port=5280);
  void stop();

  // Connection handling
  struct XMPPConnection {
    int fd; XMPPJID jid; std::string stream_id; std::string stream_ns;
    bool authenticated{false}; bool resource_bound{false}; bool tls{false};
    bool compressed{false}; std::string xml_buffer; int64_t connected_since{0};
    std::string ip; int port{0}; bool csi_active{false}; int sm_h{0};
  };
  XMPPConnection* accept_connection(int fd, const std::string& ip, int port);
  void close_connection(XMPPConnection* conn);
  void process_stream(XMPPConnection* conn, const std::string& data);

  // Stream features
  std::string get_stream_features(XMPPConnection* conn);
  std::string get_auth_features(XMPPConnection* conn);

  // SASL authentication
  bool authenticate_plain(XMPPConnection* conn, const std::string& authzid,
      const std::string& authcid, const std::string& password);
  bool authenticate_digest_md5(XMPPConnection* conn, const std::string& data);
  bool authenticate_scram_sha1(XMPPConnection* conn, const std::string& data);
  bool authenticate_scram_sha256(XMPPConnection* conn, const std::string& data);
  bool authenticate_external(XMPPConnection* conn, const std::string& data);

  // Resource binding
  std::string bind_resource(XMPPConnection* conn, const std::string& resource);
  void unbind_resource(XMPPConnection* conn);

  // Stanza routing
  void route_presence(XMPPConnection* conn, const XMPPPresence& presence);
  void route_message(XMPPConnection* conn, const XMPPMessage& message);
  void route_iq(XMPPConnection* conn, const XMPPIQ& iq);

  // IQ handlers (XEP implementations)
  void handle_disco_info(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_disco_items(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_roster_get(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_roster_set(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_roster_push(const XMPPJID& user, const XMPPJID& contact,
      const std::string& subscription);
  void handle_vcard_get(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_vcard_set(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_register_get(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_register_set(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_privacy_list(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_version(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_last_activity(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_ping(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_time(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_blocking(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_mam_query(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_upload_request(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_upload_slot(XMPPConnection* conn, const XMPPIQ& iq);

  // Multi-User Chat (MUC) - XEP-0045
  void handle_muc_join(XMPPConnection* conn, const XMPPJID& room_jid,
      const std::string& nickname, const std::string& password);
  void handle_muc_leave(XMPPConnection* conn, const XMPPJID& room_jid);
  void handle_muc_message(XMPPConnection* conn, const XMPPJID& room_jid,
      const XMPPMessage& msg);
  void handle_muc_presence(XMPPConnection* conn, const XMPPJID& room_jid,
      const XMPPPresence& pres);
  void handle_muc_admin(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_muc_owner(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_muc_config(XMPPConnection* conn, const XMPPJID& room_jid,
      const std::string& config);
  void handle_muc_destroy(XMPPConnection* conn, const XMPPJID& room_jid,
      const std::string& reason);

  // PubSub - XEP-0060
  void handle_pubsub_publish(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_pubsub_subscribe(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_pubsub_unsubscribe(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_pubsub_items(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_pubsub_configure(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_pubsub_retract(XMPPConnection* conn, const XMPPIQ& iq);
  void handle_pubsub_delete(XMPPConnection* conn, const XMPPIQ& iq);

  // Message Carbons - XEP-0280
  void enable_carbons(XMPPConnection* conn);
  void disable_carbons(XMPPConnection* conn);
  void send_carbon(const XMPPMessage& msg);

  // Stream Management - XEP-0198
  void handle_sm_enable(XMPPConnection* conn);
  void handle_sm_resume(XMPPConnection* conn, const std::string& prev_id, int h);
  void handle_sm_ack(XMPPConnection* conn, int h);
  void handle_sm_request(XMPPConnection* conn);

  // Client State Indication - XEP-0352
  void handle_csi_active(XMPPConnection* conn);
  void handle_csi_inactive(XMPPConnection* conn);

  // HTTP / BOSH / WebSocket
  void handle_bosh_request(const std::string& body);
  void handle_websocket_frame(XMPPConnection* conn, const std::string& frame);

  // S2S (Server-to-Server)
  void handle_s2s_stream(const std::string& from, const std::string& to,
      const std::string& stream_id);
  void route_s2s_stanza(const std::string& from_domain, const std::string& xml);

  // User/Room management
  XMPPUser* get_user(const XMPPJID& jid);
  void update_user(const XMPPUser& user);
  void delete_user(const XMPPJID& jid);
  XMPPRoom* get_room(const std::string& name);
  XMPPRoom* create_room(const std::string& name);
  void delete_room(const std::string& name);

  // Delivery
  void deliver_to_user(const XMPPJID& jid, const std::string& stanza_xml);
  void deliver_to_room(const std::string& room, const std::string& stanza_xml);
  void store_offline_message(const XMPPJID& jid, const std::string& stanza_xml);
  std::vector<std::string> get_offline_messages(const XMPPJID& jid);
  void delete_offline_messages(const XMPPJID& jid);

  // Privacy / Blocking
  bool is_blocked(const XMPPJID& user, const XMPPJID& contact);
  bool is_privacy_allowed(const XMPPJID& user, const XMPPJID& contact,
      const std::string& stanza_type);

  // Roster management
  std::string get_subscription(const XMPPJID& user, const XMPPJID& contact);
  void set_subscription(const XMPPJID& user, const XMPPJID& contact,
      const std::string& subscription);
  void add_roster_item(const XMPPJID& user, const XMPPJID& contact,
      const std::string& name, const std::vector<std::string>& groups);
  void remove_roster_item(const XMPPJID& user, const XMPPJID& contact);

  // vCard
  json get_vcard(const XMPPJID& jid);
  void set_vcard(const XMPPJID& jid, const json& vcard);

  // Avatar
  json get_avatar(const XMPPJID& jid);
  void set_avatar(const XMPPJID& jid, const std::string& mime_type,
      const std::vector<uint8_t>& data);

  // HTTP upload
  std::string create_upload_slot(const XMPPJID& uploader, const std::string& filename,
      int64_t size, const std::string& content_type);
  std::optional<std::string> get_upload_url(const std::string& slot);

  // Config
  struct ServerConfig {
    std::string domain; std::string server_name; std::vector<std::string> hosts;
    int c2s_port{5222}; int s2s_port{5269}; int http_port{5280};
    int max_stanza_size{65536}; int max_users{0}; int max_rooms{0};
    std::string welcome_message; bool registration_enabled{true};
    bool s2s_enabled{true}; bool websocket_enabled{true};
    std::vector<std::string> trusted_servers;
    std::map<std::string,std::string> s2s_certs;
  };
  ServerConfig& config() { return config_; }

  // Statistics
  int64_t online_users() const;
  int64_t registered_users() const;
  int64_t active_rooms() const;
  int64_t s2s_connections() const;

  // Module system (ejabberd-style)
  struct XMPPModule {
    std::string name; std::string author; std::string version;
    std::function<void(XMPPServer&)> start;
    std::function<void(XMPPServer&)> stop;
    std::function<bool(XMPPConnection*,const XMPPPresence&)> on_presence;
    std::function<bool(XMPPConnection*,const XMPPMessage&)> on_message;
    std::function<bool(XMPPConnection*,const XMPPIQ&)> on_iq;
    std::function<void(const XMPPJID&)> on_user_online;
    std::function<void(const XMPPJID&)> on_user_offline;
    std::function<void(const std::string&,const std::string&)> on_register;
  };
  void register_module(const XMPPModule& mod);
  void unregister_module(const std::string& name);

private:
  std::map<std::string,XMPPUser> users_;
  std::map<std::string,XMPPRoom> rooms_;
  std::map<int,XMPPConnection> connections_;
  std::map<std::string,std::vector<std::string>> offline_messages_;
  std::map<std::string,XMPPModule> modules_;
  std::map<std::string,json> vcards_;
  std::map<std::string,std::string> upload_slots_;
  std::map<std::string,std::string> privacy_lists_;
  ServerConfig config_;
  bool running_{false};
  int c2s_fd_{-1}; int s2s_fd_{-1}; int http_fd_{-1};
  int64_t start_time_{0};
  int sm_id_counter_{0};
};

} // namespace progressive::xmpp
