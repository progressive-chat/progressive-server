// progressive-server: DeltaChat core - Email-based chat protocol
// Reference: deltachat-core (118,836 lines Rust) - MIME encoding/decoding,
// SMTP/IMAP handling, end-to-end encryption (Autocrypt), contact management,
// chat groups via email threads, message formatting, QR code verification.
// Translating all 1,500+ Rust structs, enums, and functions to C++20.

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <optional>
#include <variant>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <regex>
#include <random>
#include <map>
#include <set>
#include <deque>
#include <cstring>
#include <cstdlib>

namespace progressive {
namespace deltachat {

// =============================================================================
// DeltaChat constants
// =============================================================================
static constexpr int DC_VERSION_MAJOR = 1;
static constexpr int DC_VERSION_MINOR = 148;
static constexpr int DC_VERSION_PATCH = 4;
static constexpr int DC_FETCH_EXISTING_MSGS = 0x01;
static constexpr int DC_FETCH_EXISTING_MSGS_NEW_CONTACTS = 0x02;
static constexpr int DC_MSG_ID_LAST_SPECIAL = 9;
static constexpr int DC_CHAT_ID_DEADDROP = 1;
static constexpr int DC_CHAT_ID_STARRED = 5;
static constexpr int DC_CHAT_ID_ARCHIVED_LINK = 6;
static constexpr int DC_CHAT_ID_ALLDONE_HINT = 7;
static constexpr int DC_CHAT_ID_TRASH = 3;
static constexpr int DC_CHAT_ID_MSGS_IN_CREATION = 4;
static constexpr int DC_MAX_SUBJECT_CHARS = 64;
static constexpr int DC_MAX_GET_INFO_LEN = 100000;
static constexpr int DC_MAX_GET_TEXT_LEN = 30000;

// =============================================================================
// Basic enums
// =============================================================================
enum class Viewtype : int {
    UNKNOWN = 0,
    TEXT = 10,
    IMAGE = 20,
    GIF = 21,
    STICKER = 23,
    AUDIO = 40,
    VOICE = 41,
    VIDEO = 50,
    FILE = 60,
    VIDEOCHAT_INVITATION = 70,
    WEBXDC = 80,
};

enum class MsgState : int {
    UNDEFINED = 0,
    IN_FRESH = 10,
    IN_NOTICED = 13,
    IN_SEEN = 16,
    OUT_PREPARING = 18,
    OUT_DRAFT = 19,
    OUT_PENDING = 20,
    OUT_FAILED = 24,
    OUT_DELIVERED = 26,
    OUT_MDN_RCVD = 28,
};

enum class ChatType : int {
    UNDEFINED = 0,
    SINGLE = 100,
    GROUP = 120,
    BROADCAST = 140,
    MAILINGLIST = 160,
};

enum class ChatVisibility : int {
    NORMAL = 0,
    ARCHIVED = 1,
    PINNED = 2,
};

enum class ChatProtection : int {
    UNPROTECTED = 0,
    PROTECTED = 1,
};

enum class EphemeralTimer : int {
    DISABLED = 0,
    ONE_MINUTE = 60,
    ONE_HOUR = 3600,
    ONE_DAY = 86400,
    ONE_WEEK = 604800,
    FOUR_WEEKS = 2419200,
};

enum class Connectivity : int {
    NOT_CONNECTED = 1000,
    CONNECTING = 2000,
    WORKING = 3000,
    CONNECTED = 4000,
};

enum class MediaQuality : int {
    BALANCED = 0,
    WORSE = 1,
};

enum class ImageFormat : int {
    DEFAULT = 0,
    JPEG = 1,
    PNG = 2,
    WEBP = 3,
};

enum class KeyGenType : int {
    DEFAULT = 0,
    RSA_2048 = 1,
    ED25519 = 2,
    RSA_4096 = 3,
};

// =============================================================================
// Contact
// =============================================================================
struct Contact {
    int64_t id = 0;
    std::string name;
    std::string addr;           // email address
    std::string display_name;   // name as displayed
    std::string auth_name;      // verified display name
    std::string status;
    std::string profile_image;  // path to avatar
    std::string color;          // hex color for UI
    std::string last_seen;
    bool blocked = false;
    bool verified = false;
    bool was_seen_recently() const;
    int is_bot = 0;
    int origin = 0;             // where we got this contact from
    int verifier_id = 0;        // who verified this contact
    int unomitted_count = 0;    // messages not in trash
    time_t timestamp = 0;
    time_t created = 0;
    time_t modified = 0;
};

// =============================================================================
// Chat
// =============================================================================
struct Chat {
    int64_t id = 0;
    ChatType type = ChatType::UNDEFINED;
    std::string name;
    std::string grpid;          // group ID (Message-ID of creation msg)
    std::string profile_image;
    std::string color;
    bool archived = false;
    ChatVisibility visibility = ChatVisibility::NORMAL;
    ChatProtection protection = ChatProtection::UNPROTECTED;
    bool is_device_talk = false;
    bool is_self_talk = false;
    bool is_broadcast = false;
    bool is_mailing_list = false;
    bool is_protected = false;
    bool is_sending_locations = false;
    bool is_muted = false;
    bool was_seen_recently() const;
    EphemeralTimer ephemeral_timer = EphemeralTimer::DISABLED;
    time_t ephemeral_timestamp = 0;
    int unomitted_count = 0;
    time_t timestamp = 0;
    time_t created = 0;
    time_t modified = 0;
    int64_t parent_id = 0;      // for mailing list threads
    std::string param_profile_image;
    int64_t draft_id = 0;
    std::string draft_text;
    int64_t draft_timestamp = 0;
};

// =============================================================================
// Message
// =============================================================================
struct Message {
    int64_t id = 0;
    int64_t chat_id = 0;
    int64_t from_id = 0;
    int64_t to_id = 0;
    int64_t quoted_message_id = 0;
    std::string rfc724_mid;     // Message-ID
    std::string in_reply_to;    // References/In-Reply-To
    std::string server_folder;
    int server_uid = 0;
    MsgState state = MsgState::UNDEFINED;
    Viewtype viewtype = Viewtype::UNKNOWN;
    std::string text;
    std::string subject;
    std::string param;          // key=value pairs
    int bytes = 0;
    int download_state = 0;     // 0=done, 1000=available, 1100=failure, 1200=in_progress
    std::string error;
    bool hidden = false;
    bool starred = false;
    bool is_dc_message = false; // DeltaChat system message
    bool has_html = false;
    bool has_location = false;
    double location_latitude = 0.0;
    double location_longitude = 0.0;
    int location_radius = 0;
    int location_timestamp = 0;
    bool is_info = false;       // informational message
    bool is_setupmessage = false;
    bool is_autocrypt_setup_message = false;
    bool is_securejoin_setup_message = false;
    bool is_webxdc = false;
    std::string webxdc_blob;
    int duration = 0;           // audio/video duration in ms
    int width = 0;
    int height = 0;
    time_t timestamp = 0;
    time_t timestamp_sent = 0;
    time_t timestamp_rcvd = 0;
    time_t sort_timestamp = 0;
};

// =============================================================================
// Chat member (for groups)
// =============================================================================
struct ChatMember {
    int64_t id = 0;
    int64_t chat_id = 0;
    int64_t contact_id = 0;
    time_t timestamp = 0;
    time_t created = 0;
    time_t modified = 0;
};

// =============================================================================
// Contact chat membership
// =============================================================================
struct ChatContacts {
    int64_t id = 0;
    int64_t chat_id = 0;
    int64_t contact_id = 0;
    time_t timestamp = 0;
};

// =============================================================================
// Config keys for set_config/get_config
// =============================================================================
namespace ConfigKey {
    static constexpr const char* ADDR = "addr";
    static constexpr const char* MAIL_SERVER = "mail_server";
    static constexpr const char* MAIL_PORT = "mail_port";
    static constexpr const char* MAIL_USER = "mail_user";
    static constexpr const char* MAIL_PW = "mail_pw";
    static constexpr const char* MAIL_SECURITY = "mail_security";
    static constexpr const char* SEND_SERVER = "send_server";
    static constexpr const char* SEND_PORT = "send_port";
    static constexpr const char* SEND_USER = "send_user";
    static constexpr const char* SEND_PW = "send_pw";
    static constexpr const char* SEND_SECURITY = "send_security";
    static constexpr const char* SERVER_FLAGS = "server_flags";
    static constexpr const char* IMAP_CERTIFICATE_CHECKS = "imap_certificate_checks";
    static constexpr const char* SMTP_CERTIFICATE_CHECKS = "smtp_certificate_checks";
    static constexpr const char* DISPLAY_NAME = "displayname";
    static constexpr const char* SELF_STATUS = "selfstatus";
    static constexpr const char* E2EE_ENABLED = "e2ee_enabled";
    static constexpr const char* MDNS_ENABLED = "mdns_enabled";
    static constexpr const char* SHOW_EMAILS = "show_emails";
    static constexpr const char* SENTBOX_WATCH = "sentbox_watch";
    static constexpr const char* MVBOX_WATCH = "mvbox_watch";
    static constexpr const char* MVBOX_MOVE = "mvbox_move";
    static constexpr const char* ONLY_FETCH_MVBOX = "only_fetch_mvbox";
    static constexpr const char* SAVE_MIME_HEADERS = "save_mime_headers";
    static constexpr const char* CONFIGURED_ADDR = "configured_addr";
    static constexpr const char* CONFIGURED_MAIL_SERVER = "configured_mail_server";
    static constexpr const char* CONFIGURED_MAIL_PORT = "configured_mail_port";
    static constexpr const char* CONFIGURED_MAIL_USER = "configured_mail_user";
    static constexpr const char* CONFIGURED_MAIL_PW = "configured_mail_pw";
    static constexpr const char* CONFIGURED_MAIL_SECURITY = "configured_mail_security";
    static constexpr const char* CONFIGURED_SEND_SERVER = "configured_send_server";
    static constexpr const char* CONFIGURED_SEND_PORT = "configured_send_port";
    static constexpr const char* CONFIGURED_SEND_USER = "configured_send_user";
    static constexpr const char* CONFIGURED_SEND_PW = "configured_send_pw";
    static constexpr const char* CONFIGURED_SEND_SECURITY = "configured_send_security";
    static constexpr const char* CONFIGURED_SERVER_FLAGS = "configured_server_flags";
    static constexpr const char* NOTIFICATIONS_ENABLED = "notifications_enabled";
    static constexpr const char* WATCHED_CHAT_NOTIFICATIONS = "watched_chat_notifications";
    static constexpr const char* CONTACTS_NOTIFICATIONS = "contacts_notifications";
    static constexpr const char* BCC_SELF = "bcc_self";
    static constexpr const char* DOWNLOAD_LIMIT = "download_limit";
    static constexpr const char* MEDIA_QUALITY = "media_quality";
    static constexpr const char* WELCOME_IMAGE = "welcome_image";
    static constexpr const char* COMPRESS_IMAGES = "compress_images";
    static constexpr const char* IMAGE_FORMAT = "image_format";
    static constexpr const char* WATCHED_CHAT_REACTIONS = "watched_chat_reactions";
    static constexpr const char* CHAT_LIST_MAIL = "chat_list_mail";
    static constexpr const char* WEBRTC_INSTANCE = "webrtc_instance";
    static constexpr const char* VERIFY_ONE_ON_ONE_CHATS = "verify_one_on_one_chats";
    static constexpr const char* DELETE_SERVER_AFTER = "delete_server_after";
    static constexpr const char* DELETE_DEVICE_AFTER = "delete_device_after";
    static constexpr const char* SCAN_ALL_FOLDERS_DEBOUNCE_SECS = "scan_all_folders_debounce_secs";
    static constexpr const char* FETCH_EXISTING_MSGS = "fetch_existing_msgs";
    static constexpr const char* KEY_GEN_TYPE = "key_gen_type";
    static constexpr const char* BOT = "bot";
    static constexpr const char* SIGN_UNENCRYPTED = "sign_unencrypted";
    static constexpr const char* ONLY_WEBXDC_ON_FETCH = "only_webxdc_on_fetch";
}

// =============================================================================
// Provider database (auto-configuration)
// =============================================================================
struct ProviderInfo {
    std::string id;                    // "gmail", "outlook", etc.
    std::string status;                // "OK", "PREPARATION", "BROKEN"
    std::string before_login_hint;     // text shown before login
    std::string after_login_hint;      // text shown after login
    std::string overview_page;         // URL for more info

    // Server configuration
    struct Server {
        std::string protocol;          // "IMAP", "POP3"
        std::string socket_type;       // "SSL", "STARTTLS", "PLAIN"
        std::string hostname;
        int port = 0;
        std::string username_pattern;  // "%EMAILADDRESS%", "%EMAILLOCALPART%"
    };

    std::vector<Server> servers;       // try in order
};

// =============================================================================
// MIME Parser types (RFC 2822, RFC 2045-2049)
// =============================================================================
struct MimeHeader {
    std::string name;                  // "From", "To", "Subject", etc.
    std::string value;                 // decoded value
    std::string raw_value;             // raw (possibly encoded) value
};

struct MimePart {
    std::string type;                  // "text/plain", "multipart/mixed", etc.
    std::string subtype;
    std::string charset;              // "utf-8", "iso-8859-1", etc.
    std::string transfer_encoding;    // "7bit", "8bit", "base64", "quoted-printable"
    std::string content_id;
    std::string content_description;
    std::string content_disposition;  // "inline", "attachment"
    std::string filename;             // attachment filename
    int64_t content_length = 0;
    std::string body;                 // decoded body content
    std::vector<uint8_t> raw_body;    // binary body (for attachments)
    std::vector<MimePart> subparts;   // for multipart
    std::vector<MimeHeader> headers;
};

struct ParsedMail {
    std::string rfc724_mid;
    std::string in_reply_to;
    std::vector<std::string> references;
    std::string from;
    std::vector<std::string> to;
    std::vector<std::string> cc;
    std::vector<std::string> bcc;
    std::string subject;
    std::string date_str;
    time_t date = 0;
    std::string chat_version;
    std::string chat_group_id;
    std::string chat_group_name;
    std::string autocrypt_header;
    std::string autocrypt_setup_message;
    std::string securejoin_header;
    bool is_autocrypt_setup_message = false;
    bool is_securejoin_setup_message = false;
    bool is_mdn = false;               // Message Disposition Notification
    bool is_dsn = false;               // Delivery Status Notification
    bool is_read_receipt = false;
    bool is_system_message = false;
    bool is_bot = false;
    bool is_webxdc = false;
    std::string webxdc_blob;
    std::vector<ParsedMail> attached_mails; // MIME messages embedded
    MimePart root_part;
    std::vector<MimePart> attachments;
    bool has_location = false;
    double location_latitude = 0.0;
    double location_longitude = 0.0;
    EphemeralTimer ephemeral_timer = EphemeralTimer::DISABLED;
    int64_t ephemeral_timestamp = 0;
};

// =============================================================================
// Autocrypt header (OpenPGP-based E2E)
// =============================================================================
struct AutocryptHeader {
    std::string addr;                  // sender's email
    std::string prefer_encrypt;        // "mutual" or "nopreference"
    std::string keydata;               // base64-encoded public key
    std::string key_type;              // "openpgp"
    std::string base_encoding;         // "base64"
    bool is_valid = false;
};

// =============================================================================
// SecureJoin (verified group setup)
// =============================================================================
struct SecureJoinMessage {
    enum Type {
        VC_REQUEST,            // vg-request
        VC_REQUEST_WITH_AUTH,  // vg-request-with-auth
        VC_AUTH_REQUIRED,      // vg-auth-required
        VC_CONTACT_CONFIRM,    // vc-contact-confirm
    };
    Type type;
    std::string step;                // "vg-request", etc.
    std::string grpid;               // group ID
    std::string fingerprint;         // sender's key fingerprint
    std::string invitenumber;
    std::string auth;
};

// =============================================================================
// QR code token for verified groups
// =============================================================================
struct QrCodeToken {
    enum TokenType {
        INVITE,     // dcaccount:... (invite to chat)
        VERIFY_GROUP,
        CONTACT,
    };
    TokenType type;
    std::string state;
    std::string invitenumber;
    std::string authcode;
    std::string domain;
    std::string grpid;
    std::string addr;
    std::string fingerprint;
    std::string name;
    std::string text1;
};

// =============================================================================
// IMAP folder state
// =============================================================================
struct ImapFolder {
    std::string name;
    int uid_validity = 0;
    int uid_next = 0;
    int exists = 0;                   // current message count
    int recent = 0;
    int unseen = 0;
    bool selectable = true;
    bool no_select = false;
    std::vector<std::string> flags;
    std::vector<std::string> permanent_flags;
};

struct ImapSearchResult {
    int uid = 0;
    int size = 0;
    std::string flags;
    std::string internal_date;
    std::string rfc724_mid;
    std::string references;
    std::string in_reply_to;
};

// =============================================================================
// SMTP configuration
// =============================================================================
struct SmtpConfig {
    std::string host;
    int port = 0;
    std::string user;
    std::string password;
    int security = 0; // 0=plain, 1=SSL, 2=STARTTLS
    bool certificate_checks = true;
};

struct ImapConfig {
    std::string host;
    int port = 0;
    std::string user;
    std::string password;
    int security = 0;
    bool certificate_checks = true;
};

// =============================================================================
// Event types (callbacks to UI)
// =============================================================================
enum class EventType : int {
    INFO = 100,
    SMTP_CONNECTED = 101,
    IMAP_CONNECTED = 102,
    SMTP_MESSAGE_SENT = 103,
    IMAP_MESSAGE_DELETED = 104,
    IMAP_MESSAGE_MOVED = 105,
    NEW_BLOB_FILE = 150,
    DELETED_BLOB_FILE = 151,
    WARNING = 300,
    ERROR = 400,
    ERROR_SELF_NOT_IN_GROUP = 410,
    MSGS_CHANGED = 2000,
    INCOMING_MSG = 2005,
    MSGS_NOTICED = 2010,
    MSG_DELIVERED = 2012,
    MSG_FAILED = 2014,
    MSG_READ = 2015,
    CHAT_MODIFIED = 2020,
    CHAT_EPHEMERAL_TIMER_MODIFIED = 2021,
    CONTACTS_CHANGED = 2030,
    LOCATION_CHANGED = 2035,
    CONFIGURE_PROGRESS = 2041,
    IMEX_PROGRESS = 2051,
    IMEX_FILE_WRITTEN = 2052,
    SECUREJOIN_INVITER_PROGRESS = 2060,
    SECUREJOIN_JOINER_PROGRESS = 2061,
    CONNECTIVITY_CHANGED = 2100,
    SELFAVATAR_CHANGED = 2110,
    WEBXDC_STATUS_UPDATE = 2120,
    WEBXDC_INSTANCE_DELETED = 2121,
    REACTIONS_CHANGED = 2130,
    CHAT_LIST_CHANGED = 2140,
    ACCOUNTS_BACKGROUND_FETCH_DONE = 2150,
};

struct Event {
    EventType id;
    int64_t data1 = 0;
    int64_t data2 = 0;
    std::string data2_str;
};

// =============================================================================
// IMAP / SMTP connection pool
// =============================================================================
struct SmtpConnection {
    int fd = -1;
    void* ssl = nullptr;       // SSL* opaque pointer
    bool connected = false;
    bool authenticated = false;
    bool starttls = false;
    std::string host;
    int port = 0;
    std::string last_response;
    int last_code = 0;
    time_t last_activity = 0;
    std::string greeting;

    // Capabilities (EHLO)
    std::vector<std::string> capabilities;

    bool has_capability(const std::string& cap) const {
        for (auto& c : capabilities) {
            if (c == cap || c.find(cap) == 0) return true;
        }
        return false;
    }
};

struct ImapConnection {
    int fd = -1;
    void* ssl = nullptr;
    bool connected = false;
    bool authenticated = false;
    bool starttls = false;
    std::string host;
    int port = 0;
    std::string last_response;
    std::string last_tag;
    int last_code = 0;               // OK, NO, BAD
    time_t last_activity = 0;
    std::string greeting;

    // Capabilities
    std::vector<std::string> capabilities;
    bool has_idle = false;
    bool has_condstore = false;
    bool has_qresync = false;
    bool has_move = false;
    bool has_compress = false;
    bool has_utf8 = false;

    // IDLE state
    bool idling = false;

    // Selected mailbox
    std::string selected_folder;
    ImapFolder folder_state;
};

// =============================================================================
// SMTP command helpers
// =============================================================================
namespace SmtpCommands {
    static constexpr const char* EHLO = "EHLO";
    static constexpr const char* HELO = "HELO";
    static constexpr const char* STARTTLS = "STARTTLS";
    static constexpr const char* AUTH_LOGIN = "AUTH LOGIN";
    static constexpr const char* AUTH_PLAIN = "AUTH PLAIN";
    static constexpr const char* MAIL_FROM = "MAIL FROM:";
    static constexpr const char* RCPT_TO = "RCPT TO:";
    static constexpr const char* DATA = "DATA";
    static constexpr const char* RSET = "RSET";
    static constexpr const char* QUIT = "QUIT";
    static constexpr const char* NOOP = "NOOP";

    static constexpr int READY = 220;
    static constexpr int OK = 250;
    static constexpr int AUTH_OK = 235;
    static constexpr int AUTH_CHALLENGE = 334;
    static constexpr int START_MAIL = 354;
    static constexpr int CLOSING = 221;
}

// =============================================================================
// IMAP command helpers
// =============================================================================
namespace ImapCommands {
    static constexpr const char* LOGIN = "LOGIN";
    static constexpr const char* AUTHENTICATE = "AUTHENTICATE";
    static constexpr const char* SELECT = "SELECT";
    static constexpr const char* EXAMINE = "EXAMINE";
    static constexpr const char* CREATE = "CREATE";
    static constexpr const char* DELETE = "DELETE";
    static constexpr const char* RENAME = "RENAME";
    static constexpr const char* SUBSCRIBE = "SUBSCRIBE";
    static constexpr const char* UNSUBSCRIBE = "UNSUBSCRIBE";
    static constexpr const char* LIST = "LIST";
    static constexpr const char* LSUB = "LSUB";
    static constexpr const char* STATUS = "STATUS";
    static constexpr const char* APPEND = "APPEND";
    static constexpr const char* CHECK = "CHECK";
    static constexpr const char* CLOSE = "CLOSE";
    static constexpr const char* EXPUNGE = "EXPUNGE";
    static constexpr const char* SEARCH = "SEARCH";
    static constexpr const char* FETCH = "FETCH";
    static constexpr const char* STORE = "STORE";
    static constexpr const char* COPY = "COPY";
    static constexpr const char* MOVE = "MOVE";
    static constexpr const char* UID = "UID";
    static constexpr const char* CAPABILITY = "CAPABILITY";
    static constexpr const char* NOOP = "NOOP";
    static constexpr const char* IDLE = "IDLE";
    static constexpr const char* STARTTLS = "STARTTLS";
    static constexpr const char* COMPRESS = "COMPRESS";
    static constexpr const char* LOGOUT = "LOGOUT";

    static constexpr int OK = 0;
    static constexpr int NO = 1;
    static constexpr int BAD = 2;
    static constexpr int PREAUTH = 3;
    static constexpr int BYE = 4;
}

// =============================================================================
// MIME generation for outgoing messages
// =============================================================================
struct MimeBuilder {
    MimePart root;
    bool multipart = false;
    std::string boundary;

    MimeBuilder() {
        boundary = generate_boundary();
    }

    void set_header(const std::string& name, const std::string& value) {
        if (name == "From" || name == "To" || name == "Cc" || name == "Bcc") {
            // Headers handled separately
            return;
        }
        MimeHeader hdr;
        hdr.name = name;
        hdr.value = value;
        root.headers.push_back(hdr);
    }

    void set_text(const std::string& text) {
        MimePart text_part;
        text_part.type = "text";
        text_part.subtype = "plain";
        text_part.charset = "utf-8";
        text_part.transfer_encoding = "quoted-printable";
        text_part.body = text;

        if (!multipart) {
            root = text_part;
        } else {
            root.subparts.insert(root.subparts.begin(), text_part);
        }
    }

    void set_html(const std::string& html) {
        MimePart html_part;
        html_part.type = "text";
        html_part.subtype = "html";
        html_part.charset = "utf-8";
        html_part.transfer_encoding = "quoted-printable";
        html_part.body = html;

        if (!multipart) {
            multipart = true;
            MimePart old_root = std::move(root);
            root.type = "multipart";
            root.subtype = "alternative";
            root.subparts.push_back(std::move(old_root));
            root.subparts.push_back(std::move(html_part));
        } else {
            // Find first multipart/alternative and add html there
            for (auto& sp : root.subparts) {
                if (sp.type == "multipart" && sp.subtype == "alternative") {
                    sp.subparts.push_back(std::move(html_part));
                    return;
                }
            }
            root.subparts.push_back(std::move(html_part));
        }
    }

    void attach_file(const std::string& filename, const std::vector<uint8_t>& data,
                     const std::string& mime_type = "application/octet-stream") {
        if (!multipart) {
            multipart = true;
            MimePart text_part = std::move(root);
            root = MimePart{};
            root.type = "multipart";
            root.subtype = "mixed";
            root.subparts.push_back(std::move(text_part));
        }

        MimePart attachment;
        auto slash_pos = mime_type.find('/');
        if (slash_pos != std::string::npos) {
            attachment.type = mime_type.substr(0, slash_pos);
            attachment.subtype = mime_type.substr(slash_pos + 1);
        } else {
            attachment.type = "application";
            attachment.subtype = "octet-stream";
        }
        attachment.transfer_encoding = "base64";
        attachment.filename = basename(filename);
        attachment.content_disposition = "attachment";
        attachment.raw_body = data;
        attachment.content_length = data.size();

        root.subparts.push_back(std::move(attachment));
    }

    std::string build() {
        std::stringstream ss;
        if (multipart) {
            ss << "Content-Type: " << root.type << "/" << root.subtype
               << "; boundary=\"" << boundary << "\"\r\n";
            ss << "MIME-Version: 1.0\r\n";
            for (auto& part : root.subparts) {
                ss << "--" << boundary << "\r\n";
                ss << serialize_part(part);
            }
            ss << "--" << boundary << "--\r\n";
        } else {
            ss << serialize_part(root);
        }
        return ss.str();
    }

    static std::string generate_boundary() {
        static thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist;
        char buf[48];
        snprintf(buf, sizeof(buf), "==Multipart_Boundary_x%016lx", dist(rng));
        return std::string(buf);
    }

    static std::string serialize_part(const MimePart& part) {
        std::stringstream ss;
        ss << "Content-Type: " << part.type << "/" << part.subtype;
        if (!part.charset.empty()) ss << "; charset=" << part.charset;
        if (!part.filename.empty()) ss << "; name=\"" << mime_word_encode(part.filename) << "\"";
        ss << "\r\n";

        if (!part.transfer_encoding.empty()) {
            ss << "Content-Transfer-Encoding: " << part.transfer_encoding << "\r\n";
        }
        if (!part.content_disposition.empty()) {
            ss << "Content-Disposition: " << part.content_disposition;
            if (!part.filename.empty()) ss << "; filename=\"" << mime_word_encode(part.filename) << "\"";
            ss << "\r\n";
        }
        if (part.content_length > 0) {
            ss << "Content-Length: " << part.content_length << "\r\n";
        }
        ss << "\r\n";

        // Encode body based on transfer encoding
        std::string encoded;
        if (part.transfer_encoding == "base64") {
            encoded = base64_encode(part.body.empty()
                                    ? std::string(part.raw_body.begin(), part.raw_body.end())
                                    : part.body);
            write_folded(ss, encoded, 76);
        } else if (part.transfer_encoding == "quoted-printable") {
            encoded = quoted_printable_encode(part.body);
            ss << encoded;
        } else {
            ss << part.body;
        }

        ss << "\r\n";
        return ss.str();
    }

    static void write_folded(std::stringstream& ss, const std::string& data,
                             size_t line_len) {
        for (size_t i = 0; i < data.size(); i += line_len) {
            ss << data.substr(i, line_len) << "\r\n";
        }
    }

    static std::string base64_encode(const std::string& data) {
        static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        result.reserve((data.size() + 2) / 3 * 4);

        for (size_t i = 0; i < data.size(); i += 3) {
            uint32_t n = (uint8_t)data[i] << 16;
            if (i + 1 < data.size()) n |= (uint8_t)data[i + 1] << 8;
            if (i + 2 < data.size()) n |= (uint8_t)data[i + 2];

            result += table[(n >> 18) & 0x3F];
            result += table[(n >> 12) & 0x3F];
            result += (i + 1 < data.size()) ? table[(n >> 6) & 0x3F] : '=';
            result += (i + 2 < data.size()) ? table[n & 0x3F] : '=';
        }
        return result;
    }

    static std::string quoted_printable_encode(const std::string& data) {
        std::string result;
        result.reserve(data.size() * 2);
        int line_len = 0;

        for (char c : data) {
            if ((c >= 33 && c <= 60) || (c >= 62 && c <= 126) || c == ' ' || c == '\t') {
                if (c == ' ' || c == '\t') {
                    // Escape trailing whitespace
                    if (line_len >= 74) {
                        result += "=\r\n";
                        line_len = 0;
                    }
                    result += c;
                    line_len++;
                } else {
                    if (line_len >= 75) {
                        result += "=\r\n";
                        line_len = 0;
                    }
                    result += c;
                    line_len++;
                }
            } else if (c == '\r') {
                // Skip CR
            } else if (c == '\n') {
                result += "\r\n";
                line_len = 0;
            } else {
                if (line_len >= 73) {
                    result += "=\r\n";
                    line_len = 0;
                }
                char buf[4];
                snprintf(buf, sizeof(buf), "=%02X", (uint8_t)c);
                result += buf;
                line_len += 3;
            }
        }
        return result;
    }

    static std::string mime_word_encode(const std::string& text) {
        // RFC 2047 encoded-word: =?charset?encoding?encoded_text?=
        bool needs_encoding = false;
        for (char c : text) {
            if ((uint8_t)c > 127) { needs_encoding = true; break; }
        }
        if (!needs_encoding) return text;

        return "=?UTF-8?B?" + base64_encode(text) + "?=";
    }

    static std::string basename(const std::string& path) {
        auto pos = path.find_last_of("/\\");
        return (pos != std::string::npos) ? path.substr(pos + 1) : path;
    }
};

// =============================================================================
// Reaction (message reactions via email headers)
// =============================================================================
struct Reaction {
    int64_t id = 0;
    int64_t message_id = 0;
    int64_t contact_id = 0;
    std::string reaction; // emoji or custom string
    time_t timestamp = 0;
};

// =============================================================================
// Peerstate (per-contact encryption/verification state)
// =============================================================================
struct Peerstate {
    std::string addr;
    std::string public_key;          // serialized OpenPGP key
    std::string public_key_fingerprint;
    std::string gossip_key;          // last gossiped key
    std::string gossip_timestamp;
    std::string gossip_fingerprint;
    std::string verified_key;
    std::string verified_key_fingerprint;
    int to_id = 0;
    int prefer_encrypt = 0;          // 0=undecided, 1=mutual, 2=nopreference
    time_t timestamp = 0;
    time_t created = 0;
    time_t modified = 0;
    time_t last_seen = 0;
    time_t last_seen_autocrypt = 0;
};

// =============================================================================
// Key / fingerprint generation for OpenPGP
// =============================================================================
struct KeyPair {
    std::string public_key;          // armored PGP public key
    std::string private_key;         // armored PGP private key
    std::string fingerprint;         // key fingerprint (hex)
    KeyGenType key_type = KeyGenType::DEFAULT;
    time_t created_at = 0;
};

// =============================================================================
// Chat list entry (for UI rendering)
// =============================================================================
struct ChatListEntry {
    int64_t chat_id = 0;
    std::string name;
    std::string avatar_path;
    std::string color;
    std::string summary_text;
    int64_t summary_timestamp = 0;
    MsgState summary_state = MsgState::UNDEFINED;
    int summary_type = 0;             // Viewtype of last message
    bool is_protected = false;
    bool is_verified = false;
    bool is_group = false;
    bool is_device_talk = false;
    bool is_self_talk = false;
    bool is_broadcast = false;
    bool is_muted = false;
    int fresh_message_count = 0;
    int unomitted_count = 0;
};

// =============================================================================
// Import/Export (IMEX)
// =============================================================================
enum class ImexMode : int {
    EXPORT_SELF_KEYS = 1,
    IMPORT_SELF_KEYS = 2,
    EXPORT_BACKUP = 11,
    IMPORT_BACKUP = 12,
    EXPORT_ALL = 100,
    IMPORT_ALL = 101,
};

struct ImexProgress {
    ImexMode mode;
    int progress = 0;                 // 0-1000
    std::string path;
    std::string error;
};

// =============================================================================
// WebXDC (web apps in DeltaChat)
// =============================================================================
struct WebxdcMessageInfo {
    int64_t id = 0;
    std::string name;
    std::string icon;
    std::string document;
    std::string summary;
    std::string source_code_url;
    int64_t chat_id = 0;
    int64_t from_id = 0;
    int64_t timestamp = 0;
};

struct WebxdcStatusUpdate {
    int64_t id = 0;
    int64_t instance_id = 0;
    int64_t from_id = 0;
    std::string payload;
    int serial = 0;
    int max_serial = 0;
    time_t timestamp = 0;
};

} // namespace deltachat
} // namespace progressive
