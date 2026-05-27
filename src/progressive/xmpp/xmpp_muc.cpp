/*
 * progressive-server - XMPP Multi-User Chat (XEP-0045) Implementation
 *
 * This file implements a comprehensive XMPP MUC service including:
 *   - Room creation, destruction, and lifecycle management
 *   - Occupant tracking with roles and affiliations
 *   - Presence broadcasting and synchronization
 *   - Room configuration via XEP-0004 data forms
 *   - Ban/member/admin/owner/moderator list management
 *   - Voice requests and moderation actions
 *   - Room history replay on join
 *   - Invitations, password protection, members-only rooms
 *   - Nickname conflict resolution
 *   - DISCO#items for room discovery
 *   - Message reflection and private messages
 *   - Persistent and temporary rooms
 *   - Max user enforcement and logging
 */

#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <memory>
#include <optional>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <mutex>
#include <functional>
#include <chrono>
#include <random>
#include <set>
#include <deque>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <atomic>
#include <cctype>

namespace progressive {
namespace xmpp {

// ============================================================================
// Forward declarations
// ============================================================================

class MUCRoom;
class MUCOccupant;
class MUCHistoryMessage;
class MUCService;

// ============================================================================
// Enumerations and Constants
// ============================================================================

enum class MUCRole {
    NONE        = 0,
    VISITOR     = 1,
    PARTICIPANT = 2,
    MODERATOR   = 3
};

enum class MUCAffiliation {
    NONE           = 0,
    OUTCAST        = 1,
    MEMBER         = 2,
    ADMIN          = 3,
    OWNER          = 4
};

inline const char* muc_role_to_string(MUCRole role) {
    switch (role) {
        case MUCRole::NONE:        return "none";
        case MUCRole::VISITOR:     return "visitor";
        case MUCRole::PARTICIPANT: return "participant";
        case MUCRole::MODERATOR:   return "moderator";
        default: return "none";
    }
}

inline const char* muc_affiliation_to_string(MUCAffiliation aff) {
    switch (aff) {
        case MUCAffiliation::NONE:    return "none";
        case MUCAffiliation::OUTCAST: return "outcast";
        case MUCAffiliation::MEMBER:  return "member";
        case MUCAffiliation::ADMIN:   return "admin";
        case MUCAffiliation::OWNER:   return "owner";
        default: return "none";
    }
}

inline MUCRole muc_role_from_string(const std::string& s) {
    if (s == "visitor")     return MUCRole::VISITOR;
    if (s == "participant") return MUCRole::PARTICIPANT;
    if (s == "moderator")   return MUCRole::MODERATOR;
    return MUCRole::NONE;
}

inline MUCAffiliation muc_affiliation_from_string(const std::string& s) {
    if (s == "outcast") return MUCAffiliation::OUTCAST;
    if (s == "member")  return MUCAffiliation::MEMBER;
    if (s == "admin")   return MUCAffiliation::ADMIN;
    if (s == "owner")   return MUCAffiliation::OWNER;
    return MUCAffiliation::NONE;
}

enum class MUCRoomState {
    CREATING,
    ACTIVE,
    DESTROYING,
    DESTROYED
};

enum class RoomConfigFieldType {
    BOOLEAN,
    STRING,
    LIST_SINGLE,
    LIST_MULTI,
    INTEGER,
    JID_LIST,
    JID_MULTI,
    TEXT_PRIVATE,
    TEXT_SINGLE,
    FIXED
};

struct RoomConfigOption {
    std::string value;
    std::string label;
};

struct RoomConfigField {
    std::string var;
    RoomConfigFieldType type;
    std::string label;
    std::string description;
    std::vector<std::string> values;
    std::vector<RoomConfigOption> options;
    bool required;
    std::string default_value;
};

// ============================================================================
// XMPP Namespaces
// ============================================================================

namespace XMPPNS {
    const char* MUC           = "http://jabber.org/protocol/muc";
    const char* MUC_USER      = "http://jabber.org/protocol/muc#user";
    const char* MUC_ADMIN     = "http://jabber.org/protocol/muc#admin";
    const char* MUC_OWNER     = "http://jabber.org/protocol/muc#owner";
    const char* MUC_UNIQUE    = "http://jabber.org/protocol/muc#unique";
    const char* DISCO_INFO    = "http://jabber.org/protocol/disco#info";
    const char* DISCO_ITEMS   = "http://jabber.org/protocol/disco#items";
    const char* X_DATA        = "jabber:x:data";
    const char* X_DELAY       = "jabber:x:delay";
    const char* DELAY2        = "urn:xmpp:delay";
}

// ============================================================================
// MUCHistoryMessage
// ============================================================================

class MUCHistoryMessage {
public:
    enum class Type {
        GROUPCHAT,
        SUBJECT_CHANGE,
        PRESENCE_JOIN,
        PRESENCE_LEAVE,
        PRESENCE_CHANGE,
        KICK,
        BAN,
        ROLE_CHANGE,
        AFFILIATION_CHANGE,
        ROOM_CREATED,
        ROOM_DESTROYED,
        CONFIG_CHANGE
    };

    MUCHistoryMessage()
        : type_(Type::GROUPCHAT)
        , timestamp_(std::chrono::system_clock::now())
        , id_("")
    {}

    MUCHistoryMessage(Type type, const std::string& from_nick,
                      const std::string& body, const std::string& id)
        : type_(type)
        , from_nick_(from_nick)
        , body_(body)
        , timestamp_(std::chrono::system_clock::now())
        , id_(id)
    {}

    Type type() const { return type_; }
    void set_type(Type t) { type_ = t; }

    const std::string& from_nick() const { return from_nick_; }
    void set_from_nick(const std::string& n) { from_nick_ = n; }

    const std::string& from_jid() const { return from_jid_; }
    void set_from_jid(const std::string& j) { from_jid_ = j; }

    const std::string& body() const { return body_; }
    void set_body(const std::string& b) { body_ = b; }

    const std::string& id() const { return id_; }
    void set_id(const std::string& i) { id_ = i; }

    std::chrono::system_clock::time_point timestamp() const { return timestamp_; }
    void set_timestamp(std::chrono::system_clock::time_point t) { timestamp_ = t; }

    const std::string& reason() const { return reason_; }
    void set_reason(const std::string& r) { reason_ = r; }

    const std::string& actor_nick() const { return actor_nick_; }
    void set_actor_nick(const std::string& a) { actor_nick_ = a; }

    const std::string& target_nick() const { return target_nick_; }
    void set_target_nick(const std::string& t) { target_nick_ = t; }

    std::string to_stamp() const {
        auto t = std::chrono::system_clock::to_time_t(timestamp_);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

private:
    Type type_;
    std::string from_nick_;
    std::string from_jid_;
    std::string body_;
    std::chrono::system_clock::time_point timestamp_;
    std::string id_;
    std::string reason_;
    std::string actor_nick_;
    std::string target_nick_;
};

// ============================================================================
// MUCOccupant
// ============================================================================

class MUCOccupant {
public:
    MUCOccupant(const std::string& nick, const std::string& real_jid,
                MUCRole role, MUCAffiliation affiliation)
        : nick_(nick)
        , real_jid_(real_jid)
        , role_(role)
        , affiliation_(affiliation)
        , joined_at_(std::chrono::system_clock::now())
        , voice_requested_(false)
        , voice_approved_(role == MUCRole::PARTICIPANT || role == MUCRole::MODERATOR)
        , is_away_(false)
        , is_xa_(false)
        , is_dnd_(false)
    {}

    const std::string& nick() const { return nick_; }
    void set_nick(const std::string& n) { nick_ = n; }

    const std::string& real_jid() const { return real_jid_; }
    void set_real_jid(const std::string& j) { real_jid_ = j; }

    MUCRole role() const { return role_; }
    void set_role(MUCRole r) { role_ = r; }

    MUCAffiliation affiliation() const { return affiliation_; }
    void set_affiliation(MUCAffiliation a) { affiliation_ = a; }

    std::chrono::system_clock::time_point joined_at() const { return joined_at_; }

    bool voice_requested() const { return voice_requested_; }
    void set_voice_requested(bool v) { voice_requested_ = v; }

    bool voice_approved() const { return voice_approved_; }
    void set_voice_approved(bool v) { voice_approved_ = v; }

    const std::string& presence_status() const { return presence_status_; }
    void set_presence_status(const std::string& s) { presence_status_ = s; }

    const std::string& presence_show() const { return presence_show_; }
    void set_presence_show(const std::string& s) { presence_show_ = s; }

    int priority() const { return priority_; }
    void set_priority(int p) { priority_ = p; }

    bool is_away() const { return is_away_; }
    void set_is_away(bool a) { is_away_ = a; }

    bool is_xa() const { return is_xa_; }
    void set_is_xa(bool x) { is_xa_ = x; }

    bool is_dnd() const { return is_dnd_; }
    void set_is_dnd(bool d) { is_dnd_ = d; }

    const std::string& avatar_hash() const { return avatar_hash_; }
    void set_avatar_hash(const std::string& h) { avatar_hash_ = h; }

    const std::string& caps_node() const { return caps_node_; }
    void set_caps_node(const std::string& c) { caps_node_ = c; }

    const std::string& caps_ver() const { return caps_ver_; }
    void set_caps_ver(const std::string& v) { caps_ver_ = v; }

    const std::string& caps_hash() const { return caps_hash_; }
    void set_caps_hash(const std::string& h) { caps_hash_ = h; }

    std::string to_xml_presence_item() const {
        std::ostringstream oss;
        oss << "<item nick=\"" << xml_escape(nick_) << "\"";
        oss << " affiliation=\"" << muc_affiliation_to_string(affiliation_) << "\"";
        oss << " role=\"" << muc_role_to_string(role_) << "\"";
        if (!real_jid_.empty()) {
            oss << " jid=\"" << xml_escape(real_jid_) << "\"";
        }
        oss << "/>";
        return oss.str();
    }

    std::string to_xml_admin_item() const {
        std::ostringstream oss;
        oss << "<item affiliation=\"" << muc_affiliation_to_string(affiliation_) << "\"";
        if (!nick_.empty()) {
            oss << " nick=\"" << xml_escape(nick_) << "\"";
        }
        oss << " jid=\"" << xml_escape(real_jid_) << "\"";
        oss << "/>";
        return oss.str();
    }

    bool can_change_subject() const {
        return role_ == MUCRole::MODERATOR || affiliation_ == MUCAffiliation::OWNER ||
               affiliation_ == MUCAffiliation::ADMIN;
    }

    bool can_kick() const {
        return role_ == MUCRole::MODERATOR || affiliation_ == MUCAffiliation::ADMIN ||
               affiliation_ == MUCAffiliation::OWNER;
    }

    bool can_ban() const {
        return affiliation_ == MUCAffiliation::ADMIN || affiliation_ == MUCAffiliation::OWNER;
    }

    bool can_grant_voice() const {
        return role_ == MUCRole::MODERATOR || affiliation_ == MUCAffiliation::ADMIN ||
               affiliation_ == MUCAffiliation::OWNER;
    }

    bool can_revoke_voice() const {
        return role_ == MUCRole::MODERATOR || affiliation_ == MUCAffiliation::ADMIN ||
               affiliation_ == MUCAffiliation::OWNER;
    }

    bool can_grant_moderator() const {
        return affiliation_ == MUCAffiliation::ADMIN || affiliation_ == MUCAffiliation::OWNER;
    }

    bool can_change_affiliation(MUCAffiliation target, MUCAffiliation current) const {
        if (affiliation_ == MUCAffiliation::OWNER) return true;
        if (affiliation_ == MUCAffiliation::ADMIN &&
            current != MUCAffiliation::OWNER &&
            target != MUCAffiliation::OWNER) return true;
        return false;
    }

private:
    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    std::string nick_;
    std::string real_jid_;
    MUCRole role_;
    MUCAffiliation affiliation_;
    std::chrono::system_clock::time_point joined_at_;
    bool voice_requested_;
    bool voice_approved_;
    std::string presence_status_;
    std::string presence_show_;
    int priority_;
    bool is_away_;
    bool is_xa_;
    bool is_dnd_;
    std::string avatar_hash_;
    std::string caps_node_;
    std::string caps_ver_;
    std::string caps_hash_;
};

// ============================================================================
// MUCRoom - Core room class
// ============================================================================

class MUCRoom {
public:
    using OccupantPtr = std::shared_ptr<MUCOccupant>;
    using MessageCallback = std::function<void(const std::string& stanza_xml)>;

    MUCRoom(const std::string& jid, const std::string& name,
            const std::string& creator_jid, const std::string& creator_nick,
            MessageCallback callback)
        : jid_(jid)
        , name_(name)
        , description_("")
        , subject_("")
        , subject_setter_("")
        , subject_timestamp_(std::chrono::system_clock::now())
        , state_(MUCRoomState::CREATING)
        , created_at_(std::chrono::system_clock::now())
        , creator_jid_(creator_jid)
        , is_persistent_(false)
        , is_password_protected_(false)
        , password_("")
        , is_members_only_(false)
        , is_moderated_(false)
        , is_non_anonymous_(false)
        , max_users_(0)
        , allow_invites_(true)
        , allow_pm_(true)
        , allow_voice_requests_(true)
        , allow_subject_change_(false)
        , logging_enabled_(false)
        , max_history_fetch_(100)
        , send_callback_(callback)
        , next_message_id_counter_(0)
        , config_changed_(false)
        , allow_member_invites_(true)
        , whois_mode_("moderators")
    {
        generate_message_id();
    }

    ~MUCRoom() = default;

    // ========================================================================
    // Room identity
    // ========================================================================

    const std::string& jid() const { return jid_; }
    const std::string& name() const { return name_; }
    void set_name(const std::string& n) { name_ = n; }

    const std::string& description() const { return description_; }
    void set_description(const std::string& d) { description_ = d; }

    const std::string& subject() const { return subject_; }
    void set_subject(const std::string& s) { subject_ = s; }

    const std::string& subject_setter() const { return subject_setter_; }
    void set_subject_setter(const std::string& s) { subject_setter_ = s; }

    std::chrono::system_clock::time_point subject_timestamp() const { return subject_timestamp_; }
    void set_subject_timestamp(std::chrono::system_clock::time_point t) { subject_timestamp_ = t; }

    MUCRoomState state() const { return state_; }
    void set_state(MUCRoomState s) { state_ = s; }

    bool is_persistent() const { return is_persistent_; }
    void set_is_persistent(bool p) { is_persistent_ = p; }

    bool is_password_protected() const { return is_password_protected_; }
    void set_is_password_protected(bool p) { is_password_protected_ = p; }

    const std::string& password() const { return password_; }
    void set_password(const std::string& p) { password_ = p; }

    bool is_members_only() const { return is_members_only_; }
    void set_is_members_only(bool m) { is_members_only_ = m; }

    bool is_moderated() const { return is_moderated_; }
    void set_is_moderated(bool m) { is_moderated_ = m; }

    bool is_non_anonymous() const { return is_non_anonymous_; }
    void set_is_non_anonymous(bool na) { is_non_anonymous_ = na; }

    int max_users() const { return max_users_; }
    void set_max_users(int m) { max_users_ = m; }

    bool allow_invites() const { return allow_invites_; }
    void set_allow_invites(bool a) { allow_invites_ = a; }

    bool allow_pm() const { return allow_pm_; }
    void set_allow_pm(bool a) { allow_pm_ = a; }

    bool allow_voice_requests() const { return allow_voice_requests_; }
    void set_allow_voice_requests(bool a) { allow_voice_requests_ = a; }

    bool allow_subject_change() const { return allow_subject_change_; }
    void set_allow_subject_change(bool a) { allow_subject_change_ = a; }

    bool logging_enabled() const { return logging_enabled_; }
    void set_logging_enabled(bool l) { logging_enabled_ = l; }

    int max_history_fetch() const { return max_history_fetch_; }
    void set_max_history_fetch(int m) { max_history_fetch_ = m; }

    bool allow_member_invites() const { return allow_member_invites_; }
    void set_allow_member_invites(bool a) { allow_member_invites_ = a; }

    const std::string& whois_mode() const { return whois_mode_; }
    void set_whois_mode(const std::string& w) { whois_mode_ = w; }

    const std::string& creator_jid() const { return creator_jid_; }

    // ========================================================================
    // Message ID generation
    // ========================================================================

    std::string next_message_id() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::ostringstream oss;
        oss << "muc_" << sanitize_for_id(jid_) << "_" << next_message_id_counter_++;
        return oss.str();
    }

    // ========================================================================
    // Occupant management
    // ========================================================================

    OccupantPtr add_occupant(const std::string& nick, const std::string& real_jid,
                             MUCRole role, MUCAffiliation affiliation) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        auto it = occupants_.find(nick);
        if (it != occupants_.end()) {
            return nullptr;
        }

        auto occ = std::make_shared<MUCOccupant>(nick, real_jid, role, affiliation);
        occupants_[nick] = occ;
        jid_to_nick_[real_jid] = nick;

        add_history_message(MUCHistoryMessage(
            MUCHistoryMessage::Type::PRESENCE_JOIN,
            nick, "", next_message_id()
        ));

        return occ;
    }

    bool remove_occupant(const std::string& nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        auto it = occupants_.find(nick);
        if (it == occupants_.end()) {
            return false;
        }

        const std::string& real_jid = it->second->real_jid();
        jid_to_nick_.erase(real_jid);
        occupants_.erase(it);

        add_history_message(MUCHistoryMessage(
            MUCHistoryMessage::Type::PRESENCE_LEAVE,
            nick, "", next_message_id()
        ));

        return true;
    }

    OccupantPtr get_occupant(const std::string& nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = occupants_.find(nick);
        if (it != occupants_.end()) {
            return it->second;
        }
        return nullptr;
    }

    OccupantPtr get_occupant_by_jid(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = jid_to_nick_.find(real_jid);
        if (it != jid_to_nick_.end()) {
            auto occ_it = occupants_.find(it->second);
            if (occ_it != occupants_.end()) {
                return occ_it->second;
            }
        }
        return nullptr;
    }

    std::string get_nick_by_jid(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = jid_to_nick_.find(real_jid);
        if (it != jid_to_nick_.end()) {
            return it->second;
        }
        return "";
    }

    bool has_occupant_nick(const std::string& nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        return occupants_.find(nick) != occupants_.end();
    }

    size_t occupant_count() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        return occupants_.size();
    }

    std::vector<OccupantPtr> get_all_occupants() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<OccupantPtr> result;
        result.reserve(occupants_.size());
        for (auto& pair : occupants_) {
            result.push_back(pair.second);
        }
        return result;
    }

    std::vector<OccupantPtr> get_occupants_by_role(MUCRole role) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<OccupantPtr> result;
        for (auto& pair : occupants_) {
            if (pair.second->role() == role) {
                result.push_back(pair.second);
            }
        }
        return result;
    }

    std::vector<OccupantPtr> get_occupants_by_affiliation(MUCAffiliation aff) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<OccupantPtr> result;
        for (auto& pair : occupants_) {
            if (pair.second->affiliation() == aff) {
                result.push_back(pair.second);
            }
        }
        return result;
    }

    bool set_occupant_role(const std::string& nick, MUCRole new_role,
                           const std::string& actor_nick, const std::string& reason) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        auto it = occupants_.find(nick);
        if (it == occupants_.end()) {
            return false;
        }

        MUCRole old_role = it->second->role();
        it->second->set_role(new_role);

        auto msg = MUCHistoryMessage(
            MUCHistoryMessage::Type::ROLE_CHANGE,
            nick, "", next_message_id()
        );
        msg.set_actor_nick(actor_nick);
        msg.set_reason(reason);
        msg.set_body(std::string(muc_role_to_string(old_role)) + " -> " +
                     std::string(muc_role_to_string(new_role)));
        add_history_message(msg);

        if (new_role == MUCRole::PARTICIPANT || new_role == MUCRole::MODERATOR) {
            it->second->set_voice_approved(true);
            it->second->set_voice_requested(false);
        }

        return true;
    }

    bool set_occupant_affiliation(const std::string& nick, MUCAffiliation new_aff,
                                  const std::string& actor_nick, const std::string& reason) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        auto it = occupants_.find(nick);
        if (it == occupants_.end()) {
            return false;
        }

        MUCAffiliation old_aff = it->second->affiliation();
        it->second->set_affiliation(new_aff);

        auto msg = MUCHistoryMessage(
            MUCHistoryMessage::Type::AFFILIATION_CHANGE,
            nick, "", next_message_id()
        );
        msg.set_actor_nick(actor_nick);
        msg.set_reason(reason);
        msg.set_body(std::string(muc_affiliation_to_string(old_aff)) + " -> " +
                     std::string(muc_affiliation_to_string(new_aff)));
        add_history_message(msg);

        return true;
    }

    bool update_occupant_nick(const std::string& old_nick, const std::string& new_nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        auto old_it = occupants_.find(old_nick);
        if (old_it == occupants_.end()) {
            return false;
        }
        if (occupants_.find(new_nick) != occupants_.end()) {
            return false;
        }

        auto occ = old_it->second;
        const std::string real_jid = occ->real_jid();
        occ->set_nick(new_nick);

        occupants_.erase(old_it);
        occupants_[new_nick] = occ;
        jid_to_nick_[real_jid] = new_nick;

        return true;
    }

    // ========================================================================
    // Nick conflict resolution
    // ========================================================================

    std::string resolve_nick_conflict(const std::string& desired_nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        if (occupants_.find(desired_nick) == occupants_.end()) {
            return desired_nick;
        }

        for (int suffix = 1; suffix <= 9999; ++suffix) {
            std::ostringstream oss;
            oss << desired_nick << "_" << suffix;
            std::string candidate = oss.str();
            if (occupants_.find(candidate) == occupants_.end()) {
                return candidate;
            }
        }

        std::mt19937 rng(std::chrono::system_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<int> dist(10000, 99999);
        return desired_nick + "_" + std::to_string(dist(rng));
    }

    // ========================================================================
    // Voice request management
    // ========================================================================

    bool request_voice(const std::string& nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = occupants_.find(nick);
        if (it == occupants_.end()) return false;
        it->second->set_voice_requested(true);
        return true;
    }

    std::vector<std::string> get_voice_requests() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<std::string> result;
        for (auto& pair : occupants_) {
            if (pair.second->voice_requested() && !pair.second->voice_approved()) {
                result.push_back(pair.first);
            }
        }
        return result;
    }

    bool approve_voice(const std::string& nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = occupants_.find(nick);
        if (it == occupants_.end()) return false;
        it->second->set_voice_approved(true);
        it->second->set_voice_requested(false);
        it->second->set_role(MUCRole::PARTICIPANT);
        return true;
    }

    // ========================================================================
    // Kick and ban
    // ========================================================================

    bool kick_occupant(const std::string& nick, const std::string& actor_nick,
                       const std::string& reason) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        auto it = occupants_.find(nick);
        if (it == occupants_.end()) return false;

        auto msg = MUCHistoryMessage(
            MUCHistoryMessage::Type::KICK,
            nick, reason, next_message_id()
        );
        msg.set_actor_nick(actor_nick);
        msg.set_reason(reason);
        add_history_message(msg);

        const std::string real_jid = it->second->real_jid();
        jid_to_nick_.erase(real_jid);
        occupants_.erase(it);

        return true;
    }

    bool ban_user(const std::string& real_jid, const std::string& actor_nick,
                  const std::string& reason) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        if (ban_list_.find(real_jid) != ban_list_.end()) {
            return true;
        }

        ban_list_[real_jid] = BanEntry(real_jid, actor_nick, reason,
                                       std::chrono::system_clock::now());

        auto msg = MUCHistoryMessage(
            MUCHistoryMessage::Type::BAN,
            "", reason, next_message_id()
        );
        msg.set_actor_nick(actor_nick);
        msg.set_target_nick(real_jid);
        msg.set_reason(reason);
        add_history_message(msg);

        auto it = jid_to_nick_.find(real_jid);
        if (it != jid_to_nick_.end()) {
            std::string nick = it->second;
            occupants_.erase(nick);
            jid_to_nick_.erase(it);

            auto ban_occ_msg = MUCHistoryMessage(
                MUCHistoryMessage::Type::PRESENCE_LEAVE,
                nick, reason, next_message_id()
            );
            ban_occ_msg.set_actor_nick(actor_nick);
            add_history_message(ban_occ_msg);
        }

        return true;
    }

    bool unban_user(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = ban_list_.find(real_jid);
        if (it == ban_list_.end()) return false;
        ban_list_.erase(it);
        return true;
    }

    bool is_banned(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        return ban_list_.find(real_jid) != ban_list_.end();
    }

    std::vector<std::string> get_ban_list() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<std::string> result;
        for (auto& pair : ban_list_) {
            result.push_back(pair.first);
        }
        return result;
    }

    // ========================================================================
    // Member list management
    // ========================================================================

    bool add_member(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        if (ban_list_.find(real_jid) != ban_list_.end()) {
            return false;
        }

        member_list_[real_jid] = MemberEntry(real_jid,
            std::chrono::system_clock::now());
        return true;
    }

    bool remove_member(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = member_list_.find(real_jid);
        if (it == member_list_.end()) return false;
        member_list_.erase(it);
        return true;
    }

    bool is_member(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        return member_list_.find(real_jid) != member_list_.end();
    }

    std::vector<std::string> get_member_list() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<std::string> result;
        for (auto& pair : member_list_) {
            result.push_back(pair.first);
        }
        return result;
    }

    // ========================================================================
    // Admin list management
    // ========================================================================

    bool add_admin(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        admin_list_[real_jid] = AdminEntry(real_jid,
            std::chrono::system_clock::now());
        return true;
    }

    bool remove_admin(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = admin_list_.find(real_jid);
        if (it == admin_list_.end()) return false;
        admin_list_.erase(it);
        return true;
    }

    bool is_admin(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        return admin_list_.find(real_jid) != admin_list_.end();
    }

    std::vector<std::string> get_admin_list() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<std::string> result;
        for (auto& pair : admin_list_) {
            result.push_back(pair.first);
        }
        return result;
    }

    // ========================================================================
    // Owner list management
    // ========================================================================

    bool add_owner(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        owner_list_[real_jid] = OwnerEntry(real_jid,
            std::chrono::system_clock::now());
        return true;
    }

    bool remove_owner(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = owner_list_.find(real_jid);
        if (it == owner_list_.end()) return false;
        if (owner_list_.size() <= 1) return false;
        owner_list_.erase(it);
        return true;
    }

    bool is_owner(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        return owner_list_.find(real_jid) != owner_list_.end();
    }

    std::vector<std::string> get_owner_list() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<std::string> result;
        for (auto& pair : owner_list_) {
            result.push_back(pair.first);
        }
        return result;
    }

    // ========================================================================
    // Moderator tracking (runtime-only)
    // ========================================================================

    std::vector<std::string> get_moderator_list() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<std::string> result;
        for (auto& pair : occupants_) {
            if (pair.second->role() == MUCRole::MODERATOR) {
                result.push_back(pair.first);
            }
        }
        return result;
    }

    // ========================================================================
    // Room history
    // ========================================================================

    void add_history_message(const MUCHistoryMessage& msg) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        history_.push_back(msg);
        while (history_.size() > static_cast<size_t>(max_history_fetch_ + 500)) {
            history_.pop_front();
        }
    }

    std::vector<MUCHistoryMessage> get_history(int max_count, time_t since) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<MUCHistoryMessage> result;
        auto now = std::chrono::system_clock::now();
        auto since_tp = std::chrono::system_clock::from_time_t(since);

        int count = 0;
        for (auto it = history_.rbegin(); it != history_.rend() && count < max_count; ++it) {
            if (it->timestamp() >= since_tp) {
                result.push_back(*it);
                ++count;
            }
        }
        std::reverse(result.begin(), result.end());
        return result;
    }

    std::vector<MUCHistoryMessage> get_recent_history(int count) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::vector<MUCHistoryMessage> result;
        int actual = std::min(count, static_cast<int>(history_.size()));
        auto start = history_.end();
        std::advance(start, -actual);

        for (auto it = start; it != history_.end(); ++it) {
            result.push_back(*it);
        }
        return result;
    }

    std::vector<MUCHistoryMessage> get_all_history() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        return std::vector<MUCHistoryMessage>(history_.begin(), history_.end());
    }

    void clear_history() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        history_.clear();
    }

    bool has_history() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        return !history_.empty();
    }

    // ========================================================================
    // Invitations
    // ========================================================================

    bool can_invite(const std::string& inviter_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        if (!allow_invites_) return false;

        auto it = jid_to_nick_.find(inviter_jid);
        if (it == jid_to_nick_.end()) return false;

        auto occ_it = occupants_.find(it->second);
        if (occ_it == occupants_.end()) return false;

        MUCAffiliation aff = occ_it->second->affiliation();
        MUCRole role = occ_it->second->role();

        if (aff == MUCAffiliation::OWNER || aff == MUCAffiliation::ADMIN) return true;
        if (is_members_only_ && allow_member_invites_ && aff == MUCAffiliation::MEMBER) return true;
        return false;
    }

    std::string generate_invitation_id() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::mt19937 rng(std::chrono::system_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<uint64_t> dist;
        std::ostringstream oss;
        oss << "inv_" << std::hex << dist(rng) << dist(rng);
        return oss.str();
    }

    // ========================================================================
    // Room destruction
    // ========================================================================

    bool destroy(const std::string& destroyer_nick, const std::string& reason,
                 const std::string& alternate_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        if (state_ == MUCRoomState::DESTROYED || state_ == MUCRoomState::DESTROYING) {
            return false;
        }

        state_ = MUCRoomState::DESTROYING;

        auto msg = MUCHistoryMessage(
            MUCHistoryMessage::Type::ROOM_DESTROYED,
            destroyer_nick, reason, next_message_id()
        );
        msg.set_actor_nick(destroyer_nick);
        msg.set_reason(reason);
        add_history_message(msg);

        destroy_reason_ = reason;
        destroy_alternate_jid_ = alternate_jid;
        destroyer_nick_ = destroyer_nick;

        state_ = MUCRoomState::DESTROYED;
        return true;
    }

    bool is_destroyed() const { return state_ == MUCRoomState::DESTROYED; }
    const std::string& destroy_reason() const { return destroy_reason_; }
    const std::string& destroy_alternate_jid() const { return destroy_alternate_jid_; }
    const std::string& destroyer_nick() const { return destroyer_nick_; }

    // ========================================================================
    // Room config validation
    // ========================================================================

    bool is_full() {
        if (max_users_ <= 0) return false;
        return occupant_count() >= static_cast<size_t>(max_users_);
    }

    bool can_join(const std::string& real_jid, const std::string& password_attempt) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        if (state_ != MUCRoomState::ACTIVE && state_ != MUCRoomState::CREATING) {
            return false;
        }

        if (is_banned(real_jid)) {
            return false;
        }

        if (is_password_protected_ && !password_.empty() && password_attempt != password_) {
            return false;
        }

        if (is_members_only_ && !is_member(real_jid) && !is_admin(real_jid) &&
            !is_owner(real_jid)) {
            return false;
        }

        if (is_full()) {
            return false;
        }

        auto jit = jid_to_nick_.find(real_jid);
        if (jit != jid_to_nick_.end()) {
            return false;
        }

        return true;
    }

    // ========================================================================
    // DISCO#items generation
    // ========================================================================

    std::string generate_disco_items() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_ITEMS << "\">";
        for (auto& pair : occupants_) {
            oss << "<item jid=\"" << xml_escape(jid_ + "/" + pair.first) << "\"";
            oss << " name=\"" << xml_escape(pair.first) << "\"/>";
        }
        oss << "</query>";
        return oss.str();
    }

    std::string generate_disco_info() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_INFO << "\">";

        oss << "<identity category=\"conference\" type=\"text\" name=\""
            << xml_escape(name_) << "\"/>";

        oss << "<feature var=\"" << XMPPNS::MUC << "\"/>";
        oss << "<feature var=\"" << XMPPNS::MUC_USER << "\"/>";
        oss << "<feature var=\"" << XMPPNS::MUC_ADMIN << "\"/>";
        oss << "<feature var=\"" << XMPPNS::MUC_OWNER << "\"/>";
        oss << "<feature var=\"" << XMPPNS::MUC_UNIQUE << "\"/>";

        if (is_password_protected_) {
            oss << "<feature var=\"muc_passwordprotected\"/>";
        }
        if (!is_non_anonymous_) {
            oss << "<feature var=\"muc_semianonymous\"/>";
        }
        if (is_members_only_) {
            oss << "<feature var=\"muc_membersonly\"/>";
        }
        if (is_moderated_) {
            oss << "<feature var=\"muc_moderated\"/>";
        }
        if (is_persistent_) {
            oss << "<feature var=\"muc_persistent\"/>";
        } else {
            oss << "<feature var=\"muc_temporary\"/>";
        }
        if (!is_non_anonymous_) {
            oss << "<feature var=\"muc_nonanonymous\"/>";
        }
        if (allow_invites_) {
            oss << "<feature var=\"muc_open\"/>";
        }

        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Configuration form generation (XEP-0004)
    // ========================================================================

    std::vector<RoomConfigField> get_config_form_fields() {
        std::vector<RoomConfigField> fields;

        {
            RoomConfigField f;
            f.var = "FORM_TYPE";
            f.type = RoomConfigFieldType::FIXED;
            f.label = "Room Configuration";
            f.values.push_back("http://jabber.org/protocol/muc#roomconfig");
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_roomname";
            f.type = RoomConfigFieldType::TEXT_SINGLE;
            f.label = "Room Name";
            f.values.push_back(name_);
            f.required = true;
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_roomdesc";
            f.type = RoomConfigFieldType::TEXT_SINGLE;
            f.label = "Room Description";
            f.values.push_back(description_);
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_persistentroom";
            f.type = RoomConfigFieldType::BOOLEAN;
            f.label = "Make Room Persistent";
            f.values.push_back(is_persistent_ ? "1" : "0");
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_publicroom";
            f.type = RoomConfigFieldType::BOOLEAN;
            f.label = "Make Room Publicly Searchable";
            f.values.push_back("1");
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_passwordprotectedroom";
            f.type = RoomConfigFieldType::BOOLEAN;
            f.label = "Password Required";
            f.values.push_back(is_password_protected_ ? "1" : "0");
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_roomsecret";
            f.type = RoomConfigFieldType::TEXT_PRIVATE;
            f.label = "Password";
            f.values.push_back(password_);
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_maxusers";
            f.type = RoomConfigFieldType::LIST_SINGLE;
            f.label = "Maximum Room Occupants";
            f.values.push_back(max_users_ > 0 ? std::to_string(max_users_) : "0");
            f.options.push_back({"0", "No limit"});
            f.options.push_back({"10", "10"});
            f.options.push_back({"20", "20"});
            f.options.push_back({"50", "50"});
            f.options.push_back({"100", "100"});
            f.options.push_back({"200", "200"});
            f.options.push_back({"500", "500"});
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_membersonly";
            f.type = RoomConfigFieldType::BOOLEAN;
            f.label = "Make Room Members-Only";
            f.values.push_back(is_members_only_ ? "1" : "0");
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_moderatedroom";
            f.type = RoomConfigFieldType::BOOLEAN;
            f.label = "Make Room Moderated";
            f.values.push_back(is_moderated_ ? "1" : "0");
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_whois";
            f.type = RoomConfigFieldType::LIST_SINGLE;
            f.label = "Who May Discover Real JIDs?";
            f.values.push_back(whois_mode_);
            f.options.push_back({"moderators", "Moderators Only"});
            f.options.push_back({"anyone", "Anyone"});
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_allowinvites";
            f.type = RoomConfigFieldType::BOOLEAN;
            f.label = "Allow Invitations";
            f.values.push_back(allow_invites_ ? "1" : "0");
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_allowpm";
            f.type = RoomConfigFieldType::LIST_SINGLE;
            f.label = "Allow Private Messages";
            f.values.push_back(allow_pm_ ? "anyone" : "none");
            f.options.push_back({"anyone", "Anyone"});
            f.options.push_back({"participants", "Participants"});
            f.options.push_back({"moderators", "Moderators"});
            f.options.push_back({"none", "None"});
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_changesubject";
            f.type = RoomConfigFieldType::BOOLEAN;
            f.label = "Allow Occupants to Change Subject";
            f.values.push_back(allow_subject_change_ ? "1" : "0");
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_enablelogging";
            f.type = RoomConfigFieldType::BOOLEAN;
            f.label = "Enable Logging";
            f.values.push_back(logging_enabled_ ? "1" : "0");
            fields.push_back(f);
        }
        {
            RoomConfigField f;
            f.var = "muc#roomconfig_allow_voice_requests";
            f.type = RoomConfigFieldType::BOOLEAN;
            f.label = "Allow Voice Requests";
            f.values.push_back(allow_voice_requests_ ? "1" : "0");
            fields.push_back(f);
        }

        return fields;
    }

    std::string generate_config_form() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto fields = get_config_form_fields();

        std::ostringstream oss;
        oss << "<x xmlns=\"" << XMPPNS::X_DATA << "\" type=\"form\">";
        oss << "<title>Room Configuration</title>";
        oss << "<instructions>Configure the room settings.</instructions>";

        for (auto& f : fields) {
            oss << "<field var=\"" << xml_escape(f.var) << "\"";
            switch (f.type) {
                case RoomConfigFieldType::BOOLEAN:
                    oss << " type=\"boolean\"";
                    break;
                case RoomConfigFieldType::STRING:
                    oss << " type=\"text-single\"";
                    break;
                case RoomConfigFieldType::LIST_SINGLE:
                    oss << " type=\"list-single\"";
                    break;
                case RoomConfigFieldType::LIST_MULTI:
                    oss << " type=\"list-multi\"";
                    break;
                case RoomConfigFieldType::INTEGER:
                    oss << " type=\"text-single\"";
                    break;
                case RoomConfigFieldType::JID_LIST:
                    oss << " type=\"jid-multi\"";
                    break;
                case RoomConfigFieldType::JID_MULTI:
                    oss << " type=\"jid-multi\"";
                    break;
                case RoomConfigFieldType::TEXT_PRIVATE:
                    oss << " type=\"text-private\"";
                    break;
                case RoomConfigFieldType::TEXT_SINGLE:
                    oss << " type=\"text-single\"";
                    break;
                case RoomConfigFieldType::FIXED:
                    oss << " type=\"fixed\"";
                    break;
            }
            if (f.required) {
                oss << "><required/>";
            }
            oss << " label=\"" << xml_escape(f.label) << "\">";

            if (!f.options.empty()) {
                for (auto& opt : f.options) {
                    oss << "<option label=\"" << xml_escape(opt.label) << "\">";
                    oss << "<value>" << xml_escape(opt.value) << "</value>";
                    oss << "</option>";
                }
            }

            if (f.type != RoomConfigFieldType::FIXED) {
                for (auto& val : f.values) {
                    oss << "<value>" << xml_escape(val) << "</value>";
                }
            }

            oss << "</field>";
        }

        oss << "</x>";
        return oss.str();
    }

    bool apply_config_form(const std::map<std::string, std::vector<std::string>>& values) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        for (auto& pair : values) {
            const std::string& var = pair.first;
            const std::vector<std::string>& vals = pair.second;

            if (vals.empty()) continue;

            if (var == "muc#roomconfig_roomname") {
                name_ = vals[0];
            } else if (var == "muc#roomconfig_roomdesc") {
                description_ = vals[0];
            } else if (var == "muc#roomconfig_persistentroom") {
                is_persistent_ = (vals[0] == "1" || vals[0] == "true");
            } else if (var == "muc#roomconfig_passwordprotectedroom") {
                is_password_protected_ = (vals[0] == "1" || vals[0] == "true");
            } else if (var == "muc#roomconfig_roomsecret") {
                password_ = vals[0];
                if (!password_.empty()) {
                    is_password_protected_ = true;
                }
            } else if (var == "muc#roomconfig_maxusers") {
                max_users_ = std::stoi(vals[0]);
            } else if (var == "muc#roomconfig_membersonly") {
                is_members_only_ = (vals[0] == "1" || vals[0] == "true");
            } else if (var == "muc#roomconfig_moderatedroom") {
                is_moderated_ = (vals[0] == "1" || vals[0] == "true");
            } else if (var == "muc#roomconfig_whois") {
                whois_mode_ = vals[0];
            } else if (var == "muc#roomconfig_allowinvites") {
                allow_invites_ = (vals[0] == "1" || vals[0] == "true");
            } else if (var == "muc#roomconfig_allowpm") {
                if (vals[0] == "none") {
                    allow_pm_ = false;
                } else {
                    allow_pm_ = true;
                }
            } else if (var == "muc#roomconfig_changesubject") {
                allow_subject_change_ = (vals[0] == "1" || vals[0] == "true");
            } else if (var == "muc#roomconfig_enablelogging") {
                logging_enabled_ = (vals[0] == "1" || vals[0] == "true");
            } else if (var == "muc#roomconfig_allow_voice_requests") {
                allow_voice_requests_ = (vals[0] == "1" || vals[0] == "true");
            }
        }

        config_changed_ = true;

        auto msg = MUCHistoryMessage(
            MUCHistoryMessage::Type::CONFIG_CHANGE,
            "", "Room configuration updated", next_message_id()
        );
        add_history_message(msg);

        return true;
    }

    bool has_config_changed() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        bool changed = config_changed_;
        config_changed_ = false;
        return changed;
    }

    // ========================================================================
    // Access control helpers
    // ========================================================================

    bool can_user_see_real_jid(const std::string& requesting_nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);

        if (whois_mode_ == "anyone") return true;
        if (whois_mode_ == "moderators") {
            auto it = occupants_.find(requesting_nick);
            if (it != occupants_.end()) {
                return it->second->role() == MUCRole::MODERATOR;
            }
        }
        return false;
    }

    bool can_send_message(const std::string& nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = occupants_.find(nick);
        if (it == occupants_.end()) return false;

        if (!is_moderated_) return true;
        MUCRole role = it->second->role();
        return role == MUCRole::PARTICIPANT || role == MUCRole::MODERATOR;
    }

    MUCRole default_role_for_affiliation(MUCAffiliation aff) {
        switch (aff) {
            case MUCAffiliation::OWNER:
            case MUCAffiliation::ADMIN:
                return MUCRole::MODERATOR;
            case MUCAffiliation::MEMBER:
                return is_moderated_ ? MUCRole::VISITOR : MUCRole::PARTICIPANT;
            default:
                return is_moderated_ ? MUCRole::VISITOR : MUCRole::PARTICIPANT;
        }
    }

    // ========================================================================
    // Serialization helpers
    // ========================================================================

    std::string serialize_state() {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::ostringstream oss;
        oss << "room:" << jid_ << "\n";
        oss << "name:" << name_ << "\n";
        oss << "desc:" << description_ << "\n";
        oss << "subject:" << subject_ << "\n";
        oss << "persistent:" << (is_persistent_ ? "1" : "0") << "\n";
        oss << "password:" << (is_password_protected_ ? "1" : "0") << "\n";
        oss << "members_only:" << (is_members_only_ ? "1" : "0") << "\n";
        oss << "moderated:" << (is_moderated_ ? "1" : "0") << "\n";
        oss << "non_anonymous:" << (is_non_anonymous_ ? "1" : "0") << "\n";
        oss << "max_users:" << max_users_ << "\n";
        oss << "logging:" << (logging_enabled_ ? "1" : "0") << "\n";
        return oss.str();
    }

    // ========================================================================
    // XML helpers for presence generation
    // ========================================================================

    std::string generate_self_presence(const std::string& nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = occupants_.find(nick);
        if (it == occupants_.end()) return "";

        auto& occ = it->second;
        std::ostringstream oss;

        oss << "<presence from=\"" << xml_escape(jid_ + "/" + nick) << "\"";
        oss << " to=\"" << xml_escape(occ->real_jid()) << "\">";

        oss << "<x xmlns=\"" << XMPPNS::MUC_USER << "\">";
        oss << "<item affiliation=\"" << muc_affiliation_to_string(occ->affiliation())
            << "\" role=\"" << muc_role_to_string(occ->role()) << "\"/>";
        oss << "<status code=\"110\"/>";

        if (state_ == MUCRoomState::CREATING) {
            oss << "<status code=\"201\"/>";
        }

        if (!is_non_anonymous_ && !occ->real_jid().empty()) {
            oss << "<status code=\"100\"/>";
        }

        oss << "</x>";

        if (!history_.empty()) {
            auto recent = get_recent_history(max_history_fetch_);
            oss << "<x xmlns=\"" << XMPPNS::X_DELAY << "\" stamp=\""
                << recent.front().to_stamp() << "\"/>";
        }

        oss << "</presence>";
        return oss.str();
    }

    std::string generate_occupant_presence(const std::string& nick,
                                           const std::string& to_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        auto it = occupants_.find(nick);
        if (it == occupants_.end()) return "";

        auto& occ = it->second;
        std::ostringstream oss;

        oss << "<presence from=\"" << xml_escape(jid_ + "/" + nick) << "\"";
        if (!to_jid.empty()) {
            oss << " to=\"" << xml_escape(to_jid) << "\"";
        }
        oss << ">";

        oss << "<x xmlns=\"" << XMPPNS::MUC_USER << "\">";
        oss << "<item affiliation=\"" << muc_affiliation_to_string(occ->affiliation())
            << "\" role=\"" << muc_role_to_string(occ->role()) << "\"";

        if (!occ->real_jid().empty() && can_user_see_real_jid(nick)) {
            oss << " jid=\"" << xml_escape(occ->real_jid()) << "\"";
        }

        oss << "/></x>";

        if (!occ->presence_show().empty()) {
            oss << "<show>" << xml_escape(occ->presence_show()) << "</show>";
        }
        if (!occ->presence_status().empty()) {
            oss << "<status>" << xml_escape(occ->presence_status()) << "</status>";
        }

        oss << "</presence>";
        return oss.str();
    }

    std::string generate_unavailable_presence(const std::string& nick,
                                              const std::string& to_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::ostringstream oss;

        oss << "<presence from=\"" << xml_escape(jid_ + "/" + nick) << "\"";
        oss << " type=\"unavailable\"";
        if (!to_jid.empty()) {
            oss << " to=\"" << xml_escape(to_jid) << "\"";
        }
        oss << ">";

        oss << "<x xmlns=\"" << XMPPNS::MUC_USER << "\">";
        oss << "<item affiliation=\"none\" role=\"none\"/>";

        if (state_ == MUCRoomState::DESTROYED) {
            oss << "<destroy";
            if (!destroy_alternate_jid_.empty()) {
                oss << " jid=\"" << xml_escape(destroy_alternate_jid_) << "\"";
            }
            oss << ">";
            if (!destroy_reason_.empty()) {
                oss << "<reason>" << xml_escape(destroy_reason_) << "</reason>";
            }
            oss << "</destroy>";
        }

        oss << "</x></presence>";
        return oss.str();
    }

    std::string generate_kick_presence(const std::string& nick,
                                       const std::string& to_jid,
                                       const std::string& actor_nick,
                                       const std::string& reason) {
        std::ostringstream oss;
        oss << "<presence from=\"" << xml_escape(jid_ + "/" + nick) << "\"";
        oss << " type=\"unavailable\"";
        if (!to_jid.empty()) {
            oss << " to=\"" << xml_escape(to_jid) << "\"";
        }
        oss << ">";

        oss << "<x xmlns=\"" << XMPPNS::MUC_USER << "\">";
        oss << "<item affiliation=\"none\" role=\"none\">";
        oss << "<actor nick=\"" << xml_escape(actor_nick) << "\"/>";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</item>";
        oss << "<status code=\"307\"/>";
        oss << "</x></presence>";
        return oss.str();
    }

    std::string generate_ban_presence(const std::string& nick,
                                      const std::string& to_jid,
                                      const std::string& actor_nick,
                                      const std::string& reason) {
        std::ostringstream oss;
        oss << "<presence from=\"" << xml_escape(jid_ + "/" + nick) << "\"";
        oss << " type=\"unavailable\"";
        if (!to_jid.empty()) {
            oss << " to=\"" << xml_escape(to_jid) << "\"";
        }
        oss << ">";

        oss << "<x xmlns=\"" << XMPPNS::MUC_USER << "\">";
        oss << "<item affiliation=\"outcast\" role=\"none\">";
        oss << "<actor nick=\"" << xml_escape(actor_nick) << "\"/>";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</item>";
        oss << "<status code=\"301\"/>";
        oss << "</x></presence>";
        return oss.str();
    }

    std::string generate_nick_change_presence(const std::string& old_nick,
                                              const std::string& new_nick,
                                              const std::string& to_jid) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::ostringstream oss;

        oss << "<presence from=\"" << xml_escape(jid_ + "/" + old_nick) << "\"";
        oss << " type=\"unavailable\"";
        if (!to_jid.empty()) {
            oss << " to=\"" << xml_escape(to_jid) << "\"";
        }
        oss << ">";

        oss << "<x xmlns=\"" << XMPPNS::MUC_USER << "\">";
        oss << "<item affiliation=\"none\" role=\"none\"/>";
        oss << "<status code=\"303\"/>";
        oss << "</x></presence>";
        return oss.str();
    }

    std::string generate_invitation(const std::string& invitee_jid,
                                    const std::string& inviter_jid,
                                    const std::string& reason) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(jid_) << "\"";
        oss << " to=\"" << xml_escape(invitee_jid) << "\">";

        oss << "<x xmlns=\"" << XMPPNS::MUC_USER << "\">";
        oss << "<invite from=\"" << xml_escape(inviter_jid) << "\">";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</invite>";

        if (is_password_protected_ && !password_.empty()) {
            oss << "<password>" << xml_escape(password_) << "</password>";
        }

        oss << "</x>";

        if (!description_.empty()) {
            oss << "<body>" << xml_escape(description_) << "</body>";
        } else {
            oss << "<body>You have been invited to room " << xml_escape(jid_)
                << "</body>";
        }

        oss << "</message>";
        return oss.str();
    }

    std::string generate_decline_message(const std::string& invitee_jid,
                                         const std::string& reason) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(invitee_jid) << "\"";
        oss << " to=\"" << xml_escape(jid_) << "\">";

        oss << "<x xmlns=\"" << XMPPNS::MUC_USER << "\">";
        oss << "<decline from=\"" << xml_escape(invitee_jid) << "\">";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</decline>";
        oss << "</x></message>";
        return oss.str();
    }

    std::string generate_message_broadcast(const std::string& from_nick,
                                           const std::string& body,
                                           const std::string& msg_id) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(jid_ + "/" + from_nick) << "\"";
        oss << " type=\"groupchat\"";
        oss << " id=\"" << xml_escape(msg_id) << "\">";
        oss << "<body>" << xml_escape(body) << "</body>";
        oss << "</message>";
        return oss.str();
    }

    std::string generate_subject_message(const std::string& from_nick) {
        std::lock_guard<std::mutex> lock(room_mutex_);
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(jid_) << "\"";
        oss << " type=\"groupchat\"";
        oss << " id=\"" << xml_escape(next_message_id()) << "\">";
        oss << "<subject>" << xml_escape(subject_) << "</subject>";
        oss << "</message>";
        return oss.str();
    }

    std::string generate_error(const std::string& to_jid,
                               const std::string& error_type,
                               const std::string& error_condition) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(jid_) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\"";
        oss << " type=\"error\"";
        oss << " id=\"" << xml_escape(next_message_id()) << "\">";
        oss << "<error type=\"" << xml_escape(error_type) << "\">";
        oss << "<" << xml_escape(error_condition)
            << " xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>";
        oss << "</error></message>";
        return oss.str();
    }

private:
    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    static std::string sanitize_for_id(const std::string& s) {
        std::string out;
        for (char c : s) {
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-') {
                out += c;
            } else {
                out += '_';
            }
        }
        return out;
    }

    void generate_message_id() {
        std::ostringstream oss;
        static std::atomic<uint64_t> global_counter{0};
        oss << "msg_" << sanitize_for_id(jid_) << "_" << (++global_counter);
        last_message_id_ = oss.str();
    }

    struct BanEntry {
        std::string jid;
        std::string banned_by;
        std::string reason;
        std::chrono::system_clock::time_point banned_at;

        BanEntry(const std::string& j, const std::string& by,
                 const std::string& r, std::chrono::system_clock::time_point t)
            : jid(j), banned_by(by), reason(r), banned_at(t) {}
    };

    struct MemberEntry {
        std::string jid;
        std::chrono::system_clock::time_point added_at;

        MemberEntry(const std::string& j, std::chrono::system_clock::time_point t)
            : jid(j), added_at(t) {}
    };

    struct AdminEntry {
        std::string jid;
        std::chrono::system_clock::time_point added_at;

        AdminEntry(const std::string& j, std::chrono::system_clock::time_point t)
            : jid(j), added_at(t) {}
    };

    struct OwnerEntry {
        std::string jid;
        std::chrono::system_clock::time_point added_at;

        OwnerEntry(const std::string& j, std::chrono::system_clock::time_point t)
            : jid(j), added_at(t) {}
    };

    std::string jid_;
    std::string name_;
    std::string description_;
    std::string subject_;
    std::string subject_setter_;
    std::chrono::system_clock::time_point subject_timestamp_;
    MUCRoomState state_;
    std::chrono::system_clock::time_point created_at_;
    std::string creator_jid_;

    bool is_persistent_;
    bool is_password_protected_;
    std::string password_;
    bool is_members_only_;
    bool is_moderated_;
    bool is_non_anonymous_;
    int max_users_;
    bool allow_invites_;
    bool allow_pm_;
    bool allow_voice_requests_;
    bool allow_subject_change_;
    bool logging_enabled_;
    int max_history_fetch_;
    bool allow_member_invites_;
    std::string whois_mode_;

    std::string destroy_reason_;
    std::string destroy_alternate_jid_;
    std::string destroyer_nick_;

    std::unordered_map<std::string, OccupantPtr> occupants_;
    std::unordered_map<std::string, std::string> jid_to_nick_;

    std::unordered_map<std::string, BanEntry> ban_list_;
    std::unordered_map<std::string, MemberEntry> member_list_;
    std::unordered_map<std::string, AdminEntry> admin_list_;
    std::unordered_map<std::string, OwnerEntry> owner_list_;

    std::deque<MUCHistoryMessage> history_;
    uint64_t next_message_id_counter_;
    std::string last_message_id_;
    bool config_changed_;

    MessageCallback send_callback_;
    mutable std::mutex room_mutex_;
};

// ============================================================================
// MUCService - Main MUC service class
// ============================================================================

class MUCService {
public:
    using RoomPtr = std::shared_ptr<MUCRoom>;
    using MessageCallback = std::function<void(const std::string& stanza_xml)>;
    using Logger = std::function<void(const std::string& level, const std::string& message)>;

    MUCService(const std::string& service_jid,
               MessageCallback send_callback)
        : service_jid_(service_jid)
        , send_callback_(send_callback)
        , next_room_id_(0)
        , service_enabled_(true)
        , max_total_rooms_(0)
        , max_rooms_per_user_(0)
        , default_max_history_(100)
        , logging_enabled_(true)
    {
        log_info("MUCService initialized for: " + service_jid_);
    }

    ~MUCService() {
        shutdown();
    }

    // ========================================================================
    // Service lifecycle
    // ========================================================================

    void shutdown() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        service_enabled_ = false;

        for (auto& pair : rooms_) {
            if (pair.second->state() == MUCRoomState::ACTIVE) {
                pair.second->set_state(MUCRoomState::DESTROYING);
                evict_all_occupants(pair.second);
                pair.second->set_state(MUCRoomState::DESTROYED);
            }
        }

        rooms_.clear();
        log_info("MUCService shut down");
    }

    bool is_enabled() const { return service_enabled_; }
    void set_enabled(bool e) { service_enabled_ = e; }

    // ========================================================================
    // Logging
    // ========================================================================

    void set_logger(Logger logger) { logger_ = logger; }

    void log_info(const std::string& msg) {
        if (logging_enabled_ && logger_) {
            logger_("INFO", msg);
        }
    }

    void log_warn(const std::string& msg) {
        if (logging_enabled_ && logger_) {
            logger_("WARN", msg);
        }
    }

    void log_error(const std::string& msg) {
        if (logging_enabled_ && logger_) {
            logger_("ERROR", msg);
        }
    }

    // ========================================================================
    // Room creation
    // ========================================================================

    RoomPtr create_room(const std::string& room_jid,
                        const std::string& room_name,
                        const std::string& creator_jid,
                        const std::string& creator_nick,
                        bool persistent = false) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        if (!service_enabled_) {
            log_error("Cannot create room: service disabled");
            return nullptr;
        }

        if (rooms_.find(room_jid) != rooms_.end()) {
            log_warn("Room already exists: " + room_jid);
            return nullptr;
        }

        if (max_total_rooms_ > 0 && rooms_.size() >= static_cast<size_t>(max_total_rooms_)) {
            log_error("Cannot create room: max total rooms (" +
                      std::to_string(max_total_rooms_) + ") reached");
            return nullptr;
        }

        if (max_rooms_per_user_ > 0) {
            int user_rooms = count_user_rooms(creator_jid);
            if (user_rooms >= max_rooms_per_user_) {
                log_error("Cannot create room: user max rooms (" +
                          std::to_string(max_rooms_per_user_) + ") reached");
                return nullptr;
            }
        }

        auto room = std::make_shared<MUCRoom>(
            room_jid, room_name, creator_jid, creator_nick,
            send_callback_
        );

        room->set_state(MUCRoomState::CREATING);
        room->set_is_persistent(persistent);
        room->set_max_history_fetch(default_max_history_);

        if (persistent) {
            room->add_owner(creator_jid);
        }

        room->add_history_message(MUCHistoryMessage(
            MUCHistoryMessage::Type::ROOM_CREATED,
            creator_nick, "Room created", next_message_id()
        ));

        rooms_[room_jid] = room;
        log_info("Room created: " + room_jid + " by " + creator_jid);
        return room;
    }

    RoomPtr create_room_with_config(const std::string& room_jid,
                                    const std::string& room_name,
                                    const std::string& creator_jid,
                                    const std::string& creator_nick,
                                    const std::map<std::string, std::vector<std::string>>& config,
                                    bool persistent = false) {
        auto room = create_room(room_jid, room_name, creator_jid, creator_nick, persistent);
        if (!room) return nullptr;

        room->apply_config_form(config);
        return room;
    }

    // ========================================================================
    // Room destruction
    // ========================================================================

    bool destroy_room(const std::string& room_jid,
                      const std::string& destroyer_jid,
                      const std::string& reason,
                      const std::string& alternate_jid = "") {
        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            log_error("Cannot destroy: room not found: " + room_jid);
            return false;
        }

        auto occ = room->get_occupant_by_jid(destroyer_jid);
        std::string destroyer_nick = occ ? occ->nick() : destroyer_jid;

        if (!occ || !occ->can_ban()) {
            log_warn("Destroy denied: insufficient privileges for " + destroyer_jid);
            return false;
        }

        room->destroy(destroyer_nick, reason, alternate_jid);
        evict_all_occupants(room);
        log_info("Room destroyed: " + room_jid);

        if (!room->is_persistent()) {
            rooms_.erase(room_jid);
        }

        return true;
    }

    // ========================================================================
    // Room lookup
    // ========================================================================

    RoomPtr get_room(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto it = rooms_.find(room_jid);
        if (it != rooms_.end()) {
            return it->second;
        }
        return nullptr;
    }

    bool room_exists(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        return rooms_.find(room_jid) != rooms_.end();
    }

    std::vector<RoomPtr> get_all_rooms() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::vector<RoomPtr> result;
        for (auto& pair : rooms_) {
            result.push_back(pair.second);
        }
        return result;
    }

    std::vector<RoomPtr> get_rooms_for_user(const std::string& real_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::vector<RoomPtr> result;
        for (auto& pair : rooms_) {
            auto occ = pair.second->get_occupant_by_jid(real_jid);
            if (occ) {
                result.push_back(pair.second);
            }
        }
        return result;
    }

    // ========================================================================
    // Handle: Join room
    // ========================================================================

    struct JoinResult {
        bool success;
        std::string error_type;
        std::string error_condition;
        std::string error_message;
        std::vector<std::string> stanzas_to_send;
    };

    JoinResult handle_join(const std::string& room_jid,
                           const std::string& user_jid,
                           const std::string& desired_nick,
                           const std::string& password_attempt = "") {
        JoinResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        if (!service_enabled_) {
            result.error_type = "cancel";
            result.error_condition = "service-unavailable";
            result.error_message = "MUC service is disabled";
            return result;
        }

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            result.error_message = "Room not found";
            return result;
        }

        if (room->is_destroyed()) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            result.error_message = "Room has been destroyed";
            return result;
        }

        if (!room->can_join(user_jid, password_attempt)) {
            if (room->is_banned(user_jid)) {
                result.error_type = "auth";
                result.error_condition = "forbidden";
                result.error_message = "You are banned from this room";
            } else if (room->is_password_protected() &&
                       password_attempt != room->password()) {
                result.error_type = "auth";
                result.error_condition = "not-authorized";
                result.error_message = "Incorrect password";
            } else if (room->is_members_only()) {
                result.error_type = "auth";
                result.error_condition = "registration-required";
                result.error_message = "Room is members-only";
            } else if (room->is_full()) {
                result.error_type = "wait";
                result.error_condition = "service-unavailable";
                result.error_message = "Room is full (max " +
                    std::to_string(room->max_users()) + " occupants)";
            } else {
                result.error_type = "cancel";
                result.error_condition = "not-allowed";
                result.error_message = "Cannot join room";
            }
            return result;
        }

        std::string nick = room->resolve_nick_conflict(desired_nick);

        MUCAffiliation affiliation = determine_affiliation(room, user_jid);
        MUCRole role = room->default_role_for_affiliation(affiliation);

        if (room->state() == MUCRoomState::CREATING &&
            user_jid == room->creator_jid()) {
            role = MUCRole::MODERATOR;
            affiliation = MUCAffiliation::OWNER;
        }

        auto occ = room->add_occupant(nick, user_jid, role, affiliation);
        if (!occ) {
            result.error_type = "cancel";
            result.error_condition = "conflict";
            result.error_message = "Nickname conflict";
            return result;
        }

        if (room->state() == MUCRoomState::CREATING) {
            room->set_state(MUCRoomState::ACTIVE);
        }

        std::string self_presence = room->generate_self_presence(nick);
        if (!self_presence.empty()) {
            result.stanzas_to_send.push_back(self_presence);
        }

        std::string subject_msg = room->generate_subject_message(nick);
        if (!subject_msg.empty()) {
            result.stanzas_to_send.push_back(subject_msg);
        }

        auto history = room->get_recent_history(room->max_history_fetch());
        for (auto& hmsg : history) {
            result.stanzas_to_send.push_back(format_history_for_send(room, hmsg));
        }

        auto occupants = room->get_all_occupants();
        for (auto& other_occ : occupants) {
            if (other_occ->nick() != nick) {
                std::string pres = room->generate_occupant_presence(
                    other_occ->nick(), user_jid);
                if (!pres.empty()) {
                    result.stanzas_to_send.push_back(pres);
                }
            }
        }

        std::string broadcast_pres = room->generate_occupant_presence(nick, "");
        if (!broadcast_pres.empty()) {
            for (auto& other : occupants) {
                if (other->nick() != nick) {
                    broadcast_to_occupant(room, other->nick(), broadcast_pres);
                }
            }
        }

        log_info("User " + user_jid + " joined room " + room_jid +
                 " as " + nick);

        result.success = true;
        return result;
    }

    // ========================================================================
    // Handle: Leave room
    // ========================================================================

    bool handle_leave(const std::string& room_jid,
                      const std::string& user_jid,
                      const std::string& nick) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) return false;

        auto occ = room->get_occupant(nick);
        if (!occ || occ->real_jid() != user_jid) return false;

        std::string unavailable = room->generate_unavailable_presence(nick, user_jid);

        room->remove_occupant(nick);

        auto occupants = room->get_all_occupants();
        for (auto& other : occupants) {
            broadcast_to_occupant(room, other->nick(), unavailable);
        }

        if (room->occupant_count() == 0 && !room->is_persistent()) {
            room->set_state(MUCRoomState::DESTROYING);
            room->set_state(MUCRoomState::DESTROYED);
            rooms_.erase(room_jid);
            log_info("Temporary room auto-destroyed: " + room_jid);
        }

        log_info("User " + user_jid + " left room " + room_jid);
        return true;
    }

    // ========================================================================
    // Handle: Groupchat message
    // ========================================================================

    struct MessageResult {
        bool success;
        std::string error_type;
        std::string error_condition;
        std::string error_message;
        std::vector<std::string> stanzas_to_send;
    };

    MessageResult handle_groupchat_message(const std::string& room_jid,
                                           const std::string& from_nick,
                                           const std::string& body,
                                           const std::string& msg_id = "") {
        MessageResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            result.error_message = "Room not found";
            return result;
        }

        if (room->is_destroyed()) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            result.error_message = "Room destroyed";
            return result;
        }

        auto occ = room->get_occupant(from_nick);
        if (!occ) {
            result.error_type = "cancel";
            result.error_condition = "not-acceptable";
            result.error_message = "Not in room";
            return result;
        }

        if (!room->can_send_message(from_nick)) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            result.error_message = "Voice required in moderated room";
            return result;
        }

        std::string actual_id = msg_id.empty() ? room->next_message_id() : msg_id;

        auto hmsg = MUCHistoryMessage(
            MUCHistoryMessage::Type::GROUPCHAT,
            from_nick, body, actual_id
        );
        hmsg.set_from_jid(occ->real_jid());
        room->add_history_message(hmsg);

        std::string broadcast = room->generate_message_broadcast(
            from_nick, body, actual_id);

        if (room->logging_enabled()) {
            log_info("Room " + room_jid + " message from " + from_nick +
                     ": " + body.substr(0, 100));
        }

        auto occupants = room->get_all_occupants();
        for (auto& other : occupants) {
            broadcast_to_occupant(room, other->nick(), broadcast);
        }

        result.success = true;
        result.stanzas_to_send.push_back(broadcast);
        return result;
    }

    // ========================================================================
    // Handle: Subject change
    // ========================================================================

    MessageResult handle_subject_change(const std::string& room_jid,
                                        const std::string& from_nick,
                                        const std::string& new_subject) {
        MessageResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        auto occ = room->get_occupant(from_nick);
        if (!occ) {
            result.error_type = "cancel";
            result.error_condition = "not-acceptable";
            return result;
        }

        bool can_change = room->allow_subject_change() || occ->can_change_subject();
        if (!can_change) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            result.error_message = "Not allowed to change subject";
            return result;
        }

        room->set_subject(new_subject);
        room->set_subject_setter(from_nick);
        room->set_subject_timestamp(std::chrono::system_clock::now());

        auto hmsg = MUCHistoryMessage(
            MUCHistoryMessage::Type::SUBJECT_CHANGE,
            from_nick, "Subject changed: " + new_subject,
            room->next_message_id()
        );
        room->add_history_message(hmsg);

        std::string subject_msg = room->generate_subject_message(from_nick);

        auto occupants = room->get_all_occupants();
        for (auto& occ_ptr : occupants) {
            broadcast_to_occupant(room, occ_ptr->nick(), subject_msg);
        }

        log_info("Room " + room_jid + " subject changed by " + from_nick);
        result.success = true;
        result.stanzas_to_send.push_back(subject_msg);
        return result;
    }

    // ========================================================================
    // Handle: Nick change
    // ========================================================================

    struct NickChangeResult {
        bool success;
        std::string error_type;
        std::string error_condition;
        std::string error_message;
        std::string actual_nick;
    };

    NickChangeResult handle_nick_change(const std::string& room_jid,
                                        const std::string& user_jid,
                                        const std::string& old_nick,
                                        const std::string& new_nick) {
        NickChangeResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        auto occ = room->get_occupant(old_nick);
        if (!occ || occ->real_jid() != user_jid) {
            result.error_type = "cancel";
            result.error_condition = "not-acceptable";
            return result;
        }

        if (room->has_occupant_nick(new_nick)) {
            result.error_type = "cancel";
            result.error_condition = "conflict";
            result.error_message = "Nickname already in use";
            return result;
        }

        std::string unavailable = room->generate_nick_change_presence(
            old_nick, new_nick, user_jid);

        if (!room->update_occupant_nick(old_nick, new_nick)) {
            result.error_type = "cancel";
            result.error_condition = "conflict";
            return result;
        }

        std::string new_presence = room->generate_occupant_presence(new_nick, "");

        auto occupants = room->get_all_occupants();
        for (auto& other : occupants) {
            broadcast_to_occupant(room, other->nick(), unavailable);
            if (other->nick() != new_nick) {
                broadcast_to_occupant(room, other->nick(), new_presence);
            }
        }

        std::string self_presence = room->generate_self_presence(new_nick);
        result.actual_nick = new_nick;
        result.success = true;

        log_info("User " + user_jid + " changed nick from " + old_nick +
                 " to " + new_nick + " in room " + room_jid);
        return result;
    }

    // ========================================================================
    // Handle: Kick
    // ========================================================================

    struct AdminActionResult {
        bool success;
        std::string error_type;
        std::string error_condition;
        std::string error_message;
        std::vector<std::string> stanzas_to_send;
    };

    AdminActionResult handle_kick(const std::string& room_jid,
                                  const std::string& actor_jid,
                                  const std::string& actor_nick,
                                  const std::string& target_nick,
                                  const std::string& reason) {
        AdminActionResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        auto actor = room->get_occupant(actor_nick);
        if (!actor || actor->real_jid() != actor_jid) {
            result.error_type = "cancel";
            result.error_condition = "not-acceptable";
            return result;
        }

        if (!actor->can_kick()) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            return result;
        }

        auto target = room->get_occupant(target_nick);
        if (!target) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            result.error_message = "Target not in room";
            return result;
        }

        if (target->affiliation() == MUCAffiliation::OWNER ||
            target->affiliation() == MUCAffiliation::ADMIN) {
            if (actor->affiliation() != MUCAffiliation::OWNER) {
                result.error_type = "auth";
                result.error_condition = "forbidden";
                result.error_message = "Cannot kick admin/owner";
                return result;
            }
        }

        std::string kick_pres = room->generate_kick_presence(
            target_nick, target->real_jid(), actor_nick, reason);

        room->kick_occupant(target_nick, actor_nick, reason);

        auto occupants = room->get_all_occupants();
        for (auto& occ : occupants) {
            broadcast_to_occupant(room, occ->nick(), kick_pres);
        }

        log_info("User " + target_nick + " kicked from " + room_jid +
                 " by " + actor_nick);

        result.success = true;
        result.stanzas_to_send.push_back(kick_pres);
        return result;
    }

    // ========================================================================
    // Handle: Ban
    // ========================================================================

    AdminActionResult handle_ban(const std::string& room_jid,
                                 const std::string& actor_jid,
                                 const std::string& actor_nick,
                                 const std::string& target_jid,
                                 const std::string& reason) {
        AdminActionResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        auto actor = room->get_occupant(actor_nick);
        if (!actor || actor->real_jid() != actor_jid) {
            result.error_type = "cancel";
            result.error_condition = "not-acceptable";
            return result;
        }

        if (!actor->can_ban()) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            return result;
        }

        auto target = room->get_occupant_by_jid(target_jid);
        if (!target && !room->is_member(target_jid)) {
            room->ban_user(target_jid, actor_nick, reason);
            result.success = true;
            log_info("User " + target_jid + " banned from " + room_jid +
                     " by " + actor_nick);
            return result;
        }

        if (target && (target->affiliation() == MUCAffiliation::OWNER)) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            result.error_message = "Cannot ban owner";
            return result;
        }

        std::string ban_pres;
        if (target) {
            ban_pres = room->generate_ban_presence(
                target->nick(), target->real_jid(), actor_nick, reason);
        }

        room->ban_user(target_jid, actor_nick, reason);

        if (target) {
            auto occupants = room->get_all_occupants();
            for (auto& occ : occupants) {
                broadcast_to_occupant(room, occ->nick(), ban_pres);
            }
        }

        log_info("User " + target_jid + " banned from " + room_jid +
                 " by " + actor_nick);

        result.success = true;
        if (!ban_pres.empty()) {
            result.stanzas_to_send.push_back(ban_pres);
        }
        return result;
    }

    // ========================================================================
    // Handle: Unban
    // ========================================================================

    AdminActionResult handle_unban(const std::string& room_jid,
                                   const std::string& actor_jid,
                                   const std::string& actor_nick,
                                   const std::string& target_jid) {
        AdminActionResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        auto actor = room->get_occupant(actor_nick);
        if (!actor || actor->real_jid() != actor_jid) {
            result.error_type = "cancel";
            result.error_condition = "not-acceptable";
            return result;
        }

        if (!actor->can_ban()) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            return result;
        }

        if (!room->unban_user(target_jid)) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            result.error_message = "User not in ban list";
            return result;
        }

        log_info("User " + target_jid + " unbanned from " + room_jid +
                 " by " + actor_nick);

        result.success = true;
        return result;
    }

    // ========================================================================
    // Handle: Role change
    // ========================================================================

    AdminActionResult handle_role_change(const std::string& room_jid,
                                         const std::string& actor_jid,
                                         const std::string& actor_nick,
                                         const std::string& target_nick,
                                         MUCRole new_role,
                                         const std::string& reason) {
        AdminActionResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        auto actor = room->get_occupant(actor_nick);
        if (!actor || actor->real_jid() != actor_jid) {
            result.error_type = "cancel";
            result.error_condition = "not-acceptable";
            return result;
        }

        auto target = room->get_occupant(target_nick);
        if (!target) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        bool allowed = false;
        switch (new_role) {
            case MUCRole::VISITOR:
                allowed = actor->can_revoke_voice();
                break;
            case MUCRole::PARTICIPANT:
                allowed = actor->can_grant_voice();
                break;
            case MUCRole::MODERATOR:
                allowed = actor->can_grant_moderator();
                break;
            default:
                break;
        }

        if (!allowed) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            return result;
        }

        room->set_occupant_role(target_nick, new_role, actor_nick, reason);

        std::string pres = room->generate_occupant_presence(target_nick, "");
        auto occupants = room->get_all_occupants();
        for (auto& occ : occupants) {
            broadcast_to_occupant(room, occ->nick(), pres);
        }

        log_info("Role change: " + target_nick + " -> " +
                 muc_role_to_string(new_role) + " in " + room_jid +
                 " by " + actor_nick);

        result.success = true;
        return result;
    }

    // ========================================================================
    // Handle: Affiliation change
    // ========================================================================

    AdminActionResult handle_affiliation_change(const std::string& room_jid,
                                                const std::string& actor_jid,
                                                const std::string& actor_nick,
                                                const std::string& target_jid_or_nick,
                                                bool is_by_jid,
                                                MUCAffiliation new_aff,
                                                const std::string& reason) {
        AdminActionResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        auto actor = room->get_occupant(actor_nick);
        if (!actor || actor->real_jid() != actor_jid) {
            result.error_type = "cancel";
            result.error_condition = "not-acceptable";
            return result;
        }

        std::string actual_jid;
        std::string target_nick;

        if (is_by_jid) {
            actual_jid = target_jid_or_nick;
            auto occ = room->get_occupant_by_jid(actual_jid);
            if (occ) target_nick = occ->nick();
        } else {
            target_nick = target_jid_or_nick;
            auto occ = room->get_occupant(target_nick);
            if (occ) actual_jid = occ->real_jid();
        }

        if (actual_jid.empty()) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        auto target = room->get_occupant_by_jid(actual_jid);
        MUCAffiliation current = target ? target->affiliation() : MUCAffiliation::NONE;

        if (!actor->can_change_affiliation(new_aff, current)) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            return result;
        }

        switch (new_aff) {
            case MUCAffiliation::OUTCAST:
                room->ban_user(actual_jid, actor_nick, reason);
                break;
            case MUCAffiliation::MEMBER:
                room->remove_member(actual_jid);
                room->add_member(actual_jid);
                break;
            case MUCAffiliation::ADMIN:
                room->add_admin(actual_jid);
                break;
            case MUCAffiliation::OWNER:
                room->add_owner(actual_jid);
                break;
            case MUCAffiliation::NONE:
                room->remove_member(actual_jid);
                room->remove_admin(actual_jid);
                room->remove_owner(actual_jid);
                break;
        }

        if (target) {
            room->set_occupant_affiliation(target_nick, new_aff, actor_nick, reason);
            std::string pres = room->generate_occupant_presence(target_nick, "");
            auto occupants = room->get_all_occupants();
            for (auto& occ : occupants) {
                broadcast_to_occupant(room, occ->nick(), pres);
            }
        }

        log_info("Affiliation change: " + actual_jid + " -> " +
                 muc_affiliation_to_string(new_aff) + " in " + room_jid +
                 " by " + actor_nick);

        result.success = true;
        return result;
    }

    // ========================================================================
    // Handle: Voice request / approval
    // ========================================================================

    bool handle_voice_request(const std::string& room_jid,
                              const std::string& from_nick) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) return false;
        if (!room->is_moderated()) return false;
        if (!room->allow_voice_requests()) return false;

        return room->request_voice(from_nick);
    }

    AdminActionResult handle_voice_approval(const std::string& room_jid,
                                            const std::string& actor_nick,
                                            const std::string& target_nick) {
        AdminActionResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        auto actor = room->get_occupant(actor_nick);
        if (!actor || !actor->can_grant_voice()) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            return result;
        }

        if (!room->approve_voice(target_nick)) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        room->set_occupant_role(target_nick, MUCRole::PARTICIPANT, actor_nick, "");

        std::string pres = room->generate_occupant_presence(target_nick, "");
        auto occupants = room->get_all_occupants();
        for (auto& occ : occupants) {
            broadcast_to_occupant(room, occ->nick(), pres);
        }

        log_info("Voice approved for " + target_nick + " in " + room_jid +
                 " by " + actor_nick);
        result.success = true;
        return result;
    }

    // ========================================================================
    // Handle: Invite
    // ========================================================================

    struct InviteResult {
        bool success;
        std::string error_type;
        std::string error_condition;
        std::string error_message;
        std::string invite_stanza;
    };

    InviteResult handle_invite(const std::string& room_jid,
                               const std::string& inviter_jid,
                               const std::string& inviter_nick,
                               const std::string& invitee_jid,
                               const std::string& reason) {
        InviteResult result;
        result.success = false;

        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            result.error_type = "cancel";
            result.error_condition = "item-not-found";
            return result;
        }

        if (!room->can_invite(inviter_jid)) {
            result.error_type = "auth";
            result.error_condition = "forbidden";
            result.error_message = "Not allowed to invite";
            return result;
        }

        result.invite_stanza = room->generate_invitation(
            invitee_jid, inviter_jid, reason);
        result.success = true;

        log_info("Invitation sent to " + invitee_jid + " for room " +
                 room_jid + " by " + inviter_jid);
        return result;
    }

    // ========================================================================
    // Handle: DISCO
    // ========================================================================

    std::string handle_disco_info(const std::string& room_jid,
                                  const std::string& from_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        if (room_jid == service_jid_) {
            return generate_service_disco_info();
        }

        auto room = get_room(room_jid);
        if (!room) {
            return generate_item_not_found("info", from_jid);
        }

        return room->generate_disco_info();
    }

    std::string handle_disco_items(const std::string& room_jid,
                                   const std::string& from_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        if (room_jid == service_jid_) {
            return generate_service_disco_items();
        }

        auto room = get_room(room_jid);
        if (!room) {
            return generate_item_not_found("items", from_jid);
        }

        return room->generate_disco_items();
    }

    // ========================================================================
    // Handle: Room config form (get)
    // ========================================================================

    std::string handle_get_room_config(const std::string& room_jid,
                                       const std::string& from_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) {
            std::ostringstream oss;
            oss << "<iq type=\"error\" id=\"cfg\" to=\"" << xml_escape(from_jid) << "\">";
            oss << "<error type=\"cancel\">";
            oss << "<item-not-found xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>";
            oss << "</error></iq>";
            return oss.str();
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"cfg\" from=\""
            << xml_escape(room_jid) << "\" to=\"" << xml_escape(from_jid) << "\">";
        oss << "<query xmlns=\"" << XMPPNS::MUC_OWNER << "\">";
        oss << room->generate_config_form();
        oss << "</query></iq>";
        return oss.str();
    }

    bool handle_set_room_config(const std::string& room_jid,
                                const std::string& from_jid,
                                const std::map<std::string, std::vector<std::string>>& fields) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        auto room = get_room(room_jid);
        if (!room) return false;

        return room->apply_config_form(fields);
    }

    // ========================================================================
    // Handle: Unique room name generation
    // ========================================================================

    std::string generate_unique_room_name(const std::string& localpart_prefix) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        std::mt19937 rng(std::chrono::system_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<int> dist(0, 35);

        static const char* chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        std::string suffix;
        for (int i = 0; i < 10; ++i) {
            suffix += chars[dist(rng)];
        }

        std::string base = localpart_prefix.empty() ? "room" : localpart_prefix;
        std::string candidate = base + "_" + suffix;

        int attempts = 0;
        while (rooms_.find(candidate + "@" + service_jid_) != rooms_.end()
               && attempts < 100) {
            suffix.clear();
            for (int i = 0; i < 10; ++i) {
                suffix += chars[dist(rng)];
            }
            candidate = base + "_" + suffix;
            ++attempts;
        }

        return candidate;
    }

    std::string generate_unique_room_jid(const std::string& localpart_prefix) {
        return generate_unique_room_name(localpart_prefix) + "@" + service_jid_;
    }

    // ========================================================================
    // Service configuration
    // ========================================================================

    void set_max_total_rooms(int max_rooms) { max_total_rooms_ = max_rooms; }
    int max_total_rooms() const { return max_total_rooms_; }

    void set_max_rooms_per_user(int max_rooms) { max_rooms_per_user_ = max_rooms; }
    int max_rooms_per_user() const { return max_rooms_per_user_; }

    void set_default_max_history(int count) { default_max_history_ = count; }
    int default_max_history() const { return default_max_history_; }

    void set_logging_enabled(bool enabled) { logging_enabled_ = enabled; }
    bool logging_enabled() const { return logging_enabled_; }

    const std::string& service_jid() const { return service_jid_; }

    // ========================================================================
    // Ban list administration
    // ========================================================================

    std::vector<std::string> get_ban_list(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto room = get_room(room_jid);
        if (!room) return {};
        return room->get_ban_list();
    }

    std::string generate_ban_list_xml(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto room = get_room(room_jid);
        if (!room) return "";

        auto bans = room->get_ban_list();
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        for (auto& jid : bans) {
            oss << "<item affiliation=\"outcast\" jid=\""
                << xml_escape(jid) << "\"/>";
        }
        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Member list administration
    // ========================================================================

    std::vector<std::string> get_member_list(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto room = get_room(room_jid);
        if (!room) return {};
        return room->get_member_list();
    }

    std::string generate_member_list_xml(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto room = get_room(room_jid);
        if (!room) return "";

        auto members = room->get_member_list();
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        for (auto& jid : members) {
            oss << "<item affiliation=\"member\" jid=\""
                << xml_escape(jid) << "\"/>";
        }
        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Admin list administration
    // ========================================================================

    std::vector<std::string> get_admin_list(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto room = get_room(room_jid);
        if (!room) return {};
        return room->get_admin_list();
    }

    std::string generate_admin_list_xml(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto room = get_room(room_jid);
        if (!room) return "";

        auto admins = room->get_admin_list();
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        for (auto& jid : admins) {
            oss << "<item affiliation=\"admin\" jid=\""
                << xml_escape(jid) << "\"/>";
        }
        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Owner list administration
    // ========================================================================

    std::vector<std::string> get_owner_list(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto room = get_room(room_jid);
        if (!room) return {};
        return room->get_owner_list();
    }

    std::string generate_owner_list_xml(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto room = get_room(room_jid);
        if (!room) return "";

        auto owners = room->get_owner_list();
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        for (auto& jid : owners) {
            oss << "<item affiliation=\"owner\" jid=\""
                << xml_escape(jid) << "\"/>";
        }
        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Moderator list
    // ========================================================================

    std::string generate_moderator_list_xml(const std::string& room_jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto room = get_room(room_jid);
        if (!room) return "";

        auto mods = room->get_moderator_list();
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        for (auto& nick : mods) {
            oss << "<item role=\"moderator\" nick=\""
                << xml_escape(nick) << "\"/>";
        }
        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    struct MUCStatistics {
        int total_rooms;
        int active_rooms;
        int persistent_rooms;
        int total_occupants;
        int members_only_rooms;
        int password_protected_rooms;
        int moderated_rooms;
        int destroyed_rooms;
    };

    MUCStatistics get_statistics() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        MUCStatistics stats;
        stats.total_rooms = static_cast<int>(rooms_.size());
        stats.active_rooms = 0;
        stats.persistent_rooms = 0;
        stats.total_occupants = 0;
        stats.members_only_rooms = 0;
        stats.password_protected_rooms = 0;
        stats.moderated_rooms = 0;
        stats.destroyed_rooms = 0;

        for (auto& pair : rooms_) {
            auto& room = pair.second;
            if (room->state() == MUCRoomState::ACTIVE) {
                stats.active_rooms++;
                stats.total_occupants += static_cast<int>(room->occupant_count());
            }
            if (room->is_persistent()) stats.persistent_rooms++;
            if (room->is_members_only()) stats.members_only_rooms++;
            if (room->is_password_protected()) stats.password_protected_rooms++;
            if (room->is_moderated()) stats.moderated_rooms++;
            if (room->is_destroyed()) stats.destroyed_rooms++;
        }

        return stats;
    }

    // ========================================================================
    // Room cleanup (garbage collect destroyed non-persistent rooms)
    // ========================================================================

    int cleanup_destroyed_rooms() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        int cleaned = 0;

        std::vector<std::string> to_remove;
        for (auto& pair : rooms_) {
            if (pair.second->is_destroyed() && !pair.second->is_persistent()) {
                to_remove.push_back(pair.first);
            }
        }

        for (auto& jid : to_remove) {
            rooms_.erase(jid);
            ++cleaned;
        }

        if (cleaned > 0) {
            log_info("Cleaned up " + std::to_string(cleaned) + " destroyed rooms");
        }

        return cleaned;
    }

    int cleanup_empty_temporary_rooms() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        int cleaned = 0;

        std::vector<std::string> to_remove;
        for (auto& pair : rooms_) {
            auto& room = pair.second;
            if (!room->is_persistent() &&
                room->occupant_count() == 0 &&
                room->state() == MUCRoomState::ACTIVE) {
                to_remove.push_back(pair.first);
            }
        }

        for (auto& jid : to_remove) {
            rooms_.erase(jid);
            ++cleaned;
        }

        return cleaned;
    }

private:
    // ========================================================================
    // Private helpers
    // ========================================================================

    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    std::string next_message_id() {
        static std::atomic<uint64_t> counter{0};
        std::ostringstream oss;
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        oss << "muc_" << ms << "_" << (++counter);
        return oss.str();
    }

    int count_user_rooms(const std::string& real_jid) {
        int count = 0;
        for (auto& pair : rooms_) {
            auto occ = pair.second->get_occupant_by_jid(real_jid);
            if (occ) ++count;
        }
        return count;
    }

    MUCAffiliation determine_affiliation(std::shared_ptr<MUCRoom> room,
                                         const std::string& real_jid) {
        if (room->is_owner(real_jid)) return MUCAffiliation::OWNER;
        if (room->is_admin(real_jid)) return MUCAffiliation::ADMIN;
        if (room->is_member(real_jid)) return MUCAffiliation::MEMBER;
        return MUCAffiliation::NONE;
    }

    void evict_all_occupants(std::shared_ptr<MUCRoom> room) {
        auto occupants = room->get_all_occupants();
        for (auto& occ : occupants) {
            std::string unavailable = room->generate_unavailable_presence(
                occ->nick(), occ->real_jid());
            room->remove_occupant(occ->nick());
            send_callback_(unavailable);
        }
    }

    void broadcast_to_occupant(std::shared_ptr<MUCRoom> room,
                               const std::string& nick,
                               const std::string& stanza) {
        if (nick.empty()) {
            send_callback_(stanza);
        } else {
            auto occ = room->get_occupant(nick);
            if (occ) {
                send_callback_(stanza);
            }
        }
    }

    std::string format_history_for_send(std::shared_ptr<MUCRoom> room,
                                        const MUCHistoryMessage& msg) {
        std::ostringstream oss;

        switch (msg.type()) {
            case MUCHistoryMessage::Type::GROUPCHAT:
                oss << "<message from=\""
                    << xml_escape(room->jid() + "/" + msg.from_nick()) << "\"";
                oss << " type=\"groupchat\"";
                oss << " id=\"" << xml_escape(msg.id()) << "\">";
                oss << "<body>" << xml_escape(msg.body()) << "</body>";
                oss << "<delay xmlns=\"" << XMPPNS::DELAY2 << "\" stamp=\""
                    << msg.to_stamp() << "\"/>";
                oss << "</message>";
                break;

            case MUCHistoryMessage::Type::SUBJECT_CHANGE:
                oss << "<message from=\"" << xml_escape(room->jid()) << "\"";
                oss << " type=\"groupchat\"";
                oss << " id=\"" << xml_escape(msg.id()) << "\">";
                oss << "<subject>" << xml_escape(msg.body()) << "</subject>";
                oss << "<delay xmlns=\"" << XMPPNS::DELAY2 << "\" stamp=\""
                    << msg.to_stamp() << "\"/>";
                oss << "</message>";
                break;

            case MUCHistoryMessage::Type::PRESENCE_JOIN:
            case MUCHistoryMessage::Type::PRESENCE_LEAVE:
                oss << "<message from=\"" << xml_escape(room->jid()) << "\"";
                oss << " type=\"groupchat\"";
                oss << " id=\"" << xml_escape(msg.id()) << "\">";
                oss << "<body>";
                if (msg.type() == MUCHistoryMessage::Type::PRESENCE_JOIN) {
                    oss << xml_escape(msg.from_nick() + " has joined the room");
                } else {
                    oss << xml_escape(msg.from_nick() + " has left the room");
                }
                oss << "</body>";
                oss << "<delay xmlns=\"" << XMPPNS::DELAY2 << "\" stamp=\""
                    << msg.to_stamp() << "\"/>";
                oss << "</message>";
                break;

            default:
                oss << "<message from=\"" << xml_escape(room->jid()) << "\"";
                oss << " type=\"groupchat\" id=\"" << xml_escape(msg.id()) << "\">";
                oss << "<body>" << xml_escape(msg.body()) << "</body>";
                oss << "<delay xmlns=\"" << XMPPNS::DELAY2 << "\" stamp=\""
                    << msg.to_stamp() << "\"/>";
                oss << "</message>";
                break;
        }

        return oss.str();
    }

    std::string generate_service_disco_info() {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_INFO << "\">";
        oss << "<identity category=\"conference\" type=\"text\" name=\"MUC Service\"/>";
        oss << "<feature var=\"" << XMPPNS::DISCO_INFO << "\"/>";
        oss << "<feature var=\"" << XMPPNS::DISCO_ITEMS << "\"/>";
        oss << "<feature var=\"" << XMPPNS::MUC << "\"/>";
        oss << "<feature var=\"" << XMPPNS::MUC_UNIQUE << "\"/>";
        oss << "</query>";
        return oss.str();
    }

    std::string generate_service_disco_items() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_ITEMS << "\">";
        for (auto& pair : rooms_) {
            if (pair.second->state() == MUCRoomState::ACTIVE) {
                oss << "<item jid=\"" << xml_escape(pair.first) << "\"";
                oss << " name=\"" << xml_escape(pair.second->name()) << "\"/>";
            }
        }
        oss << "</query>";
        return oss.str();
    }

    std::string generate_item_not_found(const std::string& query_type,
                                        const std::string& to_jid) {
        std::ostringstream oss;
        oss << "<iq type=\"error\" id=\"disco\" to=\"" << xml_escape(to_jid) << "\">";
        oss << "<query xmlns=\"http://jabber.org/protocol/disco#" << query_type << "\"/>";
        oss << "<error type=\"cancel\">";
        oss << "<item-not-found xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>";
        oss << "</error></iq>";
        return oss.str();
    }

    std::string service_jid_;
    MessageCallback send_callback_;
    Logger logger_;

    std::unordered_map<std::string, RoomPtr> rooms_;
    int next_room_id_;
    bool service_enabled_;

    int max_total_rooms_;
    int max_rooms_per_user_;
    int default_max_history_;
    bool logging_enabled_;

    mutable std::mutex service_mutex_;
};

// ============================================================================
// MUCClientSession - Client-side MUC helper
// ============================================================================

class MUCClientSession {
public:
    MUCClientSession(const std::string& user_jid,
                     std::function<void(const std::string&)> send_callback)
        : user_jid_(user_jid)
        , send_callback_(send_callback)
    {}

    struct RoomSession {
        std::string room_jid;
        std::string nick;
        MUCRole role;
        MUCAffiliation affiliation;
        bool joined;
        std::chrono::system_clock::time_point joined_at;
    };

    void add_room_session(const std::string& room_jid, const std::string& nick,
                          MUCRole role, MUCAffiliation affiliation) {
        RoomSession session;
        session.room_jid = room_jid;
        session.nick = nick;
        session.role = role;
        session.affiliation = affiliation;
        session.joined = true;
        session.joined_at = std::chrono::system_clock::now();
        rooms_[room_jid] = session;
    }

    void remove_room_session(const std::string& room_jid) {
        rooms_.erase(room_jid);
    }

    std::optional<RoomSession> get_room_session(const std::string& room_jid) {
        auto it = rooms_.find(room_jid);
        if (it != rooms_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    bool is_in_room(const std::string& room_jid) {
        return rooms_.find(room_jid) != rooms_.end();
    }

    std::string get_nick_in_room(const std::string& room_jid) {
        auto it = rooms_.find(room_jid);
        if (it != rooms_.end()) return it->second.nick;
        return "";
    }

    std::vector<RoomSession> get_all_rooms() {
        std::vector<RoomSession> result;
        for (auto& pair : rooms_) {
            result.push_back(pair.second);
        }
        return result;
    }

    size_t room_count() const { return rooms_.size(); }

    void send_join(const std::string& room_jid, const std::string& nick,
                   const std::string& password = "") {
        std::ostringstream oss;
        oss << "<presence from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid + "/" + nick) << "\">";
        oss << "<x xmlns=\"" << XMPPNS::MUC << "\">";
        oss << "<history maxchars=\"0\"/>";
        if (!password.empty()) {
            oss << "<password>" << xml_escape(password) << "</password>";
        }
        oss << "</x></presence>";
        send_callback_(oss.str());
    }

    void send_leave(const std::string& room_jid, const std::string& nick) {
        std::ostringstream oss;
        oss << "<presence from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid + "/" + nick)
            << "\" type=\"unavailable\"/>";
        send_callback_(oss.str());
    }

    void send_groupchat_message(const std::string& room_jid,
                                const std::string& body) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"groupchat\">";
        oss << "<body>" << xml_escape(body) << "</body>";
        oss << "</message>";
        send_callback_(oss.str());
    }

    void send_private_message(const std::string& room_jid,
                              const std::string& target_nick,
                              const std::string& body) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid + "/" + target_nick)
            << "\" type=\"chat\">";
        oss << "<body>" << xml_escape(body) << "</body>";
        oss << "</message>";
        send_callback_(oss.str());
    }

    void send_subject_change(const std::string& room_jid,
                             const std::string& new_subject) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"groupchat\">";
        oss << "<subject>" << xml_escape(new_subject) << "</subject>";
        oss << "</message>";
        send_callback_(oss.str());
    }

    void send_nick_change(const std::string& room_jid,
                          const std::string& new_nick) {
        std::ostringstream oss;
        oss << "<presence from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid + "/" + new_nick) << "\"/>";
        send_callback_(oss.str());
    }

    void send_voice_request(const std::string& room_jid) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid) << "\">";
        oss << "<x xmlns=\"" << XMPPNS::MUC << "\"/>";
        oss << "<body>I would like to speak</body>";
        oss << "</message>";
        send_callback_(oss.str());
    }

    void send_invite(const std::string& room_jid,
                     const std::string& invitee_jid,
                     const std::string& reason) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid) << "\">";
        oss << "<x xmlns=\"" << XMPPNS::MUC_USER << "\">";
        oss << "<invite to=\"" << xml_escape(invitee_jid) << "\">";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</invite>";
        oss << "</x></message>";
        send_callback_(oss.str());
    }

    void send_kick(const std::string& room_jid,
                   const std::string& target_nick,
                   const std::string& reason) {
        std::ostringstream oss;
        oss << "<iq from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"set\" id=\"kick1\">";
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        oss << "<item nick=\"" << xml_escape(target_nick)
            << "\" role=\"none\">";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</item></query></iq>";
        send_callback_(oss.str());
    }

    void send_ban(const std::string& room_jid,
                  const std::string& target_jid,
                  const std::string& reason) {
        std::ostringstream oss;
        oss << "<iq from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"set\" id=\"ban1\">";
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        oss << "<item affiliation=\"outcast\" jid=\""
            << xml_escape(target_jid) << "\">";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</item></query></iq>";
        send_callback_(oss.str());
    }

    void send_unban(const std::string& room_jid,
                    const std::string& target_jid) {
        std::ostringstream oss;
        oss << "<iq from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"set\" id=\"unban1\">";
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        oss << "<item affiliation=\"none\" jid=\""
            << xml_escape(target_jid) << "\"/>";
        oss << "</query></iq>";
        send_callback_(oss.str());
    }

    void send_role_change(const std::string& room_jid,
                          const std::string& target_nick,
                          MUCRole new_role,
                          const std::string& reason) {
        std::ostringstream oss;
        oss << "<iq from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"set\" id=\"role1\">";
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        oss << "<item nick=\"" << xml_escape(target_nick)
            << "\" role=\"" << muc_role_to_string(new_role) << "\">";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</item></query></iq>";
        send_callback_(oss.str());
    }

    void send_affiliation_change(const std::string& room_jid,
                                 const std::string& target_jid,
                                 MUCAffiliation new_aff,
                                 const std::string& reason) {
        std::ostringstream oss;
        oss << "<iq from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"set\" id=\"aff1\">";
        oss << "<query xmlns=\"" << XMPPNS::MUC_ADMIN << "\">";
        oss << "<item affiliation=\"" << muc_affiliation_to_string(new_aff)
            << "\" jid=\"" << xml_escape(target_jid) << "\">";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</item></query></iq>";
        send_callback_(oss.str());
    }

    void send_request_room_config(const std::string& room_jid) {
        std::ostringstream oss;
        oss << "<iq from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"get\" id=\"cfg1\">";
        oss << "<query xmlns=\"" << XMPPNS::MUC_OWNER << "\"/>";
        oss << "</iq>";
        send_callback_(oss.str());
    }

    void send_set_room_config(const std::string& room_jid,
                              const std::map<std::string, std::vector<std::string>>& fields) {
        std::ostringstream oss;
        oss << "<iq from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"set\" id=\"cfg2\">";
        oss << "<query xmlns=\"" << XMPPNS::MUC_OWNER << "\">";
        oss << "<x xmlns=\"" << XMPPNS::X_DATA << "\" type=\"submit\">";

        for (auto& pair : fields) {
            oss << "<field var=\"" << xml_escape(pair.first) << "\">";
            for (auto& val : pair.second) {
                oss << "<value>" << xml_escape(val) << "</value>";
            }
            oss << "</field>";
        }

        oss << "</x></query></iq>";
        send_callback_(oss.str());
    }

    void send_destroy_room(const std::string& room_jid,
                           const std::string& reason,
                           const std::string& alternate_jid = "") {
        std::ostringstream oss;
        oss << "<iq from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(room_jid)
            << "\" type=\"set\" id=\"destroy1\">";
        oss << "<query xmlns=\"" << XMPPNS::MUC_OWNER << "\">";
        oss << "<destroy";
        if (!alternate_jid.empty()) {
            oss << " jid=\"" << xml_escape(alternate_jid) << "\"";
        }
        oss << ">";
        if (!reason.empty()) {
            oss << "<reason>" << xml_escape(reason) << "</reason>";
        }
        oss << "</destroy></query></iq>";
        send_callback_(oss.str());
    }

    void send_request_unique_name(const std::string& service_jid) {
        std::ostringstream oss;
        oss << "<iq from=\"" << xml_escape(user_jid_)
            << "\" to=\"" << xml_escape(service_jid)
            << "\" type=\"get\" id=\"uniq1\">";
        oss << "<unique xmlns=\"" << XMPPNS::MUC_UNIQUE << "\"/>";
        oss << "</iq>";
        send_callback_(oss.str());
    }

private:
    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    std::string user_jid_;
    std::function<void(const std::string&)> send_callback_;
    std::unordered_map<std::string, RoomSession> rooms_;
};

// ============================================================================
// MUCStanzaParser - Parse MUC-related stanzas
// ============================================================================

class MUCStanzaParser {
public:
    enum class StanzaType {
        UNKNOWN,
        PRESENCE_JOIN,
        PRESENCE_LEAVE,
        PRESENCE_NICK_CHANGE,
        MESSAGE_GROUPCHAT,
        MESSAGE_SUBJECT,
        MESSAGE_PRIVATE,
        IQ_SET_ROLE,
        IQ_SET_AFFILIATION,
        IQ_GET_CONFIG,
        IQ_SET_CONFIG,
        IQ_GET_BAN_LIST,
        IQ_GET_MEMBER_LIST,
        IQ_GET_ADMIN_LIST,
        IQ_GET_OWNER_LIST,
        IQ_GET_MODERATOR_LIST,
        IQ_DESTROY,
        IQ_GET_UNIQUE,
        INVITE,
        DECLINE
    };

    struct ParsedStanza {
        StanzaType type;
        std::string from_jid;
        std::string to_jid;
        std::string room_jid;
        std::string nick;
        std::string body;
        std::string subject;
        std::string password;
        std::string reason;
        std::string target_nick;
        std::string target_jid;
        std::string new_nick;
        MUCRole role;
        MUCAffiliation affiliation;
        std::map<std::string, std::vector<std::string>> config_fields;
    };

    static ParsedStanza parse(const std::string& xml) {
        ParsedStanza result;
        result.type = StanzaType::UNKNOWN;
        result.role = MUCRole::NONE;
        result.affiliation = MUCAffiliation::NONE;

        if (is_presence(xml)) {
            return parse_presence(xml);
        } else if (is_message(xml)) {
            return parse_message(xml);
        } else if (is_iq(xml)) {
            return parse_iq(xml);
        }

        return result;
    }

private:
    static std::string extract_attr(const std::string& xml, const std::string& attr) {
        std::string search = attr + "=\"";
        size_t pos = xml.find(search);
        if (pos == std::string::npos) {
            search = attr + "='";
            pos = xml.find(search);
            if (pos == std::string::npos) return "";
        }
        pos += search.length();
        size_t end = xml.find(xml[pos - 1], pos);
        if (end == std::string::npos) return "";
        return unescape_xml(xml.substr(pos, end - pos));
    }

    static std::string extract_child_text(const std::string& xml,
                                          const std::string& tag) {
        std::string open = "<" + tag;
        size_t pos = xml.find(open);
        if (pos == std::string::npos) return "";

        size_t open_end = xml.find('>', pos);
        if (open_end == std::string::npos) return "";

        pos = open_end + 1;
        size_t close = xml.find("</" + tag + ">", pos);
        if (close == std::string::npos) return "";

        return unescape_xml(trim(xml.substr(pos, close - pos)));
    }

    static std::string extract_child_with_attr(const std::string& xml,
                                               const std::string& tag,
                                               const std::string& attr_name,
                                               const std::string& attr_value) {
        std::string open = "<" + tag;
        size_t pos = 0;
        while ((pos = xml.find(open, pos)) != std::string::npos) {
            size_t tag_end = xml.find('>', pos);
            if (tag_end == std::string::npos) break;
            std::string tag_content = xml.substr(pos, tag_end - pos + 1);

            if (attr_value.empty() || tag_content.find(attr_name + "=\"" + attr_value + "\"") != std::string::npos ||
                tag_content.find(attr_name + "='" + attr_value + "'") != std::string::npos) {
                size_t content_start = tag_end + 1;
                size_t content_end = xml.find("</" + tag + ">", content_start);
                if (content_end == std::string::npos) break;
                return unescape_xml(trim(xml.substr(content_start, content_end - content_start)));
            }
            ++pos;
        }
        return "";
    }

    static std::string unescape_xml(const std::string& s) {
        std::string result = s;
        size_t pos;
        while ((pos = result.find("&amp;")) != std::string::npos)
            result.replace(pos, 5, "&");
        while ((pos = result.find("&lt;")) != std::string::npos)
            result.replace(pos, 4, "<");
        while ((pos = result.find("&gt;")) != std::string::npos)
            result.replace(pos, 4, ">");
        while ((pos = result.find("&quot;")) != std::string::npos)
            result.replace(pos, 6, "\"");
        while ((pos = result.find("&apos;")) != std::string::npos)
            result.replace(pos, 6, "'");
        return result;
    }

    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\n\r");
        return s.substr(start, end - start + 1);
    }

    static bool is_presence(const std::string& xml) {
        return xml.find("<presence") != std::string::npos;
    }

    static bool is_message(const std::string& xml) {
        return xml.find("<message") != std::string::npos;
    }

    static bool is_iq(const std::string& xml) {
        return xml.find("<iq") != std::string::npos;
    }

    static void parse_jid_and_room(const std::string& xml, ParsedStanza& result) {
        result.from_jid = extract_attr(xml, "from");
        result.to_jid = extract_attr(xml, "to");

        std::string to = result.to_jid;
        size_t slash = to.find('/');
        if (slash != std::string::npos) {
            result.room_jid = to.substr(0, slash);
            result.nick = to.substr(slash + 1);
        } else {
            result.room_jid = to;
        }

        if (result.room_jid.empty()) {
            std::string from = result.from_jid;
            slash = from.find('/');
            if (slash != std::string::npos) {
                result.room_jid = from.substr(0, slash);
                result.nick = from.substr(slash + 1);
            }
        }
    }

    static ParsedStanza parse_presence(const std::string& xml) {
        ParsedStanza result;
        parse_jid_and_room(xml, result);

        std::string type = extract_attr(xml, "type");

        if (type == "unavailable") {
            result.type = StanzaType::PRESENCE_LEAVE;
        } else {
            std::string from = result.from_jid;
            size_t slash = from.find('/');
            if (slash != std::string::npos) {
                std::string existing_nick = from.substr(slash + 1);
                if (!existing_nick.empty() && !result.nick.empty() &&
                    existing_nick != result.nick) {
                    result.type = StanzaType::PRESENCE_NICK_CHANGE;
                    result.new_nick = result.nick;
                    result.nick = existing_nick;
                } else {
                    result.type = StanzaType::PRESENCE_JOIN;
                }
            } else {
                result.type = StanzaType::PRESENCE_JOIN;
            }
        }

        result.password = extract_child_text(xml, "password");

        return result;
    }

    static ParsedStanza parse_message(const std::string& xml) {
        ParsedStanza result;
        parse_jid_and_room(xml, result);

        result.body = extract_child_text(xml, "body");
        result.subject = extract_child_text(xml, "subject");
        result.reason = extract_child_text(xml, "reason");

        if (!result.subject.empty()) {
            result.type = StanzaType::MESSAGE_SUBJECT;
        } else if (xml.find("<invite") != std::string::npos) {
            result.type = StanzaType::INVITE;
            result.target_jid = extract_attr(xml, "to");
        } else if (xml.find("<decline") != std::string::npos) {
            result.type = StanzaType::DECLINE;
        } else {
            result.type = StanzaType::MESSAGE_GROUPCHAT;
        }

        return result;
    }

    static ParsedStanza parse_iq(const std::string& xml) {
        ParsedStanza result;
        result.type = StanzaType::UNKNOWN;
        result.role = MUCRole::NONE;
        result.affiliation = MUCAffiliation::NONE;

        result.from_jid = extract_attr(xml, "from");
        result.to_jid = extract_attr(xml, "to");
        result.room_jid = result.to_jid;

        std::string iq_type = extract_attr(xml, "type");

        if (xml.find("<destroy") != std::string::npos) {
            result.type = StanzaType::IQ_DESTROY;
            result.reason = extract_child_text(xml, "reason");
            result.target_jid = extract_attr(xml, "jid");
            return result;
        }

        if (xml.find("<unique") != std::string::npos) {
            result.type = StanzaType::IQ_GET_UNIQUE;
            return result;
        }

        if (xml.find("<query") == std::string::npos) return result;

        std::string xmlns = extract_attr(xml, "xmlns");

        if (xml.find(XMPPNS::MUC_OWNER) != std::string::npos) {
            if (iq_type == "get") {
                result.type = StanzaType::IQ_GET_CONFIG;
            } else {
                result.type = StanzaType::IQ_SET_CONFIG;
            }
            return result;
        }

        if (xml.find(XMPPNS::MUC_ADMIN) != std::string::npos) {
            std::string item_affiliation = extract_attr_from_item(xml, "affiliation");
            std::string item_role = extract_attr_from_item(xml, "role");
            std::string item_nick = extract_attr_from_item(xml, "nick");
            std::string item_jid = extract_attr_from_item(xml, "jid");

            result.reason = extract_child_text(xml, "reason");
            result.target_nick = item_nick;
            result.target_jid = item_jid;

            if (item_role == "none" && item_nick == result.target_nick) {
                result.type = StanzaType::IQ_SET_ROLE;
                result.role = MUCRole::NONE;
                return result;
            }

            if (!item_role.empty()) {
                result.type = StanzaType::IQ_SET_ROLE;
                result.role = muc_role_from_string(item_role);
                return result;
            }

            if (item_affiliation == "outcast") {
                result.type = StanzaType::IQ_SET_AFFILIATION;
                result.affiliation = MUCAffiliation::OUTCAST;
                return result;
            }

            if (item_affiliation == "member") {
                result.type = StanzaType::IQ_SET_AFFILIATION;
                result.affiliation = MUCAffiliation::MEMBER;
                return result;
            }

            if (item_affiliation == "admin") {
                result.type = StanzaType::IQ_SET_AFFILIATION;
                result.affiliation = MUCAffiliation::ADMIN;
                return result;
            }

            if (item_affiliation == "owner") {
                result.type = StanzaType::IQ_SET_AFFILIATION;
                result.affiliation = MUCAffiliation::OWNER;
                return result;
            }

            if (item_affiliation == "none" && !item_jid.empty()) {
                result.type = StanzaType::IQ_SET_AFFILIATION;
                result.affiliation = MUCAffiliation::NONE;
                return result;
            }

            if (iq_type == "get") {
                result.type = StanzaType::IQ_GET_BAN_LIST;
                return result;
            }
        }

        return result;
    }

    static std::string extract_attr_from_item(const std::string& xml,
                                              const std::string& attr) {
        size_t item_pos = xml.find("<item");
        if (item_pos == std::string::npos) return "";

        size_t item_end = xml.find("/>", item_pos);
        if (item_end == std::string::npos) {
            item_end = xml.find(">", item_pos);
        }
        if (item_end == std::string::npos) return "";

        std::string item_str = xml.substr(item_pos, item_end - item_pos);
        return extract_attr(item_str, attr);
    }
};

} // namespace xmpp
} // namespace progressive
