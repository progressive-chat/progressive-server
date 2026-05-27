// progressive-server: Matrix Event types and processing
// Reference: Synapse events/*.py, synapse/events/builder.py, event_auth.py

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <mutex>
#include <functional>
#include "../json.hpp"

namespace progressive {
namespace events {

using json = nlohmann::json;

// =============================================================================
// Event base types
// =============================================================================
enum class EventType : uint8_t {
    ROOM_CREATE, ROOM_MEMBER, ROOM_POWER_LEVELS, ROOM_JOIN_RULES,
    ROOM_HISTORY_VISIBILITY, ROOM_GUEST_ACCESS, ROOM_NAME, ROOM_TOPIC,
    ROOM_AVATAR, ROOM_CANONICAL_ALIAS, ROOM_ENCRYPTION, ROOM_THIRD_PARTY_INVITE,
    ROOM_TOMBSTONE, ROOM_SERVER_ACL, ROOM_MESSAGE, ROOM_MESSAGE_FEEDBACK,
    ROOM_REDACTION, ROOM_TAG, RECEIPT, FULLY_READ,
    TYPING, PRESENCE, DIRECT_TO_DEVICE, ROOM_KEY, ROOM_KEY_REQUEST,
    FORWARDED_ROOM_KEY, OLM, MEGOLM, CALL_INVITE, CALL_CANDIDATES,
    CALL_ANSWER, CALL_HANGUP, CALL_REJECT, CALL_NEGOTIATE, CALL_SELECT_ANSWER,
    STICKER, REACTION, RELATION, WIDGET, SPACE_CHILD, SPACE_PARENT,
    POLL_START, POLL_RESPONSE, POLL_END, LOCATION, BEACON_INFO,
    VOICE_MESSAGE, KEY_VERIFICATION_START, KEY_VERIFICATION_ACCEPT,
    KEY_VERIFICATION_KEY, KEY_VERIFICATION_MAC, KEY_VERIFICATION_DONE,
    KEY_VERIFICATION_CANCEL, SECRET_SEND, SECRET_REQUEST,
    DUMMY, CUSTOM,
};

struct EventBase {
    std::string event_id;
    std::string room_id;
    std::string sender;
    std::string origin_server_ts;
    std::string type;
    std::string state_key;
    json content;
    json unsigned_data;
    json redacts;
    int depth = 0;
    json prev_events;
    json auth_events;
    json hashes;
    json signatures;
};

// =============================================================================
// Event builder and validator
// =============================================================================
class EventBuilder {
public:
    static json build_member_event(const std::string& room_id, const std::string& sender,
                                    const std::string& state_key, const std::string& membership,
                                    const std::string& displayname = "",
                                    const std::string& avatar_url = "",
                                    const std::string& reason = "") {
        json event;
        event["type"] = "m.room.member";
        event["state_key"] = state_key;
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        event["content"]["membership"] = membership;

        if (!displayname.empty()) event["content"]["displayname"] = displayname;
        if (!avatar_url.empty()) event["content"]["avatar_url"] = avatar_url;
        if (!reason.empty()) event["content"]["reason"] = reason;

        if (membership == "join") {
            // Add prev_events and auth_events
            event["prev_events"] = json::array();
            event["auth_events"] = json::array();
            event["depth"] = 1;
        }

        event["event_id"] = generate_event_id(sender);
        return event;
    }

    static json build_create_event(const std::string& room_id, const std::string& creator,
                                    const std::string& room_version = "10",
                                    bool federate = true,
                                    const std::string& predecessor = "") {
        json event;
        event["type"] = "m.room.create";
        event["state_key"] = "";
        event["sender"] = creator;
        event["room_id"] = room_id;
        event["content"]["creator"] = creator;
        event["content"]["room_version"] = room_version;
        event["content"]["m.federate"] = federate;

        if (!predecessor.empty()) {
            event["content"]["predecessor"]["room_id"] = predecessor;
            event["content"]["predecessor"]["event_id"] = "";
        }

        event["event_id"] = generate_event_id(creator);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        event["depth"] = 1;
        event["prev_events"] = json::array();
        event["auth_events"] = json::array();

        return event;
    }

    static json build_power_levels_event(const std::string& room_id, const std::string& sender,
                                          int users_default = 0, int events_default = 0,
                                          int state_default = 50, int ban = 50,
                                          int kick = 50, int redact = 50,
                                          int invite = 0) {
        json event;
        event["type"] = "m.room.power_levels";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["users"] = json::object();
        event["content"]["users_default"] = users_default;
        event["content"]["events"] = json::object();
        event["content"]["events_default"] = events_default;
        event["content"]["state_default"] = state_default;
        event["content"]["ban"] = ban;
        event["content"]["kick"] = kick;
        event["content"]["redact"] = redact;
        event["content"]["invite"] = invite;
        event["content"]["notifications"]["room"] = 50;

        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_message_event(const std::string& room_id, const std::string& sender,
                                     const std::string& msgtype, const std::string& body,
                                     const std::string& formatted_body = "",
                                     const std::string& format = "") {
        json event;
        event["type"] = "m.room.message";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["msgtype"] = msgtype;
        event["content"]["body"] = body;

        if (!formatted_body.empty()) {
            event["content"]["formatted_body"] = formatted_body;
            event["content"]["format"] = format.empty() ? "org.matrix.custom.html" : format;
        }

        if (msgtype == "m.image" || msgtype == "m.file" || msgtype == "m.audio" ||
            msgtype == "m.video") {
            event["content"]["url"] = "mxc://localhost/" + generate_media_id();
            event["content"]["filename"] = extract_filename(body);
            // Add info section
            json info;
            if (msgtype == "m.image") {
                info["w"] = 0; info["h"] = 0; info["mimetype"] = "image/jpeg"; info["size"] = 0;
            } else if (msgtype == "m.audio" || msgtype == "m.video") {
                info["duration"] = 0; info["mimetype"] = (msgtype == "m.audio" ? "audio/mp4" : "video/mp4"); info["size"] = 0;
            } else {
                info["mimetype"] = "application/octet-stream"; info["size"] = 0;
            }
            event["content"]["info"] = info;
        }

        if (msgtype == "m.location") {
            event["content"]["geo_uri"] = "geo:0,0";
            event["content"]["org.matrix.msc3488.location"]["description"] = body;
        }

        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_reaction_event(const std::string& room_id, const std::string& sender,
                                      const std::string& relates_to_event_id,
                                      const std::string& key) {
        json event;
        event["type"] = "m.reaction";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["m.relates_to"]["event_id"] = relates_to_event_id;
        event["content"]["m.relates_to"]["rel_type"] = "m.annotation";
        event["content"]["m.relates_to"]["key"] = key;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_redaction_event(const std::string& room_id, const std::string& sender,
                                       const std::string& redacts_event_id,
                                       const std::string& reason = "") {
        json event;
        event["type"] = "m.room.redaction";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["redacts"] = redacts_event_id;
        if (!reason.empty()) event["content"]["reason"] = reason;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_encryption_event(const std::string& room_id, const std::string& sender,
                                        const std::string& algorithm = "m.megolm.v1.aes-sha2",
                                        int rotation_period_ms = 604800000,
                                        int rotation_period_msgs = 100) {
        json event;
        event["type"] = "m.room.encryption";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["algorithm"] = algorithm;
        event["content"]["rotation_period_ms"] = rotation_period_ms;
        event["content"]["rotation_period_msgs"] = rotation_period_msgs;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_name_event(const std::string& room_id, const std::string& sender,
                                  const std::string& name) {
        json event;
        event["type"] = "m.room.name";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["name"] = name;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_topic_event(const std::string& room_id, const std::string& sender,
                                   const std::string& topic) {
        json event;
        event["type"] = "m.room.topic";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["topic"] = topic;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_avatar_event(const std::string& room_id, const std::string& sender,
                                    const std::string& url) {
        json event;
        event["type"] = "m.room.avatar";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["url"] = url;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_join_rules_event(const std::string& room_id, const std::string& sender,
                                        const std::string& join_rule) {
        json event;
        event["type"] = "m.room.join_rules";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["join_rule"] = join_rule;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_guest_access_event(const std::string& room_id, const std::string& sender,
                                          const std::string& guest_access) {
        json event;
        event["type"] = "m.room.guest_access";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["guest_access"] = guest_access;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_history_visibility_event(const std::string& room_id,
                                                const std::string& sender,
                                                const std::string& visibility) {
        json event;
        event["type"] = "m.room.history_visibility";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["history_visibility"] = visibility;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_canonical_alias_event(const std::string& room_id, const std::string& sender,
                                             const std::string& alias = "",
                                             const std::vector<std::string>& alt_aliases = {}) {
        json event;
        event["type"] = "m.room.canonical_alias";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        if (!alias.empty()) event["content"]["alias"] = alias;
        if (!alt_aliases.empty()) event["content"]["alt_aliases"] = alt_aliases;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_tombstone_event(const std::string& room_id, const std::string& sender,
                                       const std::string& replacement_room,
                                       const std::string& body = "") {
        json event;
        event["type"] = "m.room.tombstone";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["replacement_room"] = replacement_room;
        if (!body.empty()) event["content"]["body"] = body;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_server_acl_event(const std::string& room_id, const std::string& sender,
                                        const std::vector<std::string>& allow = {},
                                        const std::vector<std::string>& deny = {},
                                        bool allow_ip_literals = true) {
        json event;
        event["type"] = "m.room.server_acl";
        event["state_key"] = "";
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["allow"] = allow;
        event["content"]["deny"] = deny;
        event["content"]["allow_ip_literals"] = allow_ip_literals;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_third_party_invite_event(const std::string& room_id,
                                                const std::string& sender,
                                                const std::string& display_name,
                                                const std::string& key_validity_url,
                                                const std::string& public_key,
                                                const json& public_keys = {}) {
        json event;
        event["type"] = "m.room.third_party_invite";
        event["state_key"] = generate_invite_token();
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["display_name"] = display_name;
        event["content"]["key_validity_url"] = key_validity_url;
        event["content"]["public_key"] = public_key;
        if (!public_keys.is_null()) event["content"]["public_keys"] = public_keys;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_space_child_event(const std::string& room_id, const std::string& sender,
                                         const std::string& child_room_id,
                                         bool suggested = false,
                                         const std::string& via = "",
                                         const std::string& order = "") {
        json event;
        event["type"] = "m.space.child";
        event["state_key"] = child_room_id;
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["via"] = json::array();
        if (!via.empty()) event["content"]["via"].push_back(via);
        if (suggested) event["content"]["suggested"] = true;
        if (!order.empty()) event["content"]["order"] = order;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_space_parent_event(const std::string& room_id, const std::string& sender,
                                          const std::string& parent_room_id,
                                          bool canonical = false,
                                          const std::string& via = "") {
        json event;
        event["type"] = "m.space.parent";
        event["state_key"] = parent_room_id;
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["via"] = json::array();
        if (!via.empty()) event["content"]["via"].push_back(via);
        if (canonical) event["content"]["canonical"] = true;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_widget_event(const std::string& room_id, const std::string& sender,
                                    const std::string& widget_id, const std::string& widget_type,
                                    const std::string& url, const std::string& name = "",
                                    bool wait_for_iframe_load = true) {
        json event;
        event["type"] = "im.vector.modular.widgets";
        event["state_key"] = widget_id;
        event["sender"] = sender;
        event["room_id"] = room_id;
        event["content"]["type"] = widget_type;
        event["content"]["url"] = url;
        event["content"]["waitForIframeLoad"] = wait_for_iframe_load;
        if (!name.empty()) event["content"]["name"] = name;
        event["content"]["data"] = json::object();
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

    static json build_poll_start_event(const std::string& room_id, const std::string& sender,
                                        const std::string& question,
                                        const std::vector<json>& answers,
                                        int max_selections = 1) {
        json event;
        event["type"] = "m.poll.start";
        event["sender"] = sender;
        event["room_id"] = room_id;
        json poll_content;
        poll_content["m.poll"]["question"]["body"] = question;
        poll_content["m.poll"]["question"]["kind"] = "m.text";
        poll_content["m.poll"]["answers"] = answers;
        poll_content["m.poll"]["max_selections"] = max_selections;
        poll_content["m.text"] = question + "\n" + format_poll_answers(answers);
        event["content"] = poll_content;
        event["event_id"] = generate_event_id(sender);
        event["origin_server_ts"] = std::to_string(current_ts_ms());
        return event;
    }

private:
    static int64_t current_ts_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static std::string generate_event_id(const std::string& sender) {
        static std::atomic<uint64_t> c{0};
        auto ts = current_ts_ms();
        return "$" + std::to_string(ts) + "-" + std::to_string(c.fetch_add(1));
    }

    static std::string generate_media_id() {
        static std::atomic<uint64_t> mc{0};
        return "media_" + std::to_string(mc.fetch_add(1));
    }

    static std::string generate_invite_token() {
        static const char* hex = "0123456789abcdef";
        std::string token;
        for (int i = 0; i < 32; i++) token += hex[rand() % 16];
        return token;
    }

    static std::string extract_filename(const std::string& body) { return body; }

    static std::string format_poll_answers(const std::vector<json>& answers) {
        std::stringstream ss;
        for (size_t i = 0; i < answers.size(); i++) {
            ss << (i+1) << ". " << answers[i].value("m.text", "") << "\n";
        }
        return ss.str();
    }
};

} // namespace events
} // namespace progressive
