// progressive-server: Matrix room alias, directory, and third-party network handlers
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <mutex>
#include <functional>
#include "../json.hpp"

namespace progressive {
namespace handlers {

using json = nlohmann::json;

class RoomAliasHandler {
    std::unordered_map<std::string, std::string> alias_to_room_;
    std::unordered_map<std::string, std::vector<std::string>> room_to_aliases_;
    std::mutex mutex_;
public:
    json create_alias(const std::string& alias, const std::string& room_id, const std::string& user_id) {
        std::lock_guard lock(mutex_);
        if (alias_to_room_.count(alias)) return json({{"errcode","M_ALIAS_IN_USE"},{"error","Alias already in use"}});
        auto pos = alias.find(':'); if (pos == std::string::npos) return json({{"errcode","M_INVALID_PARAM"},{"error","Invalid alias format"}});
        alias_to_room_[alias] = room_id;
        room_to_aliases_[room_id].push_back(alias);
        return json::object();
    }
    json get_alias(const std::string& alias) {
        auto it = alias_to_room_.find(alias);
        if (it == alias_to_room_.end()) return json({{"errcode","M_NOT_FOUND"},{"error","Alias not found"}});
        return json({{"room_id",it->second},{"servers",json::array({"localhost"})}});
    }
    json delete_alias(const std::string& alias, const std::string& user_id) {
        std::lock_guard lock(mutex_);
        auto it = alias_to_room_.find(alias);
        if (it == alias_to_room_.end()) return json({{"errcode","M_NOT_FOUND"}});
        auto& aliases = room_to_aliases_[it->second];
        aliases.erase(std::remove(aliases.begin(),aliases.end(),alias),aliases.end());
        alias_to_room_.erase(it);
        return json::object();
    }
    std::vector<std::string> get_room_aliases(const std::string& room_id) {
        auto it = room_to_aliases_.find(room_id);
        return (it != room_to_aliases_.end()) ? it->second : std::vector<std::string>{};
    }
};

class PublicRoomListHandler {
    struct PublicRoom { std::string room_id; std::string name; std::string topic; int num_joined_members; std::string avatar_url; std::string world_readable; std::string guest_can_join; std::string canonical_alias; };
    std::vector<PublicRoom> public_rooms_;
    std::mutex mutex_;
public:
    void add_public_room(const PublicRoom& room) { std::lock_guard lock(mutex_); public_rooms_.push_back(room); }
    void remove_public_room(const std::string& room_id) { std::lock_guard lock(mutex_); public_rooms_.erase(std::remove_if(public_rooms_.begin(),public_rooms_.end(),[&](const PublicRoom& r){return r.room_id==room_id;}),public_rooms_.end()); }
    json list_public_rooms(int limit, const std::string& since, const std::string& server, const std::string& search_term) {
        std::lock_guard lock(mutex_);
        json result; json chunk = json::array();
        int start = 0; if (!since.empty()) start = std::stoi(since);
        for (int i = start; i < (int)public_rooms_.size() && (int)chunk.size() < limit; i++) {
            auto& pr = public_rooms_[i];
            if (!search_term.empty() && pr.name.find(search_term) == std::string::npos && pr.topic.find(search_term) == std::string::npos) continue;
            json room; room["room_id"] = pr.room_id; room["name"] = pr.name; room["topic"] = pr.topic; room["num_joined_members"] = pr.num_joined_members;
            if (!pr.avatar_url.empty()) room["avatar_url"] = pr.avatar_url; if (!pr.world_readable.empty()) room["world_readable"] = pr.world_readable;
            if (!pr.guest_can_join.empty()) room["guest_can_join"] = pr.guest_can_join; if (!pr.canonical_alias.empty()) room["canonical_alias"] = pr.canonical_alias;
            chunk.push_back(room);
        }
        result["chunk"] = chunk; result["next_batch"] = std::to_string(start + limit); result["prev_batch"] = since; result["total_room_count_estimate"] = (int)public_rooms_.size();
        return result;
    }
};

class ThirdPartyProtocolHandler {
    struct Protocol { std::string user_fields; std::string location_fields; std::string icon; std::vector<std::string> field_types; std::vector<std::string> instances; };
    std::unordered_map<std::string, Protocol> protocols_;
public:
    ThirdPartyProtocolHandler() {
        protocols_["irc"] = {"network/channel/nickname", "", "mxc://localhost/irc_icon", {"network","channel","nickname"}, {"freenode","oftc"}};
        protocols_["gitter"] = {"room", "", "mxc://localhost/gitter_icon", {"room"}, {}};
    }
    json get_protocols() { json result; for(auto&[k,v]:protocols_){json p;p["user_fields"]=v.user_fields;p["location_fields"]=v.location_fields;p["icon"]=v.icon;p["field_types"]=v.field_types;p["instances"]=v.instances;result[k]=p;} return result; }
    json get_protocol(const std::string& protocol) { auto it=protocols_.find(protocol); if(it==protocols_.end())return json({{"errcode","M_NOT_FOUND"}}); json p;p["user_fields"]=it->second.user_fields;p["location_fields"]=it->second.location_fields;p["icon"]=it->second.icon;p["field_types"]=it->second.field_types;p["instances"]=it->second.instances;return p; }
    json get_user(const std::string& protocol, const json& fields) { return json::array(); }
    json get_location(const std::string& protocol, const json& fields) { return json::array(); }
};

class RoomDirectoryHandler {
    RoomAliasHandler aliases_;
    PublicRoomListHandler public_rooms_;
    ThirdPartyProtocolHandler third_party_;
public:
    json handle_create_alias(const std::string& alias, const std::string& room_id, const std::string& user_id) { return aliases_.create_alias(alias, room_id, user_id); }
    json handle_get_alias(const std::string& alias) { return aliases_.get_alias(alias); }
    json handle_delete_alias(const std::string& alias, const std::string& user_id) { return aliases_.delete_alias(alias, user_id); }
    json handle_list_public_rooms(int limit, const std::string& since, const std::string& server) { return public_rooms_.list_public_rooms(limit, since, server, ""); }
    json handle_search_public_rooms(const std::string& search_term, int limit) { return public_rooms_.list_public_rooms(limit, "", "", search_term); }
    json handle_get_third_party_protocols() { return third_party_.get_protocols(); }
    json handle_get_third_party_protocol(const std::string& protocol) { return third_party_.get_protocol(protocol); }
    json handle_get_third_party_user(const std::string& protocol, const json& fields) { return third_party_.get_user(protocol, fields); }
    json handle_get_third_party_location(const std::string& protocol, const json& fields) { return third_party_.get_location(protocol, fields); }
    std::vector<std::string> get_room_local_aliases(const std::string& room_id) { return aliases_.get_room_aliases(room_id); }
};

class RoomUpgradeHandler {
    std::unordered_map<std::string, std::string> tombstone_redirects_;
    std::mutex mutex_;
public:
    json upgrade_room(const std::string& old_room_id, const std::string& new_version, const std::string& user_id) {
        std::string new_room_id = "!" + generate_id(16) + ":localhost";
        json result; result["replacement_room"] = new_room_id;
        std::lock_guard lock(mutex_); tombstone_redirects_[old_room_id] = new_room_id;
        return result;
    }
    std::string get_successor(const std::string& room_id) { auto it = tombstone_redirects_.find(room_id); return (it != tombstone_redirects_.end()) ? it->second : ""; }
    static std::string generate_id(int len) { std::string r; for(int i=0;i<len;i++)r+="abcdefghijklmnopqrstuvwxyz0123456789"[rand()%36]; return r; }
};

class RoomPreviewHandler {
public:
    json get_room_preview(const std::string& room_id, const std::string& user_id) {
        json result;
        result["room_id"] = room_id; result["name"] = "Room Preview"; result["topic"] = "";
        result["num_joined_members"] = 0; result["room_type"] = ""; result["canonical_alias"] = "";
        result["world_readable"] = true; result["guest_can_join"] = false;
        result["avatar_url"] = ""; result["join_rule"] = "public";
        result["membership"] = "leave"; result["is_encrypted"] = false;
        return result;
    }
};

} // namespace handlers
} // namespace progressive
