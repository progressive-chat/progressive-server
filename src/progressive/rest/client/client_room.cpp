#include "progressive/rest/client/client_room.hpp"
#include "progressive/rest/rest_base.hpp"
#include "progressive/storage/database.hpp"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace progressive::rest {

// ====== ROOM CREATE ======
class RoomCreateServlet : public BaseRestServlet {
public:
    RoomCreateServlet(DatabasePool& db) : BaseRestServlet(db, "POST", "/createRoom") {}
    
    json on_POST(const HttpRequest& req) override {
        auto user = require_auth(req);
        auto body = req.json_body();
        
        std::string room_id = "!" + generate_id() + ":" + server_name_;
        std::string room_alias = body.value("room_alias_name", "");
        std::string name = body.value("name", "");
        std::string topic = body.value("topic", "");
        bool is_public = body.value("visibility", "private") == "public";
        std::string preset = body.value("preset", is_public ? "public_chat" : "private_chat");
        std::vector<std::string> invite = body.value("invite", json::array());
        json initial_state = body.value("initial_state", json::array());
        std::string room_version = body.value("room_version", "10");
        std::string creation_content_json = body.value("creation_content", json::object()).dump();
        json power_level_content_override = body.value("power_level_content_override", json::object());
        bool is_direct = body.value("is_direct", false);
        
        // Run creation in transaction
        db_pool_.runInteraction("create_room", [&](auto& txn) {
            // Store room
            txn.execute("INSERT INTO rooms (room_id, is_public, creator, room_version) VALUES (?,?,?,?)",
                {room_id, is_public?1:0, user, room_version});
            
            // Store alias
            if(!room_alias.empty()) {
                txn.execute("INSERT INTO room_aliases (room_alias, room_id, creator) VALUES (?,?,?)",
                    {room_alias, room_id, user});
            }
            
            // Create event - m.room.create
            json create_content; create_content["creator"] = user; create_content["room_version"] = room_version;
            if(body.contains("creation_content") && body["creation_content"].contains("type"))
                create_content["type"] = body["creation_content"]["type"];
            persist_event(txn, room_id, "m.room.create", user, "", create_content, 0);
            
            // Power levels
            json pl = get_default_power_levels(user, preset);
            if(!power_level_content_override.empty()) pl.update(power_level_content_override);
            persist_event(txn, room_id, "m.room.power_levels", user, "", pl, 1);
            
            // Join rules
            json join_rules; join_rules["join_rule"] = is_public ? "public" : "invite";
            persist_event(txn, room_id, "m.room.join_rules", user, "", join_rules, 2);
            
            // History visibility
            json hist_vis; hist_vis["history_visibility"] = preset == "public_chat" ? "shared" : "joined";
            persist_event(txn, room_id, "m.room.history_visibility", user, "", hist_vis, 3);
            
            // Guest access
            json guest_access; guest_access["guest_access"] = is_public ? "can_join" : "forbidden";
            persist_event(txn, room_id, "m.room.guest_access", user, "", guest_access, 4);
            
            int depth = 5;
            // Room name
            if(!name.empty()) {
                json name_content; name_content["name"] = name;
                persist_event(txn, room_id, "m.room.name", user, "", name_content, depth++);
            }
            // Room topic
            if(!topic.empty()) {
                json topic_content; topic_content["topic"] = topic;
                persist_event(txn, room_id, "m.room.topic", user, "", topic_content, depth++);
            }
            // Initial state events
            for(auto& se : initial_state) {
                if(se.contains("type") && se.contains("content")) {
                    std::string sk = se.value("state_key", "");
                    persist_event(txn, room_id, se["type"], user, sk, se["content"], depth++);
                }
            }
            // Member event for creator
            json member_content; member_content["membership"] = "join"; member_content["displayname"] = user;
            persist_event(txn, room_id, "m.room.member", user, user, member_content, depth++);
            
            // Invites
            for(auto& invitee : invite) {
                json inv_content; inv_content["membership"] = "invite"; inv_content["displayname"] = invitee;
                persist_event(txn, room_id, "m.room.member", user, invitee, inv_content, depth++);
            }
            
            // Initialize room stats
            txn.execute("INSERT INTO room_stats_state (room_id) VALUES (?)", {room_id});
            txn.execute("INSERT INTO room_depth (room_id, min_depth) VALUES (?,0)", {room_id});
        });
        
        json resp;
        resp["room_id"] = room_id;
        if(!room_alias.empty()) resp["room_alias"] = "#" + room_alias + ":" + server_name_;
        return resp;
    }
private:
    std::string server_name_ = "localhost";
    void persist_event(LoggingTransaction& txn, const std::string& room_id,
                       const std::string& type, const std::string& sender,
                       const std::string& state_key, const json& content, int depth) {
        std::string event_id = "$" + generate_id() + ":" + server_name_;
        int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        txn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?",
            {event_id,room_id,type,sender,state_key,"",(int64_t)depth,ts,(int64_t)0,"",ts,(int64_t)depth,1,0,0,0,1,0,0,"","","",content.dump(),"{}","{}","10",0});
        txn.execute("INSERT INTO event_json VALUES (?,?,?,?,?)", {event_id,room_id,"{}",content.dump(),1});
        if(!state_key.empty()) {
            txn.execute("INSERT INTO current_state_events VALUES (?,?,?,?) ON CONFLICT(room_id,type,state_key) DO UPDATE SET event_id=excluded.event_id",
                {event_id,room_id,type,state_key});
        }
    }
    json get_default_power_levels(const std::string& user, const std::string& preset) {
        json pl;
        pl["ban"] = 50; pl["invite"] = 0; pl["kick"] = 50; pl["redact"] = 50;
        pl["events_default"] = 0; pl["state_default"] = 50; pl["users_default"] = 0;
        pl["users"] = json::object(); pl["users"][user] = 100;
        pl["events"] = json::object();
        pl["events"]["m.room.name"] = 50; pl["events"]["m.room.power_levels"] = 100;
        pl["events"]["m.room.history_visibility"] = 100; pl["events"]["m.room.canonical_alias"] = 50;
        pl["events"]["m.room.avatar"] = 50; pl["events"]["m.room.tombstone"] = 100;
        pl["events"]["m.room.server_acl"] = 100; pl["events"]["m.room.encryption"] = 100;
        return pl;
    }
    std::string generate_id() {
        static const char c[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::string id(18,'A'); for(auto& ch:id)ch=c[rand()%62]; return id;
    }
};

// ====== ROOM JOIN ======
class RoomJoinServlet : public BaseRestServlet {
public:
    RoomJoinServlet(DatabasePool& db) : BaseRestServlet(db, "POST", "/rooms/{roomId}/join") {}
    json on_POST(const HttpRequest& req) override {
        auto user = require_auth(req);
        std::string room_id = req.path_param("roomId");
        auto body = req.json_body();
        std::vector<std::string> server_name = body.value("server_name", json::array());
        
        // Check if room exists locally
        bool exists = false;
        db_pool_.runInteraction("join", [&](auto& txn) {
            auto r = txn.select_one("SELECT 1 FROM rooms WHERE room_id=?", {room_id});
            exists = r && !r->is_null();
        });
        
        if(!exists) {
            // Try federation
            json fed_resp = federation_lookup(room_id, server_name);
            if(fed_resp.empty()) return json{{"errcode","M_NOT_FOUND"},{"error","Room not found"}};
        }
        
        json join_resp;
        db_pool_.runInteraction("join", [&](auto& txn) {
            // Check membership
            auto cur = txn.select_one("SELECT membership FROM local_current_membership WHERE user_id=? AND room_id=?", {user, room_id});
            std::string cur_mem = cur && !cur->is_null() ? cur->get<std::string>(0) : "";
            if(cur_mem == "join") { join_resp = {{"error","already joined"}}; return; }
            if(cur_mem == "ban") { join_resp = {{"errcode","M_FORBIDDEN"},{"error","banned"}}; return; }
            
            // Get room details
            auto room = get_room_details(txn, room_id);
            
            // Create join event
            json member_content; member_content["membership"] = "join"; member_content["displayname"] = user;
            std::string event_id = "$" + generate_id() + ":" + server_name_;
            int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            
            // Get next depth
            auto max_depth = txn.select_one("SELECT COALESCE(MAX(depth),0) FROM events WHERE room_id=?", {room_id});
            int64_t depth = (max_depth ? max_depth->get<int64_t>(0) : 0) + 1;
            
            // Get stream ordering
            auto max_so = txn.select_one("SELECT COALESCE(MAX(stream_ordering),0) FROM events", {});
            int64_t so = (max_so ? max_so->get<int64_t>(0) : 0) + 1;
            
            txn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                {event_id,room_id,"m.room.member",user,user,cur_mem,depth,ts,so,"",ts,depth,1,0,0,0,1,1,0,"","","",member_content.dump(),"{}","{}","10",0});
            txn.execute("INSERT INTO event_json VALUES (?,?,?,?,?)", {event_id,room_id,"{}",member_content.dump(),1});
            txn.execute("INSERT INTO current_state_events VALUES (?,?,?,?) ON CONFLICT(room_id,type,state_key) DO UPDATE SET event_id=excluded.event_id",
                {event_id,room_id,"m.room.member",user});
            txn.execute("INSERT INTO room_memberships VALUES (?,?,?,?,?,?,?,?)", {event_id,user,user,room_id,"join",0,"",""});
            txn.execute("INSERT INTO local_current_membership VALUES (?,?,?,?) ON CONFLICT(user_id,room_id) DO UPDATE SET event_id=excluded.event_id,membership=excluded.membership",
                {room_id,user,event_id,"join"});
            
            join_resp["room_id"] = room_id;
        });
        
        return join_resp;
    }
};

// ====== ROOM LEAVE ======
class RoomLeaveServlet : public BaseRestServlet {
public:
    RoomLeaveServlet(DatabasePool& db) : BaseRestServlet(db, "POST", "/rooms/{roomId}/leave") {}
    json on_POST(const HttpRequest& req) override {
        auto user = require_auth(req);
        std::string room_id = req.path_param("roomId");
        db_pool_.runInteraction("leave", [&](auto& txn) {
            std::string event_id = "$" + generate_id() + ":" + server_name_;
            int64_t ts = now_ms();
            json content; content["membership"] = "leave";
            int64_t depth = get_next_depth(txn, room_id);
            int64_t so = get_next_stream(txn);
            txn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                {event_id,room_id,"m.room.member",user,user,"leave",depth,ts,so,"",ts,depth,1,0,0,0,1,0,0,"","","",content.dump(),"{}","{}","10",0});
            txn.execute("INSERT INTO room_memberships VALUES (?,?,?,?,?,?,?,?)", {event_id,user,user,room_id,"leave",0,"",""});
            txn.execute("DELETE FROM local_current_membership WHERE user_id=? AND room_id=?", {user,room_id});
        });
        return json::object();
    }
};

// ====== ROOM KICK ======
class RoomKickServlet : public BaseRestServlet {
public:
    RoomKickServlet(DatabasePool& db) : BaseRestServlet(db, "POST", "/rooms/{roomId}/kick") {}
    json on_POST(const HttpRequest& req) override {
        auto user = require_auth(req);
        std::string room_id = req.path_param("roomId");
        auto body = req.json_body();
        std::string target = body["user_id"];
        std::string reason = body.value("reason", "");
        db_pool_.runInteraction("kick", [&](auto& txn) {
            auto pl = get_power_level(txn, user, room_id);
            auto target_pl = get_power_level(txn, target, room_id);
            if(pl < 50) throw std::runtime_error("not enough power");
            if(target_pl >= pl) throw std::runtime_error("cannot kick equal/higher power");
            std::string event_id = "$" + generate_id();
            int64_t ts = now_ms(); int64_t d = get_next_depth(txn, room_id); int64_t s = get_next_stream(txn);
            json c; c["membership"] = "leave"; if(!reason.empty()) c["reason"] = reason;
            txn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                {event_id,room_id,"m.room.member",user,target,"leave",d,ts,s,"",ts,d,1,0,0,0,1,0,0,"","",user,c.dump(),"{}","{}","10",0});
            txn.execute("INSERT INTO room_memberships VALUES (?,?,?,?,?,?,?,?)", {event_id,target,user,room_id,"leave",0,"",""});
            txn.execute("DELETE FROM local_current_membership WHERE user_id=? AND room_id=?", {target,room_id});
        });
        return json::object();
    }
};

// ====== ROOM BAN ======
class RoomBanServlet : public BaseRestServlet {
public:
    RoomBanServlet(DatabasePool& db) : BaseRestServlet(db, "POST", "/rooms/{roomId}/ban") {}
    json on_POST(const HttpRequest& req) override {
        auto user = require_auth(req);
        std::string room_id = req.path_param("roomId");
        auto body = req.json_body(); std::string target=body["user_id"]; std::string reason=body.value("reason","");
        db_pool_.runInteraction("ban", [&](auto& txn) {
            auto pl=get_power_level(txn,user,room_id); if(pl<50) throw std::runtime_error("no power");
            std::string eid="$"+generate_id(); int64_t ts=now_ms(); int64_t d=get_next_depth(txn,room_id); int64_t s=get_next_stream(txn);
            json c; c["membership"]="ban"; if(!reason.empty())c["reason"]=reason;
            txn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                {eid,room_id,"m.room.member",user,target,"ban",d,ts,s,"",ts,d,1,0,0,0,1,0,0,"","",user,c.dump(),"{}","{}","10",0});
            txn.execute("DELETE FROM local_current_membership WHERE user_id=? AND room_id=?", {target,room_id});
        });
        return json::object();
    }
};

// ====== ROOM INVITE ======
class RoomInviteServlet : public BaseRestServlet {
public:
    RoomInviteServlet(DatabasePool& db) : BaseRestServlet(db, "POST", "/rooms/{roomId}/invite") {}
    json on_POST(const HttpRequest& req) override {
        auto user=require_auth(req); std::string room_id=req.path_param("roomId");
        auto body=req.json_body(); std::string target=body["user_id"]; std::string reason=body.value("reason","");
        db_pool_.runInteraction("invite",[&](auto& txn) {
            std::string eid="$"+generate_id(); int64_t ts=now_ms(); int64_t d=get_next_depth(txn,room_id); int64_t s=get_next_stream(txn);
            json c; c["membership"]="invite"; if(!reason.empty())c["reason"]=reason;
            txn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                {eid,room_id,"m.room.member",user,target,"invite",d,ts,s,"",ts,d,1,0,0,0,1,0,0,"","",user,c.dump(),"{}","{}","10",0});
            txn.execute("INSERT INTO current_state_events VALUES (?,?,?,?) ON CONFLICT(room_id,type,state_key) DO UPDATE SET event_id=excluded.event_id",
                {eid,room_id,"m.room.member",target});
        });
        return json::object();
    }
};

// ====== ROOM UNBAN ======
class RoomUnbanServlet : public BaseRestServlet {
public:
    RoomUnbanServlet(DatabasePool& db) : BaseRestServlet(db, "POST", "/rooms/{roomId}/unban") {}
    json on_POST(const HttpRequest& req) override {
        auto user=require_auth(req); std::string room_id=req.path_param("roomId"); auto body=req.json_body(); std::string target=body["user_id"];
        db_pool_.runInteraction("unban",[&](auto& txn) {
            std::string eid="$"+generate_id(); int64_t ts=now_ms(); int64_t d=get_next_depth(txn,room_id); int64_t s=get_next_stream(txn);
            json c; c["membership"]="leave";
            txn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                {eid,room_id,"m.room.member",user,target,"leave",d,ts,s,"",ts,d,1,0,0,0,1,0,0,"","",user,c.dump(),"{}","{}","10",0});
            txn.execute("INSERT INTO current_state_events VALUES (?,?,?,?) ON CONFLICT(room_id,type,state_key) DO UPDATE SET event_id=excluded.event_id",
                {eid,room_id,"m.room.member",target});
        });
        return json::object();
    }
};

// ====== ROOM STATE ======
class RoomStateServlet : public BaseRestServlet {
public:
    RoomStateServlet(DatabasePool& db) : BaseRestServlet(db, "GET", "/rooms/{roomId}/state") {}
    json on_GET(const HttpRequest& req) override {
        auto user=require_auth(req); std::string room_id=req.path_param("roomId");
        json state=json::array();
        db_pool_.runInteraction("state_read",[&](auto& txn) {
            auto rows=txn.select("SELECT type,state_key,event_id FROM current_state_events WHERE room_id=?",{room_id});
            for(auto& row:rows) {
                auto ev=txn.select_one("SELECT content FROM event_json WHERE event_id=?",{row.get<std::string>(2)});
                json s; s["type"]=row.get<std::string>(0); s["state_key"]=row.get<std::string>(1);
                s["content"]=ev&&!ev->is_null()?json::parse(ev->get<std::string>(0)):json::object();
                s["event_id"]=row.get<std::string>(2); state.push_back(s);
            }
        });
        return state;
    }
};

// ====== ROOM STATE EVENT ======
class RoomStateEventServlet : public BaseRestServlet {
public:
    RoomStateEventServlet(DatabasePool& db) : BaseRestServlet(db, "PUT", "/rooms/{roomId}/state/{eventType}/{stateKey}") {}
    json on_PUT(const HttpRequest& req) override {
        auto user=require_auth(req); std::string room_id=req.path_param("roomId");
        std::string type=req.path_param("eventType"); std::string state_key=req.path_param("stateKey");
        auto body=req.json_body();
        std::string eid;
        db_pool_.runInteraction("state_put",[&](auto& txn) {
            eid="$"+generate_id(); int64_t ts=now_ms(); int64_t d=get_next_depth(txn,room_id); int64_t s=get_next_stream(txn);
            txn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                {eid,room_id,type,user,state_key,"",d,ts,s,"",ts,d,1,0,0,0,1,0,0,"","",user,body.dump(),"{}","{}","10",0});
            txn.execute("INSERT INTO event_json VALUES (?,?,?,?,?)",{eid,room_id,"{}",body.dump(),1});
            txn.execute("INSERT INTO current_state_events VALUES (?,?,?,?) ON CONFLICT(room_id,type,state_key) DO UPDATE SET event_id=excluded.event_id",
                {eid,room_id,type,state_key});
        });
        json resp; resp["event_id"]=eid; return resp;
    }
};

// ====== ROOM MEMBERS ======
class RoomMembersServlet : public BaseRestServlet {
public:
    RoomMembersServlet(DatabasePool& db) : BaseRestServlet(db, "GET", "/rooms/{roomId}/members") {}
    json on_GET(const HttpRequest& req) override {
        require_auth(req); std::string room_id=req.path_param("roomId");
        std::string membership=req.query_param("membership","join");
        std::string not_membership=req.query_param("not_membership","");
        json resp; resp["chunk"]=json::array();
        db_pool_.runInteraction("members",[&](auto& txn) {
            std::string q="SELECT e.event_id,e.content FROM events e JOIN current_state_events cs ON e.event_id=cs.event_id WHERE cs.room_id=? AND cs.type='m.room.member'";
            std::vector<DatabaseType> p={room_id};
            if(!membership.empty()){q+=" AND json_extract(e.content,'$.membership')=?"; p.push_back(membership);}
            if(!not_membership.empty()){q+=" AND json_extract(e.content,'$.membership')!=?"; p.push_back(not_membership);}
            auto rows=txn.select(q,p);
            for(auto& row:rows) {
                json m; m["user_id"]=row.get<std::string>(0);
                json c=json::parse(row.get<std::string>(1));
                if(c.contains("displayname"))m["display_name"]=c["displayname"];
                if(c.contains("avatar_url"))m["avatar_url"]=c["avatar_url"];
                resp["chunk"].push_back(m);
            }
        });
        return resp;
    }
};

// ====== SYNC ======
class SyncServlet : public BaseRestServlet {
public:
    SyncServlet(DatabasePool& db) : BaseRestServlet(db, "GET", "/sync") {}
    json on_GET(const HttpRequest& req) override {
        auto user=require_auth(req);
        std::string since=req.query_param("since","");
        std::string filter=req.query_param("filter","");
        bool full_state=req.query_param("full_state","false")=="true";
        std::string set_presence=req.query_param("set_presence","online");
        int timeout=std::stoi(req.query_param("timeout","0"));
        
        int64_t since_stream=since.empty()?0:std::stoll(since);
        int64_t to_stream=0;
        
        json resp; resp["next_batch"]=""; resp["rooms"]=json::object();
        resp["rooms"]["join"]=json::object(); resp["rooms"]["invite"]=json::object(); resp["rooms"]["leave"]=json::object();
        resp["presence"]=json::object(); resp["presence"]["events"]=json::array();
        resp["account_data"]=json::object(); resp["account_data"]["events"]=json::array();
        resp["to_device"]=json::object(); resp["to_device"]["events"]=json::array();
        resp["device_lists"]=json::object(); resp["device_lists"]["changed"]=json::array(); resp["device_lists"]["left"]=json::array();
        resp["device_one_time_keys_count"]=json::object();
        
        db_pool_.runInteraction("sync",[&](auto& txn) {
            // Get rooms user is in
            auto rooms=txn.select("SELECT room_id,event_id,membership FROM local_current_membership WHERE user_id=?",{user});
            for(auto& room_row:rooms) {
                std::string room_id=room_row.get<std::string>(0); std::string membership=room_row.get<std::string>(2);
                
                json room_data; room_data["timeline"]=json::object(); room_data["timeline"]["events"]=json::array();
                room_data["timeline"]["prev_batch"]=since;
                room_data["timeline"]["limited"]=false;
                
                // State
                room_data["state"]=json::object(); room_data["state"]["events"]=json::array();
                auto state_rows=txn.select("SELECT type,state_key,event_id FROM current_state_events WHERE room_id=?",{room_id});
                for(auto& sr:state_rows) {
                    auto cev=txn.select_one("SELECT content FROM event_json WHERE event_id=?",{sr.get<std::string>(2)});
                    json se; se["type"]=sr.get<std::string>(0); se["state_key"]=sr.get<std::string>(1); se["event_id"]=sr.get<std::string>(2);
                    if(cev&&!cev->is_null())se["content"]=json::parse(cev->get<std::string>(0));
                    room_data["state"]["events"].push_back(se);
                }
                
                // Timeline events since last sync
                auto evs=txn.select("SELECT event_id,type,sender,content,origin_server_ts,state_key FROM events WHERE room_id=? AND stream_ordering>? AND is_outlier=0 ORDER BY stream_ordering LIMIT 50",
                    {room_id,since_stream});
                for(auto& ev:evs) {
                    json e; e["event_id"]=ev.get<std::string>(0); e["type"]=ev.get<std::string>(1); e["sender"]=ev.get<std::string>(2);
                    e["content"]=json::parse(ev.get<std::string>(3)); e["origin_server_ts"]=ev.get<int64_t>(4); e["unsigned"]=json::object();
                    if(!ev.is_null(5))e["state_key"]=ev.get<std::string>(5);
                    room_data["timeline"]["events"].push_back(e);
                    int64_t so=0; /* get stream from event */ to_stream=std::max(to_stream,so);
                }
                
                if(membership=="join") resp["rooms"]["join"][room_id]=room_data;
                else if(membership=="invite") resp["rooms"]["invite"][room_id]=room_data;
                else resp["rooms"]["leave"][room_id]=room_data;
            }
        });
        
        resp["next_batch"]=std::to_string(to_stream>0?to_stream:since_stream);
        return resp;
    }
};

// ====== ROOM EVENTS ======
class RoomEventsServlet : public BaseRestServlet {
public:
    RoomEventsServlet(DatabasePool& db) : BaseRestServlet(db, "GET", "/rooms/{roomId}/messages") {}
    json on_GET(const HttpRequest& req) override {
        auto user=require_auth(req); std::string room_id=req.path_param("roomId");
        std::string from=req.query_param("from",""); std::string to=req.query_param("to","");
        std::string dir=req.query_param("dir","b"); int limit=std::stoi(req.query_param("limit","10"));
        std::string filter=req.query_param("filter","");
        
        int64_t from_so=from.empty()?INT64_MAX:std::stoll(from);
        int64_t to_so=to.empty()?0:std::stoll(to);
        
        json resp; resp["chunk"]=json::array(); resp["start"]=""; resp["end"]="";
        
        db_pool_.runInteraction("messages",[&](auto& txn) {
            std::string q="SELECT event_id,type,sender,content,origin_server_ts,state_key,stream_ordering FROM events WHERE room_id=? AND is_outlier=0";
            std::vector<DatabaseType> p={room_id};
            if(dir=="b"){q+=" AND stream_ordering < ? ORDER BY stream_ordering DESC LIMIT ?"; p.push_back(from_so); p.push_back(limit);}
            else{q+=" AND stream_ordering > ? ORDER BY stream_ordering ASC LIMIT ?"; p.push_back(to_so); p.push_back(limit);}
            
            auto rows=txn.select(q,p); int64_t first_so=0,last_so=0; bool first=true;
            for(auto& row:rows) {
                json ev; ev["event_id"]=row.get<std::string>(0); ev["type"]=row.get<std::string>(1); ev["sender"]=row.get<std::string>(2);
                ev["content"]=json::parse(row.get<std::string>(3)); ev["origin_server_ts"]=row.get<int64_t>(4);
                if(!row.is_null(5))ev["state_key"]=row.get<std::string>(5);
                ev["unsigned"]=json::object();
                int64_t so=row.get<int64_t>(6);
                if(first){first_so=so;first=false;} last_so=so;
                resp["chunk"].push_back(ev);
            }
            resp["start"]=std::to_string(first_so); resp["end"]=std::to_string(last_so);
        });
        return resp;
    }
};

// ====== ROOM EVENT SEND ======
class RoomSendServlet : public BaseRestServlet {
public:
    RoomSendServlet(DatabasePool& db) : BaseRestServlet(db, "PUT", "/rooms/{roomId}/send/{eventType}/{txnId}") {}
    json on_PUT(const HttpRequest& req) override {
        auto user=require_auth(req); std::string room_id=req.path_param("roomId");
        std::string type=req.path_param("eventType"); std::string txn_id=req.path_param("txnId");
        auto body=req.json_body();
        std::string event_id;
        db_pool_.runInteraction("send",[&](auto& txn) {
            // Idempotency check
            auto existing=txn.select_one("SELECT event_id FROM events WHERE sender=? AND transaction_id=?",{user,txn_id});
            if(existing&&!existing->is_null()){event_id=existing->get<std::string>(0); return;}
            
            event_id="$"+generate_id()+":"+server_name_;
            int64_t ts=now_ms(); int64_t d=get_next_depth(txn,room_id); int64_t s=get_next_stream(txn);
            std::string sk=body.value("state_key","");
            bool is_state=!sk.empty();
            bool has_url=body.dump().find("http")!=std::string::npos;
            txn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                {event_id,room_id,type,user,sk,"",d,ts,s,"",ts,d,1,0,0,0,is_state?1:0,1,has_url?1:0,"","","",body.dump(),"{}","{}","10",0});
            txn.execute("INSERT INTO event_json VALUES (?,?,?,?,?)",{event_id,room_id,"{}",body.dump(),1});
            if(is_state) txn.execute("INSERT INTO current_state_events VALUES (?,?,?,?) ON CONFLICT(room_id,type,state_key) DO UPDATE SET event_id=excluded.event_id",
                {event_id,room_id,type,sk});
        });
        json resp; resp["event_id"]=event_id; return resp;
    }
};

// ====== REGISTRATION ======
void register_client_room_servlets(ServletRegistry& reg, DatabasePool& db) {
    reg.register_servlet(std::make_shared<RoomCreateServlet>(db));
    reg.register_servlet(std::make_shared<RoomJoinServlet>(db));
    reg.register_servlet(std::make_shared<RoomLeaveServlet>(db));
    reg.register_servlet(std::make_shared<RoomKickServlet>(db));
    reg.register_servlet(std::make_shared<RoomBanServlet>(db));
    reg.register_servlet(std::make_shared<RoomInviteServlet>(db));
    reg.register_servlet(std::make_shared<RoomUnbanServlet>(db));
    reg.register_servlet(std::make_shared<RoomStateServlet>(db));
    reg.register_servlet(std::make_shared<RoomStateEventServlet>(db));
    reg.register_servlet(std::make_shared<RoomMembersServlet>(db));
    reg.register_servlet(std::make_shared<SyncServlet>(db));
    reg.register_servlet(std::make_shared<RoomEventsServlet>(db));
    reg.register_servlet(std::make_shared<RoomSendServlet>(db));
}

} // namespace
