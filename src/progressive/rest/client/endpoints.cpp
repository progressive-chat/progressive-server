#include "endpoints.hpp"

#include <nlohmann/json.hpp>

#include "../../events/event_factory.hpp"
#include "../../types/matrix_id.hpp"
#include "../../util/random.hpp"
#include "../../util/time.hpp"

namespace progressive::rest::client {

namespace bhttp = boost::beast::http;
namespace phttp = progressive::http;
using phttp::error_response;
using phttp::set_cors;
using phttp::set_json;
using ::progressive::auth::Auth;
using ::progressive::auth::AuthResult;

using Req = bhttp::request<bhttp::string_body>;
using Res = bhttp::response<bhttp::string_body>;
using Params = std::map<std::string, std::string>;

static constexpr unsigned HTTP11 = 11;

static std::string sql_esc(std::string_view s) {
  std::string out;
  for (char c : s) {
    if (c == '\'')
      out += "''";
    else
      out += c;
  }
  return out;
}

static AuthResult check_auth(auth::Auth& auth_unit, Req& req) {
  auto hdr = req[bhttp::field::authorization];
  if (hdr.empty()) {
    AuthResult r;
    r.error = "Missing access token";
    r.errcode = "M_MISSING_TOKEN";
    return r;
  }
  std::string_view h(hdr);
  if (h.starts_with("Bearer "))
    h.remove_prefix(7);
  return auth_unit.validate_token(h);
}

void register_routes(server::Server& server, progressive::http::Router& router) {
  auto* auth_ = new auth::Auth(server.db());
  auto* db_ = &server.db();
  auto sn = server.config().server.server_name;

  // versions
  router.add_route(
      bhttp::verb::get, "/_matrix/client/versions",
      [](Req&&, Params) -> Res {
        nlohmann::json j;
        j["versions"] = {"r0.6.1", "v1.1", "v1.2", "v1.3", "v1.4",  "v1.5",
                         "v1.6",   "v1.7", "v1.8", "v1.9", "v1.10", "v1.11"};
        Res r{bhttp::status::ok, HTTP11};
        set_json(r, j.dump());
        set_cors(r);
        return r;
      },
      "client_versions");

  // login
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/login",
      [auth_, db_, sn](Req&& req, Params) -> Res {
        try {
          auto body = nlohmann::json::parse(req.body());
          std::string type = body.value("type", std::string{});
          if (type != "m.login.password") {
            nlohmann::json j;
            j["flows"] = {{{"type", "m.login.password"}}};
            Res r{bhttp::status::unauthorized, HTTP11};
            set_json(r, j.dump());
            set_cors(r);
            return r;
          }
          std::string uid =
              body.value("identifier", nlohmann::json::object()).value("user", std::string{});
          if (uid.empty())
            uid = body.value("user", std::string{});
          std::string pw = body.value("password", std::string{});
          if (uid.empty() || pw.empty())
            return error_response(bhttp::status::bad_request, "M_BAD_JSON",
                                  "Missing user or password");
          auto rows = db_->query("SELECT password_hash FROM users WHERE id='" + sql_esc(uid) + "'");
          if (rows.empty() || rows[0]["password_hash"].is_null())
            return error_response(bhttp::status::forbidden, "M_FORBIDDEN",
                                  "Invalid username or password");
          if (!auth_->verify_password(pw, rows[0]["password_hash"].template get<std::string>()))
            return error_response(bhttp::status::forbidden, "M_FORBIDDEN",
                                  "Invalid username or password");
          std::string tok = auth_->create_token(uid);
          nlohmann::json resp;
          resp["user_id"] = uid;
          resp["access_token"] = tok;
          resp["home_server"] = sn;
          resp["device_id"] = "AAAAAAAAAAA";
          Res r{bhttp::status::ok, HTTP11};
          set_json(r, resp.dump());
          set_cors(r);
          return r;
        } catch (const std::exception& e) {
          return error_response(bhttp::status::bad_request, "M_BAD_JSON", e.what());
        }
      },
      "client_login");

  // register
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/register",
      [auth_, db_, sn](Req&& req, Params) -> Res {
        try {
          auto body = nlohmann::json::parse(req.body());
          std::string user = body.value("username", std::string{});
          std::string pw = body.value("password", std::string{});
          if (user.empty() || pw.empty())
            return error_response(bhttp::status::bad_request, "M_BAD_JSON",
                                  "Missing username or password");
          std::string uid = "@" + user + ":" + sn;
          auto result = auth_->register_user(uid, pw);
          if (result.contains("errcode")) {
            auto s = (result["errcode"] == "M_USER_IN_USE") ? bhttp::status::bad_request
                                                            : bhttp::status::internal_server_error;
            Res r{s, HTTP11};
            set_json(r, result.dump());
            set_cors(r);
            return r;
          }
          Res r{bhttp::status::ok, HTTP11};
          set_json(r, result.dump());
          set_cors(r);
          return r;
        } catch (const std::exception& e) {
          return error_response(bhttp::status::bad_request, "M_BAD_JSON", e.what());
        }
      },
      "client_register");

  // whoami
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/account/whoami",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json j;
        j["user_id"] = r.user_id;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, j.dump());
        set_cors(res);
        return res;
      },
      "client_whoami");

  // createRoom
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/createRoom",
      [auth_, db_, sn](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        try {
          auto body = nlohmann::json::parse(req.body());
          std::string name = body.value("name", std::string{});
          std::string room_local = "!" + util::random_token(18);
          std::string rid_str = room_local + ":" + sn;
          uint64_t now = util::now_ms();
          nlohmann::json resp;

          db_->execute("INSERT INTO rooms (room_id, creator, creation_ts) VALUES ('" +
                       sql_esc(rid_str) + "','" + sql_esc(r.user_id) + "'," + std::to_string(now) +
                       ")");

          auto rid = RoomID::from_string(rid_str);
          nlohmann::json cc;
          cc["creator"] = r.user_id;
          cc["room_version"] = "10";

          auto cev = events::create_local_event(rid, "m.room.create", r.user_id, cc, "");
          db_->execute(
              "INSERT INTO events "
              "(event_id,room_id,type,sender,content,state_key,depth,"
              "origin_server_ts,stream_ordering) VALUES ('" +
              sql_esc(cev.event_id.to_string()) + "','" + sql_esc(rid_str) + "','m.room.create','" +
              sql_esc(r.user_id) + "','" + sql_esc(cev.content.dump()) + "','',1,'" +
              sql_esc(cev.origin_server_ts) + "'," + std::to_string(now) + ")");

          nlohmann::json jc;
          jc["membership"] = "join";
          auto jev = events::create_local_event(rid, "m.room.member", r.user_id, jc, r.user_id);
          db_->execute(
              "INSERT INTO events "
              "(event_id,room_id,type,sender,content,state_key,depth,"
              "origin_server_ts,stream_ordering) VALUES ('" +
              sql_esc(jev.event_id.to_string()) + "','" + sql_esc(rid_str) + "','m.room.member','" +
              sql_esc(r.user_id) + "','" + sql_esc(jev.content.dump()) + "','" +
              sql_esc(r.user_id) + "',2,'" + sql_esc(jev.origin_server_ts) + "'," +
              std::to_string(now + 1) + ")");
          db_->execute(
              "INSERT INTO room_memberships "
              "(event_id,room_id,user_id,membership,sender) VALUES ('" +
              sql_esc(jev.event_id.to_string()) + "','" + sql_esc(rid_str) + "','" +
              sql_esc(r.user_id) + "','join','" + sql_esc(r.user_id) + "')");

          if (!name.empty()) {
            nlohmann::json nc;
            nc["name"] = name;
            auto nev = events::create_local_event(rid, "m.room.name", r.user_id, nc, "");
            db_->execute(
                "INSERT INTO events "
                "(event_id,room_id,type,sender,content,state_key,depth,"
                "origin_server_ts,stream_ordering) VALUES ('" +
                sql_esc(nev.event_id.to_string()) + "','" + sql_esc(rid_str) + "','m.room.name','" +
                sql_esc(r.user_id) + "','" + sql_esc(nev.content.dump()) + "','',3,'" +
                sql_esc(nev.origin_server_ts) + "'," + std::to_string(now + 2) + ")");
          }
          resp["room_id"] = rid_str;
          Res res{bhttp::status::ok, HTTP11};
          set_json(res, resp.dump());
          set_cors(res);
          return res;
        } catch (const std::exception& e) {
          return error_response(bhttp::status::internal_server_error, "M_UNKNOWN", e.what());
        }
      },
      "client_create_room");

  // sync
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/sync",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);

        uint64_t since = 0;
        std::string target(req.target());
        auto sp = target.find("since=");
        if (sp != std::string::npos) {
          auto ep = target.find('&', sp);
          auto val = (ep != std::string::npos) ? target.substr(sp + 6, ep - sp - 6)
                                               : target.substr(sp + 6);
          if (!val.empty() && (val[0] == 's' || val[0] == 't'))
            val = val.substr(1);
          try {
            since = std::stoull(val);
          } catch (...) {
          }
        }

        uint64_t now = util::now_ms();
        nlohmann::json resp;
        resp["next_batch"] = "s" + std::to_string(now);
        resp["rooms"] = nlohmann::json::object();
        resp["rooms"]["join"] = nlohmann::json::object();
        resp["rooms"]["invite"] = nlohmann::json::object();
        resp["rooms"]["leave"] = nlohmann::json::object();

        auto rows = db_->query(
            "SELECT DISTINCT room_id FROM room_memberships "
            "WHERE user_id='" +
            sql_esc(r.user_id) + "' AND membership='join'");
        for (auto& row : rows) {
          if (row["room_id"].is_null())
            continue;
          std::string rid = row["room_id"].template get<std::string>();
          nlohmann::json rd;
          rd["timeline"] = nlohmann::json::object();
          rd["timeline"]["events"] = nlohmann::json::array();
          rd["timeline"]["limited"] = false;
          rd["timeline"]["prev_batch"] = resp["next_batch"];
          rd["state"] = nlohmann::json::object();
          rd["state"]["events"] = nlohmann::json::array();

          auto evr = db_->query(
              std::string("SELECT event_id,type,sender,content,state_key,depth,"
                          "origin_server_ts,stream_ordering FROM events WHERE room_id='") +
              sql_esc(rid) + "'" +
              (since > 0 ? " AND stream_ordering > " + std::to_string(since) : "") +
              " ORDER BY stream_ordering");
          for (auto& ev : evr) {
            if (ev["event_id"].is_null())
              continue;
            nlohmann::json ej;
            ej["event_id"] = ev["event_id"];
            ej["type"] = ev["type"];
            ej["sender"] = ev["sender"];
            ej["room_id"] = rid;
            ej["origin_server_ts"] = ev.value("origin_server_ts", "");
            try {
              ej["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
            } catch (...) {
              ej["content"] = nlohmann::json::object();
            }
            if (!ev["state_key"].is_null() && !ev["state_key"].template get<std::string>().empty())
              ej["state_key"] = ev["state_key"];
            ej["unsigned"] = nlohmann::json::object();
            rd["timeline"]["events"].push_back(ej);
          }
          resp["rooms"]["join"][rid] = rd;
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_sync");

  // room redact
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);

        try {
          auto body = nlohmann::json::parse(req.body());
          std::string reason = body.value("reason", std::string{});

          // Check event exists in this room
          auto rows = db_->query("SELECT * FROM events WHERE event_id='" + sql_esc(p["eventId"]) +
                                 "' AND room_id='" + sql_esc(p["roomId"]) + "'");
          if (rows.empty() || rows[0]["event_id"].is_null())
            return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Event not found");

          // Create redaction event
          auto rid = RoomID::from_string(p["roomId"]);
          nlohmann::json redact_content;
          redact_content["reason"] = reason;
          redact_content["redacts"] = p["eventId"];

          auto redact_ev =
              events::create_local_event(rid, "m.room.redaction", r.user_id, redact_content);
          redact_ev.event_id = EventID::from_string("$" + util::random_token(43) + ":" + sn);

          uint64_t now = util::now_ms();
          db_->execute(
              "INSERT INTO events "
              "(event_id,room_id,type,sender,content,state_key,depth,"
              "origin_server_ts,stream_ordering) VALUES ('" +
              sql_esc(redact_ev.event_id.to_string()) + "','" + sql_esc(p["roomId"]) +
              "','m.room.redaction','" + sql_esc(r.user_id) + "','" +
              sql_esc(redact_ev.content.dump()) + "','',1,'" + sql_esc(redact_ev.origin_server_ts) +
              "'," + std::to_string(now) + ")");

          // Mark the redacted event
          nlohmann::json redacts;
          redacts["event_id"] = redact_ev.event_id.to_string();
          redacts["type"] = "m.room.redaction";
          redacts["sender"] = r.user_id;
          redacts["origin_server_ts"] = redact_ev.origin_server_ts;
          redacts["content"] = redact_content;

          db_->execute(
              "UPDATE events SET content = content || "
              "'\"redacted_because\":" +
              sql_esc(redacts.dump()) + "}' WHERE event_id='" + sql_esc(p["eventId"]) + "'");

          nlohmann::json resp;
          resp["event_id"] = redact_ev.event_id.to_string();
          Res res{bhttp::status::ok, HTTP11};
          set_json(res, resp.dump());
          set_cors(res);
          return res;
        } catch (const std::exception& e) {
          return error_response(bhttp::status::internal_server_error, "M_UNKNOWN", e.what());
        }
      },
      "client_redact");

  // room directory (alias lookup)
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/directory/room/{roomAlias}",
      [db_](Req&&, Params p) -> Res {
        auto alias = p["roomAlias"];
        // Lookup: currently no alias table, return not found
        return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Room alias not found");
      },
      "client_directory");

  // send message
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        try {
          auto body = nlohmann::json::parse(req.body());
          auto rid = RoomID::from_string(p["roomId"]);
          auto ev = events::create_local_event(rid, p["eventType"], r.user_id, body);
          ev.event_id = EventID::from_string("$" + util::random_token(43) + ":" + sn);
          uint64_t now = util::now_ms();
          db_->execute(
              "INSERT INTO events "
              "(event_id,room_id,type,sender,content,state_key,depth,"
              "origin_server_ts,stream_ordering) VALUES ('" +
              sql_esc(ev.event_id.to_string()) + "','" + sql_esc(p["roomId"]) + "','" +
              sql_esc(p["eventType"]) + "','" + sql_esc(r.user_id) + "','" +
              sql_esc(ev.content.dump()) + "','',1,'" + sql_esc(ev.origin_server_ts) + "'," +
              std::to_string(now) + ")");
          nlohmann::json resp;
          resp["event_id"] = ev.event_id.to_string();
          Res res{bhttp::status::ok, HTTP11};
          set_json(res, resp.dump());
          set_cors(res);
          return res;
        } catch (const std::exception& e) {
          return error_response(bhttp::status::internal_server_error, "M_UNKNOWN", e.what());
        }
      },
      "client_send");

  // room join
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/join",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto rid = RoomID::from_string(p["roomId"]);
        nlohmann::json jc;
        jc["membership"] = "join";
        auto ev = events::create_local_event(rid, "m.room.member", r.user_id, jc, r.user_id);
        ev.event_id = EventID::from_string("$" + util::random_token(43) + ":" + sn);
        uint64_t now = util::now_ms();
        db_->execute(
            "INSERT OR REPLACE INTO room_memberships "
            "(event_id,room_id,user_id,membership,sender) VALUES ('" +
            sql_esc(ev.event_id.to_string()) + "','" + sql_esc(p["roomId"]) + "','" +
            sql_esc(r.user_id) + "','join','" + sql_esc(r.user_id) + "')");
        db_->execute(
            "INSERT INTO events "
            "(event_id,room_id,type,sender,content,state_key,depth,"
            "origin_server_ts,stream_ordering) VALUES ('" +
            sql_esc(ev.event_id.to_string()) + "','" + sql_esc(p["roomId"]) +
            "','m.room.member','" + sql_esc(r.user_id) + "','" + sql_esc(ev.content.dump()) +
            "','" + sql_esc(r.user_id) + "',1,'" + sql_esc(ev.origin_server_ts) + "'," +
            std::to_string(now) + ")");
        nlohmann::json resp;
        resp["room_id"] = p["roomId"];
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_join");

  // message pagination
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/messages",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        std::string dir = "b";
        auto target = std::string(req.target());
        auto dp = target.find("dir=");
        if (dp != std::string::npos)
          dir = target.substr(dp + 4, 1);

        auto evr = db_->query(
            "SELECT event_id,type,sender,content,state_key,depth,"
            "origin_server_ts FROM events WHERE room_id='" +
            sql_esc(p["roomId"]) + "' ORDER BY depth " + (dir == "b" ? "DESC" : "ASC") +
            " LIMIT 20");
        nlohmann::json resp;
        resp["chunk"] = nlohmann::json::array();
        resp["start"] = "t0";
        resp["end"] = "t1";
        for (auto& ev : evr) {
          nlohmann::json ej;
          ej["event_id"] = ev["event_id"];
          ej["type"] = ev["type"];
          ej["sender"] = ev["sender"];
          ej["room_id"] = p["roomId"];
          ej["origin_server_ts"] = ev.value("origin_server_ts", "");
          try {
            ej["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
          } catch (...) {
            ej["content"] = nlohmann::json::object();
          }
          resp["chunk"].push_back(ej);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_messages");

  // typing
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/rooms/{roomId}/typing/{userId}",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_typing");

  // read receipts
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_receipt");

  // media upload — now handled by media module

  // presence
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/presence/{userId}/status",
      [auth_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "presence_status");

  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/presence/{userId}/status",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["presence"] = "offline";
        resp["last_active_ago"] = 3600000;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "presence_get");

  // admin: list users
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v2/users",
      [db_](Req&&, Params) -> Res {
        auto rows = db_->query("SELECT id,admin,deactivated FROM users");
        nlohmann::json resp;
        resp["users"] = nlohmann::json::array();
        for (auto& r : rows) {
          nlohmann::json u;
          u["name"] = r["id"];
          u["admin"] = r.value("admin", 0);
          u["deactivated"] = r.value("deactivated", 0);
          resp["users"].push_back(u);
        }
        resp["total"] = resp["users"].size();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_users");

  // CORS options
  router.add_route(
      bhttp::verb::options, "/*",
      [](Req&&, Params) -> Res {
        Res r{bhttp::status::ok, HTTP11};
        set_cors(r);
        r.set(bhttp::field::content_length, "0");
        return r;
      },
      "cors_options");

  // .well-known
  router.add_route(
      bhttp::verb::get, "/.well-known/matrix/client",
      [](Req&&, Params) -> Res {
        nlohmann::json j;
        j["m.homeserver"] = {{"base_url", "http://localhost:8008/"}};
        Res r{bhttp::status::ok, HTTP11};
        set_json(r, j.dump());
        set_cors(r);
        return r;
      },
      "well_known_client");
}

}  // namespace progressive::rest::client
