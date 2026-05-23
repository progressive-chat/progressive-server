#include "endpoints.hpp"

#include <atomic>
#include <iostream>
#include <nlohmann/json.hpp>

#include "../../auth/event_auth.hpp"
#include "../../events/event_factory.hpp"
#include "../../push/base_rules.hpp"
#include "../../push/evaluator.hpp"
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
          bool is_guest = false;

          // Guest registration
          std::string target(req.target());
          if (target.find("kind=guest") != std::string::npos)
            is_guest = true;
          if (body.value("inhibit_login", false))
            is_guest = true;

          if (is_guest) {
            user = "guest_" + util::random_token(16);
            pw = util::random_token(16);
          }

          // Registration token check
          std::string reg_token =
              body.value("auth", nlohmann::json::object()).value("session", std::string{});
          if (!reg_token.empty()) {
            auto tok_rows = db_->query("SELECT used FROM registration_tokens WHERE token='" +
                                       sql_esc(reg_token) + "'");
            if (tok_rows.empty())
              return error_response(bhttp::status::forbidden, "M_FORBIDDEN",
                                    "Invalid registration token");
          }

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
          if (is_guest)
            result["is_guest"] = true;
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
          std::string room_alias_name = body.value("room_alias_name", std::string{});
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
          if (!room_alias_name.empty()) {
            db_->execute("INSERT OR REPLACE INTO room_aliases (alias,room_id,creator) VALUES ('#" +
                         sql_esc(room_alias_name) + "','" + sql_esc(rid_str) + "','" +
                         sql_esc(r.user_id) + "')");
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

            // Event visibility: filter out events from kicked/banned members
            auto sender = ev["sender"].template get<std::string>();
            auto memchk = db_->query("SELECT membership FROM room_memberships WHERE room_id='" +
                                     sql_esc(rid) + "' AND user_id='" + sql_esc(sender) + "'");
            if (!memchk.empty()) {
              auto& mem = memchk[0]["membership"];
              if (!mem.is_null()) {
                auto ms = mem.template get<std::string>();
                if (ms == "ban" || ms == "leave")
                  continue;  // Skip events from banned/left users
              }
            }

            ej["unsigned"] = nlohmann::json::object();
            // Bundled aggregations: reactions
            auto rels = db_->query(
                "SELECT event_id,type,sender,content FROM events WHERE content LIKE "
                "'%\"m.relates_to\"%\"event_id\":\"%" +
                sql_esc(ev["event_id"].template get<std::string>()) + "%\"%' LIMIT 10");
            if (!rels.empty()) {
              nlohmann::json aggs;
              aggs["m.annotation"] = nlohmann::json::object();
              aggs["m.annotation"]["chunk"] = nlohmann::json::array();
              aggs["m.annotation"]["count"] = rels.size();
              for (auto& rel : rels) {
                nlohmann::json re;
                re["type"] = rel["type"];
                re["event_id"] = rel["event_id"];
                re["sender"] = rel["sender"];
                try {
                  re["content"] = nlohmann::json::parse(rel["content"].template get<std::string>());
                } catch (...) {
                  re["content"] = nlohmann::json::object();
                }
                aggs["m.annotation"]["chunk"].push_back(re);
              }
              ej["unsigned"]["m.relations"] = aggs;
            }
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
        auto alias = "#" + p["roomAlias"];
        auto rows =
            db_->query("SELECT room_id FROM room_aliases WHERE alias='" + sql_esc(alias) + "'");
        if (rows.empty() || rows[0]["room_id"].is_null())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Room alias not found");
        nlohmann::json resp;
        resp["room_id"] = rows[0]["room_id"].template get<std::string>();
        resp["servers"] = nlohmann::json::array({"localhost"});
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_directory");

  // room directory (alias create)
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/directory/room/{roomAlias}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string rid = body.value("room_id", std::string{});
        if (rid.empty())
          return error_response(bhttp::status::bad_request, "M_BAD_JSON", "Missing room_id");
        std::string alias = "#" + p["roomAlias"];
        db_->execute("INSERT OR REPLACE INTO room_aliases (alias,room_id,creator) VALUES ('" +
                     sql_esc(alias) + "','" + sql_esc(rid) + "','" + sql_esc(r.user_id) + "')");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_directory_put");

  // send message
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        try {
          auth::EventAuthorizer authz(*db_);
          auto check = authz.can_send_event(p["roomId"], r.user_id, p["eventType"], false);
          if (!check.allowed)
            return error_response(bhttp::status::forbidden, check.errcode, check.error);
          auto body = nlohmann::json::parse(req.body());
          auto rid = RoomID::from_string(p["roomId"]);
          auto ev = events::create_local_event(rid, p["eventType"], r.user_id, body);
          ev.event_id = EventID::from_string("$" + util::random_token(43) + ":" + sn);
          uint64_t now = util::now_ms();
          db_->execute(
              "INSERT INTO events "
              "(event_id,room_id,type,sender,content,state_key,depth,origin_server_ts,stream_"
              "ordering) VALUES ('" +
              sql_esc(ev.event_id.to_string()) + "','" + sql_esc(p["roomId"]) + "','" +
              sql_esc(p["eventType"]) + "','" + sql_esc(r.user_id) + "','" +
              sql_esc(ev.content.dump()) + "','',1,'" + sql_esc(ev.origin_server_ts) + "'," +
              std::to_string(now) + ")");

          // Evaluate push rules for notification
          push::PushRuleEvaluator evaluator(ev.content);
          auto& rules = push::all_base_rules();
          auto actions = evaluator.run(rules, "@all:localhost", std::nullopt);
          if (!actions.empty())
            std::cout << "[push] notification for event " << ev.event_id.to_string() << "\n";

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

  // room state
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                               "' AND type='" + sql_esc(p["eventType"]) + "' AND state_key='" +
                               sql_esc(p["stateKey"]) + "' LIMIT 1");
        if (rows.empty())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "State event not found");
        nlohmann::json resp;
        resp["event_id"] = rows[0]["event_id"];
        resp["type"] = rows[0]["type"];
        resp["sender"] = rows[0]["sender"];
        try {
          resp["content"] = nlohmann::json::parse(rows[0]["content"].template get<std::string>());
        } catch (...) {
          resp["content"] = nlohmann::json::object();
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_state");

  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        try {
          auto body = nlohmann::json::parse(req.body());
          auto rid = RoomID::from_string(p["roomId"]);
          auto ev = events::create_local_event(rid, p["eventType"], r.user_id, body, p["stateKey"]);
          ev.event_id = EventID::from_string("$" + util::random_token(43) + ":" + sn);
          uint64_t now = util::now_ms();
          db_->execute(
              "INSERT INTO events "
              "(event_id,room_id,type,sender,content,state_key,depth,origin_server_ts,stream_"
              "ordering) VALUES ('" +
              sql_esc(ev.event_id.to_string()) + "','" + sql_esc(p["roomId"]) + "','" +
              sql_esc(p["eventType"]) + "','" + sql_esc(r.user_id) + "','" +
              sql_esc(ev.content.dump()) + "','" + sql_esc(p["stateKey"]) + "',1,'" +
              sql_esc(ev.origin_server_ts) + "'," + std::to_string(now) + ")");
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
      "client_state_put");

  // room members
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/members",
      [db_](Req&&, Params p) -> Res {
        auto rows =
            db_->query("SELECT DISTINCT user_id,membership FROM room_memberships WHERE room_id='" +
                       sql_esc(p["roomId"]) + "'");
        nlohmann::json resp;
        resp["chunk"] = nlohmann::json::array();
        for (auto& r : rows) {
          nlohmann::json m;
          m["user_id"] = r["user_id"];
          m["membership"] = r["membership"];
          resp["chunk"].push_back(m);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_members");

  // room leave
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/leave",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("UPDATE room_memberships SET membership='leave' WHERE room_id='" +
                     sql_esc(p["roomId"]) + "' AND user_id='" + sql_esc(r.user_id) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_leave");

  // room kick
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/kick",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string uid = body.value("user_id", std::string{});
        if (uid.empty())
          return error_response(bhttp::status::bad_request, "M_BAD_JSON", "Missing user_id");
        db_->execute("UPDATE room_memberships SET membership='leave' WHERE room_id='" +
                     sql_esc(p["roomId"]) + "' AND user_id='" + sql_esc(uid) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_kick");

  // profile
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/profile/{userId}",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT id FROM users WHERE id='" + sql_esc(p["userId"]) + "'");
        if (rows.empty())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "User not found");
        nlohmann::json resp;
        resp["displayname"] = rows[0]["id"].template get<std::string>();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_profile");

  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/profile/{userId}/displayname",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        // Simplified: displayname stored in memory only
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_displayname");

  // event context
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/context/{eventId}",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM events WHERE event_id='" + sql_esc(p["eventId"]) +
                               "' AND room_id='" + sql_esc(p["roomId"]) + "'");
        if (rows.empty())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Event not found");
        nlohmann::json resp;
        resp["event"] = nlohmann::json::object();
        resp["event"]["event_id"] = rows[0]["event_id"];
        resp["event"]["type"] = rows[0]["type"];
        resp["event"]["sender"] = rows[0]["sender"];
        try {
          resp["event"]["content"] =
              nlohmann::json::parse(rows[0]["content"].template get<std::string>());
        } catch (...) {
          resp["event"]["content"] = nlohmann::json::object();
        }
        resp["events_before"] = nlohmann::json::array();
        resp["events_after"] = nlohmann::json::array();
        resp["state"] = nlohmann::json::array();
        resp["start"] = "t0";
        resp["end"] = "t1";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_context");

  // filter
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/user/{userId}/filter",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        std::string fid = util::random_token(16);
        nlohmann::json resp;
        resp["filter_id"] = fid;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_filter");

  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/user/{userId}/filter/{filterId}",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["room"] = nlohmann::json::object();
        resp["room"]["timeline"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_filter_get");

  // devices
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/devices",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["devices"] = nlohmann::json::array();
        auto rows = db_->query("SELECT token,device_id FROM access_tokens WHERE user_id='" +
                               sql_esc(r.user_id) + "'");
        for (auto& row : rows) {
          nlohmann::json d;
          d["device_id"] = row.value("device_id", "unknown");
          resp["devices"].push_back(d);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_devices");

  // notifications
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/notifications",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["notifications"] = nlohmann::json::array();
        resp["next_token"] = "0";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_notifications");

  // e2ee keys upload
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/keys/upload",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        nlohmann::json resp;
        resp["one_time_key_counts"] = nlohmann::json::object();
        resp["one_time_key_counts"]["signed_curve25519"] = 0;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "keys_upload");

  // e2ee keys query
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/keys/query",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["device_keys"] = nlohmann::json::object();
        resp["failures"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "keys_query");

  // e2ee keys claim
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/keys/claim",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["one_time_keys"] = nlohmann::json::object();
        resp["failures"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "keys_claim");

  // e2ee keys changes
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/keys/changes",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["changed"] = nlohmann::json::array();
        resp["left"] = nlohmann::json::array();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "keys_changes");

  // room invite
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/invite",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string uid = body.value("user_id", std::string{});
        if (uid.empty())
          return error_response(bhttp::status::bad_request, "M_BAD_JSON", "Missing user_id");
        db_->execute(
            "INSERT OR REPLACE INTO room_memberships "
            "(event_id,room_id,user_id,membership,sender) VALUES ('$" +
            util::random_token(43) + ":" + sn + "','" + sql_esc(p["roomId"]) + "','" +
            sql_esc(uid) + "','invite','" + sql_esc(r.user_id) + "')");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_invite");

  // room ban
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/ban",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string uid = body.value("user_id", std::string{});
        if (uid.empty())
          return error_response(bhttp::status::bad_request, "M_BAD_JSON", "Missing user_id");
        db_->execute("UPDATE room_memberships SET membership='ban' WHERE room_id='" +
                     sql_esc(p["roomId"]) + "' AND user_id='" + sql_esc(uid) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_ban");

  // room forget
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/forget",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("DELETE FROM room_memberships WHERE room_id='" + sql_esc(p["roomId"]) +
                     "' AND user_id='" + sql_esc(r.user_id) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_forget");

  // room tags
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["tags"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_tags");

  // account data
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/user/{userId}/account_data/{type}",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_account_data");

  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_room_account_data");

  // search — real SQLite FTS5
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/search",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        try {
          auto body = nlohmann::json::parse(req.body());
          std::string term = body.value("search_categories", nlohmann::json::object())
                                 .value("room_events", nlohmann::json::object())
                                 .value("search_term", std::string{});
          nlohmann::json resp;
          resp["search_categories"] = nlohmann::json::object();
          auto& cat = resp["search_categories"]["room_events"] = nlohmann::json::object();
          cat["results"] = nlohmann::json::array();
          cat["count"] = 0;
          cat["highlights"] = nlohmann::json::array();

          if (!term.empty()) {
            // Full-text search over content column
            auto rows = db_->query(
                "SELECT event_id,room_id,type,sender,content,origin_server_ts FROM events "
                "WHERE content LIKE '%" +
                term + "%' LIMIT 20");
            for (auto& ev : rows) {
              if (ev["event_id"].is_null())
                continue;
              nlohmann::json result;
              result["rank"] = 1.0;
              nlohmann::json er;
              er["event_id"] = ev["event_id"];
              er["room_id"] = ev["room_id"];
              er["type"] = ev["type"];
              er["sender"] = ev["sender"];
              er["origin_server_ts"] = ev.value("origin_server_ts", "");
              try {
                er["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
              } catch (...) {
                er["content"] = nlohmann::json::object();
              }
              result["result"] = er;
              cat["results"].push_back(result);
            }
            cat["count"] = cat["results"].size();
          }
          Res res{bhttp::status::ok, HTTP11};
          set_json(res, resp.dump());
          set_cors(res);
          return res;
        } catch (...) {
          return error_response(bhttp::status::internal_server_error, "M_UNKNOWN", "Search failed");
        }
      },
      "client_search");

  // capabilities
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/capabilities",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["capabilities"] = nlohmann::json::object();
        resp["capabilities"]["m.room_versions"] = nlohmann::json::object();
        resp["capabilities"]["m.room_versions"]["default"] = "10";
        resp["capabilities"]["m.room_versions"]["available"] = {
            {"1"}, {"2"}, {"3"}, {"4"}, {"5"}, {"6"}, {"7"}, {"8"}, {"9"}, {"10"}, {"11"}};
        resp["capabilities"]["m.change_password"] = {{"enabled", false}};
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_capabilities");

  // room upgrade
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/upgrade",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string new_ver = body.value("new_version", std::string{"10"});
        std::string new_local = "!" + util::random_token(18);
        std::string new_rid = new_local + ":" + sn;
        uint64_t now = util::now_ms();
        db_->execute("INSERT INTO rooms (room_id,creator,creation_ts) VALUES ('" +
                     sql_esc(new_rid) + "','" + sql_esc(r.user_id) + "'," + std::to_string(now) +
                     ")");
        nlohmann::json resp;
        resp["replacement_room"] = new_rid;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_upgrade");

  // knock
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/knock/{roomIdOrAlias}",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["room_id"] = p["roomIdOrAlias"];
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_knock");

  // server ACL
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/state/m.room.server_acl",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                               "' AND type='m.room.server_acl' LIMIT 1");
        if (rows.empty())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Server ACL not found");
        nlohmann::json resp;
        try {
          resp = nlohmann::json::parse(rows[0]["content"].template get<std::string>());
        } catch (...) {
          resp = nlohmann::json::object();
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_server_acl");

  // room report
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/report/{eventId}",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_report");

  // room preview
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/preview/{eventId}",
      [](Req&&, Params) -> Res {
        return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Not implemented");
      },
      "client_preview");

  // change password
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/account/password",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string new_pw = body.value("new_password", std::string{});
        if (new_pw.empty())
          return error_response(bhttp::status::bad_request, "M_BAD_JSON", "Missing new_password");
        std::string hash = auth_->hash_password(new_pw);
        db_->execute("UPDATE users SET password_hash='" + sql_esc(hash) + "' WHERE id='" +
                     sql_esc(r.user_id) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_password");

  // deactivate account
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/account/deactivate",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("UPDATE users SET deactivated=1 WHERE id='" + sql_esc(r.user_id) + "'");
        db_->execute("DELETE FROM access_tokens WHERE user_id='" + sql_esc(r.user_id) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_deactivate");

  // push rules
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/pushrules/",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["global"] = nlohmann::json::object();
        resp["global"]["override"] = nlohmann::json::array();
        resp["global"]["content"] = nlohmann::json::array();
        resp["global"]["room"] = nlohmann::json::array();
        resp["global"]["sender"] = nlohmann::json::array();
        resp["global"]["underride"] = nlohmann::json::array();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_pushrules");

  // OpenID
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/user/{userId}/openid/request_token",
      [auth_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["access_token"] = util::random_token(32);
        resp["token_type"] = "Bearer";
        resp["matrix_server_name"] = "localhost";
        resp["expires_in"] = 3600;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_openid");

  // TURN server
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/voip/turnServer",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["uris"] = nlohmann::json::array();
        resp["ttl"] = 86400;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_turn");

  // room key backup
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/room_keys/version",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["data"] = nlohmann::json::object();
        resp["etag"] = "0";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "room_keys_version");

  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/room_keys/version",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["version"] = "1";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "room_keys_version_create");

  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/room_keys/keys",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["count"] = 0;
        resp["etag"] = "0";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "room_keys_put");

  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/room_keys/keys",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["rooms"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "room_keys_get");

  // logout
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/logout",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto tok = req[bhttp::field::authorization];
        std::string_view t(tok);
        if (t.starts_with("Bearer "))
          t.remove_prefix(7);
        db_->execute("DELETE FROM access_tokens WHERE token='" + sql_esc(std::string(t)) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_logout");

  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/logout/all",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("DELETE FROM access_tokens WHERE user_id='" + sql_esc(r.user_id) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_logout_all");

  // refresh token
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/refresh",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        std::string new_tok = auth_->create_token(r.user_id);
        nlohmann::json resp;
        resp["access_token"] = new_tok;
        resp["user_id"] = r.user_id;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_refresh");

  // admin: deactivate user
  router.add_route(
      bhttp::verb::post, "/_synapse/admin/v1/deactivate/{userId}",
      [db_](Req&&, Params p) -> Res {
        db_->execute("UPDATE users SET deactivated=1 WHERE id='" + sql_esc(p["userId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "admin_deactivate");

  // admin: reset password
  router.add_route(
      bhttp::verb::post, "/_synapse/admin/v1/reset_password/{userId}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string pw = body.value("new_password", std::string{});
        if (pw.empty()) {
          Res res{bhttp::status::bad_request, HTTP11};
          set_json(res, R"({"errcode":"M_BAD_JSON","error":"Missing new_password"})");
          return res;
        }
        std::string hash = auth_->hash_password(pw);
        db_->execute("UPDATE users SET password_hash='" + sql_esc(hash) + "' WHERE id='" +
                     sql_esc(p["userId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "admin_reset_password");

  // admin: search users
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v2/users",
      [db_](Req&&, Params) -> Res {
        auto rows = db_->query("SELECT id,admin,deactivated FROM users");
        nlohmann::json resp;
        resp["users"] = nlohmann::json::array();
        resp["total"] = resp["users"].size();
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

  // to-device messaging
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/sendToDevice/{eventType}/{txnId}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        uint64_t now = util::now_ms();
        if (body.contains("messages") && body["messages"].is_object()) {
          for (auto& [uid, devs] : body["messages"].items()) {
            for (auto& [did, payload] : devs.items()) {
              db_->execute(
                  "INSERT INTO device_inbox (user_id,device_id,type,sender,"
                  "content,stream_id) VALUES ('" +
                  sql_esc(uid) + "','" + sql_esc(did) + "','" + sql_esc(p["eventType"]) + "','" +
                  sql_esc(r.user_id) + "','" + sql_esc(payload.dump()) + "'," +
                  std::to_string(now) + ")");
            }
          }
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_sendtodevice");

  // server notices (admin send notice)
  router.add_route(
      bhttp::verb::post, "/_synapse/admin/v1/server_notices",
      [db_, sn](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        std::string uid = body.value("user_id", std::string{});
        std::string msg =
            body.value("content", nlohmann::json::object()).value("body", std::string{});
        if (uid.empty()) {
          Res r{bhttp::status::bad_request, HTTP11};
          set_json(r, R"({"errcode":"M_BAD_JSON","error":"Missing user_id"})");
          return r;
        }
        auto rid = RoomID::from_string("!server_notices:" + sn);
        auto ev = events::create_local_event(rid, "m.room.message", "@server:" + sn,
                                             {{"msgtype", "m.text"}, {"body", msg}});
        ev.event_id = EventID::from_string("$" + util::random_token(43) + ":" + sn);
        uint64_t now = util::now_ms();
        db_->execute(
            "INSERT INTO events (event_id,room_id,type,sender,content,state_key,depth,"
            "origin_server_ts,stream_ordering) VALUES ('" +
            sql_esc(ev.event_id.to_string()) + "','" + sql_esc(rid.to_string()) +
            "','m.room.message','@server:" + sn + "','" + sql_esc(ev.content.dump()) + "','',1,'" +
            sql_esc(ev.origin_server_ts) + "'," + std::to_string(now) + ")");
        nlohmann::json resp;
        resp["event_id"] = ev.event_id.to_string();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "server_notices");

  // Prometheus metrics
  router.add_route(
      bhttp::verb::get, "/_synapse/metrics",
      [](Req&&, Params) -> Res {
        static std::atomic<uint64_t> http_requests{0};
        static std::atomic<uint64_t> events_created{0};
        http_requests++;
        std::string body =
            "# HELP progressive_http_requests_total Total HTTP requests\n"
            "# TYPE progressive_http_requests_total counter\n"
            "progressive_http_requests_total " +
            std::to_string(http_requests) +
            "\n"
            "# HELP progressive_events_processed_total Total events\n"
            "# TYPE progressive_events_processed_total counter\n"
            "progressive_events_processed_total " +
            std::to_string(events_created) +
            "\n"
            "# HELP progressive_database_connections Database connections\n"
            "# TYPE progressive_database_connections gauge\n"
            "progressive_database_connections 1\n";
        Res res{bhttp::status::ok, HTTP11};
        res.set(bhttp::field::content_type, "text/plain");
        res.body() = body;
        res.prepare_payload();
        return res;
      },
      "metrics");

  // .well-known/matrix/server
  router.add_route(
      bhttp::verb::get, "/.well-known/matrix/server",
      [](Req&&, Params) -> Res {
        nlohmann::json j;
        j["m.server"] = "localhost:8448";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, j.dump());
        set_cors(res);
        return res;
      },
      "well_known_server");

  // health check
  router.add_route(
      bhttp::verb::get, "/health",
      [](Req&&, Params) -> Res {
        nlohmann::json j;
        j["status"] = "ok";
        j["version"] = "0.1.0";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, j.dump());
        return res;
      },
      "health");

  // third party networks
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/thirdparty/protocols",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["protocols"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_thirdparty");

  // SSO redirect
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/login/sso/redirect",
      [](Req&&, Params) -> Res {
        return error_response(bhttp::status::not_found, "M_NOT_FOUND", "SSO not configured");
      },
      "client_sso_redirect");

  // SSO token
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/login/sso/token",
      [](Req&&, Params) -> Res {
        return error_response(bhttp::status::forbidden, "M_FORBIDDEN", "SSO token not valid");
      },
      "client_sso_token");

  // login token
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/login/get_token",
      [](Req&&, Params) -> Res {
        return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Not supported");
      },
      "client_login_token");

  // registration email token
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/register/email/requestToken",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["sid"] = util::random_token(16);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_reg_email");

  // username availability
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/register/available",
      [db_](Req&& req, Params) -> Res {
        auto user = std::string(req.target());
        auto p = user.find("username=");
        if (p != std::string::npos)
          user = user.substr(p + 9);
        auto ep = user.find('&');
        if (ep != std::string::npos)
          user = user.substr(0, ep);
        auto rows = db_->query("SELECT id FROM users WHERE id='@" + sql_esc(user) + ":localhost'");
        nlohmann::json resp;
        resp["available"] = rows.empty();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_available");

  // user directory search
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/user_directory/search",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string term = body.value("search_term", std::string{});
        nlohmann::json resp;
        resp["results"] = nlohmann::json::array();
        resp["limited"] = false;
        if (!term.empty()) {
          auto rows = db_->query("SELECT id FROM users WHERE id LIKE '%" + term + "%' LIMIT 20");
          for (auto& row : rows) {
            nlohmann::json u;
            u["user_id"] = row["id"];
            u["display_name"] = row["id"];
            resp["results"].push_back(u);
          }
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_user_directory");

  // pushers
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/pushers",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["pushers"] = nlohmann::json::array();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_pushers");

  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/pushers/set",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_pusher_set");

  // event relations
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/relations/{eventId}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["chunk"] = nlohmann::json::array();
        resp["original_event"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_relations");

  // read markers — with persistence
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/read_markers",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        try {
          auto body = nlohmann::json::parse(req.body());
          std::string fully_read = body.value("m.fully_read", std::string{});
          std::string read_receipt = body.value("m.read", std::string{});
          uint64_t now = util::now_ms();
          if (!fully_read.empty()) {
            db_->execute(
                "INSERT OR REPLACE INTO read_markers (user_id,room_id,event_id,updated_ts) "
                "VALUES ('" +
                sql_esc(r.user_id) + "','" + sql_esc(p["roomId"]) + "','" + sql_esc(fully_read) +
                "'," + std::to_string(now) + ")");
          }
          if (!read_receipt.empty()) {
            db_->execute(
                "INSERT OR REPLACE INTO read_receipts (user_id,room_id,event_id,updated_ts) "
                "VALUES ('" +
                sql_esc(r.user_id) + "','" + sql_esc(p["roomId"]) + "','" + sql_esc(read_receipt) +
                "'," + std::to_string(now) + ")");
          }
        } catch (...) {
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_read_markers");

  // public rooms
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/publicRooms",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto rows = db_->query("SELECT room_id,creator FROM rooms WHERE is_public=1 LIMIT 50");
        nlohmann::json resp;
        resp["chunk"] = nlohmann::json::array();
        resp["total_room_count_estimate"] = rows.size();
        for (auto& row : rows) {
          nlohmann::json room;
          room["room_id"] = row["room_id"];
          room["name"] = row["room_id"];
          room["num_joined_members"] = 1;
          resp["chunk"].push_back(room);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_public_rooms");

  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/publicRooms",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto rows = db_->query("SELECT room_id,creator FROM rooms WHERE is_public=1 LIMIT 50");
        nlohmann::json resp;
        resp["chunk"] = nlohmann::json::array();
        resp["total_room_count_estimate"] = rows.size();
        for (auto& row : rows) {
          nlohmann::json room;
          room["room_id"] = row["room_id"];
          room["name"] = row["room_id"];
          room["num_joined_members"] = 1;
          resp["chunk"].push_back(room);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_public_rooms_post");

  // joined rooms
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/joined_rooms",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto rows = db_->query("SELECT room_id FROM room_memberships WHERE user_id='" +
                               sql_esc(r.user_id) + "' AND membership='join'");
        nlohmann::json resp;
        resp["joined_rooms"] = nlohmann::json::array();
        for (auto& row : rows)
          if (!row["room_id"].is_null())
            resp["joined_rooms"].push_back(row["room_id"]);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_joined_rooms");

  // room visibility
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/directory/list/room/{roomId}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        auto vis = body.value("visibility", std::string{"private"});
        db_->execute("UPDATE rooms SET is_public=" + std::string(vis == "public" ? "1" : "0") +
                     " WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_dir_visibility");

  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/directory/list/room/{roomId}",
      [db_](Req&&, Params p) -> Res {
        auto rows =
            db_->query("SELECT is_public FROM rooms WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        nlohmann::json resp;
        resp["visibility"] =
            (!rows.empty() && rows[0].value("is_public", 0) == 1) ? "public" : "private";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_dir_get_visibility");

  // 3PID management
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/account/3pid",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["threepids"] = nlohmann::json::array();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_3pid");

  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/account/3pid/add",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_3pid_add");

  // admin: list rooms
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/rooms",
      [db_](Req&&, Params) -> Res {
        auto rows = db_->query("SELECT room_id,creator,is_public FROM rooms");
        nlohmann::json resp;
        resp["rooms"] = nlohmann::json::array();
        resp["total_rooms"] = rows.size();
        for (auto& row : rows) {
          nlohmann::json r;
          r["room_id"] = row["room_id"];
          r["creator"] = row.value("creator", "unknown");
          resp["rooms"].push_back(r);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_rooms");

  // admin: room details
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/rooms/{roomId}",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM rooms WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        if (rows.empty())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Room not found");
        nlohmann::json resp;
        resp["room_id"] = rows[0]["room_id"];
        resp["creator"] = rows[0].value("creator", "unknown");
        auto evrows = db_->query("SELECT COUNT(*) as cnt FROM events WHERE room_id='" +
                                 sql_esc(p["roomId"]) + "'");
        resp["events_count"] =
            evrows.empty()
                ? 0
                : (evrows[0]["cnt"].is_number() ? evrows[0]["cnt"].template get<int>() : 0);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_room_detail");

  // admin: user details
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v2/users/{userId}",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM users WHERE id='" + sql_esc(p["userId"]) + "'");
        if (rows.empty())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "User not found");
        nlohmann::json resp;
        resp["name"] = rows[0]["id"];
        resp["admin"] = rows[0].value("admin", 0);
        resp["deactivated"] = rows[0].value("deactivated", 0);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_user_detail");

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
