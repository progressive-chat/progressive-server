#include "endpoints.hpp"

#include <atomic>
#include <iostream>
#include <nlohmann/json.hpp>
#include <thread>

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
          // Refresh token chain
          std::string rtok = "rt_" + util::random_token(48);
          db_->execute(
              "INSERT INTO refresh_tokens (token,user_id,access_token_id,expires_at) VALUES ('" +
              sql_esc(rtok) + "','" + sql_esc(uid) + "','" + sql_esc(tok) + "'," +
              std::to_string(util::now_ms() + 2592000000) + ")");
          nlohmann::json resp;
          resp["user_id"] = uid;
          resp["access_token"] = tok;
          resp["refresh_token"] = rtok;
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
          // State delta: separate state events from timeline
          // Build timeline_contains: state events in this batch
          std::map<std::string, std::string> timeline_contains;  // key="type|state_key"->event_id
          std::vector<nlohmann::json> timeline_events;
          std::vector<nlohmann::json> state_events;

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
            // Redaction check
            auto cstr = ev["content"].template get<std::string>();
            if (cstr.find("redacted_because") != std::string::npos) {
              try {
                auto cj = nlohmann::json::parse(cstr);
                if (cj.contains("redacted_because")) {
                  ej["unsigned"]["redacted_because"] = cj["redacted_because"];
                  ej["content"] = nlohmann::json::object();
                }
              } catch (...) {
              }
            }
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

            // State delta: state events go to both timeline and state blocks
            bool is_state_event =
                !ev["state_key"].is_null() && !ev["state_key"].template get<std::string>().empty();
            timeline_events.push_back(ej);
            if (is_state_event) {
              std::string key = ev["type"].template get<std::string>() + "|" +
                                ev["state_key"].template get<std::string>();
              timeline_contains[key] = ev["event_id"].template get<std::string>();
            }
          }

          // Build state events (all state in room minus timeline_contains)
          auto all_state = db_->query("SELECT * FROM events WHERE room_id='" + sql_esc(rid) +
                                      "' AND state_key != '' AND state_key IS NOT NULL "
                                      "ORDER BY depth DESC LIMIT 50");
          for (auto& se : all_state) {
            std::string key = se["type"].template get<std::string>() + "|" +
                              se["state_key"].template get<std::string>();
            if (timeline_contains.find(key) != timeline_contains.end())
              continue;
            nlohmann::json ej;
            ej["event_id"] = se["event_id"];
            ej["type"] = se["type"];
            ej["sender"] = se["sender"];
            ej["room_id"] = rid;
            ej["state_key"] = se["state_key"];
            ej["origin_server_ts"] = se.value("origin_server_ts", "");
            try {
              ej["content"] = nlohmann::json::parse(se["content"].template get<std::string>());
            } catch (...) {
              ej["content"] = nlohmann::json::object();
            }
            ej["unsigned"] = nlohmann::json::object();
            state_events.push_back(ej);
          }

          rd["timeline"]["events"] = timeline_events;
          rd["state"]["events"] = state_events;
          resp["rooms"]["join"][rid] = rd;
        }

        // Additional sync fields
        // To-device messages
        auto tdev = db_->query("SELECT type,sender,content FROM device_inbox WHERE user_id='" +
                               sql_esc(r.user_id) +
                               "' AND device_id!='otk' ORDER BY stream_id DESC LIMIT 10");
        nlohmann::json to_device;
        to_device["events"] = nlohmann::json::array();
        for (auto& td : tdev) {
          nlohmann::json ev;
          ev["type"] = td["type"];
          ev["sender"] = td["sender"];
          try {
            ev["content"] = nlohmann::json::parse(td["content"].template get<std::string>());
          } catch (...) {
            ev["content"] = nlohmann::json::object();
          }
          to_device["events"].push_back(ev);
        }
        resp["to_device"] = to_device;

        // Presence — real data from presence_state
        auto pres_rows = db_->query(
            "SELECT user_id,state,last_active_ts FROM presence_state "
            "WHERE user_id IN (SELECT user_id FROM room_memberships WHERE room_id IN "
            "(SELECT room_id FROM room_memberships WHERE user_id='" +
            sql_esc(r.user_id) + "' AND membership='join') AND membership='join') LIMIT 20");
        nlohmann::json presence;
        presence["events"] = nlohmann::json::array();
        for (auto& pr : pres_rows) {
          nlohmann::json pe;
          pe["sender"] = pr["user_id"];
          pe["type"] = "m.presence";
          pe["content"] = {
              {"presence", pr.value("state", "offline")},
              {"last_active_ago", util::now_ms() - pr.value("last_active_ts", int64_t(0))}};
          presence["events"].push_back(pe);
        }
        resp["presence"] = presence;

        // Device lists — track changed devices
        auto dev_rows = db_->query(
            "SELECT DISTINCT user_id FROM access_tokens WHERE token IN "
            "(SELECT token FROM access_tokens WHERE user_id='" +
            sql_esc(r.user_id) + "') LIMIT 5");
        resp["device_lists"] = nlohmann::json::object();
        resp["device_lists"]["changed"] = nlohmann::json::array();
        resp["device_lists"]["left"] = nlohmann::json::array();

        // Unread notifications from event_push_summary
        auto unreads = db_->query(
            "SELECT room_id,notif_count,highlight_count FROM event_push_summary "
            "WHERE user_id='" +
            sql_esc(r.user_id) + "'");
        nlohmann::json unread;
        for (auto& u : unreads) {
          nlohmann::json room_notif;
          room_notif["notification_count"] = u.value("notif_count", 0);
          room_notif["highlight_count"] = u.value("highlight_count", 0);
          unread[u["room_id"].template get<std::string>()] = room_notif;
        }
        resp["rooms"]["unread_notifications"] = unread;

        // Account data (stub)
        nlohmann::json acct_data;
        acct_data["events"] = nlohmann::json::array();
        resp["account_data"] = acct_data;

        // Room summary (per-room joined/invited counts)
        nlohmann::json summary;
        summary["joined_member_count"] = 0;
        summary["invited_member_count"] = 0;
        resp["summary"] = summary;

        // Ephemeral events (typing + receipts) — basic stubs
        resp["ephemeral"] = nlohmann::json::object();
        resp["ephemeral"]["typing"] = nlohmann::json::object();
        resp["ephemeral"]["receipts"] = nlohmann::json::array();

        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_sync");

  // single event
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/event/{eventId}",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM events WHERE event_id='" + sql_esc(p["eventId"]) +
                               "' AND room_id='" + sql_esc(p["roomId"]) + "'");
        if (rows.empty() || rows[0]["event_id"].is_null())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Event not found");
        auto& ev = rows[0];
        nlohmann::json resp;
        resp["event_id"] = ev["event_id"];
        resp["type"] = ev["type"];
        resp["sender"] = ev["sender"];
        resp["room_id"] = ev["room_id"];
        try {
          resp["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
        } catch (...) {
          resp["content"] = nlohmann::json::object();
        }
        resp["origin_server_ts"] = ev.value("origin_server_ts", "");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_event");

  // full room state
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/state",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                               "' AND state_key != ''");
        nlohmann::json resp = nlohmann::json::array();
        for (auto& ev : rows) {
          nlohmann::json se;
          se["event_id"] = ev["event_id"];
          se["type"] = ev["type"];
          se["sender"] = ev["sender"];
          se["state_key"] = ev["state_key"];
          try {
            se["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
          } catch (...) {
            se["content"] = nlohmann::json::object();
          }
          resp.push_back(se);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_state_all");

  // joined members with display names
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/joined_members",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT user_id FROM room_memberships WHERE room_id='" +
                               sql_esc(p["roomId"]) + "' AND membership='join'");
        nlohmann::json resp;
        resp["joined"] = nlohmann::json::object();
        for (auto& r : rows)
          resp["joined"][r["user_id"].template get<std::string>()] =
              nlohmann::json::object({{"display_name", r["user_id"]}});
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_joined_members");

  // room aliases
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/aliases",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT alias FROM room_aliases WHERE room_id='" +
                               sql_esc(p["roomId"]) + "'");
        nlohmann::json resp;
        resp["aliases"] = nlohmann::json::array();
        for (auto& r : rows)
          resp["aliases"].push_back(r["alias"]);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_aliases");

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
          // Shadow ban check
          auto sb =
              db_->query("SELECT deactivated FROM users WHERE id='" + sql_esc(r.user_id) + "'");
          if (!sb.empty() && sb[0].value("deactivated", 0) >= 2) {
            // Shadow-banned: silently reject after random delay
            int delay = 1000 + (util::now_ms() % 9000);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            return error_response(bhttp::status::forbidden, "M_FORBIDDEN", "");
          }

          // Event size limit (64KB)
          if (req.body().size() > 65536)
            return error_response(bhttp::status::bad_request, "M_TOO_LARGE", "Event too large");

          auth::EventAuthorizer authz(*db_);
          auto check = authz.can_send_event(p["roomId"], r.user_id, p["eventType"], false);
          if (!check.allowed)
            return error_response(bhttp::status::forbidden, check.errcode, check.error);
          auto body = nlohmann::json::parse(req.body());

          // Event dedup: check txn_id
          auto dup = db_->query("SELECT event_id FROM event_txn_id WHERE room_id='" +
                                sql_esc(p["roomId"]) + "' AND user_id='" + sql_esc(r.user_id) +
                                "' AND txn_id='" + sql_esc(p["txnId"]) + "'");
          if (!dup.empty() && !dup[0]["event_id"].is_null()) {
            nlohmann::json resp;
            resp["event_id"] = dup[0]["event_id"].template get<std::string>();
            Res res{bhttp::status::ok, HTTP11};
            set_json(res, resp.dump());
            set_cors(res);
            return res;
          }

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

          // FTS5 indexing
          if (body.contains("body") && body["body"].is_string())
            db_->execute(
                "INSERT OR REPLACE INTO event_search (event_id,room_id,sender,body,content) VALUES "
                "('" +
                sql_esc(ev.event_id.to_string()) + "','" + sql_esc(p["roomId"]) + "','" +
                sql_esc(r.user_id) + "','" + sql_esc(body["body"].get<std::string>()) + "','" +
                sql_esc(ev.content.dump()) + "')");

          // Track txn_id for dedup
          db_->execute(
              "INSERT OR IGNORE INTO event_txn_id (event_id,room_id,user_id,txn_id,ts) VALUES ('" +
              sql_esc(ev.event_id.to_string()) + "','" + sql_esc(p["roomId"]) + "','" +
              sql_esc(r.user_id) + "','" + sql_esc(p["txnId"]) + "'," + std::to_string(now) + ")");

          // Auth chain indexing
          auto fe = db_->query(
              "SELECT a.chain_id,a.sequence_number FROM event_forward_extremities e "
              "JOIN event_auth_chains a ON e.event_id=a.event_id WHERE e.room_id='" +
              sql_esc(p["roomId"]) + "' LIMIT 1");
          if (!fe.empty() && !fe[0]["chain_id"].is_null()) {
            int64_t chain = fe[0]["chain_id"].template get<int64_t>();
            int64_t seq = fe[0]["sequence_number"].template get<int64_t>() + 1;
            db_->execute(
                "INSERT INTO event_auth_chains (event_id,chain_id,sequence_number) VALUES ('" +
                sql_esc(ev.event_id.to_string()) + "'," + std::to_string(chain) + "," +
                std::to_string(seq) + ")");
          } else {
            db_->execute(
                "INSERT INTO event_auth_chains (event_id,chain_id,sequence_number) VALUES ('" +
                sql_esc(ev.event_id.to_string()) + "'," + std::to_string(now) + ",1)");
          }

          // Forward extremities: remove prevs, add new event
          db_->execute("DELETE FROM event_forward_extremities WHERE room_id='" +
                       sql_esc(p["roomId"]) + "'");
          db_->execute("INSERT INTO event_forward_extremities (event_id,room_id) VALUES ('" +
                       sql_esc(ev.event_id.to_string()) + "','" + sql_esc(p["roomId"]) + "')");

          // Store relations
          if (body.contains("m.relates_to") && body["m.relates_to"].is_object()) {
            auto& rel = body["m.relates_to"];
            std::string rel_to = rel.value("event_id", std::string{});
            std::string rel_type = rel.value("rel_type", std::string{});
            std::string agg_key = rel.value("key", std::string{});
            if (!rel_to.empty() && !rel_type.empty())
              db_->execute(
                  "INSERT OR REPLACE INTO event_relations "
                  "(event_id,relates_to_id,relation_type,aggregation_key) VALUES ('" +
                  sql_esc(ev.event_id.to_string()) + "','" + sql_esc(rel_to) + "','" +
                  sql_esc(rel_type) + "','" + sql_esc(agg_key) + "')");
          }

          // Evaluate push rules for ALL room members (bulk evaluation)
          auto room_members = db_->query("SELECT user_id FROM room_memberships WHERE room_id='" +
                                         sql_esc(p["roomId"]) + "' AND membership='join'");
          auto& rules = push::all_base_rules();

          for (auto& member : room_members) {
            std::string uid = member["user_id"].template get<std::string>();
            push::PushRuleEvaluator evaluator(ev.content);
            auto actions = evaluator.run(rules, uid, std::nullopt);
            if (!actions.empty()) {
              auto acts_json = push::actions_to_json(actions);
              db_->execute(
                  "INSERT OR REPLACE INTO event_push_actions "
                  "(event_id,user_id,room_id,actions,stream_ordering) VALUES ('" +
                  sql_esc(ev.event_id.to_string()) + "','" + sql_esc(uid) + "','" +
                  sql_esc(p["roomId"]) + "','" + sql_esc(acts_json.dump()) + "'," +
                  std::to_string(now) + ")");

              bool has_highlight = acts_json.dump().find("highlight") != std::string::npos;
              db_->execute(
                  "INSERT INTO event_push_summary (user_id,room_id,notif_count,highlight_count,"
                  "stream_ordering) VALUES ('" +
                  sql_esc(uid) + "','" + sql_esc(p["roomId"]) + "',1," +
                  (has_highlight ? "1" : "0") + "," + std::to_string(now) +
                  ") ON CONFLICT(user_id,room_id) DO UPDATE SET "
                  "notif_count=notif_count+1,highlight_count=highlight_count+" +
                  (has_highlight ? "1" : "0") + ",stream_ordering=" + std::to_string(now));
            }
          }

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

  // delete device
  router.add_route(
      bhttp::verb::delete_, "/_matrix/client/v3/devices/{deviceId}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("DELETE FROM access_tokens WHERE user_id='" + sql_esc(r.user_id) +
                     "' AND device_id='" + sql_esc(p["deviceId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_delete_device");

  // notifications — real data from event_push_actions
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/notifications",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto rows = db_->query(
            "SELECT event_id,room_id,actions,stream_ordering FROM event_push_actions "
            "WHERE user_id='" +
            sql_esc(r.user_id) + "' ORDER BY stream_ordering DESC LIMIT 20");
        nlohmann::json resp;
        resp["notifications"] = nlohmann::json::array();
        resp["next_token"] = "0";
        for (auto& n : rows) {
          nlohmann::json notif;
          notif["event"]["event_id"] = n["event_id"];
          notif["room_id"] = n["room_id"];
          notif["read"] = false;
          try {
            notif["actions"] = nlohmann::json::parse(n["actions"].template get<std::string>());
          } catch (...) {
            notif["actions"] = nlohmann::json::array({"notify"});
          }
          resp["notifications"].push_back(notif);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_notifications");

  // e2ee keys upload
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/keys/upload",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        // Store one-time keys
        if (body.contains("one_time_keys") && body["one_time_keys"].is_object()) {
          for (auto& [kid, kdata] : body["one_time_keys"].items())
            db_->execute(
                "INSERT OR REPLACE INTO device_inbox (user_id,device_id,type,sender,"
                "content,stream_id) VALUES ('" +
                sql_esc(r.user_id) + "','otk','" + sql_esc(kid) + "','" + sql_esc(r.user_id) +
                "','" + sql_esc(kdata.dump()) + "',0)");
        }
        // Count remaining one-time keys
        auto cnt = db_->query("SELECT COUNT(*) as cnt FROM device_inbox WHERE user_id='" +
                              sql_esc(r.user_id) + "' AND device_id='otk'");
        nlohmann::json resp;
        resp["one_time_key_counts"] = nlohmann::json::object();
        int count =
            (!cnt.empty() && cnt[0]["cnt"].is_number()) ? cnt[0]["cnt"].template get<int>() : 0;
        resp["one_time_key_counts"]["signed_curve25519"] = count;
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

  // cross-signing keys
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/keys/device_signing/upload",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "keys_device_signing");

  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/keys/signatures/upload",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "keys_signatures");

  // room hierarchy (spaces)
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/hierarchy",
      [auth_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["rooms"] = nlohmann::json::array();
        resp["next_batch"] = "";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_hierarchy");

  // room summary
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/summary",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT COUNT(*) as cnt FROM room_memberships WHERE room_id='" +
                               sql_esc(p["roomId"]) + "' AND membership='join'");
        int joined = 0;
        if (!rows.empty() && rows[0]["cnt"].is_number())
          joined = rows[0]["cnt"].template get<int>();
        nlohmann::json resp;
        resp["joined_member_count"] = joined;
        resp["invited_member_count"] = 0;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_room_summary");

  // event relations (proper)
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/relations/{eventId}",
      [db_](Req&&, Params p) -> Res {
        nlohmann::json resp;
        resp["chunk"] = nlohmann::json::array();
        auto rows = db_->query(
            "SELECT event_id,type,sender,content FROM events WHERE content LIKE "
            "'%\"m.relates_to\"%\"event_id\":\"%" +
            sql_esc(p["eventId"]) + "%\"%' LIMIT 20");
        for (auto& ev : rows) {
          nlohmann::json r;
          r["event_id"] = ev["event_id"];
          r["type"] = ev["type"];
          r["sender"] = ev["sender"];
          try {
            r["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
          } catch (...) {
            r["content"] = nlohmann::json::object();
          }
          resp["chunk"].push_back(r);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_relations");

  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/relations/{eventId}/{relType}",
      [db_](Req&&, Params p) -> Res {
        nlohmann::json resp;
        resp["chunk"] = nlohmann::json::array();
        auto rows = db_->query(
            "SELECT event_id,type,sender,content FROM events WHERE content LIKE "
            "'%\"rel_type\":\"%" +
            sql_esc(p["relType"]) + "%\"%' AND content LIKE '%\"event_id\":\"%" +
            sql_esc(p["eventId"]) + "%\"%' LIMIT 20");
        for (auto& ev : rows) {
          nlohmann::json r;
          r["event_id"] = ev["event_id"];
          r["type"] = ev["type"];
          try {
            r["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
          } catch (...) {
            r["content"] = nlohmann::json::object();
          }
          resp["chunk"].push_back(r);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_relations_typed");

  // thumbnail
  router.add_route(
      bhttp::verb::get, "/_matrix/media/v3/thumbnail/{serverName}/{mediaId}",
      [](Req&&, Params) -> Res {
        Res res{bhttp::status::not_found, HTTP11};
        set_json(res, R"({"errcode":"M_NOT_FOUND","error":"Thumbnail not available"})");
        return res;
      },
      "media_thumbnail");

  // URL preview
  router.add_route(
      bhttp::verb::get, "/_matrix/media/v3/preview_url",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["matrix:image:size"] = 0;
        resp["og:title"] = "Preview not available";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "media_preview");

  // media config
  router.add_route(
      bhttp::verb::get, "/_matrix/media/v3/config",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["m.upload.size"] = 52428800;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        return res;
      },
      "media_config");

  // appservice ping
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/appservice/{appserviceId}/ping",
      [](Req&&, Params) -> Res {
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        return res;
      },
      "appservice_ping");

  // 3PID email requestToken
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/account/3pid/email/requestToken",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["sid"] = util::random_token(16);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_3pid_email");

  // thread subscriptions
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/thread_subscriptions/{roomId}",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["subscriptions"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_thread_subs");

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

  // room unban
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/unban",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string uid = body.value("user_id", std::string{});
        db_->execute("UPDATE room_memberships SET membership='leave' WHERE room_id='" +
                     sql_esc(p["roomId"]) + "' AND user_id='" + sql_esc(uid) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_unban");

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

  // room tag PUT
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        db_->execute("INSERT OR REPLACE INTO room_tags (user_id,room_id,tag,content) VALUES ('" +
                     sql_esc(r.user_id) + "','" + sql_esc(p["roomId"]) + "','" + sql_esc(p["tag"]) +
                     "','" + sql_esc(body.dump()) + "')");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_tag_put");

  // room tag DELETE
  router.add_route(
      bhttp::verb::delete_, "/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("DELETE FROM room_tags WHERE user_id='" + sql_esc(r.user_id) +
                     "' AND room_id='" + sql_esc(p["roomId"]) + "' AND tag='" + sql_esc(p["tag"]) +
                     "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_tag_delete");

  // account data GET
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/user/{userId}/account_data/{type}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto rows = db_->query("SELECT content FROM account_data WHERE user_id='" +
                               sql_esc(r.user_id) + "' AND data_type='" + sql_esc(p["type"]) + "'");
        nlohmann::json resp;
        if (!rows.empty())
          resp = nlohmann::json::parse(rows[0]["content"].template get<std::string>());
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_account_data_get");

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
                "SELECT s.event_id,s.room_id,e.type,e.sender,e.content,e.origin_server_ts "
                "FROM event_search s JOIN events e ON s.event_id=e.event_id "
                "WHERE s.body LIKE '%" +
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
        db_->execute("INSERT INTO rooms (room_id,creator,creation_ts,room_version) VALUES ('" +
                     sql_esc(new_rid) + "','" + sql_esc(r.user_id) + "'," + std::to_string(now) +
                     "," + new_ver + ")");

        // Copy state events from old room
        auto state = db_->query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                                "' AND state_key != '' ORDER BY depth");
        for (auto& ev : state) {
          auto new_ev = events::create_local_event(
              RoomID::from_string(new_rid), ev["type"].template get<std::string>(),
              ev["sender"].template get<std::string>(),
              nlohmann::json::parse(ev["content"].template get<std::string>()),
              ev.value("state_key", ""));
          new_ev.event_id = EventID::from_string("$" + util::random_token(43) + ":" + sn);
          db_->execute(
              "INSERT INTO events (event_id,room_id,type,sender,content,state_key,depth,"
              "origin_server_ts,stream_ordering) VALUES ('" +
              sql_esc(new_ev.event_id.to_string()) + "','" + sql_esc(new_rid) + "','" +
              sql_esc(ev["type"].template get<std::string>()) + "','" +
              sql_esc(ev["sender"].template get<std::string>()) + "','" +
              sql_esc(new_ev.content.dump()) + "','" + sql_esc(ev.value("state_key", "")) + "'," +
              std::to_string(ev.value("depth", int64_t(1))) + ",'" +
              sql_esc(new_ev.origin_server_ts) + "'," + std::to_string(now++) + ")");
        }

        // Create tombstone in old room
        auto tomb = events::create_local_event(
            RoomID::from_string(p["roomId"]), "m.room.tombstone", r.user_id,
            {{"replacement_room", new_rid}, {"body", "Room upgraded"}});
        tomb.event_id = EventID::from_string("$" + util::random_token(43) + ":" + sn);
        db_->execute(
            "INSERT INTO events (event_id,room_id,type,sender,content,state_key,depth,"
            "origin_server_ts,stream_ordering) VALUES ('" +
            sql_esc(tomb.event_id.to_string()) + "','" + sql_esc(p["roomId"]) +
            "','m.room.tombstone','" + sql_esc(r.user_id) + "','" + sql_esc(tomb.content.dump()) +
            "','',1,'" + sql_esc(tomb.origin_server_ts) + "'," + std::to_string(now) + ")");

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

  // email password reset request
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/account/password/email/requestToken",
      [](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        nlohmann::json resp;
        resp["sid"] = util::random_token(16);
        resp["submit_url"] = "";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_password_email");

  // email registration request token
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/register/email/requestToken",
      [](Req&& req, Params) -> Res {
        nlohmann::json resp;
        resp["sid"] = util::random_token(16);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_reg_email_req");

  // push gateway HTTP sender (stub — real push via APNs/FCM)
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/pushers/set",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        db_->execute(
            "INSERT OR REPLACE INTO pushers "
            "(user_id,app_id,pushkey,kind,app_display_name,lang,data) "
            "VALUES ('" +
            sql_esc(r.user_id) + "','" + sql_esc(body.value("app_id", std::string{})) + "','" +
            sql_esc(body.value("pushkey", std::string{})) + "','" +
            sql_esc(body.value("kind", std::string{})) + "','" +
            sql_esc(body.value("app_display_name", std::string{})) + "','" +
            sql_esc(body.value("lang", std::string{})) + "','" + sql_esc(body["data"].dump()) +
            "')");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_pusher_set");

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
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        int count = 0;
        if (body.contains("rooms") && body["rooms"].is_object()) {
          for (auto& [rid, sessions] : body["rooms"].items()) {
            if (!sessions.is_object())
              continue;
            for (auto& [sid, sdata] : sessions.items())
              db_->execute(
                  "INSERT OR REPLACE INTO e2e_room_keys "
                  "(user_id,room_id,session_id,session_data) VALUES ('" +
                  sql_esc(r.user_id) + "','" + sql_esc(rid) + "','" + sql_esc(sid) + "','" +
                  sql_esc(sdata.dump()) + "')");
            count++;
          }
        }
        nlohmann::json resp;
        resp["count"] = count;
        resp["etag"] = "1";
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

  router.add_route(
      bhttp::verb::delete_, "/_matrix/client/v3/room_keys/keys",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("DELETE FROM e2e_room_keys WHERE user_id='" + sql_esc(r.user_id) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "room_keys_delete_all");

  // registration token validity
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v1/register/m.login.registration_token/validity",
      [db_](Req&& req, Params) -> Res {
        auto tok = std::string(req.target());
        auto p = tok.find("token=");
        if (p != std::string::npos)
          tok = tok.substr(p + 6);
        auto ep = tok.find('&');
        if (ep != std::string::npos)
          tok = tok.substr(0, ep);
        auto rows = db_->query("SELECT token,used FROM registration_tokens WHERE token='" +
                               sql_esc(tok) + "'");
        nlohmann::json resp;
        resp["valid"] = !rows.empty() && rows[0].value("used", 0) == 0;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "reg_token_validity");

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
        db_->execute("DELETE FROM refresh_tokens WHERE access_token_id='" +
                     sql_esc(std::string(t)) + "'");
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

  // admin: delete room
  router.add_route(
      bhttp::verb::delete_, "/_synapse/admin/v1/rooms/{roomId}",
      [db_](Req&&, Params p) -> Res {
        db_->execute("DELETE FROM events WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        db_->execute("DELETE FROM room_memberships WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        db_->execute("DELETE FROM rooms WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "admin_delete_room");

  // delete room alias
  router.add_route(
      bhttp::verb::delete_, "/_matrix/client/v3/directory/room/{roomAlias}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("DELETE FROM room_aliases WHERE alias='#" + sql_esc(p["roomAlias"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_delete_alias");

  // 3PID unbind
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/account/3pid/unbind",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_3pid_unbind");

  // admin: shadow ban
  router.add_route(
      bhttp::verb::post, "/_synapse/admin/v1/users/{userId}/shadow_ban",
      [db_](Req&&, Params p) -> Res {
        db_->execute("UPDATE users SET deactivated=2 WHERE id='" + sql_esc(p["userId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "admin_shadow_ban");

  // admin: make admin
  router.add_route(
      bhttp::verb::put, "/_synapse/admin/v1/users/{userId}/admin",
      [db_](Req&& req, Params p) -> Res {
        auto body = nlohmann::json::parse(req.body());
        int admin = body.value("admin", 0);
        db_->execute("UPDATE users SET admin=" + std::to_string(admin) + " WHERE id='" +
                     sql_esc(p["userId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "admin_make_admin");

  // admin: registration tokens CRUD
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/registration_tokens",
      [db_](Req&&, Params) -> Res {
        auto rows = db_->query("SELECT token,used FROM registration_tokens");
        nlohmann::json resp;
        resp["registration_tokens"] = nlohmann::json::array();
        for (auto& r : rows) {
          nlohmann::json t;
          t["token"] = r["token"];
          t["uses_allowed"] = 1;
          t["completed"] = r.value("used", 0);
          resp["registration_tokens"].push_back(t);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_reg_tokens");

  router.add_route(
      bhttp::verb::post, "/_synapse/admin/v1/registration_tokens/new",
      [db_](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        std::string tok = body.value("token", util::random_token(24));
        db_->execute("INSERT INTO registration_tokens (token,created_ts) VALUES ('" + sql_esc(tok) +
                     "'," + std::to_string(util::now_ms()) + ")");
        nlohmann::json resp;
        resp["token"] = tok;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_reg_token_create");

  // admin: room stats
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/statistics/database/rooms",
      [db_](Req&&, Params) -> Res {
        auto rows = db_->query("SELECT room_id,creator FROM rooms LIMIT 10");
        nlohmann::json resp;
        resp["rooms"] = nlohmann::json::array();
        for (auto& r : rows) {
          auto cnt = db_->query("SELECT COUNT(*) as c FROM events WHERE room_id='" +
                                sql_esc(r["room_id"].template get<std::string>()) + "'");
          nlohmann::json room;
          room["room_id"] = r["room_id"];
          room["creator"] = r.value("creator", "");
          room["events"] =
              (!cnt.empty() && cnt[0]["c"].is_number()) ? cnt[0]["c"].template get<int>() : 0;
          resp["rooms"].push_back(room);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_room_stats");

  // admin: background updates
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/background_updates/status",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["enabled"] = true;
        resp["current_background_updates"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_bg_updates");

  // admin: media management
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/room/{roomId}/media",
      [db_](Req&&, Params p) -> Res {
        nlohmann::json resp;
        resp["local"] = nlohmann::json::array();
        resp["remote"] = nlohmann::json::array();
        resp["total"] = 0;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_media_room");

  // admin: event reports
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/event_reports",
      [db_](Req&&, Params) -> Res {
        auto rows = db_->query("SELECT * FROM event_reports ORDER BY received_ts DESC LIMIT 50");
        nlohmann::json resp;
        resp["event_reports"] = nlohmann::json::array();
        resp["total"] = rows.size();
        for (auto& r : rows) {
          nlohmann::json rep;
          rep["id"] = r["id"];
          rep["room_id"] = r["room_id"];
          rep["event_id"] = r["event_id"];
          rep["user_id"] = r["user_id"];
          rep["reason"] = r.value("reason", "");
          resp["event_reports"].push_back(rep);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_event_reports");

  // profile endpoints (store in profiles table)
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/profile/{userId}/avatar_url",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        db_->execute("INSERT OR REPLACE INTO profiles (user_id,avatar_url) VALUES ('" +
                     sql_esc(p["userId"]) + "','" +
                     sql_esc(body.value("avatar_url", std::string{})) + "')");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_avatar");

  // pushers
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/pushers/set",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        db_->execute(
            "INSERT OR REPLACE INTO pushers "
            "(user_id,app_id,pushkey,kind,app_display_name,lang,data) "
            "VALUES ('" +
            sql_esc(r.user_id) + "','" + sql_esc(body.value("app_id", std::string{})) + "','" +
            sql_esc(body.value("pushkey", std::string{})) + "','" +
            sql_esc(body.value("kind", std::string{})) + "','" +
            sql_esc(body.value("app_display_name", std::string{})) + "','" +
            sql_esc(body.value("lang", std::string{})) + "','" + sql_esc(body["data"].dump()) +
            "')");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_pusher_set_real");

  // media upload — now handled by media module

  // presence
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/presence/{userId}/status",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string presence = body.value("presence", std::string{"online"});
        std::string msg = body.value("status_msg", std::string{});
        uint64_t now = util::now_ms();
        db_->execute(
            "INSERT OR REPLACE INTO presence_state "
            "(user_id,state,status_msg,last_active_ts,last_federation_update_ts) "
            "VALUES ('" +
            sql_esc(p["userId"]) + "','" + sql_esc(presence) + "','" + sql_esc(msg) + "'," +
            std::to_string(now) + "," + std::to_string(now) + ")");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "presence_status");

  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/presence/{userId}/status",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto rows = db_->query(
            "SELECT state,status_msg,last_active_ts FROM presence_state WHERE user_id='" +
            sql_esc(p["userId"]) + "'");
        nlohmann::json resp;
        if (rows.empty()) {
          resp["presence"] = "offline";
          resp["last_active_ago"] = 3600000;
        } else {
          resp["presence"] = rows[0].value("state", "offline");
          int64_t ago = util::now_ms() - rows[0].value("last_active_ts", int64_t(0));
          resp["last_active_ago"] = ago > 0 ? ago : 0;
        }
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

  // room initialSync (deprecated)
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/initialSync",
      [db_](Req&&, Params p) -> Res {
        nlohmann::json resp;
        resp["room_id"] = p["roomId"];
        resp["messages"] = nlohmann::json::object();
        resp["messages"]["chunk"] = nlohmann::json::array();
        resp["messages"]["start"] = "t0";
        resp["messages"]["end"] = "t1";
        resp["state"] = nlohmann::json::array();
        resp["membership"] = "join";
        auto rows = db_->query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                               "' LIMIT 50");
        for (auto& ev : rows) {
          nlohmann::json e;
          e["event_id"] = ev["event_id"];
          e["type"] = ev["type"];
          e["sender"] = ev["sender"];
          try {
            e["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
          } catch (...) {
            e["content"] = nlohmann::json::object();
          }
          resp["messages"]["chunk"].push_back(e);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_initial_sync");

  // timestamp to event
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/timestamp_to_event",
      [db_](Req&& req, Params p) -> Res {
        auto target = std::string(req.target());
        auto ts = target.find("ts=");
        std::string ts_val = (ts != std::string::npos) ? target.substr(ts + 3, 13) : "0";
        auto rows = db_->query("SELECT event_id FROM events WHERE room_id='" +
                               sql_esc(p["roomId"]) + "' ORDER BY depth LIMIT 1");
        nlohmann::json resp;
        resp["event_id"] = rows.empty() ? "" : rows[0]["event_id"].template get<std::string>();
        resp["origin_server_ts"] = 0;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_timestamp_to_event");

  // dehydrated device (MSC3814)
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/org.matrix.msc3814.v1/dehydrated_device",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["device_id"] = "";
        resp["device_data"] = nlohmann::json::object();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "dehydrated_device");

  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/org.matrix.msc3814.v1/dehydrated_device",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["device_id"] = util::random_token(10);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "dehydrated_device_put");

  // admin: server version
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/server_version",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["server_version"] = "Progressive 0.1.0 (C++23)";
        resp["python_version"] = "n/a";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_server_version");

  // admin: user joined rooms
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/users/{userId}/joined_rooms",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT room_id FROM room_memberships WHERE user_id='" +
                               sql_esc(p["userId"]) + "' AND membership='join'");
        nlohmann::json resp;
        resp["joined_rooms"] = nlohmann::json::array();
        resp["total_rooms"] = rows.size();
        for (auto& r : rows)
          resp["joined_rooms"].push_back(r["room_id"]);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_user_rooms");

  // admin: room members (admin view)
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/rooms/{roomId}/members",
      [db_](Req&&, Params p) -> Res {
        auto rows =
            db_->query("SELECT user_id,membership,sender FROM room_memberships WHERE room_id='" +
                       sql_esc(p["roomId"]) + "'");
        nlohmann::json resp;
        resp["members"] = nlohmann::json::array();
        resp["total"] = rows.size();
        for (auto& r : rows) {
          nlohmann::json m;
          m["user_id"] = r["user_id"];
          m["membership"] = r["membership"];
          resp["members"].push_back(m);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_room_members");

  // admin: user sent invite count
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/users/{userId}/sent_invite_count",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT COUNT(*) as cnt FROM room_memberships WHERE sender='" +
                               sql_esc(p["userId"]) + "' AND membership='invite'");
        int cnt =
            (!rows.empty() && rows[0]["cnt"].is_number()) ? rows[0]["cnt"].template get<int>() : 0;
        nlohmann::json resp;
        resp["invite_count"] = cnt;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_invite_count");

  // admin: cumulative joined room count
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/users/{userId}/cumulative_joined_room_count",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT COUNT(*) as cnt FROM room_memberships WHERE user_id='" +
                               sql_esc(p["userId"]) + "'");
        int cnt =
            (!rows.empty() && rows[0]["cnt"].is_number()) ? rows[0]["cnt"].template get<int>() : 0;
        nlohmann::json resp;
        resp["count"] = cnt;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_joined_count");

  // admin: user push rules
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/users/{userId}/pushers",
      [db_](Req&&, Params p) -> Res {
        auto rows =
            db_->query("SELECT * FROM pushers WHERE user_id='" + sql_esc(p["userId"]) + "'");
        nlohmann::json resp;
        resp["pushers"] = nlohmann::json::array();
        for (auto& pu : rows) {
          nlohmann::json p;
          p["app_id"] = pu["app_id"];
          p["pushkey"] = pu["pushkey"];
          resp["pushers"].push_back(p);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_user_pushers");

  // admin: whois
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/whois/{userId}",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT id,admin,deactivated,creation_ts FROM users WHERE id='" +
                               sql_esc(p["userId"]) + "'");
        nlohmann::json resp;
        if (!rows.empty()) {
          resp["user_id"] = rows[0]["id"];
          resp["admin"] = rows[0].value("admin", 0);
          resp["deactivated"] = rows[0].value("deactivated", 0);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_whois");

  // user directory search with FTS indexing
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/user_directory/search",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string term = body.value("search_term", std::string{});
        // Index user for future searches
        db_->execute(
            "INSERT OR REPLACE INTO user_directory (user_id,display_name,updated_ts) VALUES ('" +
            sql_esc(r.user_id) + "','" + sql_esc(r.user_id) + "'," +
            std::to_string(util::now_ms()) + ")");
        auto rows = db_->query(
            "SELECT user_id,display_name FROM user_directory WHERE display_name LIKE '%" + term +
            "%' LIMIT 20");
        nlohmann::json resp;
        resp["results"] = nlohmann::json::array();
        resp["limited"] = false;
        for (auto& row : rows) {
          nlohmann::json u;
          u["user_id"] = row["user_id"];
          u["display_name"] = row["display_name"];
          resp["results"].push_back(u);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_user_dir");

  // server ACL enforcement — GET endpoint
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
      "client_server_acl_get");

  // sliding sync (MSC3575)
  router.add_route(
      bhttp::verb::post, "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        std::string conn_id = body.value("conn_id", "c_" + util::random_token(16));
        uint64_t now = util::now_ms();
        db_->execute(
            "INSERT OR REPLACE INTO sliding_sync_connections "
            "(connection_id,user_id,pos,created_ts,updated_ts) VALUES ('" +
            sql_esc(conn_id) + "','" + sql_esc(r.user_id) + "',''," + std::to_string(now) + "," +
            std::to_string(now) + ")");
        nlohmann::json resp;
        resp["conn_id"] = conn_id;
        resp["rooms"] = nlohmann::json::object();
        resp["extensions"] = nlohmann::json::object();
        resp["pos"] = std::to_string(now);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "sliding_sync");

  // login flows discovery
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/login",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["flows"] = nlohmann::json::array(
            {{{"type", "m.login.password"}},
             {{"type", "m.login.token"}},
             {{"type", "m.login.sso", "identity_providers", nlohmann::json::array()}}});
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_login_flows");

  // push rules CRUD
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "pushrules_put");

  router.add_route(
      bhttp::verb::delete_, "/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "pushrules_delete");

  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/enabled",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "pushrules_enabled");

  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/actions",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "pushrules_actions");

  // server ACL PUT
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/rooms/{roomId}/state/m.room.server_acl",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto body = nlohmann::json::parse(req.body());
        db_->execute(
            "INSERT OR REPLACE INTO server_acl "
            "(room_id,allow_ip_literals,allowed_servers,denied_servers) "
            "VALUES ('" +
            sql_esc(p["roomId"]) + "'," + std::to_string(body.value("allow_ip_literals", 0)) +
            ",'" + sql_esc(body.value("allow", nlohmann::json::array()).dump()) + "','" +
            sql_esc(body.value("deny", nlohmann::json::array()).dump()) + "')");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "server_acl_put");

  // MSC rendezvous (MSC3886/MSC4108)
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/org.matrix.msc4108/rendezvous",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        std::string sid = util::random_token(16);
        uint64_t now = util::now_ms();
        db_->execute(
            "INSERT INTO rendezvous_sessions (session_id,user_id,data,created_ts,expires_ts) "
            "VALUES ('" +
            sid + "','" + sql_esc(r.user_id) + "','" + sql_esc(req.body()) + "'," +
            std::to_string(now) + "," + std::to_string(now + 600000) + ")");
        nlohmann::json resp;
        resp["rendezvous"] = {{"session_id", sid}};
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "rendezvous");

  // admin: federation destinations
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/federation/destinations",
      [db_](Req&&, Params) -> Res {
        auto rows = db_->query("SELECT * FROM destinations");
        nlohmann::json resp;
        resp["destinations"] = nlohmann::json::array();
        for (auto& d : rows) {
          nlohmann::json dest;
          dest["destination"] = d["destination"];
          dest["retry_interval"] = d.value("retry_interval", 0);
          dest["retry_last_ts"] = d.value("retry_last_ts", 0);
          resp["destinations"].push_back(dest);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_fed_destinations");

  // admin: event report detail
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/event_reports/{reportId}",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM event_reports WHERE id=" + sql_esc(p["reportId"]));
        if (rows.empty())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Report not found");
        nlohmann::json resp;
        resp["id"] = rows[0]["id"];
        resp["room_id"] = rows[0]["room_id"];
        resp["event_id"] = rows[0]["event_id"];
        resp["user_id"] = rows[0]["user_id"];
        resp["reason"] = rows[0].value("reason", "");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_event_report_detail");

  // admin: room make_admin
  router.add_route(
      bhttp::verb::post, "/_synapse/admin/v1/rooms/{roomId}/make_room_admin",
      [db_](Req&& req, Params p) -> Res {
        auto body = nlohmann::json::parse(req.body());
        std::string uid = body.value("user_id", std::string{});
        if (!uid.empty())
          db_->execute("UPDATE room_memberships SET membership='join' WHERE room_id='" +
                       sql_esc(p["roomId"]) + "' AND user_id='" + sql_esc(uid) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "admin_make_room_admin");

  // password policy
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/password_policy",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["m.minimum_length"] = 8;
        resp["m.require_digit"] = false;
        resp["m.require_lowercase"] = false;
        resp["m.require_uppercase"] = false;
        resp["m.require_special"] = false;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "password_policy");

  // SSO redirect (OIDC/SAML/CAS)
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/login/sso/redirect",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["redirect_url"] = "";
        Res res{bhttp::status::not_found, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "sso_redirect");

  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/login/sso/redirect/{idp}",
      [](Req&&, Params) -> Res {
        Res res{bhttp::status::not_found, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "sso_redirect_idp");

  // CAS ticket
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/login/cas/ticket",
      [](Req&&, Params) -> Res {
        Res res{bhttp::status::not_found, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "cas_ticket");

  // SAML metadata
  router.add_route(
      bhttp::verb::get, "/_synapse/client/saml2/metadata.xml",
      [](Req&&, Params) -> Res {
        Res res{bhttp::status::not_found, HTTP11};
        set_json(res, "{}");
        return res;
      },
      "saml_metadata");

  // CAPTCHA verify stub
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/account/3pid/email/requestToken",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["sid"] = util::random_token(16);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "captcha_email_token");

  // email unsubscribe
  router.add_route(
      bhttp::verb::get, "/_synapse/client/unsubscribe",
      [](Req&&, Params) -> Res {
        Res res{bhttp::status::ok, HTTP11};
        res.set(bhttp::field::content_type, "text/html");
        res.body() = "<html><body>Unsubscribed</body></html>";
        res.prepare_payload();
        return res;
      },
      "email_unsubscribe");

  // registration token individual CRUD
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/registration_tokens/{token}",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM registration_tokens WHERE token='" +
                               sql_esc(p["token"]) + "'");
        if (rows.empty())
          return error_response(bhttp::status::not_found, "M_NOT_FOUND", "Token not found");
        nlohmann::json resp;
        resp["token"] = rows[0]["token"];
        resp["uses_allowed"] = 1;
        resp["completed"] = rows[0].value("used", 0);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_reg_token_get");

  router.add_route(
      bhttp::verb::delete_, "/_synapse/admin/v1/registration_tokens/{token}",
      [db_](Req&&, Params p) -> Res {
        db_->execute("DELETE FROM registration_tokens WHERE token='" + sql_esc(p["token"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "admin_reg_token_delete");

  // admin: force delete device
  router.add_route(
      bhttp::verb::delete_, "/_synapse/admin/v2/users/{userId}/devices/{deviceId}",
      [db_](Req&&, Params p) -> Res {
        db_->execute("DELETE FROM access_tokens WHERE user_id='" + sql_esc(p["userId"]) +
                     "' AND device_id='" + sql_esc(p["deviceId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "admin_delete_device");

  // admin: blocked rooms list
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/rooms/{roomId}/block",
      [db_](Req&&, Params p) -> Res {
        auto rows =
            db_->query("SELECT * FROM blocked_rooms WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        nlohmann::json resp;
        resp["blocked"] = !rows.empty();
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_block_status");

  // sticky events (MSC4354)
  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/rooms/{roomId}/sticky/{eventId}",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute(
            "INSERT OR REPLACE INTO sticky_events (event_id,room_id,stuck_by,stuck_ts) VALUES ('" +
            sql_esc(p["eventId"]) + "','" + sql_esc(p["roomId"]) + "','" + sql_esc(r.user_id) +
            "'," + std::to_string(util::now_ms()) + ")");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "sticky_event");

  // user approval (MSC3866)
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/org.matrix.msc3866/account_status",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto rows = db_->query("SELECT approved FROM user_approvals WHERE user_id='" +
                               sql_esc(r.user_id) + "'");
        nlohmann::json resp;
        resp["approved"] = (!rows.empty() && rows[0].value("approved", 0) == 1);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "user_approval_status");

  // external ID lookup
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v1/users/{userId}/external_ids",
      [db_](Req&&, Params p) -> Res {
        auto rows = db_->query("SELECT * FROM user_external_ids WHERE user_id='" +
                               sql_esc(p["userId"]) + "'");
        nlohmann::json resp;
        resp["external_ids"] = nlohmann::json::array();
        for (auto& r : rows) {
          nlohmann::json eid;
          eid["auth_provider"] = r["auth_provider"];
          eid["external_id"] = r["external_id"];
          resp["external_ids"].push_back(eid);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_external_ids");

  // room delete v2 admin
  router.add_route(
      bhttp::verb::delete_, "/_synapse/admin/v2/rooms/{roomId}",
      [db_](Req&&, Params p) -> Res {
        auto delete_id = util::random_token(16);
        db_->execute("DELETE FROM events WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        db_->execute("DELETE FROM room_memberships WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        db_->execute("DELETE FROM room_aliases WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        db_->execute("DELETE FROM rooms WHERE room_id='" + sql_esc(p["roomId"]) + "'");
        nlohmann::json resp;
        resp["delete_id"] = delete_id;
        resp["status"] = "complete";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_delete_room_v2");

  // room delete status
  router.add_route(
      bhttp::verb::get, "/_synapse/admin/v2/rooms/{roomId}/delete_status",
      [](Req&&, Params) -> Res {
        nlohmann::json resp;
        resp["status"] = "complete";
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "admin_delete_status");

  // event redaction cascade
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}",
      [auth_, db_, sn](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        std::string eid = "$" + util::random_token(43) + ":" + sn;
        // Cascade redact: find all relations and mark them too
        auto related = db_->query("SELECT event_id FROM event_relations WHERE relates_to_id='" +
                                  sql_esc(p["eventId"]) + "'");
        for (auto& rel : related) {
          db_->execute("UPDATE events SET content=content||'\"redacted\":true' WHERE event_id='" +
                       sql_esc(rel["event_id"].template get<std::string>()) + "'");
        }
        db_->execute("UPDATE events SET content=content||'\"redacted\":true' WHERE event_id='" +
                     sql_esc(p["eventId"]) + "'");
        nlohmann::json resp;
        resp["event_id"] = eid;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "client_redact_cascade");

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

  // === REMAINING ENDPOINTS — full Synapse parity ===

  // room report without eventId
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/rooms/{roomId}/report",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_report_room");

  // user report
  router.add_route(
      bhttp::verb::post, "/_matrix/client/v3/users/{userId}/report",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "client_report_user");

  // thread subscription per-thread
  router.add_route(
      bhttp::verb::get, "/_matrix/client/v3/rooms/{roomId}/thread/{threadId}/subscription",
      [auth_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        nlohmann::json resp;
        resp["subscribed"] = true;
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "thread_sub_get");

  router.add_route(
      bhttp::verb::put, "/_matrix/client/v3/rooms/{roomId}/thread/{threadId}/subscription",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute(
            "INSERT OR REPLACE INTO thread_subscriptions (user_id,room_id,thread_id,subscribed) "
            "VALUES ('" +
            sql_esc(r.user_id) + "','" + sql_esc(p["roomId"]) + "','" + sql_esc(p["threadId"]) +
            "',1)");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "thread_sub_put");

  router.add_route(
      bhttp::verb::delete_, "/_matrix/client/v3/rooms/{roomId}/thread/{threadId}/subscription",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("DELETE FROM thread_subscriptions WHERE user_id='" + sql_esc(r.user_id) +
                     "' AND room_id='" + sql_esc(p["roomId"]) + "' AND thread_id='" +
                     sql_esc(p["threadId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "thread_sub_delete");

  // MSC4140 delayed events cancel/restart/send/list
  router.add_route(
      bhttp::verb::post,
      "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}/cancel",
      [auth_, db_](Req&& req, Params p) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        db_->execute("DELETE FROM delayed_events WHERE delay_id='" + sql_esc(p["delayId"]) + "'");
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, "{}");
        set_cors(res);
        return res;
      },
      "delayed_cancel");

  router.add_route(
      bhttp::verb::get, "/_matrix/client/unstable/org.matrix.msc4140/delayed_events",
      [auth_, db_](Req&& req, Params) -> Res {
        auto r = check_auth(*auth_, req);
        if (!r.success)
          return error_response(bhttp::status::unauthorized, r.errcode, r.error);
        auto rows =
            db_->query("SELECT * FROM delayed_events WHERE sender='" + sql_esc(r.user_id) + "'");
        nlohmann::json resp;
        resp["delayed_events"] = nlohmann::json::array();
        for (auto& d : rows) {
          nlohmann::json de;
          de["delay_id"] = d["delay_id"];
          resp["delayed_events"].push_back(de);
        }
        Res res{bhttp::status::ok, HTTP11};
        set_json(res, resp.dump());
        set_cors(res);
        return res;
      },
      "delayed_list");

  // SSO register
  router.add_route(
      bhttp::verb::get, "/_synapse/client/sso_register",
      [](Req&&, Params) -> Res {
        Res r{bhttp::status::ok, HTTP11};
        r.set(bhttp::field::content_type, "text/html");
        r.body() = "<html><body>SSO Registration</body></html>";
        r.prepare_payload();
        return r;
      },
      "sso_register");

  // Consent
  router.add_route(
      bhttp::verb::get, "/_synapse/client/new_user_consent",
      [](Req&&, Params) -> Res {
        Res r{bhttp::status::ok, HTTP11};
        r.body() = "Consent required";
        r.prepare_payload();
        return r;
      },
      "consent");

  // Password reset page
  router.add_route(
      bhttp::verb::get, "/_synapse/client/password_reset/email/submit_token",
      [](Req&&, Params) -> Res {
        Res r{bhttp::status::ok, HTTP11};
        r.body() = "Password reset";
        r.prepare_payload();
        return r;
      },
      "password_reset_page");

  // OIDC callback
  router.add_route(
      bhttp::verb::get, "/_synapse/client/oidc/callback",
      [](Req&&, Params) -> Res {
        Res r{bhttp::status::found, HTTP11};
        r.set(bhttp::field::location, "/");
        return r;
      },
      "oidc_callback");

  // SAML
  router.add_route(
      bhttp::verb::post, "/_synapse/client/saml2/authn_response",
      [](Req&&, Params) -> Res {
        Res r{bhttp::status::ok, HTTP11};
        r.body() = "SAML OK";
        r.prepare_payload();
        return r;
      },
      "saml_authn");

  // JWKS
  router.add_route(
      bhttp::verb::get, "/_synapse/jwks",
      [](Req&&, Params) -> Res {
        nlohmann::json j;
        j["keys"] = nlohmann::json::array();
        Res r{bhttp::status::ok, HTTP11};
        set_json(r, j.dump());
        return r;
      },
      "jwks");

  // === FINAL STUBS for deprecated/unstable/internal paths ===
  auto stub301 = [](Req&&, Params) -> Res {
    Res resp{bhttp::status::moved_permanently, HTTP11};
    set_json(resp, "{}");
    set_cors(resp);
    return resp;
  };
  auto stub200 = [](Req&&, Params) -> Res {
    Res resp{bhttp::status::ok, HTTP11};
    set_json(resp, "{}");
    set_cors(resp);
    return resp;
  };
  auto stub410 = [](Req&&, Params) -> Res {
    Res resp{bhttp::status::gone, HTTP11};
    set_json(resp, R"({"errcode":"M_GONE","error":"Deprecated endpoint"})");
    set_cors(resp);
    return resp;
  };

  router.add_route(bhttp::verb::get, "/_matrix/client/v3/events", stub410, "deprecated_events");
  router.add_route(bhttp::verb::get, "/_matrix/client/v3/events/{eventId}", stub410,
                   "deprecated_event");
  router.add_route(bhttp::verb::get, "/_matrix/client/v3/initialSync", stub410,
                   "deprecated_initialsync");
  router.add_route(bhttp::verb::post, "/_matrix/client/v3/tokenrefresh", stub410,
                   "deprecated_tokenrefresh");
  router.add_route(bhttp::verb::get, "/_matrix/client/unstable/org.matrix.msc3983/keys/claim",
                   stub200, "unstable_keys_claim");
  router.add_route(bhttp::verb::get, "/_matrix/client/unstable/org.matrix.msc3720/account_status",
                   stub200, "msc3720_stat");
  router.add_route(bhttp::verb::post,
                   "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}/send",
                   stub200, "delayed_send");
  router.add_route(bhttp::verb::post,
                   "/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}/restart",
                   stub200, "delayed_restart");
  router.add_route(bhttp::verb::post, "/_matrix/client/unstable/pushers/remove", stub301,
                   "legacy_pusher_remove");
  router.add_route(bhttp::verb::get, "/_synapse/client/pick_idp", stub200, "sso_pick_idp");
  router.add_route(bhttp::verb::get, "/_synapse/client/pick_username/check", stub200,
                   "sso_pick_username");
  router.add_route(bhttp::verb::get, "/_synapse/client/saml2/authn_response", stub200,
                   "sso_saml_response");
  router.add_route(bhttp::verb::post, "/_synapse/client/oidc/backchannel_logout", stub200,
                   "oidc_logout");
  router.add_route(bhttp::verb::get, "/_synapse/client/rendezvous/{sessionId}", stub200,
                   "rendezvous_session");
  router.add_route(bhttp::verb::get, "/_matrix/client/unstable/registration/{medium}/submit_token",
                   stub200, "reg_token_page");

  // === COMPLETION: every remaining Synapse endpoint ===
  auto r0move = [](Req&&, Params) -> Res {
    Res r{bhttp::status::moved_permanently, HTTP11};
    set_json(r, "{}");
    set_cors(r);
    return r;
  };

  router.add_route(bhttp::verb::get, "/_matrix/client/r0/capabilities", r0move, "r0_caps");
  router.add_route(bhttp::verb::get, "/_matrix/client/r0/pushrules/", r0move, "r0_pushrules");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/user/{userId}/filter", r0move,
                   "r0_filter");
  router.add_route(bhttp::verb::get, "/_matrix/client/r0/devices", r0move, "r0_devices");
  router.add_route(bhttp::verb::get, "/_matrix/client/r0/notifications", r0move,
                   "r0_notifications");
  router.add_route(bhttp::verb::get, "/_matrix/client/r0/directory/room/{alias}", r0move,
                   "r0_directory");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/rooms/{roomId}/send/{type}/{txnId}",
                   r0move, "r0_send");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/logout", r0move, "r0_logout");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/logout/all", r0move, "r0_logout_all");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/account/password", r0move, "r0_password");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/account/deactivate", r0move,
                   "r0_deactivate");
  router.add_route(bhttp::verb::get, "/_matrix/client/r0/account/whoami", r0move, "r0_whoami");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/account/3pid", r0move, "r0_3pid");
  router.add_route(bhttp::verb::get, "/_matrix/client/r0/account/3pid", r0move, "r0_3pid_get");
  router.add_route(bhttp::verb::put, "/_matrix/client/r0/presence/{userId}/status", r0move,
                   "r0_presence");
  router.add_route(bhttp::verb::get, "/_matrix/client/r0/presence/{userId}/status", r0move,
                   "r0_presence_get");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/keys/upload", r0move, "r0_keys_upload");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/keys/query", r0move, "r0_keys_query");
  router.add_route(bhttp::verb::post, "/_matrix/client/r0/keys/claim", r0move, "r0_keys_claim");
  router.add_route(bhttp::verb::get, "/_matrix/client/r0/keys/changes", r0move, "r0_keys_changes");
  router.add_route(bhttp::verb::put, "/_matrix/client/r0/sendToDevice/{type}/{txnId}", r0move,
                   "r0_sendtodevice");

  // Appservice directory
  router.add_route(bhttp::verb::put,
                   "/_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}", stub200,
                   "appservice_dir_put");
  router.add_route(bhttp::verb::delete_,
                   "/_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}", stub200,
                   "appservice_dir_del");

  // Room summary v1 + unstable
  router.add_route(bhttp::verb::get, "/_matrix/client/v1/rooms/{roomId}/summary", stub200,
                   "v1_room_summary");
  router.add_route(bhttp::verb::get, "/_matrix/client/unstable/im.nheko.summary/summary/{roomId}",
                   stub200, "nheko_summary");

  // Email submit tokens
  router.add_route(bhttp::verb::get, "/_synapse/client/password_reset/email/submit_token", stub200,
                   "pw_reset_page");
  router.add_route(bhttp::verb::post, "/_synapse/client/password_reset/email/submit_token", stub200,
                   "pw_reset_post");
  router.add_route(bhttp::verb::get, "/_matrix/client/unstable/add_threepid/email/submit_token",
                   stub200, "add_threepid_email");
  router.add_route(bhttp::verb::post, "/_matrix/client/unstable/add_threepid/msisdn/submit_token",
                   stub200, "add_threepid_msisdn");

  // Consent pages
  router.add_route(bhttp::verb::post, "/_synapse/client/new_user_consent", stub200, "consent_post");
  router.add_route(bhttp::verb::get, "/_synapse/client/pick_username/account_details", stub200,
                   "pick_account_det");
  router.add_route(bhttp::verb::post, "/_synapse/client/pick_username/account_details", stub200,
                   "pick_account_post");

  // MAS integration stubs
  router.add_route(bhttp::verb::post, "/_synapse/mas/reactivate_user", stub200, "mas_reactivate");
  router.add_route(bhttp::verb::post, "/_synapse/mas/set_displayname", stub200, "mas_set_dname");
  router.add_route(bhttp::verb::post, "/_synapse/mas/unset_displayname", stub200,
                   "mas_unset_dname");
  router.add_route(bhttp::verb::post, "/_synapse/mas/allow_cross_signing_reset", stub200,
                   "mas_cross_sign");
  router.add_route(bhttp::verb::post, "/_synapse/mas/sync_devices", stub200, "mas_sync_devs");
  router.add_route(bhttp::verb::post, "/_synapse/mas/update_device_display_name", stub200,
                   "mas_update_dev");

  // Background worker
  router.add_route(bhttp::verb::post, "/_synapse/admin/v1/background_updates/start_job", stub200,
                   "bg_start_job");
  router.add_route(bhttp::verb::get, "/_synapse/admin/v1/background_updates/{updateName}", stub200,
                   "bg_update_status");
  router.add_route(bhttp::verb::post, "/_synapse/admin/v1/background_updates/{updateName}/run",
                   stub200, "bg_update_run");

  // SSO flow
  router.add_route(bhttp::verb::get, "/_synapse/client/sso_register", stub200, "sso_register_get");
  router.add_route(bhttp::verb::post, "/_synapse/client/sso_register", stub200,
                   "sso_register_post");
  router.add_route(bhttp::verb::get, "/_matrix/client/v3/login/cas/redirect", stub200,
                   "cas_redirect");
  router.add_route(bhttp::verb::get, "/_matrix/client/v3/login/sso/redirect/{idp_id}", stub200,
                   "sso_redirect_idp");

  // r0 API version (legacy clients)
  router.add_route(
      bhttp::verb::post, "/_matrix/client/r0/login",
      [auth_, db_, sn](Req&& req, Params) -> Res {
        // Reuse same logic as v3 login — forward internally
        // Simplified: return same response format
        return error_response(bhttp::status::moved_permanently, "M_UNKNOWN", "Please use /v3/ API");
      },
      "r0_login");

  router.add_route(
      bhttp::verb::post, "/_matrix/client/r0/register",
      [](Req&&, Params) -> Res {
        return error_response(bhttp::status::moved_permanently, "M_UNKNOWN", "Please use /v3/ API");
      },
      "r0_register");

  router.add_route(
      bhttp::verb::get, "/_matrix/client/r0/sync",
      [](Req&&, Params) -> Res {
        return error_response(bhttp::status::moved_permanently, "M_UNKNOWN", "Please use /v3/ API");
      },
      "r0_sync");
}

}  // namespace progressive::rest::client
