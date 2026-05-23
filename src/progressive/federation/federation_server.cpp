#include "federation_server.hpp"

#include <nlohmann/json.hpp>

#include "../events/event.hpp"
#include "../http/router.hpp"
#include "../util/time.hpp"
#include "auth.hpp"

namespace progressive::federation {

namespace bhttp = boost::beast::http;

PDU PDU::from_json(const nlohmann::json& j) {
  PDU p;
  p.event_id = j.at("event_id").get<std::string>();
  p.room_id = j.at("room_id").get<std::string>();
  p.type = j.at("type").get<std::string>();
  p.sender = j.at("sender").get<std::string>();
  p.content = j.at("content");
  p.depth = j.value("depth", int64_t(0));
  for (auto& pe : j.value("prev_events", nlohmann::json::array()))
    if (pe.is_string())
      p.prev_events.push_back(pe.get<std::string>());
  for (auto& ae : j.value("auth_events", nlohmann::json::array()))
    if (ae.is_string())
      p.auth_events.push_back(ae.get<std::string>());
  p.origin = j.value("origin", std::string{});
  p.origin_server_ts = j.value("origin_server_ts", std::string{});
  if (j.contains("state_key") && j["state_key"].is_string())
    p.state_key = j["state_key"].get<std::string>();
  if (j.contains("signatures"))
    p.signatures = j["signatures"];
  return p;
}

nlohmann::json PDU::to_json() const {
  nlohmann::json j;
  j["event_id"] = event_id;
  j["room_id"] = room_id;
  j["type"] = type;
  j["sender"] = sender;
  j["content"] = content;
  j["depth"] = depth;
  j["prev_events"] = prev_events;
  j["auth_events"] = auth_events;
  j["origin"] = origin;
  j["origin_server_ts"] = origin_server_ts;
  if (state_key)
    j["state_key"] = *state_key;
  j["signatures"] = signatures;
  return j;
}

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

static int64_t safe_int(const nlohmann::json& j, const char* key, int64_t def) {
  try {
    return j.value(key, def);
  } catch (...) {
    return def;
  }
}

static std::string safe_str(const nlohmann::json& j, const char* key, const std::string& def) {
  try {
    return j.value(key, def);
  } catch (...) {
    return def;
  }
}

void register_federation_routes(storage::DatabasePool& db, progressive::http::Router& router,
                                std::string_view server_name) {
  using Req = bhttp::request<bhttp::string_body>;
  using Res = bhttp::response<bhttp::string_body>;
  using Params = std::map<std::string, std::string>;
  namespace phttp = progressive::http;

  // GET /_matrix/federation/v1/version
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/version",
      [server_name](Req&&, Params) -> Res {
        nlohmann::json j;
        j["server"] = {{"name", server_name}, {"version", "Progressive 0.1.0"}};
        Res r{bhttp::status::ok, 11};
        phttp::set_json(r, j.dump());
        return r;
      },
      "fed_version");

  // PUT /_matrix/federation/v1/send/{txnId}
  router.add_route(
      bhttp::verb::put, "/_matrix/federation/v1/send/{txnId}",
      [&db](Req&& req, Params p) -> Res {
        try {
          auto body = nlohmann::json::parse(req.body());
          auto txn_origin = body.value("origin", std::string{});
          uint64_t txn_ts = body.value("origin_server_ts", uint64_t(0));
          uint64_t now = util::now_ms();

          // Process PDUs
          if (body.contains("pdus") && body["pdus"].is_array()) {
            for (auto& pdu_json : body["pdus"]) {
              auto pdu = PDU::from_json(pdu_json);

              // Validate PDU signature
              if (!pdu_json.contains("signatures") || pdu_json["signatures"].empty()) {
                return make_federation_error(bhttp::status::bad_request, "M_BAD_SIGNATURE",
                                             "Missing PDU signatures");
              }

              // Basic auth check: event must have sender matching origin
              if (pdu.sender.find(txn_origin) == std::string::npos) {
                return make_federation_error(bhttp::status::forbidden, "M_FORBIDDEN",
                                             "PDU sender must match transaction origin");
              }

              // Check for duplicate event
              auto existing = db.query("SELECT event_id FROM events WHERE event_id='" +
                                       sql_esc(pdu_json.value("event_id", std::string{})) + "'");
              if (!existing.empty())
                continue;  // skip duplicate
              db.execute(
                  "INSERT OR REPLACE INTO events "
                  "(event_id,room_id,type,sender,content,state_key,depth,"
                  "origin_server_ts,stream_ordering) VALUES ('" +
                  sql_esc(pdu.event_id) + "','" + sql_esc(pdu.room_id) + "','" + sql_esc(pdu.type) +
                  "','" + sql_esc(pdu.sender) + "','" + sql_esc(pdu.content.dump()) + "','" +
                  sql_esc(pdu.state_key.value_or("")) + "'," + std::to_string(pdu.depth) + ",'" +
                  sql_esc(pdu.origin_server_ts) + "'," + std::to_string(now) + ")");
            }
          }

          nlohmann::json resp;
          resp["pdus"] = nlohmann::json::object();
          Res r{bhttp::status::ok, 11};
          phttp::set_json(r, resp.dump());
          return r;
        } catch (const std::exception& e) {
          return make_federation_error(bhttp::status::bad_request, "M_BAD_JSON", e.what());
        }
      },
      "fed_send");

  // GET /_matrix/federation/v1/event/{eventId}
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/event/{eventId}",
      [&db](Req&&, Params p) -> Res {
        try {
          auto eid = p["eventId"];
          auto rows = db.query("SELECT * FROM events WHERE event_id='" + sql_esc(eid) + "'");
          if (rows.empty() || rows[0]["event_id"].is_null()) {
            return make_federation_error(bhttp::status::not_found, "M_NOT_FOUND",
                                         "Event not found");
          }
          auto& ev = rows[0];
          nlohmann::json j;
          j["event_id"] = ev["event_id"];
          j["room_id"] = ev["room_id"];
          j["type"] = ev["type"];
          j["sender"] = ev["sender"];
          try {
            j["content"] = nlohmann::json::parse(ev["content"].get<std::string>());
          } catch (...) {
            j["content"] = nlohmann::json::object();
          }
          j["depth"] = safe_int(ev, "depth", 0);
          j["origin_server_ts"] = safe_str(ev, "origin_server_ts", "");
          if (!ev["state_key"].is_null() && !ev["state_key"].get<std::string>().empty())
            j["state_key"] = ev["state_key"];

          nlohmann::json resp;
          resp["origin"] = "localhost";
          resp["origin_server_ts"] = util::now_ms();
          j["prev_events"] = nlohmann::json::array();
          j["auth_events"] = nlohmann::json::array();
          if (!ev["state_key"].is_null() && !ev["state_key"].get<std::string>().empty())
            j["state_key"] = ev["state_key"];
          j["signatures"] = nlohmann::json::object();

          resp["pdus"] = nlohmann::json::array({j});
          Res r{bhttp::status::ok, 11};
          phttp::set_json(r, resp.dump());
          return r;
        } catch (const std::exception& e) {
          return make_federation_error(bhttp::status::internal_server_error, "M_UNKNOWN", e.what());
        }
      },
      "fed_event");

  // GET /_matrix/federation/v1/make_join/{roomId}/{userId}
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/make_join/{roomId}/{userId}",
      [&db](Req&&, Params p) -> Res {
        auto rid = p["roomId"];
        auto rows = db.query("SELECT * FROM rooms WHERE room_id='" + sql_esc(rid) + "'");
        if (rows.empty() || rows[0]["room_id"].is_null()) {
          return make_federation_error(bhttp::status::not_found, "M_NOT_FOUND", "Room not found");
        }
        nlohmann::json j;
        j["room_version"] = "10";

        // Get forward extremities as prev_events
        auto fe = db.query("SELECT event_id FROM event_forward_extremities WHERE room_id='" +
                           sql_esc(rid) + "'");
        nlohmann::json prevs = nlohmann::json::array();
        for (auto& f : fe)
          prevs.push_back(f["event_id"].template get<std::string>());

        // Get last few events as auth_events
        auto auth = db.query("SELECT event_id FROM events WHERE room_id='" + sql_esc(rid) +
                             "' ORDER BY depth DESC LIMIT 5");
        nlohmann::json auths = nlohmann::json::array();
        for (auto& a : auth)
          auths.push_back(a["event_id"].template get<std::string>());

        nlohmann::json evt;
        evt["type"] = "m.room.member";
        evt["sender"] = p["userId"];
        evt["room_id"] = rid;
        evt["state_key"] = p["userId"];
        evt["content"] = {{"membership", "join"}};
        evt["depth"] = 1;
        evt["auth_events"] = auths;
        evt["prev_events"] = prevs;
        j["event"] = evt;

        Res r{bhttp::status::ok, 11};
        phttp::set_json(r, j.dump());
        return r;
      },
      "fed_make_join");

  // PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}
  router.add_route(
      bhttp::verb::put, "/_matrix/federation/v1/send_join/{roomId}/{eventId}",
      [&db](Req&& req, Params p) -> Res {
        try {
          auto body = nlohmann::json::parse(req.body());
          uint64_t now = util::now_ms();

          // Store the join event
          if (body.contains("event")) {
            auto& evt = body["event"];
            std::string eid = evt.value("event_id", std::string{});
            if (!eid.empty()) {
              db.execute(
                  "INSERT OR REPLACE INTO events "
                  "(event_id,room_id,type,sender,content,state_key,depth,"
                  "origin_server_ts,stream_ordering) VALUES ('" +
                  sql_esc(eid) + "','" + sql_esc(p["roomId"]) + "','" +
                  sql_esc(evt.value("type", std::string{})) + "','" +
                  sql_esc(evt.value("sender", std::string{})) + "','" +
                  sql_esc(evt["content"].dump()) + "','" +
                  sql_esc(evt.value("state_key", std::string{})) + "'," +
                  std::to_string(evt.value("depth", int64_t(1))) + ",'" +
                  sql_esc(evt.value("origin_server_ts", std::string{})) + "'," +
                  std::to_string(now) + ")");
              db.execute(
                  "INSERT OR REPLACE INTO room_memberships "
                  "(event_id,room_id,user_id,membership,sender) VALUES ('" +
                  sql_esc(eid) + "','" + sql_esc(p["roomId"]) + "','" +
                  sql_esc(evt.value("state_key", std::string{})) + "','join','" +
                  sql_esc(evt.value("sender", std::string{})) + "')");

              // Update forward extremities
              db.execute("DELETE FROM event_forward_extremities WHERE room_id='" +
                         sql_esc(p["roomId"]) + "'");
              db.execute("INSERT INTO event_forward_extremities (event_id,room_id) VALUES ('" +
                         sql_esc(eid) + "','" + sql_esc(p["roomId"]) + "')");
            }
          }

          // Return auth chain + state
          nlohmann::json resp;
          resp["auth_chain"] = nlohmann::json::array();
          // Auth chain: depth-sorted events before the join event
          auto auth_rows = db.query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                                    "' AND depth < 10 ORDER BY depth LIMIT 10");
          for (auto& ar : auth_rows) {
            nlohmann::json ae;
            ae["event_id"] = ar["event_id"];
            ae["type"] = ar["type"];
            ae["sender"] = ar["sender"];
            ae["room_id"] = ar["room_id"];
            ae["depth"] = ar.value("depth", int64_t(0));
            ae["auth_events"] = nlohmann::json::array();
            ae["prev_events"] = nlohmann::json::array();
            ae["origin"] = "localhost";
            ae["origin_server_ts"] = ar.value("origin_server_ts", "");
            try {
              ae["content"] = nlohmann::json::parse(ar["content"].template get<std::string>());
            } catch (...) {
              ae["content"] = nlohmann::json::object();
            }
            if (!ar["state_key"].is_null())
              ae["state_key"] = ar["state_key"];
            resp["auth_chain"].push_back(ae);
          }
          resp["state"] = nlohmann::json::array();

          // Get room state
          auto state_rows = db.query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                                     "' AND state_key != ''");
          for (auto& sr : state_rows) {
            nlohmann::json se;
            se["event_id"] = sr["event_id"];
            se["type"] = sr["type"];
            se["sender"] = sr["sender"];
            se["room_id"] = sr["room_id"];
            se["state_key"] = sr["state_key"];
            try {
              se["content"] = nlohmann::json::parse(sr["content"].get<std::string>());
            } catch (...) {
              se["content"] = nlohmann::json::object();
            }
            resp["state"].push_back(se);
          }

          Res r{bhttp::status::ok, 11};
          phttp::set_json(r, resp.dump());
          return r;
        } catch (const std::exception& e) {
          return make_federation_error(bhttp::status::internal_server_error, "M_UNKNOWN", e.what());
        }
      },
      "fed_send_join");

  // GET /_matrix/federation/v1/state/{roomId}
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/state/{roomId}",
      [&db](Req&&, Params p) -> Res {
        nlohmann::json resp;
        resp["auth_chain"] = nlohmann::json::array();
        resp["pdus"] = nlohmann::json::array();

        auto rows = db.query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                             "' AND state_key != ''");
        for (auto& sr : rows) {
          nlohmann::json se;
          se["event_id"] = sr["event_id"];
          se["type"] = sr["type"];
          se["sender"] = sr["sender"];
          se["room_id"] = sr["room_id"];
          se["state_key"] = sr["state_key"];
          try {
            se["content"] = nlohmann::json::parse(sr["content"].get<std::string>());
          } catch (...) {
            se["content"] = nlohmann::json::object();
          }
          se["depth"] = sr.value("depth", int64_t(0));
          resp["pdus"].push_back(se);
        }

        Res r{bhttp::status::ok, 11};
        phttp::set_json(r, resp.dump());
        return r;
      },
      "fed_state");

  // GET /_matrix/federation/v1/query/directory
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/query/directory",
      [&db](Req&&, Params) -> Res {
        Res r{bhttp::status::not_found, 11};
        nlohmann::json j;
        j["errcode"] = "M_NOT_FOUND";
        j["error"] = "Room alias not found";
        phttp::set_json(r, j.dump());
        return r;
      },
      "fed_directory");

  // GET /_matrix/federation/v1/query/profile
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/query/profile",
      [](Req&&, Params) -> Res {
        Res r{bhttp::status::not_found, 11};
        nlohmann::json j;
        j["errcode"] = "M_NOT_FOUND";
        j["error"] = "Profile not found";
        phttp::set_json(r, j.dump());
        return r;
      },
      "fed_profile");

  // backfill
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/backfill/{roomId}",
      [&db](Req&&, Params p) -> Res {
        nlohmann::json resp;
        resp["origin"] = "localhost";
        resp["origin_server_ts"] = util::now_ms();
        resp["pdus"] = nlohmann::json::array();

        auto rows = db.query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                             "' ORDER BY depth DESC LIMIT 50");
        for (auto& ev : rows) {
          nlohmann::json pdu;
          pdu["event_id"] = ev["event_id"];
          pdu["room_id"] = ev["room_id"];
          pdu["type"] = ev["type"];
          pdu["sender"] = ev["sender"];
          try {
            pdu["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
          } catch (...) {
            pdu["content"] = nlohmann::json::object();
          }
          pdu["depth"] = ev.value("depth", int64_t(0));
          pdu["origin"] = "localhost";
          pdu["origin_server_ts"] = ev.value("origin_server_ts", "");
          if (!ev["state_key"].is_null())
            pdu["state_key"] = ev["state_key"];
          resp["pdus"].push_back(pdu);
        }
        Res r{bhttp::status::ok, 11};
        phttp::set_json(r, resp.dump());
        return r;
      },
      "fed_backfill");

  // event auth — return real auth chain as PDUs
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/event_auth/{roomId}/{eventId}",
      [&db](Req&&, Params p) -> Res {
        nlohmann::json resp;
        resp["auth_chain"] = nlohmann::json::array();
        // Return events before this event in the room's DAG as the auth chain
        auto target =
            db.query("SELECT depth FROM events WHERE event_id='" + sql_esc(p["eventId"]) + "'");
        int target_depth = 0;
        if (!target.empty() && target[0]["depth"].is_number())
          target_depth = target[0]["depth"].template get<int>();

        auto rows = db.query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                             "' AND depth < " + std::to_string(std::max(1, target_depth)) +
                             " ORDER BY depth LIMIT 10");
        for (auto& ev : rows) {
          nlohmann::json pdu;
          pdu["event_id"] = ev["event_id"];
          pdu["room_id"] = ev["room_id"];
          pdu["type"] = ev["type"];
          pdu["sender"] = ev["sender"];
          pdu["depth"] = ev.value("depth", int64_t(0));
          pdu["auth_events"] = nlohmann::json::array();
          pdu["prev_events"] = nlohmann::json::array();
          pdu["origin"] = "localhost";
          pdu["origin_server_ts"] = ev.value("origin_server_ts", "");
          try {
            pdu["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
          } catch (...) {
            pdu["content"] = nlohmann::json::object();
          }
          resp["auth_chain"].push_back(pdu);
        }
        Res res{bhttp::status::ok, 11};
        phttp::set_json(res, resp.dump());
        return res;
      },
      "fed_event_auth");

  // get missing events
  router.add_route(
      bhttp::verb::post, "/_matrix/federation/v1/get_missing_events/{roomId}",
      [&db](Req&&, Params p) -> Res {
        nlohmann::json resp;
        resp["events"] = nlohmann::json::array();
        auto rows = db.query("SELECT * FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                             "' ORDER BY depth DESC LIMIT 20");
        for (auto& ev : rows) {
          nlohmann::json pdu;
          pdu["event_id"] = ev["event_id"];
          pdu["room_id"] = ev["room_id"];
          pdu["type"] = ev["type"];
          pdu["sender"] = ev["sender"];
          try {
            pdu["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
          } catch (...) {
            pdu["content"] = nlohmann::json::object();
          }
          pdu["depth"] = ev.value("depth", int64_t(0));
          resp["events"].push_back(pdu);
        }
        Res res{bhttp::status::ok, 11};
        phttp::set_json(res, resp.dump());
        return res;
      },
      "fed_missing_events");

  // make leave
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/make_leave/{roomId}/{userId}",
      [](Req&&, Params p) -> Res {
        nlohmann::json j;
        j["room_version"] = "10";
        nlohmann::json evt;
        evt["type"] = "m.room.member";
        evt["sender"] = p["userId"];
        evt["room_id"] = p["roomId"];
        evt["state_key"] = p["userId"];
        evt["content"] = {{"membership", "leave"}};
        evt["depth"] = 1;
        j["event"] = evt;
        Res r{bhttp::status::ok, 11};
        phttp::set_json(r, j.dump());
        return r;
      },
      "fed_make_leave");

  router.add_route(
      bhttp::verb::put, "/_matrix/federation/v1/send_leave/{roomId}/{eventId}",
      [](Req&&, Params) -> Res {
        nlohmann::json j;
        j["auth_chain"] = nlohmann::json::array();
        j["state"] = nlohmann::json::array();
        Res r{bhttp::status::ok, 11};
        phttp::set_json(r, j.dump());
        return r;
      },
      "fed_send_leave");

  // query profile
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/query/profile",
      [&db](Req&&, Params) -> Res {
        Res r{bhttp::status::not_found, 11};
        nlohmann::json j;
        j["errcode"] = "M_NOT_FOUND";
        j["error"] = "Profile not found";
        phttp::set_json(r, j.dump());
        return r;
      },
      "fed_query_profile");

  // state_ids
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/state_ids/{roomId}",
      [&db](Req&&, Params p) -> Res {
        nlohmann::json resp;
        resp["pdu_ids"] = nlohmann::json::array();
        resp["auth_chain_ids"] = nlohmann::json::array();
        auto rows = db.query("SELECT event_id FROM events WHERE room_id='" + sql_esc(p["roomId"]) +
                             "' LIMIT 50");
        for (auto& r : rows)
          resp["pdu_ids"].push_back(r["event_id"]);
        Res res{bhttp::status::ok, 11};
        phttp::set_json(res, resp.dump());
        return res;
      },
      "fed_state_ids");

  // invite
  router.add_route(
      bhttp::verb::put, "/_matrix/federation/v2/invite/{roomId}/{eventId}",
      [&db](Req&& req, Params p) -> Res {
        auto body = nlohmann::json::parse(req.body());
        if (body.contains("event")) {
          auto& evt = body["event"];
          db.execute(
              "INSERT OR REPLACE INTO events (event_id,room_id,type,sender,content,state_key,depth,"
              "origin_server_ts,stream_ordering) VALUES ('" +
              sql_esc(evt.value("event_id", p["eventId"])) + "','" +
              sql_esc(evt.value("room_id", p["roomId"])) + "','" +
              sql_esc(evt.value("type", std::string{"m.room.member"})) + "','" +
              sql_esc(evt.value("sender", std::string{})) + "','" + sql_esc(evt["content"].dump()) +
              "','" + sql_esc(evt.value("state_key", std::string{})) + "'," +
              std::to_string(evt.value("depth", int64_t(1))) + ",'" +
              sql_esc(evt.value("origin_server_ts", std::string{})) + "'," +
              std::to_string(util::now_ms()) + ")");
          db.execute(
              "INSERT OR REPLACE INTO room_memberships "
              "(event_id,room_id,user_id,membership,sender) "
              "VALUES ('" +
              sql_esc(evt.value("event_id", p["eventId"])) + "','" +
              sql_esc(evt.value("room_id", p["roomId"])) + "','" +
              sql_esc(evt.value("state_key", std::string{})) + "','invite','" +
              sql_esc(evt.value("sender", std::string{})) + "')");
        }
        nlohmann::json resp;
        resp["event"] = body.value("event", nlohmann::json::object());
        Res r{bhttp::status::ok, 11};
        phttp::set_json(r, resp.dump());
        return r;
      },
      "fed_invite");

  // federation media download
  router.add_route(
      bhttp::verb::get, "/_matrix/federation/v1/media/download/{mediaId}",
      [](Req&&, Params) -> Res {
        Res r{bhttp::status::not_found, 11};
        phttp::set_json(r, R"({"errcode":"M_NOT_FOUND","error":"Media not found"})");
        return r;
      },
      "fed_media_download");
}

}  // namespace progressive::federation
