#include "ruma_wrapper.hpp"

#include <iostream>

namespace ruma {

const char* errcode(ErrorKind kind) {
  switch (kind) {
    case ErrorKind::InvalidUsername: return "M_INVALID_USERNAME";
    case ErrorKind::UserInUse: return "M_USER_IN_USE";
    case ErrorKind::Forbidden: return "M_FORBIDDEN";
    case ErrorKind::Unknown: return "M_UNKNOWN";
    case ErrorKind::NotFound: return "M_NOT_FOUND";
    case ErrorKind::UserDeactivated: return "M_USER_DEACTIVATED";
    case ErrorKind::InvalidParam: return "M_INVALID_PARAM";
    case ErrorKind::BadJson: return "M_BAD_JSON";
  }
  return "M_UNKNOWN";
}

// serde_json::from_str::<RegisterRequest>(body)

template <>
Ruma<RegisterRequest> Ruma<RegisterRequest>::from_request(const httplib::Request& req) {
  RegisterRequest parsed;
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      if (auto it = body.find("username"); it != body.end() && it->is_string())
        parsed.username = it->get<std::string>();
      if (auto it = body.find("password"); it != body.end() && it->is_string())
        parsed.password = it->get<std::string>();
      if (auto it = body.find("device_id"); it != body.end() && it->is_string())
        parsed.device_id = it->get<std::string>();
    }
  }
  Ruma<RegisterRequest> wrapper;
  wrapper.value = std::move(parsed);
  return wrapper;
}

// serde_json::from_str::<LoginRequest>: flattened legacy form preferred, like
// old ruma; modern "identifier" nesting accepted too.
template <>
Ruma<LoginRequest> Ruma<LoginRequest>::from_request(const httplib::Request& req) {
  LoginRequest parsed;
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      auto type = body.find("type");
      if (type != body.end() && *type == "m.id.user") {
        auto user = body.find("user");
        if (user != body.end() && user->is_string()) {
          parsed.user_is_matrix_id = true;
          parsed.user_localpart = user->get<std::string>();
        }
      } else {
        auto ident = body.find("identifier");
        if (ident != body.end() && ident->is_object()) {
          auto id_type = ident->find("type");
          auto id_user = ident->find("user");
          if (id_type != ident->end() && *id_type == "m.id.user" &&
              id_user != ident->end() && id_user->is_string()) {
            parsed.user_is_matrix_id = true;
            parsed.user_localpart = id_user->get<std::string>();
          }
        }
      }
      if (auto it = body.find("password"); it != body.end() && it->is_string())
        parsed.password = it->get<std::string>();
      if (auto it = body.find("device_id"); it != body.end() && it->is_string())
        parsed.device_id = it->get<std::string>();
    }
  }
  Ruma<LoginRequest> wrapper;
  wrapper.value = std::move(parsed);
  return wrapper;
}

// NEW in fa322689: /sync has no body to parse.
template <>
Ruma<SyncRequest> Ruma<SyncRequest>::from_request(const httplib::Request&) {
  return Ruma<SyncRequest>{};
}

// NEW in 533260ed: raw content kept; EventResult validity checked in handler.
template <>
Ruma<CreateMessageEventRequest> Ruma<CreateMessageEventRequest>::from_request(
    const httplib::Request& req) {
  Ruma<CreateMessageEventRequest> wrapper;
  wrapper.value.content_json = req.body;
  return wrapper;
}

json to_json(const RegisterResponse& r) {
  return json{{"access_token", r.access_token},
              {"device_id", r.device_id},
              {"home_server", r.home_server},
              {"user_id", r.user_id}};
}

json to_json(const LoginResponse& r) {
  json out{{"access_token", r.access_token},
           {"device_id", r.device_id},
           {"user_id", r.user_id}};
  if (r.home_server) out["home_server"] = *r.home_server;
  return out;
}

json to_json(const GetSupportedVersionsResponse& r) {
  return json{{"versions", r.versions}, {"unstable_features", r.unstable_features}};
}

json to_json(const GetAliasResponse& r) {
  return json{{"room_id", r.room_id}, {"servers", r.servers}};
}

json to_json(const JoinRoomByIdResponse& r) {
  return json{{"room_id", r.room_id}};
}

json to_json(const CreateMessageEventResponse& r) {
  return json{{"event_id", r.event_id}};
}

json to_json(const CreateRoomResponse& r) {
  return json{{"room_id", r.room_id}};
}

json to_json(const PublicRoomsResponse& r) {
  return json{{"chunk", r.chunk},
              {"total_room_count_estimate", r.total_room_count_estimate}};
}

json to_error_json(const Error& e) {
  return json{{"errcode", errcode(e.kind)}, {"error", e.message}};
}

void respond(httplib::Response& res, const json& body, int status) {
  res.status = status;
  res.set_content(body.dump(), "application/json");
}

namespace {

template <typename T>
void respond_result(httplib::Response& res, const MatrixResult<T>& result,
                    json (*serialize)(const T&)) {
  if (result.result.index() == 0) {
    respond(res, serialize(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    // NEW in f62258ba: log every error response (upstream error.rs warn!).
    std::cerr << "[warn] " << e.status_code << ": " << e.message << "\n";
    respond(res, to_error_json(e), e.status_code);
  }
}

}  // namespace

void respond(httplib::Response& res, const MatrixResult<RegisterResponse>& result) {
  respond_result(res, result, to_json);
}
void respond(httplib::Response& res, const MatrixResult<LoginResponse>& result) {
  respond_result(res, result, to_json);
}
void respond(httplib::Response& res,
             const MatrixResult<GetSupportedVersionsResponse>& result) {
  respond_result(res, result, to_json);
}
void respond(httplib::Response& res,
             const MatrixResult<CreateMessageEventResponse>& result) {
  respond_result(res, result, to_json);
}

// sync_events::Response skeleton — only join.<room>.timeline.events filled
// (upstream left timeline.events as todo!(); we return the stored PDUs).
void respond(httplib::Response& res,
             const MatrixResult<GetAliasResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}

void respond(httplib::Response& res,
             const MatrixResult<JoinRoomByIdResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}

void respond(httplib::Response& res, const MatrixResult<SyncResponse>& result) {
  if (result.result.index() != 0) {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
    return;
  }
  const SyncResponse& r = std::get<0>(result.result);

  auto joined_room_json = [](const SyncResponse& room) {
    json events = json::array();
    for (const auto& pdu : room.timeline_events) events.push_back(json::parse(pdu));
    json timeline = {{"events", std::move(events)},
                     {"prev_batch", room.prev_batch}};
    if (room.limited) timeline["limited"] = true;
    // NEW in 662a0cf1: stored notification/highlight counts (upstream
    // unread_notifications), replacing PDU scans since last read.
    json unread = {{"notification_count", room.notification_count},
                   {"highlight_count", room.highlight_count}};
    return json{
        {"account_data", {{"events", json::array()}}},
        {"ephemeral", {{"events", json::array()}}},
        {"state", {{"events", json::array()}}},
        {"summary", json::object()},
        {"unread_notifications", std::move(unread)},
        {"timeline", std::move(timeline)},
    };
  };

  auto invited_room_json = [](const SyncResponse& room) {
    // Stripped state events (to_stripped_state_event upstream).
    json events = json::array();
    for (const auto& pdu : room.stripped_state) {
      auto full = json::parse(pdu);
      events.push_back({
          {"content", full.value("content", json::object())},
          {"sender", full.value("sender", "")},
          {"state_key", full.value("state_key", "")},
          {"type", full.value("type", "")},
      });
    }
    return json{{"invite_state", {{"events", std::move(events)}}}};
  };

  // NEW in b4d65ab6: rooms whose timeline AND state are empty are skipped —
  // clients treat their absence as "nothing changed since last sync".
  auto room_is_empty = [](const SyncResponse& room) {
    return room.timeline_events.empty() && room.stripped_state.empty();
  };

  json join = json::object();
  for (const auto& [room_id, room] : r.joined)
    if (!room_is_empty(room)) join[room_id] = joined_room_json(room);
  json invite = json::object();
  for (const auto& [room_id, room] : r.invited)
    if (!room.stripped_state.empty()) invite[room_id] = invited_room_json(room);

  // Always use the modern multi-room shape; an empty account yields empty maps.
  if (true) {
    json out = {
        {"next_batch", ""},
        {"rooms",
         {{"invite", std::move(invite)},
          {"join", std::move(join)},
          {"leave", json::object()}}},
        {"to_device", {{"events", json::array()}}},
    };
    respond(res, out);
    return;
  }

  // Legacy single-timeline shape (kept from fa322689 behaviour).
  json events = json::array();
  for (const auto& pdu : r.timeline_events) events.push_back(json::parse(pdu));
  json timeline = {{"events", std::move(events)}};
  json joined_room = {
      {"account_data", {{"events", json::array()}}},
      {"ephemeral", {{"events", json::array()}}},
      {"state", {{"events", json::array()}}},
      {"summary", json::object()},
      {"unread_notifications", json::object()},
      {"timeline", std::move(timeline)},
  };
  json j2;
  j2[r.joined_room_id] = std::move(joined_room);
  json out = {
      {"next_batch", ""},
      {"rooms",
       {{"invite", json::object()},
        {"join", std::move(j2)},
        {"leave", json::object()}}},
      {"to_device", {{"events", json::array()}}},
  };
  respond(res, out);
}
}  // namespace ruma

namespace ruma {

template <>
Ruma<CreateRoomRequest> Ruma<CreateRoomRequest>::from_request(const httplib::Request& req) {
  Ruma<CreateRoomRequest> wrapper;
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      if (auto it = body.find("name"); it != body.end() && it->is_string())
        wrapper.value.name = it->get<std::string>();
      if (auto it = body.find("topic"); it != body.end() && it->is_string())
        wrapper.value.topic = it->get<std::string>();
      if (auto it = body.find("invite"); it != body.end() && it->is_array())
        for (const auto& u : *it)
          if (u.is_string()) wrapper.value.invite.push_back(u.get<std::string>());
      if (auto it = body.find("is_direct"); it != body.end() && it->is_boolean())
        wrapper.value.is_direct = it->get<bool>();
      if (auto it = body.find("power_level_content_override"); it != body.end())
        wrapper.value.power_level_content_override = *it;
      if (auto it = body.find("visibility"); it != body.end() && it->is_string())
        wrapper.value.visibility = it->get<std::string>();
      if (auto it = body.find("room_alias_name"); it != body.end() && it->is_string())
        wrapper.value.room_alias_name = it->get<std::string>();
    }
  }
  return wrapper;
}

template <>
Ruma<InviteRequest> Ruma<InviteRequest>::from_request(const httplib::Request& req) {
  Ruma<InviteRequest> wrapper;
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      auto recipient = body.find("recipient");
      if (recipient != body.end() && recipient->is_object()) {
        if (auto uid = recipient->find("user_id"); uid != recipient->end() && uid->is_string())
          wrapper.value.target = uid->get<std::string>();
      }
    }
  }
  return wrapper;
}

template <>
Ruma<SearchUsersRequest> Ruma<SearchUsersRequest>::from_request(
    const httplib::Request& req) {
  Ruma<SearchUsersRequest> wrapper;
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      if (auto it = body.find("search_term"); it != body.end() && it->is_string())
        wrapper.value.search_term = it->get<std::string>();
    }
  }
  return wrapper;
}

// NEW in dcac1361: parse search_categories.room_events.{search_term,
// filter.{rooms, limit}} plus the next_batch pagination token.
template <>
Ruma<SearchEventsRequest> Ruma<SearchEventsRequest>::from_request(
    const httplib::Request& req) {
  Ruma<SearchEventsRequest> wrapper;
  if (req.body.empty()) return wrapper;
  const json body = json::parse(req.body, nullptr, false);
  if (body.is_discarded() || !body.is_object()) return wrapper;
  const auto cats = body.find("search_categories");
  if (cats == body.end() || !cats->is_object()) return wrapper;
  const auto re = cats->find("room_events");
  if (re == cats->end() || !re->is_object()) return wrapper;
  SearchEventsRequest::SearchCategories categories;
  SearchEventsRequest::RoomEvents room_events;
  if (auto st = re->find("search_term"); st != re->end() && st->is_string())
    room_events.search_term = st->get<std::string>();
  if (auto f = re->find("filter"); f != re->end() && f->is_object()) {
    SearchEventsRequest::Filter filter;
    if (auto rooms = f->find("rooms");
        rooms != f->end() && rooms->is_array()) {
      std::vector<std::string> ids;
      for (const auto& r : *rooms)
        if (r.is_string()) ids.push_back(r.get<std::string>());
      filter.rooms = std::move(ids);
    }
    if (auto limit = f->find("limit");
        limit != f->end() && limit->is_number())
      filter.limit = limit->get<int64_t>();
    room_events.filter = std::move(filter);
  }
  categories.room_events = std::move(room_events);
  wrapper.value.search_categories = std::move(categories);
  if (auto nb = body.find("next_batch"); nb != body.end() && nb->is_string())
    wrapper.value.next_batch = nb->get<std::string>();
  return wrapper;
}

json to_json(const SearchEventsResponse& r) {
  json highlights = json::array();
  for (const auto& h : r.highlights) highlights.push_back(h);
  json response = json::object();
  response["search_categories"] = json::object();
  json room_events = json::object();
  room_events["count"] = r.count;
  room_events["highlights"] = std::move(highlights);
  if (!r.next_batch.empty()) room_events["next_batch"] = r.next_batch;
  room_events["results"] = r.results;
  response["search_categories"]["room_events"] = std::move(room_events);
  return response;
}

void respond(httplib::Response& res,
             const MatrixResult<CreateRoomResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}

void respond(httplib::Response& res,
             const MatrixResult<PublicRoomsResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}

void respond(httplib::Response& res,
             const MatrixResult<SearchEventsResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}

}  // namespace ruma

namespace ruma {

template <>
Ruma<SetDisplaynameRequest> Ruma<SetDisplaynameRequest>::from_request(
    const httplib::Request& req) {
  Ruma<SetDisplaynameRequest> wrapper;
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      if (auto it = body.find("displayname"); it != body.end() && it->is_string())
        wrapper.value.displayname = it->get<std::string>();
    }
  }
  return wrapper;
}

}  // namespace ruma

namespace ruma {

template <>
Ruma<GetMessagesRequest> Ruma<GetMessagesRequest>::from_request(
    const httplib::Request& req) {
  Ruma<GetMessagesRequest> wrapper;
  wrapper.value.room_id = req.path_params.count("room_id")
                              ? req.path_params.at("room_id")
                              : "";
  wrapper.value.from = req.get_param_value("from");
  if (req.has_param("dir")) wrapper.value.dir = req.get_param_value("dir");
  return wrapper;
}

void respond(httplib::Response& res,
             const MatrixResult<GetMessagesResponse>& result) {
  if (result.result.index() != 0) {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
    return;
  }
  const GetMessagesResponse& r = std::get<0>(result.result);
  json chunk = json::array();
  for (const auto& pdu : r.chunk) chunk.push_back(json::parse(pdu));
  json out{{"start", r.start}, {"end", r.end}, {"chunk", std::move(chunk)}};
  respond(res, out);
}

}  // namespace ruma

namespace ruma {

template <>
Ruma<RoomUpgradeRequest> Ruma<RoomUpgradeRequest>::from_request(const httplib::Request& req) {
  Ruma<RoomUpgradeRequest> wrapper;
  // room_id is taken from the URL path by the caller (req.matches).
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      if (auto it = body.find("new_version"); it != body.end() && it->is_string())
        wrapper.value.new_version = it->get<std::string>();
    }
  }
  return wrapper;
}

void respond(httplib::Response& res,
             const MatrixResult<RoomUpgradeResponse>& result) {
  if (result.result.index() != 0) {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
    return;
  }
  const RoomUpgradeResponse& r = std::get<0>(result.result);
  respond(res, json{{"replacement_room", r.replacement_room}});
}

}  // namespace ruma
