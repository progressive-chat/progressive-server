#pragma once
// client_rest_room.hpp - room, sync, events, members, state REST servlets
#include "rest_base.hpp"
#include "progressive/storage/database.hpp"

namespace progressive::rest {

// ====== RoomRestServlet - handles /rooms/* endpoints ======
class RoomRestServlet : public ClientV1RestServlet {
public:
  explicit RoomRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/createRoom","/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}",
            "/_matrix/client/v3/rooms/{roomId}/state","/_matrix/client/v3/rooms/{roomId}/state/{eventType}",
            "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",
            "/_matrix/client/v3/rooms/{roomId}/join","/_matrix/client/v3/join/{roomAlias}",
            "/_matrix/client/v3/rooms/{roomId}/leave","/_matrix/client/v3/rooms/{roomId}/forget",
            "/_matrix/client/v3/rooms/{roomId}/invite","/_matrix/client/v3/rooms/{roomId}/kick",
            "/_matrix/client/v3/rooms/{roomId}/ban","/_matrix/client/v3/rooms/{roomId}/unban",
            "/_matrix/client/v3/rooms/{roomId}/messages","/_matrix/client/v3/rooms/{roomId}/initialSync",
            "/_matrix/client/v3/rooms/{roomId}/members","/_matrix/client/v3/rooms/{roomId}/joined_members",
            "/_matrix/client/v3/rooms/{roomId}/context/{eventId}",
            "/_matrix/client/v3/rooms/{roomId}/event/{eventId}",
            "/_matrix/client/v3/rooms/{roomId}/upgrade",
            "/_matrix/client/v3/rooms/{roomId}/report/{eventId}",
            "/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}",
            "/_matrix/client/v3/rooms/{roomId}/read_markers",
            "/_matrix/client/v3/publicRooms","/_matrix/client/v3/joined_rooms"};
  }
  std::vector<std::string> methods() const override {
    return {"GET","POST","PUT","DELETE"};
  }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  // Room lifecycle
  HttpResponse create_room(const HttpRequest& req);
  HttpResponse join_room(const HttpRequest& req, const std::string& room_id, const std::string& alias);
  HttpResponse leave_room(const HttpRequest& req, const std::string& room_id);
  HttpResponse forget_room(const HttpRequest& req, const std::string& room_id);
  HttpResponse invite_user(const HttpRequest& req, const std::string& room_id);
  HttpResponse kick_user(const HttpRequest& req, const std::string& room_id);
  HttpResponse ban_user(const HttpRequest& req, const std::string& room_id);
  HttpResponse unban_user(const HttpRequest& req, const std::string& room_id);
  // Events
  HttpResponse send_event(const HttpRequest& req, const std::string& room_id, const std::string& event_type, const std::string& txn_id);
  HttpResponse get_event(const HttpRequest& req, const std::string& room_id, const std::string& event_id);
  HttpResponse get_messages(const HttpRequest& req, const std::string& room_id);
  HttpResponse redact_event(const HttpRequest& req, const std::string& room_id, const std::string& event_id, const std::string& txn_id);
  HttpResponse get_context(const HttpRequest& req, const std::string& room_id, const std::string& event_id);
  // State
  HttpResponse get_state(const HttpRequest& req, const std::string& room_id, const std::optional<std::string>& event_type={}, const std::optional<std::string>& state_key={});
  HttpResponse send_state(const HttpRequest& req, const std::string& room_id, const std::string& event_type, const std::optional<std::string>& state_key={});
  // Members
  HttpResponse get_members(const HttpRequest& req, const std::string& room_id);
  HttpResponse get_joined_members(const HttpRequest& req, const std::string& room_id);
  // Rooms listing
  HttpResponse get_public_rooms(const HttpRequest& req);
  HttpResponse get_joined_rooms(const HttpRequest& req);
  // Misc
  HttpResponse upgrade_room(const HttpRequest& req, const std::string& room_id);
  HttpResponse report_event(const HttpRequest& req, const std::string& room_id, const std::string& event_id);
  HttpResponse set_read_marker(const HttpRequest& req, const std::string& room_id);
  storage::DatabasePool& db_;
};

// ====== SyncRestServlet - handles /sync endpoint ======
class SyncRestServlet : public ClientV1RestServlet {
public:
  explicit SyncRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/sync","/_matrix/client/v3/initialSync"};
  }
  std::vector<std::string> methods() const override { return {"GET"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse do_sync(const HttpRequest& req);
  HttpResponse do_initial_sync(const HttpRequest& req);
  json build_sync_response(const std::string& user_id, const std::string& since,
      int64_t timeout, bool full_state, const std::string& filter);
  storage::DatabasePool& db_;
};

// ====== EventsRestServlet - handles /events, /event, /initialSync =====
class EventsRestServlet : public ClientV1RestServlet {
public:
  explicit EventsRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/events","/_matrix/client/v3/event/{eventId}"};
  }
  std::vector<std::string> methods() const override { return {"GET"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse get_events_stream(const HttpRequest& req);
  HttpResponse get_single_event(const HttpRequest& req);
  storage::DatabasePool& db_;
};

// ====== ProfileRestServlet ======
class ProfileRestServlet : public ClientV1RestServlet {
public:
  explicit ProfileRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/profile/{userId}",
            "/_matrix/client/v3/profile/{userId}/displayname",
            "/_matrix/client/v3/profile/{userId}/avatar_url"};
  }
  std::vector<std::string> methods() const override { return {"GET","PUT"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse get_profile(const std::string& user_id);
  HttpResponse set_display_name(const HttpRequest& req, const std::string& user_id);
  HttpResponse set_avatar_url(const HttpRequest& req, const std::string& user_id);
  storage::DatabasePool& db_;
};

// ====== DirectoryRestServlet ======
class DirectoryRestServlet : public ClientV1RestServlet {
public:
  explicit DirectoryRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/directory/room/{roomAlias}",
            "/_matrix/client/v3/directory/list/room/{roomId}"};
  }
  std::vector<std::string> methods() const override { return {"GET","PUT","DELETE"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse get_room_by_alias(const std::string& alias);
  HttpResponse set_room_alias(const HttpRequest& req, const std::string& alias);
  HttpResponse delete_room_alias(const std::string& alias);
  HttpResponse set_room_visibility(const HttpRequest& req, const std::string& room_id);
  HttpResponse get_room_visibility(const std::string& room_id);
  storage::DatabasePool& db_;
};

} // namespace
