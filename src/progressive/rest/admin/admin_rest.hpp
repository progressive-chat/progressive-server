#pragma once
// admin_rest.hpp - Admin REST API (17 files from synapse/rest/admin/)
#include "rest_base.hpp"
namespace progressive::rest {

// ====== AdminRestServlet - all admin endpoints combined ======
class AdminRestServlet : public BaseRestServlet {
public:
  explicit AdminRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {
      "/_synapse/admin/v1/register",
      "/_synapse/admin/v1/users/{userId}",
      "/_synapse/admin/v1/users/{userId}/admin",
      "/_synapse/admin/v1/users/{userId}/login",
      "/_synapse/admin/v1/users/{userId}/shadowBan",
      "/_synapse/admin/v1/deactivate/{userId}",
      "/_synapse/admin/v1/whois/{userId}",
      "/_synapse/admin/v1/username_available",
      "/_synapse/admin/v2/users",
      "/_synapse/admin/v2/users/{userId}",
      "/_synapse/admin/v1/rooms",
      "/_synapse/admin/v1/rooms/{roomId}",
      "/_synapse/admin/v1/rooms/{roomId}/members",
      "/_synapse/admin/v1/rooms/{roomId}/state",
      "/_synapse/admin/v1/rooms/{roomId}/delete",
      "/_synapse/admin/v1/rooms/{roomId}/make_room_admin",
      "/_synapse/admin/v1/rooms/{roomId}/block",
      "/_synapse/admin/v1/media/{serverName}/{mediaId}",
      "/_synapse/admin/v1/media/{serverName}/{mediaId}/delete",
      "/_synapse/admin/v1/media/{serverName}/{mediaId}/quarantine",
      "/_synapse/admin/v1/purge_media_cache",
      "/_synapse/admin/v1/quarantine_media/{roomId}",
      "/_synapse/admin/v1/quarantine_media/user/{userId}",
      "/_synapse/admin/v1/statistics",
      "/_synapse/admin/v1/statistics/users/media",
      "/_synapse/admin/v1/statistics/database/rooms",
      "/_synapse/admin/v1/server_version",
      "/_synapse/admin/v1/federation/destinations",
      "/_synapse/admin/v1/federation/destinations/{destination}",
      "/_synapse/admin/v1/reset_password/{userId}",
      "/_synapse/admin/v1/event_reports",
      "/_synapse/admin/v1/event_reports/{reportId}",
      "/_synapse/admin/v1/background_updates/enabled",
      "/_synapse/admin/v1/background_updates/status",
      "/_synapse/admin/v1/background_updates",
      "/_synapse/admin/v1/experimental_features",
      "/_synapse/admin/v1/registration_tokens",
      "/_synapse/admin/v1/registration_tokens/new",
      "/_synapse/admin/v1/registration_tokens/{token}",
      "/_synapse/admin/v1/registration_tokens/{token}/update",
    };
  }
  std::vector<std::string> methods() const override {
    return {"GET","POST","PUT","DELETE"};
  }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  // User management
  HttpResponse get_users(const HttpRequest& req);
  HttpResponse get_user(const std::string& user_id);
  HttpResponse create_user(const HttpRequest& req);
  HttpResponse deactivate_user(const std::string& user_id, bool erase=false);
  HttpResponse set_user_admin(const HttpRequest& req, const std::string& user_id);
  HttpResponse shadow_ban_user(const HttpRequest& req, const std::string& user_id);
  HttpResponse reset_password(const HttpRequest& req, const std::string& user_id);
  HttpResponse whois_user(const std::string& user_id);
  HttpResponse check_username(const HttpRequest& req);
  // Room management
  HttpResponse get_rooms(const HttpRequest& req);
  HttpResponse get_room_info(const std::string& room_id);
  HttpResponse get_room_members(const HttpRequest& req, const std::string& room_id);
  HttpResponse delete_room(const std::string& room_id);
  HttpResponse make_room_admin(const HttpRequest& req, const std::string& room_id);
  HttpResponse block_room(const std::string& room_id, bool block);
  // Media management
  HttpResponse get_media_info(const std::string& server, const std::string& media_id);
  HttpResponse delete_media(const std::string& server, const std::string& media_id);
  HttpResponse quarantine_media(const std::string& server, const std::string& media_id);
  HttpResponse purge_media_cache(const HttpRequest& req);
  HttpResponse quarantine_room_media(const std::string& room_id);
  HttpResponse quarantine_user_media(const std::string& user_id);
  // Statistics
  HttpResponse get_statistics();
  HttpResponse get_user_media_stats();
  HttpResponse get_database_room_stats();
  HttpResponse get_server_version();
  // Federation
  HttpResponse get_federation_destinations();
  HttpResponse get_federation_destination(const std::string& dest);
  // Event reports
  HttpResponse get_event_reports(const HttpRequest& req);
  HttpResponse get_event_report(const std::string& report_id);
  // Background updates
  HttpResponse get_bg_update_status();
  HttpResponse toggle_bg_updates(const HttpRequest& req);
  HttpResponse run_bg_update(const HttpRequest& req);
  // Experimental features
  HttpResponse get_experimental_features();
  HttpResponse set_experimental_features(const HttpRequest& req);
  // Registration tokens
  HttpResponse get_registration_tokens();
  HttpResponse create_registration_token(const HttpRequest& req);
  HttpResponse get_registration_token(const std::string& token);
  HttpResponse update_registration_token(const HttpRequest& req, const std::string& token);
  storage::DatabasePool& db_;
};

} // namespace
