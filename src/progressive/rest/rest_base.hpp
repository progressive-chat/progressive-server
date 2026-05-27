#pragma once
// rest_base.hpp - Base REST servlet infrastructure
// Equivalent to synapse/rest/client/_base.py + synapse/http/servlet.py

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"

namespace progressive::rest {

using json = nlohmann::json;

// ============================================================================
// HTTP request/response types
// ============================================================================
struct HttpRequest {
  std::string method; // GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
  std::string path;
  std::string body;
  std::map<std::string, std::string> headers;
  std::map<std::string, std::string> query_params;
  std::map<std::string, std::string> path_params;
  std::optional<std::string> auth_user;
  std::optional<std::string> access_token;
  std::string client_ip;
  bool is_json{false};
};

struct HttpResponse {
  int code{200};
  json body;
  std::map<std::string, std::string> headers;
  std::string content_type{"application/json"};
};

// ============================================================================
// Requester - authenticated user context
// Equivalent to synapse.types.Requester
// ============================================================================
struct Requester {
  std::string user_id;
  std::optional<std::string> device_id;
  bool is_guest{false};
  bool is_admin{false};
  std::optional<std::string> app_service_id;
  bool shadow_banned{false};
};

// ============================================================================
// BaseRestServlet - all REST servlets inherit from this
// Equivalent to synapse.http.servlet.RestServlet
// ============================================================================
class BaseRestServlet {
public:
  virtual ~BaseRestServlet() = default;

  // Pattern that this servlet handles
  virtual std::vector<std::string> patterns() const = 0;

  // HTTP methods this servlet supports
  virtual std::vector<std::string> methods() const = 0;

  // Handle the request - returns response
  virtual HttpResponse on_request(const HttpRequest& req) = 0;

  // Parse JSON body with error handling
  static json parse_json_body(const HttpRequest& req);

  // Parse integer query parameter
  static std::optional<int64_t> parse_integer(
      const HttpRequest& req, const std::string& name,
      bool required = false);

  // Parse string query parameter
  static std::optional<std::string> parse_string(
      const HttpRequest& req, const std::string& name,
      std::optional<std::string> default_val = std::nullopt);

  // Parse boolean query parameter
  static bool parse_boolean(const HttpRequest& req, const std::string& name,
                              bool default_val = false);

  // Respond with an error
  static HttpResponse error_response(int code, const std::string& errcode,
                                       const std::string& error);

  // Standard success response
  static HttpResponse success_response(const json& data = json::object());

  // Build pagination response
  static json paginate(int64_t start, int64_t limit, int64_t total,
                         const json& results);
};

// ============================================================================
// ClientV1RestServlet - base for Client-Server API v1
// ============================================================================
class ClientV1RestServlet : public BaseRestServlet {
public:
  std::vector<std::string> methods() const override {
    return {"GET", "POST", "PUT", "DELETE", "OPTIONS"};
  }

protected:
  // Client API patterns use /_matrix/client/v1/ or /_matrix/client/v3/
  static std::string client_pattern(const std::string& path, bool v1 = false);
};

// ============================================================================
// Pattern registration helper
// ============================================================================
class ServletRegistry {
public:
  void register_servlet(std::unique_ptr<BaseRestServlet> servlet);
  std::optional<HttpResponse> route(const HttpRequest& req);

private:
  struct Route {
    std::unique_ptr<BaseRestServlet> servlet;
    std::regex pattern;
  };
  std::vector<Route> routes_;
};

// ============================================================================
// Auth helpers
// ============================================================================
class AuthHelper {
public:
  AuthHelper(storage::DatabasePool& db);

  // Get user from access token
  std::optional<Requester> get_user_by_access_token(
      const std::string& token);

  // Check if user is allowed (not deactivated, not shadow_banned)
  bool check_user_allowed(const Requester& requester);

  // Require authentication - throws if not authenticated
  Requester require_auth(const HttpRequest& req);

  // Check admin access
  bool is_admin(const Requester& req);

private:
  storage::DatabasePool& db_;
};

} // namespace progressive::rest
