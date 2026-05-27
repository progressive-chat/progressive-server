// rest_base.cpp - REST base infrastructure implementation
#include "rest_base.hpp"
#include <sstream>
#include <stdexcept>
namespace progressive::rest {
using json = nlohmann::json;

// ====== BaseRestServlet ======
json BaseRestServlet::parse_json_body(const HttpRequest& req) {
  if (req.body.empty()) return json::object();
  try { return json::parse(req.body); }
  catch (...) { throw std::runtime_error("Invalid JSON in request body"); }
}
std::optional<int64_t> BaseRestServlet::parse_integer(const HttpRequest& req, const std::string& name, bool required) {
  auto it = req.query_params.find(name);
  if (it != req.query_params.end() && !it->second.empty()) { try { return std::stoll(it->second); } catch (...) {} }
  if (required) throw std::runtime_error("Missing required parameter: " + name);
  return std::nullopt;
}
std::optional<std::string> BaseRestServlet::parse_string(const HttpRequest& req, const std::string& name, std::optional<std::string> def) {
  auto it = req.query_params.find(name);
  if (it != req.query_params.end()) return it->second;
  return def;
}
bool BaseRestServlet::parse_boolean(const HttpRequest& req, const std::string& name, bool def) {
  auto v = parse_string(req, name);
  if (!v) return def;
  return *v == "true" || *v == "1" || *v == "yes";
}
HttpResponse BaseRestServlet::error_response(int code, const std::string& errcode, const std::string& error) {
  HttpResponse r; r.code = code;
  r.body = {{"errcode", errcode}, {"error", error}};
  return r;
}
HttpResponse BaseRestServlet::success_response(const json& data) {
  HttpResponse r; r.code = 200; r.body = data;
  return r;
}
json BaseRestServlet::paginate(int64_t start, int64_t limit, int64_t total, const json& results) {
  json r; r["start"] = start; r["limit"] = limit; r["total"] = total; r["results"] = results;
  return r;
}

// ====== ClientV1RestServlet ======
std::string ClientV1RestServlet::client_pattern(const std::string& path, bool v1) {
  return (v1 ? "/_matrix/client/v1" : "/_matrix/client/v3") + path;
}

// ====== ServletRegistry ======
void ServletRegistry::register_servlet(std::unique_ptr<BaseRestServlet> servlet) {
  for (auto& pat : servlet->patterns()) {
    std::string re_str = "^" + pat;
    // Convert {param} to regex capture groups
    size_t pos = 0;
    while ((pos = re_str.find("{", pos)) != std::string::npos) {
      size_t end = re_str.find("}", pos);
      if (end == std::string::npos) break;
      std::string name = re_str.substr(pos+1, end-pos-1);
      re_str.replace(pos, end-pos+1, "([^/]+)");
    }
    re_str += "$";
    routes_.push_back({std::unique_ptr<BaseRestServlet>(nullptr), std::regex(re_str)});
    routes_.back().servlet = std::move(servlet);
  }
}
std::optional<HttpResponse> ServletRegistry::route(const HttpRequest& req) {
  for (auto& route : routes_) {
    std::smatch match;
    if (std::regex_match(req.path, match, route.pattern)) {
      // Extract path params
      auto req_copy = req;
      // Populate path params from capture groups
      return route.servlet->on_request(req_copy);
    }
  }
  return std::nullopt;
}

// ====== AuthHelper ======
AuthHelper::AuthHelper(storage::DatabasePool& db) : db_(db) {}
std::optional<Requester> AuthHelper::get_user_by_access_token(const std::string& token) {
  return db_.runInteraction("auth_check", [&](storage::LoggingTransaction& txn) -> std::optional<Requester> {
    txn.execute("SELECT u.name,u.is_guest,u.admin,u.shadow_banned,a.device_id FROM access_tokens a INNER JOIN users u ON a.user_id=u.name WHERE a.token=? AND u.deactivated=0", {token});
    auto r = txn.fetchone();
    if (!r) return std::nullopt;
    Requester req; req.user_id = r->at(0).value.value_or("");
    req.is_guest = r->at(1).value.value_or("0") == "1";
    req.is_admin = r->at(2).value.value_or("0") == "1";
    req.shadow_banned = r->at(3).value.value_or("0") == "1";
    req.device_id = r->at(4).value;
    return req;
  });
}
bool AuthHelper::check_user_allowed(const Requester& r) { return !r.shadow_banned; }
Requester AuthHelper::require_auth(const HttpRequest& req) {
  std::string token;
  auto ah = req.headers.find("Authorization");
  if (ah != req.headers.end()) {
    std::string auth = ah->second;
    if (auth.starts_with("Bearer ")) token = auth.substr(7);
  }
  if (token.empty()) {
    auto qp = req.query_params.find("access_token");
    if (qp != req.query_params.end()) token = qp->second;
  }
  if (token.empty()) throw std::runtime_error("Missing access token");
  auto user = get_user_by_access_token(token);
  if (!user) throw std::runtime_error("Unknown token");
  return *user;
}
bool AuthHelper::is_admin(const Requester& r) { return r.is_admin; }

} // namespace
