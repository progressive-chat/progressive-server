#include "router.hpp"

#include <nlohmann/json.hpp>

namespace progressive::http {

void Router::add_route(boost_http::verb method, std::string pattern, Handler handler,
                       std::string name) {
  std::regex re;
  std::vector<std::string> param_names;

  std::string re_str;
  size_t pos = 0;
  while (pos < pattern.size()) {
    if (pattern[pos] == '{') {
      auto end = pattern.find('}', pos);
      if (end == std::string::npos)
        break;
      auto param = pattern.substr(pos + 1, end - pos - 1);
      param_names.push_back(param);
      re_str += "([^/]*)";
      pos = end + 1;
    } else {
      if (pattern[pos] == '.')
        re_str += "\\.";
      else if (pattern[pos] == '*')
        re_str += ".*";
      else
        re_str += pattern[pos];
      pos++;
    }
  }
  re = std::regex("^" + re_str + "$");
  routes_.push_back({method, re, param_names, std::move(handler), std::move(name)});
}

boost_http::response<boost_http::string_body> Router::route(
    boost_http::request<boost_http::string_body>&& req) {
  return handle_request(std::move(req));
}

boost_http::response<boost_http::string_body> Router::handle_request(
    boost_http::request<boost_http::string_body>&& req) {
  std::string target(req.target());

  auto query_pos = target.find('?');
  std::string path = (query_pos != std::string::npos) ? target.substr(0, query_pos) : target;

  for (auto& route : routes_) {
    if (route.method != req.method())
      continue;
    std::smatch match;
    if (std::regex_match(path, match, route.pattern)) {
      std::map<std::string, std::string> params;
      for (size_t i = 0; i < route.param_names.size() && i + 1 < match.size(); i++) {
        params[route.param_names[i]] = match[i + 1].str();
      }
      return route.handler(std::move(req), std::move(params));
    }
  }

  if (fallback_handler_) {
    return fallback_handler_(std::move(req));
  }

  return not_found();
}

void set_cors(boost_http::response<boost_http::string_body>& res) {
  res.set(boost_http::field::access_control_allow_origin, "*");
  res.set(boost_http::field::access_control_allow_methods, "GET, POST, PUT, DELETE, OPTIONS");
  res.set(boost_http::field::access_control_allow_headers, "Content-Type, Authorization");
}

void set_json(boost_http::response<boost_http::string_body>& res, const std::string& body) {
  res.set(boost_http::field::content_type, "application/json");
  res.body() = body;
  res.prepare_payload();
}

boost_http::response<boost_http::string_body> error_response(boost_http::status status,
                                                             const std::string& errcode,
                                                             const std::string& error) {
  boost_http::response<boost_http::string_body> res;
  res.result(status);
  nlohmann::json j;
  j["errcode"] = errcode;
  j["error"] = error;
  set_json(res, j.dump());
  set_cors(res);
  return res;
}

boost_http::response<boost_http::string_body> not_found() {
  boost_http::response<boost_http::string_body> res;
  res.result(boost_http::status::not_found);
  nlohmann::json j;
  j["errcode"] = "M_NOT_FOUND";
  j["error"] = "Unrecognized request";
  set_json(res, j.dump());
  set_cors(res);
  return res;
}

}  // namespace progressive::http
