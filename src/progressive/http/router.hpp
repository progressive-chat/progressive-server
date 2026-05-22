#pragma once
#include <boost/beast/http.hpp>
#include <functional>
#include <map>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace boost_http = boost::beast::http;

namespace progressive::http {

class Router {
public:
  using Handler = std::function<boost_http::response<boost_http::string_body>(
      boost_http::request<boost_http::string_body>&&, std::map<std::string, std::string>)>;

  void add_route(boost_http::verb method, std::string pattern, Handler handler,
                 std::string name = {});

  boost_http::response<boost_http::string_body> route(
      boost_http::request<boost_http::string_body>&& req);

  boost_http::response<boost_http::string_body> handle_request(
      boost_http::request<boost_http::string_body>&& req);

private:
  struct Route {
    boost_http::verb method;
    std::regex pattern;
    std::vector<std::string> param_names;
    Handler handler;
    std::string name;
  };

  std::vector<Route> routes_;
  Handler default_handler_;
  std::function<boost_http::response<boost_http::string_body>(
      boost_http::request<boost_http::string_body>&&)>
      fallback_handler_;
};

void set_cors(boost_http::response<boost_http::string_body>& res);
void set_json(boost_http::response<boost_http::string_body>& res, const std::string& body);
boost_http::response<boost_http::string_body> error_response(boost_http::status status,
                                                             const std::string& errcode,
                                                             const std::string& error);
boost_http::response<boost_http::string_body> not_found();

}  // namespace progressive::http
