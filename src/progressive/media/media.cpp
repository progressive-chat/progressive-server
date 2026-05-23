#include "media.hpp"

#include <filesystem>
#include <fstream>

#include "../http/router.hpp"
#include "../util/random.hpp"

namespace progressive::media {

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

static progressive::auth::AuthResult check_auth(
    auth::Auth& auth_unit, boost::beast::http::request<boost::beast::http::string_body>& req) {
  auto hdr = req[boost::beast::http::field::authorization];
  if (hdr.empty()) {
    progressive::auth::AuthResult r;
    r.error = "Missing access token";
    r.errcode = "M_MISSING_TOKEN";
    return r;
  }
  std::string_view h(hdr);
  if (h.starts_with("Bearer "))
    h.remove_prefix(7);
  return auth_unit.validate_token(h);
}

void register_routes(progressive::http::Router& router, auth::Auth& auth_unit,
                     std::string_view media_dir, std::string_view server_name) {
  namespace bhttp = boost::beast::http;

  // Upload
  router.add_route(
      bhttp::verb::post, "/_matrix/media/v3/upload",
      [&](bhttp::request<bhttp::string_body>&& req,
          std::map<std::string, std::string>) -> bhttp::response<bhttp::string_body> {
        auto r = check_auth(auth_unit, req);
        if (!r.success) {
          bhttp::response<bhttp::string_body> res{bhttp::status::unauthorized, 11};
          progressive::http::set_json(
              res, R"({"errcode":"M_MISSING_TOKEN","error":"Missing access token"})");
          return res;
        }

        auto media_id = util::random_token(24);
        std::string filename = "upload-" + media_id;
        std::string filepath = std::filesystem::path(media_dir) / filename;

        // Save file
        std::ofstream out(filepath, std::ios::binary);
        out.write(req.body().data(), req.body().size());
        out.close();

        std::string mxc = "mxc://" + std::string(server_name) + "/" + media_id;
        nlohmann::json resp;
        resp["content_uri"] = mxc;

        bhttp::response<bhttp::string_body> res{bhttp::status::ok, 11};
        progressive::http::set_json(res, resp.dump());
        progressive::http::set_cors(res);
        return res;
      },
      "media_upload");

  // Download
  router.add_route(
      bhttp::verb::get, "/_matrix/media/v3/download/{serverName}/{mediaId}",
      [media_dir](bhttp::request<bhttp::string_body>&&,
                  std::map<std::string, std::string> p) -> bhttp::response<bhttp::string_body> {
        std::string filename = "upload-" + p["mediaId"];
        std::string filepath = std::filesystem::path(std::string(media_dir)) / filename;

        if (!std::filesystem::exists(filepath)) {
          bhttp::response<bhttp::string_body> res{bhttp::status::not_found, 11};
          progressive::http::set_json(res,
                                      R"({"errcode":"M_NOT_FOUND","error":"Media not found"})");
          return res;
        }

        std::ifstream in(filepath, std::ios::binary | std::ios::ate);
        size_t size = in.tellg();
        in.seekg(0);
        std::string content(size, '\0');
        in.read(content.data(), size);

        bhttp::response<bhttp::string_body> res{bhttp::status::ok, 11};
        res.set(bhttp::field::content_type, "application/octet-stream");
        res.body() = std::move(content);
        res.prepare_payload();
        return res;
      },
      "media_download");
}

}  // namespace progressive::media
