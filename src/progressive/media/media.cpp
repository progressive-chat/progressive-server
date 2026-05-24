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
        // CVE-2021-41281: Sanitize mediaId to prevent path traversal
        std::string safe_id = p["mediaId"];
        safe_id.erase(std::remove(safe_id.begin(), safe_id.end(), '/'), safe_id.end());
        safe_id.erase(std::remove(safe_id.begin(), safe_id.end(), '\\'), safe_id.end());
        safe_id.erase(std::remove(safe_id.begin(), safe_id.end(), '.'), safe_id.end());
        safe_id = safe_id.substr(0, 64);

        std::string filename = "upload-" + safe_id;
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
        // Content-type detection by extension
        std::string ct = "application/octet-stream";
        auto dot = p["mediaId"].rfind('.');
        if (dot != std::string::npos) {
          std::string ext = p["mediaId"].substr(dot + 1);
          if (ext == "png")
            ct = "image/png";
          else if (ext == "jpg" || ext == "jpeg")
            ct = "image/jpeg";
          else if (ext == "gif")
            ct = "image/gif";
          else if (ext == "webp")
            ct = "image/webp";
          else if (ext == "mp4")
            ct = "video/mp4";
          else if (ext == "webm")
            ct = "video/webm";
          else if (ext == "mp3")
            ct = "audio/mpeg";
          else if (ext == "ogg")
            ct = "audio/ogg";
          else if (ext == "pdf")
            ct = "application/pdf";
          else if (ext == "json")
            ct = "application/json";
          else if (ext == "txt")
            ct = "text/plain";
          else if (ext == "html")
            ct = "text/html";
        }
        res.set(bhttp::field::content_type, ct);
        res.body() = std::move(content);
        res.prepare_payload();
        return res;
      },
      "media_download");

  // Thumbnail — serve original as fallback
  router.add_route(
      bhttp::verb::get, "/_matrix/media/v3/thumbnail/{serverName}/{mediaId}",
      [media_dir](bhttp::request<bhttp::string_body>&&,
                  std::map<std::string, std::string> p) -> bhttp::response<bhttp::string_body> {
        // Serve original image as fallback thumbnail
        std::string safe_id = p["mediaId"];
        safe_id.erase(std::remove(safe_id.begin(), safe_id.end(), '/'), safe_id.end());
        safe_id.erase(std::remove(safe_id.begin(), safe_id.end(), '\\'), safe_id.end());
        safe_id = safe_id.substr(0, 64);
        std::string filename = "upload-" + safe_id;
        std::string filepath = std::filesystem::path(std::string(media_dir)) / filename;
        if (!std::filesystem::exists(filepath)) {
          bhttp::response<bhttp::string_body> res{bhttp::status::not_found, 11};
          progressive::http::set_json(res,
                                      R"({"errcode":"M_NOT_FOUND","error":"Media not found"})");
          return res;
        }
        std::ifstream in(filepath, std::ios::binary | std::ios::ate);
        std::string content(in.tellg(), '\0');
        in.seekg(0);
        in.read(content.data(), content.size());
        std::string ct = "image/png";
        bhttp::response<bhttp::string_body> res{bhttp::status::ok, 11};
        res.set(bhttp::field::content_type, ct);
        res.set(bhttp::field::cache_control, "public, max-age=86400");
        res.body() = std::move(content);
        res.prepare_payload();
        return res;
      },
      "media_thumbnail_real");
}

}  // namespace progressive::media
