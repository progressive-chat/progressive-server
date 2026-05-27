// progressive-server: Matrix Media Repository
// Reference: Synapse media_repository.py, media/thumbnailer.py, media/storage_provider.py
// File upload, download, thumbnail generation, URL preview, quarantine

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <mutex>
#include <functional>
#include <fstream>
#include "../json.hpp"

namespace progressive {
namespace media {

using json = nlohmann::json;

struct MediaInfo {
    std::string media_id;
    std::string media_type;    // "image/jpeg", "video/mp4", etc.
    int64_t media_length;
    int64_t upload_ts;
    std::string upload_name;
    std::string user_id;
    std::string last_access_ts;
    bool quarantined;
    bool safe_from_quarantine;
};

struct ThumbnailInfo {
    std::string media_id;
    int width, height;
    std::string method;   // "crop" or "scale"
    std::string type;     // "image/jpeg"
    int64_t length;
};

class MediaStore {
    std::string base_path_ = "/var/lib/progressive/media";
    std::mutex mutex_;
public:
    MediaStore(const std::string& path="") { if(!path.empty()) base_path_=path; }
    std::string store_path(const std::string& media_id) {
        return base_path_+"/storage/"+media_id.substr(0,2)+"/"+media_id.substr(2,2)+"/"+media_id;
    }
    std::string thumb_path(const std::string& media_id, int w, int h, const std::string& method, const std::string& type) {
        return base_path_+"/thumbnails/"+media_id.substr(0,2)+"/"+media_id.substr(2,2)+"/"+media_id+"_"+std::to_string(w)+"x"+std::to_string(h)+"_"+method+"."+(type=="image/jpeg"?"jpg":"png");
    }
    std::string url_preview_path(const std::string& url) {
        std::string hash = sha256(url);
        return base_path_+"/url_cache/"+hash.substr(0,2)+"/"+hash;
    }
    bool file_exists(const std::string& path) {
        std::ifstream f(path); return f.good();
    }
    std::vector<uint8_t> read_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary|std::ios::ate);
        if(!f) return {};
        auto size = f.tellg(); f.seekg(0);
        std::vector<uint8_t> data(size); f.read((char*)data.data(), size);
        return data;
    }
    bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
        // Create directories
        auto pos = path.find_last_of('/');
        if(pos != std::string::npos) {
            std::string dir = path.substr(0,pos);
            system(("mkdir -p "+dir).c_str());
        }
        std::ofstream f(path, std::ios::binary);
        if(!f) return false;
        f.write((const char*)data.data(), data.size());
        return f.good();
    }
    static std::string sha256(const std::string& s) { return "hash_placeholder"; }
};

enum class ThumbnailMethod { CROP, SCALE };
enum class ThumbnailType { JPEG, PNG, WEBP };

class Thumbnailer {
    MediaStore& store_;
public:
    Thumbnailer(MediaStore& s) : store_(s) {}
    struct ThumbnailResult {
        std::vector<uint8_t> data;
        int width, height;
        std::string content_type;
        bool success;
    };
    ThumbnailResult generate(const std::string& media_id, int desired_width, int desired_height,
                              ThumbnailMethod method=ThumbnailMethod::SCALE, ThumbnailType type=ThumbnailType::JPEG) {
        ThumbnailResult result;
        std::string src_path = store_.store_path(media_id);
        if(!store_.file_exists(src_path)) { result.success=false; return result; }

        auto src_data = store_.read_file(src_path);
        if(src_data.empty()) { result.success=false; return result; }

        // In real impl: use ImageMagick or libvips for resizing
        result.data = src_data;
        result.width = std::min(desired_width, 800);
        result.height = std::min(desired_height, 600);
        result.content_type = "image/jpeg";
        result.success = true;

        // Save thumbnail
        std::string thumb_path = store_.thumb_path(media_id, result.width, result.height,
            method==ThumbnailMethod::CROP?"crop":"scale", result.content_type);
        store_.write_file(thumb_path, result.data);

        return result;
    }
    bool can_thumbnail(const std::string& content_type) {
        return content_type.find("image/")==0 && content_type!="image/svg+xml";
    }
    static constexpr int MAX_WIDTH = 800;
    static constexpr int MAX_HEIGHT = 600;
    static constexpr std::array<int,5> SUPPORTED_SIZES = {32, 96, 320, 640, 800};
};

class UrlPreviewer {
    MediaStore& store_;
    std::unordered_map<std::string, json> cache_;
    std::mutex mutex_;
public:
    UrlPreviewer(MediaStore& s) : store_(s) {}

    struct PreviewResult {
        std::string title;
        std::string description;
        std::string image_url;
        std::string site_name;
        std::string url;
        int64_t image_width=0, image_height=0;
        int64_t image_size=0;
        std::string image_type;
        bool success;
    };

    PreviewResult fetch_preview(const std::string& url, int64_t ts=0, int64_t max_delta=3600000) {
        PreviewResult result; result.url=url;
        // Check cache
        {
            std::lock_guard lock(mutex_);
            auto it = cache_.find(url);
            if(it != cache_.end()) {
                auto& cached = it->second;
                int64_t age = (std::time(nullptr)*1000) - cached.value("ts",0LL);
                if(age < max_delta) {
                    result.title = cached.value("og:title","");
                    result.description = cached.value("og:description","");
                    result.image_url = cached.value("og:image","");
                    result.site_name = cached.value("og:site_name","");
                    result.success = true;
                    return result;
                }
            }
        }
        // In real: HTTP GET the URL, parse OpenGraph/meta tags
        result.title = url;
        result.description = "Preview of " + url;
        result.success = true;

        // Cache the result
        json cached;
        cached["og:title"] = result.title;
        cached["og:description"] = result.description;
        cached["og:image"] = result.image_url;
        cached["og:site_name"] = result.site_name;
        cached["ts"] = std::time(nullptr)*1000;
        { std::lock_guard lock(mutex_); cache_[url]=cached; }

        return result;
    }

    bool is_url_blocked(const std::string& url) {
        static std::vector<std::string> blocked = {"localhost","127.0.0.1","0.0.0.0","[::1]"};
        for(auto& b:blocked) if(url.find(b)!=std::string::npos) return true;
        return false;
    }

    int64_t max_spider_size() { return 2097152; } // 2MB
    int max_title_length() { return 1024; }
    int max_description_length() { return 2048; }
};

class MediaRepository {
    MediaStore store_;
    Thumbnailer thumbnailer_;
    UrlPreviewer previewer_;
    std::unordered_map<std::string, MediaInfo> media_info_;
    std::mutex mutex_;
public:
    MediaRepository() : thumbnailer_(store_), previewer_(store_) {}

    struct UploadResult { std::string media_id; int64_t size; bool success; std::string error; };
    UploadResult upload(const std::vector<uint8_t>& data, const std::string& content_type,
                        const std::string& upload_name, const std::string& user_id) {
        UploadResult result;
        std::string media_id = generate_media_id();
        result.media_id = media_id;
        result.size = data.size();
        result.success = store_.write_file(store_.store_path(media_id), data);

        if(result.success) {
            MediaInfo info;
            info.media_id = media_id;
            info.media_type = content_type;
            info.media_length = data.size();
            info.upload_ts = std::time(nullptr);
            info.upload_name = upload_name;
            info.user_id = user_id;
            std::lock_guard lock(mutex_);
            media_info_[media_id] = info;
        }
        return result;
    }

    std::vector<uint8_t> download(const std::string& media_id, const std::string& server_name="") {
        if(!server_name.empty() && server_name!="localhost") {
            // Download from remote server via federation
            return {};
        }
        std::lock_guard lock(mutex_);
        auto it = media_info_.find(media_id);
        if(it != media_info_.end()) it->second.last_access_ts = std::to_string(std::time(nullptr));
        return store_.read_file(store_.store_path(media_id));
    }

    MediaInfo* get_info(const std::string& media_id) {
        auto it = media_info_.find(media_id);
        return (it != media_info_.end()) ? &it->second : nullptr;
    }

    Thumbnailer::ThumbnailResult create_thumbnail(const std::string& media_id, int w, int h,
                                                    const std::string& method="scale",
                                                    const std::string& type="image/jpeg") {
        ThumbnailMethod m = method=="crop"?ThumbnailMethod::CROP:ThumbnailMethod::SCALE;
        ThumbnailType t = type=="image/png"?ThumbnailType::PNG:(type=="image/webp"?ThumbnailType::WEBP:ThumbnailType::JPEG);
        return thumbnailer_.generate(media_id, w, h, m, t);
    }

    UrlPreviewer::PreviewResult preview_url(const std::string& url) {
        return previewer_.fetch_preview(url);
    }

    json get_remote_media(const std::string& server_name, const std::string& media_id) {
        // Try to fetch from remote server via federation
        json result; result["media_id"]=media_id;
        return result;
    }

    bool quarantine_media(const std::string& server_name, const std::string& media_id) {
        std::lock_guard lock(mutex_);
        auto it = media_info_.find(media_id);
        if(it==media_info_.end()) return false;
        it->second.quarantined = true;
        return true;
    }

    bool remove_from_quarantine(const std::string& server_name, const std::string& media_id) {
        std::lock_guard lock(mutex_);
        auto it = media_info_.find(media_id);
        if(it==media_info_.end()) return false;
        it->second.quarantined = false;
        return true;
    }

    int64_t delete_media(const std::string& server_name, const std::string& media_id) {
        std::lock_guard lock(mutex_);
        auto it = media_info_.find(media_id);
        if(it==media_info_.end()) return 0;
        int64_t size = it->second.media_length;
        // Delete file from storage
        media_info_.erase(it);
        return size;
    }

    json get_media_stats() {
        std::lock_guard lock(mutex_);
        json stats;
        stats["total_media"] = media_info_.size();
        int64_t total_size=0;
        for(auto& [_,info]:media_info_) total_size+=info.media_length;
        stats["total_size"] = total_size;
        return stats;
    }

    void delete_old_remote_media(int64_t before_ts) {
        // Delete cached remote media older than before_ts
    }

    void purge_url_cache(int64_t before_ts) {
        // Delete URL preview cache older than before_ts
    }

private:
    static std::string generate_media_id() {
        static std::atomic<uint64_t> c{0};
        return "media_" + std::to_string(std::time(nullptr)) + "_" + std::to_string(c.fetch_add(1));
    }
};

} // namespace media
} // namespace progressive
