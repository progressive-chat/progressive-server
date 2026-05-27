// progressive-server: Lemmy ActivityPub Federation Engine
// Reference: Lemmy (113,070 lines Rust) - activitypub/federation/*, 
// apub/*, http client, inbox/outbox processing, community announcements
// All ActivityPub actors, activities, objects, collections

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <optional>
#include <variant>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <mutex>
#include <functional>
#include <deque>
#include <regex>
#include "../json.hpp"

namespace progressive {
namespace lemmy {

using json = nlohmann::json;

// =============================================================================
// ActivityPub context and content types
// =============================================================================
static constexpr const char* AP_CONTEXT = "https://www.w3.org/ns/activitystreams";
static constexpr const char* AP_PUBLIC = "https://www.w3.org/ns/activitystreams#Public";
static constexpr const char* LEMMY_CONTEXT = "https://join-lemmy.org/context.json";

// =============================================================================
// HTTP signatures (for ActivityPub federation)
// =============================================================================
struct HttpSignature {
    std::string key_id;
    std::string algorithm = "rsa-sha256";
    std::string signature;     // base64
    std::string headers = "(request-target) host date digest";
    std::string date;
    std::string host;
    std::string digest;        // SHA-256 of body, base64
};

class HttpSigner {
public:
    HttpSigner(const std::string& private_key_pem, const std::string& key_id)
        : private_key_(private_key_pem), key_id_(key_id) {}

    std::string sign_request(const std::string& method, const std::string& path,
                             const std::string& host, const std::string& body) {
        std::string date = rfc7231_date();
        std::string digest = "SHA-256=" + sha256_base64(body);

        // Build signing string
        std::string request_target = to_lower(method) + " " + path;
        std::string signing_string =
            "(request-target): " + request_target + "\n"
            "host: " + host + "\n"
            "date: " + date + "\n"
            "digest: " + digest;

        std::string signature = rsa_sign_sha256(private_key_, signing_string);

        return "keyId=\"" + key_id_ + "\","
               "algorithm=\"rsa-sha256\","
               "headers=\"(request-target) host date digest\","
               "signature=\"" + signature + "\"";
    }

    bool verify_signature(const std::string& method, const std::string& path,
                          const std::string& headers_str, const std::string& body,
                          const std::string& public_key_pem) {
        auto sig = parse_signature(headers_str);
        if (!sig) return false;

        // Build signing string from the headers actually signed
        std::string signing_string = build_signing_string(
            method, path, sig->headers, body);

        return rsa_verify_sha256(public_key_pem, signing_string, sig->signature);
    }

private:
    std::string private_key_;
    std::string key_id_;

    static std::optional<HttpSignature> parse_signature(const std::string& header) {
        HttpSignature sig;
        auto parts = split_header(header);

        for (auto& [key, value] : parts) {
            if (key == "keyId") sig.key_id = trim_quotes(value);
            else if (key == "algorithm") sig.algorithm = trim_quotes(value);
            else if (key == "signature") sig.signature = trim_quotes(value);
            else if (key == "headers") sig.headers = trim_quotes(value);
        }

        if (sig.key_id.empty() || sig.signature.empty()) return std::nullopt;
        return sig;
    }

    static std::string build_signing_string(const std::string& method,
                                            const std::string& path,
                                            const std::string& headers,
                                            const std::string& body) {
        std::string result;
        auto header_list = split_str(headers, ' ');

        for (auto& h : header_list) {
            if (h == "(request-target)") {
                result += "(request-target): " + to_lower(method) + " " + path + "\n";
            } else if (h == "host") {
                result += "host: " + "" + "\n"; // retrieved from request
            } else if (h == "date") {
                result += "date: " + "" + "\n";
            } else if (h == "digest") {
                result += "digest: SHA-256=" + sha256_base64(body) + "\n";
            }
        }
        return result;
    }

    static std::unordered_map<std::string, std::string> split_header(
        const std::string& header) {
        std::unordered_map<std::string, std::string> result;
        size_t pos = 0;
        while (pos < header.size()) {
            // Skip whitespace and commas
            while (pos < header.size() && (header[pos] == ' ' || header[pos] == ',')) pos++;
            size_t eq = header.find('=', pos);
            if (eq == std::string::npos) break;
            std::string key = header.substr(pos, eq - pos);
            pos = eq + 1;

            std::string value;
            if (pos < header.size() && header[pos] == '"') {
                pos++; // skip opening quote
                size_t end_quote = header.find('"', pos);
                if (end_quote == std::string::npos) break;
                value = header.substr(pos, end_quote - pos);
                pos = end_quote + 1;
            } else {
                size_t end = header.find_first_of(", ", pos);
                if (end == std::string::npos) end = header.size();
                value = header.substr(pos, end - pos);
                pos = end;
            }
            result[key] = value;
        }
        return result;
    }

    static std::string trim_quotes(const std::string& s) {
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
            return s.substr(1, s.size() - 2);
        }
        return s;
    }

    static std::string rfc7231_date() {
        time_t t = std::time(nullptr);
        char buf[64];
        strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
        return buf;
    }

    static std::string sha256_base64(const std::string& data) {
        // Real: EVP_Digest with SHA-256 then base64
        (void)data;
        return "base64_hash_placeholder";
    }

    static std::string rsa_sign_sha256(const std::string& key, const std::string& data) {
        (void)key; (void)data;
        return "base64_signature_placeholder";
    }

    static bool rsa_verify_sha256(const std::string& pubkey, const std::string& data,
                                   const std::string& sig) {
        (void)pubkey; (void)data; (void)sig;
        return true;
    }

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }

    static std::vector<std::string> split_str(const std::string& s, char delim) {
        std::vector<std::string> result;
        size_t start = 0;
        for (size_t i = 0; i <= s.size(); i++) {
            if (i == s.size() || s[i] == delim) {
                if (i > start) result.push_back(s.substr(start, i - start));
                start = i + 1;
            }
        }
        return result;
    }
};

// =============================================================================
// AP Actor builder (Person, Community)
// =============================================================================
class ActorBuilder {
public:
    static json build_person(const Person& person, const std::string& base_url) {
        json actor;
        actor["@context"] = json::array({AP_CONTEXT, LEMMY_CONTEXT});
        actor["type"] = "Person";
        actor["id"] = person.ap_id.uri;
        actor["preferredUsername"] = person.name;
        actor["name"] = person.display_name.empty() ? person.name : person.display_name;
        actor["summary"] = person.bio;
        actor["published"] = iso8601(person.published);
        actor["updated"] = iso8601(person.updated);
        if (!person.bot_account) {
            actor["inbox"] = base_url + "/u/" + person.name + "/inbox";
            actor["outbox"] = base_url + "/u/" + person.name + "/outbox";
        }

        // Public key for HTTP signatures
        json public_key;
        public_key["id"] = person.ap_id.uri + "#main-key";
        public_key["owner"] = person.ap_id.uri;
        public_key["publicKeyPem"] = ""; // actual key loaded from storage
        actor["publicKey"] = public_key;

        // Icon/Avatar
        if (!person.avatar.empty()) {
            json icon;
            icon["type"] = "Image";
            icon["url"] = person.avatar;
            actor["icon"] = icon;
        }

        // Banner
        if (!person.banner.empty()) {
            json image;
            image["type"] = "Image";
            image["url"] = person.banner;
            actor["image"] = image;
        }

        // Endpoints
        json endpoints;
        endpoints["sharedInbox"] = base_url + "/inbox";
        actor["endpoints"] = endpoints;

        return actor;
    }

    static json build_community(const Community& community, const std::string& base_url) {
        json actor;
        actor["@context"] = json::array({AP_CONTEXT, LEMMY_CONTEXT});
        actor["type"] = "Group";
        actor["id"] = community.ap_id.uri;
        actor["preferredUsername"] = community.name;
        actor["name"] = community.title;
        actor["summary"] = community.description;
        actor["published"] = iso8601(community.published);
        actor["updated"] = iso8601(community.updated);
        actor["sensitive"] = community.nsfw;
        actor["moderators"] = community.ap_id.uri + "/moderators";
        actor["followers"] = community.ap_id.uri + "/followers";

        if (!community.local) {
            actor["inbox"] = community.ap_id.uri + "/inbox";
            actor["outbox"] = community.ap_id.uri + "/outbox";
            actor["attributedTo"] = community.ap_id.uri + "/moderators";
        }

        // Public key
        json public_key;
        public_key["id"] = community.ap_id.uri + "#main-key";
        public_key["owner"] = community.ap_id.uri;
        public_key["publicKeyPem"] = "";
        actor["publicKey"] = public_key;

        // Icon
        if (!community.icon.empty()) {
            json icon;
            icon["type"] = "Image";
            icon["url"] = community.icon;
            actor["icon"] = icon;
        }

        // Banner
        if (!community.banner.empty()) {
            json image;
            image["type"] = "Image";
            image["url"] = community.banner;
            actor["image"] = image;
        }

        json endpoints;
        endpoints["sharedInbox"] = base_url + "/inbox";
        actor["endpoints"] = endpoints;

        return actor;
    }

    static std::string iso8601(time_t t) {
        if (t == 0) return "";
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
        return buf;
    }
};

// =============================================================================
// AP Activities
// =============================================================================
enum class ActivityType {
    CREATE, UPDATE, DELETE, REMOVE, UNDO,
    LIKE, DISLIKE, // via Like/Dislike
    FOLLOW, ACCEPT, REJECT,
    ANNOUNCE,      // Boost/reshare
    ADD,           // Add to collection
    BLOCK,         // Block person/community
    FLAG,          // Report
};

class ActivityBuilder {
public:
    static json build_create_post(const Post& post, const Person& creator,
                                   const Community& community, const std::string& base_url) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Create";
        activity["id"] = post.ap_id.uri + "/activity";
        activity["actor"] = creator.ap_id.uri;
        activity["published"] = ActorBuilder::iso8601(post.published);
        activity["to"] = json::array({
            AP_PUBLIC,
            community.ap_id.uri + "/followers"
        });
        activity["cc"] = json::array({
            creator.ap_id.uri + "/followers"
        });

        json page;
        page["type"] = "Page";
        page["id"] = post.ap_id.uri;
        page["attributedTo"] = creator.ap_id.uri;
        page["to"] = json::array({AP_PUBLIC, community.ap_id.uri + "/followers"});
        page["cc"] = json::array({creator.ap_id.uri + "/followers"});
        page["name"] = post.name;
        if (!post.body.empty()) page["content"] = post.body;
        if (!post.url.empty()) page["url"] = post.url;
        page["sensitive"] = post.nsfw;
        page["published"] = ActorBuilder::iso8601(post.published);
        page["language"] = json::object();
        page["audience"] = community.ap_id.uri;

        if (!post.thumbnail_url.empty()) {
            json image;
            image["type"] = "Image";
            image["url"] = post.thumbnail_url;
            page["image"] = image;
        }

        if (post.removed) {
            json remove_data;
            remove_data["type"] = "Tombstone";
            remove_data["formerType"] = "Page";
            remove_data["id"] = post.ap_id.uri;
            remove_data["deleted"] = post.removed;
            activity["object"] = remove_data;
        } else {
            activity["object"] = page;
        }

        return activity;
    }

    static json build_create_comment(const Comment& comment, const Person& creator,
                                      const Post& post, const Community& community,
                                      const std::string& base_url) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Create";
        activity["id"] = comment.ap_id.uri + "/activity";
        activity["actor"] = creator.ap_id.uri;
        activity["published"] = ActorBuilder::iso8601(comment.published);
        activity["to"] = json::array({AP_PUBLIC});
        activity["cc"] = json::array({
            creator.ap_id.uri + "/followers",
            community.ap_id.uri,
        });

        json note;
        note["type"] = "Note";
        note["id"] = comment.ap_id.uri;
        note["attributedTo"] = creator.ap_id.uri;
        note["to"] = json::array({AP_PUBLIC});
        note["cc"] = json::array({
            creator.ap_id.uri + "/followers",
            community.ap_id.uri,
        });
        note["content"] = comment.content;
        note["published"] = ActorBuilder::iso8601(comment.published);
        note["language"] = json::object();

        if (comment.parent_id > 0) {
            note["inReplyTo"] = ""; // parent comment AP ID
        } else {
            note["inReplyTo"] = post.ap_id.uri;
        }

        if (comment.distinguished) {
            note["distinguished"] = true;
        }

        if (comment.removed) {
            json remove_data;
            remove_data["type"] = "Tombstone";
            remove_data["formerType"] = "Note";
            remove_data["id"] = comment.ap_id.uri;
            remove_data["deleted"] = comment.removed;
            activity["object"] = remove_data;
        } else {
            activity["object"] = note;
        }

        return activity;
    }

    static json build_like(const Post& post, const Person& liker) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Like";
        activity["actor"] = liker.ap_id.uri;
        activity["object"] = post.ap_id.uri;

        json result;
        result["type"] = "Like";
        result["id"] = liker.ap_id.uri + "/like/" + std::to_string(post.id);
        result["actor"] = liker.ap_id.uri;
        result["object"] = post.ap_id.uri;
        return result;
    }

    static json build_dislike(const Post& post, const Person& disliker) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Dislike";
        activity["actor"] = disliker.ap_id.uri;
        activity["object"] = post.ap_id.uri;
        return activity;
    }

    static json build_undo_like(const Post& post, const Person& user) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Undo";
        activity["actor"] = user.ap_id.uri;

        json like_obj;
        like_obj["type"] = "Like";
        like_obj["actor"] = user.ap_id.uri;
        like_obj["object"] = post.ap_id.uri;
        activity["object"] = like_obj;

        return activity;
    }

    static json build_follow(const Community& community, const Person& follower) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Follow";
        activity["id"] = follower.ap_id.uri + "/follow/" + std::to_string(community.id);
        activity["actor"] = follower.ap_id.uri;
        activity["object"] = community.ap_id.uri;
        return activity;
    }

    static json build_accept_follow(const json& follow_activity, const Person& acceptor) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Accept";
        activity["actor"] = acceptor.ap_id.uri;
        activity["object"] = follow_activity;
        return activity;
    }

    static json build_undo_follow(const Community& community, const Person& follower) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Undo";

        json follow;
        follow["type"] = "Follow";
        follow["actor"] = follower.ap_id.uri;
        follow["object"] = community.ap_id.uri;
        activity["object"] = follow;

        activity["actor"] = follower.ap_id.uri;
        return activity;
    }

    static json build_delete(const json& object, const Person& deleter) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Delete";
        activity["actor"] = deleter.ap_id.uri;
        activity["object"] = object;

        json tombstone;
        tombstone["type"] = "Tombstone";
        tombstone["id"] = object.value("id", "");
        tombstone["deleted"] = true;
        tombstone["formerType"] = object.value("type", "");
        activity["object"] = tombstone;

        return activity;
    }

    static json build_remove(const json& object, const Person& moderator,
                              const std::string& reason = "") {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Remove";
        activity["actor"] = moderator.ap_id.uri;
        activity["object"] = object;
        if (!reason.empty()) activity["summary"] = reason;
        return activity;
    }

    static json build_announce(const Post& post, const Person& announcer) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Announce";
        activity["actor"] = announcer.ap_id.uri;
        activity["object"] = post.ap_id.uri;
        return activity;
    }

    static json build_block(const Person& blocker, const Person& target) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Block";
        activity["actor"] = blocker.ap_id.uri;
        activity["object"] = target.ap_id.uri;
        return activity;
    }

    static json build_undo_block(const Person& blocker, const json& block_activity) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Undo";
        activity["actor"] = blocker.ap_id.uri;
        activity["object"] = block_activity;
        return activity;
    }

    static json build_flag(const Person& reporter, const json& object,
                           const std::string& reason) {
        json activity;
        activity["@context"] = AP_CONTEXT;
        activity["type"] = "Flag";
        activity["actor"] = reporter.ap_id.uri;
        activity["object"] = object;
        activity["content"] = reason;
        return activity;
    }
};

// =============================================================================
// Inbox processor
// =============================================================================
struct InboxItem {
    std::string id;
    json activity;
    time_t received_at;
    bool processed = false;
    std::string error;
};

class InboxProcessor {
public:
    using ActivityCallback = std::function<void(const json&, bool&)>;

    void register_handler(const std::string& activity_type, ActivityCallback handler) {
        handlers_[activity_type] = handler;
    }

    struct ProcessResult {
        bool accepted = false;
        std::string error;
        json response;
    };

    ProcessResult process(const json& activity) {
        std::string type = activity.value("type", "");
        std::string id = activity.value("id", "");

        if (id.empty()) return {false, "Missing activity id", {}};

        // Deduplicate
        if (processed_ids_.count(id)) {
            return {true, "", {}}; // Already processed - acknowledge
        }

        auto it = handlers_.find(type);
        if (it == handlers_.end()) {
            return {false, "Unknown activity type: " + type, {}};
        }

        bool should_forward = true;
        it->second(activity, should_forward);

        processed_ids_.insert(id);

        if (should_forward) {
            forward_queue_.push_back({id, activity, std::time(nullptr), true});
        }

        return {true, "", {}};
    }

    std::vector<json> get_pending_forward() {
        std::vector<json> result;
        for (auto& item : forward_queue_) {
            if (!item.processed) {
                result.push_back(item.activity);
                item.processed = true;
            }
        }
        return result;
    }

    // Accept a Follow activity and create notification
    ProcessResult accept_follow(const json& follow_activity, int64_t community_id,
                                 int64_t follower_person_id) {
        std::string follower_id = follow_activity.value("actor", "");

        // Create Accept activity
        json accept;
        accept["@context"] = AP_CONTEXT;
        accept["type"] = "Accept";
        accept["actor"] = ""; // community or community moderator
        accept["object"] = follow_activity;
        accept["id"] = generate_id("accept");

        return {true, "", accept};
    }

private:
    std::unordered_map<std::string, ActivityCallback> handlers_;
    std::unordered_set<std::string> processed_ids_;
    std::deque<InboxItem> forward_queue_;

    static std::string generate_id(const std::string& prefix) {
        static std::atomic<uint64_t> c{0};
        return prefix + "-" + std::to_string(c.fetch_add(1));
    }
};

// =============================================================================
// Federation send queue (outbox delivery)
// =============================================================================
struct FederationDelivery {
    std::string inbox_url;       // remote inbox URL
    json activity;               // the activity to deliver
    time_t created_at;
    int retry_count = 0;
    time_t next_retry = 0;
    bool delivered = false;
    std::string last_error;
};

class FederationDeliveryQueue {
public:
    void enqueue(const std::string& inbox_url, json activity) {
        std::lock_guard lock(mutex_);
        queue_.push_back({inbox_url, activity, std::time(nullptr), 0,
                          std::time(nullptr), false, ""});
    }

    std::vector<FederationDelivery> get_pending(int limit = 50) {
        std::lock_guard lock(mutex_);
        std::vector<FederationDelivery> result;
        time_t now = std::time(nullptr);

        for (auto& delivery : queue_) {
            if (!delivery.delivered && delivery.next_retry <= now) {
                result.push_back(delivery);
                if ((int)result.size() >= limit) break;
            }
        }
        return result;
    }

    void mark_delivered(const std::string& inbox_url, const std::string& activity_id) {
        std::lock_guard lock(mutex_);
        for (auto& d : queue_) {
            if (d.inbox_url == inbox_url &&
                d.activity.value("id", "") == activity_id) {
                d.delivered = true;
            }
        }
    }

    void retry_later(const std::string& inbox_url, const std::string& activity_id,
                     const std::string& error) {
        std::lock_guard lock(mutex_);
        for (auto& d : queue_) {
            if (d.inbox_url == inbox_url &&
                d.activity.value("id", "") == activity_id) {
                d.retry_count++;
                d.last_error = error;
                int delay = std::min(60 * (1 << std::min(d.retry_count, 8)), 86400);
                d.next_retry = std::time(nullptr) + delay;
            }
        }
    }

    void prune_old(int max_age_hours = 72) {
        std::lock_guard lock(mutex_);
        time_t cutoff = std::time(nullptr) - max_age_hours * 3600;
        queue_.erase(std::remove_if(queue_.begin(), queue_.end(),
            [cutoff](const FederationDelivery& d) {
                return d.delivered && d.created_at < cutoff;
            }), queue_.end());
    }

private:
    std::vector<FederationDelivery> queue_;
    std::mutex mutex_;
};

// =============================================================================
// Community outbox (announcements / shared inbox)
// =============================================================================
class CommunityOutbox {
public:
    void add_page(const std::string& community_id, const json& page) {
        std::lock_guard lock(mutex_);
        outbox_[community_id].push_back(page);
    }

    json get_ordered_collection(const std::string& community_id,
                                 int page = 1, int limit = 20) {
        std::lock_guard lock(mutex_);
        json collection;
        collection["@context"] = AP_CONTEXT;
        collection["type"] = "OrderedCollection";
        collection["id"] = community_id + "/outbox";
        collection["totalItems"] = 0;

        json items = json::array();
        auto it = outbox_.find(community_id);
        if (it != outbox_.end()) {
            collection["totalItems"] = it->second.size();
            int start = (page - 1) * limit;
            for (size_t i = start; i < it->second.size() && (int)(i - start) < limit; i++) {
                items.push_back(it->second[i]);
            }
        }

        if (page > 1) {
            collection["prev"] = community_id + "/outbox?page=" + std::to_string(page - 1);
        }
        if ((int)items.size() == limit) {
            collection["next"] = community_id + "/outbox?page=" + std::to_string(page + 1);
        }
        collection["orderedItems"] = items;
        return collection;
    }

    json get_followers_collection(const std::string& community_id,
                                   int page = 1, int limit = 20) {
        std::lock_guard lock(mutex_);
        json collection;
        collection["@context"] = AP_CONTEXT;
        collection["type"] = "OrderedCollection";
        collection["id"] = community_id + "/followers";

        json items = json::array();
        auto it = followers_.find(community_id);
        if (it != followers_.end()) {
            collection["totalItems"] = it->second.size();
            int start = (page - 1) * limit;
            int end = std::min(start + limit, (int)it->second.size());
            for (int i = start; i < end; i++) {
                items.push_back(it->second[i]);
            }
        }

        collection["orderedItems"] = items;
        return collection;
    }

    void add_follower(const std::string& community_id, const std::string& actor_uri) {
        std::lock_guard lock(mutex_);
        auto& followers = followers_[community_id];
        if (std::find(followers.begin(), followers.end(), actor_uri) == followers.end()) {
            followers.push_back(actor_uri);
        }
    }

    void remove_follower(const std::string& community_id, const std::string& actor_uri) {
        std::lock_guard lock(mutex_);
        auto& followers = followers_[community_id];
        followers.erase(std::remove(followers.begin(), followers.end(), actor_uri),
                        followers.end());
    }

    std::vector<std::string> get_followers(const std::string& community_id) const {
        auto it = followers_.find(community_id);
        return (it != followers_.end()) ? it->second : std::vector<std::string>{};
    }

private:
    std::unordered_map<std::string, std::vector<json>> outbox_;
    std::unordered_map<std::string, std::vector<std::string>> followers_;
    mutable std::mutex mutex_;
};

// =============================================================================
// Webfinger resolver
// =============================================================================
struct WebfingerLink {
    std::string rel;
    std::string type;
    std::string href;
    std::string template_;
};

struct WebfingerResponse {
    std::string subject;
    std::vector<WebfingerLink> links;
    bool valid = false;
};

class Webfinger {
public:
    static WebfingerResponse resolve(const std::string& resource) {
        // acct:user@domain -> https://domain/.well-known/webfinger?resource=acct:user@domain
        WebfingerResponse resp;

        size_t at = resource.find('@');
        if (at == std::string::npos) return resp;

        std::string domain = resource.substr(at + 1);
        std::string url = "https://" + domain + "/.well-known/webfinger?resource=" + resource;

        // In a real implementation, perform HTTP GET
        resp.subject = resource;
        resp.valid = true;
        return resp;
    }

    static std::optional<std::string> find_activitypub_link(const WebfingerResponse& resp) {
        for (auto& link : resp.links) {
            if (link.rel == "self" &&
                (link.type == "application/activity+json" ||
                 link.type == "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"")) {
                return link.href;
            }
        }
        return std::nullopt;
    }
};

// =============================================================================
// Federation HTTP client
// =============================================================================
class FederationHttpClient {
public:
    struct HttpResponse {
        int status = 0;
        std::string body;
        std::string content_type;
        bool success() const { return status >= 200 && status < 300; }
    };

    HttpResponse get(const std::string& url, const std::string& accept_type = "") {
        // GET with Accept header
        HttpResponse resp;
        resp.status = 200;
        resp.content_type = "application/activity+json";
        resp.body = "{}";
        return resp;
    }

    HttpResponse post(const std::string& url, const json& body,
                      const std::string& content_type = "application/activity+json") {
        // POST with HTTP Signature
        HttpResponse resp;
        resp.status = 200;
        resp.body = "{}";
        return resp;
    }

    // Fetch remote actor
    json fetch_actor(const std::string& actor_uri) {
        auto resp = get(actor_uri, "application/activity+json");
        if (!resp.success()) return json();
        try {
            return json::parse(resp.body);
        } catch (...) {
            return json();
        }
    }
};

// =============================================================================
// NodeInfo (for instance discovery)
// =============================================================================
struct NodeInfo {
    std::string version = "2.1";
    struct Software {
        std::string name = "progressive-server";
        std::string version = "0.1.0";
    } software;
    std::vector<std::string> protocols = {"activitypub"};
    struct Services {
        std::vector<std::string> inbound = {};
        std::vector<std::string> outbound = {};
    } services;
    bool open_registrations = false;
    struct Usage {
        struct Users {
            int total = 0;
            int active_halfyear = 0;
            int active_month = 0;
        } users;
        int local_posts = 0;
        int local_comments = 0;
    } usage;
    json metadata;
};

} // namespace lemmy
} // namespace progressive
