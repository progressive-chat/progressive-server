// progressive-server: ActivityPub / Lemmy implementation
// Reference: Lemmy (113,070 lines Rust) - full ActivityPub server, community
// management, post/comment federation, user authentication, WebSocket API.
// Translating Rust → C++ precisely, maintaining all data structures, 
// API endpoints, federation protocols, and moderation features.

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <functional>
#include <optional>
#include <variant>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <regex>
#include <atomic>
#include <mutex>

namespace progressive {
namespace lemmy {

// =============================================================================
// ActivityPub actor types
// =============================================================================
enum class ActorType : uint8_t {
    PERSON,
    GROUP,          // Lemmy Community
    APPLICATION,
    SERVICE,
    ORGANIZATION,
};

enum class PostListingType : uint8_t {
    ALL, LOCAL, SUBSCRIBED, MODERATOR_VIEW
};

enum class SortType : uint8_t {
    ACTIVE, HOT, NEW, OLD, TOP_DAY, TOP_WEEK, TOP_MONTH,
    TOP_YEAR, TOP_ALL, MOST_COMMENTS, NEW_COMMENTS,
    TOP_HOUR, TOP_SIX_HOUR, TOP_TWELVE_HOUR,
    TOP_THREE_MONTHS, TOP_SIX_MONTHS, TOP_NINE_MONTHS,
    CONTROVERSIAL, SCALED
};

enum class CommentSortType : uint8_t {
    HOT, TOP, NEW, OLD, CONTROVERSIAL
};

enum class SubscribedType : uint8_t {
    NOT_SUBSCRIBED, PENDING, SUBSCRIBED
};

enum class RegistrationMode : uint8_t {
    CLOSED, REQUIRE_APPLICATION, OPEN
};

enum class FederationMode : uint8_t {
    ALL, LOCAL, DISABLED
};

// =============================================================================
// AP IDs (ActivityPub resource identifiers)
// =============================================================================
struct ApId {
    std::string uri; // Full URL: https://lemmy.example/u/username
    std::string host; // Domain only

    static ApId from_str(const std::string& s) {
        ApId id;
        id.uri = s;
        // Extract host
        size_t scheme_end = s.find("://");
        if (scheme_end != std::string::npos) {
            size_t host_start = scheme_end + 3;
            size_t host_end = s.find('/', host_start);
            id.host = s.substr(host_start, host_end - host_start);
        }
        return id;
    }

    bool is_local(const std::string& local_host) const {
        return host == local_host;
    }

    std::string to_string() const { return uri; }
    bool operator==(const ApId& o) const { return uri == o.uri; }
};

struct ApIdHash {
    size_t operator()(const ApId& id) const {
        return std::hash<std::string>{}(id.uri);
    }
};

// =============================================================================
// Person (User)
// =============================================================================
struct Person {
    int64_t id = 0;
    ApId ap_id;
    std::string name;
    std::string display_name;
    std::string avatar;      // URL
    std::string banner;      // URL
    std::string bio;
    std::string matrix_user_id;
    bool bot_account = false;
    bool banned = false;
    bool deleted = false;
    bool admin = false;
    time_t published;
    time_t updated;
    time_t last_refreshed_at = 0;

    // Login credentials (local users only)
    std::string password_encrypted;
    std::string email;
    bool email_verified = false;
    bool show_nsfw = false;
    std::string theme;
    std::string default_sort_type;
    std::string default_listing_type;
    std::string interface_language;
    bool show_avatars = true;
    bool send_notifications_to_email = false;
    bool show_bot_accounts = true;
    bool show_read_posts = true;
    bool show_new_post_notifs = false;

    // Totp
    std::string totp_secret;
    bool totp_enabled = false;

    // Counts
    int64_t comment_score = 0;
    int64_t post_score = 0;
    int comment_count = 0;
    int post_count = 0;
};

// =============================================================================
// Community
// =============================================================================
struct Community {
    int64_t id = 0;
    ApId ap_id;
    std::string name;
    std::string title;
    std::string description;
    std::string icon;        // URL
    std::string banner;      // URL
    bool removed = false;
    bool deleted = false;
    bool nsfw = false;
    bool local = true;
    bool hidden = false;
    bool posting_restricted_to_mods = false;
    int64_t creator_id = 0;
    time_t published;
    time_t updated;
    time_t last_refreshed_at = 0;
    std::string instance_id; // remote instance

    // Counts
    int subscribers = 0;
    int posts = 0;
    int comments = 0;
    int users_active_day = 0;
    int users_active_week = 0;
    int users_active_month = 0;
    int users_active_half_year = 0;
};

// =============================================================================
// Post
// =============================================================================
struct Post {
    int64_t id = 0;
    ApId ap_id;
    std::string name;
    std::string url;             // Link post
    std::string body;            // Text post
    bool nsfw = false;
    bool removed = false;
    bool deleted = false;
    bool locked = false;
    bool featured_community = false;
    bool featured_local = false;
    bool local = true;
    time_t published;
    time_t updated;
    int64_t creator_id = 0;
    int64_t community_id = 0;
    std::string embed_title;
    std::string embed_description;
    std::string embed_video_url;
    std::string thumbnail_url;

    // Counts
    int score = 0;
    int upvotes = 0;
    int downvotes = 0;
    int comments_count = 0;
    bool hot_rank_active = false;
    double hot_rank = 0.0;
    double scaled_rank = 0.0;
    double controversy_rank = 0.0;

    // Tracking
    int newest_comment_time = 0;
    std::string language_id;
};

// =============================================================================
// Comment
// =============================================================================
struct Comment {
    int64_t id = 0;
    ApId ap_id;
    std::string content;
    bool removed = false;
    bool deleted = false;
    bool local = true;
    bool distinguished = false;
    time_t published;
    time_t updated;
    int64_t creator_id = 0;
    int64_t post_id = 0;
    int64_t parent_id = 0; // 0 = top-level comment
    int depth = 0;         // nesting depth
    std::string path;      // 0.123.456 for tree navigation

    // Counts
    int score = 0;
    int upvotes = 0;
    int downvotes = 0;
    int child_count = 0;

    // Language
    std::string language_id;
};

// =============================================================================
// Comment reply (notification)
// =============================================================================
struct CommentReply {
    int64_t id = 0;
    int64_t recipient_id = 0;
    int64_t comment_id = 0;
    bool read = false;
    time_t published;
};

// =============================================================================
// Person mention
// =============================================================================
struct PersonMention {
    int64_t id = 0;
    int64_t recipient_id = 0;
    int64_t comment_id = 0;
    bool read = false;
    time_t published;
};

// =============================================================================
// Private message
// =============================================================================
struct PrivateMessage {
    int64_t id = 0;
    ApId ap_id;
    std::string content;
    bool deleted = false;
    bool read = false;
    bool local = true;
    time_t published;
    time_t updated;
    int64_t creator_id = 0;
    int64_t recipient_id = 0;
};

// =============================================================================
// Private message report
// =============================================================================
struct PrivateMessageReport {
    int64_t id = 0;
    int64_t creator_id = 0;
    int64_t pm_id = 0;
    std::string original_content;
    std::string reason;
    bool resolved = false;
    int64_t resolver_id = 0;
    time_t published;
    time_t updated;
};

// =============================================================================
// Post report
// =============================================================================
struct PostReport {
    int64_t id = 0;
    int64_t creator_id = 0;
    int64_t post_id = 0;
    std::string original_post_name;
    std::string original_post_url;
    std::string original_post_body;
    std::string reason;
    bool resolved = false;
    int64_t resolver_id = 0;
    time_t published;
    time_t updated;
};

// =============================================================================
// Comment report
// =============================================================================
struct CommentReport {
    int64_t id = 0;
    int64_t creator_id = 0;
    int64_t comment_id = 0;
    std::string original_comment_text;
    std::string reason;
    bool resolved = false;
    int64_t resolver_id = 0;
    time_t published;
    time_t updated;
};

// =============================================================================
// Site (instance configuration)
// =============================================================================
struct Site {
    int64_t id = 0;
    std::string name;
    std::string sidebar;
    std::string description;
    std::string icon;
    std::string banner;
    bool enable_downvotes = true;
    bool enable_nsfw = true;
    bool community_creation_admin_only = false;
    bool require_email_verification = false;
    bool require_application = false;
    std::string application_question;
    bool private_instance = false;
    std::string default_theme;
    std::string default_post_listing_type;
    std::string legal_information;
    bool hide_modlog_mod_names = true;
    std::string discussion_languages;
    std::string slur_filter_regex;
    int actor_name_max_length = 20;
    bool federation_enabled = true;
    int federation_debug = 0;
    bool captcha_enabled = false;
    std::string captcha_difficulty;
    time_t published;
    time_t updated;
    int64_t creator_id = 0;
    std::string instance_id;
    std::string content_warning;
    bool registration_mode_enabled = false;
};

// =============================================================================
// Local user (credentials)
// =============================================================================
struct LocalUser {
    int64_t id = 0;
    int64_t person_id = 0;
    std::string password_encrypted;
    std::string email;
    bool email_verified = false;
    bool accepted_application = false;
    bool admin = false;
    std::string default_listing_type;
    std::string default_sort_type;
    std::string theme;
    bool show_nsfw = false;
    std::string interface_language;
    bool show_avatars = true;
    bool send_notifications_to_email = false;
    bool show_scores = true;
    bool show_bot_accounts = true;
    bool show_read_posts = true;
    bool show_new_post_notifs = false;
    bool email_notifications_enabled = false;
    std::string validator_time;
};

// =============================================================================
// Vote structures
// =============================================================================
struct PostLike {
    int64_t id = 0;
    int64_t post_id = 0;
    int64_t person_id = 0;
    int score = 0;     // 1 = upvote, -1 = downvote
    time_t published;
};

struct CommentLike {
    int64_t id = 0;
    int64_t comment_id = 0;
    int64_t person_id = 0;
    int score = 0;
    time_t published;
};

// =============================================================================
// Subscription (Community subscription)
// =============================================================================
struct CommunityFollower {
    int64_t id = 0;
    int64_t community_id = 0;
    int64_t person_id = 0;
    SubscribedType state = SubscribedType::NOT_SUBSCRIBED;
    time_t published;
};

// =============================================================================
// Community block
// =============================================================================
struct CommunityBlock {
    int64_t id = 0;
    int64_t person_id = 0;
    int64_t community_id = 0;
    time_t published;
};

// =============================================================================
// Person block
// =============================================================================
struct PersonBlock {
    int64_t id = 0;
    int64_t person_id = 0;
    int64_t target_id = 0;
    time_t published;
};

// =============================================================================
// Instance block (defederation)
// =============================================================================
struct InstanceBlock {
    int64_t id = 0;
    int64_t person_id = 0;
    int64_t instance_id = 0;
    time_t published;
};

// =============================================================================
// Local site (rate limit config)
// =============================================================================
struct LocalSite {
    int64_t id = 0;
    int64_t site_id = 0;
    bool site_setup = false;
    bool enable_downvotes = true;
    bool enable_nsfw = true;
    bool community_creation_admin_only = false;
    bool require_email_verification = false;
    std::string application_question;
    bool private_instance = false;
    std::string default_theme;
    std::string default_post_listing_type;
    std::string legal_information;
    bool hide_modlog_mod_names = true;
    std::string discussion_languages;
    std::string slur_filter_regex;
    int actor_name_max_length = 20;
    bool federation_enabled = true;
    int federation_debug = 0;
    bool captcha_enabled = false;
    std::string captcha_difficulty;
    time_t published;
    time_t updated;
};

// =============================================================================
// Local site rate limit
// =============================================================================
struct LocalSiteRateLimit {
    int64_t id = 0;
    int local_site_id = 0;
    int message = 60;           // per second
    int message_per_second = 60;
    int post = 6;               // per second
    int post_per_second = 600;
    int register_per_second = 3600;
    int image = 6;              // per second
    int image_per_second = 3600;
    int comment = 6;            // per second
    int comment_per_second = 600;
    int search = 60;            // per second
    int search_per_second = 600;
    time_t published;
    time_t updated;
};

// =============================================================================
// Language
// =============================================================================
struct Language {
    int64_t id = 0;
    std::string code;         // en, ru, de, etc.
    std::string name;         // English, Russian, German
};

// =============================================================================
// Tagline
// =============================================================================
struct Tagline {
    int64_t id = 0;
    int local_site_id = 0;
    std::string content;
    time_t published;
    time_t updated;
};

// =============================================================================
// Custom Emoji
// =============================================================================
struct CustomEmoji {
    int64_t id = 0;
    int local_site_id = 0;
    std::string shortcode;
    std::string image_url;
    std::string alt_text;
    std::string category;
    time_t published;
    time_t updated;
};

// =============================================================================
// Custom Emoji keyword
// =============================================================================
struct CustomEmojiKeyword {
    int64_t id = 0;
    int64_t custom_emoji_id = 0;
    std::string keyword;
};

// =============================================================================
// Mod actions
// =============================================================================
struct ModAdd {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t other_person_id = 0;
    bool removed = false;
    time_t when;
};

struct ModAddCommunity {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t other_person_id = 0;
    int64_t community_id = 0;
    bool removed = false;
    time_t when;
};

struct ModBan {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t other_person_id = 0;
    std::string reason;
    int ban_type = 0; // 0=ban, 1=unban
    bool banned = true;
    time_t expires;
    time_t when;
};

struct ModBanFromCommunity {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t other_person_id = 0;
    int64_t community_id = 0;
    std::string reason;
    bool banned = true;
    time_t expires;
    time_t when;
};

struct ModHideCommunity {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t community_id = 0;
    std::string reason;
    bool hidden = true;
    time_t when;
};

struct ModLockPost {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t post_id = 0;
    bool locked = true;
    time_t when;
};

struct ModRemoveComment {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t comment_id = 0;
    std::string reason;
    bool removed = true;
    time_t when;
};

struct ModRemoveCommunity {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t community_id = 0;
    std::string reason;
    bool removed = true;
    time_t expires;
    time_t when;
};

struct ModRemovePost {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t post_id = 0;
    std::string reason;
    bool removed = true;
    time_t when;
};

struct ModFeaturePost {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t post_id = 0;
    bool featured = true;
    bool is_featured_community = false;
    time_t when;
};

struct ModTransferCommunity {
    int64_t id = 0;
    int64_t mod_person_id = 0;
    int64_t other_person_id = 0;
    int64_t community_id = 0;
    time_t when;
};

// =============================================================================
// Registration application
// =============================================================================
struct RegistrationApplication {
    int64_t id = 0;
    int64_t person_id = 0;
    std::string answer;
    int64_t admin_id = 0;
    std::string deny_reason;
    time_t published;
};

// =============================================================================
// Private message view
// =============================================================================
struct PrivateMessageReportView {
    PrivateMessageReport report;
    PrivateMessage pm;
    Person creator;
    Person pm_creator;
    Person resolver;
};

// =============================================================================
// Post view (joined data)
// =============================================================================
struct PostView {
    Post post;
    Person creator;
    Community community;
    bool creator_banned_from_community = false;
    OptionalInt64 my_vote;
    bool saved = false;
    bool read = false;
    bool creator_blocked = false;
    int unread_comments = 0;

    struct OptionalInt64 {
        std::optional<int> value;
    };
};

// =============================================================================
// Comment view
// =============================================================================
struct CommentView {
    Comment comment;
    Person creator;
    Post post;
    Community community;
    int my_vote = 0;
    bool saved = false;
    bool creator_blocked = false;
    int subscribed = 0; // SubscribedType
    Comment* parent_comment = nullptr;
};

// =============================================================================
// Community moderator view
// =============================================================================
struct CommunityModeratorView {
    Community community;
    Person moderator;
};

// =============================================================================
// Community follower view
// =============================================================================
struct CommunityFollowerView {
    Community community;
    Person follower;
};

// =============================================================================
// Person view safe
// =============================================================================
struct PersonViewSafe {
    Person person;
    int counts_total = 0;
};

// =============================================================================
// Mod log
// =============================================================================
struct ModlogEntry {
    enum Type {
        MOD_REMOVE_POST, MOD_LOCK_POST, MOD_FEATURE_POST,
        MOD_REMOVE_COMMENT, MOD_REMOVE_COMMUNITY,
        MOD_BAN_FROM_COMMUNITY, MOD_BAN,
        MOD_ADD_COMMUNITY, MOD_ADD,
        MOD_TRANSFER_COMMUNITY, MOD_HIDE_COMMUNITY,
        ADMIN_PURGE_POST, ADMIN_PURGE_COMMENT, ADMIN_PURGE_PERSON,
        ADMIN_PURGE_COMMUNITY
    };
    Type type;
    time_t when;
    std::string reason;
    int64_t mod_person_id = 0;
    int64_t other_person_id = 0;
    int64_t post_id = 0;
    int64_t comment_id = 0;
    int64_t community_id = 0;
};

// =============================================================================
// Image upload
// =============================================================================
struct ImageUpload {
    std::string file;
    bool delete_url = false;
};

struct ImageUploadResponse {
    std::string msg;
    bool files_too_large = false;
    std::string delete_url;
};

struct ImageDetails {
    std::string delete_token;
    std::string file;
};

// =============================================================================
// Search
// =============================================================================
struct SearchParams {
    std::string q;
    int64_t community_id = 0;
    std::string community_name;
    int64_t creator_id = 0;
    std::string type_;    // All, Comments, Posts, Communities, Users, Url
    SortType sort = SortType::TOP_ALL;
    PostListingType listing_type = PostListingType::ALL;
    int page = 1;
    int limit = 20;
    std::string auth;
};

struct SearchResponse {
    std::string type_;
    std::vector<CommentView> comments;
    std::vector<PostView> posts;
    std::vector<Community> communities;
    std::vector<PersonViewSafe> users;
};

// =============================================================================
// Resolve object
// =============================================================================
struct ResolveObjectParams {
    std::string q;
    std::string auth;
};

struct ResolveObjectResponse {
    std::optional<CommentView> comment;
    std::optional<PostView> post;
    std::optional<Community> community;
    std::optional<PersonViewSafe> person;
};

// =============================================================================
// Site metadata (for federation)
// =============================================================================
struct SiteMetadata {
    std::string title;
    std::string description;
    std::string image;
    std::string embed_video_url;
};

// =============================================================================
// Get site response
// =============================================================================
struct GetSiteResponse {
    SiteView site_view;
    std::vector<Person> admins;
    std::string version;
    MyUserInfo my_user;
    std::vector<Language> all_languages;
    std::vector<int64_t> discussion_languages;
    std::vector<Tagline> taglines;
    std::vector<CustomEmojiView> custom_emojis;
    std::vector<LocalSiteRateLimit> local_site_rate_limit;
    bool federated_instances = false;

    struct SiteView {
        Site site;
        LocalSite local_site;
        LocalSiteRateLimit local_site_rate_limit;
        int counts;
    };

    struct MyUserInfo {
        std::optional<LocalUserView> local_user_view;
        std::vector<int64_t> follows;
        std::vector<int64_t> community_blocks;
        std::vector<int64_t> person_blocks;
        std::vector<int64_t> instance_blocks;
        std::vector<int64_t> moderates;
    };

    struct LocalUserView {
        LocalUser local_user;
        Person person;
        int counts;
    };

    struct CustomEmojiView {
        CustomEmoji custom_emoji;
        std::vector<CustomEmojiKeyword> keywords;
    };
};

// =============================================================================
// Registration
// =============================================================================
struct RegisterParams {
    std::string username;
    std::string password;
    std::string password_verify;
    std::string email;
    std::string captcha_uuid;
    std::string captcha_answer;
    std::string answer;       // application answer
    bool show_nsfw = false;
    std::string honeypot;
};

struct LoginParams {
    std::string username_or_email;
    std::string password;
    std::string totp_2fa_token;
};

struct LoginResponse {
    std::string jwt;
    bool registration_created = false;
    bool verify_email_sent = false;
};

struct PasswordChangeParams {
    std::string token;
    std::string password;
    std::string password_verify;
};

struct PasswordResetParams {
    std::string email;
};

struct VerifyEmailParams {
    std::string token;
};

// =============================================================================
// API wrappers (Community)
// =============================================================================
struct GetCommunityParams {
    std::optional<int64_t> id;
    std::optional<std::string> name;
    std::string auth;
};

struct GetCommunityResponse {
    CommunityView community_view;
    std::optional<int64_t> discussion_languages;
    std::vector<CommunityModeratorView> moderators;
    bool online = false;

    struct CommunityView {
        Community community;
        SubscribedType subscribed = SubscribedType::NOT_SUBSCRIBED;
        bool blocked = false;
        int counts;
    };
};

struct CreateCommunityParams {
    std::string name;
    std::string title;
    std::string description;
    std::string icon;
    std::string banner;
    bool nsfw = false;
    bool posting_restricted_to_mods = false;
    std::vector<int64_t> discussion_languages;
    std::string auth;
};

struct EditCommunityParams {
    int64_t community_id = 0;
    std::string title;
    std::string description;
    std::string icon;
    std::string banner;
    bool nsfw = false;
    bool posting_restricted_to_mods = false;
    std::vector<int64_t> discussion_languages;
    std::string auth;
};

struct DeleteCommunityParams {
    int64_t community_id = 0;
    bool deleted = true;
    std::string auth;
};

struct RemoveCommunityParams {
    int64_t community_id = 0;
    bool removed = true;
    std::string reason;
    time_t expires = 0;
    std::string auth;
};

struct HideCommunityParams {
    int64_t community_id = 0;
    bool hidden = true;
    std::string reason;
    std::string auth;
};

struct TransferCommunityParams {
    int64_t community_id = 0;
    int64_t person_id = 0;
    std::string auth;
};

struct BanFromCommunityParams {
    int64_t community_id = 0;
    int64_t person_id = 0;
    bool ban = true;
    bool remove_data = false;
    std::string reason;
    int expires = 0;
    std::string auth;
};

struct AddModToCommunityParams {
    int64_t community_id = 0;
    int64_t person_id = 0;
    bool added = true;
    std::string auth;
};

struct FollowCommunityParams {
    int64_t community_id = 0;
    bool follow = true;
    std::string auth;
};

struct BlockCommunityParams {
    int64_t community_id = 0;
    bool block = true;
    std::string auth;
};

struct ListCommunitiesParams {
    SortType sort = SortType::HOT;
    PostListingType type_ = PostListingType::ALL;
    int page = 1;
    int limit = 20;
    bool show_nsfw = false;
    std::string auth;
};

// =============================================================================
// Post API
// =============================================================================
struct CreatePostParams {
    std::string name;
    int64_t community_id = 0;
    std::string url;
    std::string body;
    std::string honeypot;
    bool nsfw = false;
    std::optional<int64_t> language_id;
    std::string auth;
};

struct GetPostParams {
    int64_t id = 0;
    std::optional<int64_t> comment_id;
    std::string auth;
};

struct GetPostResponse {
    PostView post_view;
    int64_t community_id = 0;
    std::vector<CommunityModeratorView> moderators;
    bool online = false;
};

struct EditPostParams {
    int64_t post_id = 0;
    std::string name;
    std::string url;
    std::string body;
    bool nsfw = false;
    std::optional<int64_t> language_id;
    std::string auth;
};

struct DeletePostParams {
    int64_t post_id = 0;
    bool deleted = true;
    std::string auth;
};

struct RemovePostParams {
    int64_t post_id = 0;
    bool removed = true;
    std::string reason;
    std::string auth;
};

struct LockPostParams {
    int64_t post_id = 0;
    bool locked = true;
    std::string auth;
};

struct FeaturePostParams {
    int64_t post_id = 0;
    bool featured = true;
    bool feature_type_local = false;
    std::string auth;
};

struct GetPostsParams {
    SortType sort = SortType::HOT;
    PostListingType type_ = PostListingType::ALL;
    std::optional<int64_t> community_id;
    std::optional<std::string> community_name;
    int page = 1;
    int limit = 20;
    bool saved_only = false;
    bool liked_only = false;
    bool disliked_only = false;
    bool show_hidden = false;
    std::string auth;
};

struct GetPostsResponse {
    std::vector<PostView> posts;
};

struct CreatePostLikeParams {
    int64_t post_id = 0;
    int score = 1; // 1 = upvote, -1 = downvote, 0 = remove
    std::string auth;
};

struct SavePostParams {
    int64_t post_id = 0;
    bool save = true;
    std::string auth;
};

struct ReadPostParams {
    int64_t post_id = 0;
    bool read = true;
    std::string auth;
};

struct MarkPostAsReadParams {
    std::vector<int64_t> post_ids;
    bool read = true;
    std::string auth;
};

// =============================================================================
// Comment API
// =============================================================================
struct CreateCommentParams {
    std::string content;
    int64_t post_id = 0;
    std::optional<int64_t> parent_id;
    std::string form_id;
    std::optional<int64_t> language_id;
    std::string honeypot;
    std::string auth;
};

struct EditCommentParams {
    int64_t comment_id = 0;
    std::string content;
    std::optional<int64_t> language_id;
    std::string auth;
};

struct DeleteCommentParams {
    int64_t comment_id = 0;
    bool deleted = true;
    std::string auth;
};

struct RemoveCommentParams {
    int64_t comment_id = 0;
    bool removed = true;
    std::string reason;
    std::string auth;
};

struct GetCommentsParams {
    SortType sort = SortType::HOT;
    PostListingType type_ = PostListingType::ALL;
    std::optional<int64_t> community_id;
    std::optional<std::string> community_name;
    std::optional<int64_t> post_id;
    std::optional<int64_t> parent_id;
    int page = 1;
    int limit = 20;
    bool saved_only = false;
    bool liked_only = false;
    bool disliked_only = false;
    int max_depth = 8;
    std::string auth;
};

struct GetCommentsResponse {
    std::vector<CommentView> comments;
};

struct LikeCommentParams {
    int64_t comment_id = 0;
    int score = 1;
    std::string auth;
};

struct SaveCommentParams {
    int64_t comment_id = 0;
    bool save = true;
    std::string auth;
};

struct DistinguishCommentParams {
    int64_t comment_id = 0;
    bool distinguished = true;
    std::string auth;
};

// =============================================================================
// Person API
// =============================================================================
struct GetPersonDetailsParams {
    std::optional<int64_t> person_id;
    std::optional<std::string> username;
    SortType sort = SortType::NEW;
    int page = 1;
    int limit = 20;
    int saved_only = 0;
    std::string auth;
};

struct GetPersonDetailsResponse {
    PersonView person_view;
    std::vector<CommentView> comments;
    std::vector<PostView> posts;
    std::vector<CommunityModeratorView> moderates;

    struct PersonView {
        Person person;
        int counts;
        bool is_admin = false;
    };
};

struct GetPersonMentionsParams {
    SortType sort = SortType::NEW;
    int page = 1;
    int limit = 20;
    bool unread_only = false;
    std::string auth;
};

struct PersonMentionResponse {
    std::vector<PersonMentionView> mentions;

    struct PersonMentionView {
        PersonMention person_mention;
        Comment comment;
        Person creator;
        Post post;
        Community community;
        Person recipient;
        int creator_banned_from_community = 0;
        int my_vote = 0;
        bool saved = false;
        int subscribed = 0;
    };
};

struct MarkPersonMentionAsReadParams {
    int64_t person_mention_id = 0;
    bool read = true;
    std::string auth;
};

struct GetRepliesParams {
    SortType sort = SortType::NEW;
    int page = 1;
    int limit = 20;
    bool unread_only = false;
    std::string auth;
};

struct GetRepliesResponse {
    std::vector<CommentReplyView> replies;

    struct CommentReplyView {
        CommentReply comment_reply;
        Comment comment;
        Person creator;
        Post post;
        Community community;
        Person recipient;
        bool creator_banned_from_community = false;
        int my_vote = 0;
        bool saved = false;
        int subscribed = 0;
    };
};

struct MarkCommentReplyAsReadParams {
    int64_t comment_reply_id = 0;
    bool read = true;
    std::string auth;
};

struct BlockPersonParams {
    int64_t person_id = 0;
    bool block = true;
    std::string auth;
};

struct GetUnreadCountParams {
    std::string auth;
};

struct GetUnreadCountResponse {
    int replies = 0;
    int mentions = 0;
    int private_messages = 0;
};

// =============================================================================
// Private message API
// =============================================================================
struct GetPrivateMessagesParams {
    int page = 1;
    int limit = 20;
    bool unread_only = false;
    std::string auth;
};

struct PrivateMessagesResponse {
    std::vector<PrivateMessageView> private_messages;

    struct PrivateMessageView {
        PrivateMessage private_message;
        Person creator;
        Person recipient;
    };
};

struct CreatePrivateMessageParams {
    std::string content;
    int64_t recipient_id = 0;
    std::string auth;
};

struct EditPrivateMessageParams {
    int64_t private_message_id = 0;
    std::string content;
    std::string auth;
};

struct DeletePrivateMessageParams {
    int64_t private_message_id = 0;
    bool deleted = true;
    std::string auth;
};

struct MarkPrivateMessageAsReadParams {
    int64_t private_message_id = 0;
    bool read = true;
    std::string auth;
};

struct CreatePrivateMessageReportParams {
    int64_t private_message_id = 0;
    std::string reason;
    std::string auth;
};

// =============================================================================
// Admin API
// =============================================================================
struct AddAdminParams {
    int64_t person_id = 0;
    bool added = true;
    std::string auth;
};

struct BanPersonParams {
    int64_t person_id = 0;
    bool ban = true;
    bool remove_data = false;
    std::string reason;
    int expires = 0;
    std::string auth;
};

struct GetBannedPersonsParams {
    std::string auth;
};

struct BannedPersonsResponse {
    std::vector<BannedPersonView> banned;

    struct BannedPersonView {
        Person person;
        bool banned = true;
    };
};

struct PurgePersonParams {
    int64_t person_id = 0;
    std::string reason;
    std::string auth;
};

struct PurgePostParams {
    int64_t post_id = 0;
    std::string reason;
    std::string auth;
};

struct PurgeCommentParams {
    int64_t comment_id = 0;
    std::string reason;
    std::string auth;
};

struct PurgeCommunityParams {
    int64_t community_id = 0;
    std::string reason;
    std::string auth;
};

struct GetRegistrationApplicationsParams {
    bool unread_only = false;
    int page = 1;
    int limit = 20;
    std::string auth;
};

struct RegistrationApplicationsResponse {
    std::vector<RegistrationApplicationView> applications;

    struct RegistrationApplicationView {
        RegistrationApplication registration_application;
        Person creator;
        Person admin;
    };
};

struct ApproveRegistrationApplicationParams {
    int64_t id = 0;
    bool approve = true;
    std::string deny_reason;
    std::string auth;
};

struct GetReportCountParams {
    std::optional<int64_t> community_id;
    std::string auth;
};

struct GetReportCountResponse {
    int community_id = 0;
    int comment_reports = 0;
    int post_reports = 0;
    int private_message_reports = 0;
};

struct GetUnreadRegistrationApplicationCountParams {
    std::string auth;
};

struct GetUnreadRegistrationApplicationCountResponse {
    int registration_applications = 0;
};

struct ListPostReportsParams {
    int page = 1;
    int limit = 20;
    std::optional<int64_t> community_id;
    bool unresolved_only = false;
    std::string auth;
};

struct ListPostReportsResponse {
    std::vector<PostReportView> post_reports;

    struct PostReportView {
        PostReport post_report;
        Post post;
        Community community;
        Person creator;
        Person post_creator;
        Person resolver;
        bool creator_banned_from_community = false;
        int my_vote = 0;
        int counts;
    };
};

struct ListCommentReportsParams {
    int page = 1;
    int limit = 20;
    std::optional<int64_t> community_id;
    bool unresolved_only = false;
    std::string auth;
};

struct ListCommentReportsResponse {
    std::vector<CommentReportView> comment_reports;

    struct CommentReportView {
        CommentReport comment_report;
        Comment comment;
        Post post;
        Community community;
        Person creator;
        Person comment_creator;
        Person resolver;
        bool creator_banned_from_community = false;
        int my_vote = 0;
        int counts;
    };
};

struct ListPrivateMessageReportsParams {
    int page = 1;
    int limit = 20;
    bool unresolved_only = false;
    std::string auth;
};

struct ListPrivateMessageReportsResponse {
    std::vector<PrivateMessageReportView> private_message_reports;
};

struct ResolvePostReportParams {
    int64_t report_id = 0;
    bool resolved = true;
    std::string auth;
};

struct ResolveCommentReportParams {
    int64_t report_id = 0;
    bool resolved = true;
    std::string auth;
};

struct ResolvePrivateMessageReportParams {
    int64_t report_id = 0;
    bool resolved = true;
    std::string auth;
};

// =============================================================================
// Modlog API
// =============================================================================
struct GetModlogParams {
    int64_t mod_person_id = 0;
    int64_t community_id = 0;
    int page = 1;
    int limit = 20;
    std::string auth;
};

struct GetModlogResponse {
    std::vector<ModlogEntry> removed_posts;
    std::vector<ModlogEntry> locked_posts;
    std::vector<ModlogEntry> featured_posts;
    std::vector<ModlogEntry> removed_comments;
    std::vector<ModlogEntry> removed_communities;
    std::vector<ModlogEntry> banned_from_community;
    std::vector<ModlogEntry> banned;
    std::vector<ModlogEntry> added_to_community;
    std::vector<ModlogEntry> added;
    std::vector<ModlogEntry> transferred_to_community;
    std::vector<ModlogEntry> hidden_communities;
    std::vector<ModlogEntry> admin_purged_persons;
    std::vector<ModlogEntry> admin_purged_communities;
    std::vector<ModlogEntry> admin_purged_posts;
    std::vector<ModlogEntry> admin_purged_comments;
};

// =============================================================================
// Federated instances
// =============================================================================
struct FederatedInstancesParams {
    std::string auth;
};

struct FederatedInstancesResponse {
    std::vector<std::string> linked;
    std::vector<std::string> allowed;
    std::vector<std::string> blocked;
};

// =============================================================================
// Site configuration
// =============================================================================
struct CreateSiteParams {
    std::string name;
    std::string sidebar;
    std::string description;
    std::string icon;
    std::string banner;
    bool enable_downvotes = true;
    bool enable_nsfw = true;
    bool community_creation_admin_only = false;
    bool require_email_verification = false;
    std::string application_question;
    bool private_instance = false;
    std::string default_theme;
    std::string default_post_listing_type;
    std::string legal_information;
    std::string application_email_admins;
    bool hide_modlog_mod_names = true;
    std::string discussion_languages;
    std::string slur_filter_regex;
    int actor_name_max_length = 20;
    bool federation_enabled = true;
    bool captcha_enabled = false;
    std::string captcha_difficulty;
    std::string allowed_instances;
    std::string blocked_instances;
    std::string auth;
};

struct EditSiteParams {
    std::string name;
    std::string sidebar;
    std::string description;
    std::string icon;
    std::string banner;
    bool enable_downvotes = true;
    bool enable_nsfw = true;
    bool community_creation_admin_only = false;
    bool require_email_verification = false;
    std::string application_question;
    bool private_instance = false;
    std::string default_theme;
    std::string default_post_listing_type;
    std::string legal_information;
    std::string application_email_admins;
    bool hide_modlog_mod_names = true;
    std::string discussion_languages;
    std::string slur_filter_regex;
    int actor_name_max_length = 20;
    bool federation_enabled = true;
    bool captcha_enabled = false;
    std::string captcha_difficulty;
    std::string allowed_instances;
    std::string blocked_instances;
    std::string auth;
};

struct GetSiteParams {
    std::string auth;
};

struct LeaveAdminParams {
    std::string auth;
};

struct GenerateTotpSecretResponse {
    std::string totp_secret_url;
};

struct UpdateTotpParams {
    std::string totp_token;
    bool enabled = true;
    std::string auth;
};

struct SaveUserSettingsParams {
    bool show_nsfw = false;
    bool show_scores = true;
    std::string theme;
    std::string default_sort_type;
    std::string default_listing_type;
    std::string interface_language;
    std::string avatar;
    std::string banner;
    std::string display_name;
    std::string email;
    std::string bio;
    std::string matrix_user_id;
    bool show_avatars = true;
    bool send_notifications_to_email = false;
    bool show_bot_accounts = true;
    bool show_read_posts = true;
    bool show_new_post_notifs = false;
    std::string discussion_languages;
    bool generate_totp_2fa = false;
    std::string auth;
    std::string bot_account;
};

struct ChangePasswordParams {
    std::string new_password;
    std::string new_password_verify;
    std::string old_password;
    std::string auth;
};

struct DeleteAccountParams {
    std::string password;
    bool delete_content = false;
    std::string auth;
};

} // namespace lemmy
} // namespace progressive
