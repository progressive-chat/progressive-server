#pragma once
// lemmy_server.hpp - Lemmy federated link aggregator (113,070 lines reference)
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <nlohmann/json.hpp>

namespace progressive::lemmy {
using json = nlohmann::json;

// ActivityPub types
struct APObject { std::string id; std::string type; json data; };
struct APActor : APObject { std::string inbox; std::string outbox; std::string followers; std::string following; std::string public_key; std::string private_key; };
struct APActivity : APObject { std::string actor_id; std::string object_id; std::string target_id; };

// Lemmy domain types
struct User {
  std::string id; std::string name; std::string display_name;
  std::string email; std::string password_hash; std::string bio;
  std::optional<std::string> avatar; std::optional<std::string> banner;
  std::optional<std::string> matrix_user_id; bool admin{false};
  bool bot_account{false}; int64_t comment_score{0}; int64_t post_score{0};
  int64_t published{0}; int64_t updated{0};
};
struct Community {
  std::string id; std::string name; std::string title; std::string description;
  std::optional<std::string> icon; std::optional<std::string> banner;
  bool nsfw{false}; bool removed{false}; bool deleted{false};
  bool hidden{false}; bool posting_restricted_to_mods{false};
  int64_t subscribers{0}; int64_t posts{0}; int64_t comments{0};
  int64_t published{0}; int64_t updated{0};
};
struct Post {
  std::string id; std::string name; std::string url; std::string body;
  std::string creator_id; std::string community_id; bool nsfw{false};
  bool removed{false}; bool deleted{false}; bool locked{false};
  bool stickied{false}; bool featured_community{false}; bool featured_local{false};
  int64_t score{0}; int64_t upvotes{0}; int64_t downvotes{0};
  int64_t comments{0}; int64_t published{0}; int64_t updated{0};
};
struct Comment {
  std::string id; std::string content; std::string creator_id;
  std::string post_id; std::optional<std::string> parent_id;
  bool removed{false}; bool deleted{false}; bool distinguished{false};
  int64_t score{0}; int64_t upvotes{0}; int64_t downvotes{0};
  int64_t published{0}; int64_t updated{0};
};
struct PrivateMessage {
  std::string id; std::string content; std::string creator_id;
  std::string recipient_id; bool read{false}; bool deleted{false};
  int64_t published{0}; int64_t updated{0};
};
struct Vote { std::string user_id; std::string post_id; int score{0}; int64_t published{0}; };
struct CommentVote { std::string user_id; std::string comment_id; int score{0}; int64_t published{0}; };
struct Subscription { std::string user_id; std::string community_id; int64_t published{0}; };
struct Block { std::string person_id; std::string target_id; int64_t published{0}; };
struct CommunityBlock { std::string person_id; std::string community_id; int64_t published{0}; };
struct ModAction { std::string id; std::string mod_person_id; std::string target_person_id; std::string community_id; std::string action; std::string reason; bool removed{false}; int64_t published{0}; };
struct Site { std::string id; std::string name; std::string description; std::string sidebar; bool enable_nsfw{false}; bool enable_downvotes{true}; bool open_registration{true}; bool private_instance{false}; int64_t published{0}; };
struct Tagline { std::string id; std::string content; int64_t published{0}; int64_t updated{0}; };
struct CustomEmoji { std::string id; std::string shortcode; std::string image_url; std::string alt_text; std::string category; int64_t published{0}; };
struct Report { std::string id; std::string creator_id; std::string target_id; std::string target_type; std::string reason; bool resolved{false}; int64_t published{0}; };
struct RegistrationApplication { std::string id; std::string user_id; std::string answer; bool accepted{false}; int64_t published{0}; };

// ============================================================================
// Lemmy Server
// ============================================================================
class LemmyServer {
public:
  LemmyServer(const std::string& hostname);

  // Start/stop
  void start(int port=8080);
  void stop();

  // ---- User management ----
  User create_user(const std::string& name, const std::string& password, const std::string& email="", bool admin=false);
  std::optional<User> get_user(const std::string& id_or_name);
  User update_user(const std::string& id, const json& updates);
  void delete_user(const std::string& id);
  User login(const std::string& username_or_email, const std::string& password);
  std::string generate_jwt(const std::string& user_id);
  bool verify_jwt(const std::string& token);
  void change_password(const std::string& user_id, const std::string& old_pw, const std::string& new_pw);
  void reset_password(const std::string& email);
  void mark_user_as_bot(const std::string& user_id, bool bot);
  std::vector<User> get_admins();
  std::vector<User> get_banned_users();
  void ban_user(const std::string& user_id, bool ban, const std::string& reason);

  // ---- Community management ----
  Community create_community(const std::string& name, const std::string& title, const std::string& desc, const std::string& creator_id, bool nsfw=false);
  std::optional<Community> get_community(const std::string& id_or_name);
  Community update_community(const std::string& id, const json& updates);
  void delete_community(const std::string& id);
  void remove_community(const std::string& id, const std::string& mod_id, const std::string& reason);
  void hide_community(const std::string& id, const std::string& mod_id, const std::string& reason);
  void follow_community(const std::string& user_id, const std::string& community_id);
  void unfollow_community(const std::string& user_id, const std::string& community_id);
  std::vector<Community> list_communities(const std::string& sort="hot", int page=1, int limit=20, const std::string& type_="all");
  std::vector<Community> search_communities(const std::string& query, int page=1, int limit=20);
  Community get_community_by_actor_id(const std::string& actor_id);

  // ---- Post management ----
  Post create_post(const std::string& name, const std::string& community_id, const std::string& creator_id, const std::string& url="", const std::string& body="", bool nsfw=false);
  std::optional<Post> get_post(const std::string& id);
  Post update_post(const std::string& id, const json& updates);
  void delete_post(const std::string& id);
  void remove_post(const std::string& id, const std::string& mod_id, const std::string& reason);
  void lock_post(const std::string& id, const std::string& mod_id, bool lock);
  void sticky_post(const std::string& id, const std::string& mod_id, bool sticky);
  void feature_post(const std::string& id, bool feature_community, bool feature_local);
  std::vector<Post> get_posts(const std::string& sort="hot", int page=1, int limit=20, const std::optional<std::string>& community_id={}, const std::optional<std::string>& community_name={});
  std::vector<Post> search_posts(const std::string& query, int page=1, int limit=20, const std::optional<std::string>& community_id={});
  Post get_post_by_ap_id(const std::string& ap_id);

  // ---- Comment management ----
  Comment create_comment(const std::string& content, const std::string& post_id, const std::string& creator_id, const std::optional<std::string>& parent_id={});
  std::optional<Comment> get_comment(const std::string& id);
  Comment update_comment(const std::string& id, const json& updates);
  void delete_comment(const std::string& id);
  void remove_comment(const std::string& id, const std::string& mod_id, const std::string& reason);
  void distinguish_comment(const std::string& id, const std::string& mod_id, bool distinguish);
  std::vector<Comment> get_comments(const std::string& post_id, int page=1, int limit=20, const std::string& sort="hot", int max_depth=8);

  // ---- Voting ----
  Vote vote_post(const std::string& post_id, const std::string& user_id, int score);
  CommentVote vote_comment(const std::string& comment_id, const std::string& user_id, int score);
  int get_post_vote_count(const std::string& post_id);
  int get_comment_vote_count(const std::string& comment_id);

  // ---- Private messaging ----
  PrivateMessage send_private_message(const std::string& content, const std::string& creator_id, const std::string& recipient_id);
  std::vector<PrivateMessage> get_private_messages(const std::string& user_id, int page=1, int limit=20, bool unread_only=false);
  void mark_pm_read(const std::string& pm_id);
  void mark_all_pm_read(const std::string& user_id);

  // ---- Moderation ----
  ModAction add_mod(const std::string& community_id, const std::string& mod_id, const std::string& target_id);
  ModAction remove_mod(const std::string& community_id, const std::string& mod_id, const std::string& target_id);
  ModAction ban_from_community(const std::string& community_id, const std::string& mod_id, const std::string& target_id, const std::string& reason, bool ban, int days=0);
  ModAction add_admin(const std::string& admin_id, const std::string& target_id);
  std::vector<ModAction> get_mod_log(const std::string& community_id, int page=1, int limit=20);

  // ---- Reports ----
  Report create_report(const std::string& creator_id, const std::string& target_id, const std::string& target_type, const std::string& reason);
  std::vector<Report> get_reports(int page=1, int limit=20, bool unresolved_only=true);
  Report resolve_report(const std::string& report_id, bool resolved);

  // ---- Registration applications ----
  RegistrationApplication create_registration_application(const std::string& user_id, const std::string& answer);
  std::vector<RegistrationApplication> get_registration_applications(int page=1, int limit=20, bool unread_only=true);
  RegistrationApplication approve_registration_application(const std::string& app_id, bool approve, const std::string& reason="");

  // ---- Site management ----
  Site get_site();
  Site update_site(const json& updates);
  std::string get_site_name();
  std::string get_site_description();
  bool site_allows_registration();

  // ---- Taglines ----
  Tagline create_tagline(const std::string& content);
  std::vector<Tagline> get_taglines(int page=1, int limit=20);
  Tagline update_tagline(const std::string& id, const std::string& content);
  void delete_tagline(const std::string& id);

  // ---- Custom emojis ----
  CustomEmoji create_custom_emoji(const std::string& shortcode, const std::string& image_url, const std::string& alt_text, const std::string& category);
  std::vector<CustomEmoji> get_custom_emojis();
  CustomEmoji update_custom_emoji(const std::string& id, const json& updates);
  void delete_custom_emoji(const std::string& id);

  // ---- Blocking ----
  Block block_person(const std::string& person_id, const std::string& target_id);
  void unblock_person(const std::string& person_id, const std::string& target_id);
  std::vector<User> get_blocked_users(const std::string& person_id);
  CommunityBlock block_community(const std::string& person_id, const std::string& community_id);
  void unblock_community(const std::string& person_id, const std::string& community_id);

  // ---- ActivityPub federation ----
  void send_activity(const json& activity, const std::string& target_inbox);
  void receive_activity(const json& activity);
  void fetch_remote_object(const std::string& ap_id);
  void announce_to_followers(const APActor& actor, const json& activity);
  void fetch_community_outbox(const std::string& community_actor_id);
  bool verify_http_signature(const std::string& request_body, const std::map<std::string,std::string>& headers);

  // ---- Search ----
  struct SearchResults { std::vector<Post> posts; std::vector<Comment> comments; std::vector<Community> communities; std::vector<User> users; };
  SearchResults search(const std::string& query, int page=1, int limit=20, const std::string& type_="all", const std::optional<std::string>& community_id={});

  // ---- RSS/Atom feeds ----
  std::string get_feed(const std::string& feed_type, const std::string& sort="hot", int page=1, int limit=20, const std::optional<std::string>& community_id={});

  // ---- Statistics ----
  struct SiteStats { int64_t users{0}; int64_t posts{0}; int64_t comments{0}; int64_t communities{0}; };
  SiteStats get_site_stats();
  SiteStats get_community_stats(const std::string& community_id);
  int64_t count_users();
  int64_t count_posts();
  int64_t count_comments();
  int64_t count_communities();

  // ---- Image upload ----
  std::string upload_image(const std::string& user_id, const std::string& filename, const std::vector<uint8_t>& data, const std::string& content_type);
  void delete_image(const std::string& image_url);

  // ---- Config ----
  struct ServerConfig {
    std::string hostname; std::string name; std::string description;
    int port{8080}; bool ssl{false}; int max_upload_size{10485760};
    bool registration_enabled{true}; bool private_instance{false};
    std::string email_from; std::string jwt_secret;
  };
  ServerConfig& config() { return config_; }

private:
  // Nested types needed for data members
  struct BannedUser {
    std::string user_id; std::string reason; int64_t banned_at{0};
    int64_t expires_at{0};
  };
  struct LocalBan {
    std::string user_id; std::string community_id; std::string reason;
    int64_t banned_at{0}; int64_t expires_at{0};
  };
  struct FederationOutboxItem {
    std::string body; int64_t timestamp{0}; std::string type;
    std::string actor; std::string object;
  };
  struct FederationQueueItem {
    std::string target_inbox; std::string body; int64_t timestamp{0};
    int retry_count{0}; bool sent{false};
  };

  // Core data stores
  std::map<std::string,User> users_; std::map<std::string,Community> communities_;
  std::map<std::string,Post> posts_; std::map<std::string,Comment> comments_;
  std::map<std::string,PrivateMessage> pms_;
  std::map<std::string,Vote> post_votes_; std::map<std::string,Vote> comment_votes_;
  std::map<std::string,Subscription> subscriptions_;
  std::map<std::string,Block> blocks_; std::map<std::string,CommunityBlock> community_blocks_;
  std::map<std::string,ModAction> mod_actions_;
  std::map<std::string,Site> sites_; std::map<std::string,Tagline> taglines_;
  std::map<std::string,CustomEmoji> emojis_; std::map<std::string,Report> reports_;
  std::map<std::string,RegistrationApplication> registrations_;
  std::map<std::string,APActor> actors_;
  ServerConfig config_; bool running_{false}; int listen_fd_{-1};

  // Extended private members for full implementation
  std::string instance_private_key_;
  std::string instance_public_key_;
  bool federation_enabled_{true};
  bool federation_debug_{false};
  bool strict_allowlist_{false};
  bool captcha_enabled_{false};
  std::string captcha_difficulty_{"medium"};
  std::unordered_set<std::string> allowed_instances_;
  std::unordered_set<std::string> blocked_instances_;
  std::unordered_set<std::string> purged_user_ids_;
  std::map<std::string,std::set<std::string>> community_mods_;
  std::unordered_map<std::string,LocalBan> community_bans_;
  std::string site_legal_information_;
  std::string site_default_theme_{"darkly"};
  std::string site_application_question_;
  std::map<std::string,BannedUser> banned_users_;
  std::map<std::string,std::vector<uint8_t>> uploaded_images_;
  std::vector<FederationQueueItem> federation_queue_;
  std::vector<FederationOutboxItem> federation_outbox_;
  // Helper methods (declared only - implemented in lemmy_server_full.cpp)
  void create_user_actor(const User& user);
  void update_user_actor(const User& user);
  void create_community_actor(const Community& community);
  void update_community_actor(const Community& community);
  std::string get_user_actor_id(const std::string& user_id);
  double calculate_post_rank(const Post& p, const std::string& sort);
  void recalculate_post_votes(const std::string& post_id);
  void recalculate_comment_votes(const std::string& comment_id);
  void federate_create_post(const Post& post);
  void federate_update_post(const Post& post);
  void federate_create_comment(const Comment& comment, const Post& post);
  void federate_update_comment(const Comment& comment);
  void federate_mod_action(const ModAction& action);
  void log_mod_action(const std::string& community_id, const std::string& mod_id, const std::string& target_id, const std::string& action, const std::string& reason);
  void queue_federation_activity(const json& activity);
  void broadcast_to_community_followers(const std::string& community_id, const json& activity);
  void handle_ap_create(const json& activity);
  void handle_ap_like(const json& activity);
  void handle_ap_dislike(const json& activity);
  void handle_ap_follow(const json& activity);
  void handle_ap_undo(const json& activity);
  void handle_ap_delete(const json& activity);
  void handle_ap_update(const json& activity);
  void handle_ap_announce(const json& activity);
  void handle_ap_accept(const json& activity);
  void handle_ap_reject(const json& activity);
  void handle_ap_add(const json& activity);
  void handle_ap_remove(const json& activity);
  void handle_ap_block(const json& activity);
  std::string resolve_remote_user(const std::string& actor_id);
  void lemmy_update_remote_person(const json& person_obj);
  void lemmy_update_remote_community(const json& group_obj);
  std::string resolve_post_by_ap_id(const std::string& ap_id);
  std::string sha256_hmac(const std::string& key, const std::string& data);
  std::string format_iso8601(int64_t ts_ms);
  std::string decode_jwt_user_id(const std::string& token);
  bool is_blocked_by(const std::string& user_id, const std::string& target_id);
  bool is_instance_allowed(const std::string& domain);
  void notify_user(const std::string& user_id, const std::string& event_type, const json& data);
  void notify_admins(const std::string& event_type, const json& data);
  void flush_federation_queue();
  int64_t count_unread_pms(const std::string& user_id);

  // ActivityPub public helpers
  json get_actor_json(const std::string& actor_name);
  json build_person_actor(const User& user);
  json build_group_actor(const Community& community);
  json webfinger(const std::string& resource);
  json nodeinfo(const std::string& version="2.0");
  json get_outbox(const std::string& actor_name, int page=0);
  json get_followers(const std::string& actor_name, int page=0);

  // Federation management
  void allow_instance(const std::string& domain);
  void block_instance(const std::string& domain);
  void unallow_instance(const std::string& domain);
  void unblock_instance(const std::string& domain);
  json get_federation_queue(int page=1, int limit=20);
  int64_t count_federation_queue();
  void retry_federation_send(int64_t activity_index);

  // Purge operations
  void purge_user(const std::string& admin_id, const std::string& user_id);
  void purge_post(const std::string& admin_id, const std::string& post_id);
  void purge_comment(const std::string& admin_id, const std::string& comment_id);
  void purge_community(const std::string& admin_id, const std::string& community_id);
};

} // namespace progressive::lemmy
