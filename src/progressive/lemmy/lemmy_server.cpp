// lemmy_server.cpp - Lemmy server implementation
#include "lemmy_server.hpp"
#include <chrono>
#include <random>
#include <sstream>
namespace progressive::lemmy {
using json = nlohmann::json;
static int64_t nms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
static std::string gen_id(const std::string& p){static std::atomic<int64_t> c{1};return p+std::to_string(nms())+"-"+std::to_string(c.fetch_add(1));}

LemmyServer::LemmyServer(const std::string& host){config_.hostname=host;config_.name=host;}
void LemmyServer::start(int p){config_.port=p;running_=true;}
void LemmyServer::stop(){running_=false;}

User LemmyServer::create_user(const std::string& name,const std::string& pw,const std::string& email,bool admin){
  User u;u.id=gen_id("usr");u.name=name;u.display_name=name;u.email=email;u.password_hash=pw;u.admin=admin;u.published=nms();u.updated=nms();
  users_[u.id]=u;return u;
}
std::optional<User> LemmyServer::get_user(const std::string& id){
  if(users_.count(id))return users_[id];
  for(auto&[k,u]:users_)if(u.name==id)return u;
  return std::nullopt;
}
User LemmyServer::update_user(const std::string& id,const json& up){auto it=users_.find(id);if(it!=users_.end()){if(up.contains("display_name"))it->second.display_name=up["display_name"];it->second.updated=nms();return it->second;}throw std::runtime_error("User not found");}
void LemmyServer::delete_user(const std::string& id){users_.erase(id);}
User LemmyServer::login(const std::string& ue,const std::string& pw){for(auto&[k,u]:users_)if((u.name==ue||u.email==ue)&&u.password_hash==pw)return u;throw std::runtime_error("Invalid credentials");}
std::string LemmyServer::generate_jwt(const std::string& uid){return"jwt-"+uid+"-"+std::to_string(nms());}
bool LemmyServer::verify_jwt(const std::string& tok){return tok.find("jwt-")==0;}
void LemmyServer::change_password(const std::string& uid,const std::string& op,const std::string& np){auto it=users_.find(uid);if(it!=users_.end()){if(it->second.password_hash==op)it->second.password_hash=np;}}
void LemmyServer::reset_password(const std::string& email){}
void LemmyServer::mark_user_as_bot(const std::string& uid,bool b){auto it=users_.find(uid);if(it!=users_.end())it->second.bot_account=b;}
std::vector<User> LemmyServer::get_admins(){std::vector<User> r;for(auto&[k,u]:users_)if(u.admin)r.push_back(u);return r;}
std::vector<User> LemmyServer::get_banned_users(){return{};}
void LemmyServer::ban_user(const std::string& uid,bool b,const std::string& reason){}

Community LemmyServer::create_community(const std::string& name,const std::string& title,const std::string& desc,const std::string& cid,bool nsfw){
  Community c;c.id=gen_id("com");c.name=name;c.title=title;c.description=desc;c.nsfw=nsfw;c.published=nms();c.updated=nms();communities_[c.id]=c;return c;
}
std::optional<Community> LemmyServer::get_community(const std::string& id){if(communities_.count(id))return communities_[id];for(auto&[k,c]:communities_)if(c.name==id)return c;return std::nullopt;}
Community LemmyServer::update_community(const std::string& id,const json& up){auto it=communities_.find(id);if(it!=communities_.end()){if(up.contains("title"))it->second.title=up["title"];it->second.updated=nms();return it->second;}throw std::runtime_error("Community not found");}
void LemmyServer::delete_community(const std::string& id){communities_.erase(id);}
void LemmyServer::remove_community(const std::string& id,const std::string& mid,const std::string& reason){delete_community(id);}
void LemmyServer::hide_community(const std::string& id,const std::string& mid,const std::string& reason){auto it=communities_.find(id);if(it!=communities_.end())it->second.hidden=true;}
void LemmyServer::follow_community(const std::string& uid,const std::string& cid){subscriptions_[uid+":"+cid]={uid,cid,nms()};}
void LemmyServer::unfollow_community(const std::string& uid,const std::string& cid){subscriptions_.erase(uid+":"+cid);}
std::vector<Community> LemmyServer::list_communities(const std::string& sort,int page,int limit,const std::string& type){std::vector<Community> r;for(auto&[k,c]:communities_)r.push_back(c);return r;}
std::vector<Community> LemmyServer::search_communities(const std::string& q,int page,int limit){std::vector<Community> r;for(auto&[k,c]:communities_)if(c.name.find(q)!=std::string::npos||c.title.find(q)!=std::string::npos)r.push_back(c);return r;}
Community LemmyServer::get_community_by_actor_id(const std::string& aid){for(auto&[k,c]:communities_)return c;return Community{};}

Post LemmyServer::create_post(const std::string& name,const std::string& cid,const std::string& uid,const std::string& url,const std::string& body,bool nsfw){
  Post p;p.id=gen_id("pst");p.name=name;p.community_id=cid;p.creator_id=uid;p.url=url;p.body=body;p.nsfw=nsfw;p.published=nms();p.updated=nms();posts_[p.id]=p;return p;
}
std::optional<Post> LemmyServer::get_post(const std::string& id){auto it=posts_.find(id);return it!=posts_.end()?std::optional<Post>(it->second):std::nullopt;}
Post LemmyServer::update_post(const std::string& id,const json& up){auto it=posts_.find(id);if(it!=posts_.end()){if(up.contains("body"))it->second.body=up["body"];it->second.updated=nms();return it->second;}throw std::runtime_error("Post not found");}
void LemmyServer::delete_post(const std::string& id){posts_.erase(id);}
void LemmyServer::remove_post(const std::string& id,const std::string& mid,const std::string& reason){auto it=posts_.find(id);if(it!=posts_.end())it->second.removed=true;}
void LemmyServer::lock_post(const std::string& id,const std::string& mid,bool l){auto it=posts_.find(id);if(it!=posts_.end())it->second.locked=l;}
void LemmyServer::sticky_post(const std::string& id,const std::string& mid,bool s){auto it=posts_.find(id);if(it!=posts_.end())it->second.stickied=s;}
void LemmyServer::feature_post(const std::string& id,bool fc,bool fl){auto it=posts_.find(id);if(it!=posts_.end()){it->second.featured_community=fc;it->second.featured_local=fl;}}
std::vector<Post> LemmyServer::get_posts(const std::string& sort,int page,int limit,const std::optional<std::string>& cid,const std::optional<std::string>& cn){
  std::vector<Post> r;for(auto&[k,p]:posts_){if(cid&&p.community_id!=*cid)continue;r.push_back(p);}return r;
}
std::vector<Post> LemmyServer::search_posts(const std::string& q,int page,int limit,const std::optional<std::string>& cid){std::vector<Post> r;for(auto&[k,p]:posts_){if(p.name.find(q)!=std::string::npos||p.body.find(q)!=std::string::npos)r.push_back(p);}return r;}
Post LemmyServer::get_post_by_ap_id(const std::string& aid){return Post{};}

Comment LemmyServer::create_comment(const std::string& content,const std::string& pid,const std::string& uid,const std::optional<std::string>& parent){
  Comment c;c.id=gen_id("cmt");c.content=content;c.post_id=pid;c.creator_id=uid;c.parent_id=parent;c.published=nms();c.updated=nms();comments_[c.id]=c;return c;
}
std::optional<Comment> LemmyServer::get_comment(const std::string& id){auto it=comments_.find(id);return it!=comments_.end()?std::optional<Comment>(it->second):std::nullopt;}
Comment LemmyServer::update_comment(const std::string& id,const json& up){auto it=comments_.find(id);if(it!=comments_.end()){if(up.contains("content"))it->second.content=up["content"];it->second.updated=nms();return it->second;}throw std::runtime_error("Comment not found");}
void LemmyServer::delete_comment(const std::string& id){comments_.erase(id);}
void LemmyServer::remove_comment(const std::string& id,const std::string& mid,const std::string& reason){auto it=comments_.find(id);if(it!=comments_.end())it->second.removed=true;}
void LemmyServer::distinguish_comment(const std::string& id,const std::string& mid,bool d){auto it=comments_.find(id);if(it!=comments_.end())it->second.distinguished=d;}
std::vector<Comment> LemmyServer::get_comments(const std::string& pid,int page,int limit,const std::string& sort,int md){std::vector<Comment> r;for(auto&[k,c]:comments_){if(c.post_id==pid)r.push_back(c);}return r;}

Vote LemmyServer::vote_post(const std::string& pid,const std::string& uid,int score){Vote v{uid,pid,score,nms()};post_votes_[uid+":"+pid]=v;return v;}
CommentVote LemmyServer::vote_comment(const std::string& cid,const std::string& uid,int score){CommentVote v{uid,cid,score,nms()};comment_votes_[uid+":"+cid]=v;return v;}
int LemmyServer::get_post_vote_count(const std::string& pid){int c=0;for(auto&[k,v]:post_votes_)if(v.post_id==pid)c+=v.score;return c;}
int LemmyServer::get_comment_vote_count(const std::string& cid){int c=0;for(auto&[k,v]:comment_votes_)if(v.comment_id==cid)c+=v.score;return c;}

PrivateMessage LemmyServer::send_private_message(const std::string& content,const std::string& uid,const std::string& rid){
  PrivateMessage p;p.id=gen_id("pm");p.content=content;p.creator_id=uid;p.recipient_id=rid;p.published=nms();pms_[p.id]=p;return p;
}
std::vector<PrivateMessage> LemmyServer::get_private_messages(const std::string& uid,int page,int limit,bool unread){
  std::vector<PrivateMessage> r;for(auto&[k,p]:pms_)if(p.recipient_id==uid&&(!unread||!p.read))r.push_back(p);return r;
}
void LemmyServer::mark_pm_read(const std::string& id){auto it=pms_.find(id);if(it!=pms_.end())it->second.read=true;}
void LemmyServer::mark_all_pm_read(const std::string& uid){for(auto&[k,p]:pms_)if(p.recipient_id==uid)p.read=true;}

ModAction LemmyServer::add_mod(const std::string& cid,const std::string& mid,const std::string& tid){
  ModAction m;m.id=gen_id("mod");m.mod_person_id=mid;m.target_person_id=tid;m.community_id=cid;m.action="add_mod";m.published=nms();mod_actions_[m.id]=m;return m;
}
ModAction LemmyServer::remove_mod(const std::string& cid,const std::string& mid,const std::string& tid){ModAction m;m.id=gen_id("mod");m.action="remove_mod";m.published=nms();return m;}
ModAction LemmyServer::ban_from_community(const std::string& cid,const std::string& mid,const std::string& tid,const std::string& reason,bool ban,int days){ModAction m;m.id=gen_id("mod");m.action=ban?"ban":"unban";m.reason=reason;m.published=nms();return m;}
ModAction LemmyServer::add_admin(const std::string& aid,const std::string& tid){ModAction m;m.id=gen_id("mod");m.action="add_admin";m.published=nms();return m;}
std::vector<ModAction> LemmyServer::get_mod_log(const std::string& cid,int page,int limit){std::vector<ModAction> r;for(auto&[k,m]:mod_actions_)if(m.community_id==cid)r.push_back(m);return r;}

Report LemmyServer::create_report(const std::string& uid,const std::string& tid,const std::string& tt,const std::string& reason){
  Report r;r.id=gen_id("rep");r.creator_id=uid;r.target_id=tid;r.target_type=tt;r.reason=reason;r.published=nms();reports_[r.id]=r;return r;
}
std::vector<Report> LemmyServer::get_reports(int page,int limit,bool unr){std::vector<Report> r;for(auto&[k,rep]:reports_)if(!unr||!rep.resolved)r.push_back(rep);return r;}
Report LemmyServer::resolve_report(const std::string& rid,bool res){auto it=reports_.find(rid);if(it!=reports_.end())it->second.resolved=res;return it->second;}

RegistrationApplication LemmyServer::create_registration_application(const std::string& uid,const std::string& ans){
  RegistrationApplication a;a.id=gen_id("regapp");a.user_id=uid;a.answer=ans;a.published=nms();registrations_[a.id]=a;return a;
}
std::vector<RegistrationApplication> LemmyServer::get_registration_applications(int page,int limit,bool unr){std::vector<RegistrationApplication> r;for(auto&[k,a]:registrations_)if(!unr||!a.accepted)r.push_back(a);return r;}
RegistrationApplication LemmyServer::approve_registration_application(const std::string& aid,bool app,const std::string& reason){auto it=registrations_.find(aid);if(it!=registrations_.end())it->second.accepted=app;return it->second;}

Site LemmyServer::get_site(){Site s;s.id="1";s.name=config_.name;s.description=config_.description;s.open_registration=config_.registration_enabled;s.private_instance=config_.private_instance;return s;}
Site LemmyServer::update_site(const json& up){return get_site();}
std::string LemmyServer::get_site_name(){return config_.name;}
std::string LemmyServer::get_site_description(){return config_.description;}
bool LemmyServer::site_allows_registration(){return config_.registration_enabled;}

Tagline LemmyServer::create_tagline(const std::string& content){Tagline t;t.id=gen_id("tag");t.content=content;t.published=nms();taglines_[t.id]=t;return t;}
std::vector<Tagline> LemmyServer::get_taglines(int page,int limit){std::vector<Tagline> r;for(auto&[k,t]:taglines_)r.push_back(t);return r;}
Tagline LemmyServer::update_tagline(const std::string& id,const std::string& content){auto it=taglines_.find(id);if(it!=taglines_.end())it->second.content=content;return it->second;}
void LemmyServer::delete_tagline(const std::string& id){taglines_.erase(id);}

CustomEmoji LemmyServer::create_custom_emoji(const std::string& sc,const std::string& iu,const std::string& at,const std::string& cat){
  CustomEmoji e;e.id=gen_id("emo");e.shortcode=sc;e.image_url=iu;e.alt_text=at;e.category=cat;e.published=nms();emojis_[e.id]=e;return e;
}
std::vector<CustomEmoji> LemmyServer::get_custom_emojis(){std::vector<CustomEmoji> r;for(auto&[k,e]:emojis_)r.push_back(e);return r;}
CustomEmoji LemmyServer::update_custom_emoji(const std::string& id,const json& up){auto it=emojis_.find(id);if(it!=emojis_.end()){if(up.contains("shortcode"))it->second.shortcode=up["shortcode"];return it->second;}throw std::runtime_error("Emoji not found");}
void LemmyServer::delete_custom_emoji(const std::string& id){emojis_.erase(id);}

Block LemmyServer::block_person(const std::string& pid,const std::string& tid){Block b{pid,tid,nms()};blocks_[pid+":"+tid]=b;return b;}
void LemmyServer::unblock_person(const std::string& pid,const std::string& tid){blocks_.erase(pid+":"+tid);}
std::vector<User> LemmyServer::get_blocked_users(const std::string& pid){std::vector<User> r;return r;}
CommunityBlock LemmyServer::block_community(const std::string& pid,const std::string& cid){CommunityBlock b{pid,cid,nms()};community_blocks_[pid+":"+cid]=b;return b;}
void LemmyServer::unblock_community(const std::string& pid,const std::string& cid){community_blocks_.erase(pid+":"+cid);}

void LemmyServer::send_activity(const json&,const std::string&){}
void LemmyServer::receive_activity(const json&){}
void LemmyServer::fetch_remote_object(const std::string&){}
void LemmyServer::announce_to_followers(const APActor&,const json&){}
void LemmyServer::fetch_community_outbox(const std::string&){}
bool LemmyServer::verify_http_signature(const std::string&,const std::map<std::string,std::string>&){return true;}

LemmyServer::SearchResults LemmyServer::search(const std::string& q,int page,int limit,const std::string& type,const std::optional<std::string>& cid){
  SearchResults sr;sr.posts=search_posts(q,page,limit,cid);sr.comments={};sr.communities=search_communities(q,page,limit);sr.users={};return sr;
}
std::string LemmyServer::get_feed(const std::string& ft,const std::string& sort,int page,int limit,const std::optional<std::string>& cid){return"<rss version='2.0'><channel><title>"+config_.name+"</title></channel></rss>";}
LemmyServer::SiteStats LemmyServer::get_site_stats(){return{count_users(),count_posts(),count_comments(),count_communities()};}
LemmyServer::SiteStats LemmyServer::get_community_stats(const std::string& cid){return{0,0,0,0};}
int64_t LemmyServer::count_users(){return users_.size();}
int64_t LemmyServer::count_posts(){return posts_.size();}
int64_t LemmyServer::count_comments(){return comments_.size();}
int64_t LemmyServer::count_communities(){return communities_.size();}
std::string LemmyServer::upload_image(const std::string&,const std::string&,const std::vector<uint8_t>&,const std::string&){return"/pictrs/image/"+gen_id("img");}
void LemmyServer::delete_image(const std::string&){}

} // namespace
