// progressive-server: DeltaChat full message parsing, formatting, and rich text
#include <string> <vector> <unordered_map> <memory> <ctime> <algorithm> <sstream> <mutex> <functional> <regex>
namespace progressive { namespace deltachat {

struct MessageFormatter {
    static std::string format_plain(const std::string& text) { std::string r; for(char c:text) r+=c; return r; }
    static std::string plain_to_html(const std::string& text) { return "<html><body><pre>"+escape_html(text)+"</pre></body></html>"; }
    static std::string html_to_plain(const std::string& html) { std::string r=html; auto strip=[](std::string& s,const std::string& t,const std::string& e){size_t p;while((p=s.find(t))!=std::string::npos){size_t q=s.find(e,p);if(q!=std::string::npos)s.erase(p,q-p+e.length());else break;} }; strip(r,"<style","</style>"); strip(r,"<script","</script>"); strip(r,"<!--","-->"); for(size_t i=0;i<r.size();i++)if(r[i]=='<'){while(i<r.size()&&r[i]!='>')i++; if(i<r.size())r[i]=' ';} return r; }
    static std::string escape_html(const std::string& s) { std::string r; for(char c:s){switch(c){case'&':r+="&amp;";break;case'<':r+="&lt;";break;case'>':r+="&gt;";break;case'"':r+="&quot;";break;default:r+=c;}} return r; }
    static std::string format_quote(const std::string& text,const std::string& author,const std::string& date) { std::string r="> "; for(char c:text){r+=c; if(c=='\n')r+="> ";} return author+" - "+date+"\n"+r; }
    static std::string detect_markdown(const std::string& text) { if(text.find("**")!=std::string::npos||text.find("*")!=std::string::npos||text.find("`")!=std::string::npos)return "text/markdown"; return "text/plain"; }
    static std::string add_footer(const std::string& text,const std::string& footer) { return text+"\n--\n"+footer; }
    static std::string truncate(const std::string& text,size_t max_len=500) { if(text.size()<=max_len)return text; return text.substr(0,max_len-3)+"..."; }
    static std::string format_chat_summary(const std::string& name,int unread,const std::string& last_msg,time_t ts) { char buf[256]; snprintf(buf,sizeof(buf),"%s (%d): %s [%ld]",name.c_str(),unread,truncate(last_msg,50).c_str(),(long)ts); return buf; }
};

struct MessageParser {
    struct ParsedMsg { std::string text; std::string html; std::string subject; std::string quote_text; std::string quote_author; std::string footer; bool has_quote; bool has_footer; time_t date; };
    static ParsedMsg parse(const std::string& raw) { ParsedMsg m; m.text=raw; m.has_quote=false; m.has_footer=false; m.date=std::time(nullptr); size_t sig=raw.rfind("\n--\n"); if(sig!=std::string::npos){m.footer=raw.substr(sig+4); m.text=raw.substr(0,sig); m.has_footer=true;} size_t quote_end=std::string::npos; for(size_t i=0;i<m.text.size();i++){if(m.text[i]=='\n'&&i+1<m.text.size()&&m.text[i+1]=='>'){if(quote_end==std::string::npos)quote_end=i;} else if(m.text[i]!='>'&&m.text[i]!=' '&&quote_end!=std::string::npos)quote_end=std::string::npos;} if(quote_end!=std::string::npos){m.quote_text=m.text.substr(quote_end); m.text=m.text.substr(0,quote_end); m.has_quote=true;} return m; }
};

struct ChatFormatter {
    static std::string format_group_name(const std::vector<std::string>& members) { if(members.empty())return "Empty Group"; std::string r; for(size_t i=0;i<std::min(members.size(),(size_t)3);i++){if(i)r+=", ";r+=members[i];} if(members.size()>3)r+=" +"+std::to_string(members.size()-3); return r; }
    static std::string format_email_preview(const std::string& from,const std::string& subject,const std::string& body,size_t max_len=100) { return from+": "+subject+" - "+MessageFormatter::truncate(body,max_len); }
    static std::string format_date(time_t t) { char buf[64]; strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M",localtime(&t)); return buf; }
    static std::string format_file_size(int64_t bytes) { if(bytes<1024)return std::to_string(bytes)+" B"; if(bytes<1048576)return std::to_string(bytes/1024)+" KB"; return std::to_string(bytes/1048576)+" MB"; }
    static std::string format_ephemeral_info(int timer_secs) { if(timer_secs<=0)return ""; if(timer_secs<60)return std::to_string(timer_secs)+"s"; if(timer_secs<3600)return std::to_string(timer_secs/60)+"m"; return std::to_string(timer_secs/3600)+"h"; }
    static std::string format_bot_indicator(bool is_bot) { return is_bot?"[BOT] ":""; }
    static std::string format_verified_indicator(bool verified) { return verified?"[VERIFIED] ":""; }
};

struct ChatColorAssigner {
    static constexpr const char* COLORS[] = {"#FF0000","#00FF00","#0000FF","#FFFF00","#FF00FF","#00FFFF","#FF8800","#8800FF","#0088FF","#FF0088","#88FF00","#00FF88","#888888","#FF4444","#44FF44","#4444FF"};
    static std::string assign(int64_t chat_id) { return COLORS[std::abs(chat_id)%16]; }
};

struct ChatSearchEngine {
    std::vector<int64_t> search(const std::string& query) { return {}; }
    std::vector<int64_t> search_chat(int64_t chat_id,const std::string& query) { return {}; }
};

struct MessageDraftManager {
    std::unordered_map<int64_t,std::string> drafts_;
    void save(int64_t chat_id,const std::string& text) { drafts_[chat_id]=text; }
    std::string get(int64_t chat_id) { auto it=drafts_.find(chat_id);return it!=drafts_.end()?it->second:""; }
    void clear(int64_t chat_id) { drafts_.erase(chat_id); }
    bool has(int64_t chat_id) { return drafts_.count(chat_id); }
    std::vector<int64_t> chats_with_drafts() { std::vector<int64_t> r; for(auto&[k,_]:drafts_)r.push_back(k); return r; }
};

struct AttachmentHandler {
    std::string get_mime_type(const std::string& filename) { size_t d=filename.rfind('.'); if(d==std::string::npos)return"application/octet-stream"; std::string ext=filename.substr(d+1); if(ext=="jpg"||ext=="jpeg")return"image/jpeg"; if(ext=="png")return"image/png"; if(ext=="gif")return"image/gif"; if(ext=="webp")return"image/webp"; if(ext=="mp4")return"video/mp4"; if(ext=="mp3")return"audio/mpeg"; if(ext=="ogg")return"audio/ogg"; if(ext=="pdf")return"application/pdf"; return"application/octet-stream"; }
    bool is_image(const std::string& mime) { return mime.find("image/")==0; }
    bool is_video(const std::string& mime) { return mime.find("video/")==0; }
    bool is_audio(const std::string& mime) { return mime.find("audio/")==0; }
};

struct SystemMessageGenerator {
    static std::string member_added(const std::string& name) { return "Member "+name+" added."; }
    static std::string member_removed(const std::string& name) { return "Member "+name+" removed."; }
    static std::string group_name_changed(const std::string& old_n,const std::string& new_n) { return "Group name changed from \""+old_n+"\" to \""+new_n+"\"."; }
    static std::string group_image_changed() { return "Group image changed."; }
    static std::string group_image_deleted() { return "Group image deleted."; }
    static std::string chat_protection_enabled() { return "Chat protection enabled."; }
    static std::string chat_protection_disabled() { return "Chat protection disabled."; }
    static std::string ephemeral_timer_changed(int secs) { return "Disappearing messages set to "+ChatFormatter::format_ephemeral_info(secs)+"."; }
    static std::string ephemeral_timer_disabled() { return "Disappearing messages disabled."; }
    static std::string location_enabled() { return "Location streaming enabled."; }
    static std::string location_disabled() { return "Location streaming disabled."; }
    static std::string videochat_invitation(const std::string& url) { return "Video chat invitation: "+url; }
    static std::string webxdc_instance(const std::string& name) { return "App \""+name+"\" started."; }
    static std::string message_deleted() { return "This message was deleted."; }
    static std::string chat_created() { return "Chat created."; }
};

} }
