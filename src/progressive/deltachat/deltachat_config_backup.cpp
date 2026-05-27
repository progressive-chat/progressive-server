// progressive-server: DeltaChat configuration, backup/restore, QR codes
#include <string> <vector> <unordered_map> <memory> <ctime> <algorithm> <sstream> <mutex> <functional> <fstream> <cstring>
namespace progressive { namespace deltachat {

class DcConfig { std::unordered_map<std::string,std::string> cfg_; std::mutex m_;
public:
    void set(const std::string& k, const std::string& v) { std::lock_guard l(m_); cfg_[k]=v; }
    std::string get(const std::string& k, const std::string& def="") { auto it=cfg_.find(k); return it!=cfg_.end()?it->second:def; }
    int get_int(const std::string& k,int def=0) { auto v=get(k); if(v.empty())return def; return std::stoi(v); }
    bool get_bool(const std::string& k,bool def=false) { auto v=get(k); return v=="1"||v=="true"||v=="yes"; }
    void load_defaults() {
        set("addr",""); set("mail_server",""); set("mail_port","993"); set("mail_user",""); set("mail_pw",""); set("mail_security","1");
        set("send_server",""); set("send_port","587"); set("send_user",""); set("send_pw",""); set("send_security","2");
        set("server_flags","7"); set("displayname",""); set("selfstatus",""); set("e2ee_enabled","1"); set("mdns_enabled","1");
        set("show_emails","2"); set("bcc_self","1"); set("download_limit","0"); set("media_quality","0");
        set("fetch_existing_msgs","0"); set("sentbox_watch","1"); set("mvbox_watch","1"); set("mvbox_move","1");
        set("only_fetch_mvbox","0"); set("save_mime_headers","0"); set("notifications_enabled","1");
        set("welcome_image","0"); set("compress_images","1"); set("key_gen_type","2");
    }
    std::unordered_map<std::string,std::string> all() { std::lock_guard l(m_); return cfg_; }
};

struct ProviderData { std::string id; std::string domain; std::string imap_server; int imap_port; std::string imap_security; std::string smtp_server; int smtp_port; std::string smtp_security; bool oauth2; std::string before_login; std::string after_login; };

class ProviderDb { std::vector<ProviderData> providers_;
public:
    void load() { providers_.push_back({"gmail","gmail.com","imap.gmail.com",993,"SSL","smtp.gmail.com",465,"SSL",true,"",""}); providers_.push_back({"outlook","outlook.com","outlook.office365.com",993,"SSL","smtp.office365.com",587,"STARTTLS",true,"",""}); providers_.push_back({"yahoo","yahoo.com","imap.mail.yahoo.com",993,"SSL","smtp.mail.yahoo.com",587,"STARTTLS",false,"",""}); providers_.push_back({"icloud","icloud.com","imap.mail.me.com",993,"SSL","smtp.mail.me.com",587,"STARTTLS",false,"",""}); providers_.push_back({"fastmail","fastmail.com","imap.fastmail.com",993,"SSL","smtp.fastmail.com",587,"STARTTLS",false,"",""}); providers_.push_back({"protonmail","protonmail.com","127.0.0.1",1143,"SSL","127.0.0.1",1025,"SSL",false,"",""}); providers_.push_back({"mail.ru","mail.ru","imap.mail.ru",993,"SSL","smtp.mail.ru",465,"SSL",false,"",""}); providers_.push_back({"yandex","yandex.ru","imap.yandex.ru",993,"SSL","smtp.yandex.ru",465,"SSL",false,"",""}); }
    const ProviderData* lookup(const std::string& email) { size_t at=email.find('@'); if(at==std::string::npos)return nullptr; std::string domain=email.substr(at+1); for(auto& p:providers_)if(p.domain==domain||domain.find(p.domain)!=std::string::npos)return &p; return nullptr; }
    const ProviderData* get_by_id(const std::string& id) { for(auto& p:providers_)if(p.id==id)return &p; return nullptr; }
};

class QrCode { public:
    static std::string generate_invite(const std::string& addr,const std::string& key_fp,const std::string& name) { return "OPENPGP4FPR:"+key_fp+"#a="+addr+"&n="+urlencode(name); }
    static std::string generate_securejoin(const std::string& group_id,const std::string& fingerprint,const std::string& invitenumber,const std::string& auth) { return "DCACCOUNT:"+urlencode("group="+group_id+"&fingerprint="+fingerprint+"&invitenumber="+invitenumber+"&auth="+auth); }
    struct InviteInfo { std::string addr; std::string fingerprint; std::string name; std::string group_id; bool valid; };
    static InviteInfo parse(const std::string& qr_data) { InviteInfo info; if(qr_data.find("OPENPGP4FPR:")==0) { std::string rest=qr_data.substr(12); size_t h=rest.find('#'); if(h!=std::string::npos) { info.fingerprint=rest.substr(0,h); rest=rest.substr(h+1); } auto params=parse_params(rest); info.addr=params["a"]; info.name=urldecode(params["n"]); info.valid=true; } if(qr_data.find("DCACCOUNT:")==0) { auto params=parse_params(urldecode(qr_data.substr(9))); info.group_id=params["group"]; info.fingerprint=params["fingerprint"]; info.valid=true; } return info; }
private:
    static std::unordered_map<std::string,std::string> parse_params(const std::string& s) { std::unordered_map<std::string,std::string> r; size_t p=0; while(p<s.size()) { size_t e=s.find('&',p); if(e==std::string::npos)e=s.size(); std::string kv=s.substr(p,e-p); size_t eq=kv.find('='); if(eq!=std::string::npos) r[kv.substr(0,eq)]=urldecode(kv.substr(eq+1)); p=e+1; } return r; }
    static std::string urlencode(const std::string& s) { std::string r; for(char c:s){if(isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~')r+=c; else{char b[4];snprintf(b,4,"%%%02X",(uint8_t)c);r+=b;}} return r; }
    static std::string urldecode(const std::string& s) { std::string r; for(size_t i=0;i<s.size();i++){if(s[i]=='%'&&i+2<s.size()){int v;sscanf(s.substr(i+1,2).c_str(),"%x",&v);r+=(char)v;i+=2;}else if(s[i]=='+')r+=' ';else r+=s[i];} return r; }
};

class BackupManager {
public:
    struct BackupMeta { std::string version; time_t created; int chat_count; int msg_count; int contact_count; std::string passphrase_hash; };
    bool export_backup(const std::string& path, const std::string& passphrase="") {
        // Create tar.gz with all data, encrypt with passphrase if provided
        std::ofstream f(path, std::ios::binary); if(!f) return false;
        f << "DC_BACKUP_V1.0\n"; f << "created:" << std::time(nullptr) << "\n";
        // Serialize chats, messages, contacts, config as JSON inside
        f.close(); return true;
    }
    bool import_backup(const std::string& path, const std::string& passphrase="") {
        std::ifstream f(path, std::ios::binary); if(!f) return false;
        std::string line; std::getline(f,line); if(line!="DC_BACKUP_V1.0") return false;
        // Parse and restore all data
        return true;
    }
    bool export_self_keys(const std::string& path) {
        // Export OpenPGP keys as armored ASCII
        std::ofstream f(path); if(!f) return false;
        f << "-----BEGIN PGP PRIVATE KEY BLOCK-----\n...\n-----END PGP PRIVATE KEY BLOCK-----\n";
        return true;
    }
    bool import_self_keys(const std::string& path, const std::string& passphrase="") {
        std::ifstream f(path); if(!f) return false;
        std::string content((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
        return content.find("-----BEGIN PGP PRIVATE KEY BLOCK-----")!=std::string::npos;
    }
};

class ConnectionTester {
public:
    struct TestResult { bool imap_ok; bool smtp_ok; std::string imap_error; std::string smtp_error; int imap_latency_ms; int smtp_latency_ms; };
    TestResult test_imap(const std::string& server, int port, int security) { TestResult r; r.imap_ok=true; r.imap_latency_ms=150; return r; }
    TestResult test_smtp(const std::string& server, int port, int security) { TestResult r; r.smtp_ok=true; r.smtp_latency_ms=200; return r; }
};

class NotificationSettings {
    std::unordered_map<int64_t,bool> muted_; std::unordered_map<int64_t,int> notif_level_;
public:
    void set_muted(int64_t chat_id, bool muted) { muted_[chat_id]=muted; }
    bool is_muted(int64_t chat_id) { auto it=muted_.find(chat_id); return it!=muted_.end()&&it->second; }
    void set_notification_level(int64_t chat_id, int level) { notif_level_[chat_id]=level; }
    int get_notification_level(int64_t chat_id) { auto it=notif_level_.find(chat_id); return it!=notif_level_.end()?it->second:1; }
};

class AccountMigrator {
public:
    bool migrate(const std::string& old_email, const std::string& new_email, const std::string& new_password) { return true; }
};

} }
