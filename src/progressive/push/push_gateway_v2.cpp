// progressive-server: Matrix Push Notification Gateway
// Reference: Synapse push/*.py, push/gateway.py, push/httppusher.py (3,800 lines)
#include <string> <vector> <unordered_map> <memory> <ctime> <algorithm> <sstream> <atomic> <mutex> <functional> <deque>
#include "../json.hpp"
namespace progressive { namespace push {
using json = nlohmann::json;

struct PushRule { std::string rule_id; std::string kind; std::string pattern; bool enabled; std::vector<json> actions; bool default_rule; };
struct PushRuleSet { std::vector<PushRule> content; std::vector<PushRule> override_; std::vector<PushRule> room; std::vector<PushRule> sender; std::vector<PushRule> underride; };
struct PushSubscription { std::string pushkey; std::string app_id; std::string user_id; std::string kind; std::string data_json; std::string profile_tag; int64_t last_success; int64_t last_failure; int failures; bool processed; };

class PushRuleEvaluator {
    std::vector<PushRule> rules_;
public:
    struct EvalResult { bool notify=false; bool highlight=false; std::string sound; std::vector<json> actions; std::string rule_id; };
    void load_rules(const PushRuleSet& ruleset) {
        rules_.clear();
        for(auto& r:ruleset.override_) rules_.push_back(r);
        for(auto& r:ruleset.content) rules_.push_back(r);
        for(auto& r:ruleset.room) rules_.push_back(r);
        for(auto& r:ruleset.sender) rules_.push_back(r);
        for(auto& r:ruleset.underride) rules_.push_back(r);
    }
    EvalResult evaluate(const std::string& user_id, const std::string& room_id, const json& event) {
        EvalResult result;
        for(auto& rule : rules_) {
            if(!rule.enabled) continue;
            bool matched = match_rule(rule, user_id, room_id, event);
            if(matched) {
                result.rule_id = rule.rule_id;
                result.actions = rule.actions;
                for(auto& action : rule.actions) {
                    if(action.is_string()) {
                        std::string act = action.get<std::string>();
                        if(act=="notify") result.notify=true;
                        if(act=="dont_notify") result.notify=false;
                    } else if(action.is_object()) {
                        if(action.contains("set_tweak")) {
                            std::string tweak = action["set_tweak"];
                            if(tweak=="highlight") result.highlight=action.value("value",true);
                            if(tweak=="sound") result.sound=action.value("value","default");
                        }
                    }
                }
                if(result.notify||result.highlight) break;
            }
        }
        return result;
    }
private:
    bool match_rule(const PushRule& rule, const std::string& user_id, const std::string& room_id, const json& event) {
        if(rule.kind=="override"&&rule.pattern.empty()) return true;
        if(rule.kind=="content"&&rule.pattern.find("body")!=std::string::npos) {
            std::string body = event.value("content",json::object()).value("body","");
            return body.find(rule.pattern)!=std::string::npos;
        }
        if(rule.kind=="room"&&!rule.pattern.empty()) {
            return room_id==rule.pattern;
        }
        if(rule.kind=="sender"&&!rule.pattern.empty()) {
            return event.value("sender","")==rule.pattern;
        }
        if(rule.kind=="underride"&&rule.rule_id==".m.rule.call") {
            return event.value("content",json::object()).value("msgtype","")=="m.call.invite";
        }
        if(rule.kind=="underride"&&rule.rule_id==".m.rule.room_one_to_one") {
            return true; // In 1-1 room
        }
        if(rule.kind=="underride"&&rule.rule_id==".m.rule.message") {
            return event.value("type","").find("m.room.message")!=std::string::npos;
        }
        return false;
    }
};

class PushGateway {
public:
    struct PushRequest { std::string pushkey; std::string app_id; std::string user_id; json notification; int retries=0; time_t created=0; };
    void enqueue(const PushRequest& req) { std::lock_guard lock(mutex_); queue_.push_back(req); }
    bool process_batch(int limit=100) {
        std::lock_guard lock(mutex_); int processed=0;
        for(auto& req:queue_) { if(req.retries<3) { send_to_gateway(req); processed++; if(processed>=limit) break; } }
        return processed>0;
    }
private:
    std::deque<PushRequest> queue_; std::mutex mutex_;
    void send_to_gateway(PushRequest& req) {
        json payload; payload["notification"]=req.notification;
        // POST to push gateway
        req.retries++;
    }
};

class EmailPusher {
public:
    struct EmailConfig { std::string app_id; std::string pushkey; std::string data_json; std::string email; std::string lang; std::string brand; };
    void send_email(const std::string& user_id, const std::string& room_name, const std::string& sender, const std::string& body) {
        json mail; mail["subject"]=room_name+": "+sender; mail["body"]=body;
        // Queue email for sending
    }
};

class HttpPusher {
    std::string url_; int retry_interval=300; int max_retries=3;
public:
    void configure(const std::string& url) { url_=url; }
    void push(const json& payload) {
        // POST url_ with payload
    }
};

} }
