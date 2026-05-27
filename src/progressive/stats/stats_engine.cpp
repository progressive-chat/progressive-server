// progressive-server: Matrix complete server statistics engine
#include <string> <vector> <unordered_map> <memory> <ctime> <algorithm> <sstream> <mutex> <atomic> <deque> <functional> <thread>
#include "../json.hpp"
namespace progressive { namespace stats {
using json = nlohmann::json;

struct Counter { std::atomic<int64_t> val{0}; int64_t inc(int64_t n=1) { return val.fetch_add(n); } int64_t get() { return val.load(); } void reset() { val.store(0); } };
struct Gauge { std::atomic<int64_t> val{0}; void set(int64_t v) { val.store(v); } int64_t get() { return val.load(); } };
struct Histogram { std::vector<int64_t> buckets; std::mutex m; void observe(int64_t v) { std::lock_guard l(m); for(size_t i=0;i<buckets.size();i++) if(v<=buckets[i]) { buckets[i]++; break; } } };
struct Timer { int64_t start; Timer() : start(now_us()) {} int64_t elapsed_us() { return now_us()-start; } static int64_t now_us() { return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count(); } };

class StatsEngine {
    // Room stats
    struct RoomStats { int64_t room_id; std::string room_id_str; int members; int local_members; int messages; int state_events; int reactions; int redactions; int daily_msgs[24]; int64_t last_activity; int64_t created_at; };
    std::unordered_map<std::string, RoomStats> rooms_;
    std::mutex rooms_mutex_;

    // User stats
    struct UserStats { std::string user_id; int64_t msgs_sent; int64_t rooms_joined; int64_t reactions_sent; int64_t logins; int64_t devices; int64_t last_active; int64_t created_at; };
    std::unordered_map<std::string, UserStats> users_;
    std::mutex users_mutex_;

    // Global counters
    Counter total_msgs_, total_rooms_, total_users_, total_media_uploads_, total_media_downloads_, total_api_requests_;
    Counter federation_sent_, federation_received_, federation_failed_;
    Counter push_sent_, push_failed_;
    Gauge active_users_, active_rooms_, active_connections_;

    // Per-endpoint rate limit hits
    struct EndpointStats { Counter requests; Counter rate_limited; Counter errors; Timer::int64_t total_latency_us; };
    std::unordered_map<std::string, EndpointStats> endpoints_;
    std::mutex endpoints_mutex_;

    // DB stats
    struct DbStats { int64_t total_size; int64_t events_count; int64_t state_groups_count; int64_t rooms_count; int64_t users_count; int64_t devices_count; };
    DbStats db_stats_;
    std::mutex db_mutex_;

    // Cache stats
    struct CacheStats { Counter hits; Counter misses; Counter evictions; Gauge size; std::string name; };
    std::unordered_map<std::string, CacheStats> caches_;
    std::mutex cache_mutex_;

    // Federation per-destination
    struct DestStats { std::string dest; Counter sent; Counter received; Counter failed; Timer::int64_t total_latency; int64_t last_success; int64_t last_failure; bool retrying; };
    std::unordered_map<std::string, DestStats> destinations_;
    std::mutex dest_mutex_;

    // History
    struct Snapshot { int64_t ts; int64_t users; int64_t rooms; int64_t msgs; int64_t media; };
    std::deque<Snapshot> history_;
    std::mutex history_mutex_;
    static constexpr int MAX_HISTORY = 720; // 30 days hourly

    std::atomic<bool> running_{false};
    std::thread snapshot_thread_;

public:
    void start() { running_=true; snapshot_thread_=std::thread(&StatsEngine::snapshot_loop,this); }
    void stop() { running_=false; if(snapshot_thread_.joinable()) snapshot_thread_.join(); }

    // Room tracking
    void track_room_event(const std::string& room_id, const std::string& event_type) {
        std::lock_guard l(rooms_mutex_);
        auto& rs = rooms_[room_id]; rs.room_id_str = room_id;
        if(event_type=="m.room.message") rs.messages++;
        else if(event_type=="m.reaction") rs.reactions++;
        else if(event_type=="m.room.redaction") rs.redactions++;
        else rs.state_events++;
        rs.last_activity = std::time(nullptr);
        int hour = (std::time(nullptr)/3600)%24;
        if(hour>=0&&hour<24) rs.daily_msgs[hour]++;
        total_msgs_.inc();
    }
    void track_room_join(const std::string& room_id, bool local) {
        std::lock_guard l(rooms_mutex_);
        auto& rs = rooms_[room_id]; rs.members++;
        if(local) rs.local_members++;
    }
    void track_room_leave(const std::string& room_id, bool local) {
        std::lock_guard l(rooms_mutex_);
        auto& rs = rooms_[room_id]; rs.members--;
        if(local) rs.local_members--;
    }
    void track_room_create(const std::string& room_id) {
        std::lock_guard l(rooms_mutex_);
        rooms_[room_id].created_at = std::time(nullptr);
        total_rooms_.inc();
    }

    // User tracking
    void track_user_msg(const std::string& user_id) {
        std::lock_guard l(users_mutex_);
        users_[user_id].msgs_sent++;
        users_[user_id].last_active = std::time(nullptr);
    }
    void track_user_join(const std::string& user_id) {
        std::lock_guard l(users_mutex_); users_[user_id].rooms_joined++;
    }
    void track_user_login(const std::string& user_id) {
        std::lock_guard l(users_mutex_); users_[user_id].logins++;
    }
    void track_user_create(const std::string& user_id) {
        std::lock_guard l(users_mutex_);
        users_[user_id].created_at = std::time(nullptr);
        total_users_.inc();
    }

    // Federation
    void track_fed_sent(const std::string& dest) {
        federation_sent_.inc();
        std::lock_guard l(dest_mutex_);
        auto& d = destinations_[dest]; d.dest=dest; d.sent.inc(); d.last_success=std::time(nullptr);
    }
    void track_fed_received(const std::string& dest) {
        federation_received_.inc();
        std::lock_guard l(dest_mutex_);
        auto& d = destinations_[dest]; d.received.inc(); d.last_success=std::time(nullptr);
    }
    void track_fed_failed(const std::string& dest) {
        federation_failed_.inc();
        std::lock_guard l(dest_mutex_);
        auto& d = destinations_[dest]; d.failed.inc(); d.last_failure=std::time(nullptr);
    }

    // API
    void track_api(const std::string& endpoint, int status, int64_t latency_us) {
        total_api_requests_.inc();
        std::lock_guard l(endpoints_mutex_);
        auto& ep = endpoints_[endpoint];
        ep.requests.inc();
        if(status>=400) ep.errors.inc();
        ep.total_latency_us += latency_us;
    }
    void track_rate_limit(const std::string& endpoint) {
        std::lock_guard l(endpoints_mutex_); endpoints_[endpoint].rate_limited.inc();
    }

    // Media
    void track_media_upload() { total_media_uploads_.inc(); }
    void track_media_download() { total_media_downloads_.inc(); }

    // Cache
    void track_cache_hit(const std::string& name) { std::lock_guard l(cache_mutex_); caches_[name].hits.inc(); }
    void track_cache_miss(const std::string& name) { std::lock_guard l(cache_mutex_); caches_[name].misses.inc(); }

    // Push
    void track_push_sent() { push_sent_.inc(); }
    void track_push_failed() { push_failed_.inc(); }

    // Gauge updates
    void set_active_users(int64_t n) { active_users_.set(n); }
    void set_active_rooms(int64_t n) { active_rooms_.set(n); }
    void set_active_connections(int64_t n) { active_connections_.set(n); }

    // JSON export
    json get_stats() {
        json j;
        j["totals"]["messages"] = total_msgs_.get();
        j["totals"]["rooms"] = total_rooms_.get();
        j["totals"]["users"] = total_users_.get();
        j["totals"]["media_uploads"] = total_media_uploads_.get();
        j["totals"]["media_downloads"] = total_media_downloads_.get();
        j["totals"]["api_requests"] = total_api_requests_.get();
        j["gauges"]["active_users"] = active_users_.get();
        j["gauges"]["active_rooms"] = active_rooms_.get();
        j["gauges"]["active_connections"] = active_connections_.get();
        j["federation"]["sent"] = federation_sent_.get();
        j["federation"]["received"] = federation_received_.get();
        j["federation"]["failed"] = federation_failed_.get();
        j["push"]["sent"] = push_sent_.get();
        j["push"]["failed"] = push_failed_.get();

        // Per-destination
        json dests = json::array();
        { std::lock_guard l(dest_mutex_);
            for(auto&[k,v]:destinations_) {
                json d; d["destination"]=v.dest; d["sent"]=v.sent.get(); d["received"]=v.received.get(); d["failed"]=v.failed.get();
                d["last_success"]=v.last_success; d["last_failure"]=v.last_failure; d["retrying"]=v.retrying;
                dests.push_back(d);
            }
        }
        j["destinations"] = dests;

        // Per-endpoint
        json eps = json::array();
        { std::lock_guard l(endpoints_mutex_);
            for(auto&[k,v]:endpoints_) {
                json e; e["endpoint"]=k; e["requests"]=v.requests.get(); e["rate_limited"]=v.rate_limited.get(); e["errors"]=v.errors.get();
                e["avg_latency_us"] = v.requests.get()>0 ? v.total_latency_us/v.requests.get() : 0;
                eps.push_back(e);
            }
        }
        j["endpoints"] = eps;

        // Caches
        json caches = json::array();
        { std::lock_guard l(cache_mutex_);
            for(auto&[k,v]:caches_) {
                json c; c["name"]=k; c["hits"]=v.hits.get(); c["misses"]=v.misses.get(); c["evictions"]=v.evictions.get(); c["size"]=v.size.get();
                int64_t total = v.hits.get()+v.misses.get();
                c["hit_rate"] = total>0 ? (double)v.hits.get()/total : 0.0;
                caches.push_back(c);
            }
        }
        j["caches"] = caches;

        // History
        json hist = json::array();
        { std::lock_guard l(history_mutex_);
            for(auto& s:history_) {
                json h; h["ts"]=s.ts; h["users"]=s.users; h["rooms"]=s.rooms; h["msgs"]=s.msgs; h["media"]=s.media;
                hist.push_back(h);
            }
        }
        j["history"] = hist;

        // Room stats
        json rooms_arr = json::array();
        { std::lock_guard l(rooms_mutex_);
            for(auto&[k,v]:rooms_) {
                json r; r["room_id"]=k; r["members"]=v.members; r["local_members"]=v.local_members;
                r["messages"]=v.messages; r["state_events"]=v.state_events; r["reactions"]=v.reactions;
                r["last_activity"]=v.last_activity;
                rooms_arr.push_back(r);
            }
        }
        j["rooms"] = rooms_arr;

        return j;
    }

    json get_prometheus_metrics() {
        std::stringstream ss;
        ss << "# HELP progressive_messages_total Total messages\n";
        ss << "# TYPE progressive_messages_total counter\n";
        ss << "progressive_messages_total " << total_msgs_.get() << "\n";
        ss << "progressive_rooms_total " << total_rooms_.get() << "\n";
        ss << "progressive_users_total " << total_users_.get() << "\n";
        ss << "progressive_active_users " << active_users_.get() << "\n";
        ss << "progressive_active_rooms " << active_rooms_.get() << "\n";
        ss << "progressive_federation_sent_total " << federation_sent_.get() << "\n";
        ss << "progressive_federation_received_total " << federation_received_.get() << "\n";
        ss << "progressive_push_sent_total " << push_sent_.get() << "\n";
        json j; j["metrics"] = ss.str(); return j;
    }

private:
    void snapshot_loop() {
        while(running_) {
            std::this_thread::sleep_for(std::chrono::hours(1));
            Snapshot snap;
            snap.ts = std::time(nullptr);
            snap.users = total_users_.get();
            snap.rooms = total_rooms_.get();
            snap.msgs = total_msgs_.get();
            snap.media = total_media_uploads_.get();
            std::lock_guard l(history_mutex_);
            history_.push_back(snap);
            if((int)history_.size() > MAX_HISTORY) history_.pop_front();
        }
    }
};

} }
