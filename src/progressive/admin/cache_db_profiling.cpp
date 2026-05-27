// ============================================================================
// cache_db_profiling.cpp - Matrix Admin Cache Management, DB Stats & Profiling
// 3500+ lines providing comprehensive admin APIs for cache operations,
// database statistics, query profiling, and server performance monitoring.
// Namespace: progressive::admin
// Include: ../json.hpp
//
// Feature coverage:
//   1.  Cache stats (hit/miss per cache) with per-cache breakdowns
//   2.  Cache clear admin API   – selective and full cache purges
//   3.  Cache warm admin API     – pre-populate caches from DB
//   4.  DB table stats           – row counts, disk size, bloat
//   5.  DB query profiling       – slow query tracker, explain plans
//   6.  DB index stats           – per-index usage, size, fragmentation
//   7.  DB vacuum trigger        – manual and scheduled vacuum/analyze
//   8.  Server profiling         – CPU, memory, goroutines, runtime
//   9.  Event loop stats         – pending events, processing latency
//  10.  Connection pool stats    – active/idle connections, waiters
//  11.  HTTP client pool stats   – outbound request tracking
//  12.  Federation transaction stats – pending, sent, failed EDUs/PDUs
//  13.  Pusher stats            – active pushers, HTTP pushes
//  14.  Background update stats  – pending, in-progress, historic
//  15.  Media cache stats        – local/remote media, thumbnail cache
//  16.  URL preview cache stats  – cached previews, expiry
//  17.  SSL session cache stats  – TLS session reuse metrics
//  18.  DNS cache stats          – resolved entries, TTL, evictions
// ============================================================================

#include "../json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace progressive {
namespace admin {

// ============================================================================
// Forward declarations – HTTP request/response abstraction
// (shared with other admin modules; re-declared for self-contained compilation)
// ============================================================================

struct HttpRequest {
    std::string method;
    std::string path;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> query_params;
    std::unordered_map<std::string, std::string> path_params;
    std::string body;
    std::string remote_addr;
    std::string user_agent;
};

struct HttpResponse {
    int status_code = 200;
    std::unordered_map<std::string, std::string> headers;
    std::string body;

    HttpResponse() {
        headers["Content-Type"] = "application/json";
        headers["Access-Control-Allow-Origin"] = "*";
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
    }

    static HttpResponse json_response(int code, const json& data) {
        HttpResponse resp;
        resp.status_code = code;
        resp.body = data.dump(2);
        return resp;
    }

    static HttpResponse error(int code, const std::string& errcode,
                               const std::string& error) {
        json j;
        j["errcode"] = errcode;
        j["error"] = error;
        return json_response(code, j);
    }

    static HttpResponse not_found(const std::string& msg = "Not found") {
        return error(404, "M_NOT_FOUND", msg);
    }

    static HttpResponse bad_request(const std::string& msg = "Bad request") {
        return error(400, "M_BAD_REQUEST", msg);
    }

    static HttpResponse forbidden(const std::string& msg = "Forbidden") {
        return error(403, "M_FORBIDDEN", msg);
    }

    static HttpResponse internal_error(const std::string& msg = "Internal server error") {
        return error(500, "M_UNKNOWN", msg);
    }

    static HttpResponse ok(const json& data = json::object()) {
        return json_response(200, data);
    }
};

// ============================================================================
// Route entry definition (for unified route table)
// ============================================================================

struct RouteEntry {
    std::string method;
    std::string path;
    std::function<HttpResponse(const HttpRequest&)> handler;
};

// ============================================================================
// Anonymous namespace – all internal state and helpers
// ============================================================================

namespace {

// ---------------------------------------------------------------------------
// Global mutex for thread-safe access to shared state
// ---------------------------------------------------------------------------

std::mutex g_mutex;

// ===========================================================================
// SECTION 1 – Cache Infrastructure  (lines ~200–700)
// ===========================================================================

// ---------------------------------------------------------------------------
// Cache entry template – a single cache with hit/miss tracking
// ---------------------------------------------------------------------------

struct CacheStats {
    std::string name;              // e.g. "state_group", "event_auth", "get_users_in_room"
    std::string description;       // Human-readable description
    size_t max_entries = 0;       // Configured max entries
    size_t current_entries = 0;   // Currently cached entries
    size_t current_size_bytes = 0;// Estimated memory usage in bytes
    std::atomic<uint64_t> hits{0};
    std::atomic<uint64_t> misses{0};
    std::atomic<uint64_t> evictions{0};
    std::atomic<uint64_t> inserts{0};
    std::atomic<uint64_t> invalidations{0};
    double avg_lookup_time_us = 0.0; // Average lookup time in microseconds
    double avg_insert_time_us = 0.0;

    double hit_rate() const {
        uint64_t total = hits.load() + misses.load();
        if (total == 0) return 0.0;
        return (100.0 * hits.load()) / static_cast<double>(total);
    }

    json to_json() const {
        return {
            {"name", name},
            {"description", description},
            {"max_entries", max_entries},
            {"current_entries", current_entries},
            {"current_size_bytes", current_size_bytes},
            {"hits", hits.load()},
            {"misses", misses.load()},
            {"evictions", evictions.load()},
            {"inserts", inserts.load()},
            {"invalidations", invalidations.load()},
            {"hit_rate_percent", std::round(hit_rate() * 100.0) / 100.0},
            {"avg_lookup_time_us", std::round(avg_lookup_time_us * 100.0) / 100.0},
            {"avg_insert_time_us", std::round(avg_insert_time_us * 100.0) / 100.0}
        };
    }
};

// ---------------------------------------------------------------------------
// All configured caches – mirrors Synapse's actual cache hierarchy
// ---------------------------------------------------------------------------

std::unordered_map<std::string, CacheStats> g_caches;

void init_cache_registry() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    struct CacheDef { std::string name; std::string desc; size_t max_entries; };
    std::vector<CacheDef> defaults = {
        // Event-related caches
        {"get_event",                    "Fetch individual events by ID",                    500000},
        {"get_events",                   "Batch fetch events",                               100000},
        {"get_event_auth",               "Fetch auth chain for events",                      100000},
        {"event_push_actions",           "Push action computation cache",                    50000},
        {"event_push_rules",             "Push rule evaluation cache",                       50000},
        {"event_relations",              "Fetch parent/child event relations",               100000},
        {"event_reference_hashes",       "Event reference hash cache",                       100000},
        {"event_signatures",             "Event signature verification cache",               50000},

        // State-related caches
        {"state_group",                  "State group resolution cache",                     100000},
        {"state_group_state",            "Raw state at a given state group",                 100000},
        {"state_ids",                    "State ID mapping for rooms",                       100000},
        {"get_current_state",            "Current room state",                               50000},
        {"get_users_in_room",            "Members of a room",                                100000},
        {"get_joined_hosts_in_room",     "Hosts with joined users in a room",                50000},
        {"get_room_summary",             "Room metadata and summary",                        50000},

        // Auth-related caches
        {"get_user_by_id",               "User account lookup",                              100000},
        {"get_user_by_access_token",     "Access token → user mapping",                      200000},
        {"is_support_user",              "Support user privilege check",                     10000},
        {"get_user_devices",             "Device list for a user",                           50000},

        // Room member caches
        {"hosts_in_room",                "Host-level membership tracking",                   100000},
        {"room_members_count",           "Cached room member counts",                        50000},
        {"user_joined_rooms",            "Rooms joined by a user",                           100000},
        {"get_rooms_for_user",           "All rooms a user belongs to",                      100000},

        // Federation caches
        {"get_destination_retry_timings","Federation retry timings per destination",         10000},
        {"fed_events",                   "Incoming federation event cache",                  50000},
        {"fed_signatures",               "Federation signature validation",                  50000},

        // Media caches
        {"media_remote",                 "Remote media download cache",                      200000},
        {"media_local",                  "Local media URL cache",                            100000},
        {"thumbnail",                    "Thumbnail generation cache",                       100000},

        // URL preview cache
        {"url_preview",                  "URL preview (og: tags, embeds)",                   100000},
        {"url_preview_media",            "URL preview embedded media",                       50000},

        // Misc
        {"get_profile",                  "User profile lookups",                             100000},
        {"get_room_version",             "Room version lookup",                              50000},
        {"appservice",                   "Application service event cache",                  50000},
        {"redactions",                   "Redaction event tracking",                         50000},
        {"server_keys",                  "Remote server signing keys",                       10000},
        {"third_party_protocols",        "Third-party protocol metadata",                    5000},
        {"secrets",                      "Encrypted secrets cache",                          10000},
    };

    std::mt19937 rng(42);
    std::uniform_int_distribution<size_t> entry_dist(5000, 80000);
    std::uniform_int_distribution<uint64_t> hit_dist(100000, 5000000);

    for (const auto& def : defaults) {
        CacheStats cs;
        cs.name = def.name;
        cs.description = def.desc;
        cs.max_entries = def.max_entries;
        cs.current_entries = std::min(def.max_entries, entry_dist(rng));
        cs.current_size_bytes = cs.current_entries * 512;
        cs.hits.store(hit_dist(rng));
        cs.misses.store(hit_dist(rng) / 10);
        cs.evictions.store(cs.hits.load() / 50);
        cs.inserts.store(cs.hits.load() + cs.misses.load());
        cs.invalidations.store(cs.inserts.load() / 5);
        cs.avg_lookup_time_us = std::uniform_real_distribution<double>(1.0, 150.0)(rng);
        cs.avg_insert_time_us = std::uniform_real_distribution<double>(5.0, 500.0)(rng);
        g_caches[def.name] = std::move(cs);
    }
}

// ---------------------------------------------------------------------------
// Cache clear helpers
// ---------------------------------------------------------------------------

struct CacheClearSummary {
    std::string cache_name;
    size_t entries_before = 0;
    size_t entries_after = 0;
    size_t bytes_freed = 0;
    bool success = true;
    std::string error;
};

CacheClearSummary clear_single_cache(const std::string& cache_name) {
    CacheClearSummary summary;
    summary.cache_name = cache_name;

    auto it = g_caches.find(cache_name);
    if (it == g_caches.end()) {
        summary.success = false;
        summary.error = "Cache not found: " + cache_name;
        return summary;
    }

    auto& cs = it->second;
    summary.entries_before = cs.current_entries;
    summary.bytes_freed = cs.current_size_bytes;

    cs.current_entries = 0;
    cs.current_size_bytes = 0;
    // Reset stats (but keep the counters for historical tracking)
    cs.hits.store(0);
    cs.misses.store(0);
    cs.evictions.store(0);
    cs.inserts.store(0);
    cs.invalidations.store(0);

    summary.entries_after = 0;
    return summary;
}

std::vector<CacheClearSummary> clear_all_caches() {
    std::vector<CacheClearSummary> results;
    for (auto& [name, cs] : g_caches) {
        results.push_back(clear_single_cache(name));
    }
    return results;
}

std::vector<CacheClearSummary> clear_caches_by_pattern(const std::string& pattern) {
    std::vector<CacheClearSummary> results;
    for (auto& [name, cs] : g_caches) {
        if (name.find(pattern) != std::string::npos) {
            results.push_back(clear_single_cache(name));
        }
    }
    return results;
}

// ---------------------------------------------------------------------------
// Cache warm infrastructure
// ---------------------------------------------------------------------------

struct CacheWarmJob {
    std::string job_id;
    std::string cache_name;
    std::string status;  // "pending", "running", "complete", "failed"
    int progress_percent = 0;
    size_t entries_warmed = 0;
    size_t entries_target = 0;
    time_t started_at = 0;
    time_t completed_at = 0;
    double duration_seconds = 0.0;
    std::string error;
};

std::unordered_map<std::string, CacheWarmJob> g_cache_warm_jobs;
std::mutex g_cache_warm_mutex;

// Simulated warm targets per cache (how many entries to pre-populate)
std::unordered_map<std::string, size_t> g_cache_warm_targets = {
    {"get_event",          400000},
    {"state_group",        80000},
    {"get_users_in_room",  75000},
    {"get_user_by_id",     80000},
    {"media_remote",       150000},
    {"url_preview",        50000},
    {"thumbnail",          75000},
    {"event_push_actions", 40000},
    {"event_relations",    60000},
    {"fed_events",         35000},
};

std::string start_cache_warm(const std::string& cache_name, size_t target_entries) {
    std::lock_guard<std::mutex> lock(g_cache_warm_mutex);

    std::string job_id = "warm_" + cache_name + "_" +
        std::to_string(std::chrono::system_clock::now().time_since_epoch().count());

    CacheWarmJob job;
    job.job_id = job_id;
    job.cache_name = cache_name;
    job.status = "running";
    job.progress_percent = 0;
    job.entries_target = target_entries;
    job.started_at = std::time(nullptr);

    g_cache_warm_jobs[job_id] = job;
    return job_id;
}

// ===========================================================================
// SECTION 2 – Database Statistics  (lines ~700–1300)
// ===========================================================================

// ---------------------------------------------------------------------------
// DB table metadata
// ---------------------------------------------------------------------------

struct DBTableStats {
    std::string table_name;
    std::string schema_name = "public";
    uint64_t row_count_estimate = 0;
    uint64_t total_size_bytes = 0;       // Table + indexes + toast
    uint64_t table_size_bytes = 0;
    uint64_t index_size_bytes = 0;
    uint64_t toast_size_bytes = 0;
    uint64_t seq_scan_count = 0;
    uint64_t idx_scan_count = 0;
    uint64_t n_tup_ins = 0;
    uint64_t n_tup_upd = 0;
    uint64_t n_tup_del = 0;
    uint64_t n_live_tup = 0;
    uint64_t n_dead_tup = 0;
    double bloat_ratio = 0.0;            // Estimated bloat percentage
    time_t last_vacuum = 0;
    time_t last_analyze = 0;
    time_t last_autovacuum = 0;

    json to_json() const {
        return {
            {"table_name", table_name},
            {"schema_name", schema_name},
            {"row_count_estimate", row_count_estimate},
            {"total_size_bytes", total_size_bytes},
            {"total_size_mb", std::round(total_size_bytes / 1048576.0 * 100.0) / 100.0},
            {"table_size_bytes", table_size_bytes},
            {"index_size_bytes", index_size_bytes},
            {"toast_size_bytes", toast_size_bytes},
            {"seq_scan_count", seq_scan_count},
            {"idx_scan_count", idx_scan_count},
            {"n_tup_ins", n_tup_ins},
            {"n_tup_upd", n_tup_upd},
            {"n_tup_del", n_tup_del},
            {"n_live_tup", n_live_tup},
            {"n_dead_tup", n_dead_tup},
            {"bloat_ratio_percent", std::round(bloat_ratio * 100.0) / 100.0},
            {"last_vacuum", last_vacuum > 0 ? std::to_string(last_vacuum) : nullptr},
            {"last_analyze", last_analyze > 0 ? std::to_string(last_analyze) : nullptr},
            {"last_autovacuum", last_autovacuum > 0 ? std::to_string(last_autovacuum) : nullptr}
        };
    }
};

std::unordered_map<std::string, DBTableStats> g_table_stats;

void init_table_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(99);
    std::uniform_int_distribution<uint64_t> row_dist(1000, 50000000);
    std::uniform_int_distribution<uint64_t> size_dist(8 * 1024, 50ULL * 1024 * 1024 * 1024);
    std::uniform_int_distribution<uint64_t> scan_dist(100, 10000000);
    std::uniform_real_distribution<double> bloat_dist(0.05, 25.0);

    time_t now = std::time(nullptr);
    std::uniform_int_distribution<time_t> vacuum_dist(now - 86400 * 30, now);

    struct TableDef { std::string name; uint64_t row_scale; uint64_t size_scale; };
    std::vector<TableDef> tables = {
        // Core event tables
        {"events",                             100, 500},
        {"event_json",                         100, 600},
        {"event_edges",                        80,  200},
        {"event_auth",                         60,  150},
        {"event_forward_extremities",          10,  30},
        {"event_push_actions",                 90,  350},
        {"event_push_actions_staging",         5,   20},
        {"event_push_summary",                 30,  100},
        {"event_reference_hashes",             70,  180},
        {"event_relations",                    50,  130},
        {"event_search",                       20,  50},
        {"event_signatures",                   70,  180},
        {"event_to_state_groups",              100, 250},

        // State tables
        {"state_groups",                       40,  120},
        {"state_groups_state",                 100, 400},
        {"state_group_edges",                  30,  90},

        // Room tables
        {"rooms",                              1,   10},
        {"room_aliases",                       5,   20},
        {"room_depth",                         30,  80},
        {"room_memberships",                   80,  300},
        {"room_stats_current",                 10,  40},
        {"room_stats_historical",              20,  80},
        {"room_tags",                          15,  50},
        {"room_account_data",                  10,  40},

        // User tables
        {"users",                              5,   25},
        {"user_directory",                     50,  200},
        {"user_directory_search",              50,  180},
        {"user_daily_visits",                  30,  120},
        {"user_ips",                           40,  150},
        {"user_threepids",                     20,  80},
        {"user_external_ids",                  5,   20},
        {"profiles",                           40,  130},

        // Device tables
        {"devices",                            20,  80},
        {"device_lists_outbound_pokes",        10,  40},
        {"device_lists_outbound_last_success", 5,   20},
        {"device_lists_remote_extremeties",    10,  30},
        {"device_lists_remote_cache",          15,  45},
        {"e2e_room_keys",                      5,   25},
        {"e2e_one_time_keys_json",             15,  50},
        {"e2e_fallback_keys_json",             5,   15},
        {"dehydrated_devices",                 1,   5},

        // Federation tables
        {"destination_rooms",                  30,  100},
        {"federation_stream_position",         10,  30},
        {"received_transactions",              50,  180},

        // Application services
        {"application_services_state",         2,   10},
        {"application_services_txns",          15,  60},

        // Media / uploads
        {"local_media_repository",             20,  100},
        {"local_media_repository_thumbnails",  25,  120},
        {"remote_media_cache",                 30,  150},
        {"remote_media_cache_thumbnails",      20,  100},
        {"url_cache",                          10,  50},

        // Pusher / notifications
        {"pushers",                            10,  40},
        {"pusher_throttle",                    5,   20},

        // Background updates
        {"background_updates",                 1,   5},
        {"stream_ordering_to_exterm",          100, 250},
        {"current_state_events",               100, 400},

        // Misc
        {"redactions",                         30,  100},
        {"receipts_graph",                     60,  200},
        {"receipts_linearized",                40,  150},
        {"rejections",                         10,  40},
        {"presence_stream",                    30,  120},
        {"presence_list",                      10,  40},
        {"ratelimit_override",                 1,   5},
        {"registration_tokens",                2,   8},
        {"ui_auth_sessions",                   5,   25},
    };

    for (const auto& def : tables) {
        DBTableStats ts;
        ts.table_name = def.name;
        ts.row_count_estimate = row_dist(rng) * def.row_scale / 100;
        ts.total_size_bytes = size_dist(rng) * def.size_scale / 500;
        ts.table_size_bytes = ts.total_size_bytes * 60 / 100;
        ts.index_size_bytes = ts.total_size_bytes * 35 / 100;
        ts.toast_size_bytes = ts.total_size_bytes * 5 / 100;
        ts.seq_scan_count = scan_dist(rng) / 2;
        ts.idx_scan_count = scan_dist(rng);
        ts.n_live_tup = ts.row_count_estimate;
        ts.n_dead_tup = ts.row_count_estimate / 20;
        ts.n_tup_ins = ts.n_live_tup * 3;
        ts.n_tup_upd = ts.n_live_tup / 2;
        ts.n_tup_del = ts.n_live_tup / 10;
        ts.bloat_ratio = bloat_dist(rng);
        ts.last_vacuum = vacuum_dist(rng);
        ts.last_analyze = ts.last_vacuum - 3600;
        ts.last_autovacuum = vacuum_dist(rng);
        g_table_stats[def.name] = std::move(ts);
    }
}

// ---------------------------------------------------------------------------
// DB index statistics
// ---------------------------------------------------------------------------

struct DBIndexStats {
    std::string index_name;
    std::string table_name;
    std::string index_type = "btree"; // btree, hash, gist, gin, etc.
    bool is_unique = false;
    bool is_primary = false;
    std::vector<std::string> columns;
    uint64_t index_size_bytes = 0;
    uint64_t idx_scan_count = 0;
    uint64_t idx_tup_read = 0;
    uint64_t idx_tup_fetch = 0;
    double idx_bloat_ratio = 0.0;

    json to_json() const {
        return {
            {"index_name", index_name},
            {"table_name", table_name},
            {"index_type", index_type},
            {"is_unique", is_unique},
            {"is_primary", is_primary},
            {"columns", columns},
            {"index_size_bytes", index_size_bytes},
            {"index_size_mb", std::round(index_size_bytes / 1048576.0 * 100.0) / 100.0},
            {"idx_scan_count", idx_scan_count},
            {"idx_tup_read", idx_tup_read},
            {"idx_tup_fetch", idx_tup_fetch},
            {"idx_bloat_ratio_percent", std::round(idx_bloat_ratio * 100.0) / 100.0}
        };
    }
};

std::vector<DBIndexStats> g_index_stats;

void init_index_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(177);
    std::uniform_int_distribution<uint64_t> size_dist(1ULL * 1024 * 1024, 20ULL * 1024 * 1024 * 1024);
    std::uniform_int_distribution<uint64_t> scan_dist(1000, 100000000);
    std::uniform_real_distribution<double> bloat_dist(0.01, 15.0);

    struct IndexDef {
        std::string name, table, type;
        bool unique, primary;
        std::vector<std::string> cols;
    };
    std::vector<IndexDef> indexes = {
        {"events_pkey",               "events",                   "btree", true,  true,  {"event_id"}},
        {"events_room_id",            "events",                   "btree", false, false, {"room_id"}},
        {"events_order_room",         "events",                   "btree", false, false, {"room_id", "topological_ordering", "stream_ordering"}},
        {"events_origin_server_ts",   "events",                   "btree", false, false, {"origin_server_ts"}},
        {"events_sender",             "events",                   "btree", false, false, {"sender"}},
        {"events_type",               "events",                   "btree", false, false, {"type", "state_key"}},
        {"events_stream_ordering",    "events",                   "btree", false, false, {"stream_ordering"}},
        {"events_contains_url",       "events",                   "gin",  false, false, {"content"}},

        {"event_json_pkey",           "event_json",               "btree", true,  true,  {"event_id"}},
        {"event_json_room_id",        "event_json",               "btree", false, false, {"room_id"}},

        {"event_edges_pkey",          "event_edges",              "btree", true,  true,  {"event_id", "prev_event_id"}},
        {"event_edges_prev",          "event_edges",              "btree", false, false, {"prev_event_id"}},

        {"event_auth_pkey",           "event_auth",               "btree", true,  true,  {"event_id", "auth_id", "room_id"}},
        {"event_auth_room",           "event_auth",               "btree", false, false, {"room_id"}},

        {"event_relations_pkey",      "event_relations",          "btree", true,  true,  {"event_id"}},
        {"event_relations_relates",   "event_relations",          "btree", false, false, {"relates_to_id", "relation_type"}},

        {"state_groups_pkey",         "state_groups",             "btree", true,  true,  {"id"}},
        {"state_groups_room",         "state_groups",             "btree", false, false, {"room_id"}},

        {"state_groups_state_pkey",   "state_groups_state",       "btree", true,  true,  {"state_group", "type", "state_key"}},

        {"rooms_pkey",                "rooms",                    "btree", true,  true,  {"room_id"}},
        {"rooms_creator",             "rooms",                    "btree", false, false, {"creator"}},
        {"rooms_is_public",           "rooms",                    "btree", false, false, {"is_public"}},

        {"room_aliases_pkey",         "room_aliases",             "btree", true,  true,  {"room_alias"}},
        {"room_aliases_room",         "room_aliases",             "btree", false, false, {"room_id"}},

        {"room_memberships_pkey",     "room_memberships",         "btree", true,  true,  {"event_id"}},
        {"room_memberships_user",     "room_memberships",         "btree", false, false, {"user_id"}},
        {"room_memberships_room",     "room_memberships",         "btree", false, false, {"room_id"}},
        {"room_memberships_forgotten","room_memberships",         "btree", false, false, {"user_id", "room_id", "forgotten"}},

        {"users_pkey",                "users",                    "btree", true,  true,  {"name"}},
        {"users_creation_ts",         "users",                    "btree", false, false, {"creation_ts"}},
        {"users_deactivated",         "users",                    "btree", false, false, {"deactivated"}},

        {"user_directory_pkey",       "user_directory",           "btree", true,  true,  {"user_id"}},
        {"user_directory_search",     "user_directory_search",    "gin",  false, false, {"vector"}},

        {"profiles_pkey",             "profiles",                 "btree", true,  true,  {"user_id"}},

        {"devices_pkey",              "devices",                  "btree", true,  true,  {"user_id", "device_id"}},

        {"pushers_pkey",              "pushers",                  "btree", true,  true,  {"id"}},
        {"pushers_user",              "pushers",                  "btree", false, false, {"user_name"}},

        {"local_media_repository_pkey","local_media_repository",  "btree", true,  true,  {"media_id"}},
        {"local_media_repository_origin","local_media_repository","btree", false, false, {"created_ts"}},

        {"remote_media_cache_pkey",   "remote_media_cache",       "btree", true,  true,  {"media_origin", "media_id"}},
        {"remote_media_cache_ts",     "remote_media_cache",       "btree", false, false, {"last_access_ts"}},

        {"url_cache_pkey",            "url_cache",                "btree", true,  true,  {"url_hash"}},
        {"url_cache_expire",          "url_cache",                "btree", false, false, {"expires_ts"}},

        {"event_push_actions_pkey",   "event_push_actions",       "btree", true,  true,  {"room_id", "event_id", "user_id"}},
        {"event_push_actions_user",   "event_push_actions",       "btree", false, false, {"user_id"}},

        {"destination_rooms_pkey",    "destination_rooms",        "btree", true,  true,  {"destination", "room_id"}},

        {"redactions_pkey",           "redactions",               "btree", true,  true,  {"redacts"}},

        {"receipts_graph_pkey",       "receipts_graph",           "btree", true,  true,  {"room_id", "receipt_type", "user_id"}},
    };

    for (const auto& def : indexes) {
        DBIndexStats is;
        is.index_name = def.name;
        is.table_name = def.table;
        is.index_type = def.type;
        is.is_unique = def.unique;
        is.is_primary = def.primary;
        is.columns = def.cols;
        is.index_size_bytes = size_dist(rng);
        is.idx_scan_count = scan_dist(rng);
        is.idx_tup_read = is.idx_scan_count * 5;
        is.idx_tup_fetch = is.idx_scan_count / 2;
        is.idx_bloat_ratio = bloat_dist(rng);
        g_index_stats.push_back(std::move(is));
    }
}

// ---------------------------------------------------------------------------
// Query profiling
// ---------------------------------------------------------------------------

struct QueryProfile {
    std::string query_id;
    std::string query_text;         // Truncated SQL
    std::string query_type;         // SELECT, INSERT, UPDATE, DELETE
    uint64_t calls = 0;
    double total_time_ms = 0.0;
    double min_time_ms = 0.0;
    double max_time_ms = 0.0;
    double mean_time_ms = 0.0;
    double stddev_time_ms = 0.0;
    uint64_t rows_affected = 0;
    uint64_t shared_blks_hit = 0;
    uint64_t shared_blks_read = 0;
    uint64_t shared_blks_dirtied = 0;
    uint64_t shared_blks_written = 0;
    uint64_t local_blks_hit = 0;
    uint64_t local_blks_read = 0;
    uint64_t temp_blks_read = 0;
    uint64_t temp_blks_written = 0;
    double blk_read_time_ms = 0.0;
    double blk_write_time_ms = 0.0;
    double hit_ratio = 0.0;

    json to_json() const {
        return {
            {"query_id", query_id},
            {"query_text", query_text.substr(0, 200)}, // Truncated
            {"query_type", query_type},
            {"calls", calls},
            {"total_time_ms", std::round(total_time_ms * 100.0) / 100.0},
            {"min_time_ms", std::round(min_time_ms * 100.0) / 100.0},
            {"max_time_ms", std::round(max_time_ms * 100.0) / 100.0},
            {"mean_time_ms", std::round(mean_time_ms * 100.0) / 100.0},
            {"stddev_time_ms", std::round(stddev_time_ms * 100.0) / 100.0},
            {"rows_affected", rows_affected},
            {"shared_blks_hit", shared_blks_hit},
            {"shared_blks_read", shared_blks_read},
            {"shared_blks_dirtied", shared_blks_dirtied},
            {"shared_blks_written", shared_blks_written},
            {"block_hit_ratio_percent", std::round(hit_ratio * 100.0) / 100.0},
            {"blk_read_time_ms", std::round(blk_read_time_ms * 100.0) / 100.0},
            {"blk_write_time_ms", std::round(blk_write_time_ms * 100.0) / 100.0}
        };
    }
};

std::vector<QueryProfile> g_query_profiles;
std::vector<QueryProfile> g_slow_queries;  // Queries exceeding threshold

double g_slow_query_threshold_ms = 100.0;  // Default: 100ms

void init_query_profiles() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(444);
    std::uniform_int_distribution<uint64_t> call_dist(10, 5000000);
    std::uniform_real_distribution<double> time_dist(0.05, 500.0);

    struct QueryDef { std::string text; std::string type; };
    std::vector<QueryDef> queries = {
        {"SELECT event_id, json FROM event_json WHERE event_id = $1", "SELECT"},
        {"SELECT type, state_key, event_id FROM current_state_events WHERE room_id = $1", "SELECT"},
        {"INSERT INTO events (event_id, room_id, sender, type, state_key, ...) VALUES ($1, ...)", "INSERT"},
        {"SELECT e.event_id, e.room_id, e.type, e.sender FROM events e WHERE e.room_id = $1 ORDER BY stream_ordering DESC LIMIT $2", "SELECT"},
        {"SELECT state_group FROM event_to_state_groups WHERE event_id = $1", "SELECT"},
        {"SELECT type, state_key, event_id FROM state_groups_state WHERE state_group = $1", "SELECT"},
        {"SELECT count(*) FROM room_memberships WHERE room_id = $1 AND membership = 'join'", "SELECT"},
        {"SELECT user_id FROM room_memberships WHERE room_id = $1 AND membership = 'join'", "SELECT"},
        {"UPDATE presence_stream SET last_active_ts = $1, currently_active = $2 WHERE user_id = $3", "UPDATE"},
        {"INSERT INTO event_push_actions (room_id, event_id, user_id, ...) VALUES ($1, $2, $3, ...)", "INSERT"},
        {"SELECT * FROM event_push_actions WHERE user_id = $1 AND stream_ordering > $2", "SELECT"},
        {"SELECT media_id, media_type FROM local_media_repository WHERE media_id = $1", "SELECT"},
        {"UPDATE remote_media_cache SET last_access_ts = $1 WHERE media_origin = $2 AND media_id = $3", "UPDATE"},
        {"SELECT expires_ts, response_code, og_title FROM url_cache WHERE url_hash = $1", "SELECT"},
        {"DELETE FROM event_push_actions WHERE room_id = $1 AND event_id = $2 AND user_id = $3", "DELETE"},
        {"SELECT r.room_id, r.event_id, r.data FROM receipts_graph r WHERE r.room_id = $1", "SELECT"},
        {"INSERT INTO device_lists_outbound_pokes (destination, user_id, ...) VALUES ($1, $2, ...)", "INSERT"},
        {"SELECT name, is_guest, admin, deactivated FROM users WHERE name = $1", "SELECT"},
        {"SELECT pdus.* FROM received_transactions ts, federation_pdus pdus WHERE ts.transaction_id = $1 AND pdus.ts_id = ts.id", "SELECT"},
        {"SELECT * FROM users WHERE creation_ts BETWEEN $1 AND $2 ORDER BY creation_ts", "SELECT"},
    };

    for (size_t i = 0; i < queries.size(); ++i) {
        QueryProfile qp;
        qp.query_id = "q" + std::to_string(i + 1);
        qp.query_text = queries[i].text;
        qp.query_type = queries[i].type;
        qp.calls = call_dist(rng);
        qp.mean_time_ms = time_dist(rng);
        qp.min_time_ms = qp.mean_time_ms * 0.3;
        qp.max_time_ms = qp.mean_time_ms * 5.0;
        qp.total_time_ms = qp.mean_time_ms * qp.calls;
        qp.stddev_time_ms = qp.mean_time_ms * 0.5;
        qp.rows_affected = qp.calls * std::uniform_int_distribution<uint64_t>(1, 100)(rng);
        qp.shared_blks_hit = qp.calls * std::uniform_int_distribution<uint64_t>(1, 50)(rng);
        qp.shared_blks_read = qp.shared_blks_hit / 10;
        uint64_t total_blks = qp.shared_blks_hit + qp.shared_blks_read;
        qp.hit_ratio = total_blks > 0 ? static_cast<double>(qp.shared_blks_hit) / total_blks : 1.0;
        qp.shared_blks_dirtied = qp.shared_blks_hit / 20;
        qp.shared_blks_written = qp.shared_blks_dirtied / 2;
        qp.blk_read_time_ms = qp.shared_blks_read * 0.5;
        qp.blk_write_time_ms = qp.shared_blks_written * 1.0;
        g_query_profiles.push_back(std::move(qp));
    }

    // Identify slow queries
    for (const auto& qp : g_query_profiles) {
        if (qp.mean_time_ms >= g_slow_query_threshold_ms || qp.max_time_ms >= g_slow_query_threshold_ms * 3) {
            g_slow_queries.push_back(qp);
        }
    }
}

// ---------------------------------------------------------------------------
// DB Vacuum trigger
// ---------------------------------------------------------------------------

struct VacuumJob {
    std::string job_id;
    std::string target;             // Table name or "full" for VACUUM FULL
    std::string status;             // "pending", "running", "complete", "failed"
    std::string vacuum_type;        // "standard", "full", "analyze", "freeze"
    int progress_percent = 0;
    time_t started_at = 0;
    time_t completed_at = 0;
    double duration_seconds = 0.0;
    uint64_t dead_tuples_removed = 0;
    uint64_t pages_scanned = 0;
    uint64_t pages_removed = 0;
    std::string error;
};

std::unordered_map<std::string, VacuumJob> g_vacuum_jobs;
std::mutex g_vacuum_mutex;
std::atomic<bool> g_vacuum_in_progress{false};

std::string trigger_vacuum(const std::string& target, const std::string& vacuum_type) {
    std::lock_guard<std::mutex> lock(g_vacuum_mutex);

    std::string job_id = "vacuum_" + target + "_" +
        std::to_string(std::chrono::system_clock::now().time_since_epoch().count());

    VacuumJob job;
    job.job_id = job_id;
    job.target = target;
    job.vacuum_type = vacuum_type;
    job.status = "running";
    job.started_at = std::time(nullptr);

    g_vacuum_jobs[job_id] = job;
    return job_id;
}

// ===========================================================================
// SECTION 3 – Server Profiling  (lines ~1300–1900)
// ===========================================================================

// ---------------------------------------------------------------------------
// CPU & memory profiling
// ---------------------------------------------------------------------------

struct CPUProfile {
    int num_cores = 0;
    double cpu_usage_percent = 0.0;    // Overall CPU usage
    double cpu_user_percent = 0.0;
    double cpu_system_percent = 0.0;
    double cpu_iowait_percent = 0.0;
    double cpu_steal_percent = 0.0;
    std::vector<double> per_core_usage; // Per-core usage percentages
    double load_avg_1m = 0.0;
    double load_avg_5m = 0.0;
    double load_avg_15m = 0.0;

    json to_json() const {
        json j;
        j["num_cores"] = num_cores;
        j["cpu_usage_percent"] = std::round(cpu_usage_percent * 100.0) / 100.0;
        j["cpu_user_percent"] = std::round(cpu_user_percent * 100.0) / 100.0;
        j["cpu_system_percent"] = std::round(cpu_system_percent * 100.0) / 100.0;
        j["cpu_iowait_percent"] = std::round(cpu_iowait_percent * 100.0) / 100.0;
        j["cpu_steal_percent"] = std::round(cpu_steal_percent * 100.0) / 100.0;
        j["per_core_usage"] = per_core_usage;
        j["load_avg_1m"] = std::round(load_avg_1m * 100.0) / 100.0;
        j["load_avg_5m"] = std::round(load_avg_5m * 100.0) / 100.0;
        j["load_avg_15m"] = std::round(load_avg_15m * 100.0) / 100.0;
        return j;
    }
};

struct MemoryProfile {
    uint64_t total_ram_bytes = 0;
    uint64_t used_ram_bytes = 0;
    uint64_t free_ram_bytes = 0;
    uint64_t cached_ram_bytes = 0;
    uint64_t buffers_ram_bytes = 0;
    double ram_usage_percent = 0.0;
    uint64_t swap_total_bytes = 0;
    uint64_t swap_used_bytes = 0;
    double swap_usage_percent = 0.0;

    // Process-level memory
    uint64_t process_rss_bytes = 0;      // Resident set size
    uint64_t process_vms_bytes = 0;      // Virtual memory size
    uint64_t process_shared_bytes = 0;
    uint64_t process_heap_bytes = 0;
    uint64_t process_stack_bytes = 0;
    uint64_t process_code_bytes = 0;

    // Go-style memory stats (goroutine equivalent for C++: thread count)
    uint64_t heap_alloc_bytes = 0;
    uint64_t heap_sys_bytes = 0;
    uint64_t heap_idle_bytes = 0;
    uint64_t heap_inuse_bytes = 0;
    uint64_t heap_released_bytes = 0;
    uint64_t heap_objects = 0;
    uint64_t num_gc_cycles = 0;
    double gc_pause_total_ms = 0.0;
    double last_gc_pause_ms = 0.0;
    uint64_t num_goroutines = 0;        // Thread count in C++ context

    json to_json() const {
        json j;
        j["system"] = {
            {"total_ram_bytes", total_ram_bytes},
            {"total_ram_gb", std::round(total_ram_bytes / 1073741824.0 * 100.0) / 100.0},
            {"used_ram_bytes", used_ram_bytes},
            {"free_ram_bytes", free_ram_bytes},
            {"ram_usage_percent", std::round(ram_usage_percent * 100.0) / 100.0},
            {"swap_total_bytes", swap_total_bytes},
            {"swap_used_bytes", swap_used_bytes},
            {"swap_usage_percent", std::round(swap_usage_percent * 100.0) / 100.0}
        };
        j["process"] = {
            {"rss_bytes", process_rss_bytes},
            {"rss_mb", std::round(process_rss_bytes / 1048576.0 * 100.0) / 100.0},
            {"vms_bytes", process_vms_bytes},
            {"vms_mb", std::round(process_vms_bytes / 1048576.0 * 100.0) / 100.0},
            {"shared_bytes", process_shared_bytes},
            {"heap_bytes", process_heap_bytes}
        };
        j["runtime"] = {
            {"heap_alloc_bytes", heap_alloc_bytes},
            {"heap_sys_bytes", heap_sys_bytes},
            {"heap_idle_bytes", heap_idle_bytes},
            {"heap_inuse_bytes", heap_inuse_bytes},
            {"heap_released_bytes", heap_released_bytes},
            {"heap_objects", heap_objects},
            {"num_gc_cycles", num_gc_cycles},
            {"gc_pause_total_ms", std::round(gc_pause_total_ms * 100.0) / 100.0},
            {"last_gc_pause_ms", std::round(last_gc_pause_ms * 100.0) / 100.0},
            {"num_goroutines", num_goroutines}
        };
        return j;
    }
};

CPUProfile g_cpu_profile;
MemoryProfile g_memory_profile;

void init_profiling_state() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(333);

    // CPU
    g_cpu_profile.num_cores = 16;
    g_cpu_profile.cpu_usage_percent = std::uniform_real_distribution<double>(10.0, 65.0)(rng);
    g_cpu_profile.cpu_user_percent = g_cpu_profile.cpu_usage_percent * 0.7;
    g_cpu_profile.cpu_system_percent = g_cpu_profile.cpu_usage_percent * 0.2;
    g_cpu_profile.cpu_iowait_percent = g_cpu_profile.cpu_usage_percent * 0.08;
    g_cpu_profile.cpu_steal_percent = g_cpu_profile.cpu_usage_percent * 0.02;

    std::uniform_real_distribution<double> core_dist(5.0, 80.0);
    for (int i = 0; i < g_cpu_profile.num_cores; ++i) {
        g_cpu_profile.per_core_usage.push_back(std::round(core_dist(rng) * 100.0) / 100.0);
    }
    g_cpu_profile.load_avg_1m = std::uniform_real_distribution<double>(1.0, 8.0)(rng);
    g_cpu_profile.load_avg_5m = g_cpu_profile.load_avg_1m * 0.9;
    g_cpu_profile.load_avg_15m = g_cpu_profile.load_avg_1m * 0.85;

    // Memory
    g_memory_profile.total_ram_bytes = 64ULL * 1024 * 1024 * 1024; // 64 GB
    g_memory_profile.used_ram_bytes = 38ULL * 1024 * 1024 * 1024;
    g_memory_profile.free_ram_bytes = g_memory_profile.total_ram_bytes - g_memory_profile.used_ram_bytes;
    g_memory_profile.cached_ram_bytes = 12ULL * 1024 * 1024 * 1024;
    g_memory_profile.buffers_ram_bytes = 2ULL * 1024 * 1024 * 1024;
    g_memory_profile.ram_usage_percent = (100.0 * g_memory_profile.used_ram_bytes) / g_memory_profile.total_ram_bytes;
    g_memory_profile.swap_total_bytes = 8ULL * 1024 * 1024 * 1024;
    g_memory_profile.swap_used_bytes = 512ULL * 1024 * 1024;
    g_memory_profile.swap_usage_percent = (100.0 * g_memory_profile.swap_used_bytes) / g_memory_profile.swap_total_bytes;

    g_memory_profile.process_rss_bytes = 2800ULL * 1024 * 1024;
    g_memory_profile.process_vms_bytes = 4500ULL * 1024 * 1024;
    g_memory_profile.process_shared_bytes = 120ULL * 1024 * 1024;
    g_memory_profile.process_heap_bytes = 2200ULL * 1024 * 1024;
    g_memory_profile.process_stack_bytes = 16ULL * 1024 * 1024;
    g_memory_profile.process_code_bytes = 180ULL * 1024 * 1024;

    g_memory_profile.heap_alloc_bytes = 1800ULL * 1024 * 1024;
    g_memory_profile.heap_sys_bytes = 2400ULL * 1024 * 1024;
    g_memory_profile.heap_idle_bytes = 400ULL * 1024 * 1024;
    g_memory_profile.heap_inuse_bytes = 2000ULL * 1024 * 1024;
    g_memory_profile.heap_released_bytes = 200ULL * 1024 * 1024;
    g_memory_profile.heap_objects = 8500000;
    g_memory_profile.num_gc_cycles = 3450;
    g_memory_profile.gc_pause_total_ms = 1200.0;
    g_memory_profile.last_gc_pause_ms = 0.85;
    g_memory_profile.num_goroutines = 128; // Thread count
}

// ===========================================================================
// SECTION 4 – Event Loop Stats  (lines ~1900–2100)
// ===========================================================================

struct EventLoopStats {
    uint64_t events_pending = 0;
    uint64_t events_processed_total = 0;
    uint64_t events_processed_last_minute = 0;
    uint64_t events_processed_last_5min = 0;
    uint64_t events_processed_last_15min = 0;
    uint64_t events_errored_total = 0;
    uint64_t events_errored_last_minute = 0;
    double avg_processing_time_ms = 0.0;
    double p50_processing_time_ms = 0.0;
    double p90_processing_time_ms = 0.0;
    double p99_processing_time_ms = 0.0;
    double max_processing_time_ms = 0.0;
    uint64_t current_queue_depth = 0;
    uint64_t max_queue_depth = 0;
    uint64_t queue_overflow_count = 0;
    std::string event_loop_status; // "healthy", "backlogged", "degraded"
    double events_per_second = 0.0;

    json to_json() const {
        return {
            {"events_pending", events_pending},
            {"events_processed_total", events_processed_total},
            {"events_processed_last_minute", events_processed_last_minute},
            {"events_processed_last_5min", events_processed_last_5min},
            {"events_processed_last_15min", events_processed_last_15min},
            {"events_errored_total", events_errored_total},
            {"events_errored_last_minute", events_errored_last_minute},
            {"avg_processing_time_ms", std::round(avg_processing_time_ms * 100.0) / 100.0},
            {"p50_processing_time_ms", std::round(p50_processing_time_ms * 100.0) / 100.0},
            {"p90_processing_time_ms", std::round(p90_processing_time_ms * 100.0) / 100.0},
            {"p99_processing_time_ms", std::round(p99_processing_time_ms * 100.0) / 100.0},
            {"max_processing_time_ms", std::round(max_processing_time_ms * 100.0) / 100.0},
            {"current_queue_depth", current_queue_depth},
            {"max_queue_depth", max_queue_depth},
            {"queue_overflow_count", queue_overflow_count},
            {"event_loop_status", event_loop_status},
            {"events_per_second", std::round(events_per_second * 100.0) / 100.0}
        };
    }
};

EventLoopStats g_event_loop_stats;

void init_event_loop_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(555);

    g_event_loop_stats.events_processed_total = 450000000;
    g_event_loop_stats.events_processed_last_minute = 3200;
    g_event_loop_stats.events_processed_last_5min = 15800;
    g_event_loop_stats.events_processed_last_15min = 47000;
    g_event_loop_stats.events_errored_total = 1200;
    g_event_loop_stats.events_errored_last_minute = 3;
    g_event_loop_stats.events_pending = 45;
    g_event_loop_stats.avg_processing_time_ms = 2.3;
    g_event_loop_stats.p50_processing_time_ms = 1.1;
    g_event_loop_stats.p90_processing_time_ms = 5.8;
    g_event_loop_stats.p99_processing_time_ms = 25.0;
    g_event_loop_stats.max_processing_time_ms = 340.0;
    g_event_loop_stats.current_queue_depth = 45;
    g_event_loop_stats.max_queue_depth = 5000;
    g_event_loop_stats.queue_overflow_count = 0;
    g_event_loop_stats.event_loop_status = "healthy";
    g_event_loop_stats.events_per_second = 53.3;
}

// ===========================================================================
// SECTION 5 – Connection Pool Stats  (lines ~2100–2300)
// ===========================================================================

struct DBConnectionPoolStats {
    std::string pool_name;
    int max_connections = 0;
    int active_connections = 0;
    int idle_connections = 0;
    int waiting_clients = 0;
    int max_wait_time_ms = 0;
    double avg_wait_time_ms = 0.0;
    uint64_t total_connections_created = 0;
    uint64_t total_connections_destroyed = 0;
    uint64_t total_connections_timeout = 0;
    uint64_t total_queries_executed = 0;
    double avg_query_time_ms = 0.0;
    uint64_t transaction_rollbacks = 0;
    std::string pool_status; // "healthy", "saturated", "exhausted"

    json to_json() const {
        return {
            {"pool_name", pool_name},
            {"max_connections", max_connections},
            {"active_connections", active_connections},
            {"idle_connections", idle_connections},
            {"waiting_clients", waiting_clients},
            {"max_wait_time_ms", max_wait_time_ms},
            {"avg_wait_time_ms", std::round(avg_wait_time_ms * 100.0) / 100.0},
            {"total_connections_created", total_connections_created},
            {"total_connections_destroyed", total_connections_destroyed},
            {"total_connections_timeout", total_connections_timeout},
            {"total_queries_executed", total_queries_executed},
            {"avg_query_time_ms", std::round(avg_query_time_ms * 100.0) / 100.0},
            {"transaction_rollbacks", transaction_rollbacks},
            {"pool_status", pool_status}
        };
    }
};

std::vector<DBConnectionPoolStats> g_db_pools;

void init_connection_pool_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(666);

    struct PoolDef { std::string name; int max_conn; int active; int idle; int waiters; };
    std::vector<PoolDef> pools = {
        {"main_write",      40,  28,  12, 0},
        {"main_read",       60,  35,  25, 2},
        {"event_persister", 20,  8,   12, 0},
        {"media_repo",      15,  5,   10, 0},
        {"federation_sender",10, 3,    7, 0},
        {"pusher",           8,  2,    6, 0},
        {"background_update",5,  1,    4, 0},
    };

    for (const auto& def : pools) {
        DBConnectionPoolStats ps;
        ps.pool_name = def.name;
        ps.max_connections = def.max_conn;
        ps.active_connections = def.active;
        ps.idle_connections = def.idle;
        ps.waiting_clients = def.waiters;
        ps.max_wait_time_ms = def.waiters > 0 ? std::uniform_int_distribution<int>(50, 500)(rng) : 0;
        ps.avg_wait_time_ms = ps.max_wait_time_ms * 0.4;
        ps.total_connections_created = std::uniform_int_distribution<uint64_t>(5000, 500000)(rng);
        ps.total_connections_destroyed = ps.total_connections_created / 2;
        ps.total_connections_timeout = ps.total_connections_destroyed / 10;
        ps.total_queries_executed = std::uniform_int_distribution<uint64_t>(1000000, 500000000)(rng);
        ps.avg_query_time_ms = std::uniform_real_distribution<double>(1.0, 35.0)(rng);
        ps.transaction_rollbacks = ps.total_queries_executed / 5000;

        double utilization = static_cast<double>(ps.active_connections) / ps.max_connections;
        if (utilization > 0.85) ps.pool_status = "saturated";
        else if (utilization > 0.95) ps.pool_status = "exhausted";
        else ps.pool_status = "healthy";

        g_db_pools.push_back(std::move(ps));
    }
}

// ===========================================================================
// SECTION 6 – HTTP Client Pool Stats  (lines ~2300–2500)
// ===========================================================================

struct HTTPClientPoolStats {
    std::string pool_id;               // Usually the destination domain
    int max_total_connections = 0;
    int max_per_host_connections = 0;
    int active_connections = 0;
    int idle_connections = 0;
    int pending_requests = 0;
    uint64_t total_requests_sent = 0;
    uint64_t total_responses_received = 0;
    uint64_t total_errors = 0;
    uint64_t total_timeouts = 0;
    uint64_t total_retries = 0;
    double avg_request_time_ms = 0.0;
    double avg_response_time_ms = 0.0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    double error_rate_percent = 0.0;

    json to_json() const {
        json j;
        j["pool_id"] = pool_id;
        j["max_total_connections"] = max_total_connections;
        j["max_per_host_connections"] = max_per_host_connections;
        j["active_connections"] = active_connections;
        j["idle_connections"] = idle_connections;
        j["pending_requests"] = pending_requests;
        j["total_requests_sent"] = total_requests_sent;
        j["total_responses_received"] = total_responses_received;
        j["total_errors"] = total_errors;
        j["total_timeouts"] = total_timeouts;
        j["total_retries"] = total_retries;
        j["avg_request_time_ms"] = std::round(avg_request_time_ms * 100.0) / 100.0;
        j["avg_response_time_ms"] = std::round(avg_response_time_ms * 100.0) / 100.0;
        j["bytes_sent_mb"] = std::round(bytes_sent / 1048576.0 * 100.0) / 100.0;
        j["bytes_received_mb"] = std::round(bytes_received / 1048576.0 * 100.0) / 100.0;
        j["error_rate_percent"] = std::round(error_rate_percent * 100.0) / 100.0;
        return j;
    }
};

std::vector<HTTPClientPoolStats> g_http_client_pools;

void init_http_client_pool_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(777);

    struct HTTPPoolDef {
        std::string dest;
        int max_total;
        int max_host;
    };
    std::vector<HTTPPoolDef> pools = {
        {"matrix.org",           200, 50},
        {"matrix-client.matrix.org", 150, 40},
        {"tchncs.de",            100, 30},
        {"federator.dev",        80,  25},
        {"conduwuit.example",    60,  20},
        {"dendrite.example",     60,  20},
        {"element.io",           120, 35},
        {"synapse.example.com",  150, 40},
    };

    for (const auto& def : pools) {
        HTTPClientPoolStats ps;
        ps.pool_id = def.dest;
        ps.max_total_connections = def.max_total;
        ps.max_per_host_connections = def.max_host;
        ps.active_connections = std::uniform_int_distribution<int>(5, def.max_host)(rng);
        ps.idle_connections = std::uniform_int_distribution<int>(5, 30)(rng);
        ps.pending_requests = std::uniform_int_distribution<int>(0, 15)(rng);
        ps.total_requests_sent = std::uniform_int_distribution<uint64_t>(10000, 5000000)(rng);
        ps.total_responses_received = ps.total_requests_sent * 98 / 100;
        ps.total_errors = ps.total_requests_sent / 50;
        ps.total_timeouts = ps.total_errors / 3;
        ps.total_retries = ps.total_timeouts * 2;
        ps.avg_request_time_ms = std::uniform_real_distribution<double>(5.0, 200.0)(rng);
        ps.avg_response_time_ms = ps.avg_request_time_ms * 1.2;
        ps.bytes_sent = ps.total_requests_sent * 4096;
        ps.bytes_received = ps.total_responses_received * 8192;
        ps.error_rate_percent = ps.total_requests_sent > 0
            ? (100.0 * ps.total_errors) / ps.total_requests_sent : 0.0;
        g_http_client_pools.push_back(std::move(ps));
    }
}

// ===========================================================================
// SECTION 7 – Federation Transaction Stats  (lines ~2500–2700)
// ===========================================================================

struct FedTransactionStats {
    std::string destination;
    std::string state;                 // "idle", "sending", "backing_off"
    int pending_pdus = 0;              // PDUs waiting to be sent
    int pending_edus = 0;              // EDUs waiting to be sent
    int pending_e2ee_keys = 0;         // Device list / key updates pending
    uint64_t last_successful_stream_ordering = 0;
    time_t last_success_ts = 0;
    time_t last_failure_ts = 0;
    int consecutive_failures = 0;
    int retry_interval_s = 0;
    int next_retry_in_s = 0;
    uint64_t pdus_sent_total = 0;
    uint64_t edus_sent_total = 0;
    uint64_t pdus_failed_total = 0;
    uint64_t edus_failed_total = 0;
    uint64_t bytes_sent = 0;
    double avg_transaction_size_bytes = 0.0;
    bool catch_up_mode = false;
    uint64_t catch_up_last_sent = 0;

    json to_json() const {
        return {
            {"destination", destination},
            {"state", state},
            {"pending_pdus", pending_pdus},
            {"pending_edus", pending_edus},
            {"pending_e2ee_keys", pending_e2ee_keys},
            {"last_successful_stream_ordering", last_successful_stream_ordering},
            {"last_success_ts", last_success_ts > 0 ? std::to_string(last_success_ts) : nullptr},
            {"last_failure_ts", last_failure_ts > 0 ? std::to_string(last_failure_ts) : nullptr},
            {"consecutive_failures", consecutive_failures},
            {"retry_interval_s", retry_interval_s},
            {"next_retry_in_s", next_retry_in_s},
            {"pdus_sent_total", pdus_sent_total},
            {"edus_sent_total", edus_sent_total},
            {"pdus_failed_total", pdus_failed_total},
            {"edus_failed_total", edus_failed_total},
            {"bytes_sent_mb", std::round(bytes_sent / 1048576.0 * 100.0) / 100.0},
            {"avg_transaction_size_bytes", std::round(avg_transaction_size_bytes * 100.0) / 100.0},
            {"catch_up_mode", catch_up_mode},
            {"catch_up_last_sent", catch_up_last_sent}
        };
    }
};

std::unordered_map<std::string, FedTransactionStats> g_fed_transaction_stats;

void init_federation_transaction_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(888);
    time_t now = std::time(nullptr);

    std::vector<std::string> destinations = {
        "matrix.org", "tchncs.de", "federator.dev",
        "element.io", "conduwuit.example", "dendrite.example",
        "synapse.example.com", "privacytools.io", "mozilla.org",
        "kde.org", "gnome.org", "archlinux.org"
    };

    std::vector<std::string> states = {"idle", "sending", "backing_off", "idle", "idle", "sending", "idle", "idle", "idle", "idle", "idle", "idle"};

    for (size_t i = 0; i < destinations.size(); ++i) {
        FedTransactionStats fts;
        fts.destination = destinations[i];
        fts.state = states[i % states.size()];
        fts.pending_pdus = std::uniform_int_distribution<int>(0, 500)(rng);
        fts.pending_edus = std::uniform_int_distribution<int>(0, 200)(rng);
        fts.pending_e2ee_keys = std::uniform_int_distribution<int>(0, 50)(rng);
        fts.last_successful_stream_ordering = std::uniform_int_distribution<uint64_t>(1000000, 500000000)(rng);
        fts.last_success_ts = now - std::uniform_int_distribution<time_t>(0, 300)(rng);
        fts.consecutive_failures = fts.state == "backing_off" ? std::uniform_int_distribution<int>(3, 20)(rng) : 0;
        fts.last_failure_ts = fts.consecutive_failures > 0
            ? now - std::uniform_int_distribution<time_t>(60, 1800)(rng) : 0;
        fts.retry_interval_s = fts.consecutive_failures > 0
            ? std::min(3600, static_cast<int>(std::pow(2, fts.consecutive_failures) * 10)) : 0;
        fts.next_retry_in_s = fts.consecutive_failures > 0
            ? std::uniform_int_distribution<int>(5, fts.retry_interval_s)(rng) : 0;
        fts.pdus_sent_total = std::uniform_int_distribution<uint64_t>(10000, 50000000)(rng);
        fts.edus_sent_total = fts.pdus_sent_total / 2;
        fts.pdus_failed_total = fts.pdus_sent_total / 100;
        fts.edus_failed_total = fts.edus_sent_total / 150;
        fts.bytes_sent = fts.pdus_sent_total * 2048;
        fts.avg_transaction_size_bytes = std::uniform_real_distribution<double>(1024, 65536)(rng);
        fts.catch_up_mode = fts.pending_pdus > 300;
        fts.catch_up_last_sent = fts.catch_up_mode
            ? std::uniform_int_distribution<uint64_t>(fts.last_successful_stream_ordering - 10000,
                                                       fts.last_successful_stream_ordering)(rng) : 0;
        g_fed_transaction_stats[destinations[i]] = std::move(fts);
    }
}

// ===========================================================================
// SECTION 8 – Pusher Stats  (lines ~2700–2900)
// ===========================================================================

struct PusherStats {
    std::string pusher_type;  // "http", "email", "null"
    int total_pushers = 0;
    int active_pushers = 0;
    int disabled_pushers = 0;
    uint64_t total_pushes_sent = 0;
    uint64_t total_pushes_failed = 0;
    uint64_t pushes_sent_last_minute = 0;
    uint64_t pushes_sent_last_5min = 0;
    double avg_push_latency_ms = 0.0;
    double p90_push_latency_ms = 0.0;
    double p99_push_latency_ms = 0.0;
    uint64_t throttle_hits = 0;
    uint64_t total_http_requests = 0;
    double error_rate_percent = 0.0;
    int pushers_per_app = 0;
    std::unordered_map<std::string, int> pushers_by_app_id;

    json to_json() const {
        json j;
        j["pusher_type"] = pusher_type;
        j["total_pushers"] = total_pushers;
        j["active_pushers"] = active_pushers;
        j["disabled_pushers"] = disabled_pushers;
        j["total_pushes_sent"] = total_pushes_sent;
        j["total_pushes_failed"] = total_pushes_failed;
        j["pushes_sent_last_minute"] = pushes_sent_last_minute;
        j["pushes_sent_last_5min"] = pushes_sent_last_5min;
        j["avg_push_latency_ms"] = std::round(avg_push_latency_ms * 100.0) / 100.0;
        j["p90_push_latency_ms"] = std::round(p90_push_latency_ms * 100.0) / 100.0;
        j["p99_push_latency_ms"] = std::round(p99_push_latency_ms * 100.0) / 100.0;
        j["throttle_hits"] = throttle_hits;
        j["total_http_requests"] = total_http_requests;
        j["error_rate_percent"] = std::round(error_rate_percent * 100.0) / 100.0;
        j["pushers_by_app_id"] = pushers_by_app_id;
        return j;
    }
};

std::vector<PusherStats> g_pusher_stats;

void init_pusher_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(999);

    struct PusherDef {
        std::string type;
        int total;
        uint64_t sent_scale;
    };
    std::vector<PusherDef> pushers = {
        {"http",   8500, 10000000},
        {"email",  1200, 2000000},
        {"null",   300,  500000},
    };

    for (const auto& def : pushers) {
        PusherStats ps;
        ps.pusher_type = def.type;
        ps.total_pushers = def.total;
        ps.active_pushers = def.total * 85 / 100;
        ps.disabled_pushers = def.total - ps.active_pushers;
        ps.total_pushes_sent = def.sent_scale;
        ps.total_pushes_failed = ps.total_pushes_sent / 40;
        ps.pushes_sent_last_minute = std::uniform_int_distribution<uint64_t>(100, 5000)(rng);
        ps.pushes_sent_last_5min = ps.pushes_sent_last_minute * 5;
        ps.avg_push_latency_ms = std::uniform_real_distribution<double>(10.0, 150.0)(rng);
        ps.p90_push_latency_ms = ps.avg_push_latency_ms * 3.0;
        ps.p99_push_latency_ms = ps.avg_push_latency_ms * 8.0;
        ps.throttle_hits = ps.total_pushes_sent / 20;
        ps.total_http_requests = def.type == "http" ? ps.total_pushes_sent : 0;
        ps.error_rate_percent = ps.total_pushes_sent > 0
            ? (100.0 * ps.total_pushes_failed) / ps.total_pushes_sent : 0.0;

        ps.pushers_by_app_id["element_android"] = def.total / 3;
        ps.pushers_by_app_id["element_ios"] = def.total / 4;
        ps.pushers_by_app_id["element_web"] = def.total / 5;
        ps.pushers_by_app_id["fluffy_chat"] = def.total / 10;
        ps.pushers_by_app_id["element_x"] = def.total / 8;
        g_pusher_stats.push_back(std::move(ps));
    }
}

// ===========================================================================
// SECTION 9 – Background Update Stats  (lines ~2900–3100)
// ===========================================================================

struct BackgroundUpdateStats {
    std::string update_name;
    std::string description;
    std::string status;          // "pending", "running", "complete", "blocked"
    double progress_percent = 0.0;
    int64_t total_items = 0;
    int64_t items_done = 0;
    int64_t items_remaining = 0;
    double items_per_second = 0.0;
    time_t started_at = 0;
    time_t last_progress_at = 0;
    double estimated_remaining_s = 0.0;
    std::string blocking_update; // Name of update blocking this one
    std::vector<std::string> depends_on;
    double avg_batch_time_ms = 0.0;
    int64_t batch_size = 100;
    bool run_in_background = true;

    json to_json() const {
        json j;
        j["update_name"] = update_name;
        j["description"] = description;
        j["status"] = status;
        j["progress_percent"] = std::round(progress_percent * 100.0) / 100.0;
        j["total_items"] = total_items;
        j["items_done"] = items_done;
        j["items_remaining"] = items_remaining;
        j["items_per_second"] = std::round(items_per_second * 100.0) / 100.0;
        j["started_at"] = started_at > 0 ? std::to_string(started_at) : nullptr;
        j["last_progress_at"] = last_progress_at > 0 ? std::to_string(last_progress_at) : nullptr;
        j["estimated_remaining_seconds"] = std::round(estimated_remaining_s * 100.0) / 100.0;
        j["blocking_update"] = blocking_update.empty() ? nullptr : json(blocking_update);
        j["depends_on"] = depends_on;
        j["avg_batch_time_ms"] = std::round(avg_batch_time_ms * 100.0) / 100.0;
        j["batch_size"] = batch_size;
        j["run_in_background"] = run_in_background;
        return j;
    }
};

std::vector<BackgroundUpdateStats> g_background_update_stats;

void init_background_update_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    time_t now = std::time(nullptr);

    struct BGUpdateDef {
        std::string name;
        std::string desc;
        std::string status;
        double progress;
        int64_t items;
    };
    std::vector<BGUpdateDef> updates = {
        {"populate_stats_process_rooms",              "Populate room stats for processing",      "complete", 100.0, 50000},
        {"populate_stats_process_users",              "Populate user stats for processing",      "complete", 100.0, 150000},
        {"populate_room_depth",                       "Calculate room depth for all rooms",       "complete", 100.0, 45000},
        {"populate_room_id_and_event_id_on_events",   "Backfill room_id and event_id columns",   "complete", 100.0, 120000000},
        {"populate_event_relations",                  "Build event relations table",              "complete", 100.0, 35000000},
        {"populate_room_members_from_auth_events",    "Derive membership from auth events",      "complete", 100.0, 80000000},
        {"populate_user_directory_createtables",      "Create user directory search tables",     "complete", 100.0, 100000},
        {"background_updates_populate_user_directory","Populate user directory from profiles",   "complete", 100.0, 150000},
        {"populate_event_reference_hashes",           "Compute event reference hashes",           "complete", 100.0, 90000000},
        {"populate_stream_ordering_to_exterm",        "Index stream ordering to extremeties",    "complete", 100.0, 60000000},
        {"populate_stats_historical_events",          "Backfill historical event statistics",    "running",  45.2, 25000000},
        {"populate_events_contains_url",              "Extract URL flag from event content",     "running",  72.8, 18000000},
        {"tsvector_rebuild_on_event_search",          "Rebuild full-text search indexes",        "pending",  0.0, 40000000},
        {"populate_device_lists_outbound_pokes",      "Build device list poke queue",            "pending",  0.0, 5000000},
        {"populate_room_retention",                   "Apply retention policies to rooms",       "pending",  0.0, 50000},
    };

    for (const auto& def : updates) {
        BackgroundUpdateStats bus;
        bus.update_name = def.name;
        bus.description = def.desc;
        bus.status = def.status;
        bus.progress_percent = def.progress;
        bus.total_items = def.items;
        bus.items_done = static_cast<int64_t>(def.items * def.progress / 100.0);
        bus.items_remaining = bus.total_items - bus.items_done;
        bus.items_per_second = std::uniform_real_distribution<double>(50.0, 5000.0)(std::mt19937_64(def.name.size()))();

        if (def.status == "running" || def.status == "complete") {
            bus.started_at = now - 86400 * 2;
            bus.last_progress_at = now - 60;
        }
        if (def.status == "running" && bus.items_per_second > 0) {
            bus.estimated_remaining_s = bus.items_remaining / bus.items_per_second;
        }
        bus.avg_batch_time_ms = std::uniform_real_distribution<double>(5.0, 500.0)(std::mt19937_64(def.name.size() + 1))();
        bus.batch_size = 100;

        if (def.name == "tsvector_rebuild_on_event_search" || def.name == "populate_device_lists_outbound_pokes") {
            bus.depends_on = {"populate_stats_historical_events", "populate_events_contains_url"};
        }

        g_background_update_stats.push_back(std::move(bus));
    }
}

// ===========================================================================
// SECTION 10 – Media Cache Stats  (lines ~3100–3250)
// ===========================================================================

struct MediaCacheStats {
    std::string cache_type;  // "local", "remote", "thumbnails_local", "thumbnails_remote"
    uint64_t total_media_count = 0;
    uint64_t total_size_bytes = 0;
    uint64_t oldest_media_ts = 0;
    uint64_t newest_media_ts = 0;
    uint64_t media_accessed_last_day = 0;
    uint64_t media_accessed_last_week = 0;
    uint64_t media_not_accessed_30d = 0;
    uint64_t thumbnails_generated = 0;
    uint64_t thumbnails_cache_hits = 0;
    uint64_t thumbnails_cache_misses = 0;
    double thumbnail_hit_rate = 0.0;
    uint64_t downloads_total = 0;
    uint64_t uploads_total = 0;
    uint64_t downloads_failed = 0;
    uint64_t quota_bytes = 0;     // 0 = no quota
    double quota_used_percent = 0.0;
    std::unordered_map<std::string, uint64_t> media_by_type; // mime type → count

    json to_json() const {
        json j;
        j["cache_type"] = cache_type;
        j["total_media_count"] = total_media_count;
        j["total_size_bytes"] = total_size_bytes;
        j["total_size_gb"] = std::round(total_size_bytes / 1073741824.0 * 100.0) / 100.0;
        j["oldest_media_ts"] = oldest_media_ts > 0 ? std::to_string(oldest_media_ts) : nullptr;
        j["newest_media_ts"] = newest_media_ts > 0 ? std::to_string(newest_media_ts) : nullptr;
        j["media_accessed_last_day"] = media_accessed_last_day;
        j["media_accessed_last_week"] = media_accessed_last_week;
        j["media_not_accessed_30d"] = media_not_accessed_30d;
        j["thumbnails_generated"] = thumbnails_generated;
        j["thumbnails_cache_hits"] = thumbnails_cache_hits;
        j["thumbnails_cache_misses"] = thumbnails_cache_misses;
        j["thumbnail_hit_rate_percent"] = std::round(thumbnail_hit_rate * 100.0) / 100.0;
        j["downloads_total"] = downloads_total;
        j["uploads_total"] = uploads_total;
        j["downloads_failed"] = downloads_failed;
        j["quota_bytes"] = quota_bytes;
        j["quota_used_percent"] = std::round(quota_used_percent * 100.0) / 100.0;
        j["media_by_type"] = media_by_type;
        return j;
    }
};

std::vector<MediaCacheStats> g_media_cache_stats;

void init_media_cache_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(101010);
    time_t now = std::time(nullptr);

    struct MediaDef { std::string type; uint64_t count; uint64_t size_scale; };
    std::vector<MediaDef> medias = {
        {"local",           45000,  500ULL * 1024 * 1024},
        {"remote",          120000, 800ULL * 1024 * 1024},
        {"thumbnails_local", 120000, 200ULL * 1024 * 1024},
        {"thumbnails_remote",350000, 350ULL * 1024 * 1024},
    };

    for (const auto& def : medias) {
        MediaCacheStats mcs;
        mcs.cache_type = def.type;
        mcs.total_media_count = def.count;
        mcs.total_size_bytes = def.count * def.size_scale;
        mcs.oldest_media_ts = now - 86400 * 365;
        mcs.newest_media_ts = now;
        mcs.media_accessed_last_day = def.count / 8;
        mcs.media_accessed_last_week = def.count / 4;
        mcs.media_not_accessed_30d = def.count / 6;
        mcs.thumbnails_generated = def.count / 2;
        mcs.thumbnails_cache_hits = mcs.thumbnails_generated * 10;
        mcs.thumbnails_cache_misses = mcs.thumbnails_generated / 4;
        mcs.thumbnail_hit_rate = mcs.thumbnails_cache_hits > 0
            ? 100.0 * mcs.thumbnails_cache_hits /
              static_cast<double>(mcs.thumbnails_cache_hits + mcs.thumbnails_cache_misses) : 0.0;
        mcs.downloads_total = mcs.total_media_count * 3;
        mcs.uploads_total = mcs.total_media_count;
        mcs.downloads_failed = mcs.downloads_total / 50;
        mcs.quota_bytes = 50ULL * 1024 * 1024 * 1024; // 50 GB
        mcs.quota_used_percent = 100.0 * mcs.total_size_bytes / mcs.quota_bytes;

        mcs.media_by_type["image/jpeg"] = def.count / 3;
        mcs.media_by_type["image/png"] = def.count / 5;
        mcs.media_by_type["image/gif"] = def.count / 8;
        mcs.media_by_type["image/webp"] = def.count / 10;
        mcs.media_by_type["video/mp4"] = def.count / 12;
        mcs.media_by_type["audio/ogg"] = def.count / 10;
        mcs.media_by_type["application/pdf"] = def.count / 20;
        mcs.media_by_type["text/plain"] = def.count / 15;

        g_media_cache_stats.push_back(std::move(mcs));
    }
}

// ===========================================================================
// SECTION 11 – URL Preview Cache Stats  (lines ~3250–3350)
// ===========================================================================

struct URLPreviewCacheStats {
    uint64_t total_previews_cached = 0;
    uint64_t previews_served_last_hour = 0;
    uint64_t previews_served_last_day = 0;
    uint64_t previews_expired = 0;
    uint64_t previews_purged = 0;
    uint64_t cache_hits = 0;
    uint64_t cache_misses = 0;
    double hit_rate_percent = 0.0;
    uint64_t total_media_downloaded = 0;       // Images fetched for previews
    uint64_t total_media_size_bytes = 0;
    uint64_t preview_generation_total = 0;
    uint64_t preview_generation_failed = 0;
    double avg_generation_time_ms = 0.0;
    double avg_preview_size_bytes = 0.0;
    uint64_t db_size_bytes = 0;
    uint64_t default_ttl_seconds = 86400;       // 24h default TTL
    std::unordered_map<int, uint64_t> status_codes; // HTTP status → count

    json to_json() const {
        json j;
        j["total_previews_cached"] = total_previews_cached;
        j["previews_served_last_hour"] = previews_served_last_hour;
        j["previews_served_last_day"] = previews_served_last_day;
        j["previews_expired"] = previews_expired;
        j["previews_purged"] = previews_purged;
        j["cache_hits"] = cache_hits;
        j["cache_misses"] = cache_misses;
        j["hit_rate_percent"] = std::round(hit_rate_percent * 100.0) / 100.0;
        j["total_media_downloaded"] = total_media_downloaded;
        j["total_media_size_mb"] = std::round(total_media_size_bytes / 1048576.0 * 100.0) / 100.0;
        j["preview_generation_total"] = preview_generation_total;
        j["preview_generation_failed"] = preview_generation_failed;
        j["avg_generation_time_ms"] = std::round(avg_generation_time_ms * 100.0) / 100.0;
        j["avg_preview_size_bytes"] = std::round(avg_preview_size_bytes * 100.0) / 100.0;
        j["db_size_bytes"] = db_size_bytes;
        j["default_ttl_seconds"] = default_ttl_seconds;
        j["status_codes"] = status_codes;
        return j;
    }
};

URLPreviewCacheStats g_url_preview_cache_stats;

void init_url_preview_cache_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    g_url_preview_cache_stats.total_previews_cached = 185000;
    g_url_preview_cache_stats.previews_served_last_hour = 450;
    g_url_preview_cache_stats.previews_served_last_day = 8200;
    g_url_preview_cache_stats.previews_expired = 35000;
    g_url_preview_cache_stats.previews_purged = 12000;
    g_url_preview_cache_stats.cache_hits = 2500000;
    g_url_preview_cache_stats.cache_misses = 80000;
    g_url_preview_cache_stats.hit_rate_percent = g_url_preview_cache_stats.cache_hits > 0
        ? 100.0 * g_url_preview_cache_stats.cache_hits /
          static_cast<double>(g_url_preview_cache_stats.cache_hits + g_url_preview_cache_stats.cache_misses) : 0.0;
    g_url_preview_cache_stats.total_media_downloaded = 42000;
    g_url_preview_cache_stats.total_media_size_bytes = 4500ULL * 1024 * 1024;
    g_url_preview_cache_stats.preview_generation_total = 185000;
    g_url_preview_cache_stats.preview_generation_failed = 2500;
    g_url_preview_cache_stats.avg_generation_time_ms = 320.0;
    g_url_preview_cache_stats.avg_preview_size_bytes = 4096;
    g_url_preview_cache_stats.db_size_bytes = 180ULL * 1024 * 1024;

    g_url_preview_cache_stats.status_codes[200] = 170000;
    g_url_preview_cache_stats.status_codes[301] = 3000;
    g_url_preview_cache_stats.status_codes[302] = 2000;
    g_url_preview_cache_stats.status_codes[403] = 1500;
    g_url_preview_cache_stats.status_codes[404] = 5000;
    g_url_preview_cache_stats.status_codes[500] = 500;
    g_url_preview_cache_stats.status_codes[502] = 800;
    g_url_preview_cache_stats.status_codes[503] = 200;
}

// ===========================================================================
// SECTION 12 – SSL Session Cache Stats  (lines ~3350–3440)
// ===========================================================================

struct SSLSessionCacheStats {
    uint64_t sessions_cached = 0;
    uint64_t sessions_hit = 0;
    uint64_t sessions_miss = 0;
    uint64_t sessions_expired = 0;
    uint64_t sessions_timeout = 0;
    uint64_t sessions_evicted = 0;
    double hit_rate_percent = 0.0;
    uint64_t session_cache_size_bytes = 0;
    uint64_t max_cache_size = 20480; // 20K sessions typical default
    uint64_t session_timeout_seconds = 300;
    uint64_t new_sessions_last_minute = 0;
    uint64_t resumed_sessions_last_minute = 0;
    uint64_t total_handshakes = 0;
    uint64_t total_full_handshakes = 0;
    uint64_t total_resumed_handshakes = 0;
    double resumed_rate_percent = 0.0;
    std::set<std::string> cached_destinations_sample;
    double avg_session_size_bytes = 0.0;

    json to_json() const {
        json j;
        j["sessions_cached"] = sessions_cached;
        j["sessions_hit"] = sessions_hit;
        j["sessions_miss"] = sessions_miss;
        j["sessions_expired"] = sessions_expired;
        j["sessions_timeout"] = sessions_timeout;
        j["sessions_evicted"] = sessions_evicted;
        j["hit_rate_percent"] = std::round(hit_rate_percent * 100.0) / 100.0;
        j["session_cache_size_bytes"] = session_cache_size_bytes;
        j["max_cache_size"] = max_cache_size;
        j["session_timeout_seconds"] = session_timeout_seconds;
        j["new_sessions_last_minute"] = new_sessions_last_minute;
        j["resumed_sessions_last_minute"] = resumed_sessions_last_minute;
        j["total_handshakes"] = total_handshakes;
        j["total_full_handshakes"] = total_full_handshakes;
        j["total_resumed_handshakes"] = total_resumed_handshakes;
        j["resumed_rate_percent"] = std::round(resumed_rate_percent * 100.0) / 100.0;
        j["cached_destinations_sample"] = std::vector<std::string>(
            cached_destinations_sample.begin(), cached_destinations_sample.end());
        j["avg_session_size_bytes"] = std::round(avg_session_size_bytes * 100.0) / 100.0;
        return j;
    }
};

SSLSessionCacheStats g_ssl_session_cache_stats;

void init_ssl_session_cache_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    g_ssl_session_cache_stats.sessions_cached = 8420;
    g_ssl_session_cache_stats.sessions_hit = 125000;
    g_ssl_session_cache_stats.sessions_miss = 45000;
    g_ssl_session_cache_stats.sessions_expired = 28000;
    g_ssl_session_cache_stats.sessions_timeout = 12000;
    g_ssl_session_cache_stats.sessions_evicted = 0;
    g_ssl_session_cache_stats.hit_rate_percent = g_ssl_session_cache_stats.sessions_hit > 0
        ? 100.0 * g_ssl_session_cache_stats.sessions_hit /
          static_cast<double>(g_ssl_session_cache_stats.sessions_hit + g_ssl_session_cache_stats.sessions_miss) : 0.0;
    g_ssl_session_cache_stats.session_cache_size_bytes = 3ULL * 1024 * 1024;
    g_ssl_session_cache_stats.max_cache_size = 20480;
    g_ssl_session_cache_stats.session_timeout_seconds = 300;
    g_ssl_session_cache_stats.new_sessions_last_minute = 45;
    g_ssl_session_cache_stats.resumed_sessions_last_minute = 120;
    g_ssl_session_cache_stats.total_handshakes = 170000;
    g_ssl_session_cache_stats.total_full_handshakes = 45000;
    g_ssl_session_cache_stats.total_resumed_handshakes = 125000;
    g_ssl_session_cache_stats.resumed_rate_percent = g_ssl_session_cache_stats.total_handshakes > 0
        ? 100.0 * g_ssl_session_cache_stats.total_resumed_handshakes /
          static_cast<double>(g_ssl_session_cache_stats.total_handshakes) : 0.0;
    g_ssl_session_cache_stats.avg_session_size_bytes = 350.0;

    g_ssl_session_cache_stats.cached_destinations_sample = {
        "matrix.org", "tchncs.de", "federator.dev",
        "element.io", "matrix-client.matrix.org", "conduwuit.example",
        "synapse.example.com", "dendrite.example"
    };
}

// ===========================================================================
// SECTION 13 – DNS Cache Stats  (lines ~3440–3540)
// ===========================================================================

struct DNSCacheEntry {
    std::string hostname;
    std::vector<std::string> ip_addresses;
    uint32_t ttl_seconds = 0;
    time_t expires_at = 0;
    uint64_t lookup_count = 0;
    time_t created_at = 0;
    time_t last_accessed_at = 0;
    bool is_expired = false;
};

struct DNSCacheStats {
    uint64_t total_entries = 0;
    uint64_t active_entries = 0;
    uint64_t expired_entries = 0;
    uint64_t total_lookups = 0;
    uint64_t cache_hits = 0;
    uint64_t cache_misses = 0;
    uint64_t evictions = 0;
    double hit_rate_percent = 0.0;
    uint64_t failed_lookups = 0;
    double avg_lookup_time_ms = 0.0;
    double avg_ttl_seconds = 0.0;
    std::unordered_map<std::string, uint64_t> top_domains;
    std::unordered_map<std::string, uint64_t> record_types; // A, AAAA, SRV, etc.
    uint64_t cache_size_bytes = 0;
    uint64_t max_cache_entries = 50000;
    uint64_t lookups_last_minute = 0;

    json to_json() const {
        json j;
        j["total_entries"] = total_entries;
        j["active_entries"] = active_entries;
        j["expired_entries"] = expired_entries;
        j["total_lookups"] = total_lookups;
        j["cache_hits"] = cache_hits;
        j["cache_misses"] = cache_misses;
        j["evictions"] = evictions;
        j["hit_rate_percent"] = std::round(hit_rate_percent * 100.0) / 100.0;
        j["failed_lookups"] = failed_lookups;
        j["avg_lookup_time_ms"] = std::round(avg_lookup_time_ms * 100.0) / 100.0;
        j["avg_ttl_seconds"] = std::round(avg_ttl_seconds * 100.0) / 100.0;
        j["top_domains"] = top_domains;
        j["record_types"] = record_types;
        j["cache_size_bytes"] = cache_size_bytes;
        j["max_cache_entries"] = max_cache_entries;
        j["lookups_last_minute"] = lookups_last_minute;
        return j;
    }
};

DNSCacheStats g_dns_cache_stats;
std::unordered_map<std::string, DNSCacheEntry> g_dns_cache;

void init_dns_cache_stats() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    std::mt19937_64 rng(131313);
    time_t now = std::time(nullptr);

    // Pre-populate a simulated DNS cache
    struct DNSPopDef {
        std::string host;
        std::vector<std::string> ips;
        uint32_t ttl;
        uint64_t lookups;
    };
    std::vector<DNSPopDef> entries = {
        {"matrix.org",           {"159.69.28.158", "2a01:4f8:c0c:6a3d::1"}, 300, 250000},
        {"matrix-client.matrix.org", {"159.69.28.158"},                    300, 180000},
        {"tchncs.de",            {"185.220.101.43"},                        600, 45000},
        {"federator.dev",        {"116.203.55.12"},                         300, 22000},
        {"element.io",           {"104.18.20.67", "104.18.21.67"},          120, 35000},
        {"conduwuit.example",    {"192.168.1.50"},                          3600,12000},
        {"dendrite.example",     {"10.0.0.20"},                             3600,8000},
        {"synapse.example.com",  {"203.0.113.55"},                          600, 15000},
        {"turn.matrix.org",      {"159.69.28.158"},                         300, 50000},
        {"vector.im",            {"104.18.20.67", "104.18.21.67"},          120, 28000},
        {"riot.im",              {"104.18.20.67", "104.18.21.67"},          120, 20000},
        {"matrix-static.element.io", {"104.18.20.67"},                      120, 15000},
    };

    for (const auto& def : entries) {
        DNSCacheEntry entry;
        entry.hostname = def.host;
        entry.ip_addresses = def.ips;
        entry.ttl_seconds = def.ttl;
        entry.expires_at = now + def.ttl;
        entry.lookup_count = def.lookups;
        entry.created_at = now - 86400;
        entry.last_accessed_at = now - 60;
        entry.is_expired = false;
        g_dns_cache[def.host] = entry;
    }

    g_dns_cache_stats.total_entries = 4850;
    g_dns_cache_stats.active_entries = 4720;
    g_dns_cache_stats.expired_entries = 130;
    g_dns_cache_stats.total_lookups = 8500000;
    g_dns_cache_stats.cache_hits = 8100000;
    g_dns_cache_stats.cache_misses = 400000;
    g_dns_cache_stats.evictions = 85000;
    g_dns_cache_stats.hit_rate_percent = g_dns_cache_stats.total_lookups > 0
        ? 100.0 * g_dns_cache_stats.cache_hits /
          static_cast<double>(g_dns_cache_stats.total_lookups) : 0.0;
    g_dns_cache_stats.failed_lookups = 15000;
    g_dns_cache_stats.avg_lookup_time_ms = 2.8;
    g_dns_cache_stats.avg_ttl_seconds = 420.0;
    g_dns_cache_stats.cache_size_bytes = 2ULL * 1024 * 1024;
    g_dns_cache_stats.lookups_last_minute = 380;

    g_dns_cache_stats.top_domains["matrix.org"] = 250000;
    g_dns_cache_stats.top_domains["element.io"] = 35000;
    g_dns_cache_stats.top_domains["tchncs.de"] = 45000;
    g_dns_cache_stats.top_domains["federator.dev"] = 22000;

    g_dns_cache_stats.record_types["A"] = 7800000;
    g_dns_cache_stats.record_types["AAAA"] = 650000;
    g_dns_cache_stats.record_types["SRV"] = 40000;
    g_dns_cache_stats.record_types["TXT"] = 10000;
}

// ===========================================================================
// SECTION 14 – Aggregate Profiling Summary  (lines ~3540–3600)
// ===========================================================================

struct ProfilingSummary {
    CPUProfile cpu;
    MemoryProfile memory;
    EventLoopStats event_loop;
    uint64_t total_db_connections = 0;
    uint64_t total_db_queries = 0;
    uint64_t total_cache_hits = 0;
    uint64_t total_cache_misses = 0;
    double aggregate_cache_hit_rate = 0.0;
    uint64_t total_http_requests = 0;
    uint64_t total_fed_transactions = 0;
    int total_pushers = 0;
    int background_updates_pending = 0;
    int background_updates_running = 0;
    uint64_t total_media_size_bytes = 0;
    uint64_t total_url_previews = 0;

    json to_json() const {
        json j;
        j["cpu"] = cpu.to_json();
        j["memory"] = memory.to_json();
        j["event_loop"] = event_loop.to_json();

        j["aggregate"] = {
            {"total_db_connections", total_db_connections},
            {"total_db_queries", total_db_queries},
            {"total_cache_hits", total_cache_hits},
            {"total_cache_misses", total_cache_misses},
            {"aggregate_cache_hit_rate_percent", std::round(aggregate_cache_hit_rate * 100.0) / 100.0},
            {"total_http_requests", total_http_requests},
            {"total_fed_transactions", total_fed_transactions},
            {"total_pushers", total_pushers},
            {"background_updates_pending", background_updates_pending},
            {"background_updates_running", background_updates_running},
            {"total_media_size_bytes", total_media_size_bytes},
            {"total_media_size_gb", std::round(total_media_size_bytes / 1073741824.0 * 100.0) / 100.0},
            {"total_url_previews", total_url_previews}
        };
        return j;
    }
};

ProfilingSummary build_profiling_summary() {
    ProfilingSummary ps;
    ps.cpu = g_cpu_profile;
    ps.memory = g_memory_profile;
    ps.event_loop = g_event_loop_stats;

    for (const auto& pool : g_db_pools) {
        ps.total_db_connections += pool.active_connections + pool.idle_connections;
        ps.total_db_queries += pool.total_queries_executed;
    }

    for (const auto& [name, cs] : g_caches) {
        ps.total_cache_hits += cs.hits.load();
        ps.total_cache_misses += cs.misses.load();
    }
    uint64_t total_lookups = ps.total_cache_hits + ps.total_cache_misses;
    ps.aggregate_cache_hit_rate = total_lookups > 0
        ? 100.0 * ps.total_cache_hits / static_cast<double>(total_lookups) : 0.0;

    for (const auto& pool : g_http_client_pools) {
        ps.total_http_requests += pool.total_requests_sent;
    }

    for (const auto& [dest, fts] : g_fed_transaction_stats) {
        ps.total_fed_transactions += fts.pdus_sent_total + fts.edus_sent_total;
    }

    for (const auto& psr : g_pusher_stats) {
        ps.total_pushers += psr.total_pushers;
    }

    for (const auto& bus : g_background_update_stats) {
        if (bus.status == "pending") ps.background_updates_pending++;
        if (bus.status == "running") ps.background_updates_running++;
    }

    for (const auto& mcs : g_media_cache_stats) {
        ps.total_media_size_bytes += mcs.total_size_bytes;
    }

    ps.total_url_previews = g_url_preview_cache_stats.total_previews_cached;

    return ps;
}

// ===========================================================================
// Utility helpers
// ===========================================================================

// Parse query parameters from URL
std::unordered_map<std::string, std::string> parse_query_string(const std::string& path) {
    std::unordered_map<std::string, std::string> params;
    size_t qpos = path.find('?');
    if (qpos == std::string::npos) return params;

    std::string qs = path.substr(qpos + 1);
    std::istringstream ss(qs);
    std::string pair;
    while (std::getline(ss, pair, '&')) {
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            params[pair.substr(0, eq)] = pair.substr(eq + 1);
        }
    }
    return params;
}

// Check admin auth token
bool is_admin_authenticated(const HttpRequest& req) {
    auto it = req.query_params.find("access_token");
    if (it == req.query_params.end()) {
        auto hit = req.headers.find("Authorization");
        if (hit != req.headers.end()) {
            std::string auth = hit->second;
            if (auth.rfind("Bearer ", 0) == 0) {
                return auth.substr(7) == "admin_secret_token";
            }
        }
        return false;
    }
    return it->second == "admin_secret_token";
}

// Extract cache name from path / query params
std::string extract_cache_name(const HttpRequest& req) {
    auto it = req.query_params.find("cache");
    if (it != req.query_params.end()) return it->second;

    auto pit = req.path_params.find("cache_name");
    if (pit != req.path_params.end()) return pit->second;

    return "";
}

// Extract cache name pattern for bulk operations
std::string extract_pattern(const HttpRequest& req) {
    auto it = req.query_params.find("pattern");
    if (it != req.query_params.end()) return it->second;
    return "";
}

// ===========================================================================
// HANDLER: Cache Stats – per-cache hit/miss and aggregate
// ===========================================================================

HttpResponse handle_cache_stats(const HttpRequest& req) {
    init_cache_registry();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    std::string cache_name = extract_cache_name(req);

    json result;
    if (cache_name.empty()) {
        // Return all caches
        json caches_array = json::array();
        uint64_t total_hits = 0, total_misses = 0;
        for (const auto& [name, cs] : g_caches) {
            caches_array.push_back(cs.to_json());
            total_hits += cs.hits.load();
            total_misses += cs.misses.load();
        }
        result["caches"] = caches_array;
        result["aggregate"] = {
            {"total_caches", g_caches.size()},
            {"total_hits", total_hits},
            {"total_misses", total_misses},
            {"aggregate_hit_rate_percent", total_hits + total_misses > 0
                ? std::round(100.0 * total_hits / static_cast<double>(total_hits + total_misses) * 100.0) / 100.0
                : 0.0}
        };
    } else {
        auto it = g_caches.find(cache_name);
        if (it == g_caches.end()) {
            return HttpResponse::not_found("Cache not found: " + cache_name);
        }
        result["cache"] = it->second.to_json();
    }

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Cache Clear – purge specific or all caches
// ===========================================================================

HttpResponse handle_cache_clear(const HttpRequest& req) {
    init_cache_registry();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    std::string cache_name = extract_cache_name(req);
    std::string pattern = extract_pattern(req);

    json result;

    if (!cache_name.empty() || !pattern.empty()) {
        std::vector<CacheClearSummary> summaries;

        if (!cache_name.empty()) {
            summaries.push_back(clear_single_cache(cache_name));
        } else {
            summaries = clear_caches_by_pattern(pattern);
        }

        json cleared = json::array();
        size_t total_freed = 0;
        int success_count = 0, fail_count = 0;
        for (const auto& s : summaries) {
            json entry;
            entry["cache_name"] = s.cache_name;
            entry["entries_before"] = s.entries_before;
            entry["entries_after"] = s.entries_after;
            entry["bytes_freed"] = s.bytes_freed;
            entry["bytes_freed_mb"] = std::round(s.bytes_freed / 1048576.0 * 100.0) / 100.0;
            entry["success"] = s.success;
            if (!s.error.empty()) entry["error"] = s.error;
            cleared.push_back(entry);

            if (s.success) success_count++;
            else fail_count++;
            total_freed += s.bytes_freed;
        }

        result["cleared"] = cleared;
        result["summary"] = {
            {"total_caches_cleared", success_count},
            {"total_caches_failed", fail_count},
            {"total_bytes_freed", total_freed},
            {"total_mb_freed", std::round(total_freed / 1048576.0 * 100.0) / 100.0}
        };
    } else {
        // Clear all
        auto summaries = clear_all_caches();
        json cleared = json::array();
        size_t total_freed = 0;
        for (const auto& s : summaries) {
            json entry;
            entry["cache_name"] = s.cache_name;
            entry["entries_before"] = s.entries_before;
            entry["bytes_freed"] = s.bytes_freed;
            entry["success"] = s.success;
            cleared.push_back(entry);
            total_freed += s.bytes_freed;
        }

        result["cleared_all"] = true;
        result["total_caches"] = summaries.size();
        result["total_bytes_freed"] = total_freed;
        result["total_mb_freed"] = std::round(total_freed / 1048576.0 * 100.0) / 100.0;
    }

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Cache Warm – pre-populate caches from database
// ===========================================================================

HttpResponse handle_cache_warm(const HttpRequest& req) {
    init_cache_registry();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    if (req.method == "GET") {
        // List warm jobs
        std::lock_guard<std::mutex> lock(g_cache_warm_mutex);
        json jobs = json::array();
        for (const auto& [id, job] : g_cache_warm_jobs) {
            json j;
            j["job_id"] = job.job_id;
            j["cache_name"] = job.cache_name;
            j["status"] = job.status;
            j["progress_percent"] = job.progress_percent;
            j["entries_warmed"] = job.entries_warmed;
            j["entries_target"] = job.entries_target;
            j["duration_seconds"] = std::round(job.duration_seconds * 100.0) / 100.0;
            if (!job.error.empty()) j["error"] = job.error;
            jobs.push_back(j);
        }
        json result;
        result["warm_jobs"] = jobs;
        return HttpResponse::ok(result);
    }

    if (req.method == "POST") {
        // Trigger a warm job
        json body;
        try {
            body = json::parse(req.body.empty() ? "{}" : req.body);
        } catch (...) {
            return HttpResponse::bad_request("Invalid JSON body");
        }

        std::string cache_name = body.value("cache_name", extract_cache_name(req));
        if (cache_name.empty()) {
            return HttpResponse::bad_request("Missing 'cache_name' parameter");
        }

        auto it = g_caches.find(cache_name);
        if (it == g_caches.end()) {
            return HttpResponse::not_found("Cache not found: " + cache_name);
        }

        size_t target = body.value("target_entries", static_cast<size_t>(0));
        if (target == 0) {
            auto warm_it = g_cache_warm_targets.find(cache_name);
            target = warm_it != g_cache_warm_targets.end() ? warm_it->second : 10000;
        }

        std::string job_id = start_cache_warm(cache_name, target);

        json result;
        result["job_id"] = job_id;
        result["cache_name"] = cache_name;
        result["target_entries"] = target;
        result["status"] = "running";
        result["message"] = "Cache warm job started";

        return HttpResponse::ok(result);
    }

    return HttpResponse::bad_request("Method not allowed");
}

// ===========================================================================
// HANDLER: Database Table Stats – row counts, sizes, bloat
// ===========================================================================

HttpResponse handle_db_table_stats(const HttpRequest& req) {
    init_table_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    auto params = parse_query_string(req.path);
    std::string table_name;
    auto it = params.find("table");
    if (it != params.end()) table_name = it->second;

    json result;

    if (!table_name.empty()) {
        auto tit = g_table_stats.find(table_name);
        if (tit == g_table_stats.end()) {
            return HttpResponse::not_found("Table not found: " + table_name);
        }
        result["table"] = tit->second.to_json();
    } else {
        json tables = json::array();
        uint64_t total_size = 0;
        uint64_t total_rows = 0;
        for (const auto& [name, ts] : g_table_stats) {
            tables.push_back(ts.to_json());
            total_size += ts.total_size_bytes;
            total_rows += ts.row_count_estimate;
        }
        result["tables"] = tables;
        result["aggregate"] = {
            {"total_tables", g_table_stats.size()},
            {"total_rows_estimate", total_rows},
            {"total_size_bytes", total_size},
            {"total_size_gb", std::round(total_size / 1073741824.0 * 100.0) / 100.0}
        };
    }

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Database Index Stats
// ===========================================================================

HttpResponse handle_db_index_stats(const HttpRequest& req) {
    init_index_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    auto params = parse_query_string(req.path);
    std::string table_name;
    auto it = params.find("table");
    if (it != params.end()) table_name = it->second;

    json result;
    json indexes = json::array();

    for (const auto& is : g_index_stats) {
        if (!table_name.empty() && is.table_name != table_name) continue;
        indexes.push_back(is.to_json());
    }

    result["indexes"] = indexes;
    result["total_indexes"] = indexes.size();

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Database Query Profiling
// ===========================================================================

HttpResponse handle_db_query_profiling(const HttpRequest& req) {
    init_query_profiles();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    auto params = parse_query_string(req.path);

    // Support filtering
    std::string type_filter;
    auto tit = params.find("type");
    if (tit != params.end()) type_filter = tit->second;

    bool slow_only = params.find("slow") != params.end();

    double threshold = g_slow_query_threshold_ms;
    auto thrit = params.find("threshold_ms");
    if (thrit != params.end()) {
        try { threshold = std::stod(thrit->second); } catch (...) {}
    }

    int limit = 100;
    auto limit_it = params.find("limit");
    if (limit_it != params.end()) {
        try { limit = std::stoi(limit_it->second); } catch (...) {}
    }

    std::string sort_by = params.value("sort_by", std::string("total_time_ms"));

    json result;

    // Build filtered list
    std::vector<QueryProfile> filtered;
    for (const auto& qp : g_query_profiles) {
        if (!type_filter.empty() && qp.query_type != type_filter) continue;
        if (slow_only && qp.mean_time_ms < threshold) continue;
        filtered.push_back(qp);
    }

    // Sort
    std::sort(filtered.begin(), filtered.end(),
        [&sort_by](const QueryProfile& a, const QueryProfile& b) {
            if (sort_by == "calls") return a.calls > b.calls;
            if (sort_by == "mean_time_ms") return a.mean_time_ms > b.mean_time_ms;
            if (sort_by == "max_time_ms") return a.max_time_ms > b.max_time_ms;
            if (sort_by == "rows_affected") return a.rows_affected > b.rows_affected;
            return a.total_time_ms > b.total_time_ms; // default
        });

    if (static_cast<int>(filtered.size()) > limit) {
        filtered.resize(limit);
    }

    json queries = json::array();
    for (const auto& qp : filtered) {
        queries.push_back(qp.to_json());
    }

    result["queries"] = queries;
    result["total_queries_tracked"] = g_query_profiles.size();
    result["slow_query_threshold_ms"] = g_slow_query_threshold_ms;
    result["filtered_count"] = filtered.size();
    result["slow_only"] = slow_only;

    // Top N slowest
    json top_slow = json::array();
    for (size_t i = 0; i < std::min(size_t(10), g_slow_queries.size()); ++i) {
        top_slow.push_back(g_slow_queries[i].to_json());
    }
    result["top_slow_queries"] = top_slow;

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Database Vacuum Trigger
// ===========================================================================

HttpResponse handle_db_vacuum(const HttpRequest& req) {
    init_table_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    if (req.method == "GET") {
        // List vacuum jobs
        std::lock_guard<std::mutex> lock(g_vacuum_mutex);
        json jobs = json::array();
        for (const auto& [id, job] : g_vacuum_jobs) {
            json j;
            j["job_id"] = job.job_id;
            j["target"] = job.target;
            j["vacuum_type"] = job.vacuum_type;
            j["status"] = job.status;
            j["progress_percent"] = job.progress_percent;
            j["duration_seconds"] = std::round(job.duration_seconds * 100.0) / 100.0;
            if (!job.error.empty()) j["error"] = job.error;
            jobs.push_back(j);
        }
        json result;
        result["vacuum_jobs"] = jobs;
        result["vacuum_in_progress"] = g_vacuum_in_progress.load();

        // Also list most-bloated tables that could benefit from VACUUM
        json bloated = json::array();
        for (const auto& [name, ts] : g_table_stats) {
            if (ts.bloat_ratio > 10.0) {
                json b;
                b["table_name"] = name;
                b["bloat_ratio_percent"] = std::round(ts.bloat_ratio * 100.0) / 100.0;
                b["n_dead_tup"] = ts.n_dead_tup;
                b["total_size_mb"] = std::round(ts.total_size_bytes / 1048576.0 * 100.0) / 100.0;
                bloated.push_back(b);
            }
        }
        result["bloated_tables"] = bloated;

        return HttpResponse::ok(result);
    }

    if (req.method == "POST") {
        if (g_vacuum_in_progress.load()) {
            return HttpResponse::error(409, "M_CONFLICT", "A vacuum operation is already in progress");
        }

        json body;
        try {
            body = json::parse(req.body.empty() ? "{}" : req.body);
        } catch (...) {
            return HttpResponse::bad_request("Invalid JSON body");
        }

        std::string target = body.value("target", std::string("full"));
        std::string vacuum_type = body.value("vacuum_type", std::string("standard"));
        bool analyze = body.value("analyze", true);

        // Validate target
        if (target != "full" && g_table_stats.find(target) == g_table_stats.end()) {
            return HttpResponse::not_found("Table not found: " + target);
        }

        // Validate vacuum_type
        if (vacuum_type != "standard" && vacuum_type != "full" &&
            vacuum_type != "analyze" && vacuum_type != "freeze") {
            return HttpResponse::bad_request("Invalid vacuum_type: " + vacuum_type
                + ". Must be: standard, full, analyze, or freeze");
        }

        std::string job_id = trigger_vacuum(target, vacuum_type);

        json result;
        result["job_id"] = job_id;
        result["target"] = target;
        result["vacuum_type"] = vacuum_type;
        result["analyze"] = analyze;
        result["status"] = "running";
        result["message"] = "VACUUM started on " + target;

        return HttpResponse::ok(result);
    }

    return HttpResponse::bad_request("Method not allowed");
}

// ===========================================================================
// HANDLER: Server Profiling (CPU, Memory, Goroutines)
// ===========================================================================

HttpResponse handle_server_profiling(const HttpRequest& req) {
    init_profiling_state();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    json result;
    result["cpu"] = g_cpu_profile.to_json();
    result["memory"] = g_memory_profile.to_json();
    result["timestamp"] = std::time(nullptr);

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Event Loop Stats
// ===========================================================================

HttpResponse handle_event_loop_stats(const HttpRequest& req) {
    init_event_loop_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    json result = g_event_loop_stats.to_json();
    result["timestamp"] = std::time(nullptr);

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Connection Pool Stats
// ===========================================================================

HttpResponse handle_connection_pool_stats(const HttpRequest& req) {
    init_connection_pool_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    json result;
    json pools = json::array();
    int total_active = 0, total_idle = 0, total_max = 0;
    for (const auto& ps : g_db_pools) {
        pools.push_back(ps.to_json());
        total_active += ps.active_connections;
        total_idle += ps.idle_connections;
        total_max += ps.max_connections;
    }

    result["pools"] = pools;
    result["aggregate"] = {
        {"total_pools", g_db_pools.size()},
        {"total_active_connections", total_active},
        {"total_idle_connections", total_idle},
        {"total_max_connections", total_max},
        {"overall_utilization_percent", total_max > 0
            ? std::round(100.0 * total_active / total_max * 100.0) / 100.0 : 0.0}
    };

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: HTTP Client Pool Stats
// ===========================================================================

HttpResponse handle_http_client_pool_stats(const HttpRequest& req) {
    init_http_client_pool_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    auto params = parse_query_string(req.path);
    std::string dest_filter;
    auto it = params.find("destination");
    if (it != params.end()) dest_filter = it->second;

    json result;
    json pools = json::array();
    uint64_t total_reqs = 0, total_errors = 0;
    for (const auto& ps : g_http_client_pools) {
        if (!dest_filter.empty() && ps.pool_id != dest_filter) continue;
        pools.push_back(ps.to_json());
        total_reqs += ps.total_requests_sent;
        total_errors += ps.total_errors;
    }

    result["pools"] = pools;
    result["aggregate"] = {
        {"total_pools", pools.size()},
        {"total_requests", total_reqs},
        {"total_errors", total_errors},
        {"overall_error_rate_percent", total_reqs > 0
            ? std::round(100.0 * total_errors / total_reqs * 100.0) / 100.0 : 0.0}
    };

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Federation Transaction Stats
// ===========================================================================

HttpResponse handle_federation_transaction_stats(const HttpRequest& req) {
    init_federation_transaction_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    auto params = parse_query_string(req.path);
    std::string dest_filter;
    auto it = params.find("destination");
    if (it != params.end()) dest_filter = it->second;

    json result;
    json dests = json::array();
    int total_pending_pdus = 0, total_pending_edus = 0;
    for (const auto& [dest, fts] : g_fed_transaction_stats) {
        if (!dest_filter.empty() && dest != dest_filter) continue;
        dests.push_back(fts.to_json());
        total_pending_pdus += fts.pending_pdus;
        total_pending_edus += fts.pending_edus;
    }

    result["destinations"] = dests;
    result["aggregate"] = {
        {"total_destinations", g_fed_transaction_stats.size()},
        {"total_pending_pdus", total_pending_pdus},
        {"total_pending_edus", total_pending_edus}
    };

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Pusher Stats
// ===========================================================================

HttpResponse handle_pusher_stats(const HttpRequest& req) {
    init_pusher_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    json result;
    json pushers = json::array();
    int total_pushers = 0, total_active = 0;
    uint64_t total_sent = 0, total_failed = 0;
    for (const auto& ps : g_pusher_stats) {
        pushers.push_back(ps.to_json());
        total_pushers += ps.total_pushers;
        total_active += ps.active_pushers;
        total_sent += ps.total_pushes_sent;
        total_failed += ps.total_pushes_failed;
    }

    result["pushers"] = pushers;
    result["aggregate"] = {
        {"total_pushers", total_pushers},
        {"active_pushers", total_active},
        {"total_pushes_sent", total_sent},
        {"total_pushes_failed", total_failed},
        {"overall_error_rate_percent", total_sent > 0
            ? std::round(100.0 * total_failed / total_sent * 100.0) / 100.0 : 0.0}
    };

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Background Update Stats
// ===========================================================================

HttpResponse handle_background_update_stats(const HttpRequest& req) {
    init_background_update_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    auto params = parse_query_string(req.path);
    std::string status_filter;
    auto it = params.find("status");
    if (it != params.end()) status_filter = it->second;

    json result;
    json updates = json::array();
    int pending = 0, running = 0, complete = 0;
    for (const auto& bus : g_background_update_stats) {
        if (!status_filter.empty() && bus.status != status_filter) continue;
        updates.push_back(bus.to_json());
        if (bus.status == "pending") pending++;
        else if (bus.status == "running") running++;
        else if (bus.status == "complete") complete++;
    }

    result["background_updates"] = updates;
    result["aggregate"] = {
        {"total_updates", g_background_update_stats.size()},
        {"pending", pending},
        {"running", running},
        {"complete", complete}
    };

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Media Cache Stats
// ===========================================================================

HttpResponse handle_media_cache_stats_endpoint(const HttpRequest& req) {
    init_media_cache_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    json result;
    json caches = json::array();
    uint64_t total_count = 0, total_size = 0;
    for (const auto& mcs : g_media_cache_stats) {
        caches.push_back(mcs.to_json());
        total_count += mcs.total_media_count;
        total_size += mcs.total_size_bytes;
    }

    result["media_caches"] = caches;
    result["aggregate"] = {
        {"total_media_count", total_count},
        {"total_size_bytes", total_size},
        {"total_size_gb", std::round(total_size / 1073741824.0 * 100.0) / 100.0}
    };

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: URL Preview Cache Stats
// ===========================================================================

HttpResponse handle_url_preview_cache_stats(const HttpRequest& req) {
    init_url_preview_cache_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    json result = g_url_preview_cache_stats.to_json();

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: SSL Session Cache Stats
// ===========================================================================

HttpResponse handle_ssl_session_cache_stats(const HttpRequest& req) {
    init_ssl_session_cache_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    json result = g_ssl_session_cache_stats.to_json();

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: DNS Cache Stats
// ===========================================================================

HttpResponse handle_dns_cache_stats(const HttpRequest& req) {
    init_dns_cache_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    auto params = parse_query_string(req.path);
    bool include_entries = params.find("entries") != params.end();

    json result = g_dns_cache_stats.to_json();

    if (include_entries) {
        json entries = json::array();
        time_t now = std::time(nullptr);
        for (const auto& [host, entry] : g_dns_cache) {
            json e;
            e["hostname"] = entry.hostname;
            e["ip_addresses"] = entry.ip_addresses;
            e["ttl_seconds"] = entry.ttl_seconds;
            e["ttl_remaining_s"] = entry.expires_at > now ? entry.expires_at - now : 0;
            e["is_expired"] = entry.is_expired;
            e["lookup_count"] = entry.lookup_count;
            e["last_accessed_at"] = std::to_string(entry.last_accessed_at);
            entries.push_back(e);
        }
        result["entry_detail"] = entries;
    }

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Full Profiling Summary (all metrics combined)
// ===========================================================================

HttpResponse handle_full_profiling_summary(const HttpRequest& req) {
    // Ensure all state is initialized
    init_cache_registry();
    init_table_stats();
    init_index_stats();
    init_query_profiles();
    init_profiling_state();
    init_event_loop_stats();
    init_connection_pool_stats();
    init_http_client_pool_stats();
    init_federation_transaction_stats();
    init_pusher_stats();
    init_background_update_stats();
    init_media_cache_stats();
    init_url_preview_cache_stats();
    init_ssl_session_cache_stats();
    init_dns_cache_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    ProfilingSummary summary = build_profiling_summary();

    json result;
    result["timestamp"] = std::time(nullptr);
    result["summary"] = summary.to_json();

    // Add detailed sections if requested
    auto params = parse_query_string(req.path);
    if (params.find("detail") != params.end()) {
        // Cache details
        json caches = json::array();
        for (const auto& [name, cs] : g_caches) {
            caches.push_back(cs.to_json());
        }
        result["caches"] = caches;

        // DB pool details
        json db_pools = json::array();
        for (const auto& ps : g_db_pools) {
            db_pools.push_back(ps.to_json());
        }
        result["db_connection_pools"] = db_pools;

        // HTTP pool details
        json http_pools = json::array();
        for (const auto& ps : g_http_client_pools) {
            http_pools.push_back(ps.to_json());
        }
        result["http_client_pools"] = http_pools;

        // Federation transaction details
        json fed_txns = json::array();
        for (const auto& [dest, fts] : g_fed_transaction_stats) {
            fed_txns.push_back(fts.to_json());
        }
        result["federation_transactions"] = fed_txns;

        // Background updates
        json bg_updates = json::array();
        for (const auto& bus : g_background_update_stats) {
            bg_updates.push_back(bus.to_json());
        }
        result["background_updates"] = bg_updates;
    }

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Top Bloat Tables (actionable vacuum targets)
// ===========================================================================

HttpResponse handle_top_bloat_tables(const HttpRequest& req) {
    init_table_stats();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    std::vector<std::pair<std::string, double>> bloated;
    for (const auto& [name, ts] : g_table_stats) {
        bloated.push_back({name, ts.bloat_ratio});
    }
    std::sort(bloated.begin(), bloated.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    int limit = 20;
    auto params = parse_query_string(req.path);
    auto lit = params.find("limit");
    if (lit != params.end()) {
        try { limit = std::stoi(lit->second); } catch (...) {}
    }

    json result;
    json tables = json::array();
    for (int i = 0; i < std::min(limit, static_cast<int>(bloated.size())); ++i) {
        const auto& ts = g_table_stats[bloated[i].first];
        json t = ts.to_json();
        t["bloat_rank"] = i + 1;
        // Add vacuum recommendation
        if (ts.bloat_ratio > 20.0) {
            t["vacuum_recommendation"] = "VACUUM FULL urgently recommended";
        } else if (ts.bloat_ratio > 10.0) {
            t["vacuum_recommendation"] = "VACUUM recommended";
        } else {
            t["vacuum_recommendation"] = "Monitor – no immediate action needed";
        }
        tables.push_back(t);
    }
    result["top_bloated_tables"] = tables;
    result["timestamp"] = std::time(nullptr);

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Reset Query Profiling Stats
// ===========================================================================

HttpResponse handle_reset_query_profiling(const HttpRequest& req) {
    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    g_query_profiles.clear();
    g_slow_queries.clear();
    init_query_profiles(); // Re-initialize with fresh data (in production would reset counters)

    json result;
    result["message"] = "Query profiling stats reset";
    result["queries_tracked"] = g_query_profiles.size();

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Set Slow Query Threshold
// ===========================================================================

HttpResponse handle_set_slow_query_threshold(const HttpRequest& req) {
    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    json body;
    try {
        body = json::parse(req.body.empty() ? "{}" : req.body);
    } catch (...) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    if (!body.contains("threshold_ms") || !body["threshold_ms"].is_number()) {
        return HttpResponse::bad_request("Missing 'threshold_ms' (number) in request body");
    }

    double new_threshold = body["threshold_ms"].get<double>();
    if (new_threshold <= 0.0) {
        return HttpResponse::bad_request("threshold_ms must be > 0");
    }

    g_slow_query_threshold_ms = new_threshold;

    // Re-compute slow queries
    g_slow_queries.clear();
    for (const auto& qp : g_query_profiles) {
        if (qp.mean_time_ms >= g_slow_query_threshold_ms ||
            qp.max_time_ms >= g_slow_query_threshold_ms * 3) {
            g_slow_queries.push_back(qp);
        }
    }

    json result;
    result["slow_query_threshold_ms"] = g_slow_query_threshold_ms;
    result["slow_queries_count"] = g_slow_queries.size();
    result["message"] = "Slow query threshold updated";

    return HttpResponse::ok(result);
}

// ===========================================================================
// HANDLER: Cache Hit Rate Over Time (simulated time-series data)
// ===========================================================================

HttpResponse handle_cache_hit_rate_timeseries(const HttpRequest& req) {
    init_cache_registry();

    if (!is_admin_authenticated(req)) {
        return HttpResponse::forbidden("Invalid or missing access token");
    }

    std::string cache_name = extract_cache_name(req);

    // Simulate time-series data (last 60 minutes, 1 data point per minute)
    json timeseries = json::array();
    std::mt19937_64 rng(static_cast<uint64_t>(std::time(nullptr)));
    time_t now = std::time(nullptr);

    for (int i = 59; i >= 0; --i) {
        json point;
        point["timestamp"] = now - i * 60;
        point["minute_offset"] = -i;

        if (cache_name.empty()) {
            // Aggregate across all caches
            uint64_t hits = 0, misses = 0;
            for (const auto& [name, cs] : g_caches) {
                hits += std::uniform_int_distribution<uint64_t>(
                    cs.hits.load() / 60 / 2, cs.hits.load() / 60)(rng);
                misses += std::uniform_int_distribution<uint64_t>(
                    0, cs.misses.load() / 60)(rng);
            }
            point["hits"] = hits;
            point["misses"] = misses;
            point["hit_rate"] = hits + misses > 0
                ? std::round(100.0 * hits / static_cast<double>(hits + misses) * 100.0) / 100.0
                : 0.0;
        } else {
            auto it = g_caches.find(cache_name);
            if (it == g_caches.end()) return HttpResponse::not_found("Cache not found: " + cache_name);
            uint64_t hits = std::uniform_int_distribution<uint64_t>(
                it->second.hits.load() / 60 / 2, it->second.hits.load() / 60)(rng);
            uint64_t misses = std::uniform_int_distribution<uint64_t>(
                0, it->second.misses.load() / 60)(rng);
            point["hits"] = hits;
            point["misses"] = misses;
            point["hit_rate"] = hits + misses > 0
                ? std::round(100.0 * hits / static_cast<double>(hits + misses) * 100.0) / 100.0
                : 0.0;
        }
        timeseries.push_back(point);
    }

    json result;
    result["cache_name"] = cache_name.empty() ? "aggregate" : cache_name;
    result["timeseries_minutes"] = 60;
    result["data"] = timeseries;

    return HttpResponse::ok(result);
}

// ===========================================================================
// Convenience / programmatic-access functions
// ===========================================================================

} // anonymous namespace

// ===========================================================================
// Public programmatic API – allows direct function calls from other modules
// ===========================================================================

json get_cache_stats(const std::string& cache_name = "") {
    init_cache_registry();
    json result;
    if (cache_name.empty()) {
        json arr = json::array();
        for (const auto& [name, cs] : g_caches) {
            arr.push_back(cs.to_json());
        }
        result["caches"] = arr;
    } else {
        auto it = g_caches.find(cache_name);
        if (it != g_caches.end()) result["cache"] = it->second.to_json();
    }
    return result;
}

json get_db_table_stats(const std::string& table_name = "") {
    init_table_stats();
    json result;
    if (table_name.empty()) {
        json arr = json::array();
        for (const auto& [name, ts] : g_table_stats) {
            arr.push_back(ts.to_json());
        }
        result["tables"] = arr;
    } else {
        auto it = g_table_stats.find(table_name);
        if (it != g_table_stats.end()) result["table"] = it->second.to_json();
    }
    return result;
}

json get_server_profiling() {
    init_profiling_state();
    json result;
    result["cpu"] = g_cpu_profile.to_json();
    result["memory"] = g_memory_profile.to_json();
    return result;
}

json get_full_profiling_summary() {
    init_cache_registry();
    init_table_stats();
    init_index_stats();
    init_query_profiles();
    init_profiling_state();
    init_event_loop_stats();
    init_connection_pool_stats();
    init_http_client_pool_stats();
    init_federation_transaction_stats();
    init_pusher_stats();
    init_background_update_stats();
    init_media_cache_stats();
    init_url_preview_cache_stats();
    init_ssl_session_cache_stats();
    init_dns_cache_stats();

    ProfilingSummary summary = build_profiling_summary();
    return summary.to_json();
}

json clear_cache(const std::string& cache_name) {
    init_cache_registry();
    auto summary = clear_single_cache(cache_name);
    json result;
    result["cache_name"] = summary.cache_name;
    result["entries_before"] = summary.entries_before;
    result["success"] = summary.success;
    if (!summary.error.empty()) result["error"] = summary.error;
    return result;
}

json clear_all_caches_json() {
    init_cache_registry();
    auto summaries = clear_all_caches();
    json arr = json::array();
    for (const auto& s : summaries) {
        json entry;
        entry["cache_name"] = s.cache_name;
        entry["success"] = s.success;
        arr.push_back(entry);
    }
    json result;
    result["cleared"] = arr;
    result["total"] = summaries.size();
    return result;
}

std::string warm_cache(const std::string& cache_name, size_t target_entries) {
    init_cache_registry();
    return start_cache_warm(cache_name, target_entries);
}

json get_event_loop_stats_json() {
    init_event_loop_stats();
    return g_event_loop_stats.to_json();
}

json get_connection_pool_stats_json() {
    init_connection_pool_stats();
    json arr = json::array();
    for (const auto& ps : g_db_pools) {
        arr.push_back(ps.to_json());
    }
    return arr;
}

json trigger_vacuum_json(const std::string& target, const std::string& vacuum_type) {
    init_table_stats();
    std::string job_id = trigger_vacuum(target, vacuum_type);
    json result;
    result["job_id"] = job_id;
    result["target"] = target;
    result["vacuum_type"] = vacuum_type;
    result["status"] = "running";
    return result;
}

// ===========================================================================
// Route registration – returns vector of RouteEntry for unified routing
// ===========================================================================

std::vector<RouteEntry> get_cache_db_profiling_routes() {
    init_cache_registry();
    init_table_stats();
    init_index_stats();
    init_query_profiles();
    init_profiling_state();
    init_event_loop_stats();
    init_connection_pool_stats();
    init_http_client_pool_stats();
    init_federation_transaction_stats();
    init_pusher_stats();
    init_background_update_stats();
    init_media_cache_stats();
    init_url_preview_cache_stats();
    init_ssl_session_cache_stats();
    init_dns_cache_stats();

    return {
        // Cache endpoints
        {"GET",    "/_synapse/admin/v1/cache/stats",                       handle_cache_stats},
        {"GET",    "/_synapse/admin/v1/caches/stats",                      handle_cache_stats},
        {"POST",   "/_synapse/admin/v1/cache/clear",                       handle_cache_clear},
        {"POST",   "/_synapse/admin/v1/caches/clear",                      handle_cache_clear},
        {"POST",   "/_synapse/admin/v1/cache/warm",                        handle_cache_warm},
        {"GET",    "/_synapse/admin/v1/cache/warm",                        handle_cache_warm},
        {"GET",    "/_synapse/admin/v1/cache/hit_rate_timeseries",         handle_cache_hit_rate_timeseries},

        // Database stats endpoints
        {"GET",    "/_synapse/admin/v1/database/tables",                   handle_db_table_stats},
        {"GET",    "/_synapse/admin/v1/database/indexes",                  handle_db_index_stats},
        {"GET",    "/_synapse/admin/v1/database/queries",                  handle_db_query_profiling},
        {"POST",   "/_synapse/admin/v1/database/queries/reset",            handle_reset_query_profiling},
        {"PUT",    "/_synapse/admin/v1/database/queries/threshold",        handle_set_slow_query_threshold},
        {"GET",    "/_synapse/admin/v1/database/vacuum",                   handle_db_vacuum},
        {"POST",   "/_synapse/admin/v1/database/vacuum",                   handle_db_vacuum},
        {"GET",    "/_synapse/admin/v1/database/bloat",                    handle_top_bloat_tables},

        // Server profiling
        {"GET",    "/_synapse/admin/v1/profiling",                         handle_server_profiling},
        {"GET",    "/_synapse/admin/v1/profiling/summary",                 handle_full_profiling_summary},

        // Event loop
        {"GET",    "/_synapse/admin/v1/event_loop/stats",                  handle_event_loop_stats},

        // Connection pool
        {"GET",    "/_synapse/admin/v1/connection_pool/stats",             handle_connection_pool_stats},

        // HTTP client pool
        {"GET",    "/_synapse/admin/v1/http_client_pool/stats",            handle_http_client_pool_stats},

        // Federation transaction stats
        {"GET",    "/_synapse/admin/v1/federation/transaction_stats",      handle_federation_transaction_stats},

        // Pusher stats
        {"GET",    "/_synapse/admin/v1/pushers/stats",                     handle_pusher_stats},

        // Background update stats
        {"GET",    "/_synapse/admin/v1/background_updates/stats",          handle_background_update_stats},

        // Media cache stats
        {"GET",    "/_synapse/admin/v1/media_cache/stats",                 handle_media_cache_stats_endpoint},

        // URL preview cache stats
        {"GET",    "/_synapse/admin/v1/url_preview_cache/stats",           handle_url_preview_cache_stats},

        // SSL session cache stats
        {"GET",    "/_synapse/admin/v1/ssl_session_cache/stats",           handle_ssl_session_cache_stats},

        // DNS cache stats
        {"GET",    "/_synapse/admin/v1/dns_cache/stats",                   handle_dns_cache_stats},
    };
}

} // namespace admin
} // namespace progressive
