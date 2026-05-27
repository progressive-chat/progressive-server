// =============================================================================
// progressive-server/src/progressive/storage/state_storage.cpp
// State storage implementation for Matrix homeserver.
//
// Covers:
//   1.  Background update runner
//   2.  State compression (delta encoding, prune unreferenced)
//   3.  State group storage (state_groups, state_groups_state, state_group_edges)
//   4.  Event to state group mapping
//   5.  State resolution storage (cached resolution results)
//   6.  Room statistics
//   7.  Monthly active users tracking
//   8.  Daily active users tracking
//   9.  User directory search index
//  10.  Room directory (public room listing with pagination)
//  11.  Current state delta storage (deltas for compression)
//  12.  Purge history (delete events from room up to a point)
//  13.  Purge room (complete room deletion)
//  14.  Sharded event ID generation
//  15.  Stream ordering (event stream positions per room)
//  16.  Backfill extremeties tracking
//  17.  Event forward extremeties management
//  18.  State autocompression trigger
//  19.  Cache invalidation callbacks
//  20.  Database migrations specific to state storage
// =============================================================================

#include "../json.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace progressive::storage {

// =============================================================================
// Forward declarations & type aliases
// =============================================================================

using json = nlohmann::json;

using EventId    = std::string;
using RoomId     = std::string;
using UserId     = std::string;
using StateKey   = std::string;
using StateGroup = int64_t;
using StreamPos  = int64_t;
using Depth      = int64_t;

// =============================================================================
// Utility helpers
// =============================================================================

namespace {

uint64_t now_millis() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

uint64_t now_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

std::string today_date() {
    auto t  = std::time(nullptr);
    auto tm = *std::localtime(&t);
    char buf[11];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday);
    return buf;
}

std::string month_key() {
    auto t  = std::time(nullptr);
    auto tm = *std::localtime(&t);
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%04d-%02d", tm.tm_year + 1900,
                  tm.tm_mon + 1);
    return buf;
}

// Simple UUID-like shard id
uint64_t shard_id_counter() {
    static std::atomic<uint64_t> c{0};
    return ++c;
}

// ---------------------------------------------------------------------------
// Minimal transaction wrapper (LoggingTransaction stub)
// ---------------------------------------------------------------------------
class LoggingTransaction {
public:
    explicit LoggingTransaction(const std::string& name)
        : name_(name), active_(true) {}

    ~LoggingTransaction() {
        if (active_) rollback();
    }

    void commit() { active_ = false; }
    void rollback() { active_ = false; }

    const std::string& name() const { return name_; }

private:
    std::string name_;
    bool        active_;
};

// Minimal DatabasePool stub
class DatabasePool {
public:
    static DatabasePool& instance() {
        static DatabasePool pool;
        return pool;
    }

    // Returns a reference that callers can use for querying.
    struct DbHandle {
        // In real code this wraps a DB connection.
        LoggingTransaction begin_transaction(const std::string& name) {
            return LoggingTransaction(name);
        }
    };

    DbHandle get_db() { return DbHandle{}; }
};

} // anonymous namespace

// =============================================================================
// 1. Background Update Runner
// =============================================================================

struct BackgroundUpdate {
    std::string  update_name;
    std::string  depends_on;      // optional dependency
    int          batch_size = 100;
    bool         run_once   = false;
    std::function<size_t(LoggingTransaction& /*txn*/)> runner;
};

class BackgroundUpdateRunner {
public:
    explicit BackgroundUpdateRunner(DatabasePool& pool)
        : pool_(pool), running_(false), paused_(false), next_id_(0) {}

    // -----------------------------------------------------------------------
    void register_update(BackgroundUpdate update) {
        std::lock_guard<std::mutex> lk(mu_);
        InternalUpdate iu;
        iu.update_name = std::move(update.update_name);
        iu.depends_on  = std::move(update.depends_on);
        iu.batch_size  = update.batch_size;
        iu.run_once    = update.run_once;
        iu.runner      = std::move(update.runner);
        iu.id          = next_id_++;
        pending_[iu.update_name] = std::move(iu);
    }

    // -----------------------------------------------------------------------
    void start() {
        if (running_.exchange(true)) return;
        worker_ = std::thread([this] { run_loop(); });
    }

    // -----------------------------------------------------------------------
    void stop() {
        running_ = false;
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    // -----------------------------------------------------------------------
    void pause() {
        paused_ = true;
    }

    void resume() {
        paused_ = false;
        cv_.notify_all();
    }

    // -----------------------------------------------------------------------
    // Run a single named update immediately (blocking) in its own txn.
    bool run_single(const std::string& name) {
        std::unique_lock<std::mutex> lk(mu_);
        auto it = pending_.find(name);
        if (it == pending_.end()) return false;
        auto upd = it->second; // copy
        lk.unlock();

        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("bg_update_" + name);
        size_t n = upd.runner(txn);
        txn.commit();

        lk.lock();
        if (upd.run_once || n == 0) {
            completed_.insert(name);
            pending_.erase(name);
        }
        return true;
    }

    // -----------------------------------------------------------------------
    std::vector<std::string> pending_names() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<std::string> out;
        for (auto& kv : pending_) out.push_back(kv.first);
        return out;
    }

    bool has_pending() const {
        std::lock_guard<std::mutex> lk(mu_);
        return !pending_.empty();
    }

private:
    void run_loop() {
        while (running_) {
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait_for(lk, std::chrono::milliseconds(500), [this] {
                    return !running_ || (!paused_ && !pending_.empty());
                });
                if (!running_) return;
                if (paused_ || pending_.empty()) continue;
            }

            // Pick next update — simple round-robin for illustration.
            std::unique_lock<std::mutex> lk(mu_);
            if (pending_.empty()) continue;
            auto it   = pending_.begin();
            auto name = it->first;
            auto upd  = it->second;
            bool run_once = upd.run_once;
            lk.unlock();

            auto db  = pool_.get_db();
            auto txn = db.begin_transaction("bg_update_" + name);
            size_t processed = 0;
            try {
                processed = upd.runner(txn);
                txn.commit();
            } catch (...) {
                // Log and continue
                txn.rollback();
            }

            lk.lock();
            if (run_once || processed == 0) {
                completed_.insert(name);
                pending_.erase(name);
            }
        }
    }

    DatabasePool& pool_;
    std::atomic<bool> running_;
    std::atomic<bool> paused_;
    std::thread worker_;
    mutable std::mutex mu_;
    std::condition_variable cv_;

    struct InternalUpdate : BackgroundUpdate {
        int id = 0;
    };
    std::unordered_map<std::string, InternalUpdate> pending_;
    std::unordered_set<std::string> completed_;
    int next_id_;
};

// =============================================================================
// 2. State Compression (delta encoding, prune unreferenced)
// =============================================================================

class StateCompressor {
public:
    explicit StateCompressor(DatabasePool& pool) : pool_(pool) {}

    // ---- Delta encode a state group against its predecessor ----
    struct DeltaState {
        std::map<std::string, std::string> added;    // (type, state_key) -> event_id
        std::set<std::string>              removed;  // (type, state_key)
        StateGroup                         prev_group;
    };

    DeltaState compute_delta(StateGroup group, StateGroup prev_group) {
        auto state      = fetch_state_group(group);
        auto prev_state = fetch_state_group(prev_group);
        DeltaState delta;
        delta.prev_group = prev_group;

        for (auto& [key, event_id] : state) {
            auto pit = prev_state.find(key);
            if (pit == prev_state.end() || pit->second != event_id) {
                delta.added[key] = event_id;
            }
        }
        for (auto& [key, _] : prev_state) {
            if (state.find(key) == state.end()) {
                delta.removed.insert(key);
            }
        }
        return delta;
    }

    // ---- Store a delta ----
    void store_delta(StateGroup group, const DeltaState& delta) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("store_state_delta");
        // INSERT INTO state_group_deltas(group_id, prev_group_id, added_json, removed_json)
        json added_json   = json::object();
        for (auto& kv : delta.added) added_json[kv.first] = kv.second;
        json removed_json = json::array();
        for (auto& r : delta.removed) removed_json.push_back(r);

        // (database insert simulated)
        (void)group;
        (void)added_json;
        (void)removed_json;
        txn.commit();
    }

    // ---- Prune unreferenced state groups ----
    struct PruneResult {
        int64_t groups_removed  = 0;
        int64_t events_freed    = 0;
        int64_t bytes_reclaimed = 0;
    };

    PruneResult prune_unreferenced(int64_t older_than_seconds) {
        PruneResult result;
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("prune_state_groups");

        // Find groups not referenced by events, older than threshold.
        // In real impl this queries state_groups LEFT JOIN events.
        // Simulated:
        std::vector<StateGroup> unreferenced;

        // Query: SELECT sg.id FROM state_groups sg
        //        LEFT JOIN event_to_state_groups esg ON sg.id = esg.state_group
        //        WHERE esg.state_group IS NULL AND sg.created_ts < ?
        (void)older_than_seconds;

        for (auto& g : unreferenced) {
            // DELETE FROM state_groups_state WHERE state_group = ?
            // DELETE FROM state_group_edges WHERE state_group = ?
            // DELETE FROM state_groups WHERE id = ?
            ++result.groups_removed;
        }
        txn.commit();
        return result;
    }

    // ---- Full state compression cycle ----
    struct CompressionStats {
        int64_t groups_delta_encoded = 0;
        int64_t groups_pruned        = 0;
        int64_t total_bytes_before   = 0;
        int64_t total_bytes_after    = 0;
    };

    CompressionStats compress_room(const RoomId& room_id) {
        CompressionStats stats;
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("compress_room_state");

        // Walk state groups in topological order.
        auto groups = get_state_groups_for_room(room_id);

        StateGroup prev = -1;
        for (auto& g : groups) {
            if (prev != -1) {
                auto delta = compute_delta(g, prev);
                store_delta(g, delta);
                ++stats.groups_delta_encoded;
                // Delete full state for this group, keep delta.
            }
            prev = g;
        }

        auto prune = prune_unreferenced(86400); // 24h
        stats.groups_pruned = prune.groups_removed;
        txn.commit();
        return stats;
    }

    // ---- Bulk recompress all rooms ----
    void recompress_all(int batch_size = 50) {
        auto rooms = all_room_ids();
        for (auto& rid : rooms) {
            compress_room(rid);
        }
        (void)batch_size;
    }

private:
    // (type, state_key) -> event_id
    using StateMap = std::map<std::string, std::string>;

    static std::string make_key(const std::string& type,
                                 const std::string& state_key) {
        return type + "\x1F" + state_key;
    }

    StateMap fetch_state_group(StateGroup group) {
        // SELECT type, state_key, event_id FROM state_groups_state
        // WHERE state_group = ?
        (void)group;
        return {};
    }

    std::vector<StateGroup> get_state_groups_for_room(const RoomId& room_id) {
        // SELECT DISTINCT sg.id FROM state_groups sg
        // JOIN event_to_state_groups e2s ON sg.id = e2s.state_group
        // WHERE e2s.room_id = ? ORDER BY sg.id
        (void)room_id;
        return {};
    }

    std::vector<RoomId> all_room_ids() {
        // SELECT DISTINCT room_id FROM rooms
        return {};
    }

    DatabasePool& pool_;
};

// =============================================================================
// 3. State Group Storage
// =============================================================================

class StateGroupStorage {
public:
    explicit StateGroupStorage(DatabasePool& pool) : pool_(pool) {}

    // ---- Create a new state group ----
    StateGroup create_state_group(const RoomId& room_id,
                                  const std::map<std::string, std::string>& state,
                                  std::optional<StateGroup> prev_group = std::nullopt) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("create_state_group");

        // INSERT INTO state_groups (room_id, event_id) VALUES (?, NULL)
        // returning id
        StateGroup new_id = allocate_state_group_id();

        // INSERT INTO state_groups_state (state_group, room_id, type, state_key, event_id)
        for (auto& [key, event_id] : state) {
            auto sep = key.find('\x1F');
            auto type = key.substr(0, sep);
            auto sk   = key.substr(sep + 1);
            (void)event_id;
            (void)type;
            (void)sk;
        }

        txn.commit();
        return new_id;
    }

    // ---- Fetch full state for a group ----
    std::map<std::string, std::string> get_state(StateGroup group) {
        auto db = pool_.get_db();
        // SELECT type, state_key, event_id FROM state_groups_state
        // WHERE state_group = ?
        (void)group;
        return {};
    }

    // ---- Add edge between state groups ----
    void add_edge(StateGroup group, StateGroup prev_group) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("add_state_edge");
        // INSERT INTO state_group_edges (state_group, prev_state_group)
        // VALUES (?, ?) ON CONFLICT DO NOTHING
        (void)group;
        (void)prev_group;
        txn.commit();
    }

    // ---- Get ancestor chain ----
    std::vector<StateGroup> get_ancestors(StateGroup group, int limit = 100) {
        std::vector<StateGroup> chain;
        auto db = pool_.get_db();
        // Recursive CTE or iterative fetch:
        // SELECT prev_state_group FROM state_group_edges WHERE state_group = ?
        (void)group;
        (void)limit;
        return chain;
    }

    // ---- Check if state group exists ----
    bool exists(StateGroup group) {
        auto db = pool_.get_db();
        // SELECT 1 FROM state_groups WHERE id = ?
        (void)group;
        return false;
    }

private:
    StateGroup allocate_state_group_id() {
        static std::atomic<StateGroup> next{1};
        return next.fetch_add(1);
    }

    DatabasePool& pool_;
};

// =============================================================================
// 4. Event to State Group Mapping
// =============================================================================

class EventStateGroupMapper {
public:
    explicit EventStateGroupMapper(DatabasePool& pool) : pool_(pool) {}

    void set_state_group(const EventId& event_id, StateGroup group,
                          const RoomId& room_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("set_event_state_group");
        // INSERT INTO event_to_state_groups (event_id, state_group, room_id)
        // VALUES (?, ?, ?)
        (void)event_id;
        (void)group;
        (void)room_id;
        txn.commit();
    }

    std::optional<StateGroup> get_state_group(const EventId& event_id) {
        auto db = pool_.get_db();
        // SELECT state_group FROM event_to_state_groups WHERE event_id = ?
        (void)event_id;
        return std::nullopt;
    }

    std::vector<EventId> get_events_in_state_group(StateGroup group) {
        auto db = pool_.get_db();
        // SELECT event_id FROM event_to_state_groups WHERE state_group = ?
        (void)group;
        return {};
    }

    // Batch load
    std::unordered_map<EventId, StateGroup>
    get_state_groups_batch(const std::vector<EventId>& event_ids) {
        std::unordered_map<EventId, StateGroup> result;
        auto db = pool_.get_db();
        // SELECT event_id, state_group FROM event_to_state_groups
        // WHERE event_id IN (?, ?, ...)
        (void)event_ids;
        return result;
    }

    // Update state group reference (e.g. after backfill)
    void update_state_group(const EventId& event_id, StateGroup new_group) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("update_event_state_group");
        // UPDATE event_to_state_groups SET state_group = ? WHERE event_id = ?
        (void)event_id;
        (void)new_group;
        txn.commit();
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 5. State Resolution Storage (cached resolution results)
// =============================================================================

struct ResolvedState {
    StateGroup resolved_group;
    int64_t    created_at;
    int64_t    ttl_seconds;
    // serialized state map stored separately.
};

class StateResolutionCache {
public:
    explicit StateResolutionCache(DatabasePool& pool) : pool_(pool) {}

    // ---- Cache a resolution result ----
    void cache_resolution(const std::vector<StateGroup>& input_groups,
                          StateGroup resolved_group,
                          int64_t ttl_seconds = 86400) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("cache_state_resolution");

        // Build a deterministic key from sorted input groups
        std::vector<StateGroup> sorted(input_groups);
        std::sort(sorted.begin(), sorted.end());
        std::ostringstream oss;
        for (size_t i = 0; i < sorted.size(); ++i) {
            if (i) oss << ",";
            oss << sorted[i];
        }
        std::string input_key = oss.str();

        // INSERT INTO state_resolution_cache
        //   (input_hash, resolved_group, created_at, expires_at)
        // VALUES (?, ?, ?, ?)
        int64_t now = static_cast<int64_t>(now_seconds());
        (void)input_key;
        (void)resolved_group;
        (void)ttl_seconds;
        (void)now;
        txn.commit();
    }

    // ---- Look up cached resolution ----
    std::optional<StateGroup>
    lookup_resolution(const std::vector<StateGroup>& input_groups) {
        std::vector<StateGroup> sorted(input_groups);
        std::sort(sorted.begin(), sorted.end());
        std::ostringstream oss;
        for (size_t i = 0; i < sorted.size(); ++i) {
            if (i) oss << ",";
            oss << sorted[i];
        }
        std::string input_key = oss.str();

        auto db = pool_.get_db();
        // SELECT resolved_group FROM state_resolution_cache
        // WHERE input_hash = ? AND expires_at > NOW()
        (void)input_key;
        return std::nullopt;
    }

    // ---- Invalidate stale entries ----
    size_t invalidate_expired() {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("invalidate_resolution_cache");
        // DELETE FROM state_resolution_cache WHERE expires_at <= NOW()
        size_t removed = 0;
        (void)removed;
        txn.commit();
        return removed;
    }

    // ---- Clear all resolution cache for a room ----
    void clear_room(const RoomId& room_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("clear_room_resolution_cache");
        // DELETE FROM state_resolution_cache
        // WHERE input_hash IN (
        //   SELECT DISTINCT input_hash FROM state_resolution_cache
        //   JOIN state_groups ON ... WHERE room_id = ?
        // )
        (void)room_id;
        txn.commit();
    }

    // ---- Get cache statistics ----
    struct CacheStats {
        size_t total_entries    = 0;
        size_t expired_entries  = 0;
        size_t hit_count        = 0;
        size_t miss_count       = 0;
    };

    CacheStats stats() {
        CacheStats s;
        auto db = pool_.get_db();
        // SELECT COUNT(*), SUM(CASE WHEN expires_at <= NOW() THEN 1 ELSE 0 END)
        // FROM state_resolution_cache
        (void)db;
        return s;
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 6. Room Statistics
// =============================================================================

class RoomStatistics {
public:
    explicit RoomStatistics(DatabasePool& pool) : pool_(pool) {}

    struct RoomStats {
        RoomId    room_id;
        int64_t   joined_members        = 0;
        int64_t   local_users_in_room   = 0;
        int64_t   invited_members       = 0;
        int64_t   banned_members        = 0;
        int64_t   total_events          = 0;
        int64_t   state_events          = 0;
        int64_t   forward_extremities   = 0;
        int64_t   backward_extremities  = 0;
        int64_t   depth                 = 0;
        int64_t   highlight_count       = 0;
        bool      is_encrypted          = false;
        bool      has_federation        = false;
        std::string room_name;
        std::string room_topic;
        int64_t   bytes_used            = 0;
    };

    // ---- Compute stats for a room ----
    RoomStats compute_room_stats(const RoomId& room_id) {
        RoomStats stats;
        stats.room_id = room_id;
        auto db = pool_.get_db();

        // SELECT COUNT(*) FROM current_state_events
        // WHERE room_id = ? AND membership = 'join'
        stats.joined_members = 0;

        // SELECT COUNT(*) FROM current_state_events
        // WHERE room_id = ? AND membership = 'join' AND is_local = true
        stats.local_users_in_room = 0;

        // SELECT COUNT(*) FROM current_state_events
        // WHERE room_id = ? AND membership = 'invite'
        stats.invited_members = 0;

        // SELECT COUNT(*) FROM current_state_events
        // WHERE room_id = ? AND membership = 'ban'
        stats.banned_members = 0;

        // SELECT COUNT(*) FROM events WHERE room_id = ?
        stats.total_events = 0;

        // SELECT COUNT(*) FROM events WHERE room_id = ? AND type LIKE 'm.room.%'
        stats.state_events = 0;

        // SELECT COUNT(*) FROM event_forward_extremities WHERE room_id = ?
        stats.forward_extremities = 0;

        // SELECT COUNT(*) FROM event_backward_extremities WHERE room_id = ?
        stats.backward_extremities = 0;

        // SELECT COALESCE(MAX(depth), 0) FROM events WHERE room_id = ?
        stats.depth = 0;

        (void)db;
        return stats;
    }

    // ---- Bulk room stats ----
    std::vector<RoomStats> compute_all_room_stats() {
        std::vector<RoomStats> results;
        // SELECT room_id FROM rooms
        // For each room, call compute_room_stats
        return results;
    }

    // ---- Update joined members count quickly ----
    void update_joined_members(const RoomId& room_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("update_joined_members");
        int64_t count = 0;
        // SELECT COUNT(*) FROM current_state_events
        // WHERE room_id = ? AND type='m.room.member' AND membership='join'
        // UPSERT INTO room_stats_current (room_id, joined_members, updated_at)
        // VALUES (?, ?, NOW())
        (void)room_id;
        (void)count;
        txn.commit();
    }

    // ---- Get largest rooms by member count ----
    std::vector<std::pair<RoomId, int64_t>> largest_rooms(int limit = 50) {
        std::vector<std::pair<RoomId, int64_t>> out;
        auto db = pool_.get_db();
        // SELECT room_id, joined_members FROM room_stats_current
        // ORDER BY joined_members DESC LIMIT ?
        (void)db;
        (void)limit;
        return out;
    }

    // ---- Server participation in room ----
    struct ServerParticipation {
        std::string server_name;
        int64_t     user_count;
        int64_t     room_count;
    };

    std::vector<ServerParticipation> server_participation(const RoomId& room_id) {
        std::vector<ServerParticipation> out;
        auto db = pool_.get_db();
        // SELECT server_name, COUNT(*) FROM current_state_events
        // WHERE room_id = ? AND membership='join'
        // GROUP BY server_name
        (void)room_id;
        (void)db;
        return out;
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 7. Monthly Active Users (MAU) Tracking
// =============================================================================

class MonthlyActiveUsers {
public:
    explicit MonthlyActiveUsers(DatabasePool& pool)
        : pool_(pool), max_mau_limit_(0) {}

    // ---- Record user activity ----
    void record_user_active(const UserId& user_id, uint64_t timestamp_ms = 0) {
        if (timestamp_ms == 0) timestamp_ms = now_millis();
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("record_mau");

        std::string month = month_key();
        // INSERT INTO monthly_active_users (user_id, month_key, last_active)
        // VALUES (?, ?, ?)
        // ON CONFLICT (user_id, month_key) DO UPDATE SET last_active = ?
        (void)user_id;
        (void)month;
        (void)timestamp_ms;
        txn.commit();
    }

    // ---- Check if MAU limit is exceeded ----
    bool is_mau_limit_reached() {
        if (max_mau_limit_ == 0) return false; // no limit
        int64_t current = count_current_mau();
        return current >= max_mau_limit_;
    }

    // ---- Count MAU for current month ----
    int64_t count_current_mau() {
        auto db = pool_.get_db();
        std::string month = month_key();
        // SELECT COUNT(DISTINCT user_id) FROM monthly_active_users
        // WHERE month_key = ?
        (void)month;
        (void)db;
        return 0;
    }

    // ---- Get MAU for a specific month ----
    int64_t count_mau_for_month(const std::string& month) {
        auto db = pool_.get_db();
        // SELECT COUNT(DISTINCT user_id) FROM monthly_active_users
        // WHERE month_key = ?
        (void)month;
        (void)db;
        return 0;
    }

    // ---- List all MAU for a month ----
    std::vector<UserId> get_mau_list(const std::string& month) {
        auto db = pool_.get_db();
        // SELECT DISTINCT user_id FROM monthly_active_users WHERE month_key = ?
        (void)month;
        (void)db;
        return {};
    }

    // ---- Set MAU limit (0 = no limit) ----
    void set_mau_limit(int64_t limit) {
        max_mau_limit_ = limit;
    }

    int64_t mau_limit() const { return max_mau_limit_; }

    // ---- Prune old MAU records ----
    size_t prune_old(int keep_months = 24) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("prune_mau");
        // DELETE FROM monthly_active_users
        // WHERE month_key < date('now', '-' || ? || ' months')
        size_t removed = 0;
        (void)keep_months;
        txn.commit();
        return removed;
    }

    // ---- Reserve a MAU slot for registration (prevent exceeding limit) ----
    bool try_reserve_slot(const UserId& user_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("reserve_mau_slot");

        if (max_mau_limit_ > 0) {
            int64_t current = count_current_mau();
            if (current >= max_mau_limit_) {
                // Check if this user is already counted
                // If user has no activity this month, reject
                (void)user_id;
                txn.rollback();
                return false;
            }
        }
        record_user_active(user_id);
        txn.commit();
        return true;
    }

private:
    DatabasePool& pool_;
    int64_t max_mau_limit_;
};

// =============================================================================
// 8. Daily Active Users (DAU) Tracking
// =============================================================================

class DailyActiveUsers {
public:
    explicit DailyActiveUsers(DatabasePool& pool) : pool_(pool) {}

    // ---- Record daily activity ----
    void record_user_active(const UserId& user_id, uint64_t timestamp_ms = 0) {
        if (timestamp_ms == 0) timestamp_ms = now_millis();
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("record_dau");

        std::string date = today_date();
        // INSERT INTO daily_active_users (user_id, date, last_active, event_count)
        // VALUES (?, ?, ?, 1)
        // ON CONFLICT (user_id, date) DO UPDATE
        //   SET last_active = ?, event_count = event_count + 1
        (void)user_id;
        (void)date;
        (void)timestamp_ms;
        txn.commit();
    }

    // ---- Count DAU for today ----
    int64_t count_today() {
        return count_for_date(today_date());
    }

    // ---- Count DAU for a specific date ----
    int64_t count_for_date(const std::string& date) {
        auto db = pool_.get_db();
        // SELECT COUNT(DISTINCT user_id) FROM daily_active_users WHERE date = ?
        (void)date;
        (void)db;
        return 0;
    }

    // ---- Get DAU time series ----
    struct DayCount {
        std::string date;
        int64_t     users;
    };

    std::vector<DayCount> dau_series(int days_back = 30) {
        std::vector<DayCount> out;
        auto db = pool_.get_db();
        // SELECT date, COUNT(DISTINCT user_id) FROM daily_active_users
        // WHERE date >= date('now', '-? days') GROUP BY date ORDER BY date
        (void)days_back;
        (void)db;
        return out;
    }

    // ---- Get 7-day and 30-day rolling averages ----
    struct RollingStats {
        double avg_7day  = 0.0;
        double avg_30day = 0.0;
        int64_t peak_7day  = 0;
        int64_t peak_30day = 0;
    };

    RollingStats rolling_averages() {
        RollingStats stats;
        auto db = pool_.get_db();
        // Complex query computing moving averages
        (void)db;
        return stats;
    }

    // ---- Get most active users today ----
    std::vector<std::pair<UserId, int64_t>> top_users_today(int limit = 100) {
        std::vector<std::pair<UserId, int64_t>> out;
        auto db = pool_.get_db();
        // SELECT user_id, event_count FROM daily_active_users
        // WHERE date = ? ORDER BY event_count DESC LIMIT ?
        (void)db;
        (void)limit;
        return out;
    }

    // ---- Prune old DAU data ----
    size_t prune_old(int keep_days = 90) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("prune_dau");
        // DELETE FROM daily_active_users WHERE date < date('now', '-? days')
        size_t removed = 0;
        (void)keep_days;
        txn.commit();
        return removed;
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 9. User Directory Search Index
// =============================================================================

class UserDirectoryIndex {
public:
    explicit UserDirectoryIndex(DatabasePool& pool) : pool_(pool) {}

    // ---- Update user in search index (on profile change) ----
    void update_user(const UserId& user_id,
                     const std::optional<std::string>& display_name,
                     const std::optional<std::string>& avatar_url) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("update_user_directory");

        // UPSERT INTO user_directory (user_id, display_name, avatar_url, updated_at)
        // VALUES (?, ?, ?, NOW())
        (void)user_id;
        (void)display_name;
        (void)avatar_url;
        txn.commit();
    }

    // ---- Remove user from search index ----
    void remove_user(const UserId& user_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("remove_user_directory");
        // DELETE FROM user_directory WHERE user_id = ?
        (void)user_id;
        txn.commit();
    }

    // ---- Search users ----
    struct UserSearchResult {
        UserId      user_id;
        std::string display_name;
        std::string avatar_url;
        double      relevance = 0.0;
    };

    std::vector<UserSearchResult> search(const std::string& query,
                                          int limit = 50) {
        std::vector<UserSearchResult> out;
        auto db = pool_.get_db();
        // Full-text or LIKE search on display_name / user_id
        // SELECT user_id, display_name, avatar_url,
        //   similarity(display_name, ?) as relevance
        // FROM user_directory
        // WHERE display_name ILIKE '%' || ? || '%'
        //    OR user_id ILIKE '%' || ? || '%'
        // ORDER BY relevance DESC LIMIT ?
        (void)query;
        (void)limit;
        (void)db;
        return out;
    }

    // ---- Populate index from existing users ----
    BackgroundUpdate create_populate_update() {
        BackgroundUpdate upd;
        upd.update_name = "populate_user_directory";
        upd.run_once    = true;
        upd.batch_size  = 500;
        upd.runner      = [this](LoggingTransaction& txn) -> size_t {
            return populate_from_users_batch(txn);
        };
        return upd;
    }

    // ---- Rebuild entire index ----
    void rebuild_index() {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("rebuild_user_directory");
        // DELETE FROM user_directory;
        // INSERT INTO user_directory (user_id, display_name, avatar_url)
        // SELECT ...
        txn.commit();
    }

    // ---- Get indexed user count ----
    int64_t indexed_count() {
        auto db = pool_.get_db();
        // SELECT COUNT(*) FROM user_directory
        (void)db;
        return 0;
    }

private:
    size_t populate_from_users_batch(LoggingTransaction& /*txn*/) {
        // Read next batch of unindexed users, insert into user_directory
        // Returns number of users processed
        return 0;
    }

    DatabasePool& pool_;
};

// =============================================================================
// 10. Room Directory (public rooms listing)
// =============================================================================

class RoomDirectory {
public:
    explicit RoomDirectory(DatabasePool& pool) : pool_(pool) {}

    // ---- Publish a room to directory ----
    void publish_room(const RoomId& room_id, const std::string& visibility = "public") {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("publish_room");
        // INSERT INTO room_directory (room_id, visibility, published_at)
        // VALUES (?, ?, NOW())
        // ON CONFLICT (room_id) DO UPDATE SET visibility = ?
        (void)room_id;
        (void)visibility;
        txn.commit();
    }

    // ---- Unpublish a room ----
    void unpublish_room(const RoomId& room_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("unpublish_room");
        // DELETE FROM room_directory WHERE room_id = ?
        (void)room_id;
        txn.commit();
    }

    // ---- Update room directory metadata ----
    void update_room_metadata(const RoomId& room_id,
                               const std::string& name,
                               const std::string& topic,
                               const std::string& avatar_url,
                               int64_t num_joined_members,
                               bool world_readable) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("update_room_metadata");
        // UPDATE room_directory SET
        //   name = ?, topic = ?, avatar_url = ?,
        //   num_joined_members = ?, world_readable = ?
        // WHERE room_id = ?
        (void)room_id;
        (void)name;
        (void)topic;
        (void)avatar_url;
        (void)num_joined_members;
        (void)world_readable;
        txn.commit();
    }

    // ---- Search public rooms with pagination ----
    struct PublicRoom {
        RoomId      room_id;
        std::string name;
        std::string topic;
        std::string avatar_url;
        int64_t     num_joined_members = 0;
        bool        world_readable     = false;
        std::string canonical_alias;
        std::vector<std::string> aliases;
        std::string room_type;
    };

    struct RoomDirectoryResult {
        std::vector<PublicRoom> rooms;
        std::string             next_batch;
        int64_t                 total_rooms = 0;
    };

    RoomDirectoryResult list_rooms(
            const std::optional<std::string>& search_term = std::nullopt,
            const std::optional<std::string>& order_by    = std::nullopt,
            const std::optional<std::string>& direction   = std::nullopt,
            int limit = 50,
            const std::optional<std::string>& from_token  = std::nullopt,
            const std::optional<std::string>& server      = std::nullopt,
            bool only_public = true) {

        RoomDirectoryResult result;
        auto db = pool_.get_db();

        // Build query dynamically:
        // SELECT room_id, name, topic, avatar_url, num_joined_members,
        //        world_readable, canonical_alias
        // FROM room_directory
        // WHERE visibility = 'public' AND (search conditions)
        // ORDER BY num_joined_members DESC
        // LIMIT ? OFFSET ?

        (void)search_term;
        (void)order_by;
        (void)direction;
        (void)limit;
        (void)from_token;
        (void)server;
        (void)only_public;
        (void)db;
        return result;
    }

    // ---- List rooms for a specific server (federation) ----
    RoomDirectoryResult list_rooms_for_server(
            const std::string& server_name,
            int limit = 50,
            const std::optional<std::string>& since = std::nullopt) {
        RoomDirectoryResult result;
        auto db = pool_.get_db();
        // Only rooms with users from this server
        (void)server_name;
        (void)limit;
        (void)since;
        (void)db;
        return result;
    }

    // ---- Count public rooms ----
    int64_t count_public_rooms() {
        auto db = pool_.get_db();
        // SELECT COUNT(*) FROM room_directory WHERE visibility = 'public'
        (void)db;
        return 0;
    }

    // ---- Check if room is published ----
    bool is_published(const RoomId& room_id) {
        auto db = pool_.get_db();
        // SELECT 1 FROM room_directory WHERE room_id = ? AND visibility = 'public'
        (void)room_id;
        (void)db;
        return false;
    }

    // ---- Get room aliases ----
    std::vector<std::string> get_room_aliases(const RoomId& room_id) {
        auto db = pool_.get_db();
        // SELECT room_alias FROM room_aliases WHERE room_id = ?
        (void)room_id;
        (void)db;
        return {};
    }

    // ---- Recompute joined member counts in directory ----
    BackgroundUpdate create_recount_update() {
        BackgroundUpdate upd;
        upd.update_name = "recount_room_directory_members";
        upd.run_once    = false;
        upd.batch_size  = 100;
        upd.runner      = [this](LoggingTransaction& txn) -> size_t {
            return recount_members_batch(txn);
        };
        return upd;
    }

private:
    size_t recount_members_batch(LoggingTransaction& /*txn*/) {
        // Update num_joined_members in room_directory from current_state_events
        return 0;
    }

    DatabasePool& pool_;
};

// =============================================================================
// 11. Current State Delta Storage
// =============================================================================

struct StateDelta {
    RoomId  room_id;
    int64_t stream_ordering;
    std::string event_type;
    std::string state_key;
    std::optional<std::string> prev_event_id;  // nullopt if insert
    std::optional<std::string> new_event_id;    // nullopt if delete
};

class CurrentStateDeltaStorage {
public:
    explicit CurrentStateDeltaStorage(DatabasePool& pool) : pool_(pool) {}

    // ---- Record a state delta ----
    void record_delta(const StateDelta& delta) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("record_state_delta");

        // INSERT INTO current_state_deltas
        //   (room_id, stream_ordering, event_type, state_key,
        //    prev_event_id, new_event_id)
        // VALUES (?, ?, ?, ?, ?, ?)
        (void)delta;
        txn.commit();
    }

    // ---- Get all deltas since a given stream position ----
    std::vector<StateDelta> get_deltas_since(const RoomId& room_id,
                                               int64_t since_stream) {
        std::vector<StateDelta> out;
        auto db = pool_.get_db();
        // SELECT * FROM current_state_deltas
        // WHERE room_id = ? AND stream_ordering > ?
        // ORDER BY stream_ordering ASC
        (void)room_id;
        (void)since_stream;
        (void)db;
        return out;
    }

    // ---- Compress deltas older than a threshold ----
    size_t compress_deltas(const RoomId& room_id, int64_t before_stream) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("compress_state_deltas");

        // For deltas before the threshold, we can merge them into
        // a single "snapshot" entry and remove individual deltas.
        // INSERT INTO state_delta_snapshots (room_id, up_to_stream, state_json)
        // SELECT ?, MAX(stream_ordering), json_group_object(...)
        // FROM current_state_deltas WHERE room_id = ? AND stream_ordering <= ?
        // DELETE FROM current_state_deltas
        // WHERE room_id = ? AND stream_ordering <= ?

        size_t compressed = 0;
        (void)room_id;
        (void)before_stream;
        txn.commit();
        return compressed;
    }

    // ---- Reconstruct current state from deltas ----
    std::map<std::string, std::string>
    reconstruct_current(const RoomId& room_id) {
        std::map<std::string, std::string> state;
        auto db = pool_.get_db();
        // Walk deltas in order, applying each one.
        // Or, more efficiently, load the latest snapshot and apply deltas since.
        (void)room_id;
        (void)db;
        return state;
    }

    // ---- Prune old deltas ----
    size_t prune_deltas(int64_t older_than_seconds) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("prune_state_deltas");
        // DELETE FROM current_state_deltas WHERE created_at < ? - ?
        size_t pruned = 0;
        (void)older_than_seconds;
        txn.commit();
        return pruned;
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 12. Purge History (delete events from room up to a point)
// =============================================================================

class PurgeHistory {
public:
    explicit PurgeHistory(DatabasePool& pool) : pool_(pool) {}

    struct PurgeResult {
        int64_t events_deleted     = 0;
        int64_t state_groups_freed = 0;
        int64_t bytes_freed        = 0;
        std::string error;
        bool success = false;
    };

    // ---- Purge events up to (and including) a given event/token ----
    PurgeResult purge_before_event(const RoomId& room_id,
                                    const EventId& before_event_id,
                                    bool delete_local = false) {
        PurgeResult result;
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("purge_history");

        // 1. Find topological ordering / depth of the target event
        // SELECT depth, stream_ordering FROM events
        // WHERE event_id = ? AND room_id = ?

        // 2. Select all events in room with depth <= that depth
        //    that are NOT state events needed for current state.
        // SELECT event_id FROM events
        // WHERE room_id = ? AND depth <= ? AND NOT is_state
        // AND event_id NOT IN (
        //   SELECT event_id FROM current_state_events WHERE room_id = ?
        // )

        // 3. Respect `delete_local` flag — skip events from local users if false.

        // 4. Delete in chunks to avoid long transactions:
        //    DELETE FROM event_json WHERE event_id IN (...)
        //    DELETE FROM event_edges WHERE event_id IN (...)
        //    DELETE FROM event_forward_extremities WHERE event_id IN (...)
        //    DELETE FROM event_to_state_groups WHERE event_id IN (...)
        //    DELETE FROM events WHERE event_id IN (...)

        // 5. Recalculate room depth/stream as needed

        (void)room_id;
        (void)before_event_id;
        (void)delete_local;

        result.success = true;
        txn.commit();
        return result;
    }

    // ---- Purge all history before a timestamp ----
    PurgeResult purge_before_ts(const RoomId& room_id,
                                 int64_t before_timestamp_ms) {
        PurgeResult result;
        // Find last event before timestamp, then call purge_before_event
        (void)room_id;
        (void)before_timestamp_ms;
        return result;
    }

    // ---- Count events that would be purged (dry run) ----
    int64_t count_purgeable(const RoomId& room_id,
                             const EventId& before_event_id) {
        auto db = pool_.get_db();
        // SELECT COUNT(*) FROM events
        // WHERE room_id = ? AND depth <= (SELECT depth FROM events WHERE event_id = ?)
        // AND event_id NOT IN (SELECT event_id FROM current_state_events WHERE room_id = ?)
        (void)room_id;
        (void)before_event_id;
        (void)db;
        return 0;
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 13. Purge Room (complete room deletion)
// =============================================================================

class PurgeRoom {
public:
    explicit PurgeRoom(DatabasePool& pool) : pool_(pool) {}

    struct PurgeRoomResult {
        int64_t events_deleted      = 0;
        int64_t state_groups_freed  = 0;
        int64_t bytes_freed         = 0;
        std::vector<std::string> tables_cleaned;
        bool success = false;
        std::string error;
    };

    // ---- Full room purge ----
    PurgeRoomResult purge_room(const RoomId& room_id, bool force = false) {
        PurgeRoomResult result;
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("purge_room_full");

        // List of tables to clean:
        static const std::vector<std::string> tables = {
            "events",
            "event_json",
            "event_edges",
            "event_forward_extremities",
            "event_backward_extremities",
            "event_to_state_groups",
            "state_groups_state",
            "state_group_edges",
            "state_groups",
            "current_state_events",
            "current_state_deltas",
            "room_memberships",
            "room_aliases",
            "room_tags",
            "room_account_data",
            "event_reports",
            "event_reactions",
            "event_relations",
            "redactions",
            "receipts_graph",
            "receipts_linearized",
            "room_stats_current",
            "room_stats_historical",
            "room_stats_state",
            "user_directory_rooms",
            "local_current_membership",
            "pusher_throttle",
            "room_depth",
            "stream_ordering_to_exterm",
            "e2e_room_keys",
            "event_push_actions",
            "event_push_actions_staging",
            "event_push_summary",
            "event_push_summary_staging",
            "event_search",
            "room_directory",
        };

        for (auto& table : tables) {
            // DELETE FROM {table} WHERE room_id = ?
            result.tables_cleaned.push_back(table);
            (void)table;
        }

        // Also clean room from rooms table itself
        // DELETE FROM rooms WHERE room_id = ?

        (void)room_id;
        (void)force;

        result.success = true;
        txn.commit();
        return result;
    }

    // ---- Dry-run room deletion (count what would be removed) ----
    struct CountResult {
        int64_t events          = 0;
        int64_t state_groups    = 0;
        int64_t current_state   = 0;
        int64_t extremeties     = 0;
        int64_t total_rows      = 0;
    };

    CountResult count_room_data(const RoomId& room_id) {
        CountResult counts;
        auto db = pool_.get_db();
        // SELECT COUNT(*) FROM events WHERE room_id = ?
        (void)room_id;
        (void)db;
        return counts;
    }

    // ---- Shutdown a room (mark as purged, keep minimal metadata) ----
    void shutdown_room(const RoomId& room_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("shutdown_room");
        // Mark room as purged / shut down.
        // Keep a tombstone entry so the room_id is not reused.
        // INSERT INTO purged_rooms (room_id, purged_at) VALUES (?, NOW())
        (void)room_id;
        txn.commit();
    }

    // ---- Check if a room has been purged ----
    bool is_purged(const RoomId& room_id) {
        auto db = pool_.get_db();
        // SELECT 1 FROM purged_rooms WHERE room_id = ?
        (void)room_id;
        (void)db;
        return false;
    }

    // ---- List purged rooms ----
    std::vector<std::pair<RoomId, int64_t>> list_purged_rooms() {
        std::vector<std::pair<RoomId, int64_t>> out;
        auto db = pool_.get_db();
        // SELECT room_id, purged_at FROM purged_rooms ORDER BY purged_at DESC
        (void)db;
        return out;
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 14. Sharded Event ID Generation
// =============================================================================

class ShardedEventIdGenerator {
public:
    explicit ShardedEventIdGenerator(DatabasePool& pool,
                                      const std::string& server_name = "localhost",
                                      int shard_count = 16)
        : pool_(pool),
          server_name_(server_name),
          shard_count_(shard_count)
    {
        // Ensure shard registry exists
        init_shards();
    }

    // ---- Generate next event ID ----
    EventId generate_event_id(const RoomId& room_id) {
        int shard = pick_shard(room_id);
        int64_t local_id = next_local_id(shard);
        return format_event_id(shard, local_id);
    }

    // ---- Generate a batch of event IDs ----
    std::vector<EventId> generate_event_ids(const RoomId& room_id, size_t count) {
        std::vector<EventId> ids;
        ids.reserve(count);
        int shard = pick_shard(room_id);
        for (size_t i = 0; i < count; ++i) {
            int64_t local_id = next_local_id(shard);
            ids.push_back(format_event_id(shard, local_id));
        }
        return ids;
    }

    // ---- Parse an event ID back into shard and local ID ----
    struct ParsedEventId {
        int     shard;
        int64_t local_id;
        bool    valid = false;
    };

    ParsedEventId parse(const EventId& event_id) {
        ParsedEventId parsed;
        // Format: "$<shard_hex><local_id_hex>-<server_name>"
        // Simple parse:
        if (event_id.size() < 3 || event_id[0] != '$') return parsed;

        auto dash_pos = event_id.rfind('-');
        if (dash_pos == std::string::npos) return parsed;

        auto id_part = event_id.substr(1, dash_pos - 1);
        if (id_part.size() < 3) return parsed;

        try {
            auto shard_hex = id_part.substr(0, 2);
            parsed.shard = std::stoi(shard_hex, nullptr, 16);
            parsed.local_id = std::stoll(id_part.substr(2), nullptr, 16);
            parsed.valid = true;
        } catch (...) {
            parsed.valid = false;
        }
        return parsed;
    }

    // ---- Get current max ID for a shard ----
    int64_t get_max_local_id(int shard) {
        auto db = pool_.get_db();
        // SELECT max_local_id FROM event_id_shards WHERE shard = ?
        (void)shard;
        (void)db;
        return 0;
    }

    // ---- Set shard count ----
    void set_shard_count(int count) {
        shard_count_ = count;
        init_shards();
    }

    int get_shard_count() const { return shard_count_; }

    // ---- Reserve a range of IDs for bulk import ----
    struct ReservedRange {
        int     shard;
        int64_t start_id;
        int64_t end_id;
    };

    ReservedRange reserve_range(int shard, int64_t count) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("reserve_id_range");
        // UPDATE event_id_shards
        // SET max_local_id = max_local_id + ?
        // WHERE shard = ?
        // RETURNING max_local_id - ? + 1 as start_id, max_local_id as end_id
        ReservedRange rng;
        rng.shard    = shard;
        rng.start_id = 0;
        rng.end_id   = count - 1;
        (void)count;
        txn.commit();
        return rng;
    }

private:
    void init_shards() {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("init_event_id_shards");
        for (int i = 0; i < shard_count_; ++i) {
            // INSERT INTO event_id_shards (shard, server_name, max_local_id)
            // VALUES (?, ?, 0) ON CONFLICT DO NOTHING
            (void)i;
        }
        txn.commit();
    }

    int pick_shard(const RoomId& room_id) {
        // Deterministic shard selection based on room_id hash
        std::hash<std::string> hasher;
        size_t h = hasher(room_id);
        return static_cast<int>(h % shard_count_);
    }

    int64_t next_local_id(int shard) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("next_event_id");
        // UPDATE event_id_shards
        // SET max_local_id = max_local_id + 1
        // WHERE shard = ?
        // RETURNING max_local_id
        int64_t id = 0;
        (void)shard;
        (void)db;
        txn.commit();
        return id;
    }

    std::string format_event_id(int shard, int64_t local_id) {
        std::ostringstream oss;
        oss << "$"
            << std::hex << std::setfill('0') << std::setw(2) << (shard & 0xFF)
            << std::hex << std::setfill('0') << std::setw(12) << local_id
            << "-" << server_name_;
        return oss.str();
    }

    DatabasePool& pool_;
    std::string server_name_;
    int shard_count_;
};

// =============================================================================
// 15. Stream Ordering (event stream positions per room)
// =============================================================================

class StreamOrdering {
public:
    explicit StreamOrdering(DatabasePool& pool) : pool_(pool) {}

    // ---- Allocate next stream position for a room ----
    StreamPos allocate_stream_pos(const RoomId& room_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("allocate_stream_pos");

        // UPDATE stream_positions
        // SET position = position + 1
        // WHERE room_id = ? AND stream_type = 'event'
        // RETURNING position
        // On first use, INSERT with position = 1
        StreamPos pos = 0;
        (void)room_id;
        (void)db;
        txn.commit();
        return pos;
    }

    // ---- Get current stream position ----
    StreamPos current_stream_pos(const RoomId& room_id,
                                  const std::string& stream_type = "event") {
        auto db = pool_.get_db();
        // SELECT position FROM stream_positions
        // WHERE room_id = ? AND stream_type = ?
        (void)room_id;
        (void)stream_type;
        (void)db;
        return 0;
    }

    // ---- Get events after a given stream position (paginated) ----
    struct StreamEvent {
        EventId   event_id;
        StreamPos stream_pos;
        int64_t   depth;
    };

    std::vector<StreamEvent> get_events_since(const RoomId& room_id,
                                                StreamPos since,
                                                int limit = 100) {
        std::vector<StreamEvent> out;
        auto db = pool_.get_db();
        // SELECT event_id, stream_ordering, depth FROM events
        // WHERE room_id = ? AND stream_ordering > ?
        // ORDER BY stream_ordering ASC LIMIT ?
        (void)room_id;
        (void)since;
        (void)limit;
        (void)db;
        return out;
    }

    // ---- Get max stream position across all rooms ----
    StreamPos global_max_stream_pos() {
        auto db = pool_.get_db();
        // SELECT COALESCE(MAX(stream_ordering), 0) FROM events
        (void)db;
        return 0;
    }

    // ---- Bulk allocate stream positions (for batch imports) ----
    std::vector<StreamPos> allocate_stream_pos_batch(
            const RoomId& room_id, size_t count) {
        std::vector<StreamPos> positions;
        positions.reserve(count);
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("allocate_stream_pos_batch");
        // UPDATE stream_positions
        // SET position = position + ?
        // WHERE room_id = ? AND stream_type = 'event'
        // RETURNING position - ? + generate_series(0, ?) as positions
        for (size_t i = 0; i < count; ++i) {
            positions.push_back(0 + static_cast<StreamPos>(i));
        }
        (void)room_id;
        (void)count;
        txn.commit();
        return positions;
    }

    // ---- Reset stream position (dangerous, for admin use) ----
    void reset_stream_pos(const RoomId& room_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("reset_stream_pos");
        // DELETE FROM stream_positions WHERE room_id = ?
        (void)room_id;
        txn.commit();
    }

    // ---- Get all room stream positions ----
    struct RoomStreamPos {
        RoomId    room_id;
        StreamPos position;
    };

    std::vector<RoomStreamPos> all_stream_positions() {
        std::vector<RoomStreamPos> out;
        auto db = pool_.get_db();
        // SELECT room_id, position FROM stream_positions
        (void)db;
        return out;
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 16. Backfill Extremeties Tracking
// =============================================================================

struct BackwardExtremity {
    EventId   event_id;
    RoomId    room_id;
    int64_t   depth;
    bool      processed;
    int64_t   created_at;
};

class BackfillExtremetiesTracker {
public:
    explicit BackfillExtremetiesTracker(DatabasePool& pool) : pool_(pool) {}

    // ---- Insert a new backward extremity ----
    void insert(const BackwardExtremity& ext) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("insert_backward_extremity");
        // INSERT INTO event_backward_extremities
        //   (event_id, room_id, depth, processed, created_at)
        // VALUES (?, ?, ?, 0, NOW())
        // ON CONFLICT (event_id) DO NOTHING
        (void)ext;
        txn.commit();
    }

    // ---- Insert multiple extremities ----
    void insert_batch(const std::vector<BackwardExtremity>& extremities) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("insert_backward_extremities");
        for (auto& ext : extremities) {
            // INSERT ... ON CONFLICT DO NOTHING
            (void)ext;
        }
        txn.commit();
    }

    // ---- Mark extremity as processed (when backfill completes) ----
    void mark_processed(const EventId& event_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("mark_backward_extremity_processed");
        // UPDATE event_backward_extremities
        // SET processed = 1, processed_at = NOW()
        // WHERE event_id = ?
        (void)event_id;
        txn.commit();
    }

    // ---- Get unprocessed extremities for a room, ordered by depth ----
    std::vector<BackwardExtremity> get_unprocessed(const RoomId& room_id,
                                                      int limit = 10) {
        std::vector<BackwardExtremity> out;
        auto db = pool_.get_db();
        // SELECT event_id, room_id, depth, processed
        // FROM event_backward_extremities
        // WHERE room_id = ? AND processed = 0
        // ORDER BY depth DESC LIMIT ?
        (void)room_id;
        (void)limit;
        (void)db;
        return out;
    }

    // ---- Count outstanding extremities ----
    int64_t count_unprocessed(const RoomId& room_id) {
        auto db = pool_.get_db();
        // SELECT COUNT(*) FROM event_backward_extremities
        // WHERE room_id = ? AND processed = 0
        (void)room_id;
        (void)db;
        return 0;
    }

    // ---- Delete processed extremities older than threshold ----
    size_t prune_processed(int64_t older_than_seconds = 604800) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("prune_backward_extremities");
        // DELETE FROM event_backward_extremities
        // WHERE processed = 1 AND processed_at < NOW() - INTERVAL '? seconds'
        size_t removed = 0;
        (void)older_than_seconds;
        txn.commit();
        return removed;
    }

    // ---- Delete all extremities for a room ----
    void delete_for_room(const RoomId& room_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("delete_backward_extremities_room");
        // DELETE FROM event_backward_extremities WHERE room_id = ?
        (void)room_id;
        txn.commit();
    }

    // ---- Get rooms with most outstanding backward extremities ----
    struct RoomExtremityCount {
        RoomId room_id;
        int64_t count;
    };

    std::vector<RoomExtremityCount> rooms_needing_backfill(int top_n = 20) {
        std::vector<RoomExtremityCount> out;
        auto db = pool_.get_db();
        // SELECT room_id, COUNT(*) as cnt
        // FROM event_backward_extremities
        // WHERE processed = 0
        // GROUP BY room_id ORDER BY cnt DESC LIMIT ?
        (void)top_n;
        (void)db;
        return out;
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 17. Event Forward Extremeties Management
// =============================================================================

struct ForwardExtremity {
    EventId   event_id;
    RoomId    room_id;
    int64_t   depth;
    StateGroup state_group;
    int64_t   created_at;
};

class ForwardExtremetiesManager {
public:
    explicit ForwardExtremetiesManager(DatabasePool& pool) : pool_(pool) {}

    // ---- Add a forward extremity ----
    void add(const ForwardExtremity& ext) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("add_forward_extremity");
        // INSERT INTO event_forward_extremities
        //   (event_id, room_id, depth, state_group, created_at)
        // VALUES (?, ?, ?, ?, NOW())
        (void)ext;
        txn.commit();
    }

    // ---- Replace all forward extremities for a room (transactional) ----
    void replace_all(const RoomId& room_id,
                     const std::vector<ForwardExtremity>& new_extremities) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("replace_forward_extremities");
        // DELETE FROM event_forward_extremities WHERE room_id = ?
        // Then insert new ones.
        (void)room_id;
        (void)new_extremities;
        txn.commit();
    }

    // ---- Remove a specific forward extremity ----
    void remove(const EventId& event_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("remove_forward_extremity");
        // DELETE FROM event_forward_extremities WHERE event_id = ?
        (void)event_id;
        txn.commit();
    }

    // ---- Get all forward extremities for a room ----
    std::vector<ForwardExtremity> get_for_room(const RoomId& room_id) {
        std::vector<ForwardExtremity> out;
        auto db = pool_.get_db();
        // SELECT event_id, room_id, depth, state_group, created_at
        // FROM event_forward_extremities WHERE room_id = ?
        (void)room_id;
        (void)db;
        return out;
    }

    // ---- Count forward extremities per room ----
    int64_t count_for_room(const RoomId& room_id) {
        auto db = pool_.get_db();
        // SELECT COUNT(*) FROM event_forward_extremities WHERE room_id = ?
        (void)room_id;
        (void)db;
        return 0;
    }

    // ---- Detect rooms with excessive forward extremities (potential split-brain) ----
    struct RoomExtremityAlert {
        RoomId room_id;
        int64_t count;
        int64_t max_depth;
        int64_t min_depth;
        int64_t depth_gap;
    };

    std::vector<RoomExtremityAlert> detect_problem_rooms(
            int threshold = 5, int max_rooms = 50) {
        std::vector<RoomExtremityAlert> out;
        auto db = pool_.get_db();
        // SELECT room_id, COUNT(*) as cnt,
        //   MAX(depth) as max_d, MIN(depth) as min_d,
        //   MAX(depth) - MIN(depth) as gap
        // FROM event_forward_extremities
        // GROUP BY room_id
        // HAVING COUNT(*) > ?
        // ORDER BY cnt DESC LIMIT ?
        (void)threshold;
        (void)max_rooms;
        (void)db;
        return out;
    }

    // ---- Get state groups from forward extremities (used for resolution) ----
    std::vector<StateGroup> get_conflict_state_groups(const RoomId& room_id) {
        std::vector<StateGroup> groups;
        auto exts = get_for_room(room_id);
        for (auto& ext : exts) {
            groups.push_back(ext.state_group);
        }
        return groups;
    }

    // ---- Prune orphaned forward extremities (event doesn't exist) ----
    size_t prune_orphaned() {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("prune_orphan_forward_extremities");
        // DELETE FROM event_forward_extremities efe
        // WHERE NOT EXISTS (SELECT 1 FROM events e WHERE e.event_id = efe.event_id)
        size_t removed = 0;
        (void)removed;
        txn.commit();
        return removed;
    }

private:
    DatabasePool& pool_;
};

// =============================================================================
// 18. State Autocompression Trigger
// =============================================================================

class StateAutocompressionTrigger {
public:
    explicit StateAutocompressionTrigger(DatabasePool& pool,
                                          StateCompressor& compressor)
        : pool_(pool), compressor_(compressor) {}

    // ---- Check if a room needs compression ----
    struct CompressionNeed {
        RoomId room_id;
        bool   needs_compression = false;
        int64_t state_group_count = 0;
        int64_t uncompressed_bytes = 0;
        double  compression_ratio  = 0.0;
        int64_t state_events_count = 0;
    };

    CompressionNeed assess_room(const RoomId& room_id) {
        CompressionNeed need;
        need.room_id = room_id;
        auto db = pool_.get_db();

        // SELECT COUNT(*) FROM state_groups sg
        // JOIN event_to_state_groups e2s ON sg.id = e2s.state_group
        // WHERE e2s.room_id = ?

        // If state_groups > threshold (e.g. 1000), flag for compression.
        need.needs_compression = false;
        (void)db;
        return need;
    }

    // ---- Scan all rooms for compression candidates ----
    std::vector<CompressionNeed> find_compression_candidates(
            int64_t state_group_threshold = 500,
            int64_t uncompressed_bytes_threshold = 50 * 1024 * 1024) {

        std::vector<CompressionNeed> candidates;
        auto db = pool_.get_db();
        // SELECT ... FROM state_groups GROUP BY ...
        // HAVING COUNT(*) > ? OR SUM(size) > ?
        (void)state_group_threshold;
        (void)uncompressed_bytes_threshold;
        (void)db;
        return candidates;
    }

    // ---- Auto-compress rooms that exceed thresholds ----
    struct AutoCompressionResult {
        int     rooms_assessed   = 0;
        int     rooms_compressed = 0;
        int64_t bytes_saved      = 0;
        int64_t groups_removed   = 0;
    };

    AutoCompressionResult run_auto_compression(
            int max_rooms = 10,
            int64_t state_group_threshold = 500) {

        AutoCompressionResult result;
        auto candidates = find_compression_candidates(state_group_threshold);

        int processed = 0;
        for (auto& c : candidates) {
            if (processed >= max_rooms) break;
            ++result.rooms_assessed;

            try {
                auto stats = compressor_.compress_room(c.room_id);
                result.bytes_saved += (stats.total_bytes_before - stats.total_bytes_after);
                result.groups_removed += stats.groups_pruned;
                ++result.rooms_compressed;
                ++processed;
            } catch (...) {
                // Log and continue to next room
            }
        }
        return result;
    }

    // ---- Create a background update for periodic autocompression ----
    BackgroundUpdate create_autocompression_update() {
        BackgroundUpdate upd;
        upd.update_name = "autocompress_state";
        upd.run_once    = false;
        upd.batch_size  = 5;
        upd.runner      = [this](LoggingTransaction& txn) -> size_t {
            auto result = run_auto_compression(5, 500);
            (void)txn;
            return static_cast<size_t>(result.rooms_compressed);
        };
        return upd;
    }

    // ---- Set global compression thresholds ----
    void set_thresholds(int64_t group_count, int64_t bytes) {
        threshold_group_count_ = group_count;
        threshold_bytes_       = bytes;
    }

    // ---- Immediate compression trigger for a room after heavy activity ----
    void trigger_if_needed(const RoomId& room_id) {
        auto need = assess_room(room_id);
        if (need.needs_compression) {
            compressor_.compress_room(room_id);
        }
    }

    // ---- Schedule periodic compression check ----
    void schedule_periodic_check(int interval_seconds = 3600) {
        // In a real implementation, this would use a timer/scheduler.
        // Here we just store the interval for reference.
        periodic_interval_seconds_ = interval_seconds;
    }

    // ---- Get compression statistics ----
    struct GlobalCompressionStats {
        int64_t total_state_groups    = 0;
        int64_t total_uncompressed    = 0;
        int64_t total_compressed      = 0;
        double  overall_ratio         = 0.0;
        int64_t estimated_savings_bytes = 0;
        int     rooms_needing_compression = 0;
    };

    GlobalCompressionStats global_stats() {
        GlobalCompressionStats s;
        auto db = pool_.get_db();
        // Aggregate statistics across all rooms
        (void)db;
        return s;
    }

private:
    DatabasePool& pool_;
    StateCompressor& compressor_;
    int64_t threshold_group_count_ = 500;
    int64_t threshold_bytes_ = 50 * 1024 * 1024;
    int periodic_interval_seconds_ = 3600;
};

// =============================================================================
// 19. Cache Invalidation Callbacks
// =============================================================================

using CacheInvalidationCallback = std::function<void(const std::string& scope,
                                                       const std::string& key)>;

class CacheInvalidationManager {
public:
    explicit CacheInvalidationManager(DatabasePool& pool) : pool_(pool) {}

    // ---- Register a callback ----
    uint64_t register_callback(const std::string& scope, CacheInvalidationCallback cb) {
        std::lock_guard<std::mutex> lk(mu_);
        uint64_t id = next_callback_id_++;
        callbacks_[scope].emplace_back(id, std::move(cb));
        return id;
    }

    // ---- Unregister a callback ----
    bool unregister_callback(uint64_t id) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& [scope, cbs] : callbacks_) {
            auto it = std::find_if(cbs.begin(), cbs.end(),
                                    [id](auto& p) { return p.first == id; });
            if (it != cbs.end()) {
                cbs.erase(it);
                return true;
            }
        }
        return false;
    }

    // ---- Invalidate a specific key in a scope ----
    void invalidate(const std::string& scope, const std::string& key) {
        std::vector<CacheInvalidationCallback> cbs_copy;
        {
            std::shared_lock<std::shared_mutex> lk(mu_);
            auto it = callbacks_.find(scope);
            if (it != callbacks_.end()) {
                for (auto& [id, cb] : it->second) {
                    cbs_copy.push_back(cb);
                }
            }
        }
        for (auto& cb : cbs_copy) {
            cb(scope, key);
        }
    }

    // ---- Invalidate all keys in a scope ----
    void invalidate_scope(const std::string& scope) {
        std::vector<CacheInvalidationCallback> cbs_copy;
        {
            std::shared_lock<std::shared_mutex> lk(mu_);
            auto it = callbacks_.find(scope);
            if (it != callbacks_.end()) {
                for (auto& [id, cb] : it->second) {
                    cbs_copy.push_back(cb);
                }
            }
        }
        for (auto& cb : cbs_copy) {
            cb(scope, "*");
        }
    }

    // ---- Standard invalidation triggers ----

    void on_room_state_change(const RoomId& room_id) {
        invalidate("room_state", room_id);
        invalidate("room_members", room_id);
        invalidate("room_stats", room_id);
    }

    void on_new_event(const RoomId& room_id, const EventId& event_id) {
        invalidate("room_events", room_id);
        invalidate("room_timeline", room_id);
        invalidate("event", event_id);
    }

    void on_user_profile_change(const UserId& user_id) {
        invalidate("user_profile", user_id);
        invalidate("user_directory", "search");
    }

    void on_room_directory_change() {
        invalidate_scope("room_directory");
    }

    void on_state_group_change(StateGroup group) {
        invalidate("state_group", std::to_string(group));
        invalidate_scope("state_resolution");
    }

    void on_purge(const RoomId& room_id) {
        invalidate("room_state", room_id);
        invalidate("room_events", room_id);
        invalidate("room_timeline", room_id);
        invalidate("room_members", room_id);
        invalidate("room_stats", room_id);
        invalidate("state_resolution", room_id);
        invalidate_scope("room_directory");
    }

    // ---- Batch invalidation ----
    void invalidate_batch(const std::string& scope,
                           const std::vector<std::string>& keys) {
        std::vector<CacheInvalidationCallback> cbs_copy;
        {
            std::shared_lock<std::shared_mutex> lk(mu_);
            auto it = callbacks_.find(scope);
            if (it != callbacks_.end()) {
                for (auto& [id, cb] : it->second) {
                    cbs_copy.push_back(cb);
                }
            }
        }
        for (auto& key : keys) {
            for (auto& cb : cbs_copy) {
                cb(scope, key);
            }
        }
    }

    // ---- Get registered callback count ----
    size_t callback_count(const std::string& scope) const {
        std::shared_lock<std::shared_mutex> lk(mu_);
        auto it = callbacks_.find(scope);
        if (it != callbacks_.end()) return it->second.size();
        return 0;
    }

    // ---- Global invalidation (flush all caches) ----
    void invalidate_all() {
        std::vector<std::string> scopes;
        {
            std::shared_lock<std::shared_mutex> lk(mu_);
            for (auto& [scope, _] : callbacks_) {
                scopes.push_back(scope);
            }
        }
        for (auto& scope : scopes) {
            invalidate_scope(scope);
        }
    }

    // ---- Persist invalidation log to DB ----
    void log_invalidation(const std::string& scope, const std::string& key,
                           const std::string& reason) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("log_cache_invalidation");
        // INSERT INTO cache_invalidation_log (scope, cache_key, reason, invalidated_at)
        // VALUES (?, ?, ?, NOW())
        (void)scope;
        (void)key;
        (void)reason;
        txn.commit();
    }

private:
    DatabasePool& pool_;
    mutable std::shared_mutex mu_;
    std::unordered_map<std::string,
        std::vector<std::pair<uint64_t, CacheInvalidationCallback>>> callbacks_;
    uint64_t next_callback_id_ = 1;
};

// =============================================================================
// 20. Database Migrations (state storage specific)
// =============================================================================

class StateStorageMigrations {
public:
    explicit StateStorageMigrations(DatabasePool& pool,
                                     BackgroundUpdateRunner& bg_runner)
        : pool_(pool), bg_runner_(bg_runner)
    {
        register_all_migrations();
    }

    // ---- Run all pending migrations ----
    void run_migrations() {
        for (auto& [version, mig] : migrations_) {
            if (!is_applied(version)) {
                apply_migration(version, mig);
                bg_runner_.register_update(mig.background_update);
            }
        }
    }

    // ---- Migration definitions ----
    struct Migration {
        int         version;
        std::string name;
        std::string description;
        std::function<void(LoggingTransaction&)> apply;
        BackgroundUpdate background_update;
        bool requires_background_update = false;
    };

private:
    void register_all_migrations() {
        // Migrations are registered in version order.
        // Each migration may optionally create a background update
        // for processing existing data.

        // Migration 1: Create state_groups table
        register_migration({
            1,
            "create_state_groups",
            "Create state_groups, state_groups_state, state_group_edges tables",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS state_groups (
                //   id BIGINT PRIMARY KEY,
                //   room_id TEXT NOT NULL,
                //   event_id TEXT,
                //   created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))
                // );
                // CREATE TABLE IF NOT EXISTS state_groups_state (
                //   state_group BIGINT NOT NULL REFERENCES state_groups(id),
                //   room_id TEXT NOT NULL,
                //   type TEXT NOT NULL,
                //   state_key TEXT NOT NULL,
                //   event_id TEXT NOT NULL,
                //   PRIMARY KEY (state_group, type, state_key)
                // );
                // CREATE TABLE IF NOT EXISTS state_group_edges (
                //   state_group BIGINT NOT NULL,
                //   prev_state_group BIGINT NOT NULL,
                //   PRIMARY KEY (state_group, prev_state_group)
                // );
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 2: Create event_to_state_groups table
        register_migration({
            2,
            "create_event_to_state_groups",
            "Create mapping from events to state groups",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS event_to_state_groups (
                //   event_id TEXT NOT NULL,
                //   state_group BIGINT NOT NULL REFERENCES state_groups(id),
                //   room_id TEXT NOT NULL,
                //   PRIMARY KEY (event_id)
                // );
                // CREATE INDEX idx_event_to_state_groups_sg
                //   ON event_to_state_groups(state_group);
                // CREATE INDEX idx_event_to_state_groups_room
                //   ON event_to_state_groups(room_id);
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 3: Create state_resolution_cache table
        register_migration({
            3,
            "create_state_resolution_cache",
            "Create cache for state resolution results",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS state_resolution_cache (
                //   input_hash TEXT NOT NULL PRIMARY KEY,
                //   resolved_group BIGINT NOT NULL,
                //   created_at BIGINT NOT NULL,
                //   expires_at BIGINT NOT NULL
                // );
                // CREATE INDEX idx_state_resolution_cache_expires
                //   ON state_resolution_cache(expires_at);
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 4: Create room_stats tables
        register_migration({
            4,
            "create_room_stats",
            "Create room statistics tables",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS room_stats_current (
                //   room_id TEXT NOT NULL PRIMARY KEY,
                //   joined_members BIGINT DEFAULT 0,
                //   local_users_in_room BIGINT DEFAULT 0,
                //   invited_members BIGINT DEFAULT 0,
                //   banned_members BIGINT DEFAULT 0,
                //   total_events BIGINT DEFAULT 0,
                //   state_events BIGINT DEFAULT 0,
                //   forward_extremities BIGINT DEFAULT 0,
                //   backward_extremities BIGINT DEFAULT 0,
                //   depth BIGINT DEFAULT 0,
                //   updated_at BIGINT NOT NULL
                // );
                // CREATE TABLE IF NOT EXISTS room_stats_historical (
                //   room_id TEXT NOT NULL,
                //   joined_members BIGINT,
                //   total_events BIGINT,
                //   snapshot_ts BIGINT NOT NULL,
                //   PRIMARY KEY (room_id, snapshot_ts)
                // );
                (void)txn;
            },
            // Background update to populate room stats from existing data
            BackgroundUpdate{
                "populate_room_stats",
                "",
                100,
                true,
                [](LoggingTransaction&) -> size_t { return 0; }
            },
            true
        });

        // Migration 5: Create MAU/DAU tables
        register_migration({
            5,
            "create_mau_dau",
            "Create monthly and daily active users tables",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS monthly_active_users (
                //   user_id TEXT NOT NULL,
                //   month_key TEXT NOT NULL,
                //   last_active BIGINT NOT NULL,
                //   PRIMARY KEY (user_id, month_key)
                // );
                // CREATE TABLE IF NOT EXISTS daily_active_users (
                //   user_id TEXT NOT NULL,
                //   date TEXT NOT NULL,
                //   last_active BIGINT NOT NULL,
                //   event_count BIGINT DEFAULT 1,
                //   PRIMARY KEY (user_id, date)
                // );
                (void)txn;
            },
            BackgroundUpdate{
                "populate_mau_dau",
                "",
                500,
                true,
                [](LoggingTransaction&) -> size_t { return 0; }
            },
            true
        });

        // Migration 6: Create user_directory table
        register_migration({
            6,
            "create_user_directory",
            "Create user directory search index",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS user_directory (
                //   user_id TEXT NOT NULL PRIMARY KEY,
                //   display_name TEXT,
                //   avatar_url TEXT,
                //   updated_at BIGINT NOT NULL
                // );
                // CREATE INDEX idx_user_directory_display_name
                //   ON user_directory(display_name);
                (void)txn;
            },
            BackgroundUpdate{
                "populate_user_directory",
                "",
                500,
                true,
                [](LoggingTransaction&) -> size_t { return 0; }
            },
            true
        });

        // Migration 7: Create room_directory table
        register_migration({
            7,
            "create_room_directory",
            "Create public room directory",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS room_directory (
                //   room_id TEXT NOT NULL PRIMARY KEY,
                //   visibility TEXT NOT NULL DEFAULT 'public',
                //   name TEXT,
                //   topic TEXT,
                //   avatar_url TEXT,
                //   num_joined_members BIGINT DEFAULT 0,
                //   world_readable BOOLEAN DEFAULT FALSE,
                //   canonical_alias TEXT,
                //   room_type TEXT,
                //   published_at BIGINT,
                //   updated_at BIGINT
                // );
                // CREATE TABLE IF NOT EXISTS room_aliases (
                //   room_alias TEXT NOT NULL PRIMARY KEY,
                //   room_id TEXT NOT NULL,
                //   created_at BIGINT
                // );
                (void)txn;
            },
            BackgroundUpdate{
                "populate_room_directory",
                "",
                100,
                true,
                [](LoggingTransaction&) -> size_t { return 0; }
            },
            true
        });

        // Migration 8: Create state delta storage tables
        register_migration({
            8,
            "create_state_deltas",
            "Create current state delta tables",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS current_state_deltas (
                //   id BIGINT PRIMARY KEY AUTOINCREMENT,
                //   room_id TEXT NOT NULL,
                //   stream_ordering BIGINT NOT NULL,
                //   event_type TEXT NOT NULL,
                //   state_key TEXT NOT NULL,
                //   prev_event_id TEXT,
                //   new_event_id TEXT,
                //   created_at BIGINT NOT NULL
                // );
                // CREATE TABLE IF NOT EXISTS state_delta_snapshots (
                //   room_id TEXT NOT NULL,
                //   up_to_stream BIGINT NOT NULL,
                //   state_json TEXT NOT NULL,
                //   created_at BIGINT NOT NULL,
                //   PRIMARY KEY (room_id, up_to_stream)
                // );
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 9: Create extremeties tables
        register_migration({
            9,
            "create_extremeties",
            "Create forward and backward extremeties tables",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS event_forward_extremities (
                //   event_id TEXT NOT NULL PRIMARY KEY,
                //   room_id TEXT NOT NULL,
                //   depth BIGINT NOT NULL DEFAULT 0,
                //   state_group BIGINT NOT NULL DEFAULT 0,
                //   created_at BIGINT NOT NULL
                // );
                // CREATE TABLE IF NOT EXISTS event_backward_extremities (
                //   event_id TEXT NOT NULL PRIMARY KEY,
                //   room_id TEXT NOT NULL,
                //   depth BIGINT NOT NULL DEFAULT 0,
                //   processed BOOLEAN NOT NULL DEFAULT FALSE,
                //   created_at BIGINT NOT NULL,
                //   processed_at BIGINT
                // );
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 10: Create event ID shards
        register_migration({
            10,
            "create_event_id_shards",
            "Create sharded event ID generation table",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS event_id_shards (
                //   shard INT NOT NULL PRIMARY KEY,
                //   server_name TEXT NOT NULL,
                //   max_local_id BIGINT NOT NULL DEFAULT 0
                // );
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 11: Create stream ordering table
        register_migration({
            11,
            "create_stream_ordering",
            "Create stream positions table",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS stream_positions (
                //   room_id TEXT NOT NULL,
                //   stream_type TEXT NOT NULL DEFAULT 'event',
                //   position BIGINT NOT NULL DEFAULT 0,
                //   PRIMARY KEY (room_id, stream_type)
                // );
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 12: Create state autocompression metadata
        register_migration({
            12,
            "create_autocompression",
            "Create state autocompression metadata table",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS state_compression_log (
                //   room_id TEXT NOT NULL,
                //   compressed_at BIGINT NOT NULL,
                //   groups_before BIGINT,
                //   groups_after BIGINT,
                //   bytes_before BIGINT,
                //   bytes_after BIGINT,
                //   PRIMARY KEY (room_id, compressed_at)
                // );
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 13: Create cache invalidation log
        register_migration({
            13,
            "create_cache_invalidation_log",
            "Create cache invalidation log table",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS cache_invalidation_log (
                //   id BIGINT PRIMARY KEY AUTOINCREMENT,
                //   scope TEXT NOT NULL,
                //   cache_key TEXT NOT NULL,
                //   reason TEXT,
                //   invalidated_at BIGINT NOT NULL
                // );
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 14: Create purged_rooms tracking
        register_migration({
            14,
            "create_purged_rooms",
            "Create purged rooms tracking table",
            [](LoggingTransaction& txn) {
                // CREATE TABLE IF NOT EXISTS purged_rooms (
                //   room_id TEXT NOT NULL PRIMARY KEY,
                //   purged_at BIGINT NOT NULL,
                //   purged_by TEXT
                // );
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });

        // Migration 15: Add indexes for state storage performance
        register_migration({
            15,
            "add_state_storage_indexes",
            "Add performance indexes for state storage",
            [](LoggingTransaction& txn) {
                // CREATE INDEX IF NOT EXISTS idx_sgs_room ON state_groups_state(room_id);
                // CREATE INDEX IF NOT EXISTS idx_sgs_event ON state_groups_state(event_id);
                // CREATE INDEX IF NOT EXISTS idx_sge_sg ON state_group_edges(state_group);
                // CREATE INDEX IF NOT EXISTS idx_sge_prev ON state_group_edges(prev_state_group);
                // CREATE INDEX IF NOT EXISTS idx_efe_room ON event_forward_extremities(room_id);
                // CREATE INDEX IF NOT EXISTS idx_ebe_room ON event_backward_extremities(room_id, processed);
                // CREATE INDEX IF NOT EXISTS idx_csd_room_stream ON current_state_deltas(room_id, stream_ordering);
                // CREATE INDEX IF NOT EXISTS idx_rc_expires ON state_resolution_cache(expires_at);
                // CREATE INDEX IF NOT EXISTS idx_mau_month ON monthly_active_users(month_key);
                // CREATE INDEX IF NOT EXISTS idx_dau_date ON daily_active_users(date);
                // CREATE INDEX IF NOT EXISTS idx_rd_visibility ON room_directory(visibility);
                (void)txn;
            },
            BackgroundUpdate{},
            false
        });
    }

    void register_migration(const Migration& mig) {
        migrations_[mig.version] = mig;
    }

    bool is_applied(int version) {
        auto db = pool_.get_db();
        // Query applied_schema_migrations or similar
        // SELECT 1 FROM schema_migrations WHERE version = ?
        (void)version;
        (void)db;
        return false;
    }

    void apply_migration(int version, const Migration& mig) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("migration_v" + std::to_string(version));
        try {
            mig.apply(txn);
            // INSERT INTO schema_migrations (version, name, applied_at)
            // VALUES (?, ?, NOW())
            txn.commit();
        } catch (...) {
            txn.rollback();
            throw;
        }
    }

    DatabasePool& pool_;
    BackgroundUpdateRunner& bg_runner_;
    std::map<int, Migration> migrations_;
};

// =============================================================================
// Main StateStorage orchestrator
// =============================================================================

class StateStorage {
public:
    explicit StateStorage(DatabasePool& pool)
        : pool_(pool),
          bg_update_runner_(pool),
          compressor_(pool),
          state_group_storage_(pool),
          event_state_mapper_(pool),
          resolution_cache_(pool),
          room_stats_(pool),
          mau_(pool),
          dau_(pool),
          user_directory_(pool),
          room_directory_(pool),
          state_delta_storage_(pool),
          purge_history_(pool),
          purge_room_(pool),
          id_generator_(pool),
          stream_ordering_(pool),
          backfill_tracker_(pool),
          forward_extremeties_(pool),
          autocompression_(pool, compressor_),
          cache_invalidation_(pool),
          migrations_(pool, bg_update_runner_)
    {}

    // ---- Accessors ----
    BackgroundUpdateRunner&       background_updates()     { return bg_update_runner_; }
    StateCompressor&              compressor()             { return compressor_; }
    StateGroupStorage&            state_groups()           { return state_group_storage_; }
    EventStateGroupMapper&        event_state_mapping()    { return event_state_mapper_; }
    StateResolutionCache&         resolution_cache_mod()   { return resolution_cache_; }
    RoomStatistics&               room_statistics()        { return room_stats_; }
    MonthlyActiveUsers&           monthly_active_users()   { return mau_; }
    DailyActiveUsers&             daily_active_users()     { return dau_; }
    UserDirectoryIndex&           user_directory_idx()     { return user_directory_; }
    RoomDirectory&                room_directory_mod()     { return room_directory_; }
    CurrentStateDeltaStorage&     state_deltas()           { return state_delta_storage_; }
    PurgeHistory&                 purge_history_mod()      { return purge_history_; }
    PurgeRoom&                    purge_room_mod()         { return purge_room_; }
    ShardedEventIdGenerator&      id_generator_mod()       { return id_generator_; }
    StreamOrdering&               stream_ordering_mod()    { return stream_ordering_; }
    BackfillExtremetiesTracker&   backfill_extremeties()   { return backfill_tracker_; }
    ForwardExtremetiesManager&    forward_extremeties_mod(){ return forward_extremeties_; }
    StateAutocompressionTrigger&  autocompression_mod()    { return autocompression_; }
    CacheInvalidationManager&     cache_invalidation_mod() { return cache_invalidation_; }
    StateStorageMigrations&       migrations_mod()         { return migrations_; }

    // ---- Initialize all subsystems ----
    void initialize() {
        // Run schema migrations first
        migrations_.run_migrations();

        // Register background updates
        register_builtin_background_updates();

        // Start background update runner
        bg_update_runner_.start();
    }

    // ---- Shutdown ----
    void shutdown() {
        bg_update_runner_.stop();
    }

    // ---- Pause/resume background processing ----
    void pause_background()  { bg_update_runner_.pause(); }
    void resume_background()  { bg_update_runner_.resume(); }

    // ---- Record event and all related state bookkeeping ----
    struct EventContext {
        EventId    event_id;
        RoomId     room_id;
        StateGroup state_group;
        StreamPos  stream_pos;
        int64_t    depth;
        bool       is_state;
        UserId     sender;
    };

    void on_new_event(const EventContext& ctx) {
        // Map event to state group
        event_state_mapper_.set_state_group(ctx.event_id, ctx.state_group, ctx.room_id);

        // Update DAU/MAU
        dau_.record_user_active(ctx.sender);
        mau_.record_user_active(ctx.sender);

        // Invalidate caches
        cache_invalidation_.on_new_event(ctx.room_id, ctx.event_id);

        // Trigger autocompression check
        autocompression_.trigger_if_needed(ctx.room_id);
    }

    // ---- Manage forward extremities update after event persist ----
    void update_forward_extremeties(
            const RoomId& room_id,
            const EventId& new_event_id,
            const std::vector<EventId>& prev_event_ids,
            int64_t depth,
            StateGroup state_group,
            bool replaces_all = true) {

        if (replaces_all) {
            // Remove old forward extremities
            // Add the single new one
            forward_extremeties_.remove(new_event_id);
            // Remove all prev_event_ids from forward extremities
            for (auto& pev : prev_event_ids) {
                forward_extremeties_.remove(pev);
            }
            ForwardExtremity fe;
            fe.event_id    = new_event_id;
            fe.room_id     = room_id;
            fe.depth       = depth;
            fe.state_group = state_group;
            fe.created_at  = static_cast<int64_t>(now_seconds());
            forward_extremeties_.add(fe);
        }
    }

    // ---- Add backward extremity for backfill ----
    void add_backward_extremity(const EventId& event_id, const RoomId& room_id,
                                  int64_t depth) {
        BackwardExtremity be;
        be.event_id  = event_id;
        be.room_id   = room_id;
        be.depth     = depth;
        be.processed = false;
        be.created_at = static_cast<int64_t>(now_seconds());
        backfill_tracker_.insert(be);
    }

    // ---- Purge room (complete) ----
    PurgeRoom::PurgeRoomResult purge_room_complete(const RoomId& room_id) {
        auto result = purge_room_.purge_room(room_id);
        if (result.success) {
            cache_invalidation_.on_purge(room_id);
        }
        return result;
    }

    // ---- Purge history ----
    PurgeHistory::PurgeResult purge_room_history(const RoomId& room_id,
                                                   const EventId& before_event) {
        return purge_history_.purge_before_event(room_id, before_event);
    }

    // ---- Compress all state ----
    StateCompressor::CompressionStats compress_room_state(const RoomId& room_id) {
        return compressor_.compress_room(room_id);
    }

    // ---- Run auto-compression across all rooms ----
    StateAutocompressionTrigger::AutoCompressionResult run_auto_compression(int max_rooms) {
        return autocompression_.run_auto_compression(max_rooms);
    }

    // ---- Generate next event ID ----
    EventId next_event_id(const RoomId& room_id) {
        return id_generator_.generate_event_id(room_id);
    }

    // ---- Allocate stream position ----
    StreamPos next_stream_pos(const RoomId& room_id) {
        return stream_ordering_.allocate_stream_pos(room_id);
    }

    // ---- Record state delta ----
    void record_state_delta(const StateDelta& delta) {
        state_delta_storage_.record_delta(delta);
    }

    // ---- Search user directory ----
    std::vector<UserDirectoryIndex::UserSearchResult>
    search_users(const std::string& query, int limit = 50) {
        return user_directory_.search(query, limit);
    }

    // ---- List public rooms ----
    RoomDirectory::RoomDirectoryResult
    list_public_rooms(const std::optional<std::string>& search = std::nullopt,
                       int limit = 50) {
        return room_directory_.list_rooms(search, std::nullopt, std::nullopt,
                                           limit, std::nullopt, std::nullopt, true);
    }

    // ---- Publish/unpublish room ----
    void publish_room(const RoomId& room_id) {
        room_directory_.publish_room(room_id);
        cache_invalidation_.on_room_directory_change();
    }

    void unpublish_room(const RoomId& room_id) {
        room_directory_.unpublish_room(room_id);
        cache_invalidation_.on_room_directory_change();
    }

    // ---- Record activity for MAU/DAU ----
    void record_user_activity(const UserId& user_id) {
        dau_.record_user_active(user_id);
        mau_.record_user_active(user_id);
    }

    // ---- Check MAU limit ----
    bool is_mau_limit_exceeded() {
        return mau_.is_mau_limit_reached();
    }

    void set_mau_limit(int64_t limit) {
        mau_.set_mau_limit(limit);
    }

    // ---- Cache invalidation ----
    uint64_t register_invalidation_callback(const std::string& scope,
                                              CacheInvalidationCallback cb) {
        return cache_invalidation_.register_callback(scope, std::move(cb));
    }

    void invalidate_cache(const std::string& scope, const std::string& key) {
        cache_invalidation_.invalidate(scope, key);
    }

    // ---- Database maintenance ----
    void run_maintenance() {
        // Prune old MAU/DAU records
        dau_.prune_old(90);
        mau_.prune_old(24);

        // Prune old backward extremities
        backfill_tracker_.prune_processed(604800); // 7 days

        // Prune orphaned forward extremities
        forward_extremeties_.prune_orphaned();

        // Prune old state deltas
        state_delta_storage_.prune_deltas(86400 * 7); // 7 days

        // Invalidate expired resolution cache
        resolution_cache_.invalidate_expired();

        // Prune unreferenced state groups
        compressor_.prune_unreferenced(86400 * 7); // 7 days
    }

    // ---- Get storage statistics ----
    struct StorageStats {
        int64_t total_state_groups       = 0;
        int64_t total_events             = 0;
        int64_t forward_extremities      = 0;
        int64_t backward_extremities     = 0;
        int64_t resolution_cache_entries = 0;
        int64_t mau_current              = 0;
        int64_t dau_today                = 0;
        int64_t indexed_users            = 0;
        int64_t public_rooms             = 0;
        int64_t state_deltas             = 0;
        int64_t purged_rooms             = 0;
    };

    StorageStats compute_global_stats() {
        StorageStats s;
        s.mau_current      = mau_.count_current_mau();
        s.dau_today        = dau_.count_today();
        s.indexed_users    = user_directory_.indexed_count();
        s.public_rooms     = room_directory_.count_public_rooms();
        s.purged_rooms     = static_cast<int64_t>(purge_room_.list_purged_rooms().size());
        auto cache_stats   = resolution_cache_.stats();
        s.resolution_cache_entries = static_cast<int64_t>(cache_stats.total_entries);
        return s;
    }

private:
    void register_builtin_background_updates() {
        // Register population updates from migrations
        // They are already registered when migrations run.

        // Register periodic maintenance
        BackgroundUpdate maintenance_update;
        maintenance_update.update_name = "state_storage_maintenance";
        maintenance_update.run_once    = false;
        maintenance_update.batch_size  = 1;
        maintenance_update.runner      = [this](LoggingTransaction& txn) -> size_t {
            run_maintenance();
            (void)txn;
            return 1;
        };
        bg_update_runner_.register_update(std::move(maintenance_update));

        // Register user directory populate
        bg_update_runner_.register_update(user_directory_.create_populate_update());

        // Register room directory recount
        bg_update_runner_.register_update(room_directory_.create_recount_update());

        // Register autocompression
        bg_update_runner_.register_update(autocompression_.create_autocompression_update());
    }

    DatabasePool& pool_;

    BackgroundUpdateRunner      bg_update_runner_;
    StateCompressor             compressor_;
    StateGroupStorage           state_group_storage_;
    EventStateGroupMapper       event_state_mapper_;
    StateResolutionCache        resolution_cache_;
    RoomStatistics              room_stats_;
    MonthlyActiveUsers          mau_;
    DailyActiveUsers            dau_;
    UserDirectoryIndex          user_directory_;
    RoomDirectory               room_directory_;
    CurrentStateDeltaStorage    state_delta_storage_;
    PurgeHistory                purge_history_;
    PurgeRoom                   purge_room_;
    ShardedEventIdGenerator     id_generator_;
    StreamOrdering              stream_ordering_;
    BackfillExtremetiesTracker  backfill_tracker_;
    ForwardExtremetiesManager   forward_extremeties_;
    StateAutocompressionTrigger autocompression_;
    CacheInvalidationManager    cache_invalidation_;
    StateStorageMigrations      migrations_;
};

// =============================================================================
// Extended utility implementations for state storage
// =============================================================================

// ---------------------------------------------------------------------------
// Room membership cache helper
// ---------------------------------------------------------------------------
class RoomMembershipCache {
public:
    explicit RoomMembershipCache(DatabasePool& pool) : pool_(pool) {}

    struct MembershipEntry {
        UserId      user_id;
        RoomId      room_id;
        std::string membership;  // join, invite, ban, knock, leave
        std::string display_name;
        std::string avatar_url;
        EventId     event_id;
        StateGroup  state_group;
        int64_t     added_at;
    };

    // Load membership for user in room
    std::optional<MembershipEntry> get_membership(const RoomId& room_id,
                                                    const UserId& user_id) {
        auto db = pool_.get_db();
        // SELECT ... FROM current_state_events
        // WHERE room_id = ? AND type = 'm.room.member' AND state_key = ?
        (void)room_id;
        (void)user_id;
        (void)db;
        return std::nullopt;
    }

    // Get all members in a room (possibly filtered by membership type)
    std::vector<MembershipEntry> get_members(const RoomId& room_id,
                                               const std::optional<std::string>& membership_filter = std::nullopt) {
        std::vector<MembershipEntry> members;
        auto db = pool_.get_db();
        // Build query with optional filter
        (void)room_id;
        (void)membership_filter;
        (void)db;
        return members;
    }

    // Get all rooms for a user with their membership state
    std::vector<MembershipEntry> get_user_rooms(const UserId& user_id) {
        std::vector<MembershipEntry> rooms;
        auto db = pool_.get_db();
        // SELECT ... FROM current_state_events
        // WHERE type = 'm.room.member' AND state_key = ?
        (void)user_id;
        (void)db;
        return rooms;
    }

    // Count joined members (fast, indexed)
    int64_t count_joined(const RoomId& room_id) {
        auto db = pool_.get_db();
        // SELECT COUNT(*) FROM current_state_events
        // WHERE room_id = ? AND type = 'm.room.member' AND membership = 'join'
        (void)room_id;
        (void)db;
        return 0;
    }

    // Check if user is joined
    bool is_joined(const RoomId& room_id, const UserId& user_id) {
        auto db = pool_.get_db();
        // SELECT 1 FROM current_state_events
        // WHERE room_id = ? AND type = 'm.room.member'
        //   AND state_key = ? AND membership = 'join'
        (void)room_id;
        (void)user_id;
        (void)db;
        return false;
    }

    // Get joined servers for a room (federation)
    std::set<std::string> get_joined_servers(const RoomId& room_id) {
        std::set<std::string> servers;
        auto db = pool_.get_db();
        // SELECT DISTINCT SUBSTR(state_key, INSTR(state_key, ':') + 1) as server
        // FROM current_state_events
        // WHERE room_id = ? AND type = 'm.room.member' AND membership = 'join'
        (void)room_id;
        (void)db;
        return servers;
    }

    // Get local users in room
    std::vector<UserId> get_local_users(const RoomId& room_id) {
        std::vector<UserId> users;
        auto db = pool_.get_db();
        // SELECT state_key FROM current_state_events
        // WHERE room_id = ? AND type = 'm.room.member'
        //   AND membership = 'join' AND is_local = true
        (void)room_id;
        (void)db;
        return users;
    }

    // Bulk check joined rooms for a user (for sync filtering)
    std::vector<RoomId> get_joined_rooms(const UserId& user_id) {
        std::vector<RoomId> rooms;
        auto db = pool_.get_db();
        // SELECT room_id FROM current_state_events
        // WHERE type = 'm.room.member' AND state_key = ?
        //   AND membership = 'join'
        (void)user_id;
        (void)db;
        return rooms;
    }

    // Count rooms where user is a member (any state)
    struct UserRoomCounts {
        int64_t joined  = 0;
        int64_t invited = 0;
        int64_t left    = 0;
        int64_t banned  = 0;
    };

    UserRoomCounts get_user_room_counts(const UserId& user_id) {
        UserRoomCounts counts;
        auto db = pool_.get_db();
        // SELECT membership, COUNT(*) FROM current_state_events
        // WHERE type = 'm.room.member' AND state_key = ?
        // GROUP BY membership
        (void)user_id;
        (void)db;
        return counts;
    }

    // Invalidate cached membership data
    void invalidate_room(const RoomId& room_id) {
        // In real impl, this signals all caches to drop the room
        (void)room_id;
    }

    void invalidate_user(const UserId& user_id) {
        (void)user_id;
    }

private:
    DatabasePool& pool_;
};

// ---------------------------------------------------------------------------
// Auth chain extraction utilities
// ---------------------------------------------------------------------------
class AuthChainExtractor {
public:
    explicit AuthChainExtractor(DatabasePool& pool) : pool_(pool) {}

    // Extract the full auth chain for a set of event IDs
    // Used for state resolution and auth verification
    std::set<EventId> extract_auth_chain(const std::vector<EventId>& event_ids,
                                           int max_depth = 100) {
        std::set<EventId> seen;
        std::deque<EventId> queue(event_ids.begin(), event_ids.end());

        auto db = pool_.get_db();
        while (!queue.empty()) {
            EventId current = queue.front();
            queue.pop_front();
            if (seen.count(current)) continue;
            seen.insert(current);

            // SELECT auth_event_id FROM event_auth WHERE event_id = ?
            // For each auth event, if not seen, add to queue.
            // Also check depth limit.
            (void)current;
            (void)db;
            if (static_cast<int>(seen.size()) >= max_depth * 10) break;
        }
        return seen;
    }

    // Get the difference between two auth chains
    struct AuthChainDiff {
        std::set<EventId> only_in_first;
        std::set<EventId> only_in_second;
        std::set<EventId> in_both;
    };

    AuthChainDiff diff_auth_chains(const std::vector<EventId>& chain1,
                                     const std::vector<EventId>& chain2) {
        auto set1 = extract_auth_chain(chain1);
        auto set2 = extract_auth_chain(chain2);
        AuthChainDiff diff;
        for (auto& e : set1) {
            if (set2.count(e)) diff.in_both.insert(e);
            else diff.only_in_first.insert(e);
        }
        for (auto& e : set2) {
            if (!set1.count(e)) diff.only_in_second.insert(e);
        }
        return diff;
    }

    // Walk the auth chain and return in topological order
    std::vector<EventId> topological_auth_chain(const EventId& event_id) {
        std::vector<EventId> ordered;
        std::set<EventId> visited;
        std::function<void(const EventId&)> dfs =
            [&](const EventId& eid) {
                if (visited.count(eid)) return;
                visited.insert(eid);
                auto parents = get_auth_events(eid);
                for (auto& p : parents) dfs(p);
                ordered.push_back(eid);
            };
        dfs(event_id);
        return ordered;
    }

    // Find common auth events between two events (for conflict resolution)
    std::set<EventId> common_auth_events(const EventId& a, const EventId& b) {
        auto chain_a = extract_auth_chain({a});
        auto chain_b = extract_auth_chain({b});
        std::set<EventId> common;
        for (auto& e : chain_a) {
            if (chain_b.count(e)) common.insert(e);
        }
        return common;
    }

private:
    std::vector<EventId> get_auth_events(const EventId& event_id) {
        std::vector<EventId> auth;
        auto db = pool_.get_db();
        // SELECT auth_event_id FROM event_auth WHERE event_id = ?
        (void)event_id;
        (void)db;
        return auth;
    }

    DatabasePool& pool_;
};

// ---------------------------------------------------------------------------
// Event relation chain management
// ---------------------------------------------------------------------------
class EventRelationsManager {
public:
    explicit EventRelationsManager(DatabasePool& pool) : pool_(pool) {}

    enum class RelationType {
        Annotation,  // m.annotation (reactions)
        Reference,   // m.reference
        Replace,     // m.replace (edits)
        Thread,      // m.thread
    };

    struct Relation {
        EventId      event_id;
        EventId      relates_to;
        RelationType rel_type;
        std::string  key;         // aggregation key for annotations
        int64_t      created_at;
    };

    // Add a relation
    void add_relation(const Relation& rel) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("add_event_relation");
        // INSERT INTO event_relations
        //   (event_id, relates_to, relation_type, aggregation_key, created_at)
        // VALUES (?, ?, ?, ?, ?)
        (void)rel;
        txn.commit();
    }

    // Get all relations pointing to an event
    std::vector<Relation> get_relations_to(const EventId& event_id,
                                             std::optional<RelationType> type_filter = std::nullopt) {
        std::vector<Relation> out;
        auto db = pool_.get_db();
        // SELECT * FROM event_relations WHERE relates_to = ?
        (void)event_id;
        (void)type_filter;
        (void)db;
        return out;
    }

    // Count annotations (reactions) for aggregation
    struct AnnotationCount {
        std::string key;
        int64_t     count;
    };

    std::vector<AnnotationCount> count_annotations(const EventId& event_id) {
        std::vector<AnnotationCount> counts;
        auto db = pool_.get_db();
        // SELECT aggregation_key, COUNT(*) FROM event_relations
        // WHERE relates_to = ? AND relation_type = 'm.annotation'
        // GROUP BY aggregation_key
        (void)event_id;
        (void)db;
        return counts;
    }

    // Get thread events (recursive)
    std::vector<EventId> get_thread_events(const EventId& root_event,
                                              int max_depth = 50) {
        std::vector<EventId> thread;
        std::set<EventId> visited;
        std::deque<EventId> queue;
        queue.push_back(root_event);

        auto db = pool_.get_db();
        while (!queue.empty()) {
            EventId current = queue.front();
            queue.pop_front();
            if (visited.count(current)) continue;
            visited.insert(current);

            // SELECT event_id FROM event_relations
            // WHERE relates_to = ? AND relation_type = 'm.thread'
            (void)current;
            (void)db;

            if (static_cast<int>(visited.size()) >= max_depth) break;
        }
        return thread;
    }

    // Remove all relations for an event (on purge/redaction)
    void remove_relations_for(const EventId& event_id) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("remove_event_relations");
        // DELETE FROM event_relations
        // WHERE event_id = ? OR relates_to = ?
        (void)event_id;
        txn.commit();
    }

private:
    DatabasePool& pool_;
};

// ---------------------------------------------------------------------------
// Room version and capability management
// ---------------------------------------------------------------------------
class RoomVersionManager {
public:
    explicit RoomVersionManager(DatabasePool& pool) : pool_(pool) {}

    struct RoomVersion {
        RoomId      room_id;
        std::string version;       // e.g. "1", "2", ..., "11"
        EventId     creator_event;
        int64_t     created_at;
        int64_t     upgraded_at;   // 0 if original
    };

    // Get room version
    std::string get_room_version(const RoomId& room_id) {
        auto db = pool_.get_db();
        // Check m.room.create event's "room_version" content field
        // Default to "1" if not specified
        (void)room_id;
        (void)db;
        return "1";
    }

    // Check if room supports a specific capability
    bool supports(const RoomId& room_id, const std::string& capability) {
        std::string ver = get_room_version(room_id);

        // Capability registry based on room version
        static const std::map<std::string, std::set<std::string>> version_caps = {
            {"1", {"m.room.create", "m.room.member", "m.room.power_levels",
                   "m.room.join_rules", "m.room.history_visibility"}},
            {"2", {"m.room.create", "m.room.member", "m.room.power_levels"}},
        };

        auto it = version_caps.find(ver);
        if (it != version_caps.end()) {
            return it->second.count(capability) > 0;
        }
        return true; // Unknown versions assumed to support everything
    }

    // Room upgrade: record the upgrade chain
    void record_upgrade(const RoomId& old_room, const RoomId& new_room,
                          const EventId& tombstone_event) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("record_room_upgrade");
        // INSERT INTO room_upgrades (old_room_id, new_room_id, upgraded_at)
        // VALUES (?, ?, NOW())
        // UPDATE rooms SET upgraded_to = ? WHERE room_id = ?
        (void)old_room;
        (void)new_room;
        (void)tombstone_event;
        txn.commit();
    }

    // Get upgrade predecessor
    std::optional<RoomId> get_predecessor(const RoomId& room_id) {
        auto db = pool_.get_db();
        // SELECT old_room_id FROM room_upgrades WHERE new_room_id = ?
        (void)room_id;
        (void)db;
        return std::nullopt;
    }

    // Get upgrade successor
    std::optional<RoomId> get_successor(const RoomId& room_id) {
        auto db = pool_.get_db();
        // SELECT new_room_id FROM room_upgrades WHERE old_room_id = ?
        (void)room_id;
        (void)db;
        return std::nullopt;
    }

    // Walk entire upgrade chain
    std::vector<RoomId> get_upgrade_chain(const RoomId& room_id) {
        std::vector<RoomId> chain;
        // Walk predecessors to find root, then successors forward
        std::optional<RoomId> current = room_id;
        while (current) {
            current = get_predecessor(*current);
        }
        // current is now root (or nullopt if error)
        // Walk forward
        // ...
        (void)room_id;
        return chain;
    }

    // Check if a room is a tombstone (replaced room)
    bool is_tombstoned(const RoomId& room_id) {
        auto db = pool_.get_db();
        // Check for m.room.tombstone in current state
        (void)room_id;
        (void)db;
        return false;
    }

private:
    DatabasePool& pool_;
};

// ---------------------------------------------------------------------------
// Transaction batching support for bulk operations
// ---------------------------------------------------------------------------
class BulkOperationsBatcher {
public:
    explicit BulkOperationsBatcher(DatabasePool& pool, size_t max_batch = 500)
        : pool_(pool), max_batch_size_(max_batch), current_batch_count_(0) {}

    // Begin a new batch transaction
    void begin_batch() {
        current_batch_count_ = 0;
    }

    // Flush the current batch
    void flush_batch() {
        current_batch_count_ = 0;
    }

    // Check if batch should be flushed
    bool should_flush() const {
        return current_batch_count_ >= max_batch_size_;
    }

    // Batch insert state groups (optimized bulk operation)
    void batch_insert_state_groups(
            const std::vector<std::tuple<RoomId, StateGroup,
                  std::map<std::string, std::string>>>& groups) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("batch_insert_state_groups");

        // Prepare bulk inserts:
        // INSERT INTO state_groups (id, room_id) VALUES ...
        // INSERT INTO state_groups_state (state_group, room_id, type, state_key, event_id) VALUES ...

        for (auto& [room_id, sg_id, state] : groups) {
            for (auto& [key, event_id] : state) {
                auto sep = key.find('\x1F');
                auto type = key.substr(0, sep);
                auto sk   = key.substr(sep + 1);
                (void)room_id;
                (void)sg_id;
                (void)event_id;
                (void)type;
                (void)sk;
                ++current_batch_count_;
            }
            if (should_flush()) {
                txn.commit();
                txn = db.begin_transaction("batch_insert_state_groups_cont");
                current_batch_count_ = 0;
            }
        }
        txn.commit();
    }

    // Batch update event_to_state_groups
    void batch_map_events_to_state_groups(
            const std::vector<std::tuple<EventId, StateGroup, RoomId>>& mappings) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("batch_map_events");

        for (auto& [event_id, sg_id, room_id] : mappings) {
            (void)event_id;
            (void)sg_id;
            (void)room_id;
            ++current_batch_count_;
            if (should_flush()) {
                txn.commit();
                txn = db.begin_transaction("batch_map_events_cont");
                current_batch_count_ = 0;
            }
        }
        txn.commit();
    }

    // Batch delete events (used in purge operations)
    void batch_delete_events(const std::vector<EventId>& event_ids) {
        auto db  = pool_.get_db();
        auto txn = db.begin_transaction("batch_delete_events");

        for (auto& eid : event_ids) {
            (void)eid;
            ++current_batch_count_;
            if (should_flush()) {
                txn.commit();
                txn = db.begin_transaction("batch_delete_events_cont");
                current_batch_count_ = 0;
            }
        }
        txn.commit();
    }

    void set_max_batch_size(size_t size) { max_batch_size_ = size; }
    size_t current_batch_size() const { return current_batch_count_; }

private:
    DatabasePool& pool_;
    size_t max_batch_size_;
    size_t current_batch_count_;
};

// ---------------------------------------------------------------------------
// Extended state storage analytics and diagnostics
// ---------------------------------------------------------------------------
class StateStorageAnalytics {
public:
    explicit StateStorageAnalytics(DatabasePool& pool) : pool_(pool) {}

    struct StateGroupMetrics {
        int64_t total_groups;
        int64_t groups_without_events;
        int64_t groups_with_deltas;
        int64_t avg_state_events_per_group;
        int64_t max_state_events_in_group;
        int64_t min_state_events_in_group;
        int64_t total_state_rows;
        int64_t estimated_bytes;
    };

    StateGroupMetrics compute_state_group_metrics() {
        StateGroupMetrics m{};
        auto db = pool_.get_db();
        // SELECT COUNT(*) FROM state_groups
        // SELECT AVG(cnt), MAX(cnt), MIN(cnt) FROM
        //   (SELECT state_group, COUNT(*) as cnt FROM state_groups_state GROUP BY state_group)
        // SELECT COUNT(*) FROM state_groups_state
        (void)db;
        return m;
    }

    struct TableSizeInfo {
        std::string table_name;
        int64_t     row_count;
        int64_t     estimated_bytes;
        int64_t     index_bytes;
    };

    std::vector<TableSizeInfo> get_table_sizes() {
        std::vector<TableSizeInfo> sizes;
        auto db = pool_.get_db();
        // Query db stats for each table
        (void)db;
        return sizes;
    }

    struct RoomHealthReport {
        RoomId room_id;
        int64_t state_groups;
        int64_t forward_extremities;
        int64_t backward_extremities;
        int64_t state_branches;
        int64_t depth_discrepancy;
        bool    needs_compression;
        bool    needs_backfill;
        bool    has_orphaned_state;
        bool    has_duplicate_memberships;
    };

    RoomHealthReport assess_room_health(const RoomId& room_id) {
        RoomHealthReport report{};
        report.room_id = room_id;
        auto db = pool_.get_db();

        // Count forward extremities — > 1 means potential split
        // Count backward extremities — > 0 means holes in DAG
        // Count state groups — excessive means compression needed
        // Check for duplicate membership entries
        // Check depth consistency

        (void)db;
        return report;
    }

    std::vector<RoomHealthReport> scan_unhealthy_rooms(int limit = 50) {
        std::vector<RoomHealthReport> reports;
        // Query rooms with most forward extremities, most state groups, etc.
        return reports;
    }

    // Estimate space savings from compression
    struct CompressionEstimate {
        RoomId room_id;
        int64_t current_bytes;
        int64_t estimated_bytes_after;
        int64_t potential_savings;
        double  savings_percent;
    };

    std::vector<CompressionEstimate> estimate_compression_savings(
            int top_n = 20) {
        std::vector<CompressionEstimate> estimates;
        auto db = pool_.get_db();
        // For each room, estimate how much delta compression would save
        (void)top_n;
        (void)db;
        return estimates;
    }

private:
    DatabasePool& pool_;
};

} // namespace progressive::storage

// =============================================================================
// End of state_storage.cpp
// =============================================================================
