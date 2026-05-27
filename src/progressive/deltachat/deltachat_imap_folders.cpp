// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Progressive Server Contributors
//
// DeltaChat IMAP Folder Management — complete implementation of folder
// operations: LIST, CREATE, DELETE, SUBSCRIBE, STATUS, SELECT, IDLE watching,
// message movement, server-side flagging, expunge, namespace discovery,
// capability checking, statistics tracking, and error recovery.
//
// This unit focuses on server-side folder/mailbox management and message
// operations that operate at the folder level. It interacts with
// ImapConnection (from deltachat_imap_smtp.cpp) for all wire operations.

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <memory>
#include <optional>
#include <variant>
#include <ctime>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <regex>
#include <deque>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <cmath>
#include <random>
#include <condition_variable>
#include <queue>

namespace progressive {
namespace deltachat {

// ============================================================================
// Forward declarations — types from sibling units
// ============================================================================
class ImapConnection;
struct ImapResponse;
struct FetchResult;
struct Message;

// ============================================================================
// Constants
// ============================================================================
constexpr const char* DC_FOLDER_PREFIX     = "DeltaChat";
constexpr const char* DC_MVBOX_FOLDER      = "DeltaChat";
constexpr const char* DEFAULT_SENT_FOLDER  = "Sent";
constexpr const char* DEFAULT_INBOX        = "INBOX";
constexpr const char* DEFAULT_TRASH        = "Trash";
constexpr const char* DEFAULT_DRAFTS       = "Drafts";
constexpr const char* DEFAULT_ARCHIVE      = "Archive";
constexpr const char* DEFAULT_JUNK         = "Junk";
constexpr int FOLDER_LIST_TIMEOUT_SECS     = 30;
constexpr int FOLDER_CREATE_TIMEOUT_SECS   = 15;
constexpr int FOLDER_STATUS_TIMEOUT_SECS   = 10;
constexpr int FOLDER_SELECT_TIMEOUT_SECS   = 10;
constexpr int FOLDER_DELETE_TIMEOUT_SECS   = 15;
constexpr int FOLDER_MOVE_TIMEOUT_SECS     = 30;
constexpr int FOLDER_COPY_TIMEOUT_SECS     = 30;
constexpr int FOLDER_PURGE_TIMEOUT_SECS    = 15;
constexpr int IDLE_TIMEOUT_SECONDS         = 1740;  // 29 minutes
constexpr int IDLE_RENEWAL_SECONDS         = 1680;  // 28 minutes
constexpr int MAX_FOLDER_DEPTH             = 20;
constexpr int MAX_LIST_RESULTS             = 1000;
constexpr int BATCH_STORE_SIZE             = 100;
constexpr int MAX_RETRIES                  = 5;
constexpr int RETRY_BASE_DELAY_MS          = 1000;
constexpr int RETRY_MAX_DELAY_MS           = 32000;
constexpr int FOLDER_STATS_WINDOW_SEC      = 3600;

// ============================================================================
// IMAP List attributes (RFC 3501 §7.2.2)
// ============================================================================
enum class ImapListAttr : uint32_t {
    NONE          = 0,
    NOINFERIORS   = 1 << 0,   // \Noinferiors
    NOSELECT      = 1 << 1,   // \Noselect
    MARKED        = 1 << 2,   // \Marked
    UNMARKED      = 1 << 3,   // \Unmarked
    HASCHILDREN   = 1 << 4,   // \HasChildren
    HASNOCHILDREN = 1 << 5,   // \HasNoChildren
    TRASH         = 1 << 6,   // \Trash
    SENT          = 1 << 7,   // \Sent
    DRAFTS        = 1 << 8,   // \Drafts
    JUNK          = 1 << 9,   // \Junk
    ARCHIVE       = 1 << 10,  // \Archive
    ALL           = 1 << 11,  // \All
    IMPORTANT     = 1 << 12,  // \Important
    FLAGGED       = 1 << 13,  // \Flagged
    INBOX         = 1 << 14,  // \Inbox (non-standard but common)
    SUBSCRIBED    = 1 << 15,  // \Subscribed
    REMOTE        = 1 << 16,  // \Remote
    CHAT          = 1 << 17,  // custom: DeltaChat folder
};

// ============================================================================
// IMAP folder descriptor
// ============================================================================
struct ImapFolder {
    std::string name;               // full mailbox name
    std::string short_name;         // last component of hierarchy
    std::string path_delimiter;     // hierarchy delimiter
    uint32_t attributes = 0;        // bitmask of ImapListAttr
    int uid_validity = 0;          // UIDVALIDITY value
    int uid_next = 0;              // UIDNEXT value
    int exists = 0;                // EXISTS count
    int recent = 0;                // RECENT count
    int unseen = 0;                // UNSEEN count
    int highest_modseq = 0;        // HIGHESTMODSEQ (CONDSTORE)
    int first_unseen_uid = 0;      // FIRSTUNSEEN
    uint64_t last_status_check = 0; // timestamp of last STATUS
    uint64_t last_select_time = 0;  // timestamp of last SELECT
    bool is_selectable = true;      // !\Noselect
    bool is_selected = false;       // currently SELECTed
    bool is_subscribed = false;     // SUBSCRIBEd
    bool is_watched = false;        // being watched via IDLE
    bool is_deltachat = false;      // is a DeltaChat mailbox
    bool uid_validity_changed = false; // UIDVALIDITY changed since last check
    int last_seen_uid = 0;          // highest UID we've processed
    std::vector<int> known_uids;    // UIDs we've processed (fifo)
    std::vector<std::string> flags; // permanent flags from SELECT

    // Statistics
    struct Stats {
        uint64_t messages_fetched = 0;
        uint64_t messages_moved_in = 0;
        uint64_t messages_moved_out = 0;
        uint64_t messages_copied = 0;
        uint64_t messages_deleted = 0;
        uint64_t messages_flagged = 0;
        uint64_t idle_reconnects = 0;
        uint64_t errors = 0;
        uint64_t last_error_time = 0;
        std::string last_error;
    } stats;

    // Derived
    bool has_attribute(ImapListAttr attr) const {
        return (attributes & static_cast<uint32_t>(attr)) != 0;
    }
    bool is_trash() const    { return has_attribute(ImapListAttr::TRASH); }
    bool is_sent() const     { return has_attribute(ImapListAttr::SENT); }
    bool is_drafts() const   { return has_attribute(ImapListAttr::DRAFTS); }
    bool is_junk() const     { return has_attribute(ImapListAttr::JUNK); }
    bool is_archive() const  { return has_attribute(ImapListAttr::ARCHIVE); }
    bool is_inbox() const    { return has_attribute(ImapListAttr::INBOX) ||
                                      name == "INBOX" ||
                                      name_lower() == "inbox"; }
    std::string name_lower() const {
        std::string r; r.reserve(name.size());
        for (char c : name) r.push_back(static_cast<char>(std::tolower(c)));
        return r;
    }
};

// ============================================================================
// IMAP NAMESPACE response (RFC 2342)
// ============================================================================
struct ImapNamespace {
    std::string prefix;          // namespace prefix (e.g., "" or "INBOX.")
    std::string delimiter;       // hierarchy delimiter (e.g., "/" or ".")
    bool is_personal = true;     // personal namespace
    bool is_other_users = false; // other users' namespace
    bool is_shared = false;      // shared namespace

    std::string resolve(const std::string& folder) const {
        if (folder.empty()) return prefix;
        if (prefix.empty()) return folder;
        return prefix + delimiter + folder;
    }
};

struct ImapNamespaceInfo {
    std::vector<ImapNamespace> personal;
    std::vector<ImapNamespace> other_users;
    std::vector<ImapNamespace> shared;

    // Find the best personal namespace
    const ImapNamespace* best_personal() const {
        if (!personal.empty()) return &personal[0];
        return nullptr;
    }
    std::string delimiter() const {
        auto* ns = best_personal();
        return ns ? ns->delimiter : "/";
    }
    std::string prefix() const {
        auto* ns = best_personal();
        return ns ? ns->prefix : "";
    }
};

// ============================================================================
// IMAP capability tracking (per-session)
// ============================================================================
struct ImapCapabilities {
    bool imap4rev1 = true;
    bool idle = false;
    bool move = false;           // MOVE extension (RFC 6851)
    bool uidplus = false;        // UIDPLUS (RFC 4315)
    bool condstore = false;      // CONDSTORE (RFC 7162)
    bool qresync = false;        // QRESYNC (RFC 7162)
    bool namespace_cmd = false;  // NAMESPACE (RFC 2342)
    bool list_extended = false;  // LIST-EXTENDED (RFC 5258)
    bool list_status = false;    // LIST-STATUS (RFC 5819)
    bool special_use = false;    // SPECIAL-USE (RFC 6154)
    bool unselect = false;       // UNSELECT (RFC 3691)
    bool enable = false;         // ENABLE (RFC 5161)
    bool compress = false;       // COMPRESS=DEFLATE (RFC 4978)
    bool literal_plus = false;   // LITERAL+
    bool sasl_ir = false;        // SASL-IR
    bool starttls = false;
    bool auth_plain = false;
    bool auth_login = false;
    bool auth_oauth = false;     // AUTH=XOAUTH2
    bool children = false;       // CHILDREN (RFC 3348)
    bool multiappend = false;    // MULTIAPPEND (RFC 3502)
    bool sort = false;           // SORT (RFC 5256)
    bool thread = false;         // THREAD=REFERENCES
    bool esearch = false;        // ESEARCH
    bool metadata = false;       // METADATA (RFC 5464)
    bool quota = false;          // QUOTA (RFC 2087)
    bool id = false;             // ID (RFC 2971)
    bool binary = false;         // BINARY
    bool within = false;         // WITHIN
    bool searchres = false;      // SEARCHRES
    bool annotate = false;       // ANNOTATE
    bool list_myrights = false;  // LIST-MYRIGHTS
    std::string server_id;
    std::string server_name;
    std::string server_version;

    void parse_from_capability_line(const std::string& line) {
        std::string lower; lower.reserve(line.size());
        for (char c : line) lower.push_back(static_cast<char>(std::tolower(c)));

        idle = lower.find("idle") != std::string::npos;
        move = lower.find("move") != std::string::npos;
        uidplus = lower.find("uidplus") != std::string::npos;
        condstore = lower.find("condstore") != std::string::npos;
        qresync = lower.find("qresync") != std::string::npos;
        namespace_cmd = lower.find("namespace") != std::string::npos;
        list_extended = lower.find("list-extended") != std::string::npos;
        list_status = lower.find("list-status") != std::string::npos;
        special_use = lower.find("special-use") != std::string::npos;
        unselect = lower.find("unselect") != std::string::npos;
        enable = lower.find("enable") != std::string::npos;
        compress = lower.find("compress=deflate") != std::string::npos;
        literal_plus = lower.find("literal+") != std::string::npos;
        sasl_ir = lower.find("sasl-ir") != std::string::npos;
        starttls = lower.find("starttls") != std::string::npos;
        auth_plain = lower.find("auth=plain") != std::string::npos;
        auth_login = lower.find("auth=login") != std::string::npos;
        auth_oauth = lower.find("auth=xoauth2") != std::string::npos ||
                     lower.find("auth=oauthbearer") != std::string::npos;
        children = lower.find("children") != std::string::npos;
        multiappend = lower.find("multiappend") != std::string::npos;
        sort = lower.find("sort") != std::string::npos;
        thread = lower.find("thread=references") != std::string::npos;
        esearch = lower.find("esearch") != std::string::npos;
        metadata = lower.find("metadata") != std::string::npos;
        quota = lower.find("quota") != std::string::npos;
        id = lower.find(" id ") != std::string::npos || lower.find("id\r") != std::string::npos;
        binary = lower.find("binary") != std::string::npos;
        within = lower.find("within") != std::string::npos;
        searchres = lower.find("searchres") != std::string::npos;
        annotate = lower.find("annotate") != std::string::npos;
        list_myrights = lower.find("list-myrights") != std::string::npos;
    }

    bool supports_move() const { return move; }
    bool supports_idle() const { return idle; }
    bool supports_uidplus() const { return uidplus; }
};

// ============================================================================
// Folder watch configuration
// ============================================================================
struct FolderWatchConfig {
    // Which folders to watch
    bool watch_inbox = true;
    bool watch_deltachat = true;
    bool watch_sent = true;
    bool watch_drafts = false;
    bool watch_archive = false;
    bool watch_trash = false;
    bool watch_junk = false;

    // Custom folders to watch (by full name)
    std::set<std::string> custom_watch_folders;

    // IDLE settings
    int idle_timeout_seconds = IDLE_TIMEOUT_SECONDS;
    int idle_renewal_seconds = IDLE_RENEWAL_SECONDS;

    // Folder names
    std::string inbox_folder = "INBOX";
    std::string deltachat_folder = DC_MVBOX_FOLDER;
    std::string sent_folder = DEFAULT_SENT_FOLDER;
    std::string drafts_folder = DEFAULT_DRAFTS;
    std::string archive_folder = DEFAULT_ARCHIVE;
    std::string trash_folder = DEFAULT_TRASH;
    std::string junk_folder = DEFAULT_JUNK;

    // Auto-detect sent folder
    bool auto_detect_sent = true;

    // MVBOX move behavior
    bool mvbox_move = true;          // move messages to DeltaChat folder
    bool only_fetch_mvbox = false;   // only fetch from DeltaChat folder

    bool should_watch(const std::string& folder_name) const {
        if (folder_name == inbox_folder && watch_inbox) return true;
        if (folder_name == deltachat_folder && watch_deltachat) return true;
        if (folder_name == sent_folder && watch_sent) return true;
        if (folder_name == drafts_folder && watch_drafts) return true;
        if (folder_name == archive_folder && watch_archive) return true;
        if (folder_name == trash_folder && watch_trash) return true;
        if (folder_name == junk_folder && watch_junk) return true;
        return custom_watch_folders.count(folder_name) > 0;
    }

    std::vector<std::string> get_watch_list() const {
        std::vector<std::string> result;
        if (watch_inbox) result.push_back(inbox_folder);
        if (watch_deltachat) result.push_back(deltachat_folder);
        if (watch_sent) result.push_back(sent_folder);
        if (watch_drafts) result.push_back(drafts_folder);
        if (watch_archive) result.push_back(archive_folder);
        if (watch_trash) result.push_back(trash_folder);
        if (watch_junk) result.push_back(junk_folder);
        for (const auto& f : custom_watch_folders) result.push_back(f);
        return result;
    }
};

// ============================================================================
// Folder operation results
// ============================================================================
struct FolderOpResult {
    bool success = false;
    std::string error;
    int error_code = 0;
    std::string response_text;
    std::vector<std::string> response_lines;

    bool is_ok() const { return success; }
};

struct ListFolderResult {
    std::string name;
    std::string delimiter;
    uint32_t attributes = 0;
    std::string special_use; // e.g. "\\Sent", "\\Trash"
};

struct StatusResult {
    std::string folder;
    int messages = 0;
    int recent = 0;
    int unseen = 0;
    int uidnext = 0;
    int uidvalidity = 0;
    uint64_t highest_modseq = 0;
    bool success = false;
    std::string error;
};

struct SelectResult {
    int exists = 0;
    int recent = 0;
    int unseen = 0;
    int uidnext = 0;
    int uidvalidity = 0;
    uint64_t highest_modseq = 0;
    std::vector<std::string> permanent_flags;
    std::vector<std::string> response_lines;
    bool read_only = false;  // EXAMINE mode
    bool success = false;
    std::string error;
};

struct MoveResult {
    bool success = false;
    std::string error;
    int source_uid = 0;
    int dest_uid = 0;        // new UID in destination (UIDPLUS)
    std::string dest_uid_validity;
};

struct FlagResult {
    bool success = false;
    std::string error;
    int flagged_count = 0;
    std::vector<int> updated_uids;
};

// ============================================================================
// Folder statistics tracker
// ============================================================================
class FolderStatsTracker {
public:
    struct PeriodicStats {
        uint64_t total_selects = 0;
        uint64_t total_status_checks = 0;
        uint64_t total_moves = 0;
        uint64_t total_copies = 0;
        uint64_t total_deletes = 0;
        uint64_t total_expunges = 0;
        uint64_t total_flag_ops = 0;
        uint64_t total_idle_cycles = 0;
        uint64_t total_errors = 0;
        uint64_t total_reconnects = 0;

        // Message counts
        uint64_t msgs_fetched = 0;
        uint64_t msgs_moved = 0;
        uint64_t msgs_deleted = 0;
        uint64_t msgs_flagged = 0;

        // Timing
        double avg_select_ms = 0.0;
        double avg_status_ms = 0.0;
        double avg_move_ms = 0.0;
        double max_select_ms = 0.0;
        double max_status_ms = 0.0;
        double max_move_ms = 0.0;

        void merge(const PeriodicStats& other) {
            total_selects += other.total_selects;
            total_status_checks += other.total_status_checks;
            total_moves += other.total_moves;
            total_copies += other.total_copies;
            total_deletes += other.total_deletes;
            total_expunges += other.total_expunges;
            total_flag_ops += other.total_flag_ops;
            total_idle_cycles += other.total_idle_cycles;
            total_errors += other.total_errors;
            total_reconnects += other.total_reconnects;
            msgs_fetched += other.msgs_fetched;
            msgs_moved += other.msgs_moved;
            msgs_deleted += other.msgs_deleted;
            msgs_flagged += other.msgs_flagged;
            avg_select_ms = std::max(avg_select_ms, other.avg_select_ms);
            avg_status_ms = std::max(avg_status_ms, other.avg_status_ms);
            avg_move_ms = std::max(avg_move_ms, other.avg_move_ms);
            max_select_ms = std::max(max_select_ms, other.max_select_ms);
            max_status_ms = std::max(max_status_ms, other.max_status_ms);
            max_move_ms = std::max(max_move_ms, other.max_move_ms);
        }
    };

    FolderStatsTracker() = default;

    void record_select(const std::string& folder, double duration_ms, bool success) {
        std::lock_guard lock(mutex_);
        auto& s = folder_stats_[folder];
        s.total_selects++;
        if (success) {
            s.total_select_ms += duration_ms;
            s.select_count++;
            if (duration_ms > s.max_select_ms) s.max_select_ms = duration_ms;
        } else {
            s.total_errors++;
        }
        global_period_.total_selects++;
        if (duration_ms > global_period_.max_select_ms)
            global_period_.max_select_ms = duration_ms;
        touch_window(folder);
    }

    void record_status(const std::string& folder, double duration_ms, bool success) {
        std::lock_guard lock(mutex_);
        auto& s = folder_stats_[folder];
        s.total_status_checks++;
        if (success) {
            s.total_status_ms += duration_ms;
            s.status_count++;
            if (duration_ms > s.max_status_ms) s.max_status_ms = duration_ms;
        } else {
            s.total_errors++;
        }
        global_period_.total_status_checks++;
        if (duration_ms > global_period_.max_status_ms)
            global_period_.max_status_ms = duration_ms;
        touch_window(folder);
    }

    void record_move(const std::string& source, const std::string& dest,
                     double duration_ms, bool success, int count = 1) {
        std::lock_guard lock(mutex_);
        auto& s = folder_stats_[source];
        auto& d = folder_stats_[dest];
        s.total_moves++;
        d.total_moves++;
        if (success) {
            s.msgs_moved_out += count;
            d.msgs_moved_in += count;
            s.total_move_ms += duration_ms;
            if (duration_ms > s.max_move_ms) s.max_move_ms = duration_ms;
            if (duration_ms > d.max_move_ms) d.max_move_ms = duration_ms;
        } else {
            s.total_errors++;
            d.total_errors++;
        }
        global_period_.total_moves++;
        global_period_.msgs_moved += count;
        if (duration_ms > global_period_.max_move_ms)
            global_period_.max_move_ms = duration_ms;
        touch_window(source);
        touch_window(dest);
    }

    void record_copy(const std::string& source, const std::string& dest,
                     int count = 1) {
        std::lock_guard lock(mutex_);
        folder_stats_[source].total_copies++;
        folder_stats_[dest].total_copies++;
        global_period_.total_copies++;
        touch_window(source);
        touch_window(dest);
    }

    void record_delete(const std::string& folder, int count = 1) {
        std::lock_guard lock(mutex_);
        folder_stats_[folder].total_deletes++;
        folder_stats_[folder].msgs_deleted += count;
        global_period_.total_deletes++;
        global_period_.msgs_deleted += count;
        touch_window(folder);
    }

    void record_expunge(const std::string& folder, int count = 1) {
        std::lock_guard lock(mutex_);
        folder_stats_[folder].total_expunges++;
        global_period_.total_expunges++;
        touch_window(folder);
    }

    void record_flag_op(const std::string& folder, int count = 1) {
        std::lock_guard lock(mutex_);
        folder_stats_[folder].total_flag_ops++;
        folder_stats_[folder].msgs_flagged += count;
        global_period_.total_flag_ops++;
        global_period_.msgs_flagged += count;
        touch_window(folder);
    }

    void record_idle_cycle(const std::string& folder) {
        std::lock_guard lock(mutex_);
        folder_stats_[folder].total_idle_cycles++;
        global_period_.total_idle_cycles++;
        touch_window(folder);
    }

    void record_error(const std::string& folder, const std::string& error) {
        std::lock_guard lock(mutex_);
        folder_stats_[folder].total_errors++;
        global_period_.total_errors++;
        touch_window(folder);
    }

    void record_reconnect(const std::string& folder) {
        std::lock_guard lock(mutex_);
        folder_stats_[folder].total_reconnects++;
        global_period_.total_reconnects++;
        touch_window(folder);
    }

    void record_fetched(const std::string& folder, int count = 1) {
        std::lock_guard lock(mutex_);
        folder_stats_[folder].msgs_fetched += count;
        global_period_.msgs_fetched += count;
        touch_window(folder);
    }

    PeriodicStats get_global_stats() const {
        std::lock_guard lock(mutex_);
        PeriodicStats s = global_period_;
        // Compute averages
        if (select_count_ > 0) s.avg_select_ms = total_select_ms_ / select_count_;
        if (status_count_ > 0) s.avg_status_ms = total_status_ms_ / status_count_;
        if (move_count_ > 0) s.avg_move_ms = total_move_ms_ / move_count_;
        return s;
    }

    struct FolderStats {
        uint64_t total_selects = 0;
        uint64_t total_status_checks = 0;
        uint64_t total_moves = 0;
        uint64_t total_copies = 0;
        uint64_t total_deletes = 0;
        uint64_t total_expunges = 0;
        uint64_t total_flag_ops = 0;
        uint64_t total_idle_cycles = 0;
        uint64_t total_errors = 0;
        uint64_t total_reconnects = 0;
        uint64_t msgs_fetched = 0;
        uint64_t msgs_moved_in = 0;
        uint64_t msgs_moved_out = 0;
        uint64_t msgs_deleted = 0;
        uint64_t msgs_flagged = 0;
        double total_select_ms = 0.0;
        double total_status_ms = 0.0;
        double total_move_ms = 0.0;
        double max_select_ms = 0.0;
        double max_status_ms = 0.0;
        double max_move_ms = 0.0;
        int select_count = 0;
        int status_count = 0;
        int move_count = 0;
        uint64_t first_event = 0;
        uint64_t last_event = 0;
    };

    FolderStats get_folder_stats(const std::string& folder) const {
        std::lock_guard lock(mutex_);
        auto it = folder_stats_.find(folder);
        if (it != folder_stats_.end()) return it->second;
        return FolderStats{};
    }

    void reset_window() {
        std::lock_guard lock(mutex_);
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        window_start_ = now;
        window_stats_ = PeriodicStats{};
        folder_stats_.clear();
        select_count_ = 0; status_count_ = 0; move_count_ = 0;
        total_select_ms_ = 0; total_status_ms_ = 0; total_move_ms_ = 0;
    }

private:
    void touch_window(const std::string& folder) {
        auto& s = folder_stats_[folder];
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        if (s.first_event == 0) s.first_event = now;
        s.last_event = now;
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, FolderStats> folder_stats_;
    PeriodicStats window_stats_;
    PeriodicStats global_period_;
    uint64_t window_start_ = 0;
    // Running totals for averages
    uint64_t select_count_ = 0;
    uint64_t status_count_ = 0;
    uint64_t move_count_ = 0;
    double total_select_ms_ = 0.0;
    double total_status_ms_ = 0.0;
    double total_move_ms_ = 0.0;
};

// ============================================================================
// IDLE watcher — manages IDLE command lifecycle
// ============================================================================
class IdleWatcher {
public:
    struct IdleCallback {
        std::function<void(const std::string& folder, int exists, int recent)> on_exists;
        std::function<void(const std::string& folder, int uid, const std::string& flags)> on_fetch;
        std::function<void(const std::string& folder)> on_expunge;
        std::function<void(const std::string& folder)> on_uidvalidity_change;
        std::function<void(const std::string& folder, const std::string& error)> on_error;
    };

    IdleWatcher(ImapConnection& conn, FolderStatsTracker& stats)
        : conn_(conn), stats_(stats) {}

    // Start IDLE on a folder. Blocks until data arrives or timeout.
    bool start_idle(const std::string& folder, IdleCallback cb, int timeout_secs = IDLE_TIMEOUT_SECONDS) {
        std::lock_guard lock(mutex_);
        if (idle_active_) {
            stop_idle_internal();
        }

        current_folder_ = folder;
        callback_ = cb;
        idle_active_ = true;
        idle_start_time_ = std::chrono::steady_clock::now();

        // Send IDLE command
        std::string cmd = "IDLE";
        if (!conn_.send_command(cmd)) {
            idle_active_ = false;
            if (cb.on_error) cb.on_error(folder, "Failed to send IDLE command");
            return false;
        }

        // Wait for continuation
        auto cont = conn_.read_line(timeout_secs);
        if (cont.find("+") == std::string::npos) {
            idle_active_ = false;
            if (cb.on_error) cb.on_error(folder, "No IDLE continuation: " + cont);
            return false;
        }

        stats_.record_idle_cycle(folder);
        return true;
    }

    // Block waiting for IDLE data
    bool wait_for_data(int timeout_ms = 300000) {
        std::unique_lock lock(mutex_);
        if (!idle_active_) return false;
        lock.unlock();

        auto line = conn_.read_line(timeout_ms / 1000);
        if (line.empty()) return false;

        // Process untagged responses
        if (line.find("* ") == 0) {
            process_untagged(line);
        }
        return true;
    }

    // Stop IDLE
    void stop_idle() {
        std::lock_guard lock(mutex_);
        stop_idle_internal();
    }

    bool is_idle_active() const {
        std::lock_guard lock(mutex_);
        return idle_active_;
    }

    std::string current_folder() const {
        std::lock_guard lock(mutex_);
        return current_folder_;
    }

    bool needs_renewal() const {
        std::lock_guard lock(mutex_);
        if (!idle_active_) return false;
        auto elapsed = std::chrono::steady_clock::now() - idle_start_time_;
        return std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()
               >= IDLE_RENEWAL_SECONDS;
    }

    // Renew IDLE: send DONE, re-issue IDLE
    void renew_idle() {
        std::lock_guard lock(mutex_);
        if (!idle_active_) return;
        stop_idle_internal();
    }

private:
    void stop_idle_internal() {
        if (!idle_active_) return;
        conn_.send_raw("DONE\r\n");
        // Read the tagged OK
        conn_.read_line(5);
        idle_active_ = false;
        current_folder_.clear();
    }

    void process_untagged(const std::string& line) {
        // EXISTS response
        if (line.find("EXISTS") != std::string::npos) {
            int exists = parse_number_after(line, "EXISTS");
            int recent = parse_number_after(line, "RECENT");
            if (callback_.on_exists)
                callback_.on_exists(current_folder_, exists, recent);
            return;
        }

        // RECENT response
        if (line.find("RECENT") != std::string::npos && line.find("EXISTS") == std::string::npos) {
            int recent = parse_number_after(line, "RECENT");
            if (callback_.on_exists)
                callback_.on_exists(current_folder_, -1, recent);
            return;
        }

        // FETCH response (new message notification)
        if (line.find("FETCH") != std::string::npos) {
            int uid = 0;
            std::string flags;
            auto uid_pos = line.find("UID ");
            if (uid_pos != std::string::npos) {
                auto num_start = uid_pos + 4;
                auto num_end = line.find_first_of(" )\r\n", num_start);
                if (num_end != std::string::npos) {
                    uid = std::stoi(line.substr(num_start, num_end - num_start));
                }
            }
            auto flags_pos = line.find("FLAGS");
            if (flags_pos != std::string::npos) {
                auto paren_start = line.find('(', flags_pos);
                auto paren_end = line.find(')', paren_start);
                if (paren_start != std::string::npos && paren_end != std::string::npos) {
                    flags = line.substr(paren_start + 1, paren_end - paren_start - 1);
                }
            }
            if (callback_.on_fetch)
                callback_.on_fetch(current_folder_, uid, flags);
            return;
        }

        // EXPUNGE response
        if (line.find("EXPUNGE") != std::string::npos) {
            if (callback_.on_expunge)
                callback_.on_expunge(current_folder_);
            return;
        }

        // VANISHED (QRESYNC)
        if (line.find("VANISHED") != std::string::npos) {
            if (callback_.on_expunge)
                callback_.on_expunge(current_folder_);
            return;
        }
    }

    int parse_number_after(const std::string& line, const std::string& keyword) {
        auto pos = line.find(keyword);
        if (pos == std::string::npos) return -1;
        // Search backwards for the number before the keyword
        size_t num_start = 0;
        for (size_t i = pos; i > 0; --i) {
            if (i > 0 && line[i-1] == ' ') {
                num_start = i;
                break;
            }
        }
        if (num_start >= pos) return -1;
        try {
            return std::stoi(line.substr(num_start, pos - num_start));
        } catch (...) {
            return -1;
        }
    }

    ImapConnection& conn_;
    FolderStatsTracker& stats_;
    mutable std::mutex mutex_;
    std::string current_folder_;
    IdleCallback callback_;
    bool idle_active_ = false;
    std::chrono::steady_clock::time_point idle_start_time_;
};

// ============================================================================
// Standard IMAP error codes
// ============================================================================
enum class ImapError {
    OK = 0,
    NO = 1,         // operation failed
    BAD = 2,        // protocol error
    BYE = 3,        // server shutting down
    NETWORK = 4,    // network error
    TIMEOUT = 5,    // timeout
    PARSE = 6,      // response parse error
    NOT_AUTH = 7,   // not authenticated
    NOT_SELECTED = 8, // no mailbox selected
    FOLDER_EXISTS = 9,
    FOLDER_NOT_FOUND = 10,
    NAMESPACE_ERROR = 11,
    CAPABILITY_ERROR = 12,
    IDLE_ERROR = 13,
    MOVE_ERROR = 14,
    COPY_ERROR = 15,
    FLAG_ERROR = 16,
    EXPUNGE_ERROR = 17,
    STATUS_ERROR = 18,
    SUBSCRIBE_ERROR = 19,
    INTERNAL = 20,
};

static const char* imap_error_string(ImapError e) {
    switch (e) {
        case ImapError::OK: return "OK";
        case ImapError::NO: return "NO - operation failed";
        case ImapError::BAD: return "BAD - protocol error";
        case ImapError::BYE: return "BYE - server disconnecting";
        case ImapError::NETWORK: return "Network error";
        case ImapError::TIMEOUT: return "Timeout";
        case ImapError::PARSE: return "Parse error";
        case ImapError::NOT_AUTH: return "Not authenticated";
        case ImapError::NOT_SELECTED: return "No mailbox selected";
        case ImapError::FOLDER_EXISTS: return "Folder already exists";
        case ImapError::FOLDER_NOT_FOUND: return "Folder not found";
        case ImapError::NAMESPACE_ERROR: return "Namespace error";
        case ImapError::CAPABILITY_ERROR: return "Capability error";
        case ImapError::IDLE_ERROR: return "IDLE error";
        case ImapError::MOVE_ERROR: return "MOVE error";
        case ImapError::COPY_ERROR: return "COPY error";
        case ImapError::FLAG_ERROR: return "FLAG error";
        case ImapError::EXPUNGE_ERROR: return "EXPUNGE error";
        case ImapError::STATUS_ERROR: return "STATUS error";
        case ImapError::SUBSCRIBE_ERROR: return "SUBSCRIBE error";
        case ImapError::INTERNAL: return "Internal error";
        default: return "Unknown error";
    }
}

// ============================================================================
// IMAP Folder Manager — main class
// ============================================================================
class ImapFolderManager {
public:
    struct Config {
        std::string deltachat_folder_name = DC_MVBOX_FOLDER;
        std::string sent_folder_name = DEFAULT_SENT_FOLDER;
        std::string drafts_folder_name = DEFAULT_DRAFTS;
        std::string archive_folder_name = DEFAULT_ARCHIVE;
        std::string trash_folder_name = DEFAULT_TRASH;
        std::string junk_folder_name = DEFAULT_JUNK;
        bool auto_create_deltachat = true;
        bool auto_subscribe_deltachat = true;
        bool mvbox_move_enabled = true;
        bool auto_expunge = true;
        bool use_uid_expunge = true;       // UID EXPUNGE if available
        bool batch_move_enabled = true;     // batch MOVE commands
        bool use_move_extension = true;     // use MOVE if server supports it
        int move_batch_size = 50;
        int flag_batch_size = BATCH_STORE_SIZE;
        int max_retries = MAX_RETRIES;
        int retry_base_delay_ms = RETRY_BASE_DELAY_MS;
        int retry_max_delay_ms = RETRY_MAX_DELAY_MS;
        int idle_timeout_seconds = IDLE_TIMEOUT_SECONDS;
        int idle_renewal_seconds = IDLE_RENEWAL_SECONDS;
        bool enable_idle = true;
        bool detect_uidvalidity_changes = true;
        int folder_scan_interval_seconds = 60;
    };

    ImapFolderManager(ImapConnection& conn, FolderStatsTracker& stats)
        : conn_(conn), stats_(stats), idle_watcher_(conn, stats) {}

    ~ImapFolderManager() {
        stop_all_idle();
    }

    // ========================================================================
    // 1. IMAP folder listing (LIST with attributes)
    // ========================================================================

    // RFC 3501 §6.3.8 — LIST command
    std::vector<ListFolderResult> list_folders(
            const std::string& reference = "",
            const std::string& mailbox = "*",
            bool subscribed_only = false)
    {
        std::vector<ListFolderResult> results;
        std::string cmd = subscribed_only ? "LSUB" : "LIST";
        cmd += " \"" + escape_quoted(reference) + "\" \"" + escape_quoted(mailbox) + "\"";

        // Use LIST-EXTENDED if available
        if (!subscribed_only && caps_.list_extended) {
            cmd = "LIST (SUBSCRIBED RECURSIVEMATCH) \"" +
                  escape_quoted(reference) + "\" \"" +
                  escape_quoted(mailbox) +
                  "\" RETURN (SUBSCRIBED CHILDREN SPECIAL-USE)";
        } else if (!subscribed_only && caps_.special_use) {
            cmd = "LIST (SPECIAL-USE) \"" +
                  escape_quoted(reference) + "\" \"" +
                  escape_quoted(mailbox) + "\"";
        }

        auto lines = conn_.send_and_read_lines(cmd, FOLDER_LIST_TIMEOUT_SECS);
        for (const auto& line : lines) {
            if (line.find("* ") != 0) continue;
            ListFolderResult lfr = parse_list_response(line);
            if (!lfr.name.empty()) {
                results.push_back(std::move(lfr));
                if (results.size() >= MAX_LIST_RESULTS) break;
            }
        }
        return results;
    }

    // Extended LIST with all options
    std::vector<ListFolderResult> list_folders_extended(
            const std::string& reference = "",
            const std::string& mailbox = "*",
            bool subscribed = false,
            bool recursive = false,
            bool children = false,
            bool special_use = false,
            bool remote = false)
    {
        std::vector<ListFolderResult> results;
        std::string cmd = "LIST";

        // Build selection options
        std::string sel_opts;
        if (subscribed) sel_opts += " SUBSCRIBED";
        if (recursive) sel_opts += " RECURSIVEMATCH";
        if (remote) sel_opts += " REMOTE";
        if (!sel_opts.empty()) cmd += " (" + sel_opts.substr(1) + ")";

        cmd += " \"" + escape_quoted(reference) + "\" \"" + escape_quoted(mailbox) + "\"";

        // Build return options
        std::string ret_opts;
        if (children) ret_opts += " CHILDREN";
        if (special_use) ret_opts += " SPECIAL-USE";
        if (subscribed) ret_opts += " SUBSCRIBED";
        if (!ret_opts.empty()) cmd += " RETURN (" + ret_opts.substr(1) + ")";

        auto lines = conn_.send_and_read_lines(cmd, FOLDER_LIST_TIMEOUT_SECS);
        for (const auto& line : lines) {
            if (line.find("* ") != 0) continue;
            ListFolderResult lfr = parse_list_response(line);
            if (!lfr.name.empty()) {
                results.push_back(std::move(lfr));
                if (results.size() >= MAX_LIST_RESULTS) break;
            }
        }
        return results;
    }

    // ========================================================================
    // 2. IMAP folder creation (CREATE DeltaChat folder)
    // ========================================================================

    FolderOpResult create_folder(const std::string& folder_name) {
        FolderOpResult result;

        // Check if folder already exists
        auto existing = list_folders("", folder_name);
        if (!existing.empty()) {
            result.success = true;
            result.response_text = "Folder already exists";
            return result;
        }

        std::string cmd = "CREATE \"" + escape_quoted(folder_name) + "\"";
        auto response = conn_.send_command(cmd, FOLDER_CREATE_TIMEOUT_SECS);

        result.success = response.find("OK") != std::string::npos;
        result.response_text = response;
        result.error = result.success ? "" :
            (response.find("NO") != std::string::npos ? "CREATE rejected" :
             response.find("BAD") != std::string::npos ? "Bad CREATE command" :
             "Unknown error creating folder");

        if (result.success) {
            stats_.record_select(folder_name, 0, true);
        } else {
            stats_.record_error(folder_name, result.error);
        }

        return result;
    }

    // Create DeltaChat folder specifically
    FolderOpResult create_deltachat_folder() {
        return create_folder(config_.deltachat_folder_name);
    }

    // Ensure DeltaChat folder exists, creating if necessary
    bool ensure_deltachat_folder() {
        auto result = create_deltachat_folder();
        if (!result.success) return false;

        // Subscribe to it
        if (config_.auto_subscribe_deltachat) {
            subscribe_folder(config_.deltachat_folder_name);
        }
        return true;
    }

    // ========================================================================
    // 3. IMAP folder deletion
    // ========================================================================

    FolderOpResult delete_folder(const std::string& folder_name) {
        FolderOpResult result;

        // Stop watching if active
        if (idle_watcher_.current_folder() == folder_name &&
            idle_watcher_.is_idle_active()) {
            idle_watcher_.stop_idle();
        }

        std::string cmd = "DELETE \"" + escape_quoted(folder_name) + "\"";
        auto response = conn_.send_command(cmd, FOLDER_DELETE_TIMEOUT_SECS);

        result.success = response.find("OK") != std::string::npos;
        result.response_text = response;
        result.error = result.success ? "" :
            (response.find("NO") != std::string::npos ? "DELETE rejected" :
             response.find("BAD") != std::string::npos ? "Bad DELETE command" :
             "Unknown error deleting folder");

        if (result.success) {
            // Remove from folder cache
            std::lock_guard lock(folder_cache_mutex_);
            folder_cache_.erase(folder_name);
        } else {
            stats_.record_error(folder_name, result.error);
        }

        return result;
    }

    // ========================================================================
    // 4. IMAP folder subscription (SUBSCRIBE, UNSUBSCRIBE)
    // ========================================================================

    FolderOpResult subscribe_folder(const std::string& folder_name) {
        FolderOpResult result;
        std::string cmd = "SUBSCRIBE \"" + escape_quoted(folder_name) + "\"";
        auto response = conn_.send_command(cmd, FOLDER_STATUS_TIMEOUT_SECS);

        result.success = response.find("OK") != std::string::npos;
        result.response_text = response;
        result.error = result.success ? "" :
            (response.find("NO") != std::string::npos ? "SUBSCRIBE rejected" :
             response.find("BAD") != std::string::npos ? "Bad SUBSCRIBE command" :
             "Unknown error subscribing");

        if (result.success) {
            std::lock_guard lock(folder_cache_mutex_);
            auto it = folder_cache_.find(folder_name);
            if (it != folder_cache_.end()) it->second.is_subscribed = true;
        } else {
            stats_.record_error(folder_name, result.error);
        }

        return result;
    }

    FolderOpResult unsubscribe_folder(const std::string& folder_name) {
        FolderOpResult result;
        std::string cmd = "UNSUBSCRIBE \"" + escape_quoted(folder_name) + "\"";
        auto response = conn_.send_command(cmd, FOLDER_STATUS_TIMEOUT_SECS);

        result.success = response.find("OK") != std::string::npos;
        result.response_text = response;
        result.error = result.success ? "" :
            (response.find("NO") != std::string::npos ? "UNSUBSCRIBE rejected" :
             response.find("BAD") != std::string::npos ? "Bad UNSUBSCRIBE command" :
             "Unknown error unsubscribing");

        if (result.success) {
            std::lock_guard lock(folder_cache_mutex_);
            auto it = folder_cache_.find(folder_name);
            if (it != folder_cache_.end()) it->second.is_subscribed = false;
        } else {
            stats_.record_error(folder_name, result.error);
        }

        return result;
    }

    // Subscribe to all watch-listed folders
    int subscribe_watched_folders() {
        int count = 0;
        for (const auto& folder : watch_config_.get_watch_list()) {
            auto result = subscribe_folder(folder);
            if (result.success) count++;
        }
        return count;
    }

    // ========================================================================
    // 5. DeltaChat folder detection
    // ========================================================================

    // Scan all folders and detect which one is the DeltaChat mailbox
    std::optional<std::string> detect_deltachat_folder() {
        // First, check the configured name
        auto folders = list_folders();
        for (const auto& f : folders) {
            if (f.name == config_.deltachat_folder_name) {
                return f.name;
            }
        }

        // Check common variations
        static const std::vector<std::string> candidates = {
            "DeltaChat", "deltachat", "DELTACHAT",
            "INBOX.DeltaChat", "INBOX/deltachat",
            "DeltaChat.INBOX", "deltachat/INBOX",
        };

        for (const auto& f : folders) {
            std::string lower = f.name;
            for (auto& c : lower) c = static_cast<char>(std::tolower(c));
            for (const auto& candidate : candidates) {
                std::string cl = candidate;
                for (auto& c : cl) c = static_cast<char>(std::tolower(c));
                if (lower == cl) {
                    return f.name;
                }
            }
        }

        return std::nullopt;
    }

    // Full folder discovery
    struct FolderDiscovery {
        std::string inbox;
        std::optional<std::string> deltachat;
        std::optional<std::string> sent;
        std::optional<std::string> drafts;
        std::optional<std::string> archive;
        std::optional<std::string> trash;
        std::optional<std::string> junk;
        std::vector<ListFolderResult> all_folders;

        bool has_deltachat() const { return deltachat.has_value(); }
        bool has_sent() const { return sent.has_value(); }
        bool has_trash() const { return trash.has_value(); }
    };

    FolderDiscovery discover_folders() {
        FolderDiscovery discovery;
        auto folders = list_folders_extended("", "*", false, false, true, true);
        discovery.all_folders = folders;

        for (const auto& f : folders) {
            uint32_t attrs = f.attributes;

            // Detect by SPECIAL-USE
            if (attrs & static_cast<uint32_t>(ImapListAttr::INBOX) || f.name == "INBOX") {
                discovery.inbox = f.name;
            }
            if (attrs & static_cast<uint32_t>(ImapListAttr::SENT)) {
                discovery.sent = f.name;
            }
            if (attrs & static_cast<uint32_t>(ImapListAttr::DRAFTS)) {
                discovery.drafts = f.name;
            }
            if (attrs & static_cast<uint32_t>(ImapListAttr::ARCHIVE)) {
                discovery.archive = f.name;
            }
            if (attrs & static_cast<uint32_t>(ImapListAttr::TRASH)) {
                discovery.trash = f.name;
            }
            if (attrs & static_cast<uint32_t>(ImapListAttr::JUNK)) {
                discovery.junk = f.name;
            }

            // DeltaChat folder by name pattern
            std::string lower = f.name;
            for (auto& c : lower) c = static_cast<char>(std::tolower(c));
            if (lower.find("deltachat") != std::string::npos ||
                lower.find("delta_chat") != std::string::npos ||
                lower.find("delta chat") != std::string::npos) {
                if (!discovery.deltachat) discovery.deltachat = f.name;
            }
        }

        // If not found via SPECIAL-USE, try heuristics for Sent folder
        if (!discovery.sent && watch_config_.auto_detect_sent) {
            for (const auto& f : folders) {
                std::string lower = f.name;
                for (auto& c : lower) c = static_cast<char>(std::tolower(c));
                if (lower == "sent" || lower == "sent items" ||
                    lower == "sent messages" || lower == "gesendet" ||
                    lower == "enviados" || lower == "envoys" ||
                    lower.find("sent") != std::string::npos) {
                    discovery.sent = f.name;
                    break;
                }
            }
        }

        // If DeltaChat folder not found, use the configured name
        if (!discovery.deltachat) {
            discovery.deltachat = config_.deltachat_folder_name;
        }

        // Apply namespace prefix if discovered
        if (!namespace_info_.prefix().empty()) {
            auto* ns = namespace_info_.best_personal();
            if (ns && !discovery.inbox.empty()) {
                if (discovery.inbox.find(ns->prefix) != 0) {
                    discovery.inbox = ns->resolve(discovery.inbox);
                }
            }
        }

        return discovery;
    }

    // ========================================================================
    // 6. Folder watching configuration
    // ========================================================================

    void set_watch_config(const FolderWatchConfig& cfg) {
        std::lock_guard lock(watch_mutex_);
        watch_config_ = cfg;
    }

    FolderWatchConfig get_watch_config() const {
        std::lock_guard lock(watch_mutex_);
        return watch_config_;
    }

    // Add a custom folder to watch
    void add_watch_folder(const std::string& folder) {
        std::lock_guard lock(watch_mutex_);
        watch_config_.custom_watch_folders.insert(folder);
    }

    void remove_watch_folder(const std::string& folder) {
        std::lock_guard lock(watch_mutex_);
        watch_config_.custom_watch_folders.erase(folder);
    }

    // Update from folder discovery
    void apply_discovery(const FolderDiscovery& discovery) {
        std::lock_guard lock(watch_mutex_);
        watch_config_.inbox_folder = discovery.inbox;
        if (discovery.deltachat)
            watch_config_.deltachat_folder = *discovery.deltachat;
        if (discovery.sent)
            watch_config_.sent_folder = *discovery.sent;
        if (discovery.drafts)
            watch_config_.drafts_folder = *discovery.drafts;
        if (discovery.archive)
            watch_config_.archive_folder = *discovery.archive;
        if (discovery.trash)
            watch_config_.trash_folder = *discovery.trash;
        if (discovery.junk)
            watch_config_.junk_folder = *discovery.junk;
    }

    // ========================================================================
    // 7. Folder status checking (STATUS)
    // ========================================================================

    StatusResult get_folder_status(const std::string& folder_name,
                                    bool check_uidnext = true,
                                    bool check_unseen = true,
                                    bool check_modseq = false)
    {
        StatusResult result;
        result.folder = folder_name;

        std::string items = "(MESSAGES RECENT";
        if (check_uidnext) items += " UIDNEXT UIDVALIDITY";
        if (check_unseen) items += " UNSEEN";
        if (check_modseq && caps_.condstore) items += " HIGHESTMODSEQ";
        items += ")";

        std::string cmd = "STATUS \"" + escape_quoted(folder_name) + "\" " + items;

        auto start = std::chrono::steady_clock::now();
        auto lines = conn_.send_and_read_lines(cmd, FOLDER_STATUS_TIMEOUT_SECS);
        auto elapsed = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();

        result.success = false;
        for (const auto& line : lines) {
            if (line.find("* STATUS") != std::string::npos) {
                parse_status_line(line, result);
                result.success = true;
                break;
            }
            if (line.find("OK") != std::string::npos &&
                line.find("STATUS") != std::string::npos) {
                result.success = true;
            }
        }

        stats_.record_status(folder_name, elapsed, result.success);
        if (!result.success) {
            result.error = "Failed to get folder status";
            stats_.record_error(folder_name, result.error);
        }

        // Update folder cache
        if (result.success) {
            std::lock_guard lock(folder_cache_mutex_);
            auto it = folder_cache_.find(folder_name);
            if (it != folder_cache_.end()) {
                it->second.exists = result.messages;
                it->second.recent = result.recent;
                it->second.unseen = result.unseen;
                it->second.uid_next = result.uidnext;
                it->second.highest_modseq = result.highest_modseq;
                it->second.last_status_check =
                    std::chrono::steady_clock::now().time_since_epoch().count();

                // Detect UIDVALIDITY change
                if (result.uidvalidity > 0 &&
                    it->second.uid_validity > 0 &&
                    result.uidvalidity != it->second.uid_validity) {
                    it->second.uid_validity_changed = true;
                    it->second.uid_validity = result.uidvalidity;
                } else if (result.uidvalidity > 0) {
                    it->second.uid_validity = result.uidvalidity;
                }
            }
        }

        return result;
    }

    // Batch status check for multiple folders
    std::vector<StatusResult> get_folder_status_batch(
            const std::vector<std::string>& folders)
    {
        std::vector<StatusResult> results;
        results.reserve(folders.size());
        for (const auto& folder : folders) {
            results.push_back(get_folder_status(folder));
        }
        return results;
    }

    // Check all watched folders' status
    std::vector<StatusResult> check_watched_folders() {
        return get_folder_status_batch(watch_config_.get_watch_list());
    }

    // ========================================================================
    // 8. Folder selection (SELECT, EXAMINE)
    // ========================================================================

    SelectResult select_folder(const std::string& folder_name, bool read_only = false) {
        SelectResult result;

        std::string cmd = read_only ? "EXAMINE" : "SELECT";
        cmd += " \"" + escape_quoted(folder_name) + "\"";

        // Use CONDSTORE if available
        if (caps_.condstore) {
            cmd += " (CONDSTORE)";
        }

        auto start = std::chrono::steady_clock::now();
        auto lines = conn_.send_and_read_lines(cmd, FOLDER_SELECT_TIMEOUT_SECS);
        auto elapsed = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();

        result.success = false;
        for (const auto& line : lines) {
            result.response_lines.push_back(line);

            if (line.find("* OK") != std::string::npos &&
                line.find("READ-ONLY") != std::string::npos) {
                result.read_only = true;
            }

            if (line.find("* ") == 0) {
                // EXISTS
                if (line.find("EXISTS") != std::string::npos) {
                    result.exists = parse_number_before(line, "EXISTS");
                }
                // RECENT
                if (line.find("RECENT") != std::string::npos) {
                    result.recent = parse_number_before(line, "RECENT");
                }
                // OK [UNSEEN n]
                if (line.find("UNSEEN") != std::string::npos) {
                    result.unseen = extract_bracket_value(line, "UNSEEN");
                }
                // OK [UIDNEXT n]
                if (line.find("UIDNEXT") != std::string::npos) {
                    result.uidnext = extract_bracket_value(line, "UIDNEXT");
                }
                // OK [UIDVALIDITY n]
                if (line.find("UIDVALIDITY") != std::string::npos) {
                    result.uidvalidity = extract_bracket_value(line, "UIDVALIDITY");
                }
                // OK [HIGHESTMODSEQ n]
                if (line.find("HIGHESTMODSEQ") != std::string::npos) {
                    result.highest_modseq = static_cast<uint64_t>(
                        extract_bracket_value(line, "HIGHESTMODSEQ"));
                }
                // OK [PERMANENTFLAGS (...)]
                if (line.find("PERMANENTFLAGS") != std::string::npos) {
                    result.permanent_flags = extract_bracket_list(line, "PERMANENTFLAGS");
                }
            }

            // Tagged OK
            if (line.find("OK") != std::string::npos &&
                line.find("SELECT") != std::string::npos &&
                line.find("*") != 0) {
                result.success = true;
            }
        }

        stats_.record_select(folder_name, elapsed, result.success);

        if (result.success) {
            std::lock_guard lock(folder_cache_mutex_);
            auto& folder = get_or_create_folder_cache(folder_name);
            folder.exists = result.exists;
            folder.recent = result.recent;
            folder.unseen = result.unseen;
            folder.uid_next = result.uidnext;
            folder.highest_modseq = result.highest_modseq;
            folder.flags = result.permanent_flags;
            folder.is_selected = !read_only;
            folder.last_select_time =
                std::chrono::steady_clock::now().time_since_epoch().count();

            // UIDVALIDITY change detection
            if (result.uidvalidity > 0 &&
                folder.uid_validity > 0 &&
                result.uidvalidity != folder.uid_validity) {
                folder.uid_validity_changed = true;
            }
            folder.uid_validity = result.uidvalidity;

            // Mark other folders as not selected
            for (auto& [name, f] : folder_cache_) {
                if (name != folder_name) f.is_selected = false;
            }
        } else {
            result.error = "Failed to select folder";
            stats_.record_error(folder_name, result.error);
        }

        return result;
    }

    // UNSELECT / CLOSE the current folder
    FolderOpResult unselect_folder() {
        FolderOpResult result;
        std::string cmd = caps_.unselect ? "UNSELECT" : "CLOSE";
        auto response = conn_.send_command(cmd, FOLDER_SELECT_TIMEOUT_SECS);

        result.success = response.find("OK") != std::string::npos;
        result.response_text = response;

        if (result.success) {
            std::lock_guard lock(folder_cache_mutex_);
            for (auto& [name, f] : folder_cache_) f.is_selected = false;
        }

        return result;
    }

    // ========================================================================
    // 9. INBOX watching (IDLE on INBOX)
    // ========================================================================

    bool watch_inbox(IdleWatcher::IdleCallback callback) {
        if (!caps_.idle || !config_.enable_idle) return false;

        // Select INBOX first
        auto sel = select_folder(watch_config_.inbox_folder, true); // read-only
        if (!sel.success) return false;

        // Start IDLE
        bool started = idle_watcher_.start_idle(
            watch_config_.inbox_folder, callback, config_.idle_timeout_seconds);

        if (started) {
            std::lock_guard lock(folder_cache_mutex_);
            auto it = folder_cache_.find(watch_config_.inbox_folder);
            if (it != folder_cache_.end()) it->second.is_watched = true;
        }

        return started;
    }

    // ========================================================================
    // 10. DeltaChat folder watching
    // ========================================================================

    bool watch_deltachat(IdleWatcher::IdleCallback callback) {
        if (!caps_.idle || !config_.enable_idle) return false;

        auto sel = select_folder(watch_config_.deltachat_folder, true); // read-only
        if (!sel.success) return false;

        bool started = idle_watcher_.start_idle(
            watch_config_.deltachat_folder, callback, config_.idle_timeout_seconds);

        if (started) {
            std::lock_guard lock(folder_cache_mutex_);
            auto it = folder_cache_.find(watch_config_.deltachat_folder);
            if (it != folder_cache_.end()) it->second.is_watched = true;
        }

        return started;
    }

    // ========================================================================
    // 11. Sent folder watching
    // ========================================================================

    bool watch_sent(IdleWatcher::IdleCallback callback) {
        if (!caps_.idle || !config_.enable_idle) return false;
        if (watch_config_.sent_folder.empty()) return false;

        // Select sent folder in read-only mode
        auto sel = select_folder(watch_config_.sent_folder, true);
        if (!sel.success) return false;

        bool started = idle_watcher_.start_idle(
            watch_config_.sent_folder, callback, config_.idle_timeout_seconds);

        if (started) {
            std::lock_guard lock(folder_cache_mutex_);
            auto it = folder_cache_.find(watch_config_.sent_folder);
            if (it != folder_cache_.end()) it->second.is_watched = true;
        }

        return started;
    }

    // Watch all configured folders in sequence (single connection)
    struct WatchResult {
        std::string folder;
        bool success = false;
        std::string error;
    };

    std::vector<WatchResult> watch_all_folders(
            const std::unordered_map<std::string, IdleWatcher::IdleCallback>& callbacks)
    {
        std::vector<WatchResult> results;
        if (!caps_.idle) return results;

        for (const auto& folder : watch_config_.get_watch_list()) {
            WatchResult wr;
            wr.folder = folder;

            auto it = callbacks.find(folder);
            if (it == callbacks.end()) {
                wr.error = "No callback for folder";
                results.push_back(wr);
                continue;
            }

            auto sel = select_folder(folder, true);
            if (!sel.success) {
                wr.error = "Failed to select: " + sel.error;
                results.push_back(wr);
                continue;
            }

            wr.success = idle_watcher_.start_idle(
                folder, it->second, config_.idle_timeout_seconds);

            if (!wr.success) wr.error = "Failed to start IDLE";
            results.push_back(wr);
        }

        return results;
    }

    // IDLE loop with renewal
    void idle_loop(const std::string& folder, IdleWatcher::IdleCallback callback,
                   std::atomic<bool>& stop_flag, int timeout_ms = 300000)
    {
        IdleWatcher::IdleCallback wrapped_cb = callback;
        bool started = idle_watcher_.start_idle(folder, wrapped_cb, config_.idle_timeout_seconds);
        if (!started) {
            stats_.record_error(folder, "Failed to start IDLE loop");
            return;
        }

        while (!stop_flag.load(std::memory_order_relaxed)) {
            bool data = idle_watcher_.wait_for_data(timeout_ms);

            if (idle_watcher_.needs_renewal()) {
                idle_watcher_.renew_idle();
                // Re-start IDLE
                idle_watcher_.start_idle(folder, wrapped_cb, config_.idle_timeout_seconds);
                stats_.record_idle_cycle(folder);
            }

            if (!idle_watcher_.is_idle_active()) {
                // Reconnect and restart
                stats_.record_reconnect(folder);
                idle_watcher_.start_idle(folder, wrapped_cb, config_.idle_timeout_seconds);
            }
        }

        idle_watcher_.stop_idle();
    }

    void stop_all_idle() {
        idle_watcher_.stop_idle();
        std::lock_guard lock(folder_cache_mutex_);
        for (auto& [name, f] : folder_cache_) f.is_watched = false;
    }

    // ========================================================================
    // 12. Folder UIDVALIDITY change detection
    // ========================================================================

    bool check_uidvalidity_change(const std::string& folder_name) {
        auto status = get_folder_status(folder_name, true, false, false);
        if (!status.success) return false;

        std::lock_guard lock(folder_cache_mutex_);
        auto it = folder_cache_.find(folder_name);
        if (it == folder_cache_.end()) return false;

        auto& folder = it->second;
        if (folder.uid_validity > 0 && status.uidvalidity != folder.uid_validity) {
            // UIDVALIDITY changed — reset cached UIDs
            folder.uid_validity_changed = true;
            folder.uid_validity = status.uidvalidity;
            folder.known_uids.clear();
            folder.last_seen_uid = 0;
            return true;
        }

        folder.uid_validity = status.uidvalidity;
        return false;
    }

    // Check all watched folders for UIDVALIDITY changes
    std::vector<std::string> check_all_uidvalidity() {
        std::vector<std::string> changed;
        for (const auto& folder : watch_config_.get_watch_list()) {
            if (check_uidvalidity_change(folder)) {
                changed.push_back(folder);
            }
        }
        return changed;
    }

    // Get current UIDVALIDITY value
    int get_uidvalidity(const std::string& folder_name) {
        auto status = get_folder_status(folder_name, true, false, false);
        return status.uidvalidity;
    }

    // ========================================================================
    // 13. Message movement between folders (MOVE, COPY + DELETE)
    // ========================================================================

    // MOVE using UID MOVE (RFC 6851) if available
    MoveResult move_message(int uid, const std::string& source_folder,
                            const std::string& dest_folder)
    {
        MoveResult result;
        result.source_uid = uid;

        if (caps_.move && config_.use_move_extension) {
            return move_message_via_move(uid, source_folder, dest_folder);
        } else {
            return move_message_via_copy_delete(uid, source_folder, dest_folder);
        }
    }

    // Batch move multiple messages
    std::vector<MoveResult> move_messages(const std::vector<int>& uids,
                                           const std::string& source_folder,
                                           const std::string& dest_folder)
    {
        std::vector<MoveResult> results;

        if (uids.empty()) return results;

        if (caps_.move && config_.use_move_extension && config_.batch_move_enabled) {
            // Batch via UID MOVE
            results = move_messages_batch_move(uids, source_folder, dest_folder);
        } else if (config_.batch_move_enabled) {
            // Batch via UID COPY + UID STORE +FLAGS \Deleted + UID EXPUNGE
            results = move_messages_batch_copy(uids, source_folder, dest_folder);
        } else {
            // Individual moves
            for (int uid : uids) {
                results.push_back(move_message(uid, source_folder, dest_folder));
            }
        }

        // Update statistics
        int success_count = 0;
        for (const auto& r : results) if (r.success) success_count++;
        stats_.record_move(source_folder, dest_folder, 0, !results.empty(),
                          success_count);

        return results;
    }

    // COPY messages to another folder
    MoveResult copy_message(int uid, const std::string& source_folder,
                            const std::string& dest_folder)
    {
        MoveResult result;
        result.source_uid = uid;

        auto start = std::chrono::steady_clock::now();

        std::string cmd = "UID COPY " + std::to_string(uid) +
                         " \"" + escape_quoted(dest_folder) + "\"";
        auto response = conn_.send_command(cmd, FOLDER_COPY_TIMEOUT_SECS);

        auto elapsed = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();

        result.success = response.find("OK") != std::string::npos;

        // Parse UIDPLUS COPYUID response: [COPYUID uidvalidity uid-set dest-uid-set]
        if (result.success && caps_.uidplus) {
            auto copyuid_pos = response.find("COPYUID");
            if (copyuid_pos != std::string::npos) {
                result.dest_uid_validity = extract_uidvalidity(response, copyuid_pos);
                // Extract dest UID from response
                result.dest_uid = extract_dest_uid(response, copyuid_pos);
            }
        }

        result.error = result.success ? "" :
            (response.find("NO") != std::string::npos ? "COPY rejected" : "COPY failed");

        stats_.record_copy(source_folder, dest_folder);
        if (!result.success) stats_.record_error(source_folder, result.error);

        return result;
    }

    // Batch COPY
    std::vector<MoveResult> copy_messages(const std::vector<int>& uids,
                                           const std::string& source_folder,
                                           const std::string& dest_folder)
    {
        std::vector<MoveResult> results;

        for (size_t i = 0; i < uids.size(); i += config_.move_batch_size) {
            size_t batch_end = std::min(i + config_.move_batch_size, uids.size());
            std::string uid_set = build_uid_set(uids, i, batch_end);

            std::string cmd = "UID COPY " + uid_set +
                             " \"" + escape_quoted(dest_folder) + "\"";
            auto response = conn_.send_command(cmd, FOLDER_COPY_TIMEOUT_SECS);

            bool success = response.find("OK") != std::string::npos;
            for (size_t j = i; j < batch_end; ++j) {
                MoveResult mr;
                mr.source_uid = uids[j];
                mr.success = success;
                mr.error = success ? "" : "Batch COPY failed";
                results.push_back(mr);
            }

            if (!success) break;
        }

        return results;
    }

    // ========================================================================
    // 14. Server-side message flagging (STORE +FLAGS)
    // ========================================================================

    // Set flags on a single message
    FlagResult set_flags(int uid, const std::string& folder,
                         const std::string& flags, bool add = true,
                         bool silent = false)
    {
        FlagResult result;
        result.updated_uids.push_back(uid);

        std::string op = add ? "+FLAGS" : "-FLAGS";
        std::string suffix = silent ? ".SILENT" : "";
        std::string cmd = "UID STORE " + std::to_string(uid) + " " +
                         op + suffix + " (" + flags + ")";

        auto response = conn_.send_command(cmd, FOLDER_MOVE_TIMEOUT_SECS);
        result.success = response.find("OK") != std::string::npos;
        result.flagged_count = result.success ? 1 : 0;
        result.error = result.success ? "" : "STORE failed";

        stats_.record_flag_op(folder);
        if (!result.success) stats_.record_error(folder, result.error);

        return result;
    }

    // Batch flagging
    FlagResult set_flags_batch(const std::vector<int>& uids,
                                const std::string& folder,
                                const std::string& flags, bool add = true,
                                bool silent = true)
    {
        FlagResult result;
        result.updated_uids = uids;
        int total = 0;

        for (size_t i = 0; i < uids.size(); i += config_.flag_batch_size) {
            size_t batch_end = std::min(i + static_cast<size_t>(config_.flag_batch_size), uids.size());
            std::string uid_set = build_uid_set(uids, i, batch_end);

            std::string op = add ? "+FLAGS" : "-FLAGS";
            std::string suffix = silent ? ".SILENT" : "";
            std::string cmd = "UID STORE " + uid_set + " " +
                             op + suffix + " (" + flags + ")";

            auto response = conn_.send_command(cmd, FOLDER_MOVE_TIMEOUT_SECS);
            bool batch_ok = response.find("OK") != std::string::npos;

            if (batch_ok) {
                total += (batch_end - i);
            } else {
                result.error = "Batch STORE failed at offset " + std::to_string(i);
                break;
            }
        }

        result.success = (total > 0);
        result.flagged_count = total;
        if (total > 0) stats_.record_flag_op(folder, total);
        if (result.success && result.error.empty() && total < static_cast<int>(uids.size())) {
            result.success = false;
            result.error = "Partial batch STORE failure";
        }

        return result;
    }

    // Mark as seen
    FlagResult mark_seen(const std::vector<int>& uids, const std::string& folder) {
        return set_flags_batch(uids, folder, "\\Seen", true, true);
    }

    // Mark as deleted
    FlagResult mark_deleted(const std::vector<int>& uids, const std::string& folder) {
        return set_flags_batch(uids, folder, "\\Deleted", true, true);
    }

    // Mark as flagged/starred
    FlagResult mark_flagged(const std::vector<int>& uids, const std::string& folder, bool star) {
        return set_flags_batch(uids, folder, "\\Flagged", star, true);
    }

    // Remove \Seen (mark as unseen)
    FlagResult mark_unseen(const std::vector<int>& uids, const std::string& folder) {
        return set_flags_batch(uids, folder, "\\Seen", false, true);
    }

    // Set custom flags
    FlagResult set_custom_flags(const std::vector<int>& uids, const std::string& folder,
                                 const std::vector<std::string>& custom_flags, bool add = true) {
        std::string flags_str;
        for (size_t i = 0; i < custom_flags.size(); ++i) {
            if (i > 0) flags_str += " ";
            flags_str += custom_flags[i];
        }
        return set_flags_batch(uids, folder, flags_str, add, true);
    }

    // ========================================================================
    // 15. Message purging (EXPUNGE, UID EXPUNGE)
    // ========================================================================

    FolderOpResult expunge(const std::string& folder) {
        FolderOpResult result;
        std::string cmd = caps_.uidplus ? "UID EXPUNGE 1:*" : "EXPUNGE";
        auto response = conn_.send_command(cmd, FOLDER_PURGE_TIMEOUT_SECS);

        result.success = response.find("OK") != std::string::npos;
        result.response_text = response;
        result.error = result.success ? "" :
            (response.find("NO") != std::string::npos ? "EXPUNGE rejected" : "EXPUNGE failed");

        if (result.success) stats_.record_expunge(folder);
        if (!result.success) stats_.record_error(folder, result.error);

        return result;
    }

    // UID EXPUNGE specific UIDs
    FolderOpResult uid_expunge(const std::vector<int>& uids, const std::string& folder) {
        FolderOpResult result;
        if (uids.empty()) {
            result.success = true;
            return result;
        }

        std::string uid_set = build_uid_set(uids, 0, uids.size());
        std::string cmd = "UID EXPUNGE " + uid_set;
        auto response = conn_.send_command(cmd, FOLDER_PURGE_TIMEOUT_SECS);

        result.success = response.find("OK") != std::string::npos;
        result.response_text = response;
        result.error = result.success ? "" : "UID EXPUNGE failed";

        if (result.success) stats_.record_expunge(folder, uids.size());
        if (!result.success) stats_.record_error(folder, result.error);

        return result;
    }

    // Auto-expunge if configured
    void auto_expunge_if_needed(const std::string& folder) {
        if (!config_.auto_expunge) return;

        auto status = get_folder_status(folder, false, false, false);
        if (status.success && status.messages > 0) {
            expunge(folder);
        }
    }

    // Move to trash: copy to trash, mark deleted, expunge
    MoveResult move_to_trash(int uid, const std::string& source_folder) {
        MoveResult result;
        result.source_uid = uid;

        // Copy to trash folder
        auto copy_result = copy_message(uid, source_folder, watch_config_.trash_folder);
        if (!copy_result.success) {
            result.success = false;
            result.error = "Failed to copy to trash: " + copy_result.error;
            return result;
        }

        // Mark as deleted in source
        auto flag_result = mark_deleted({uid}, source_folder);
        if (flag_result.success && config_.auto_expunge) {
            uid_expunge({uid}, source_folder);
        }

        result.success = true;
        result.dest_uid = copy_result.dest_uid;
        return result;
    }

    // ========================================================================
    // 16. Folder performance optimization (batch operations)
    // ========================================================================

    // Pre-fetch folder status for all watch folders in parallel (pipelined)
    std::unordered_map<std::string, StatusResult> prefetch_all_status() {
        std::unordered_map<std::string, StatusResult> results;
        auto folders = watch_config_.get_watch_list();

        for (const auto& folder : folders) {
            results[folder] = get_folder_status(folder);
        }

        return results;
    }

    // Optimize batch size based on network latency
    void auto_tune_batch_sizes() {
        auto global = stats_.get_global_stats();

        // If operations are fast, increase batch sizes
        if (global.avg_select_ms < 50 && global.avg_select_ms > 0) {
            config_.move_batch_size = std::min(200, config_.move_batch_size + 10);
            config_.flag_batch_size = std::min(500, config_.flag_batch_size + 25);
        }
        // If operations are slow, decrease batch sizes
        else if (global.avg_select_ms > 500) {
            config_.move_batch_size = std::max(10, config_.move_batch_size - 5);
            config_.flag_batch_size = std::max(25, config_.flag_batch_size - 10);
        }
    }

    // Warm up: pre-select and gather status for watched folders
    void warmup_watched_folders() {
        for (const auto& folder : watch_config_.get_watch_list()) {
            get_folder_status(folder);
        }
    }

    // ========================================================================
    // 17. Folder error recovery (reconnect, retry)
    // ========================================================================

    struct RetryConfig {
        int max_retries = 5;
        int base_delay_ms = 1000;
        int max_delay_ms = 32000;
        bool exponential_backoff = true;
        double jitter_factor = 0.25;  // ±25% jitter
    };

    RetryConfig get_retry_config() const {
        RetryConfig cfg;
        cfg.max_retries = config_.max_retries;
        cfg.base_delay_ms = config_.retry_base_delay_ms;
        cfg.max_delay_ms = config_.retry_max_delay_ms;
        return cfg;
    }

    // Retry helper with exponential backoff + jitter
    template<typename Func>
    FolderOpResult retry_operation(Func operation, const std::string& folder,
                                    const RetryConfig& rcfg = RetryConfig{})
    {
        RetryConfig cfg = rcfg.max_retries == 0 ? get_retry_config() : rcfg;

        int attempt = 0;
        int delay_ms = cfg.base_delay_ms;
        FolderOpResult result;

        while (attempt < cfg.max_retries) {
            result = operation();

            if (result.success) return result;

            attempt++;

            // Check for unrecoverable errors
            if (result.response_text.find("BYE") != std::string::npos) {
                result.error = "Server disconnected (BYE): " + result.error;
                break;
            }
            if (result.response_text.find("BAD") != std::string::npos &&
                result.response_text.find("parse") != std::string::npos) {
                // Protocol error, don't retry
                break;
            }

            if (attempt >= cfg.max_retries) break;

            // Apply jitter
            double jitter = 1.0 + (static_cast<double>(std::rand()) / RAND_MAX * 2.0 - 1.0) * cfg.jitter_factor;
            int actual_delay = static_cast<int>(delay_ms * jitter);

            std::this_thread::sleep_for(std::chrono::milliseconds(actual_delay));

            // Exponential backoff
            delay_ms = std::min(delay_ms * 2, cfg.max_delay_ms);
        }

        stats_.record_error(folder, result.error + " (after " +
                           std::to_string(attempt) + " retries)");
        return result;
    }

    // Reconnect handler
    bool reconnect_and_recover(const std::string& last_folder = "") {
        stats_.record_reconnect(last_folder);

        // Reconnect via connection interface
        if (!conn_.reconnect()) {
            return false;
        }

        // Re-enable extensions
        if (caps_.condstore) conn_.send_command("ENABLE CONDSTORE QRESYNC");
        if (caps_.compress) conn_.send_command("COMPRESS DEFLATE");

        // Re-select last folder if needed
        if (!last_folder.empty()) {
            auto sel = select_folder(last_folder, true);
            return sel.success;
        }

        return true;
    }

    // Operation with reconnect-on-failure wrapper
    template<typename Func>
    FolderOpResult operation_with_reconnect(Func operation,
                                             const std::string& folder,
                                             int retries = 3)
    {
        int attempt = 0;
        FolderOpResult result;

        while (attempt < retries) {
            result = operation();
            if (result.success) return result;

            // Check if reconnection would help
            if (result.response_text.find("BYE") != std::string::npos ||
                result.error_code == static_cast<int>(ImapError::NETWORK) ||
                result.response_text.find("connection") != std::string::npos) {

                attempt++;
                if (!reconnect_and_recover(folder)) {
                    result.error = "Reconnection failed: " + result.error;
                    break;
                }
            } else {
                break; // Non-recoverable error
            }
        }

        return result;
    }

    // ========================================================================
    // 18. IMAP namespace discovery (NAMESPACE command)
    // ========================================================================

    ImapNamespaceInfo discover_namespace() {
        ImapNamespaceInfo info;

        if (!caps_.namespace_cmd) {
            // Default: empty prefix, "/" delimiter
            ImapNamespace ns;
            ns.prefix = "";
            ns.delimiter = "/";
            ns.is_personal = true;
            info.personal.push_back(ns);
            namespace_info_ = info;
            return info;
        }

        auto lines = conn_.send_and_read_lines("NAMESPACE", FOLDER_LIST_TIMEOUT_SECS);

        for (const auto& line : lines) {
            if (line.find("* NAMESPACE") == std::string::npos) continue;

            // Parse NAMESPACE response:
            // * NAMESPACE (("" "/")) (("Other Users." ".")) (("#shared." "."))
            // Each namespace: ("prefix" "delimiter")

            size_t pos = line.find("((");
            int ns_type = 0; // 0=personal, 1=other_users, 2=shared

            while (pos != std::string::npos && ns_type < 3) {
                size_t end = line.find("))", pos);
                if (end == std::string::npos) end = line.find(")", pos);

                // Extract all namespaces within this group
                size_t cur = pos + 2; // skip "(("
                while (cur < line.size() && line[cur] != ')') {
                    if (line[cur] == '(') {
                        size_t ns_end = line.find(')', cur);
                        if (ns_end == std::string::npos) break;

                        std::string ns_spec = line.substr(cur + 1, ns_end - cur - 1);
                        auto parts = split_quoted(ns_spec);
                        if (parts.size() >= 2) {
                            ImapNamespace ns;
                            ns.prefix = unquote(parts[0]);
                            ns.delimiter = unquote(parts[1]);
                            ns.is_personal = (ns_type == 0);
                            ns.is_other_users = (ns_type == 1);
                            ns.is_shared = (ns_type == 2);

                            if (ns_type == 0) info.personal.push_back(ns);
                            else if (ns_type == 1) info.other_users.push_back(ns);
                            else info.shared.push_back(ns);
                        }

                        cur = ns_end + 1;
                    } else {
                        cur++;
                    }
                }

                pos = line.find("((", end);
                ns_type++;
            }

            break; // Only process first NAMESPACE line
        }

        // If no personal namespace found, provide default
        if (info.personal.empty()) {
            ImapNamespace ns;
            ns.prefix = "";
            ns.delimiter = "/";
            ns.is_personal = true;
            info.personal.push_back(ns);
        }

        namespace_info_ = info;
        return info;
    }

    const ImapNamespaceInfo& get_namespace_info() const { return namespace_info_; }

    // ========================================================================
    // 19. IMAP capability checking per folder
    // ========================================================================

    // Parse CAPABILITY response
    ImapCapabilities get_capabilities() {
        auto lines = conn_.send_and_read_lines("CAPABILITY", FOLDER_STATUS_TIMEOUT_SECS);
        ImapCapabilities caps;

        for (const auto& line : lines) {
            if (line.find("CAPABILITY") != std::string::npos) {
                caps.parse_from_capability_line(line);
            }
        }

        caps_ = caps;
        return caps;
    }

    const ImapCapabilities& capabilities() const { return caps_; }

    // Check if specific capability is available for a folder
    bool folder_supports_capability(const std::string& folder,
                                     const std::string& capability) {
        // Most capabilities are global, but some depend on folder state
        if (capability == "MOVE") return caps_.move;
        if (capability == "IDLE") return caps_.idle;
        if (capability == "CONDSTORE") return caps_.condstore;
        if (capability == "QRESYNC") return caps_.qresync;
        if (capability == "UIDPLUS") return caps_.uidplus;

        // Folder-specific: check if SELECTed
        if (capability == "READ-WRITE") {
            std::lock_guard lock(folder_cache_mutex_);
            auto it = folder_cache_.find(folder);
            return it != folder_cache_.end() && it->second.is_selected;
        }

        return false;
    }

    // Dump all capabilities
    std::unordered_map<std::string, bool> capabilities_map() const {
        return {
            {"IMAP4rev1", caps_.imap4rev1},
            {"IDLE", caps_.idle},
            {"MOVE", caps_.move},
            {"UIDPLUS", caps_.uidplus},
            {"CONDSTORE", caps_.condstore},
            {"QRESYNC", caps_.qresync},
            {"NAMESPACE", caps_.namespace_cmd},
            {"LIST-EXTENDED", caps_.list_extended},
            {"LIST-STATUS", caps_.list_status},
            {"SPECIAL-USE", caps_.special_use},
            {"UNSELECT", caps_.unselect},
            {"ENABLE", caps_.enable},
            {"COMPRESS=DEFLATE", caps_.compress},
            {"LITERAL+", caps_.literal_plus},
            {"SASL-IR", caps_.sasl_ir},
            {"STARTTLS", caps_.starttls},
            {"AUTH=PLAIN", caps_.auth_plain},
            {"AUTH=LOGIN", caps_.auth_login},
            {"AUTH=XOAUTH2", caps_.auth_oauth},
            {"CHILDREN", caps_.children},
            {"MULTIAPPEND", caps_.multiappend},
            {"SORT", caps_.sort},
            {"THREAD=REFERENCES", caps_.thread},
            {"ESEARCH", caps_.esearch},
            {"METADATA", caps_.metadata},
            {"QUOTA", caps_.quota},
            {"ID", caps_.id},
            {"BINARY", caps_.binary},
            {"WITHIN", caps_.within},
            {"SEARCHRES", caps_.searchres},
        };
    }

    // Enable CONDSTORE/QRESYNC if available
    void enable_extensions() {
        if (caps_.condstore || caps_.qresync) {
            std::string enable_args;
            if (caps_.condstore) enable_args += "CONDSTORE ";
            if (caps_.qresync) enable_args += "QRESYNC";
            if (!enable_args.empty()) {
                conn_.send_command("ENABLE " + enable_args);
            }
        }

        if (caps_.compress) {
            conn_.send_command("COMPRESS DEFLATE");
        }
    }

    // ========================================================================
    // Config management
    // ========================================================================

    void set_config(const Config& cfg) {
        std::lock_guard lock(config_mutex_);
        config_ = cfg;
    }

    Config get_config() const {
        std::lock_guard lock(config_mutex_);
        return config_;
    }

    FolderStatsTracker& stats() { return stats_; }
    const FolderStatsTracker& stats() const { return stats_; }

    // ========================================================================
    // Folder cache management
    // ========================================================================

    void clear_folder_cache() {
        std::lock_guard lock(folder_cache_mutex_);
        folder_cache_.clear();
    }

    void refresh_folder_cache(bool include_subscribed_check = false) {
        auto folders = list_folders_extended("", "*", include_subscribed_check,
                                             false, true, true);

        std::lock_guard lock(folder_cache_mutex_);
        for (const auto& f : folders) {
            ImapFolder folder;
            folder.name = f.name;
            folder.path_delimiter = f.delimiter;
            folder.attributes = f.attributes;

            auto it = folder_cache_.find(f.name);
            if (it != folder_cache_.end()) {
                // Preserve dynamic state
                folder.uid_validity = it->second.uid_validity;
                folder.uid_next = it->second.uid_next;
                folder.is_watched = it->second.is_watched;
                folder.is_selected = it->second.is_selected;
            }

            folder_cache_[f.name] = folder;
        }
    }

    std::vector<ImapFolder> get_cached_folders() const {
        std::lock_guard lock(folder_cache_mutex_);
        std::vector<ImapFolder> result;
        result.reserve(folder_cache_.size());
        for (const auto& [name, folder] : folder_cache_) {
            result.push_back(folder);
        }
        return result;
    }

    std::optional<ImapFolder> get_cached_folder(const std::string& name) const {
        std::lock_guard lock(folder_cache_mutex_);
        auto it = folder_cache_.find(name);
        if (it != folder_cache_.end()) return it->second;
        return std::nullopt;
    }

    // ========================================================================
    // DeltaChat-specific folder operations
    // ========================================================================

    // Move all messages from INBOX to DeltaChat folder (MVBOX pattern)
    int mvbox_move_all(const std::vector<int>& uids) {
        if (!config_.mvbox_move_enabled) return 0;
        if (uids.empty()) return 0;

        auto results = move_messages(uids, watch_config_.inbox_folder,
                                      watch_config_.deltachat_folder);

        int moved = 0;
        for (const auto& r : results) if (r.success) moved++;
        return moved;
    }

    // Check if DeltaChat folder needs watching
    bool should_watch_deltachat() {
        return watch_config_.watch_deltachat &&
               !watch_config_.deltachat_folder.empty();
    }

    // ========================================================================
    // Diagnostics / debug
    // ========================================================================

    struct FolderManagerStats {
        int total_folders = 0;
        int watched_folders = 0;
        int subscribed_folders = 0;
        std::string active_idle_folder;
        bool idle_active = false;
        FolderStatsTracker::PeriodicStats operation_stats;
        ImapCapabilities capabilities;
    };

    FolderManagerStats get_stats() const {
        FolderManagerStats s;

        {
            std::lock_guard lock(folder_cache_mutex_);
            s.total_folders = folder_cache_.size();
            int wat = 0, sub = 0;
            for (const auto& [name, f] : folder_cache_) {
                if (f.is_watched) wat++;
                if (f.is_subscribed) sub++;
            }
            s.watched_folders = wat;
            s.subscribed_folders = sub;
        }

        s.active_idle_folder = idle_watcher_.current_folder();
        s.idle_active = idle_watcher_.is_idle_active();
        s.operation_stats = stats_.get_global_stats();
        s.capabilities = caps_;

        return s;
    }

private:
    // ========== Internal helpers ==========

    // Parse a LIST/LSUB response line
    ListFolderResult parse_list_response(const std::string& line) {
        ListFolderResult result;

        // Format: * LIST (\attr1 \attr2) "/" "folder name"
        // Or:     * LIST (\attr1) "/" folder_name (no quotes)
        // Or:     * LIST (attr1 attr2) "/" "folder name" ("CHILDREN" (...))

        size_t pos = line.find("LIST");
        if (pos == std::string::npos) {
            pos = line.find("LSUB");
        }
        if (pos == std::string::npos) return result;

        pos += 4; // skip "LIST" or "LSUB"

        // Parse attributes in parentheses
        size_t attr_start = line.find('(', pos);
        size_t attr_end = line.find(')', attr_start);
        if (attr_start != std::string::npos && attr_end != std::string::npos) {
            std::string attr_str = line.substr(attr_start + 1, attr_end - attr_start - 1);
            result.attributes = parse_list_attributes(attr_str);
            pos = attr_end + 1;
        }

        // Skip whitespace
        while (pos < line.size() && line[pos] == ' ') pos++;

        // Parse delimiter (may be quoted or NIL)
        if (pos < line.size()) {
            if (line[pos] == '"') {
                size_t delim_end = line.find('"', pos + 1);
                if (delim_end != std::string::npos) {
                    result.delimiter = line.substr(pos + 1, delim_end - pos - 1);
                    pos = delim_end + 1;
                }
            } else if (line.compare(pos, 3, "NIL") == 0) {
                result.delimiter = "";
                pos += 3;
            }
        }

        // Skip whitespace
        while (pos < line.size() && line[pos] == ' ') pos++;

        // Parse folder name (may be quoted or literal)
        if (pos < line.size()) {
            if (line[pos] == '"') {
                size_t name_end = line.find('"', pos + 1);
                if (name_end != std::string::npos) {
                    result.name = line.substr(pos + 1, name_end - pos - 1);
                }
            } else {
                // Unquoted single-word name
                size_t name_end = line.find_first_of(" \r\n\t", pos);
                if (name_end == std::string::npos) name_end = line.size();
                result.name = line.substr(pos, name_end - pos);
            }
        }

        // Determine SPECIAL-USE from attributes
        if (result.attributes & static_cast<uint32_t>(ImapListAttr::SENT))
            result.special_use = "\\Sent";
        else if (result.attributes & static_cast<uint32_t>(ImapListAttr::TRASH))
            result.special_use = "\\Trash";
        else if (result.attributes & static_cast<uint32_t>(ImapListAttr::DRAFTS))
            result.special_use = "\\Drafts";
        else if (result.attributes & static_cast<uint32_t>(ImapListAttr::JUNK))
            result.special_use = "\\Junk";
        else if (result.attributes & static_cast<uint32_t>(ImapListAttr::ARCHIVE))
            result.special_use = "\\Archive";

        // Check for DeltaChat flag
        if (result.attributes & static_cast<uint32_t>(ImapListAttr::CHAT))
            result.special_use = "DeltaChat";

        return result;
    }

    uint32_t parse_list_attributes(const std::string& attr_str) {
        uint32_t attrs = 0;
        std::string lower; lower.reserve(attr_str.size());
        for (char c : attr_str) lower.push_back(static_cast<char>(std::tolower(c)));

        if (lower.find("\\noinferiors") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::NOINFERIORS);
        if (lower.find("\\noselect") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::NOSELECT);
        if (lower.find("\\marked") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::MARKED);
        if (lower.find("\\unmarked") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::UNMARKED);
        if (lower.find("\\haschildren") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::HASCHILDREN);
        if (lower.find("\\hasnochildren") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::HASNOCHILDREN);
        if (lower.find("\\trash") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::TRASH);
        if (lower.find("\\sent") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::SENT);
        if (lower.find("\\drafts") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::DRAFTS);
        if (lower.find("\\junk") != std::string::npos || lower.find("\\spam") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::JUNK);
        if (lower.find("\\archive") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::ARCHIVE);
        if (lower.find("\\all") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::ALL);
        if (lower.find("\\important") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::IMPORTANT);
        if (lower.find("\\flagged") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::FLAGGED);
        if (lower.find("\\inbox") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::INBOX);
        if (lower.find("\\subscribed") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::SUBSCRIBED);
        if (lower.find("\\remote") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::REMOTE);
        if (lower.find("\\chat") != std::string::npos ||
            lower.find("deltachat") != std::string::npos)
            attrs |= static_cast<uint32_t>(ImapListAttr::CHAT);

        return attrs;
    }

    // Parse STATUS response line
    void parse_status_line(const std::string& line, StatusResult& result) {
        // * STATUS "folder" (MESSAGES n RECENT n UIDNEXT n UIDVALIDITY n UNSEEN n ...)
        auto parse_item = [&](const std::string& key) -> int {
            size_t pos = line.find(key);
            if (pos == std::string::npos) return 0;
            pos += key.length();
            while (pos < line.size() && line[pos] == ' ') pos++;
            size_t end = line.find_first_of(" )\r\n", pos);
            if (end == std::string::npos) end = line.size();
            try {
                return std::stoi(line.substr(pos, end - pos));
            } catch (...) {
                return 0;
            }
        };

        result.messages = parse_item("MESSAGES");
        result.recent = parse_item("RECENT");
        result.unseen = parse_item("UNSEEN");
        result.uidnext = parse_item("UIDNEXT");
        result.uidvalidity = parse_item("UIDVALIDITY");

        if (caps_.condstore) {
            size_t modseq_pos = line.find("HIGHESTMODSEQ");
            if (modseq_pos != std::string::npos) {
                modseq_pos += 13; // strlen("HIGHESTMODSEQ")
                while (modseq_pos < line.size() && line[modseq_pos] == ' ') modseq_pos++;
                size_t end = line.find_first_of(" )\r\n", modseq_pos);
                if (end == std::string::npos) end = line.size();
                try {
                    result.highest_modseq = std::stoull(
                        line.substr(modseq_pos, end - modseq_pos));
                } catch (...) {
                    result.highest_modseq = 0;
                }
            }
        }
    }

    // Parse a number immediately before a keyword in a line
    int parse_number_before(const std::string& line, const std::string& keyword) {
        auto pos = line.find(keyword);
        if (pos == std::string::npos) return -1;
        size_t num_end = pos;
        while (num_end > 0 && line[num_end - 1] == ' ') num_end--;
        size_t num_start = num_end;
        while (num_start > 0 && std::isdigit(line[num_start - 1])) num_start--;
        if (num_start < num_end) {
            try {
                return std::stoi(line.substr(num_start, num_end - num_start));
            } catch (...) {
                return -1;
            }
        }
        return -1;
    }

    // Extract value from bracket response: [KEYWORD value]
    int extract_bracket_value(const std::string& line, const std::string& keyword) {
        std::string search = keyword + " ";
        auto pos = line.find(search);
        if (pos == std::string::npos) {
            search = "[" + keyword + " ";
            pos = line.find(search);
            if (pos == std::string::npos) return 0;
            pos += 1; // skip '['
        }
        pos += keyword.length() + 1;
        while (pos < line.size() && line[pos] == ' ') pos++;
        size_t end = line.find_first_of(" ])\r\n", pos);
        if (end == std::string::npos) end = line.size();
        try {
            return std::stoi(line.substr(pos, end - pos));
        } catch (...) {
            return 0;
        }
    }

    // Extract list from bracket response: [KEYWORD (item1 item2)]
    std::vector<std::string> extract_bracket_list(const std::string& line,
                                                    const std::string& keyword) {
        std::vector<std::string> result;
        std::string search = keyword + " (";
        auto pos = line.find(search);
        if (pos == std::string::npos) {
            search = "[" + keyword + " (";
            pos = line.find(search);
        }
        if (pos == std::string::npos) return result;

        size_t start = line.find('(', pos) + 1;
        size_t end = line.find(')', start);
        if (start == std::string::npos || end == std::string::npos) return result;

        std::string items = line.substr(start, end - start);
        std::stringstream ss(items);
        std::string item;
        while (ss >> item) {
            // Strip backslash from flags
            if (!item.empty() && item[0] == '\\') item = item.substr(1);
            result.push_back(item);
        }
        return result;
    }

    // MOVE using MOVE extension
    MoveResult move_message_via_move(int uid, const std::string& source,
                                      const std::string& dest)
    {
        MoveResult result;
        result.source_uid = uid;

        std::string cmd = "UID MOVE " + std::to_string(uid) +
                         " \"" + escape_quoted(dest) + "\"";
        auto response = conn_.send_command(cmd, FOLDER_MOVE_TIMEOUT_SECS);

        result.success = response.find("OK") != std::string::npos;
        result.error = result.success ? "" :
            (response.find("NO") != std::string::npos ? "MOVE rejected" : "MOVE failed");

        // Parse COPYUID response for UIDPLUS
        if (result.success && caps_.uidplus) {
            auto copyuid_pos = response.find("COPYUID");
            if (copyuid_pos != std::string::npos) {
                result.dest_uid_validity = extract_uidvalidity(response, copyuid_pos);
                result.dest_uid = extract_dest_uid(response, copyuid_pos);
            }
        }

        return result;
    }

    // MOVE using COPY + DELETE + EXPUNGE (MOVE extension not available)
    MoveResult move_message_via_copy_delete(int uid, const std::string& source,
                                             const std::string& dest)
    {
        MoveResult result;
        result.source_uid = uid;

        // Step 1: COPY to destination
        auto copy_result = copy_message(uid, source, dest);
        if (!copy_result.success) {
            result.success = false;
            result.error = "COPY failed: " + copy_result.error;
            return result;
        }
        result.dest_uid = copy_result.dest_uid;
        result.dest_uid_validity = copy_result.dest_uid_validity;

        // Step 2: Set \Deleted flag
        auto flag_result = set_flags(uid, source, "\\Deleted", true, true);
        if (!flag_result.success) {
            result.success = false;
            result.error = "Flag as deleted failed: " + flag_result.error;
            return result;
        }

        // Step 3: EXPUNGE
        if (config_.auto_expunge) {
            uid_expunge({uid}, source);
        }

        result.success = true;
        return result;
    }

    // Batch MOVE using MOVE extension
    std::vector<MoveResult> move_messages_batch_move(const std::vector<int>& uids,
                                                      const std::string& source,
                                                      const std::string& dest)
    {
        std::vector<MoveResult> results;

        for (size_t i = 0; i < uids.size(); i += config_.move_batch_size) {
            size_t batch_end = std::min(i + static_cast<size_t>(config_.move_batch_size), uids.size());
            std::string uid_set = build_uid_set(uids, i, batch_end);

            std::string cmd = "UID MOVE " + uid_set +
                             " \"" + escape_quoted(dest) + "\"";
            auto response = conn_.send_command(cmd, FOLDER_MOVE_TIMEOUT_SECS);

            bool success = response.find("OK") != std::string::npos;
            for (size_t j = i; j < batch_end; ++j) {
                MoveResult mr;
                mr.source_uid = uids[j];
                mr.success = success;
                mr.error = success ? "" : "Batch MOVE failed";
                results.push_back(mr);
            }

            if (!success) break;
        }

        return results;
    }

    // Batch MOVE using COPY + DELETE + EXPUNGE
    std::vector<MoveResult> move_messages_batch_copy(const std::vector<int>& uids,
                                                      const std::string& source,
                                                      const std::string& dest)
    {
        std::vector<MoveResult> results;

        // Step 1: Batch COPY
        auto copy_results = copy_messages(uids, source, dest);

        // Step 2: Batch flag as deleted (only for successfully copied UIDs)
        std::vector<int> copied_uids;
        for (size_t i = 0; i < uids.size(); ++i) {
            if (copy_results[i].success) {
                copied_uids.push_back(uids[i]);
                results.push_back(copy_results[i]);
            } else {
                MoveResult mr;
                mr.source_uid = uids[i];
                mr.success = false;
                mr.error = "COPY step failed: " + copy_results[i].error;
                results.push_back(mr);
            }
        }

        if (!copied_uids.empty()) {
            mark_deleted(copied_uids, source);

            if (config_.auto_expunge) {
                uid_expunge(copied_uids, source);
            }
        }

        return results;
    }

    // Build UID set string from vector of UIDs
    std::string build_uid_set(const std::vector<int>& uids, size_t start, size_t end) {
        if (start >= end) return "";
        if (end - start == 1) return std::to_string(uids[start]);

        // Check if UIDs are contiguous
        bool contiguous = true;
        for (size_t i = start + 1; i < end; ++i) {
            if (uids[i] != uids[i-1] + 1) {
                contiguous = false;
                break;
            }
        }

        if (contiguous) {
            return std::to_string(uids[start]) + ":" + std::to_string(uids[end - 1]);
        }

        // Non-contiguous: comma-separated
        std::stringstream ss;
        for (size_t i = start; i < end; ++i) {
            if (i > start) ss << ",";
            ss << uids[i];
        }
        return ss.str();
    }

    // Escape a string for IMAP quoted-string
    std::string escape_quoted(const std::string& s) {
        std::string result;
        result.reserve(s.size() + 2);
        for (char c : s) {
            if (c == '\\' || c == '"') result += '\\';
            result += c;
        }
        return result;
    }

    // Split quoted strings in NAMESPACE response
    std::vector<std::string> split_quoted(const std::string& s) {
        std::vector<std::string> result;
        size_t pos = 0;
        while (pos < s.size()) {
            while (pos < s.size() && s[pos] == ' ') pos++;
            if (pos >= s.size()) break;

            if (s[pos] == '"') {
                size_t end = s.find('"', pos + 1);
                if (end == std::string::npos) {
                    result.push_back(s.substr(pos + 1));
                    break;
                }
                result.push_back(s.substr(pos + 1, end - pos - 1));
                pos = end + 1;
            } else {
                size_t end = s.find(' ', pos);
                if (end == std::string::npos) {
                    result.push_back(s.substr(pos));
                    break;
                }
                result.push_back(s.substr(pos, end - pos));
                pos = end + 1;
            }
        }
        return result;
    }

    // Unquote a string (remove surrounding quotes)
    std::string unquote(const std::string& s) {
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
            return s.substr(1, s.size() - 2);
        }
        return s;
    }

    // Extract UIDVALIDITY from COPYUID response
    std::string extract_uidvalidity(const std::string& response, size_t copyuid_pos) {
        // [COPYUID uidvalidity source-uid-set dest-uid-set]
        size_t pos = copyuid_pos + 7; // skip "COPYUID"
        while (pos < response.size() && response[pos] == ' ') pos++;
        size_t end = response.find(' ', pos);
        if (end == std::string::npos) return "";
        return response.substr(pos, end - pos);
    }

    // Extract destination UID from COPYUID response
    int extract_dest_uid(const std::string& response, size_t copyuid_pos) {
        // [COPYUID uidvalidity source-uid-set dest-uid-set]
        size_t pos = response.find(']', copyuid_pos);
        if (pos == std::string::npos) return 0;

        // Search backwards for the last number before ']'
        while (pos > copyuid_pos && !std::isdigit(response[pos - 1])) pos--;
        if (pos <= copyuid_pos) return 0;

        size_t num_end = pos;
        size_t num_start = pos;
        while (num_start > copyuid_pos && std::isdigit(response[num_start - 1])) num_start--;

        try {
            return std::stoi(response.substr(num_start, num_end - num_start));
        } catch (...) {
            return 0;
        }
    }

    // Get or create a folder in the cache
    ImapFolder& get_or_create_folder_cache(const std::string& name) {
        // Assumes lock is held by caller
        auto it = folder_cache_.find(name);
        if (it != folder_cache_.end()) return it->second;
        ImapFolder f;
        f.name = name;
        f.is_deltachat = (name.find("DeltaChat") != std::string::npos ||
                          name.find("deltachat") != std::string::npos);
        folder_cache_[name] = f;
        return folder_cache_[name];
    }

    // ========== Member variables ==========
    ImapConnection& conn_;
    FolderStatsTracker& stats_;
    IdleWatcher idle_watcher_;

    // Configuration
    mutable std::mutex config_mutex_;
    Config config_;

    // Cached state
    mutable std::mutex folder_cache_mutex_;
    std::unordered_map<std::string, ImapFolder> folder_cache_;

    mutable std::mutex watch_mutex_;
    FolderWatchConfig watch_config_;

    ImapCapabilities caps_;
    ImapNamespaceInfo namespace_info_;
};

// ============================================================================
// Folder Manager factory — creates ImapFolderManager with proper initialization
// ============================================================================
class FolderManagerFactory {
public:
    struct InitParams {
        // ImapConnection must be authenticated before creating folder manager
        ImapConnection* connection = nullptr;
        FolderStatsTracker* stats_tracker = nullptr;

        // Optional initial config
        ImapFolderManager::Config folder_config;
        FolderWatchConfig watch_config_override;

        // Initialization flags
        bool auto_discover_namespace = true;
        bool auto_enable_extensions = true;
        bool auto_warmup = true;
        bool auto_detect_folders = true;
    };

    static std::unique_ptr<ImapFolderManager> create(const InitParams& params) {
        if (!params.connection) return nullptr;

        auto* stats = params.stats_tracker;
        FolderStatsTracker default_stats;
        if (!stats) {
            default_stats = FolderStatsTracker{};
            stats = &default_stats;
        }

        auto mgr = std::make_unique<ImapFolderManager>(*params.connection, *stats);
        mgr->set_config(params.folder_config);

        // Step 1: Discover capabilities
        auto caps = mgr->get_capabilities();

        // Step 2: Enable extensions
        if (params.auto_enable_extensions) {
            mgr->enable_extensions();
        }

        // Step 3: Discover namespace
        if (params.auto_discover_namespace) {
            mgr->discover_namespace();
        }

        // Step 4: Discover folders
        if (params.auto_detect_folders) {
            auto discovery = mgr->discover_folders();
            mgr->apply_discovery(discovery);

            // Ensure DeltaChat folder exists
            if (params.folder_config.auto_create_deltachat) {
                if (discovery.deltachat) {
                    mgr->create_folder(*discovery.deltachat);
                }
            }

            // Subscribe to watched folders
            mgr->subscribe_watched_folders();
        }

        // Apply watch config override
        if (!params.watch_config_override.get_watch_list().empty()) {
            mgr->set_watch_config(params.watch_config_override);
        }

        // Step 5: Warm up (pre-fetch folder status)
        if (params.auto_warmup) {
            mgr->warmup_watched_folders();
        }

        return mgr;
    }
};

// ============================================================================
// Connection-aware folder operations — ensures folder is SELECTed before ops
// ============================================================================
class FolderSessionGuard {
public:
    FolderSessionGuard(ImapFolderManager& mgr, const std::string& folder,
                       bool read_only = true)
        : mgr_(mgr), folder_(folder), read_only_(read_only)
    {
        // Select the folder
        auto result = mgr_.select_folder(folder, read_only);
        if (!result.success) {
            throw std::runtime_error("FolderSessionGuard: failed to select " +
                                     folder + ": " + result.error);
        }
    }

    ~FolderSessionGuard() {
        try {
            mgr_.unselect_folder();
        } catch (...) {
            // Best effort
        }
    }

    // Prevent copying
    FolderSessionGuard(const FolderSessionGuard&) = delete;
    FolderSessionGuard& operator=(const FolderSessionGuard&) = delete;

    const std::string& folder() const { return folder_; }

private:
    ImapFolderManager& mgr_;
    std::string folder_;
    bool read_only_;
};

// ============================================================================
// Folder statistics collector — periodic aggregation for monitoring
// ============================================================================
class FolderStatisticsCollector {
public:
    struct Snapshot {
        uint64_t timestamp;
        std::unordered_map<std::string, FolderStatsTracker::FolderStats> per_folder;
        FolderStatsTracker::PeriodicStats global;
    };

    FolderStatisticsCollector(FolderStatsTracker& tracker, int window_seconds = FOLDER_STATS_WINDOW_SEC)
        : tracker_(tracker), window_seconds_(window_seconds) {}

    Snapshot take_snapshot() {
        Snapshot snap;
        snap.timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
        snap.global = tracker_.get_global_stats();

        // Collect per-folder stats for all known folders
        auto global = snap.global;
        snap.per_folder = per_folder_snapshots_;

        // Store in history
        history_.push_back(snap);
        if (history_.size() > 1000) {
            history_.erase(history_.begin());
        }

        return snap;
    }

    std::vector<Snapshot> get_history() const { return history_; }

    // Alert on unusual activity
    struct Alert {
        std::string folder;
        std::string message;
        uint64_t timestamp;
        enum Severity { INFO, WARNING, ERROR } severity = INFO;
    };

    std::vector<Alert> check_thresholds(const Snapshot& snap) {
        std::vector<Alert> alerts;
        uint64_t now = snap.timestamp;

        // Check for high error rate
        if (snap.global.total_errors > 100) {
            alerts.push_back({"*", "High error rate: " + std::to_string(snap.global.total_errors),
                              now, Alert::ERROR});
        }

        // Check for low performance
        if (snap.global.max_select_ms > 5000) {
            alerts.push_back({"*", "Slow SELECT: " + std::to_string(snap.global.max_select_ms) + "ms",
                              now, Alert::WARNING});
        }

        if (snap.global.max_move_ms > 10000) {
            alerts.push_back({"*", "Slow MOVE operations: " + std::to_string(snap.global.max_move_ms) + "ms",
                              now, Alert::WARNING});
        }

        // Check connections
        if (snap.global.total_reconnects > 10) {
            alerts.push_back({"*", "Frequent reconnects: " + std::to_string(snap.global.total_reconnects),
                              now, Alert::WARNING});
        }

        return alerts;
    }

    void reset() {
        tracker_.reset_window();
        history_.clear();
    }

private:
    FolderStatsTracker& tracker_;
    int window_seconds_;
    std::unordered_map<std::string, FolderStatsTracker::FolderStats> per_folder_snapshots_;
    std::vector<Snapshot> history_;
};

} // namespace deltachat
} // namespace progressive
