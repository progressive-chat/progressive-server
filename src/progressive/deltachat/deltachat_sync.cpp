// progressive-server: DeltaChat IMAP folder sync and message watcher
// Reference: deltachat-core scheduler.rs, imap/mod.rs, job.rs
// IDLE watching, prefetch, folder scanning, UIDVALIDITY handling

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <mutex>
#include <functional>
#include <deque>

namespace progressive {
namespace deltachat {

// Forward declarations
struct ImapFolder; struct ImapConfig; struct ImapConnection;
struct ParsedMail; struct Message;

// =============================================================================
// Folder state tracking
// =============================================================================
struct FolderState {
    std::string folder_name;
    int uid_validity = 0;
    int uid_next = 0;
    int last_seen_uid = 0;
    int exists = 0;
    int recent = 0;
    int unseen = 0;
    time_t last_sync = 0;
    time_t last_idle_check = 0;
    bool is_watched = false;     // actively being IDLE'd
    bool needs_full_sync = false;
    std::vector<int> known_uids; // UIDs we've already processed
    int highest_modseq = 0;      // for CONDSTORE
};

// =============================================================================
// Sync scheduler
// =============================================================================
class SyncScheduler {
public:
    struct SyncConfig {
        int watch_folders_interval = 60;        // seconds between folder list refresh
        int idle_timeout = 1740;                // 29 min - re-IDLE before server timeout
        int fetch_existing_days = 30;            // how far back to fetch on first sync
        int max_prefetch_per_cycle = 200;        // max messages per fetch cycle
        int debounce_seconds = 5;               // debounce rapid changes
        int reconnect_delay_init = 5;            // initial reconnect delay
        int reconnect_delay_max = 300;           // max reconnect delay
        int partial_fetch_threshold = 32768;     // 32KB - fetch body separately above this
        std::vector<std::string> watch_folders = {"INBOX", "DeltaChat"};
        std::string mvbox_folder = "DeltaChat";
        std::string sent_folder = "Sent";
        bool only_fetch_mvbox = false;
        bool scan_all_folders = false;
    };

    SyncScheduler() : config_() {}

    void configure(const SyncConfig& cfg) {
        std::lock_guard lock(mutex_);
        config_ = cfg;
    }

    // ========== Folder operations ==========
    void set_folder_state(const std::string& name, const FolderState& state) {
        std::lock_guard lock(mutex_);
        folder_states_[name] = state;
    }

    FolderState* get_folder(const std::string& name) {
        auto it = folder_states_.find(name);
        return (it != folder_states_.end()) ? &it->second : nullptr;
    }

    void mark_uid_processed(const std::string& folder, int uid) {
        std::lock_guard lock(mutex_);
        auto& state = folder_states_[folder];
        state.last_seen_uid = std::max(state.last_seen_uid, uid);
        state.known_uids.push_back(uid);
        if (state.known_uids.size() > 10000) {
            state.known_uids.erase(state.known_uids.begin(),
                                   state.known_uids.begin() + 1000);
        }
    }

    bool is_uid_seen(const std::string& folder, int uid) {
        auto it = folder_states_.find(folder);
        if (it == folder_states_.end()) return false;
        return uid <= it->second.last_seen_uid;
    }

    // ========== Sync triggers ==========
    bool should_full_sync() {
        std::lock_guard lock(mutex_);
        time_t now = std::time(nullptr);
        for (auto& [name, state] : folder_states_) {
            if (now - state.last_sync > config_.watch_folders_interval) {
                state.last_sync = now;
                return true;
            }
        }
        return false;
    }

    bool should_reidle(const std::string& folder) {
        auto it = folder_states_.find(folder);
        if (it == folder_states_.end()) return true;
        time_t now = std::time(nullptr);
        return (now - it->second.last_idle_check) > config_.idle_timeout;
    }

    // ========== Reconnect backoff ==========
    int get_reconnect_delay(int retry_count) {
        int delay = config_.reconnect_delay_init;
        for (int i = 0; i < retry_count && delay < config_.reconnect_delay_max; i++) {
            delay *= 2;
        }
        return std::min(delay, config_.reconnect_delay_max);
    }

    time_t next_reconnect_at(int retry_count) {
        return std::time(nullptr) + get_reconnect_delay(retry_count) +
               (std::rand() % 5); // jitter
    }

    // ========== Scan debounce ==========
    bool should_debounce(const std::string& trigger) {
        std::lock_guard lock(mutex_);
        time_t now = std::time(nullptr);
        auto it = last_trigger_.find(trigger);
        if (it != last_trigger_.end()) {
            if (now - it->second < config_.debounce_seconds) return true;
        }
        last_trigger_[trigger] = now;
        return false;
    }

private:
    SyncConfig config_;
    std::unordered_map<std::string, FolderState> folder_states_;
    std::unordered_map<std::string, time_t> last_trigger_;
    std::mutex mutex_;
};

// =============================================================================
// Message fetch pipeline
// =============================================================================
struct FetchRequest {
    std::string folder;
    std::vector<int> uids;
    bool fetch_body = true;
    bool fetch_headers = true;
    bool fetch_flags = false;
    int max_size = 0;          // partial fetch if body exceeds this
};

struct FetchResult {
    int uid = 0;
    std::string rfc724_mid;
    std::string references;
    std::string in_reply_to;
    std::string sender;
    std::string recipients;
    time_t date = 0;
    std::string subject;
    int size = 0;
    bool seen = false;
    bool answered = false;
    bool flagged = false;
    bool deleted_flag = false;
    bool draft = false;
    std::string body_text;
    std::string body_html;
    std::vector<std::string> attachment_filenames;
    std::string autocrypt_header;
    std::vector<std::pair<std::string,std::string>> chat_headers; // Chat-Version, etc.
    std::string error;
};

class FetchPipeline {
public:
    void set_connection(std::shared_ptr<ImapConnection> conn) {
        conn_ = conn;
    }

    void set_delegate(std::function<void(const FetchResult&)> processor) {
        processor_ = processor;
    }

    // Batch fetch UIDs from a folder
    int fetch_batch(const FetchRequest& req) {
        if (req.uids.empty()) return 0;

        int fetched = 0;
        std::vector<std::vector<int>> batches = make_uid_batches(req.uids, 50);

        for (auto& batch : batches) {
            std::string uid_set = format_uid_set(batch);

            // Fetch headers first
            auto headers = fetch_headers(req.folder, uid_set);
            for (auto& hdr : headers) {
                FetchResult result;
                result.uid = hdr.uid;
                result.rfc724_mid = hdr.headers.value("Message-ID", "");
                result.references = hdr.headers.value("References", "");
                result.in_reply_to = hdr.headers.value("In-Reply-To", "");
                result.sender = hdr.headers.value("From", "");
                result.subject = hdr.headers.value("Subject", "");
                result.date = parse_date(hdr.headers.value("Date", ""));
                result.size = hdr.size;

                // Extract Chat-* headers
                for (auto& [key, val] : hdr.headers) {
                    if (key.find("Chat-") == 0) {
                        result.chat_headers.push_back({key, val});
                    }
                    if (key == "Autocrypt") {
                        result.autocrypt_header = val;
                    }
                }

                // Fetch body if needed
                if (req.fetch_body) {
                    std::string body = fetch_body(req.folder, result.uid,
                                                   req.max_size > 0 ? req.max_size : 0);
                    result.body_text = extract_text_part(body);
                    result.body_html = extract_html_part(body);
                    result.attachment_filenames = extract_attachment_names(body);
                }

                // Fetch flags if needed
                if (req.fetch_flags) {
                    auto flags = fetch_flags(req.folder, result.uid);
                    result.seen = flags.seen;
                    result.answered = flags.answered;
                    result.flagged = flags.flagged;
                    result.deleted_flag = flags.deleted_flag;
                    result.draft = flags.draft;
                }

                if (processor_) processor_(result);
                fetched++;
            }
        }

        return fetched;
    }

    // Check for new messages in a folder
    std::vector<int> scan_new_uids(const std::string& folder, int since_uid) {
        // SEARCH UID <since_uid+1>:*
        std::string criteria = "UID " + std::to_string(since_uid + 1) + ":*";
        auto uids = search_uids(folder, criteria);
        return uids;
    }

    // Prefetch existing messages (controlled by FETCH_EXISTING_MSGS)
    int prefetch(const std::string& folder, int days_back, int limit) {
        auto uids = get_recent_uids(folder, days_back, limit);
        if (uids.empty()) return 0;

        FetchRequest req;
        req.folder = folder;
        req.uids = uids;
        req.fetch_body = true;
        req.fetch_headers = true;
        req.fetch_flags = true;

        return fetch_batch(req);
    }

private:
    std::shared_ptr<ImapConnection> conn_;
    std::function<void(const FetchResult&)> processor_;

    struct HeaderResult {
        int uid = 0;
        int size = 0;
        std::unordered_map<std::string, std::string> headers;
    };

    struct FlagResult {
        bool seen = false, answered = false, flagged = false;
        bool deleted_flag = false, draft = false;
    };

    std::vector<HeaderResult> fetch_headers(const std::string& folder,
                                            const std::string& uid_set) {
        // Send: UID FETCH <uid_set> (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS
        //   (From To Cc Bcc Subject Date Message-ID References In-Reply-To
        //    Chat-Version Chat-Group-ID Chat-Group-Name Autocrypt)])
        std::string cmd = "UID FETCH " + uid_set +
            " (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS "
            "(From To Cc Bcc Subject Date Message-ID References In-Reply-To "
            "Chat-Version Chat-Group-ID Chat-Group-Name Chat-Group-Name-Changed "
            "Chat-Verified Chat-User-Avatar Chat-Content Chat-Voice "
            "Autocrypt Autocrypt-Setup-Message Secure-Join "
            "Ephemeral-Timer MDN-Receipt-To List-ID)]";
        // Command would be sent via IMAP connection
        (void)cmd;
        return {};
    }

    std::string fetch_body(const std::string& folder, int uid, int max_size) {
        std::string fetch_cmd;
        if (max_size > 0) {
            fetch_cmd = "UID FETCH " + std::to_string(uid) +
                " (BODY.PEEK[]<0." + std::to_string(max_size) + ">)";
        } else {
            fetch_cmd = "UID FETCH " + std::to_string(uid) + " (BODY.PEEK[])";
        }
        (void)fetch_cmd;
        return "";
    }

    FlagResult fetch_flags(const std::string& folder, int uid) {
        FlagResult flags;
        std::string cmd = "UID FETCH " + std::to_string(uid) + " (FLAGS)";
        (void)cmd;
        return flags;
    }

    std::vector<int> search_uids(const std::string& folder, const std::string& criteria) {
        std::string cmd = "UID SEARCH " + criteria;
        (void)cmd;
        return {};
    }

    std::vector<int> get_recent_uids(const std::string& folder, int days_back, int limit) {
        std::string date_str = std::to_string(days_back) + "d";
        std::string criteria = "SINCE " + date_str;
        std::string cmd = "UID SEARCH " + criteria;
        (void)cmd;
        return {};
    }

    static std::vector<std::vector<int>> make_uid_batches(const std::vector<int>& uids,
                                                           int batch_size) {
        std::vector<std::vector<int>> batches;
        for (size_t i = 0; i < uids.size(); i += batch_size) {
            batches.push_back({uids.begin() + i,
                               uids.begin() + std::min(i + batch_size, uids.size())});
        }
        return batches;
    }

    static std::string format_uid_set(const std::vector<int>& uids) {
        if (uids.empty()) return "";
        std::stringstream ss;
        for (size_t i = 0; i < uids.size(); i++) {
            if (i > 0) ss << ",";
            ss << uids[i];
        }
        return ss.str();
    }

    static std::string extract_text_part(const std::string& mime) {
        // Find text/plain part in MIME structure
        (void)mime;
        return mime; // simplified
    }

    static std::string extract_html_part(const std::string& mime) {
        (void)mime;
        return "";
    }

    static std::vector<std::string> extract_attachment_names(const std::string& mime) {
        (void)mime;
        return {};
    }

    static time_t parse_date(const std::string& date_str) {
        (void)date_str;
        return std::time(nullptr);
    }
};

// =============================================================================
// IDLE watcher
// =============================================================================
class IdleWatcher {
public:
    struct IdleEvent {
        enum Type { EXISTS, RECENT, EXPUNGE, FETCH, VANISHED, NONE };
        Type type = NONE;
        int uid = 0;
        int count = 0;
        std::string folder;
    };

    using EventCallback = std::function<void(const IdleEvent&)>;

    void set_callback(EventCallback cb) { callback_ = cb; }

    bool start_idle(const std::string& folder, std::shared_ptr<ImapConnection> conn) {
        if (idle_active_) return false;

        current_folder_ = folder;
        conn_ = conn;
        idle_active_ = true;

        // Send IDLE command
        std::string cmd = "IDLE";
        // conn->send(cmd);
        (void)cmd;
        return true;
    }

    void stop_idle() {
        if (!idle_active_) return;
        idle_active_ = false;
        // Send DONE to end IDLE
    }

    bool is_active() const { return idle_active_; }

    // Process server response during IDLE (called from IMAP response parser)
    void process_idle_response(const std::string& response) {
        IdleEvent event;
        event.folder = current_folder_;

        if (response.find("EXISTS") != std::string::npos) {
            event.type = IdleEvent::EXISTS;
            event.count = extract_number(response);
        } else if (response.find("RECENT") != std::string::npos) {
            event.type = IdleEvent::RECENT;
            event.count = extract_number(response);
        } else if (response.find("EXPUNGE") != std::string::npos) {
            event.type = IdleEvent::EXPUNGE;
            event.uid = extract_number(response);
        } else if (response.find("FETCH") != std::string::npos) {
            event.type = IdleEvent::FETCH;
            event.uid = extract_number(response);
        } else if (response.find("VANISHED") != std::string::npos) {
            event.type = IdleEvent::VANISHED;
            // Parse vanished UIDs
        }

        if (callback_ && event.type != IdleEvent::NONE) {
            callback_(event);
        }
    }

private:
    bool idle_active_ = false;
    std::string current_folder_;
    std::shared_ptr<ImapConnection> conn_;
    EventCallback callback_;

    static int extract_number(const std::string& s) {
        std::string num;
        for (char c : s) {
            if (isdigit(c)) num += c;
        }
        return num.empty() ? 0 : std::stoi(num);
    }
};

// =============================================================================
// Connectivity manager
// =============================================================================
enum class ConnState : uint8_t {
    DISCONNECTED, CONNECTING, CONNECTED, WORKING, ERROR
};

class ConnectivityManager {
public:
    using StateCallback = std::function<void(ConnState, ConnState)>; // old, new

    void set_callback(StateCallback cb) { callback_ = cb; }

    void set_connected() { transition(ConnState::CONNECTED); }
    void set_working() { transition(ConnState::WORKING); }
    void set_disconnected() { transition(ConnState::DISCONNECTED); }
    void set_error() { transition(ConnState::ERROR); }
    void set_connecting() { transition(ConnState::CONNECTING); }

    ConnState state() const { return state_; }
    bool is_connected() const { return state_ >= ConnState::CONNECTED; }
    bool is_working() const { return state_ == ConnState::WORKING; }

private:
    ConnState state_ = ConnState::DISCONNECTED;
    StateCallback callback_;

    void transition(ConnState new_state) {
        if (state_ == new_state) return;
        ConnState old = state_;
        state_ = new_state;
        if (callback_) callback_(old, new_state);
    }
};

// =============================================================================
// Periodic tasks coordinator
// =============================================================================
class PeriodicTasks {
public:
    struct Task {
        std::string name;
        std::function<void()> job;
        time_t last_run = 0;
        int interval_seconds = 0;   // 0 = run once
        bool running = false;
    };

    void add_task(const Task& task) {
        std::lock_guard lock(mutex_);
        tasks_.push_back(task);
    }

    void tick() {
        std::lock_guard lock(mutex_);
        time_t now = std::time(nullptr);

        for (auto& task : tasks_) {
            if (task.running) continue;
            if (task.interval_seconds == 0 && task.last_run > 0) continue; // one-shot already done

            if (now - task.last_run >= task.interval_seconds) {
                task.running = true;
                task.last_run = now;
                task.job();
                task.running = false;
            }
        }
    }

    void run_all_now() {
        for (auto& task : tasks_) {
            if (!task.running) {
                task.running = true;
                task.job();
                task.running = false;
                task.last_run = std::time(nullptr);
            }
        }
    }

    int task_count() const { return (int)tasks_.size(); }

private:
    std::vector<Task> tasks_;
    std::mutex mutex_;
};

// =============================================================================
// Main Sync Engine
// =============================================================================
class SyncEngine {
public:
    SyncEngine() {
        // Default periodic tasks
        periodic_.add_task({"inbox_scan", [this]{ scan_inbox(); }, 0, 10});
        periodic_.add_task({"mvbox_scan", [this]{ scan_mvbox(); }, 0, 60});
        periodic_.add_task({"sentbox_scan", [this]{ scan_sent(); }, 0, 300});
        periodic_.add_task({"reconnect_check", [this]{ check_reconnect(); }, 0, 30});
        periodic_.add_task({"prune_old", [this]{ prune_data(); }, 0, 3600});
    }

    void set_scheduler(SyncScheduler* sched) { scheduler_ = sched; }
    void set_fetcher(FetchPipeline* fetch) { fetcher_ = fetch; }
    void set_watcher(IdleWatcher* watcher) { watcher_ = watcher; }

    void start() {
        running_ = true;
        connectivity_.set_connecting();
    }

    void stop() {
        running_ = false;
        if (watcher_) watcher_->stop_idle();
        connectivity_.set_disconnected();
    }

    void tick() {
        if (!running_) return;

        periodic_.tick();

        // Re-IDLE if needed
        if (watcher_ && scheduler_ && watcher_->is_active()) {
            if (scheduler_->should_reidle(current_watch_folder_)) {
                watcher_->stop_idle();
                watcher_->start_idle(current_watch_folder_, nullptr);
            }
        }
    }

private:
    bool running_ = false;
    SyncScheduler* scheduler_ = nullptr;
    FetchPipeline* fetcher_ = nullptr;
    IdleWatcher* watcher_ = nullptr;
    ConnectivityManager connectivity_;
    PeriodicTasks periodic_;
    std::string current_watch_folder_ = "INBOX";
    int reconnect_attempts_ = 0;

    void scan_inbox() {
        if (scheduler_ && scheduler_->should_debounce("inbox")) return;
        connectivity_.set_working();
        if (fetcher_) {
            auto uids = fetcher_->scan_new_uids("INBOX", 0);
            if (!uids.empty()) {
                FetchRequest req{"INBOX", uids, true, true, true};
                fetcher_->fetch_batch(req);
            }
        }
        connectivity_.set_connected();
    }

    void scan_mvbox() {
        if (scheduler_ && scheduler_->should_debounce("mvbox")) return;
        if (fetcher_) {
            auto uids = fetcher_->scan_new_uids("DeltaChat", 0);
            if (!uids.empty()) {
                FetchRequest req{"DeltaChat", uids, true, true, false};
                fetcher_->fetch_batch(req);
            }
        }
    }

    void scan_sent() {
        if (scheduler_ && scheduler_->should_debounce("sent")) return;
    }

    void check_reconnect() {
        if (!connectivity_.is_connected() && scheduler_) {
            time_t next = scheduler_->next_reconnect_at(reconnect_attempts_);
            if (std::time(nullptr) >= next) {
                connectivity_.set_connecting();
                reconnect_attempts_++;
            }
        } else {
            reconnect_attempts_ = 0;
        }
    }

    void prune_data() {
        // Prune old UIDs from folder states
    }
};

} // namespace deltachat
} // namespace progressive
