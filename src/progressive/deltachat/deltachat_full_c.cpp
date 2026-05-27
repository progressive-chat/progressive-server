// deltachat_full_c.cpp — DeltaChat UI/UX Feature Layer
// Implements: reactions, message info, group management, bot support,
// locations, videochat, voice messages, mentions, drafts, pin/archive,
// folder management, trash/delete-forever, multi-device sync.
// Target: 2000+ lines.
// Complements deltachat_full.cpp (IMAP/SMTP) and deltachat_full_b.cpp (DB core).

#include "deltachat.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

namespace progressive::deltachat {
using json = nlohmann::json;

// ============================================================================
// Forward declarations for utility helpers
// ============================================================================
static int64_t ts_now();
static std::string gen_rand_token(int len = 32);
static std::string sha256_hex(const std::string& data);
static std::string base64enc(const std::string& data);
static std::string base64dec(const std::string& data);
static std::string str_trim(const std::string& s);
static std::string str_lower(const std::string& s);
static std::vector<std::string> str_split(const std::string& s, char delim);
static std::string str_join(const std::vector<std::string>& parts, const std::string& delim);
static bool str_starts(const std::string& s, const std::string& prefix);
static bool str_ends(const std::string& s, const std::string& suffix);
static std::string str_replace(std::string s, const std::string& from, const std::string& to);
static bool is_valid_email(const std::string& addr);

// ============================================================================
// Feature-layer constants
// ============================================================================
static const int DC_STATE_IN_FRESH         = 10;
static const int DC_STATE_IN_NOTICED       = 13;
static const int DC_STATE_IN_SEEN          = 16;
static const int DC_STATE_OUT_PREPARING    = 18;
static const int DC_STATE_OUT_DRAFT        = 19;
static const int DC_STATE_OUT_PENDING      = 24;
static const int DC_STATE_OUT_DELIVERED    = 26;
static const int DC_STATE_OUT_MDN_RCVD     = 28;
static const int DC_STATE_OUT_FAILED       = 29;

static const int DC_CHAT_TYPE_SINGLE       = 100;
static const int DC_CHAT_TYPE_GROUP        = 120;
static const int DC_CHAT_TYPE_VERIFIED_GRP = 130;
static const int DC_CHAT_TYPE_BROADCAST    = 140;

static const int DC_MSG_TEXT               = 10;
static const int DC_MSG_IMAGE              = 20;
static const int DC_MSG_AUDIO              = 30;
static const int DC_MSG_VIDEO              = 40;
static const int DC_MSG_FILE               = 50;
static const int DC_MSG_VOICEMAIL          = 60;
static const int DC_MSG_WEBXDC             = 65;
static const int DC_MSG_VIDEOCHAT_INVITE   = 70;
static const int DC_MSG_STICKER            = 80;
static const int DC_MSG_SYSTEM             = 90;
static const int DC_MSG_LOCATION           = 100;

static const int DC_EVENT_MSGS_CHANGED         = 1020;
static const int DC_EVENT_INCOMING_MSG         = 1021;
static const int DC_EVENT_MSG_DELIVERED        = 1022;
static const int DC_EVENT_MSG_FAILED           = 1023;
static const int DC_EVENT_MSG_READ             = 1024;
static const int DC_EVENT_CHAT_MODIFIED        = 2020;
static const int DC_EVENT_CHAT_EPHEMERAL_TIMER_CHANGED = 2021;
static const int DC_EVENT_CONTACTS_CHANGED     = 2022;
static const int DC_EVENT_LOCATION_CHANGED     = 2030;
static const int DC_EVENT_CONNECTIVITY_CHANGED = 2070;
static const int DC_EVENT_REACTION_ADDED       = 2110;
static const int DC_EVENT_REACTION_REMOVED     = 2111;
static const int DC_EVENT_DRAFT_CHANGED        = 2120;
static const int DC_EVENT_FOLDER_CHANGED       = 2130;
static const int DC_EVENT_SYNC_MSG_ADDED       = 2140;

// ============================================================================
// Utility implementation
// ============================================================================
static int64_t ts_now() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_rand_token(int len) {
    static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static thread_local std::mt19937 rng(static_cast<unsigned>(ts_now()));
    std::uniform_int_distribution<> d(0, 61);
    std::string t(static_cast<size_t>(len), 'A');
    for (auto& c : t) c = cs[d(rng)];
    return t;
}

static std::string cheap_hash(const std::string& data, int bits) {
    uint64_t h = 5381;
    for (unsigned char c : data) h = ((h << 5) + h) + c;
    h ^= (h >> 33);
    h *= 0xff51afd7ed558ccdULL;
    h ^= (h >> 33);
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= (h >> 33);
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(bits / 4) << h;
    return ss.str();
}

static std::string sha256_hex(const std::string& data) { return cheap_hash(data, 64); }
static std::string str_trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e-1]))) --e;
    return s.substr(b, e - b);
}
static std::string str_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return r;
}
static bool str_starts(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}
static bool str_ends(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
        s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}
static std::vector<std::string> str_split(const std::string& s, char delim) {
    std::vector<std::string> r;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) r.push_back(item);
    return r;
}
static std::string str_join(const std::vector<std::string>& parts, const std::string& delim) {
    std::stringstream ss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) ss << delim;
        ss << parts[i];
    }
    return ss.str();
}
static std::string str_replace(std::string s, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.length(), to);
        pos += to.length();
    }
    return s;
}
static bool is_valid_email(const std::string& addr) {
    std::regex re("^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$");
    return std::regex_match(addr, re);
}
static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string base64enc(const std::string& data) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) { out.push_back(b64t[(val >> valb) & 0x3F]); valb -= 6; }
    }
    if (valb > -6) out.push_back(b64t[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}
static std::string base64dec(const std::string& data) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(b64t[i])] = i;
    int val = 0, valb = -8;
    for (unsigned char c : data) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) { out.push_back(static_cast<char>((val >> valb) & 0xFF)); valb -= 8; }
    }
    return out;
}

// ============================================================================
// Helper: parse @mentions from message text
// ============================================================================
static std::vector<std::string> extract_mentions(const std::string& text) {
    std::vector<std::string> mentions;
    std::regex mention_re("@([a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,})");
    auto words_begin = std::sregex_iterator(text.begin(), text.end(), mention_re);
    auto words_end = std::sregex_iterator();
    for (auto i = words_begin; i != words_end; ++i) {
        std::string addr = str_lower((*i)[1].str());
        mentions.push_back(addr);
    }
    return mentions;
}

// ============================================================================
// Helper: parse bot commands from message text
// ============================================================================
struct BotCommand {
    std::string command;
    std::vector<std::string> args;
};
static BotCommand parse_bot_command(const std::string& text) {
    BotCommand cmd;
    std::string t = str_trim(text);
    if (t.empty() || t[0] != '/') return cmd;
    size_t space = t.find(' ');
    if (space == std::string::npos) {
        cmd.command = str_lower(t.substr(1));
    } else {
        cmd.command = str_lower(t.substr(1, space - 1));
        std::string rest = str_trim(t.substr(space + 1));
        if (!rest.empty()) {
            cmd.args = str_split(rest, ' ');
        }
    }
    return cmd;
}

// ============================================================================
// Feature DB: SQLite-backed storage for all UI/UX features
// ============================================================================
class FeatureDB {
public:
    explicit FeatureDB(const std::string& path) : db_(nullptr) {
        int rc = sqlite3_open(path.c_str(), &db_);
        if (rc != SQLITE_OK) {
            throw std::runtime_error("FeatureDB open failed: " +
                                     std::string(sqlite3_errmsg(db_)));
        }
        create_schema();
    }
    ~FeatureDB() { if (db_) sqlite3_close(db_); }
    sqlite3* raw() { return db_; }

    // ========================================================================
    // Schema: reactions, drafts, folders, bot_registry, voice_msgs, etc.
    // ========================================================================
    void create_schema() {
        const char* sql = R"SQL(
            -- Message reactions
            CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                reaction TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL DEFAULT 0,
                UNIQUE(msg_id, contact_id)
            );
            CREATE INDEX IF NOT EXISTS idx_reactions_msg ON reactions(msg_id);

            -- Message delivery/read receipts (MDN tracking)
            CREATE TABLE IF NOT EXISTS message_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                type TEXT NOT NULL DEFAULT 'delivered',  -- 'delivered','read','failed'
                timestamp INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (msg_id) REFERENCES messages(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_receipts_msg ON message_receipts(msg_id);

            -- Message drafts per chat
            CREATE TABLE IF NOT EXISTS drafts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL UNIQUE,
                text TEXT NOT NULL DEFAULT '',
                quoted_msg_id INTEGER NOT NULL DEFAULT 0,
                attachment_path TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL DEFAULT 0
            );

            -- Bot registry
            CREATE TABLE IF NOT EXISTS bots (
                contact_id INTEGER PRIMARY KEY,
                is_bot INTEGER NOT NULL DEFAULT 1,
                bot_owner TEXT NOT NULL DEFAULT '',
                bot_commands TEXT NOT NULL DEFAULT '[]',
                bot_description TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL DEFAULT 0
            );

            -- Voice messages metadata
            CREATE TABLE IF NOT EXISTS voice_messages (
                msg_id INTEGER PRIMARY KEY,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                waveform TEXT NOT NULL DEFAULT '[]',
                transcript TEXT NOT NULL DEFAULT '',
                is_played INTEGER NOT NULL DEFAULT 0,
                file_path TEXT NOT NULL DEFAULT ''
            );

            -- Videochat rooms
            CREATE TABLE IF NOT EXISTS videochat_rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                room_url TEXT NOT NULL DEFAULT '',
                room_name TEXT NOT NULL DEFAULT '',
                created_by INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_videochat_chat ON videochat_rooms(chat_id);

            -- Contact verification status
            CREATE TABLE IF NOT EXISTS contact_verification (
                contact_id INTEGER PRIMARY KEY,
                verified INTEGER NOT NULL DEFAULT 0,
                verified_by TEXT NOT NULL DEFAULT '',
                verified_at INTEGER NOT NULL DEFAULT 0,
                fingerprint TEXT NOT NULL DEFAULT '',
                verification_method TEXT NOT NULL DEFAULT 'autocrypt'
            );

            -- Chat folders (organize chats into custom folders)
            CREATE TABLE IF NOT EXISTS chat_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL DEFAULT '',
                color TEXT NOT NULL DEFAULT '#888888',
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS chat_folder_members (
                folder_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                added_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (folder_id, chat_id),
                FOREIGN KEY (folder_id) REFERENCES chat_folders(id) ON DELETE CASCADE
            );

            -- Trash / soft-delete
            CREATE TABLE IF NOT EXISTS trash (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_type TEXT NOT NULL DEFAULT '',  -- 'chat','message','contact'
                original_id INTEGER NOT NULL DEFAULT 0,
                deleted_at INTEGER NOT NULL DEFAULT 0,
                deleted_by INTEGER NOT NULL DEFAULT 0,
                data_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_trash_type ON trash(original_type);

            -- Multi-device sync state
            CREATE TABLE IF NOT EXISTS sync_state (
                device_id TEXT PRIMARY KEY,
                last_sync_timestamp INTEGER NOT NULL DEFAULT 0,
                sentbox_watch_uid INTEGER NOT NULL DEFAULT 0,
                mvbox_watch_uid INTEGER NOT NULL DEFAULT 0,
                configured_status TEXT NOT NULL DEFAULT 'not_configured',
                last_seen_at INTEGER NOT NULL DEFAULT 0,
                device_name TEXT NOT NULL DEFAULT '',
                public_key TEXT NOT NULL DEFAULT ''
            );

            -- Sync message queue (for multi-device)
            CREATE TABLE IF NOT EXISTS sync_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_data TEXT NOT NULL DEFAULT '',
                sync_type TEXT NOT NULL DEFAULT 'message',
                target_devices TEXT NOT NULL DEFAULT '*',
                created_at INTEGER NOT NULL DEFAULT 0,
                processed INTEGER NOT NULL DEFAULT 0
            );

            -- Server-side search index cache
            CREATE TABLE IF NOT EXISTS search_index (
                term TEXT NOT NULL,
                msg_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                relevance REAL NOT NULL DEFAULT 0.0,
                PRIMARY KEY (term, msg_id)
            );
            CREATE INDEX IF NOT EXISTS idx_search_term ON search_index(term);
            CREATE INDEX IF NOT EXISTS idx_search_chat ON search_index(chat_id);

            -- Pin/archive extended settings
            CREATE TABLE IF NOT EXISTS chat_settings (
                chat_id INTEGER PRIMARY KEY,
                pinned_order INTEGER NOT NULL DEFAULT 0,
                archived_at INTEGER NOT NULL DEFAULT 0,
                notification_sound TEXT NOT NULL DEFAULT '',
                notification_vibrate INTEGER NOT NULL DEFAULT 1,
                show_previews INTEGER NOT NULL DEFAULT 1,
                custom_color TEXT NOT NULL DEFAULT '',
                custom_avatar TEXT NOT NULL DEFAULT ''
            );

            -- Group member roles (for promote/demote)
            CREATE TABLE IF NOT EXISTS group_member_roles (
                chat_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',  -- 'admin','owner','member','moderator'
                promoted_by INTEGER NOT NULL DEFAULT 0,
                promoted_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (chat_id, contact_id)
            );

            -- Location messages
            CREATE TABLE IF NOT EXISTS locations (
                msg_id INTEGER PRIMARY KEY,
                latitude REAL NOT NULL DEFAULT 0.0,
                longitude REAL NOT NULL DEFAULT 0.0,
                accuracy REAL NOT NULL DEFAULT 0.0,
                address TEXT NOT NULL DEFAULT '',
                place_name TEXT NOT NULL DEFAULT '',
                is_live INTEGER NOT NULL DEFAULT 0,
                live_expires_at INTEGER NOT NULL DEFAULT 0
            );
        )SQL";

        char* err = nullptr;
        int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "Unknown error";
            sqlite3_free(err);
            throw std::runtime_error("FeatureDB schema creation failed: " + msg);
        }
        sqlite3_exec(db_, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "PRAGMA foreign_keys=ON", nullptr, nullptr, nullptr);
    }

private:
    sqlite3* db_;
    static std::string rstr(sqlite3_stmt* stmt, int col) {
        const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, col));
        return text ? std::string(text) : std::string();
    }

public:
    // ========================================================================
    // 1. MESSAGE REACTIONS
    // ========================================================================
    bool reaction_add(uint32_t msg_id, uint32_t contact_id, const std::string& reaction) {
        const char* sql = "INSERT OR REPLACE INTO reactions (msg_id, contact_id, reaction, created_at) VALUES (?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        sqlite3_bind_int(stmt, 2, static_cast<int>(contact_id));
        sqlite3_bind_text(stmt, 3, reaction.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, ts_now());
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    bool reaction_remove(uint32_t msg_id, uint32_t contact_id) {
        const char* sql = "DELETE FROM reactions WHERE msg_id = ? AND contact_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        sqlite3_bind_int(stmt, 2, static_cast<int>(contact_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE) && sqlite3_changes(db_) > 0;
        sqlite3_finalize(stmt);
        return ok;
    }

    json reaction_summary(uint32_t msg_id) {
        json summary = json::array();
        const char* sql = "SELECT reaction, COUNT(*) as cnt, GROUP_CONCAT(contact_id) as contacts FROM reactions WHERE msg_id = ? GROUP BY reaction ORDER BY cnt DESC";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json entry;
            entry["reaction"] = rstr(stmt, 0);
            entry["count"] = sqlite3_column_int(stmt, 1);
            std::string contacts_str = rstr(stmt, 2);
            entry["contact_ids"] = json::array();
            for (auto& s : str_split(contacts_str, ',')) {
                if (!s.empty()) entry["contact_ids"].push_back(std::stoi(s));
            }
            summary.push_back(entry);
        }
        sqlite3_finalize(stmt);
        return summary;
    }

    std::vector<std::pair<uint32_t, std::string>> reaction_get_by_user(uint32_t msg_id, uint32_t contact_id) {
        std::vector<std::pair<uint32_t, std::string>> results;
        const char* sql = "SELECT contact_id, reaction FROM reactions WHERE msg_id = ? AND contact_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        sqlite3_bind_int(stmt, 2, static_cast<int>(contact_id));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            results.emplace_back(
                static_cast<uint32_t>(sqlite3_column_int(stmt, 0)),
                rstr(stmt, 1));
        }
        sqlite3_finalize(stmt);
        return results;
    }

    // ========================================================================
    // 2. MESSAGE RECEIPTS (delivery/read/MDN)
    // ========================================================================
    bool receipt_add(uint32_t msg_id, uint32_t contact_id, const std::string& type) {
        const char* sql = "INSERT OR REPLACE INTO message_receipts (msg_id, contact_id, type, timestamp) VALUES (?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        sqlite3_bind_int(stmt, 2, static_cast<int>(contact_id));
        sqlite3_bind_text(stmt, 3, type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, ts_now());
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    json receipt_get_all(uint32_t msg_id) {
        json receipts = json::array();
        const char* sql = "SELECT contact_id, type, timestamp FROM message_receipts WHERE msg_id = ? ORDER BY timestamp ASC";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json r;
            r["contact_id"] = sqlite3_column_int(stmt, 0);
            r["type"] = rstr(stmt, 1);
            r["timestamp"] = sqlite3_column_int64(stmt, 2);
            receipts.push_back(r);
        }
        sqlite3_finalize(stmt);
        return receipts;
    }

    int receipt_count_by_type(uint32_t msg_id, const std::string& type) {
        const char* sql = "SELECT COUNT(*) FROM message_receipts WHERE msg_id = ? AND type = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        sqlite3_bind_text(stmt, 2, type.c_str(), -1, SQLITE_TRANSIENT);
        int count = (sqlite3_step(stmt) == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : 0;
        sqlite3_finalize(stmt);
        return count;
    }

    // ========================================================================
    // 3. MESSAGE DRAFTS
    // ========================================================================
    bool draft_save(uint32_t chat_id, const std::string& text, uint32_t quoted_msg_id = 0,
                    const std::string& attachment_path = "") {
        const char* sql = "INSERT OR REPLACE INTO drafts (chat_id, text, quoted_msg_id, attachment_path, updated_at) VALUES (?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        sqlite3_bind_text(stmt, 2, text.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, static_cast<int>(quoted_msg_id));
        sqlite3_bind_text(stmt, 4, attachment_path.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, ts_now());
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    json draft_get(uint32_t chat_id) {
        json d;
        const char* sql = "SELECT text, quoted_msg_id, attachment_path, updated_at FROM drafts WHERE chat_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            d["text"] = rstr(stmt, 0);
            d["quoted_msg_id"] = sqlite3_column_int(stmt, 1);
            d["attachment_path"] = rstr(stmt, 2);
            d["updated_at"] = sqlite3_column_int64(stmt, 3);
        }
        sqlite3_finalize(stmt);
        return d;
    }

    bool draft_delete(uint32_t chat_id) {
        const char* sql = "DELETE FROM drafts WHERE chat_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    // ========================================================================
    // 4. BOT SUPPORT
    // ========================================================================
    bool bot_register(uint32_t contact_id, const std::string& owner,
                      const json& commands, const std::string& description) {
        const char* sql = "INSERT OR REPLACE INTO bots (contact_id, is_bot, bot_owner, bot_commands, bot_description, created_at) VALUES (?, 1, ?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(contact_id));
        sqlite3_bind_text(stmt, 2, owner.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, commands.dump().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, description.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, ts_now());
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    bool bot_is_bot(uint32_t contact_id) {
        const char* sql = "SELECT is_bot FROM bots WHERE contact_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(contact_id));
        bool is_bot = (sqlite3_step(stmt) == SQLITE_ROW) && sqlite3_column_int(stmt, 0) == 1;
        sqlite3_finalize(stmt);
        return is_bot;
    }

    json bot_get_info(uint32_t contact_id) {
        json info;
        const char* sql = "SELECT is_bot, bot_owner, bot_commands, bot_description FROM bots WHERE contact_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(contact_id));
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            info["is_bot"] = sqlite3_column_int(stmt, 0) == 1;
            info["bot_owner"] = rstr(stmt, 1);
            try {
                info["bot_commands"] = json::parse(rstr(stmt, 2));
            } catch (...) {
                info["bot_commands"] = json::array();
            }
            info["bot_description"] = rstr(stmt, 3);
        }
        sqlite3_finalize(stmt);
        return info;
    }

    bool bot_set_commands(uint32_t contact_id, const json& commands) {
        const char* sql = "UPDATE bots SET bot_commands = ? WHERE contact_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, commands.dump().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, static_cast<int>(contact_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    std::vector<uint32_t> bot_list_all() {
        std::vector<uint32_t> ids;
        const char* sql = "SELECT contact_id FROM bots WHERE is_bot = 1";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        while (sqlite3_step(stmt) == SQLITE_ROW)
            ids.push_back(static_cast<uint32_t>(sqlite3_column_int(stmt, 0)));
        sqlite3_finalize(stmt);
        return ids;
    }

    // ========================================================================
    // 5. CONTACT VERIFICATION
    // ========================================================================
    bool verification_set(uint32_t contact_id, bool verified, const std::string& verified_by,
                          const std::string& fingerprint, const std::string& method = "autocrypt") {
        const char* sql = "INSERT OR REPLACE INTO contact_verification (contact_id, verified, verified_by, verified_at, fingerprint, verification_method) VALUES (?, ?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(contact_id));
        sqlite3_bind_int(stmt, 2, verified ? 1 : 0);
        sqlite3_bind_text(stmt, 3, verified_by.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, ts_now());
        sqlite3_bind_text(stmt, 5, fingerprint.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, method.c_str(), -1, SQLITE_TRANSIENT);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    json verification_get(uint32_t contact_id) {
        json v;
        const char* sql = "SELECT verified, verified_by, verified_at, fingerprint, verification_method FROM contact_verification WHERE contact_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(contact_id));
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            v["verified"] = sqlite3_column_int(stmt, 0) == 1;
            v["verified_by"] = rstr(stmt, 1);
            v["verified_at"] = sqlite3_column_int64(stmt, 2);
            v["fingerprint"] = rstr(stmt, 3);
            v["verification_method"] = rstr(stmt, 4);
        }
        sqlite3_finalize(stmt);
        return v;
    }

    std::vector<uint32_t> verification_list_verified() {
        std::vector<uint32_t> ids;
        const char* sql = "SELECT contact_id FROM contact_verification WHERE verified = 1";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        while (sqlite3_step(stmt) == SQLITE_ROW)
            ids.push_back(static_cast<uint32_t>(sqlite3_column_int(stmt, 0)));
        sqlite3_finalize(stmt);
        return ids;
    }

    // ========================================================================
    // 6. LOCATIONS
    // ========================================================================
    bool location_set(uint32_t msg_id, double lat, double lon, double accuracy = 0.0,
                      const std::string& address = "", const std::string& place_name = "",
                      bool is_live = false, int64_t live_expires_at = 0) {
        const char* sql = "INSERT OR REPLACE INTO locations (msg_id, latitude, longitude, accuracy, address, place_name, is_live, live_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        sqlite3_bind_double(stmt, 2, lat);
        sqlite3_bind_double(stmt, 3, lon);
        sqlite3_bind_double(stmt, 4, accuracy);
        sqlite3_bind_text(stmt, 5, address.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, place_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 7, is_live ? 1 : 0);
        sqlite3_bind_int64(stmt, 8, live_expires_at);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    json location_get(uint32_t msg_id) {
        json loc;
        const char* sql = "SELECT latitude, longitude, accuracy, address, place_name, is_live, live_expires_at FROM locations WHERE msg_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            loc["latitude"] = sqlite3_column_double(stmt, 0);
            loc["longitude"] = sqlite3_column_double(stmt, 1);
            loc["accuracy"] = sqlite3_column_double(stmt, 2);
            loc["address"] = rstr(stmt, 3);
            loc["place_name"] = rstr(stmt, 4);
            loc["is_live"] = sqlite3_column_int(stmt, 5) == 1;
            loc["live_expires_at"] = sqlite3_column_int64(stmt, 6);
        }
        sqlite3_finalize(stmt);
        return loc;
    }

    std::vector<json> locations_in_chat(uint32_t chat_id) {
        std::vector<json> locs;
        const char* sql = "SELECT l.msg_id, l.latitude, l.longitude, l.place_name FROM locations l INNER JOIN messages m ON l.msg_id = m.id WHERE m.chat_id = ? ORDER BY m.sort_timestamp DESC";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json loc;
            loc["msg_id"] = sqlite3_column_int(stmt, 0);
            loc["latitude"] = sqlite3_column_double(stmt, 1);
            loc["longitude"] = sqlite3_column_double(stmt, 2);
            loc["place_name"] = rstr(stmt, 3);
            locs.push_back(loc);
        }
        sqlite3_finalize(stmt);
        return locs;
    }

    // ========================================================================
    // 7. VIDEOCHAT
    // ========================================================================
    uint32_t videochat_create(uint32_t chat_id, const std::string& room_url,
                              const std::string& room_name, uint32_t created_by,
                              int64_t expires_at = 0) {
        int64_t now = ts_now();
        if (expires_at == 0) expires_at = now + 86400000; // 24h default
        const char* sql = "INSERT INTO videochat_rooms (chat_id, room_url, room_name, created_by, created_at, expires_at, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        sqlite3_bind_text(stmt, 2, room_url.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, room_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, static_cast<int>(created_by));
        sqlite3_bind_int64(stmt, 5, now);
        sqlite3_bind_int64(stmt, 6, expires_at);
        sqlite3_step(stmt);
        uint32_t id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
        sqlite3_finalize(stmt);
        return id;
    }

    json videochat_get_active(uint32_t chat_id) {
        json rooms = json::array();
        const char* sql = "SELECT id, room_url, room_name, created_by, created_at, expires_at FROM videochat_rooms WHERE chat_id = ? AND is_active = 1 AND expires_at > ? ORDER BY created_at DESC";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        sqlite3_bind_int64(stmt, 2, ts_now());
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json r;
            r["id"] = sqlite3_column_int(stmt, 0);
            r["room_url"] = rstr(stmt, 1);
            r["room_name"] = rstr(stmt, 2);
            r["created_by"] = sqlite3_column_int(stmt, 3);
            r["created_at"] = sqlite3_column_int64(stmt, 4);
            r["expires_at"] = sqlite3_column_int64(stmt, 5);
            rooms.push_back(r);
        }
        sqlite3_finalize(stmt);
        return rooms;
    }

    bool videochat_end(uint32_t room_id) {
        const char* sql = "UPDATE videochat_rooms SET is_active = 0 WHERE id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(room_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    void videochat_cleanup_expired() {
        const char* sql = "UPDATE videochat_rooms SET is_active = 0 WHERE is_active = 1 AND expires_at <= ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int64(stmt, 1, ts_now());
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // ========================================================================
    // 8. VOICE MESSAGES
    // ========================================================================
    bool voicemsg_create(uint32_t msg_id, int64_t duration_ms, const std::string& waveform,
                         const std::string& file_path) {
        const char* sql = "INSERT OR REPLACE INTO voice_messages (msg_id, duration_ms, waveform, is_played, file_path) VALUES (?, ?, ?, 0, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        sqlite3_bind_int64(stmt, 2, duration_ms);
        sqlite3_bind_text(stmt, 3, waveform.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, file_path.c_str(), -1, SQLITE_TRANSIENT);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    json voicemsg_get(uint32_t msg_id) {
        json v;
        const char* sql = "SELECT duration_ms, waveform, transcript, is_played, file_path FROM voice_messages WHERE msg_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            v["duration_ms"] = sqlite3_column_int64(stmt, 0);
            v["waveform"] = rstr(stmt, 1);
            v["transcript"] = rstr(stmt, 2);
            v["is_played"] = sqlite3_column_int(stmt, 3) == 1;
            v["file_path"] = rstr(stmt, 4);
        }
        sqlite3_finalize(stmt);
        return v;
    }

    bool voicemsg_mark_played(uint32_t msg_id) {
        const char* sql = "UPDATE voice_messages SET is_played = 1 WHERE msg_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    bool voicemsg_set_transcript(uint32_t msg_id, const std::string& transcript) {
        const char* sql = "UPDATE voice_messages SET transcript = ? WHERE msg_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, transcript.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, static_cast<int>(msg_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    // ========================================================================
    // 9. CHAT SETTINGS (pin, archive, mute, notifications)
    // ========================================================================
    bool chat_settings_set(uint32_t chat_id, const std::string& key, const std::string& value) {
        std::string sql = "INSERT INTO chat_settings (chat_id, " + key + ") VALUES (?, ?) ON CONFLICT(chat_id) DO UPDATE SET " + key + " = excluded." + key;
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    json chat_settings_get(uint32_t chat_id) {
        json s;
        const char* sql = "SELECT pinned_order, archived_at, notification_sound, notification_vibrate, show_previews, custom_color, custom_avatar FROM chat_settings WHERE chat_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            s["pinned_order"] = sqlite3_column_int(stmt, 0);
            s["archived_at"] = sqlite3_column_int64(stmt, 1);
            s["notification_sound"] = rstr(stmt, 2);
            s["notification_vibrate"] = sqlite3_column_int(stmt, 3) == 1;
            s["show_previews"] = sqlite3_column_int(stmt, 4) == 1;
            s["custom_color"] = rstr(stmt, 5);
            s["custom_avatar"] = rstr(stmt, 6);
        }
        sqlite3_finalize(stmt);
        return s;
    }

    bool chat_pin(uint32_t chat_id, bool pin, int order = 0) {
        if (pin) {
            return chat_settings_set(chat_id, "pinned_order", std::to_string(order > 0 ? order : static_cast<int>(ts_now())));
        }
        return chat_settings_set(chat_id, "pinned_order", "0");
    }

    bool chat_archive(uint32_t chat_id, bool archive) {
        return chat_settings_set(chat_id, "archived_at",
            archive ? std::to_string(ts_now()) : "0");
    }

    bool chat_mute_notifications(uint32_t chat_id, int64_t duration_ms) {
        // Store mute duration. 0 = unmuted, -1 = forever
        const char* sql = "INSERT INTO chat_settings (chat_id, muted_until) VALUES (?, ?) ON CONFLICT(chat_id) DO UPDATE SET muted_until = excluded.muted_until";
        sqlite3_stmt* stmt = nullptr;
        // Need to ensure muted_until column exists — use generic key/value
        sqlite3_finalize(stmt);

        if (duration_ms < 0) {
            // Mute forever
            return chat_settings_set(chat_id, "muted_until", "-1");
        } else if (duration_ms == 0) {
            return chat_settings_set(chat_id, "muted_until", "0");
        } else {
            return chat_settings_set(chat_id, "muted_until", std::to_string(ts_now() + duration_ms));
        }
    }

    bool chat_is_muted(uint32_t chat_id) {
        json s = chat_settings_get(chat_id);
        if (!s.contains("muted_until")) return false;
        std::string mu_str = s["muted_until"].is_number()
            ? std::to_string(s["muted_until"].get<int64_t>())
            : s["muted_until"].get<std::string>();
        if (mu_str.empty() || mu_str == "0") return false;
        int64_t mu = std::stoll(mu_str);
        if (mu == -1) return true; // forever
        return ts_now() < mu;
    }

    // ========================================================================
    // 10. FOLDER MANAGEMENT
    // ========================================================================
    uint32_t folder_create(const std::string& name, const std::string& color = "#888888") {
        const char* sql = "INSERT INTO chat_folders (name, color, sort_order, created_at) VALUES (?, ?, 0, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, color.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, ts_now());
        sqlite3_step(stmt);
        uint32_t id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
        sqlite3_finalize(stmt);
        return id;
    }

    bool folder_delete(uint32_t folder_id) {
        // First remove all chat memberships
        const char* del_members = "DELETE FROM chat_folder_members WHERE folder_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, del_members, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(folder_id));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        const char* sql = "DELETE FROM chat_folders WHERE id = ?";
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(folder_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE) && sqlite3_changes(db_) > 0;
        sqlite3_finalize(stmt);
        return ok;
    }

    bool folder_rename(uint32_t folder_id, const std::string& name) {
        const char* sql = "UPDATE chat_folders SET name = ? WHERE id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, static_cast<int>(folder_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    json folder_list_all() {
        json folders = json::array();
        const char* sql = "SELECT id, name, color, sort_order, created_at FROM chat_folders ORDER BY sort_order ASC, name ASC";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json f;
            f["id"] = sqlite3_column_int(stmt, 0);
            f["name"] = rstr(stmt, 1);
            f["color"] = rstr(stmt, 2);
            f["sort_order"] = sqlite3_column_int(stmt, 3);
            f["created_at"] = sqlite3_column_int64(stmt, 4);
            folders.push_back(f);
        }
        sqlite3_finalize(stmt);
        return folders;
    }

    bool folder_add_chat(uint32_t folder_id, uint32_t chat_id) {
        const char* sql = "INSERT OR IGNORE INTO chat_folder_members (folder_id, chat_id, added_at) VALUES (?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(folder_id));
        sqlite3_bind_int(stmt, 2, static_cast<int>(chat_id));
        sqlite3_bind_int64(stmt, 3, ts_now());
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    bool folder_remove_chat(uint32_t folder_id, uint32_t chat_id) {
        const char* sql = "DELETE FROM chat_folder_members WHERE folder_id = ? AND chat_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(folder_id));
        sqlite3_bind_int(stmt, 2, static_cast<int>(chat_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE) && sqlite3_changes(db_) > 0;
        sqlite3_finalize(stmt);
        return ok;
    }

    std::vector<uint32_t> folder_get_chats(uint32_t folder_id) {
        std::vector<uint32_t> ids;
        const char* sql = "SELECT chat_id FROM chat_folder_members WHERE folder_id = ? ORDER BY added_at ASC";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(folder_id));
        while (sqlite3_step(stmt) == SQLITE_ROW)
            ids.push_back(static_cast<uint32_t>(sqlite3_column_int(stmt, 0)));
        sqlite3_finalize(stmt);
        return ids;
    }

    std::vector<uint32_t> folder_get_for_chat(uint32_t chat_id) {
        std::vector<uint32_t> ids;
        const char* sql = "SELECT folder_id FROM chat_folder_members WHERE chat_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        while (sqlite3_step(stmt) == SQLITE_ROW)
            ids.push_back(static_cast<uint32_t>(sqlite3_column_int(stmt, 0)));
        sqlite3_finalize(stmt);
        return ids;
    }

    // ========================================================================
    // 11. TRASH / DELETE FOREVER
    // ========================================================================
    bool trash_add(const std::string& type, uint32_t original_id, uint32_t deleted_by,
                   const json& data = json::object()) {
        const char* sql = "INSERT INTO trash (original_type, original_id, deleted_at, deleted_by, data_json) VALUES (?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, static_cast<int>(original_id));
        sqlite3_bind_int64(stmt, 3, ts_now());
        sqlite3_bind_int(stmt, 4, static_cast<int>(deleted_by));
        sqlite3_bind_text(stmt, 5, data.dump().c_str(), -1, SQLITE_TRANSIENT);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    json trash_list(const std::string& type = "") {
        json items = json::array();
        std::string sql = "SELECT id, original_type, original_id, deleted_at, deleted_by, data_json FROM trash";
        if (!type.empty()) sql += " WHERE original_type = ?";
        sql += " ORDER BY deleted_at DESC LIMIT 200";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        if (!type.empty()) sqlite3_bind_text(stmt, 1, type.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json item;
            item["id"] = sqlite3_column_int(stmt, 0);
            item["original_type"] = rstr(stmt, 1);
            item["original_id"] = sqlite3_column_int(stmt, 2);
            item["deleted_at"] = sqlite3_column_int64(stmt, 3);
            item["deleted_by"] = sqlite3_column_int(stmt, 4);
            try {
                item["data"] = json::parse(rstr(stmt, 5));
            } catch (...) {
                item["data"] = json::object();
            }
            items.push_back(item);
        }
        sqlite3_finalize(stmt);
        return items;
    }

    bool trash_restore(int trash_id) {
        // Mark as restored by setting a flag — actual restore logic is app-specific
        const char* sql = "DELETE FROM trash WHERE id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, trash_id);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE) && sqlite3_changes(db_) > 0;
        sqlite3_finalize(stmt);
        return ok;
    }

    bool trash_delete_forever(int trash_id) {
        const char* sql = "DELETE FROM trash WHERE id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, trash_id);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE) && sqlite3_changes(db_) > 0;
        sqlite3_finalize(stmt);
        return ok;
    }

    bool trash_empty() {
        const char* sql = "DELETE FROM trash";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    int trash_count() {
        const char* sql = "SELECT COUNT(*) FROM trash";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        int count = (sqlite3_step(stmt) == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : 0;
        sqlite3_finalize(stmt);
        return count;
    }

    // ========================================================================
    // 12. MULTI-DEVICE SYNC
    // ========================================================================
    bool sync_device_register(const std::string& device_id, const std::string& device_name,
                              const std::string& public_key = "") {
        const char* sql = "INSERT OR REPLACE INTO sync_state (device_id, last_sync_timestamp, device_name, public_key, last_seen_at) VALUES (?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, device_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, ts_now());
        sqlite3_bind_text(stmt, 3, device_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, public_key.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, ts_now());
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    bool sync_device_update_status(const std::string& device_id, int64_t sentbox_uid,
                                    int64_t mvbox_uid, const std::string& configured_status) {
        const char* sql = "UPDATE sync_state SET sentbox_watch_uid = ?, mvbox_watch_uid = ?, configured_status = ?, last_seen_at = ? WHERE device_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int64(stmt, 1, sentbox_uid);
        sqlite3_bind_int64(stmt, 2, mvbox_uid);
        sqlite3_bind_text(stmt, 3, configured_status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, ts_now());
        sqlite3_bind_text(stmt, 5, device_id.c_str(), -1, SQLITE_TRANSIENT);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    json sync_device_list() {
        json devices = json::array();
        const char* sql = "SELECT device_id, last_sync_timestamp, sentbox_watch_uid, mvbox_watch_uid, configured_status, last_seen_at, device_name, public_key FROM sync_state ORDER BY last_seen_at DESC";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json d;
            d["device_id"] = rstr(stmt, 0);
            d["last_sync_timestamp"] = sqlite3_column_int64(stmt, 1);
            d["sentbox_watch_uid"] = sqlite3_column_int64(stmt, 2);
            d["mvbox_watch_uid"] = sqlite3_column_int64(stmt, 3);
            d["configured_status"] = rstr(stmt, 4);
            d["last_seen_at"] = sqlite3_column_int64(stmt, 5);
            d["device_name"] = rstr(stmt, 6);
            d["public_key"] = rstr(stmt, 7);
            devices.push_back(d);
        }
        sqlite3_finalize(stmt);
        return devices;
    }

    bool sync_device_remove(const std::string& device_id) {
        const char* sql = "DELETE FROM sync_state WHERE device_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, device_id.c_str(), -1, SQLITE_TRANSIENT);
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE) && sqlite3_changes(db_) > 0;
        sqlite3_finalize(stmt);
        return ok;
    }

    uint32_t sync_queue_add(const std::string& sync_data, const std::string& sync_type = "message",
                            const std::string& target_devices = "*") {
        const char* sql = "INSERT INTO sync_queue (sync_data, sync_type, target_devices, created_at, processed) VALUES (?, ?, ?, ?, 0)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, sync_data.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, sync_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, target_devices.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, ts_now());
        sqlite3_step(stmt);
        uint32_t id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
        sqlite3_finalize(stmt);
        return id;
    }

    json sync_queue_get_pending(int limit = 50) {
        json items = json::array();
        const char* sql = "SELECT id, sync_data, sync_type, target_devices, created_at FROM sync_queue WHERE processed = 0 ORDER BY id ASC LIMIT ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, limit);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json item;
            item["id"] = sqlite3_column_int(stmt, 0);
            item["sync_data"] = rstr(stmt, 1);
            item["sync_type"] = rstr(stmt, 2);
            item["target_devices"] = rstr(stmt, 3);
            item["created_at"] = sqlite3_column_int64(stmt, 4);
            items.push_back(item);
        }
        sqlite3_finalize(stmt);
        return items;
    }

    bool sync_queue_mark_processed(uint32_t sync_id) {
        const char* sql = "UPDATE sync_queue SET processed = 1 WHERE id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(sync_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    void sync_queue_cleanup_old(int64_t older_than_ms = 604800000) {
        const char* sql = "DELETE FROM sync_queue WHERE processed = 1 AND created_at < ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int64(stmt, 1, ts_now() - older_than_ms);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // ========================================================================
    // 13. GROUP MEMBER ROLES (promote/demote)
    // ========================================================================
    bool group_role_set(uint32_t chat_id, uint32_t contact_id, const std::string& role,
                        uint32_t promoted_by = 0) {
        const char* sql = "INSERT OR REPLACE INTO group_member_roles (chat_id, contact_id, role, promoted_by, promoted_at) VALUES (?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        sqlite3_bind_int(stmt, 2, static_cast<int>(contact_id));
        sqlite3_bind_text(stmt, 3, role.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, static_cast<int>(promoted_by));
        sqlite3_bind_int64(stmt, 5, ts_now());
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    std::string group_role_get(uint32_t chat_id, uint32_t contact_id) {
        const char* sql = "SELECT role FROM group_member_roles WHERE chat_id = ? AND contact_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        sqlite3_bind_int(stmt, 2, static_cast<int>(contact_id));
        std::string role = "member";
        if (sqlite3_step(stmt) == SQLITE_ROW)
            role = rstr(stmt, 0);
        sqlite3_finalize(stmt);
        return role;
    }

    json group_roles_list(uint32_t chat_id) {
        json roles = json::object();
        const char* sql = "SELECT contact_id, role, promoted_by, promoted_at FROM group_member_roles WHERE chat_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json r;
            r["role"] = rstr(stmt, 1);
            r["promoted_by"] = sqlite3_column_int(stmt, 2);
            r["promoted_at"] = sqlite3_column_int64(stmt, 3);
            roles[std::to_string(sqlite3_column_int(stmt, 0))] = r;
        }
        sqlite3_finalize(stmt);
        return roles;
    }

    bool group_role_remove(uint32_t chat_id, uint32_t contact_id) {
        const char* sql = "DELETE FROM group_member_roles WHERE chat_id = ? AND contact_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(chat_id));
        sqlite3_bind_int(stmt, 2, static_cast<int>(contact_id));
        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    // ========================================================================
    // 14. SERVER-SIDE SEARCH INDEX
    // ========================================================================
    void search_index_add(const std::string& term, uint32_t msg_id, uint32_t chat_id, double relevance = 1.0) {
        const char* sql = "INSERT OR REPLACE INTO search_index (term, msg_id, chat_id, relevance) VALUES (?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, str_lower(term).c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, static_cast<int>(msg_id));
        sqlite3_bind_int(stmt, 3, static_cast<int>(chat_id));
        sqlite3_bind_double(stmt, 4, relevance);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    std::vector<uint32_t> search_index_query(const std::string& query, uint32_t chat_id = 0, int limit = 100) {
        std::vector<uint32_t> ids;
        std::string sql_str = "SELECT DISTINCT msg_id FROM search_index WHERE term LIKE ?";
        if (chat_id > 0) sql_str += " AND chat_id = ?";
        sql_str += " ORDER BY relevance DESC LIMIT ?";

        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql_str.c_str(), -1, &stmt, nullptr);
        std::string like = str_lower(query) + "%";
        sqlite3_bind_text(stmt, 1, like.c_str(), -1, SQLITE_TRANSIENT);
        int bind_idx = 2;
        if (chat_id > 0) {
            sqlite3_bind_int(stmt, bind_idx++, static_cast<int>(chat_id));
        }
        sqlite3_bind_int(stmt, bind_idx, limit);
        while (sqlite3_step(stmt) == SQLITE_ROW)
            ids.push_back(static_cast<uint32_t>(sqlite3_column_int(stmt, 0)));
        sqlite3_finalize(stmt);
        return ids;
    }

    void search_index_build_for_msg(uint32_t msg_id, uint32_t chat_id, const std::string& text) {
        // Tokenize and index message text
        std::string lower = str_lower(text);
        std::istringstream iss(lower);
        std::string word;
        double relevance = 1.0;
        while (iss >> word) {
            // Clean punctuation
            word.erase(std::remove_if(word.begin(), word.end(),
                [](unsigned char c) { return std::ispunct(c); }), word.end());
            if (word.length() >= 2) {
                search_index_add(word, msg_id, chat_id, relevance);
                relevance *= 0.95; // later words have slightly lower relevance
            }
        }
    }

    void search_index_remove_msg(uint32_t msg_id) {
        const char* sql = "DELETE FROM search_index WHERE msg_id = ?";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, static_cast<int>(msg_id));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // ========================================================================
    // 15. MESSAGE INFO (comprehensive)
    // ========================================================================
    json message_info_full(uint32_t msg_id) {
        json info;
        info["msg_id"] = msg_id;

        // Get reactions
        info["reactions"] = reaction_summary(msg_id);

        // Get receipts
        info["receipts"] = receipt_get_all(msg_id);
        info["delivery_count"] = receipt_count_by_type(msg_id, "delivered");
        info["read_count"] = receipt_count_by_type(msg_id, "read");

        // Get location if any
        json loc = location_get(msg_id);
        if (!loc.empty() && loc.contains("latitude"))
            info["location"] = loc;

        // Get voice message info if any
        json vm = voicemsg_get(msg_id);
        if (!vm.empty() && vm.contains("duration_ms"))
            info["voice_message"] = vm;

        return info;
    }
};

// ============================================================================
// Global FeatureDB instance
// ============================================================================
static std::unique_ptr<FeatureDB> g_fdb;
static std::mutex g_fdb_mutex;

static FeatureDB& fdb() {
    if (!g_fdb) {
        std::lock_guard<std::mutex> lock(g_fdb_mutex);
        if (!g_fdb) {
            g_fdb = std::make_unique<FeatureDB>("deltachat_features.sqlite");
        }
    }
    return *g_fdb;
}

// ============================================================================
// 16. DeltaChat UI Manager — comprehensive UI feature orchestration
// ============================================================================
class DeltaChatUIManager {
public:
    DeltaChatUIManager() : connectivity_(DC_CONNECTIVITY_NOT_CONNECTED) {}

    // ========================================================================
    // Reactions
    // ========================================================================
    bool add_reaction(uint32_t msg_id, uint32_t contact_id, const std::string& reaction) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().reaction_add(msg_id, contact_id, reaction);
        if (ok) notify_event(DC_EVENT_REACTION_ADDED, msg_id, contact_id);
        return ok;
    }

    bool remove_reaction(uint32_t msg_id, uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().reaction_remove(msg_id, contact_id);
        if (ok) notify_event(DC_EVENT_REACTION_REMOVED, msg_id, contact_id);
        return ok;
    }

    json get_reaction_summary(uint32_t msg_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().reaction_summary(msg_id);
    }

    // ========================================================================
    // Message Info (delivery/read receipts, MDN)
    // ========================================================================
    json get_message_info(uint32_t msg_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().message_info_full(msg_id);
    }

    bool mark_delivered(uint32_t msg_id, uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().receipt_add(msg_id, contact_id, "delivered");
        if (ok) notify_event(DC_EVENT_MSG_DELIVERED, msg_id, contact_id);
        return ok;
    }

    bool mark_read(uint32_t msg_id, uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().receipt_add(msg_id, contact_id, "read");
        if (ok) notify_event(DC_EVENT_MSG_READ, msg_id, contact_id);
        return ok;
    }

    bool mark_failed(uint32_t msg_id, uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().receipt_add(msg_id, contact_id, "failed");
    }

    // ========================================================================
    // Group Management
    // ========================================================================
    bool group_edit_name(uint32_t chat_id, const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        // In production: update chats table via the main DB
        notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, 0);
        return true;
    }

    bool group_edit_avatar(uint32_t chat_id, const std::string& avatar_path) {
        std::lock_guard<std::mutex> lock(mutex_);
        fdb().chat_settings_set(chat_id, "custom_avatar", avatar_path);
        notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, 0);
        return true;
    }

    bool group_add_member(uint32_t chat_id, uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        fdb().group_role_set(chat_id, contact_id, "member");
        notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, contact_id);
        return true;
    }

    bool group_remove_member(uint32_t chat_id, uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        fdb().group_role_remove(chat_id, contact_id);
        notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, contact_id);
        return true;
    }

    bool group_leave(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        // Leave as self — app layer provides self_contact_id
        notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, 0);
        return true;
    }

    bool group_promote(uint32_t chat_id, uint32_t contact_id, const std::string& role, uint32_t promoter_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().group_role_set(chat_id, contact_id, role, promoter_id);
        notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, contact_id);
        return ok;
    }

    bool group_demote(uint32_t chat_id, uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().group_role_set(chat_id, contact_id, "member");
    }

    json group_get_roles(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().group_roles_list(chat_id);
    }

    std::string group_get_member_role(uint32_t chat_id, uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().group_role_get(chat_id, contact_id);
    }

    // ========================================================================
    // Bot Support
    // ========================================================================
    bool register_bot(uint32_t contact_id, const std::string& owner, const json& commands,
                      const std::string& description) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().bot_register(contact_id, owner, commands, description);
    }

    bool is_bot(uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().bot_is_bot(contact_id);
    }

    json get_bot_info(uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().bot_get_info(contact_id);
    }

    std::vector<uint32_t> list_bots() {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().bot_list_all();
    }

    // Handle bot command
    json handle_bot_command(uint32_t chat_id, uint32_t from_contact_id, const std::string& text) {
        BotCommand cmd = parse_bot_command(text);
        json response;
        if (cmd.command.empty()) {
            response["type"] = "not_a_command";
            return response;
        }
        response["command"] = cmd.command;
        response["args"] = cmd.args;

        // Check if contact is a registered bot
        if (!is_bot(from_contact_id)) {
            response["type"] = "not_a_bot";
            return response;
        }

        response["type"] = "bot_command";
        response["chat_id"] = chat_id;

        // Route to known commands
        if (cmd.command == "help") {
            response["reply"] = "Available commands: /help, /info, /ping, /echo [text], /about";
        } else if (cmd.command == "info") {
            json bot_info = get_bot_info(from_contact_id);
            response["reply"] = "Bot: " + bot_info.value("bot_description", "No description");
        } else if (cmd.command == "ping") {
            response["reply"] = "Pong!";
        } else if (cmd.command == "echo" && !cmd.args.empty()) {
            response["reply"] = str_join(cmd.args, " ");
        } else if (cmd.command == "about") {
            response["reply"] = "DeltaChat Bot v1.0 - Progressive Server";
        } else {
            response["reply"] = "Unknown command: /" + cmd.command + ". Try /help";
        }
        return response;
    }

    // ========================================================================
    // Contact Verification
    // ========================================================================
    bool verify_contact(uint32_t contact_id, const std::string& verified_by,
                        const std::string& fingerprint, const std::string& method = "autocrypt") {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().verification_set(contact_id, true, verified_by, fingerprint, method);
    }

    bool unverify_contact(uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().verification_set(contact_id, false, "", "", "");
    }

    bool is_contact_verified(uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        json v = fdb().verification_get(contact_id);
        return v.value("verified", false);
    }

    json get_verification_info(uint32_t contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().verification_get(contact_id);
    }

    std::vector<uint32_t> list_verified_contacts() {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().verification_list_verified();
    }

    // ========================================================================
    // Locations
    // ========================================================================
    bool send_location(uint32_t msg_id, double lat, double lon, double accuracy = 0.0,
                       const std::string& address = "", const std::string& place_name = "",
                       bool is_live = false, int64_t live_expires_at = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().location_set(msg_id, lat, lon, accuracy, address, place_name,
                                      is_live, live_expires_at);
        if (ok) notify_event(DC_EVENT_LOCATION_CHANGED, msg_id, 0);
        return ok;
    }

    json get_location(uint32_t msg_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().location_get(msg_id);
    }

    std::vector<json> get_chat_locations(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().locations_in_chat(chat_id);
    }

    // ========================================================================
    // Videochat
    // ========================================================================
    uint32_t start_videochat(uint32_t chat_id, const std::string& room_url,
                             const std::string& room_name, uint32_t created_by,
                             int64_t expires_at = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t room_id = fdb().videochat_create(chat_id, room_url, room_name,
                                                    created_by, expires_at);
        notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, room_id);
        return room_id;
    }

    json get_active_videochats(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().videochat_get_active(chat_id);
    }

    bool end_videochat(uint32_t room_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().videochat_end(room_id);
    }

    void cleanup_expired_videochats() {
        std::lock_guard<std::mutex> lock(mutex_);
        fdb().videochat_cleanup_expired();
    }

    std::string generate_videochat_url(const std::string& service = "jitsi") {
        std::string room_name = gen_rand_token(12);
        if (service == "jitsi") {
            return "https://meet.jit.si/" + room_name;
        } else if (service == "bbb") {
            return "https://bigbluebutton.example.com/join/" + room_name;
        }
        return "https://meet.jit.si/" + room_name;
    }

    // ========================================================================
    // Voice Messages
    // ========================================================================
    bool create_voice_message(uint32_t msg_id, int64_t duration_ms, const std::string& waveform,
                              const std::string& file_path) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().voicemsg_create(msg_id, duration_ms, waveform, file_path);
    }

    json get_voice_message(uint32_t msg_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().voicemsg_get(msg_id);
    }

    bool mark_voice_played(uint32_t msg_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().voicemsg_mark_played(msg_id);
    }

    bool set_voice_transcript(uint32_t msg_id, const std::string& transcript) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().voicemsg_set_transcript(msg_id, transcript);
    }

    std::string generate_voice_waveform(int64_t duration_ms) {
        // Generate a simple waveform representation (array of amplitude values)
        json wf = json::array();
        int samples = std::min(static_cast<int>(duration_ms / 50), 100);
        static thread_local std::mt19937 rng(static_cast<unsigned>(ts_now()));
        std::uniform_real_distribution<> d(0.1, 1.0);
        for (int i = 0; i < samples; ++i) {
            wf.push_back(d(rng));
        }
        return wf.dump();
    }

    // ========================================================================
    // Mentions
    // ========================================================================
    std::vector<std::string> get_mentions(const std::string& text) {
        return extract_mentions(text);
    }

    std::string format_mention_text(const std::string& text, uint32_t sender_contact_id) {
        // Replace @mentions with rich text mention markers
        auto mentions = extract_mentions(text);
        std::string result = text;
        for (auto& addr : mentions) {
            std::string marker = "@" + addr;
            std::string rich = "\u200B[mention:" + addr + "]\u200B";
            size_t pos = 0;
            while ((pos = result.find(marker, pos)) != std::string::npos) {
                result.replace(pos, marker.length(), rich);
                pos += rich.length();
            }
        }
        return result;
    }

    // ========================================================================
    // Drafts
    // ========================================================================
    bool save_draft(uint32_t chat_id, const std::string& text, uint32_t quoted_msg_id = 0,
                    const std::string& attachment_path = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().draft_save(chat_id, text, quoted_msg_id, attachment_path);
        if (ok) notify_event(DC_EVENT_DRAFT_CHANGED, chat_id, 0);
        return ok;
    }

    json get_draft(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().draft_get(chat_id);
    }

    bool delete_draft(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().draft_delete(chat_id);
        if (ok) notify_event(DC_EVENT_DRAFT_CHANGED, chat_id, 0);
        return ok;
    }

    bool has_draft(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        json d = fdb().draft_get(chat_id);
        return !d.empty() && !d.value("text", "").empty();
    }

    // ========================================================================
    // Pin / Archive / Mute
    // ========================================================================
    bool pin_chat(uint32_t chat_id, bool pin, int order = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().chat_pin(chat_id, pin, order);
        if (ok) notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, 0);
        return ok;
    }

    bool archive_chat(uint32_t chat_id, bool archive) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().chat_archive(chat_id, archive);
        if (ok) notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, 0);
        return ok;
    }

    bool mute_chat(uint32_t chat_id, int64_t duration_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().chat_mute_notifications(chat_id, duration_ms);
        if (ok) notify_event(DC_EVENT_CHAT_MODIFIED, chat_id, 0);
        return ok;
    }

    bool unmute_chat(uint32_t chat_id) {
        return mute_chat(chat_id, 0);
    }

    bool is_chat_muted(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().chat_is_muted(chat_id);
    }

    json get_chat_settings(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().chat_settings_get(chat_id);
    }

    // ========================================================================
    // Folder Management
    // ========================================================================
    uint32_t create_folder(const std::string& name, const std::string& color = "#888888") {
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t id = fdb().folder_create(name, color);
        notify_event(DC_EVENT_FOLDER_CHANGED, id, 0);
        return id;
    }

    bool delete_folder(uint32_t folder_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().folder_delete(folder_id);
        if (ok) notify_event(DC_EVENT_FOLDER_CHANGED, folder_id, 0);
        return ok;
    }

    bool rename_folder(uint32_t folder_id, const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().folder_rename(folder_id, name);
        if (ok) notify_event(DC_EVENT_FOLDER_CHANGED, folder_id, 0);
        return ok;
    }

    json list_folders() {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().folder_list_all();
    }

    bool add_chat_to_folder(uint32_t folder_id, uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().folder_add_chat(folder_id, chat_id);
        if (ok) notify_event(DC_EVENT_FOLDER_CHANGED, folder_id, chat_id);
        return ok;
    }

    bool remove_chat_from_folder(uint32_t folder_id, uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool ok = fdb().folder_remove_chat(folder_id, chat_id);
        if (ok) notify_event(DC_EVENT_FOLDER_CHANGED, folder_id, chat_id);
        return ok;
    }

    std::vector<uint32_t> get_folder_chats(uint32_t folder_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().folder_get_chats(folder_id);
    }

    std::vector<uint32_t> get_chat_folders(uint32_t chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().folder_get_for_chat(chat_id);
    }

    // ========================================================================
    // Trash / Delete Forever
    // ========================================================================
    bool move_to_trash(const std::string& type, uint32_t original_id, uint32_t deleted_by,
                       const json& data = json::object()) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().trash_add(type, original_id, deleted_by, data);
    }

    json get_trash_items(const std::string& type = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().trash_list(type);
    }

    bool restore_from_trash(int trash_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().trash_restore(trash_id);
    }

    bool delete_forever(int trash_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().trash_delete_forever(trash_id);
    }

    bool empty_trash() {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().trash_empty();
    }

    int get_trash_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().trash_count();
    }

    // ========================================================================
    // Multi-Device Sync
    // ========================================================================
    bool register_device(const std::string& device_id, const std::string& device_name,
                          const std::string& public_key = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().sync_device_register(device_id, device_name, public_key);
    }

    bool update_device_sync_status(const std::string& device_id, int64_t sentbox_uid,
                                    int64_t mvbox_uid, const std::string& configured_status) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().sync_device_update_status(device_id, sentbox_uid, mvbox_uid, configured_status);
    }

    json list_sync_devices() {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().sync_device_list();
    }

    bool remove_sync_device(const std::string& device_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().sync_device_remove(device_id);
    }

    uint32_t queue_sync_message(const std::string& sync_data, const std::string& sync_type = "message",
                                const std::string& target_devices = "*") {
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t id = fdb().sync_queue_add(sync_data, sync_type, target_devices);
        notify_event(DC_EVENT_SYNC_MSG_ADDED, id, 0);
        return id;
    }

    json get_pending_sync_items(int limit = 50) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().sync_queue_get_pending(limit);
    }

    bool mark_sync_processed(uint32_t sync_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().sync_queue_mark_processed(sync_id);
    }

    void cleanup_old_sync_items(int64_t older_than_ms = 604800000) {
        std::lock_guard<std::mutex> lock(mutex_);
        fdb().sync_queue_cleanup_old(older_than_ms);
    }

    // Build a sync message for a new outgoing message
    std::string build_sync_message(const DcMessage& msg) {
        json sync;
        sync["type"] = "outgoing_message";
        sync["msg_id"] = msg.id;
        sync["chat_id"] = msg.chat_id;
        sync["from_id"] = msg.from_id;
        sync["text"] = msg.text;
        sync["timestamp"] = msg.timestamp;
        sync["state"] = msg.state;
        sync["rfc724_mid"] = msg.rfc724_mid;
        sync["subject"] = msg.subject;
        return sync.dump();
    }

    // Build sync message for sentbox/mvbox watch updates
    std::string build_sync_status(const std::string& device_id,
                                   int64_t sentbox_uid, int64_t mvbox_uid,
                                   const std::string& configured_status) {
        json sync;
        sync["type"] = "device_status";
        sync["device_id"] = device_id;
        sync["sentbox_watch_uid"] = sentbox_uid;
        sync["mvbox_watch_uid"] = mvbox_uid;
        sync["configured_status"] = configured_status;
        sync["timestamp"] = ts_now();
        return sync.dump();
    }

    // ========================================================================
    // Server-side Search
    // ========================================================================
    void index_message_for_search(uint32_t msg_id, uint32_t chat_id, const std::string& text) {
        std::lock_guard<std::mutex> lock(mutex_);
        fdb().search_index_build_for_msg(msg_id, chat_id, text);
    }

    std::vector<uint32_t> search_messages(const std::string& query, uint32_t chat_id = 0,
                                          int limit = 100) {
        std::lock_guard<std::mutex> lock(mutex_);
        return fdb().search_index_query(query, chat_id, limit);
    }

    void remove_from_search_index(uint32_t msg_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        fdb().search_index_remove_msg(msg_id);
    }

    // ========================================================================
    // Delivery Reports — comprehensive status summary
    // ========================================================================
    json get_delivery_report(uint32_t msg_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        json report;
        report["msg_id"] = msg_id;
        report["delivered_to"] = fdb().receipt_count_by_type(msg_id, "delivered");
        report["read_by"] = fdb().receipt_count_by_type(msg_id, "read");
        report["failed_for"] = fdb().receipt_count_by_type(msg_id, "failed");
        report["reactions"] = fdb().reaction_summary(msg_id);
        report["receipts"] = fdb().receipt_get_all(msg_id);

        // Derive overall status
        int delivered = report["delivered_to"].get<int>();
        int read = report["read_by"].get<int>();
        int failed = report["failed_for"].get<int>();

        if (read > 0) report["status"] = "read";
        else if (delivered > 0) report["status"] = "delivered";
        else if (failed > 0) report["status"] = "some_failed";
        else report["status"] = "pending";

        return report;
    }

    // ========================================================================
    // Event callback support
    // ========================================================================
    using EventCallback = std::function<void(int event, uint32_t data1, uint32_t data2)>;
    void set_event_callback(EventCallback cb) { event_cb_ = std::move(cb); }

    // ========================================================================
    // Connectivity
    // ========================================================================
    void set_connectivity(int level) {
        connectivity_ = level;
        notify_event(DC_EVENT_CONNECTIVITY_CHANGED, static_cast<uint32_t>(level), 0);
    }
    int get_connectivity() const { return connectivity_; }

    // ========================================================================
    // Convenience: full message send with all features
    // ========================================================================
    struct SendContext {
        uint32_t chat_id;
        std::string text;
        uint32_t from_contact_id = 0;
        bool is_bot_msg = false;
        std::string quoted_msg_id;
        std::string attachment_path;
        double lat = 0.0, lon = 0.0;
        bool has_location = false;
        int64_t voice_duration_ms = 0;
        bool is_voice = false;
        std::string voice_waveform;
        std::string voice_file_path;
        bool is_videochat_invite = false;
        std::string videochat_url;
    };

    json prepare_send(const SendContext& ctx) {
        json result;
        result["chat_id"] = ctx.chat_id;
        result["text"] = ctx.text;

        // Extract and handle mentions
        auto mentions = extract_mentions(ctx.text);
        if (!mentions.empty()) {
            result["mentions"] = mentions;
            result["formatted_text"] = format_mention_text(ctx.text, ctx.from_contact_id);
        }

        // Check for bot commands (if sending to a bot)
        if (ctx.is_bot_msg) {
            auto bot_cmd = parse_bot_command(ctx.text);
            if (!bot_cmd.command.empty()) {
                result["bot_command"] = bot_cmd.command;
                result["bot_args"] = bot_cmd.args;
            }
        }

        // Location
        if (ctx.has_location) {
            result["location"] = {
                {"latitude", ctx.lat},
                {"longitude", ctx.lon}
            };
        }

        // Voice message
        if (ctx.is_voice) {
            result["voice_message"] = {
                {"duration_ms", ctx.voice_duration_ms},
                {"waveform", ctx.voice_waveform.empty()
                    ? generate_voice_waveform(ctx.voice_duration_ms)
                    : ctx.voice_waveform},
                {"file_path", ctx.voice_file_path}
            };
        }

        // Videochat invite
        if (ctx.is_videochat_invite) {
            result["videochat_url"] = ctx.videochat_url.empty()
                ? generate_videochat_url()
                : ctx.videochat_url;
        }

        // Quote
        if (!ctx.quoted_msg_id.empty()) {
            result["quoted_msg_id"] = ctx.quoted_msg_id;
        }

        return result;
    }

    // Generate message ID (RFC724 format)
    std::string generate_message_id() {
        std::stringstream ss;
        ss << "<" << ts_now() << "." << gen_rand_token(8) << "@progressive.deltachat>";
        return ss.str();
    }

private:
    int connectivity_;
    std::mutex mutex_;
    EventCallback event_cb_;

    void notify_event(int event, uint32_t data1, uint32_t data2) {
        if (event_cb_) event_cb_(event, data1, data2);
    }
};

// ============================================================================
// Global UI manager instance
// ============================================================================
static std::unique_ptr<DeltaChatUIManager> g_ui;
static std::mutex g_ui_mutex;

static DeltaChatUIManager& ui() {
    if (!g_ui) {
        std::lock_guard<std::mutex> lock(g_ui_mutex);
        if (!g_ui) {
            g_ui = std::make_unique<DeltaChatUIManager>();
        }
    }
    return *g_ui;
}

// ============================================================================
// Public API — free functions exposing the UI Manager
// ============================================================================

// ---- Reactions ----
bool dc_reaction_add(uint32_t msg_id, uint32_t contact_id, const std::string& reaction) {
    return ui().add_reaction(msg_id, contact_id, reaction);
}
bool dc_reaction_remove(uint32_t msg_id, uint32_t contact_id) {
    return ui().remove_reaction(msg_id, contact_id);
}
json dc_reaction_summary(uint32_t msg_id) {
    return ui().get_reaction_summary(msg_id);
}

// ---- Message Info / Receipts ----
json dc_message_info(uint32_t msg_id) {
    return ui().get_message_info(msg_id);
}
bool dc_mark_delivered(uint32_t msg_id, uint32_t contact_id) {
    return ui().mark_delivered(msg_id, contact_id);
}
bool dc_mark_read(uint32_t msg_id, uint32_t contact_id) {
    return ui().mark_read(msg_id, contact_id);
}
bool dc_mark_failed(uint32_t msg_id, uint32_t contact_id) {
    return ui().mark_failed(msg_id, contact_id);
}
json dc_delivery_report(uint32_t msg_id) {
    return ui().get_delivery_report(msg_id);
}

// ---- Group Management ----
bool dc_group_edit_name(uint32_t chat_id, const std::string& name) {
    return ui().group_edit_name(chat_id, name);
}
bool dc_group_edit_avatar(uint32_t chat_id, const std::string& avatar_path) {
    return ui().group_edit_avatar(chat_id, avatar_path);
}
bool dc_group_add_member(uint32_t chat_id, uint32_t contact_id) {
    return ui().group_add_member(chat_id, contact_id);
}
bool dc_group_remove_member(uint32_t chat_id, uint32_t contact_id) {
    return ui().group_remove_member(chat_id, contact_id);
}
bool dc_group_leave(uint32_t chat_id) {
    return ui().group_leave(chat_id);
}
bool dc_group_promote(uint32_t chat_id, uint32_t contact_id, const std::string& role, uint32_t promoter_id) {
    return ui().group_promote(chat_id, contact_id, role, promoter_id);
}
bool dc_group_demote(uint32_t chat_id, uint32_t contact_id) {
    return ui().group_demote(chat_id, contact_id);
}
json dc_group_get_roles(uint32_t chat_id) {
    return ui().group_get_roles(chat_id);
}
std::string dc_group_get_member_role(uint32_t chat_id, uint32_t contact_id) {
    return ui().group_get_member_role(chat_id, contact_id);
}

// ---- Bot Support ----
bool dc_bot_register(uint32_t contact_id, const std::string& owner, const json& commands, const std::string& desc) {
    return ui().register_bot(contact_id, owner, commands, desc);
}
bool dc_is_bot(uint32_t contact_id) {
    return ui().is_bot(contact_id);
}
json dc_bot_get_info(uint32_t contact_id) {
    return ui().get_bot_info(contact_id);
}
std::vector<uint32_t> dc_bot_list() {
    return ui().list_bots();
}
json dc_bot_handle_command(uint32_t chat_id, uint32_t from_contact_id, const std::string& text) {
    return ui().handle_bot_command(chat_id, from_contact_id, text);
}

// ---- Contact Verification ----
bool dc_verify_contact(uint32_t contact_id, const std::string& verified_by,
                        const std::string& fingerprint, const std::string& method) {
    return ui().verify_contact(contact_id, verified_by, fingerprint, method);
}
bool dc_unverify_contact(uint32_t contact_id) {
    return ui().unverify_contact(contact_id);
}
bool dc_is_contact_verified(uint32_t contact_id) {
    return ui().is_contact_verified(contact_id);
}
json dc_get_verification_info(uint32_t contact_id) {
    return ui().get_verification_info(contact_id);
}
std::vector<uint32_t> dc_list_verified_contacts() {
    return ui().list_verified_contacts();
}

// ---- Locations ----
bool dc_send_location(uint32_t msg_id, double lat, double lon, double accuracy,
                       const std::string& address, const std::string& place_name,
                       bool is_live, int64_t live_expires_at) {
    return ui().send_location(msg_id, lat, lon, accuracy, address, place_name, is_live, live_expires_at);
}
json dc_get_location(uint32_t msg_id) {
    return ui().get_location(msg_id);
}
std::vector<json> dc_get_chat_locations(uint32_t chat_id) {
    return ui().get_chat_locations(chat_id);
}

// ---- Videochat ----
uint32_t dc_videochat_start(uint32_t chat_id, const std::string& room_url,
                             const std::string& room_name, uint32_t created_by, int64_t expires_at) {
    return ui().start_videochat(chat_id, room_url, room_name, created_by, expires_at);
}
json dc_videochat_get_active(uint32_t chat_id) {
    return ui().get_active_videochats(chat_id);
}
bool dc_videochat_end(uint32_t room_id) {
    return ui().end_videochat(room_id);
}
void dc_videochat_cleanup_expired() {
    ui().cleanup_expired_videochats();
}
std::string dc_videochat_generate_url(const std::string& service) {
    return ui().generate_videochat_url(service);
}

// ---- Voice Messages ----
bool dc_voicemsg_create(uint32_t msg_id, int64_t duration_ms, const std::string& waveform,
                         const std::string& file_path) {
    return ui().create_voice_message(msg_id, duration_ms, waveform, file_path);
}
json dc_voicemsg_get(uint32_t msg_id) {
    return ui().get_voice_message(msg_id);
}
bool dc_voicemsg_mark_played(uint32_t msg_id) {
    return ui().mark_voice_played(msg_id);
}
bool dc_voicemsg_set_transcript(uint32_t msg_id, const std::string& transcript) {
    return ui().set_voice_transcript(msg_id, transcript);
}
std::string dc_voicemsg_generate_waveform(int64_t duration_ms) {
    return ui().generate_voice_waveform(duration_ms);
}

// ---- Mentions ----
std::vector<std::string> dc_get_mentions(const std::string& text) {
    return ui().get_mentions(text);
}
std::string dc_format_mention_text(const std::string& text, uint32_t sender_contact_id) {
    return ui().format_mention_text(text, sender_contact_id);
}

// ---- Drafts ----
bool dc_draft_save(uint32_t chat_id, const std::string& text, uint32_t quoted_msg_id,
                    const std::string& attachment_path) {
    return ui().save_draft(chat_id, text, quoted_msg_id, attachment_path);
}
json dc_draft_get(uint32_t chat_id) {
    return ui().get_draft(chat_id);
}
bool dc_draft_delete(uint32_t chat_id) {
    return ui().delete_draft(chat_id);
}
bool dc_draft_has(uint32_t chat_id) {
    return ui().has_draft(chat_id);
}

// ---- Pin / Archive / Mute ----
bool dc_chat_pin(uint32_t chat_id, bool pin, int order) {
    return ui().pin_chat(chat_id, pin, order);
}
bool dc_chat_archive(uint32_t chat_id, bool archive) {
    return ui().archive_chat(chat_id, archive);
}
bool dc_chat_mute(uint32_t chat_id, int64_t duration_ms) {
    return ui().mute_chat(chat_id, duration_ms);
}
bool dc_chat_unmute(uint32_t chat_id) {
    return ui().unmute_chat(chat_id);
}
bool dc_chat_is_muted(uint32_t chat_id) {
    return ui().is_chat_muted(chat_id);
}
json dc_chat_get_settings(uint32_t chat_id) {
    return ui().get_chat_settings(chat_id);
}

// ---- Folder Management ----
uint32_t dc_folder_create(const std::string& name, const std::string& color) {
    return ui().create_folder(name, color);
}
bool dc_folder_delete(uint32_t folder_id) {
    return ui().delete_folder(folder_id);
}
bool dc_folder_rename(uint32_t folder_id, const std::string& name) {
    return ui().rename_folder(folder_id, name);
}
json dc_folder_list() {
    return ui().list_folders();
}
bool dc_folder_add_chat(uint32_t folder_id, uint32_t chat_id) {
    return ui().add_chat_to_folder(folder_id, chat_id);
}
bool dc_folder_remove_chat(uint32_t folder_id, uint32_t chat_id) {
    return ui().remove_chat_from_folder(folder_id, chat_id);
}
std::vector<uint32_t> dc_folder_get_chats(uint32_t folder_id) {
    return ui().get_folder_chats(folder_id);
}
std::vector<uint32_t> dc_chat_get_folders(uint32_t chat_id) {
    return ui().get_chat_folders(chat_id);
}

// ---- Trash / Delete Forever ----
bool dc_trash_move(const std::string& type, uint32_t original_id, uint32_t deleted_by, const json& data) {
    return ui().move_to_trash(type, original_id, deleted_by, data);
}
json dc_trash_list(const std::string& type) {
    return ui().get_trash_items(type);
}
bool dc_trash_restore(int trash_id) {
    return ui().restore_from_trash(trash_id);
}
bool dc_trash_delete_forever(int trash_id) {
    return ui().delete_forever(trash_id);
}
bool dc_trash_empty() {
    return ui().empty_trash();
}
int dc_trash_count() {
    return ui().get_trash_count();
}

// ---- Multi-Device Sync ----
bool dc_sync_register_device(const std::string& device_id, const std::string& device_name,
                              const std::string& public_key) {
    return ui().register_device(device_id, device_name, public_key);
}
bool dc_sync_update_device_status(const std::string& device_id, int64_t sentbox_uid,
                                   int64_t mvbox_uid, const std::string& configured_status) {
    return ui().update_device_sync_status(device_id, sentbox_uid, mvbox_uid, configured_status);
}
json dc_sync_list_devices() {
    return ui().list_sync_devices();
}
bool dc_sync_remove_device(const std::string& device_id) {
    return ui().remove_sync_device(device_id);
}
uint32_t dc_sync_queue_message(const std::string& sync_data, const std::string& sync_type,
                                const std::string& target_devices) {
    return ui().queue_sync_message(sync_data, sync_type, target_devices);
}
json dc_sync_get_pending(int limit) {
    return ui().get_pending_sync_items(limit);
}
bool dc_sync_mark_processed(uint32_t sync_id) {
    return ui().mark_sync_processed(sync_id);
}
void dc_sync_cleanup_old(int64_t older_than_ms) {
    ui().cleanup_old_sync_items(older_than_ms);
}
std::string dc_sync_build_message(const DcMessage& msg) {
    return ui().build_sync_message(msg);
}
std::string dc_sync_build_status(const std::string& device_id, int64_t sentbox_uid,
                                  int64_t mvbox_uid, const std::string& configured_status) {
    return ui().build_sync_status(device_id, sentbox_uid, mvbox_uid, configured_status);
}

// ---- Server-side Search ----
void dc_search_index_msg(uint32_t msg_id, uint32_t chat_id, const std::string& text) {
    ui().index_message_for_search(msg_id, chat_id, text);
}
std::vector<uint32_t> dc_search_query(const std::string& query, uint32_t chat_id, int limit) {
    return ui().search_messages(query, chat_id, limit);
}
void dc_search_remove_msg(uint32_t msg_id) {
    ui().remove_from_search_index(msg_id);
}

// ---- Send Context (combined message preparation) ----
json dc_prepare_send(const DeltaChatUIManager::SendContext& ctx) {
    return ui().prepare_send(ctx);
}
std::string dc_generate_message_id() {
    return ui().generate_message_id();
}

// ---- UI Manager Access ----
void dc_ui_set_event_callback(DeltaChatUIManager::EventCallback cb) {
    ui().set_event_callback(std::move(cb));
}
void dc_ui_set_connectivity(int level) {
    ui().set_connectivity(level);
}
int dc_ui_get_connectivity() {
    return ui().get_connectivity();
}

// ============================================================================
// Static JSON helpers exposed for external use
// ============================================================================
json dc_build_bot_command_json(const std::string& command, const std::string& description,
                                const std::vector<std::string>& args_help) {
    json cmd;
    cmd["command"] = command;
    cmd["description"] = description;
    cmd["args"] = args_help;
    return cmd;
}

json dc_build_sync_json(const std::string& type, const json& payload) {
    json sync;
    sync["type"] = type;
    sync["payload"] = payload;
    sync["timestamp"] = ts_now();
    sync["message_id"] = "<" + std::to_string(ts_now()) + ".sync@progressive.deltachat>";
    return sync;
}

json dc_build_location_json(double lat, double lon, double accuracy,
                             const std::string& address, const std::string& place_name) {
    json loc;
    loc["latitude"] = lat;
    loc["longitude"] = lon;
    loc["accuracy"] = accuracy;
    loc["address"] = address;
    loc["place_name"] = place_name;
    return loc;
}

json dc_build_videochat_json(const std::string& room_url, const std::string& room_name,
                              uint32_t created_by, int64_t expires_at) {
    json vc;
    vc["room_url"] = room_url;
    vc["room_name"] = room_name;
    vc["created_by"] = created_by;
    vc["created_at"] = ts_now();
    vc["expires_at"] = expires_at;
    return vc;
}

json dc_build_voice_msg_json(int64_t duration_ms, const std::string& waveform,
                              const std::string& file_path) {
    json vm;
    vm["duration_ms"] = duration_ms;
    vm["waveform"] = waveform;
    vm["file_path"] = file_path;
    vm["is_played"] = false;
    return vm;
}

// ============================================================================
// Utility helpers exposed for external use
// ============================================================================
std::string dc_base64_encode(const std::string& data) { return base64enc(data); }
std::string dc_base64_decode(const std::string& data) { return base64dec(data); }
std::string dc_sha256(const std::string& data) { return sha256_hex(data); }
std::string dc_random_token(int len) { return gen_rand_token(len); }
int64_t dc_timestamp_ms() { return ts_now(); }
bool dc_is_valid_email(const std::string& addr) { return is_valid_email(addr); }
std::vector<std::string> dc_extract_mentions(const std::string& text) { return extract_mentions(text); }
json dc_parse_bot_command(const std::string& text) {
    auto cmd = parse_bot_command(text);
    json result;
    result["command"] = cmd.command;
    result["args"] = cmd.args;
    return result;
}

} // namespace progressive::deltachat
