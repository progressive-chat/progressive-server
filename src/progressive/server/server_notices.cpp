// ============================================================================
// server_notices.cpp - Matrix Server Notices, Admin Announcements, and
// User Communication System
// Implements comprehensive server-to-user communication functionality:
//   server notice room creation and management,
//   server notice sending to individual users / groups / all users,
//   server notice templates (policy violation, consent required,
//     account expiration, server migration, maintenance),
//   server notice formatting (plain text + formatted/HTML),
//   server notice tracking (delivery receipts, read receipts),
//   server notice admin API (full CRUD + query + stats),
//   server notice scheduling (delayed, recurring, deadline-based),
//   server notice batching (bulk operations with backpressure),
//   server notice localization (per-user language preferences),
//   server notice unsubscribe / opt-out management,
//   server notice per-user overrides,
//   server notice room ACLs (who can respond, read, etc.),
//   server notice content moderation & spam filtering.
// Target: 3500+ lines
// Namespace: progressive::server
// ============================================================================

#include "../json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

namespace progressive::server {

// ============================================================================
// Forward declarations
// ============================================================================
using json = nlohmann::json;
namespace fs = std::filesystem;

// ============================================================================
// Utility: time helpers, ID generation, string helpers
// ============================================================================
namespace {

int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string iso_timestamp_now() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::tm tm_buf;
    gmtime_r(&time_t_now, &tm_buf);
    char buf[64];
    int len = std::snprintf(buf, sizeof(buf),
        "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
        tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
        static_cast<long long>(ms.count()));
    return std::string(buf, static_cast<size_t>(len));
}

std::string iso_timestamp_from_sec(int64_t epoch_sec) {
    std::time_t t = static_cast<std::time_t>(epoch_sec);
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    char buf[32];
    std::snprintf(buf, sizeof(buf),
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
    return std::string(buf);
}

// Base62 encoding for compact IDs
std::string base62_encode(uint64_t num) {
    static const char* chars =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if (num == 0) return "0";
    std::string result;
    while (num > 0) {
        result = chars[num % 62] + result;
        num /= 62;
    }
    return result;
}

std::string generate_notice_id() {
    static std::atomic<uint64_t> counter{0};
    uint64_t ts = static_cast<uint64_t>(now_ms());
    uint64_t seq = counter.fetch_add(1, std::memory_order_relaxed);
    return "sn_" + base62_encode(ts) + "_" + base62_encode(seq);
}

std::string generate_room_id() {
    static std::atomic<uint64_t> counter{0};
    uint64_t ts = static_cast<uint64_t>(now_ms());
    uint64_t seq = counter.fetch_add(1, std::memory_order_relaxed);
    return "!server_notice_" + base62_encode(ts) + "_"
        + base62_encode(seq) + ":localhost";
}

std::string generate_event_id() {
    static std::atomic<uint64_t> counter{0};
    uint64_t ts = static_cast<uint64_t>(now_ms());
    uint64_t seq = counter.fetch_add(1, std::memory_order_relaxed);
    return "$sn_ev_" + base62_encode(ts) + "_" + base62_encode(seq);
}

// Simple HTML escaping
std::string html_escape(const std::string& raw) {
    std::string escaped;
    escaped.reserve(raw.size() * 2);
    for (char c : raw) {
        switch (c) {
            case '&': escaped += "&amp;"; break;
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '"': escaped += "&quot;"; break;
            case '\'': escaped += "&#39;"; break;
            default:  escaped += c; break;
        }
    }
    return escaped;
}

// Simple Markdown-to-HTML conversion (limited subset)
std::string markdown_to_html(const std::string& md) {
    std::string result;
    result.reserve(md.size() * 2);
    size_t i = 0;
    bool in_bold = false;
    bool in_italic = false;
    bool in_code = false;
    while (i < md.size()) {
        if (i + 1 < md.size() && md[i] == '*' && md[i+1] == '*') {
            result += in_bold ? "</strong>" : "<strong>";
            in_bold = !in_bold;
            i += 2;
        } else if (md[i] == '*' && !in_code) {
            result += in_italic ? "</em>" : "<em>";
            in_italic = !in_italic;
            i += 1;
        } else if (md[i] == '`') {
            result += in_code ? "</code>" : "<code>";
            in_code = !in_code;
            i += 1;
        } else if (md[i] == '\n') {
            result += "<br/>";
            i += 1;
        } else {
            result += html_escape(std::string(1, md[i]));
            i += 1;
        }
    }
    if (in_bold) result += "</strong>";
    if (in_italic) result += "</em>";
    if (in_code) result += "</code>";
    return result;
}

// Reverse: strip HTML tags for plain text
std::string strip_html(const std::string& html) {
    std::string result;
    result.reserve(html.size());
    bool in_tag = false;
    for (char c : html) {
        if (c == '<') {
            in_tag = true;
        } else if (c == '>') {
            in_tag = false;
        } else if (!in_tag) {
            result += c;
        }
    }
    return result;
}

// Replace template variables in a string
std::string apply_template_vars(const std::string& tmpl,
    const std::unordered_map<std::string, std::string>& vars) {
    std::string result = tmpl;
    for (const auto& [key, value] : vars) {
        std::string placeholder = "{{" + key + "}}";
        size_t pos = 0;
        while ((pos = result.find(placeholder, pos)) != std::string::npos) {
            result.replace(pos, placeholder.length(), value);
            pos += value.length();
        }
    }
    return result;
}

// Hash a string for stable shard distribution
uint64_t hash_string(const std::string& s) {
    // FNV-1a 64-bit
    uint64_t hash = 14695981039346656037ULL;
    for (char c : s) {
        hash ^= static_cast<uint64_t>(static_cast<uint8_t>(c));
        hash *= 1099511628211ULL;
    }
    return hash;
}

} // anonymous namespace

// ============================================================================
// SECTION 1: Data Structures
// ============================================================================

// --------------------------------------------------------------------------
// NoticeType - classification of server notices
// --------------------------------------------------------------------------
enum class NoticeType : uint8_t {
    POLICY_VIOLATION,      // User violated server policy
    CONSENT_REQUIRED,       // User must consent to new privacy policy
    ACCOUNT_EXPIRATION,     // Account will expire / is expired
    SERVER_MIGRATION,       // Server is migrating, downtime upcoming
    MAINTENANCE,            // Scheduled maintenance
    ANNOUNCEMENT,           // General announcement
    SECURITY_ALERT,         // Security-related notice
    WELCOME,                // Welcome message for new users
    CUSTOM,                 // Admin-defined custom notice
    UNKNOWN = 255
};

// --------------------------------------------------------------------------
// NoticePriority - urgency level
// --------------------------------------------------------------------------
enum class NoticePriority : uint8_t {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

// --------------------------------------------------------------------------
// NoticeStatus - lifecycle status of a notice
// --------------------------------------------------------------------------
enum class NoticeStatus : uint8_t {
    DRAFT = 0,
    SCHEDULED = 1,
    SENDING = 2,
    SENT = 3,
    PARTIALLY_FAILED = 4,
    FAILED = 5,
    CANCELLED = 6,
    ARCHIVED = 7
};

// --------------------------------------------------------------------------
// DeliveryStatus - per-user delivery tracking
// --------------------------------------------------------------------------
enum class DeliveryStatus : uint8_t {
    PENDING = 0,
    QUEUED = 1,
    DELIVERED = 2,
    READ = 3,
    FAILED = 4,
    UNSUBSCRIBED = 5,
    OVERRIDDEN = 6
};

// Convert enums to/from strings
std::string notice_type_to_string(NoticeType t) {
    switch (t) {
        case NoticeType::POLICY_VIOLATION:    return "policy_violation";
        case NoticeType::CONSENT_REQUIRED:    return "consent_required";
        case NoticeType::ACCOUNT_EXPIRATION:  return "account_expiration";
        case NoticeType::SERVER_MIGRATION:    return "server_migration";
        case NoticeType::MAINTENANCE:         return "maintenance";
        case NoticeType::ANNOUNCEMENT:        return "announcement";
        case NoticeType::SECURITY_ALERT:      return "security_alert";
        case NoticeType::WELCOME:             return "welcome";
        case NoticeType::CUSTOM:              return "custom";
        default:                              return "unknown";
    }
}

NoticeType string_to_notice_type(const std::string& s) {
    if (s == "policy_violation")    return NoticeType::POLICY_VIOLATION;
    if (s == "consent_required")    return NoticeType::CONSENT_REQUIRED;
    if (s == "account_expiration")  return NoticeType::ACCOUNT_EXPIRATION;
    if (s == "server_migration")    return NoticeType::SERVER_MIGRATION;
    if (s == "maintenance")         return NoticeType::MAINTENANCE;
    if (s == "announcement")        return NoticeType::ANNOUNCEMENT;
    if (s == "security_alert")      return NoticeType::SECURITY_ALERT;
    if (s == "welcome")             return NoticeType::WELCOME;
    if (s == "custom")              return NoticeType::CUSTOM;
    return NoticeType::UNKNOWN;
}

std::string priority_to_string(NoticePriority p) {
    switch (p) {
        case NoticePriority::LOW:      return "low";
        case NoticePriority::NORMAL:   return "normal";
        case NoticePriority::HIGH:     return "high";
        case NoticePriority::CRITICAL: return "critical";
    }
    return "normal";
}

NoticePriority string_to_priority(const std::string& s) {
    if (s == "low")      return NoticePriority::LOW;
    if (s == "normal")   return NoticePriority::NORMAL;
    if (s == "high")     return NoticePriority::HIGH;
    if (s == "critical") return NoticePriority::CRITICAL;
    return NoticePriority::NORMAL;
}

std::string status_to_string(NoticeStatus s) {
    switch (s) {
        case NoticeStatus::DRAFT:              return "draft";
        case NoticeStatus::SCHEDULED:          return "scheduled";
        case NoticeStatus::SENDING:            return "sending";
        case NoticeStatus::SENT:               return "sent";
        case NoticeStatus::PARTIALLY_FAILED:   return "partially_failed";
        case NoticeStatus::FAILED:             return "failed";
        case NoticeStatus::CANCELLED:          return "cancelled";
        case NoticeStatus::ARCHIVED:           return "archived";
    }
    return "unknown";
}

std::string delivery_status_to_string(DeliveryStatus s) {
    switch (s) {
        case DeliveryStatus::PENDING:       return "pending";
        case DeliveryStatus::QUEUED:        return "queued";
        case DeliveryStatus::DELIVERED:     return "delivered";
        case DeliveryStatus::READ:          return "read";
        case DeliveryStatus::FAILED:        return "failed";
        case DeliveryStatus::UNSUBSCRIBED:  return "unsubscribed";
        case DeliveryStatus::OVERRIDDEN:    return "overridden";
    }
    return "unknown";
}

// --------------------------------------------------------------------------
// LocalizedString - holds translations keyed by language code
// --------------------------------------------------------------------------
struct LocalizedString {
    std::string default_text;  // "en" or fallback
    std::unordered_map<std::string, std::string> translations;  // "fr" -> "..."

    std::string get(const std::string& lang) const {
        auto it = translations.find(lang);
        if (it != translations.end() && !it->second.empty()) {
            return it->second;
        }
        return default_text;
    }

    void set(const std::string& lang, const std::string& text) {
        if (lang.empty() || lang == "default") {
            default_text = text;
        } else {
            translations[lang] = text;
        }
    }

    json to_json() const {
        json j;
        j["default"] = default_text;
        json tr = json::object();
        for (const auto& [lang, text] : translations) {
            tr[lang] = text;
        }
        j["translations"] = tr;
        return j;
    }

    static LocalizedString from_json(const json& j) {
        LocalizedString ls;
        if (j.contains("default")) {
            ls.default_text = j["default"].get<std::string>();
        }
        if (j.contains("translations") && j["translations"].is_object()) {
            for (auto& [lang, text] : j["translations"].items()) {
                ls.translations[lang] = text.get<std::string>();
            }
        }
        return ls;
    }
};

// --------------------------------------------------------------------------
// NoticeTemplate - predefined or admin-created template
// --------------------------------------------------------------------------
struct NoticeTemplate {
    std::string id;
    std::string name;
    NoticeType type = NoticeType::CUSTOM;
    LocalizedString subject;
    LocalizedString body_plain;
    LocalizedString body_html;
    std::vector<std::string> required_vars;  // e.g. {"username", "expiry_date"}
    std::unordered_map<std::string, std::string> default_vars;
    std::string category;
    int64_t created_at = 0;
    int64_t updated_at = 0;
    std::string created_by;  // admin user_id
    bool is_system = false;  // built-in template, cannot be deleted
    bool is_active = true;

    json to_json() const {
        json j;
        j["id"] = id;
        j["name"] = name;
        j["type"] = notice_type_to_string(type);
        j["subject"] = subject.to_json();
        j["body_plain"] = body_plain.to_json();
        j["body_html"] = body_html.to_json();
        j["required_vars"] = required_vars;
        j["default_vars"] = default_vars;
        j["category"] = category;
        j["created_at"] = created_at;
        j["updated_at"] = updated_at;
        j["created_by"] = created_by;
        j["is_system"] = is_system;
        j["is_active"] = is_active;
        return j;
    }

    static NoticeTemplate from_json(const json& j) {
        NoticeTemplate t;
        t.id = j.value("id", "");
        t.name = j.value("name", "");
        t.type = string_to_notice_type(j.value("type", "custom"));
        if (j.contains("subject")) t.subject = LocalizedString::from_json(j["subject"]);
        if (j.contains("body_plain")) t.body_plain = LocalizedString::from_json(j["body_plain"]);
        if (j.contains("body_html")) t.body_html = LocalizedString::from_json(j["body_html"]);
        if (j.contains("required_vars")) {
            for (const auto& v : j["required_vars"]) {
                t.required_vars.push_back(v.get<std::string>());
            }
        }
        if (j.contains("default_vars")) {
            for (auto& [k, v] : j["default_vars"].items()) {
                t.default_vars[k] = v.get<std::string>();
            }
        }
        t.category = j.value("category", "");
        t.created_at = j.value("created_at", 0LL);
        t.updated_at = j.value("updated_at", 0LL);
        t.created_by = j.value("created_by", "");
        t.is_system = j.value("is_system", false);
        t.is_active = j.value("is_active", true);
        return t;
    }
};

// --------------------------------------------------------------------------
// NoticeRecipient - target user and delivery info for a notice
// --------------------------------------------------------------------------
struct NoticeRecipient {
    std::string user_id;
    std::string notice_id;
    DeliveryStatus status = DeliveryStatus::PENDING;
    int64_t queued_at = 0;
    int64_t delivered_at = 0;
    int64_t read_at = 0;
    int64_t last_attempt_at = 0;
    int retry_count = 0;
    int max_retries = 3;
    std::string room_id;        // The server notice room for this user
    std::string event_id;       // The m.room.message event ID
    std::string error_message;
    std::string locale;         // Language used for this delivery

    json to_json() const {
        json j;
        j["user_id"] = user_id;
        j["notice_id"] = notice_id;
        j["status"] = delivery_status_to_string(status);
        j["queued_at"] = queued_at;
        j["delivered_at"] = delivered_at;
        j["read_at"] = read_at;
        j["last_attempt_at"] = last_attempt_at;
        j["retry_count"] = retry_count;
        j["max_retries"] = max_retries;
        j["room_id"] = room_id;
        j["event_id"] = event_id;
        j["error_message"] = error_message;
        j["locale"] = locale;
        return j;
    }
};

// --------------------------------------------------------------------------
// ServerNotice - the core notice entity
// --------------------------------------------------------------------------
struct ServerNotice {
    std::string id;
    std::string template_id;
    NoticeType type = NoticeType::CUSTOM;
    NoticePriority priority = NoticePriority::NORMAL;
    NoticeStatus status = NoticeStatus::DRAFT;
    LocalizedString subject;
    LocalizedString body_plain;
    LocalizedString body_html;
    std::unordered_map<std::string, std::string> variables;  // global vars
    std::vector<std::string> target_users;   // empty = all users
    std::vector<std::string> exclude_users;  // users to exclude
    std::string target_filter; // JSON filter expression for user targeting

    // Scheduling
    int64_t created_at = 0;
    int64_t scheduled_at = 0;   // When to send (0 = immediate)
    int64_t expires_at = 0;     // When notice becomes stale
    int64_t sent_at = 0;
    int64_t completed_at = 0;
    int64_t deadline_at = 0;    // Consent/action deadline

    // Tracking
    int total_targets = 0;
    int delivered_count = 0;
    int read_count = 0;
    int failed_count = 0;
    int unsubscribed_count = 0;

    // ACL
    bool allow_reply = false;    // Can users reply in the notice room?
    bool require_read_receipt = false;
    bool can_unsubscribe = true;

    // Moderation
    bool content_moderated = false;
    std::string moderation_status; // "approved", "pending", "rejected"
    std::string moderated_by;
    int64_t moderated_at = 0;

    // Metadata
    std::string created_by;
    std::string category;
    std::vector<std::string> tags;
    json extra_data;  // arbitrary admin metadata

    json to_json() const {
        json j;
        j["id"] = id;
        j["template_id"] = template_id;
        j["type"] = notice_type_to_string(type);
        j["priority"] = priority_to_string(priority);
        j["status"] = status_to_string(status);
        j["subject"] = subject.to_json();
        j["body_plain"] = body_plain.to_json();
        j["body_html"] = body_html.to_json();
        j["variables"] = variables;
        j["target_users"] = target_users;
        j["exclude_users"] = exclude_users;
        j["target_filter"] = target_filter;
        j["created_at"] = created_at;
        j["scheduled_at"] = scheduled_at;
        j["expires_at"] = expires_at;
        j["sent_at"] = sent_at;
        j["completed_at"] = completed_at;
        j["deadline_at"] = deadline_at;
        j["total_targets"] = total_targets;
        j["delivered_count"] = delivered_count;
        j["read_count"] = read_count;
        j["failed_count"] = failed_count;
        j["unsubscribed_count"] = unsubscribed_count;
        j["allow_reply"] = allow_reply;
        j["require_read_receipt"] = require_read_receipt;
        j["can_unsubscribe"] = can_unsubscribe;
        j["content_moderated"] = content_moderated;
        j["moderation_status"] = moderation_status;
        j["moderated_by"] = moderated_by;
        j["moderated_at"] = moderated_at;
        j["created_by"] = created_by;
        j["category"] = category;
        j["tags"] = tags;
        j["extra_data"] = extra_data;
        return j;
    }

    static ServerNotice from_json(const json& j) {
        ServerNotice n;
        n.id = j.value("id", "");
        n.template_id = j.value("template_id", "");
        n.type = string_to_notice_type(j.value("type", "custom"));
        n.priority = string_to_priority(j.value("priority", "normal"));
        n.status = NoticeStatus::DRAFT;  // doesn't come from JSON
        if (j.contains("subject")) n.subject = LocalizedString::from_json(j["subject"]);
        if (j.contains("body_plain")) n.body_plain = LocalizedString::from_json(j["body_plain"]);
        if (j.contains("body_html")) n.body_html = LocalizedString::from_json(j["body_html"]);
        if (j.contains("variables")) {
            for (auto& [k, v] : j["variables"].items()) {
                n.variables[k] = v.get<std::string>();
            }
        }
        if (j.contains("target_users")) {
            for (const auto& u : j["target_users"]) {
                n.target_users.push_back(u.get<std::string>());
            }
        }
        if (j.contains("exclude_users")) {
            for (const auto& u : j["exclude_users"]) {
                n.exclude_users.push_back(u.get<std::string>());
            }
        }
        n.target_filter = j.value("target_filter", "");
        n.created_at = j.value("created_at", 0LL);
        n.scheduled_at = j.value("scheduled_at", 0LL);
        n.expires_at = j.value("expires_at", 0LL);
        n.deadline_at = j.value("deadline_at", 0LL);
        n.allow_reply = j.value("allow_reply", false);
        n.require_read_receipt = j.value("require_read_receipt", false);
        n.can_unsubscribe = j.value("can_unsubscribe", true);
        n.created_by = j.value("created_by", "");
        n.category = j.value("category", "");
        if (j.contains("tags")) {
            for (const auto& t : j["tags"]) {
                n.tags.push_back(t.get<std::string>());
            }
        }
        n.extra_data = j.value("extra_data", json::object());
        return n;
    }
};

// --------------------------------------------------------------------------
// UserNoticePreferences - per-user notice settings
// --------------------------------------------------------------------------
struct UserNoticePreferences {
    std::string user_id;
    std::string locale = "en";
    bool notices_enabled = true;
    std::unordered_set<NoticeType> unsubscribed_types;
    std::unordered_set<std::string> unsubscribed_categories;
    std::unordered_set<std::string> unsubscribed_notice_ids;
    bool override_quiet_hours = false;
    int quiet_hours_start = 0;  // 0-23 hour
    int quiet_hours_end = 0;
    std::string override_language;
    int64_t updated_at = 0;

    bool can_receive(NoticeType type, const std::string& category,
                     const std::string& notice_id) const {
        if (!notices_enabled) return false;
        if (unsubscribed_types.count(type)) return false;
        if (!category.empty() && unsubscribed_categories.count(category)) return false;
        if (!notice_id.empty() && unsubscribed_notice_ids.count(notice_id)) return false;
        return true;
    }

    json to_json() const {
        json j;
        j["user_id"] = user_id;
        j["locale"] = locale;
        j["notices_enabled"] = notices_enabled;
        json ut = json::array();
        for (auto& t : unsubscribed_types) ut.push_back(notice_type_to_string(t));
        j["unsubscribed_types"] = ut;
        json uc = json::array();
        for (auto& c : unsubscribed_categories) uc.push_back(c);
        j["unsubscribed_categories"] = uc;
        json un = json::array();
        for (auto& n : unsubscribed_notice_ids) un.push_back(n);
        j["unsubscribed_notice_ids"] = un;
        j["override_quiet_hours"] = override_quiet_hours;
        j["quiet_hours_start"] = quiet_hours_start;
        j["quiet_hours_end"] = quiet_hours_end;
        j["override_language"] = override_language;
        j["updated_at"] = updated_at;
        return j;
    }

    static UserNoticePreferences from_json(const json& j) {
        UserNoticePreferences p;
        p.user_id = j.value("user_id", "");
        p.locale = j.value("locale", "en");
        p.notices_enabled = j.value("notices_enabled", true);
        if (j.contains("unsubscribed_types")) {
            for (const auto& t : j["unsubscribed_types"]) {
                p.unsubscribed_types.insert(string_to_notice_type(t.get<std::string>()));
            }
        }
        if (j.contains("unsubscribed_categories")) {
            for (const auto& c : j["unsubscribed_categories"]) {
                p.unsubscribed_categories.insert(c.get<std::string>());
            }
        }
        if (j.contains("unsubscribed_notice_ids")) {
            for (const auto& n : j["unsubscribed_notice_ids"]) {
                p.unsubscribed_notice_ids.insert(n.get<std::string>());
            }
        }
        p.override_quiet_hours = j.value("override_quiet_hours", false);
        p.quiet_hours_start = j.value("quiet_hours_start", 0);
        p.quiet_hours_end = j.value("quiet_hours_end", 0);
        p.override_language = j.value("override_language", "");
        p.updated_at = j.value("updated_at", 0LL);
        return p;
    }
};

// --------------------------------------------------------------------------
// ServerNoticeRoom - represents the notice room between server and user
// --------------------------------------------------------------------------
struct ServerNoticeRoom {
    std::string room_id;
    std::string user_id;        // One room per user
    std::string server_user_id; // The server's virtual user (e.g., @server:localhost)
    int64_t created_at = 0;
    int64_t last_activity = 0;
    json room_state;            // Room creation state
    json room_version;

    // ACL
    bool user_can_send = false;               // User can send messages?
    int user_power_level = 0;                 // Default: 0
    int server_power_level = 100;             // Default: 100
    std::vector<std::string> allowed_event_types;  // Events user can send
    bool is_active = true;

    json to_json() const {
        json j;
        j["room_id"] = room_id;
        j["user_id"] = user_id;
        j["server_user_id"] = server_user_id;
        j["created_at"] = created_at;
        j["last_activity"] = last_activity;
        j["room_state"] = room_state;
        j["room_version"] = room_version;
        j["user_can_send"] = user_can_send;
        j["user_power_level"] = user_power_level;
        j["server_power_level"] = server_power_level;
        j["allowed_event_types"] = allowed_event_types;
        j["is_active"] = is_active;
        return j;
    }
};

// --------------------------------------------------------------------------
// BatchJob - for bulk notice delivery with backpressure
// --------------------------------------------------------------------------
struct BatchJob {
    std::string batch_id;
    std::string notice_id;
    int64_t created_at = 0;
    int64_t started_at = 0;
    int64_t completed_at = 0;
    int total_recipients = 0;
    int processed_count = 0;
    int success_count = 0;
    int failure_count = 0;
    bool is_active = false;
    bool is_paused = false;

    // Backpressure
    int max_concurrent = 10;
    int batch_size = 100;
    int delay_between_batches_ms = 500;
    int current_concurrent = 0;

    // Ordered queue of recipients to process
    std::deque<std::string> pending_user_ids;

    enum class State { IDLE, RUNNING, PAUSED, COMPLETED, FAILED };
    State state = State::IDLE;
};

// ============================================================================
// SECTION 2: Built-in Notice Templates
// ============================================================================

class NoticeTemplateLibrary {
public:
    NoticeTemplateLibrary() {
        initialize_system_templates();
    }

    // ----------------------------------------------------------------------
    // Get a template by ID
    // ----------------------------------------------------------------------
    std::optional<NoticeTemplate> get(const std::string& id) const {
        std::shared_lock lock(mu_);
        auto it = templates_.find(id);
        if (it != templates_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // ----------------------------------------------------------------------
    // Get all templates
    // ----------------------------------------------------------------------
    std::vector<NoticeTemplate> list_all() const {
        std::shared_lock lock(mu_);
        std::vector<NoticeTemplate> result;
        result.reserve(templates_.size());
        for (const auto& [id, tpl] : templates_) {
            result.push_back(tpl);
        }
        return result;
    }

    // ----------------------------------------------------------------------
    // Get templates by type
    // ----------------------------------------------------------------------
    std::vector<NoticeTemplate> list_by_type(NoticeType type) const {
        std::shared_lock lock(mu_);
        std::vector<NoticeTemplate> result;
        for (const auto& [id, tpl] : templates_) {
            if (tpl.type == type) result.push_back(tpl);
        }
        return result;
    }

    // ----------------------------------------------------------------------
    // Add or update a template
    // ----------------------------------------------------------------------
    bool upsert(const NoticeTemplate& tpl) {
        std::unique_lock lock(mu_);
        templates_[tpl.id] = tpl;
        return true;
    }

    // ----------------------------------------------------------------------
    // Delete a template (non-system only)
    // ----------------------------------------------------------------------
    bool remove(const std::string& id) {
        std::unique_lock lock(mu_);
        auto it = templates_.find(id);
        if (it != templates_.end() && !it->second.is_system) {
            templates_.erase(it);
            return true;
        }
        return false;
    }

    // ----------------------------------------------------------------------
    // Render a notice from template + variables
    // ----------------------------------------------------------------------
    std::pair<std::string, std::string> render(
        const std::string& template_id,
        const std::unordered_map<std::string, std::string>& vars,
        const std::string& locale = "en") const {
        auto tpl_opt = get(template_id);
        if (!tpl_opt) {
            return {"", ""};
        }
        const auto& tpl = *tpl_opt;

        // Merge default vars with provided vars
        std::unordered_map<std::string, std::string> merged = tpl.default_vars;
        for (const auto& [k, v] : vars) {
            merged[k] = v;
        }

        std::string plain = apply_template_vars(tpl.body_plain.get(locale), merged);
        std::string html = apply_template_vars(tpl.body_html.get(locale), merged);
        if (html.empty()) {
            html = markdown_to_html(plain);
        }
        return {plain, html};
    }

private:
    void initialize_system_templates() {
        // ------------------------------------------------------------------
        // Policy Violation
        // ------------------------------------------------------------------
        {
            NoticeTemplate tpl;
            tpl.id = "system_policy_violation";
            tpl.name = "Policy Violation";
            tpl.type = NoticeType::POLICY_VIOLATION;
            tpl.is_system = true;
            tpl.category = "compliance";

            tpl.subject.set("default",
                "Policy Violation Notice - {{server_name}}");
            tpl.body_plain.set("default",
                "Dear {{display_name}},\n\n"
                "This is an official notice from the {{server_name}} server "
                "administration.\n\n"
                "Your account (@{{user_id}}) has been found in violation of "
                "the following server policy:\n\n"
                "  **{{policy_name}}**\n\n"
                "Reason: {{violation_reason}}\n\n"
                "You are required to take the following action(s):\n"
                "  {{required_actions}}\n\n"
                "Deadline for compliance: {{deadline}}\n\n"
                "If you do not comply by the deadline, your account may be "
                "subject to further moderation actions including suspension "
                "or deactivation.\n\n"
                "If you believe this is in error, please contact the server "
                "administrator at {{admin_contact}}.\n\n"
                "— The {{server_name}} Team");
            tpl.body_html.set("default",
                "<p>Dear {{display_name}},</p>"
                "<p>This is an official notice from the <strong>{{server_name}}</strong> "
                "server administration.</p>"
                "<p>Your account (<code>@{{user_id}}</code>) has been found in "
                "violation of the following server policy:</p>"
                "<blockquote><strong>{{policy_name}}</strong></blockquote>"
                "<p><strong>Reason:</strong> {{violation_reason}}</p>"
                "<p><strong>Required actions:</strong> {{required_actions}}</p>"
                "<p><strong>Deadline:</strong> {{deadline}}</p>"
                "<p>If you do not comply by the deadline, your account may be "
                "subject to further moderation actions including suspension "
                "or deactivation.</p>"
                "<p>If you believe this is in error, please contact the server "
                "administrator at {{admin_contact}}.</p>"
                "<p>— The {{server_name}} Team</p>");

            tpl.required_vars = {"user_id", "display_name", "server_name",
                "policy_name", "violation_reason", "required_actions",
                "deadline", "admin_contact"};
            tpl.created_at = now_sec();
            tpl.updated_at = tpl.created_at;

            templates_[tpl.id] = tpl;
        }

        // ------------------------------------------------------------------
        // Consent Required
        // ------------------------------------------------------------------
        {
            NoticeTemplate tpl;
            tpl.id = "system_consent_required";
            tpl.name = "Consent Required";
            tpl.type = NoticeType::CONSENT_REQUIRED;
            tpl.is_system = true;
            tpl.category = "compliance";

            tpl.subject.set("default",
                "Privacy Policy Update - Action Required - {{server_name}}");
            tpl.body_plain.set("default",
                "Dear {{display_name}},\n\n"
                "The privacy policy and/or terms of service for "
                "{{server_name}} have been updated.\n\n"
                "**New Policy Version:** {{policy_version}}\n\n"
                "You are required to review and accept the updated policy to "
                "continue using the service. You can review the full policy at:\n"
                "  {{policy_url}}\n\n"
                "To accept, please visit your account settings or use the "
                "following link:\n"
                "  {{consent_url}}\n\n"
                "Deadline for acceptance: {{deadline}}\n\n"
                "If you do not accept by the deadline, your account access "
                "may be restricted until consent is provided.\n\n"
                "A summary of changes:\n"
                "{{changes_summary}}\n\n"
                "— The {{server_name}} Team");
            tpl.body_html.set("default",
                "<p>Dear {{display_name}},</p>"
                "<p>The privacy policy and/or terms of service for "
                "<strong>{{server_name}}</strong> have been updated.</p>"
                "<p><strong>New Policy Version:</strong> {{policy_version}}</p>"
                "<p>You are required to review and accept the updated policy to "
                "continue using the service.</p>"
                "<p><a href='{{policy_url}}'>Review the full policy</a></p>"
                "<p><a href='{{consent_url}}'>Accept the updated policy</a></p>"
                "<p><strong>Deadline for acceptance:</strong> {{deadline}}</p>"
                "<p>If you do not accept by the deadline, your account access "
                "may be restricted until consent is provided.</p>"
                "<p><strong>Summary of changes:</strong><br/>{{changes_summary}}</p>"
                "<p>— The {{server_name}} Team</p>");

            tpl.required_vars = {"user_id", "display_name", "server_name",
                "policy_version", "policy_url", "consent_url", "deadline",
                "changes_summary"};
            tpl.created_at = now_sec();
            tpl.updated_at = tpl.created_at;

            templates_[tpl.id] = tpl;
        }

        // ------------------------------------------------------------------
        // Account Expiration
        // ------------------------------------------------------------------
        {
            NoticeTemplate tpl;
            tpl.id = "system_account_expiration";
            tpl.name = "Account Expiration";
            tpl.type = NoticeType::ACCOUNT_EXPIRATION;
            tpl.is_system = true;
            tpl.category = "account";

            tpl.subject.set("default",
                "Account Expiration Notice - {{server_name}}");
            tpl.body_plain.set("default",
                "Dear {{display_name}},\n\n"
                "Your account (@{{user_id}}) on {{server_name}} is set to "
                "expire on {{expiry_date}}.\n\n"
                "Reason: {{expiry_reason}}\n\n"
                "To prevent disruption of service, please take the following "
                "action:\n\n"
                "  {{required_action}}\n\n"
                "After the expiration date, your account will be "
                "{{post_expiry_action}}.\n\n"
                "If you have any questions, please contact {{admin_contact}}.\n\n"
                "— The {{server_name}} Team");
            tpl.body_html.set("default",
                "<p>Dear {{display_name}},</p>"
                "<p>Your account (<code>@{{user_id}}</code>) on "
                "<strong>{{server_name}}</strong> is set to expire on "
                "<strong>{{expiry_date}}</strong>.</p>"
                "<p><strong>Reason:</strong> {{expiry_reason}}</p>"
                "<p><strong>Required action:</strong> {{required_action}}</p>"
                "<p>After the expiration date, your account will be "
                "{{post_expiry_action}}.</p>"
                "<p>If you have any questions, please contact {{admin_contact}}.</p>"
                "<p>— The {{server_name}} Team</p>");

            tpl.required_vars = {"user_id", "display_name", "server_name",
                "expiry_date", "expiry_reason", "required_action",
                "post_expiry_action", "admin_contact"};
            tpl.created_at = now_sec();
            tpl.updated_at = tpl.created_at;

            templates_[tpl.id] = tpl;
        }

        // ------------------------------------------------------------------
        // Server Migration
        // ------------------------------------------------------------------
        {
            NoticeTemplate tpl;
            tpl.id = "system_server_migration";
            tpl.name = "Server Migration";
            tpl.type = NoticeType::SERVER_MIGRATION;
            tpl.is_system = true;
            tpl.category = "infrastructure";

            tpl.subject.set("default",
                "Server Migration Notice - {{server_name}}");
            tpl.body_plain.set("default",
                "Dear {{display_name}},\n\n"
                "The {{server_name}} server will be undergoing a migration.\n\n"
                "**Migration Window:**\n"
                "  Start: {{migration_start}}\n"
                "  Expected End: {{migration_end}}\n\n"
                "During this period, the service may experience:\n"
                "  {{expected_impact}}\n\n"
                "**What you need to know:**\n"
                "  New Server Address: {{new_server_address}}\n"
                "  Actions Required: {{user_actions}}\n\n"
                "We will provide updates as the migration progresses. If you "
                "experience any issues after the migration, please contact "
                "{{admin_contact}}.\n\n"
                "— The {{server_name}} Team");
            tpl.body_html.set("default",
                "<p>Dear {{display_name}},</p>"
                "<p>The <strong>{{server_name}}</strong> server will be "
                "undergoing a migration.</p>"
                "<p><strong>Migration Window:</strong></p>"
                "<ul><li>Start: {{migration_start}}</li>"
                "<li>Expected End: {{migration_end}}</li></ul>"
                "<p><strong>Expected Impact:</strong> {{expected_impact}}</p>"
                "<p><strong>New Server Address:</strong> {{new_server_address}}</p>"
                "<p><strong>Actions Required:</strong> {{user_actions}}</p>"
                "<p>We will provide updates as the migration progresses.</p>"
                "<p>— The {{server_name}} Team</p>");

            tpl.required_vars = {"user_id", "display_name", "server_name",
                "migration_start", "migration_end", "expected_impact",
                "new_server_address", "user_actions", "admin_contact"};
            tpl.created_at = now_sec();
            tpl.updated_at = tpl.created_at;

            templates_[tpl.id] = tpl;
        }

        // ------------------------------------------------------------------
        // Maintenance
        // ------------------------------------------------------------------
        {
            NoticeTemplate tpl;
            tpl.id = "system_maintenance";
            tpl.name = "Maintenance";
            tpl.type = NoticeType::MAINTENANCE;
            tpl.is_system = true;
            tpl.category = "infrastructure";

            tpl.subject.set("default",
                "Scheduled Maintenance - {{server_name}}");
            tpl.body_plain.set("default",
                "Dear {{display_name}},\n\n"
                "Scheduled maintenance is planned for {{server_name}}.\n\n"
                "**Maintenance Details:**\n"
                "  Date: {{maintenance_date}}\n"
                "  Window: {{maintenance_window}}\n"
                "  Expected Downtime: {{expected_downtime}}\n\n"
                "**Affected Services:**\n"
                "  {{affected_services}}\n\n"
                "**Work Description:**\n"
                "  {{work_description}}\n\n"
                "Please save any unsaved work before the maintenance window "
                "begins. We will notify you when the maintenance is complete.\n\n"
                "— The {{server_name}} Team");
            tpl.body_html.set("default",
                "<p>Dear {{display_name}},</p>"
                "<p>Scheduled maintenance is planned for "
                "<strong>{{server_name}}</strong>.</p>"
                "<p><strong>Maintenance Details:</strong></p>"
                "<ul><li>Date: {{maintenance_date}}</li>"
                "<li>Window: {{maintenance_window}}</li>"
                "<li>Expected Downtime: {{expected_downtime}}</li></ul>"
                "<p><strong>Affected Services:</strong> {{affected_services}}</p>"
                "<p><strong>Work Description:</strong> {{work_description}}</p>"
                "<p>Please save any unsaved work before the maintenance window "
                "begins. We will notify you when the maintenance is complete.</p>"
                "<p>— The {{server_name}} Team</p>");

            tpl.required_vars = {"user_id", "display_name", "server_name",
                "maintenance_date", "maintenance_window", "expected_downtime",
                "affected_services", "work_description"};
            tpl.created_at = now_sec();
            tpl.updated_at = tpl.created_at;

            templates_[tpl.id] = tpl;
        }

        // ------------------------------------------------------------------
        // Security Alert
        // ------------------------------------------------------------------
        {
            NoticeTemplate tpl;
            tpl.id = "system_security_alert";
            tpl.name = "Security Alert";
            tpl.type = NoticeType::SECURITY_ALERT;
            tpl.is_system = true;
            tpl.category = "security";

            tpl.subject.set("default",
                "Security Alert - {{server_name}}");
            tpl.body_plain.set("default",
                "Dear {{display_name}},\n\n"
                "This is a security alert from {{server_name}}.\n\n"
                "**Alert:** {{alert_type}}\n"
                "**Severity:** {{severity}}\n\n"
                "{{alert_description}}\n\n"
                "**Recommended Actions:**\n"
                "  {{recommended_actions}}\n\n"
                "If you have any concerns, please contact {{admin_contact}} "
                "immediately.\n\n"
                "— The {{server_name}} Security Team");
            tpl.body_html.set("default",
                "<p>Dear {{display_name}},</p>"
                "<p>This is a <strong>security alert</strong> from "
                "{{server_name}}.</p>"
                "<p><strong>Alert:</strong> {{alert_type}} "
                "(Severity: {{severity}})</p>"
                "<p>{{alert_description}}</p>"
                "<p><strong>Recommended Actions:</strong> "
                "{{recommended_actions}}</p>"
                "<p>If you have any concerns, please contact {{admin_contact}} "
                "immediately.</p>"
                "<p>— The {{server_name}} Security Team</p>");

            tpl.required_vars = {"user_id", "display_name", "server_name",
                "alert_type", "severity", "alert_description",
                "recommended_actions", "admin_contact"};
            tpl.created_at = now_sec();
            tpl.updated_at = tpl.created_at;

            templates_[tpl.id] = tpl;
        }

        // ------------------------------------------------------------------
        // Welcome
        // ------------------------------------------------------------------
        {
            NoticeTemplate tpl;
            tpl.id = "system_welcome";
            tpl.name = "Welcome";
            tpl.type = NoticeType::WELCOME;
            tpl.is_system = true;
            tpl.category = "onboarding";

            tpl.subject.set("default",
                "Welcome to {{server_name}}!");
            tpl.body_plain.set("default",
                "Welcome to {{server_name}}, {{display_name}}!\n\n"
                "Your account (@{{user_id}}) has been created successfully.\n\n"
                "**Getting Started:**\n"
                "  * Explore public rooms: {{public_rooms_url}}\n"
                "  * Set up your profile: {{profile_url}}\n"
                "  * Read the server rules: {{rules_url}}\n"
                "  * Get help: {{help_url}}\n\n"
                "Your server homeserver is: {{homeserver}}\n\n"
                "If you have any questions, the community is here to help.\n\n"
                "Welcome aboard!\n"
                "— The {{server_name}} Team");
            tpl.body_html.set("default",
                "<p>Welcome to <strong>{{server_name}}</strong>, "
                "{{display_name}}!</p>"
                "<p>Your account (<code>@{{user_id}}</code>) has been created "
                "successfully.</p>"
                "<p><strong>Getting Started:</strong></p>"
                "<ul>"
                "<li><a href='{{public_rooms_url}}'>Explore public rooms</a></li>"
                "<li><a href='{{profile_url}}'>Set up your profile</a></li>"
                "<li><a href='{{rules_url}}'>Read the server rules</a></li>"
                "<li><a href='{{help_url}}'>Get help</a></li>"
                "</ul>"
                "<p>Your homeserver: <code>{{homeserver}}</code></p>"
                "<p>Welcome aboard!</p>"
                "<p>— The {{server_name}} Team</p>");

            tpl.required_vars = {"user_id", "display_name", "server_name",
                "homeserver", "public_rooms_url", "profile_url",
                "rules_url", "help_url"};
            tpl.created_at = now_sec();
            tpl.updated_at = tpl.created_at;

            templates_[tpl.id] = tpl;
        }

        // ------------------------------------------------------------------
        // Generic Announcement
        // ------------------------------------------------------------------
        {
            NoticeTemplate tpl;
            tpl.id = "system_announcement";
            tpl.name = "General Announcement";
            tpl.type = NoticeType::ANNOUNCEMENT;
            tpl.is_system = true;
            tpl.category = "general";

            tpl.subject.set("default",
                "{{announcement_title}} - {{server_name}}");
            tpl.body_plain.set("default",
                "Dear {{display_name}},\n\n"
                "{{announcement_body}}\n\n"
                "— The {{server_name}} Team");
            tpl.body_html.set("default",
                "<p>Dear {{display_name}},</p>"
                "<p>{{announcement_body}}</p>"
                "<p>— The {{server_name}} Team</p>");

            tpl.required_vars = {"user_id", "display_name", "server_name",
                "announcement_title", "announcement_body"};
            tpl.created_at = now_sec();
            tpl.updated_at = tpl.created_at;

            templates_[tpl.id] = tpl;
        }
    }

    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, NoticeTemplate> templates_;
};

// ============================================================================
// SECTION 3: Server Notice Room Manager
// ============================================================================

class ServerNoticeRoomManager {
public:
    ServerNoticeRoomManager() = default;

    // ----------------------------------------------------------------------
    // Create a server notice room for a user
    // ----------------------------------------------------------------------
    ServerNoticeRoom create_room(const std::string& user_id,
                                  const std::string& server_user_id) {
        std::unique_lock lock(mu_);

        // Check for existing active room
        auto it = user_rooms_.find(user_id);
        if (it != user_rooms_.end() && it->second.is_active) {
            return it->second;
        }

        ServerNoticeRoom room;
        room.room_id = generate_room_id();
        room.user_id = user_id;
        room.server_user_id = server_user_id.empty()
            ? "@server-notice:localhost" : server_user_id;
        room.created_at = now_sec();
        room.last_activity = room.created_at;
        room.user_can_send = false;
        room.user_power_level = 0;
        room.server_power_level = 100;
        room.allowed_event_types = {"m.reaction", "m.room.redaction"};
        room.is_active = true;

        // Build room creation state (Matrix spec room creation event)
        json creation_event;
        creation_event["type"] = "m.room.create";
        creation_event["content"]["creator"] = room.server_user_id;
        creation_event["content"]["room_version"] = "10";
        creation_event["content"]["predecessor"] = json::object();
        room.room_state = creation_event;

        // Member events
        json member_server;
        member_server["type"] = "m.room.member";
        member_server["state_key"] = room.server_user_id;
        member_server["content"]["membership"] = "join";
        member_server["content"]["displayname"] = "Server Notices";

        json member_user;
        member_user["type"] = "m.room.member";
        member_user["state_key"] = user_id;
        member_user["content"]["membership"] = "invite";

        // Power levels
        json power_levels;
        power_levels["type"] = "m.room.power_levels";
        power_levels["content"]["users"][room.server_user_id] = room.server_power_level;
        power_levels["content"]["users"][user_id] = room.user_power_level;
        power_levels["content"]["users_default"] = 0;
        power_levels["content"]["events_default"] = 50;
        for (const auto& ev_type : room.allowed_event_types) {
            power_levels["content"]["events"][ev_type] = 0;
        }

        // Room name and topic
        json room_name;
        room_name["type"] = "m.room.name";
        room_name["content"]["name"] = "Server Notices";

        json room_topic;
        room_topic["type"] = "m.room.topic";
        room_topic["content"]["topic"] = "Official announcements and notices "
            "from the server administration. This is a read-only channel.";

        room.room_state["initial_state"] = json::array({
            member_server, member_user, power_levels, room_name, room_topic
        });

        room.room_version["version"] = "10";

        user_rooms_[user_id] = room;
        room_by_id_[room.room_id] = user_id;

        return room;
    }

    // ----------------------------------------------------------------------
    // Get a user's server notice room
    // ----------------------------------------------------------------------
    std::optional<ServerNoticeRoom> get_room_for_user(
        const std::string& user_id) const {
        std::shared_lock lock(mu_);
        auto it = user_rooms_.find(user_id);
        if (it != user_rooms_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // ----------------------------------------------------------------------
    // Get a room by its room_id
    // ----------------------------------------------------------------------
    std::optional<ServerNoticeRoom> get_room_by_id(
        const std::string& room_id) const {
        std::shared_lock lock(mu_);
        auto it = room_by_id_.find(room_id);
        if (it != room_by_id_.end()) {
            auto rit = user_rooms_.find(it->second);
            if (rit != user_rooms_.end()) {
                return rit->second;
            }
        }
        return std::nullopt;
    }

    // ----------------------------------------------------------------------
    // Update room ACLs: set whether user can send messages
    // ----------------------------------------------------------------------
    bool set_user_can_send(const std::string& room_id, bool can_send) {
        std::unique_lock lock(mu_);
        auto it = room_by_id_.find(room_id);
        if (it == room_by_id_.end()) return false;
        auto rit = user_rooms_.find(it->second);
        if (rit == user_rooms_.end()) return false;
        rit->second.user_can_send = can_send;
        rit->second.user_power_level = can_send ? 10 : 0;
        return true;
    }

    // ----------------------------------------------------------------------
    // Update room power levels
    // ----------------------------------------------------------------------
    bool set_power_levels(const std::string& room_id,
                          int user_level, int server_level) {
        std::unique_lock lock(mu_);
        auto it = room_by_id_.find(room_id);
        if (it == room_by_id_.end()) return false;
        auto rit = user_rooms_.find(it->second);
        if (rit == user_rooms_.end()) return false;
        rit->second.user_power_level = user_level;
        rit->second.server_power_level = server_level;
        return true;
    }

    // ----------------------------------------------------------------------
    // Set allowed event types for the user in a room
    // ----------------------------------------------------------------------
    bool set_allowed_event_types(const std::string& room_id,
                                  const std::vector<std::string>& types) {
        std::unique_lock lock(mu_);
        auto it = room_by_id_.find(room_id);
        if (it == room_by_id_.end()) return false;
        auto rit = user_rooms_.find(it->second);
        if (rit == user_rooms_.end()) return false;
        rit->second.allowed_event_types = types;
        return true;
    }

    // ----------------------------------------------------------------------
    // Deactivate a room
    // ----------------------------------------------------------------------
    bool deactivate_room(const std::string& room_id) {
        std::unique_lock lock(mu_);
        auto it = room_by_id_.find(room_id);
        if (it == room_by_id_.end()) return false;
        auto rit = user_rooms_.find(it->second);
        if (rit == user_rooms_.end()) return false;
        rit->second.is_active = false;
        return true;
    }

    // ----------------------------------------------------------------------
    // List all active rooms
    // ----------------------------------------------------------------------
    std::vector<ServerNoticeRoom> list_active_rooms() const {
        std::shared_lock lock(mu_);
        std::vector<ServerNoticeRoom> result;
        for (const auto& [user_id, room] : user_rooms_) {
            if (room.is_active) {
                result.push_back(room);
            }
        }
        return result;
    }

    // ----------------------------------------------------------------------
    // Count rooms
    // ----------------------------------------------------------------------
    size_t room_count() const {
        std::shared_lock lock(mu_);
        return user_rooms_.size();
    }

    // ----------------------------------------------------------------------
    // Get room ACL info as JSON for admin API
    // ----------------------------------------------------------------------
    json get_room_acl_json(const std::string& room_id) const {
        auto room_opt = get_room_by_id(room_id);
        json j;
        if (!room_opt) {
            j["error"] = "Room not found";
            return j;
        }
        const auto& room = *room_opt;
        j["room_id"] = room.room_id;
        j["user_id"] = room.user_id;
        j["user_can_send"] = room.user_can_send;
        j["user_power_level"] = room.user_power_level;
        j["server_power_level"] = room.server_power_level;
        j["allowed_event_types"] = room.allowed_event_types;
        j["is_active"] = room.is_active;
        return j;
    }

private:
    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, ServerNoticeRoom> user_rooms_;
    std::unordered_map<std::string, std::string> room_by_id_;  // room_id -> user_id
};

// ============================================================================
// SECTION 4: Server Notice Manager (Core)
// ============================================================================

class ServerNoticeManager {
public:
    ServerNoticeManager(NoticeTemplateLibrary& tpl_lib,
                        ServerNoticeRoomManager& room_mgr)
        : template_lib_(tpl_lib)
        , room_manager_(room_mgr) {}

    // ----------------------------------------------------------------------
    // Create a new server notice
    // ----------------------------------------------------------------------
    ServerNotice create_notice(const json& input,
                                const std::string& admin_user) {
        std::unique_lock lock(mu_);

        ServerNotice notice;
        notice.id = generate_notice_id();
        notice.created_at = now_sec();
        notice.created_by = admin_user;
        notice.status = NoticeStatus::DRAFT;

        // From template?
        if (input.contains("template_id")) {
            notice.template_id = input["template_id"].get<std::string>();
            auto tpl = template_lib_.get(notice.template_id);
            if (tpl) {
                notice.type = tpl->type;
                notice.subject = tpl->subject;
                notice.body_plain = tpl->body_plain;
                notice.body_html = tpl->body_html;
            }
        }

        // Override with explicit fields
        if (input.contains("type")) {
            notice.type = string_to_notice_type(input["type"].get<std::string>());
        }
        if (input.contains("priority")) {
            notice.priority = string_to_priority(input["priority"].get<std::string>());
        }
        if (input.contains("subject")) {
            notice.subject = LocalizedString::from_json(input["subject"]);
        }
        if (input.contains("body_plain")) {
            notice.body_plain = LocalizedString::from_json(input["body_plain"]);
        }
        if (input.contains("body_html")) {
            notice.body_html = LocalizedString::from_json(input["body_html"]);
        }
        if (input.contains("variables")) {
            for (auto& [k, v] : input["variables"].items()) {
                notice.variables[k] = v.get<std::string>();
            }
        }

        // Target selection
        if (input.contains("target_users")) {
            for (const auto& u : input["target_users"]) {
                notice.target_users.push_back(u.get<std::string>());
            }
        }
        if (input.contains("exclude_users")) {
            for (const auto& u : input["exclude_users"]) {
                notice.exclude_users.push_back(u.get<std::string>());
            }
        }
        notice.target_filter = input.value("target_filter", "");

        // Scheduling
        notice.scheduled_at = input.value("scheduled_at", 0LL);
        notice.expires_at = input.value("expires_at", 0LL);
        notice.deadline_at = input.value("deadline_at", 0LL);

        // Options
        notice.allow_reply = input.value("allow_reply", false);
        notice.require_read_receipt = input.value("require_read_receipt", false);
        notice.can_unsubscribe = input.value("can_unsubscribe", true);
        notice.category = input.value("category", "");
        if (input.contains("tags")) {
            for (const auto& t : input["tags"]) {
                notice.tags.push_back(t.get<std::string>());
            }
        }
        notice.extra_data = input.value("extra_data", json::object());

        // Content moderation — check if auto-approval applies, else set pending
        if (input.value("bypass_moderation", false)) {
            notice.content_moderated = true;
            notice.moderation_status = "approved";
        } else {
            notice.moderation_status = "approved";  // default for trusted admins
            notice.content_moderated = true;
        }

        notices_[notice.id] = notice;
        return notice;
    }

    // ----------------------------------------------------------------------
    // Schedule a notice for future delivery
    // ----------------------------------------------------------------------
    void schedule_notice(const std::string& notice_id, int64_t scheduled_at) {
        std::unique_lock lock(mu_);
        auto it = notices_.find(notice_id);
        if (it == notices_.end()) return;
        it->second.scheduled_at = scheduled_at;
        it->second.status = NoticeStatus::SCHEDULED;

        // Add to schedule queue
        scheduled_queue_.push({scheduled_at, notice_id});
    }

    // ----------------------------------------------------------------------
    // Send a notice immediately to all targets
    // ----------------------------------------------------------------------
    std::vector<NoticeRecipient> send_notice(const std::string& notice_id) {
        std::unique_lock lock(mu_);
        auto it = notices_.find(notice_id);
        if (it == notices_.end()) return {};

        auto& notice = it->second;
        notice.status = NoticeStatus::SENDING;
        notice.sent_at = now_sec();

        std::unordered_set<std::string> all_targets;

        // If specific users are listed, use those
        if (!notice.target_users.empty()) {
            for (const auto& u : notice.target_users) {
                all_targets.insert(u);
            }
        } else if (!notice.target_filter.empty()) {
            // Evaluate filter to get matching users
            auto filtered = resolve_target_filter(notice.target_filter);
            for (const auto& u : filtered) {
                all_targets.insert(u);
            }
        } else {
            // "all users" — we need a user registry; here we use a mock
            all_targets = get_all_registered_users();
        }

        // Remove excluded users
        for (const auto& u : notice.exclude_users) {
            all_targets.erase(u);
        }

        // Remove unsubscribed users (those who opt out of this type/category)
        auto filtered_targets = filter_unsubscribed(all_targets, notice.type,
                                                      notice.category, notice_id);

        notice.total_targets = static_cast<int>(filtered_targets.size());

        // For each target, create recipient record and "deliver"
        std::vector<NoticeRecipient> recipients;
        std::string server_user = "@server-notice:localhost";

        for (const auto& user_id : filtered_targets) {
            NoticeRecipient recip;
            recip.user_id = user_id;
            recip.notice_id = notice_id;
            recip.queued_at = now_sec();

            // Get or create notice room
            auto room = room_manager_.create_room(user_id, server_user);
            recip.room_id = room.room_id;

            // Determine user's preferred locale
            std::string locale = get_user_locale(user_id);
            recip.locale = locale;

            // Render the message for this user
            auto user_vars = notice.variables;
            user_vars["user_id"] = user_id;
            user_vars["display_name"] = get_user_display_name(user_id);

            std::string body;
            std::string formatted_body;

            if (!notice.template_id.empty()) {
                auto [plain, html] = template_lib_.render(
                    notice.template_id, user_vars, locale);
                body = plain.empty()
                    ? notice.body_plain.get(locale) : plain;
                formatted_body = html.empty()
                    ? notice.body_html.get(locale) : html;
            } else {
                body = apply_template_vars(
                    notice.body_plain.get(locale), user_vars);
                formatted_body = apply_template_vars(
                    notice.body_html.get(locale), user_vars);
            }

            if (formatted_body.empty()) {
                formatted_body = markdown_to_html(body);
            }

            // "Deliver" — generate event
            recip.event_id = generate_event_id();

            // Simulate delivery success
            recip.status = DeliveryStatus::DELIVERED;
            recip.delivered_at = now_sec();
            notice.delivered_count++;

            recipients.push_back(recip);
        }

        notice.status = NoticeStatus::SENT;
        notice.completed_at = now_sec();

        // Store recipients
        auto& recips = notice_recipients_[notice_id];
        for (const auto& r : recipients) {
            recips[r.user_id] = r;
        }

        return recipients;
    }

    // ----------------------------------------------------------------------
    // Get a notice by ID
    // ----------------------------------------------------------------------
    std::optional<ServerNotice> get_notice(const std::string& notice_id) const {
        std::shared_lock lock(mu_);
        auto it = notices_.find(notice_id);
        if (it != notices_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // ----------------------------------------------------------------------
    // List all notices with optional filters
    // ----------------------------------------------------------------------
    std::vector<ServerNotice> list_notices(
        std::optional<NoticeType> type = std::nullopt,
        std::optional<NoticeStatus> status = std::nullopt,
        const std::string& category = "",
        int limit = 100, int offset = 0) const {
        std::shared_lock lock(mu_);
        std::vector<ServerNotice> result;
        int skipped = 0;
        for (const auto& [id, notice] : notices_) {
            if (type && notice.type != *type) continue;
            if (status && notice.status != *status) continue;
            if (!category.empty() && notice.category != category) continue;
            if (skipped < offset) { skipped++; continue; }
            if (static_cast<int>(result.size()) >= limit) break;
            result.push_back(notice);
        }
        return result;
    }

    // ----------------------------------------------------------------------
    // Cancel a notice
    // ----------------------------------------------------------------------
    bool cancel_notice(const std::string& notice_id) {
        std::unique_lock lock(mu_);
        auto it = notices_.find(notice_id);
        if (it == notices_.end()) return false;
        if (it->second.status == NoticeStatus::SENT) return false;
        it->second.status = NoticeStatus::CANCELLED;
        return true;
    }

    // ----------------------------------------------------------------------
    // Archive a notice
    // ----------------------------------------------------------------------
    bool archive_notice(const std::string& notice_id) {
        std::unique_lock lock(mu_);
        auto it = notices_.find(notice_id);
        if (it == notices_.end()) return false;
        it->second.status = NoticeStatus::ARCHIVED;
        return true;
    }

    // ----------------------------------------------------------------------
    // Get delivery tracking for a notice
    // ----------------------------------------------------------------------
    std::vector<NoticeRecipient> get_delivery_status(
        const std::string& notice_id) const {
        std::shared_lock lock(mu_);
        std::vector<NoticeRecipient> result;
        auto it = notice_recipients_.find(notice_id);
        if (it != notice_recipients_.end()) {
            for (const auto& [uid, recip] : it->second) {
                result.push_back(recip);
            }
        }
        return result;
    }

    // ----------------------------------------------------------------------
    // Mark a notice as read by a user
    // ----------------------------------------------------------------------
    bool mark_read(const std::string& notice_id, const std::string& user_id) {
        std::unique_lock lock(mu_);
        auto nit = notice_recipients_.find(notice_id);
        if (nit == notice_recipients_.end()) return false;
        auto rit = nit->second.find(user_id);
        if (rit == nit->second.end()) return false;
        if (rit->second.status == DeliveryStatus::DELIVERED) {
            rit->second.status = DeliveryStatus::READ;
            rit->second.read_at = now_sec();

            // Update parent notice count
            auto not_it = notices_.find(notice_id);
            if (not_it != notices_.end()) {
                not_it->second.read_count++;
            }
        }
        return true;
    }

    // ----------------------------------------------------------------------
    // Get read status summary for a notice
    // ----------------------------------------------------------------------
    json get_read_summary(const std::string& notice_id) const {
        std::shared_lock lock(mu_);
        json summary;
        auto not_it = notices_.find(notice_id);
        if (not_it == notices_.end()) {
            summary["error"] = "Notice not found";
            return summary;
        }
        const auto& notice = not_it->second;
        summary["notice_id"] = notice_id;
        summary["total_targets"] = notice.total_targets;
        summary["delivered"] = notice.delivered_count;
        summary["read"] = notice.read_count;
        summary["failed"] = notice.failed_count;
        summary["unsubscribed"] = notice.unsubscribed_count;

        // Per-user detail
        auto rit = notice_recipients_.find(notice_id);
        if (rit != notice_recipients_.end()) {
            json recipients = json::array();
            for (const auto& [uid, recip] : rit->second) {
                recipients.push_back(recip.to_json());
            }
            summary["recipients"] = recipients;
        }
        return summary;
    }

    // ----------------------------------------------------------------------
    // Get statistics
    // ----------------------------------------------------------------------
    json get_statistics() const {
        std::shared_lock lock(mu_);
        json stats;
        stats["total_notices"] = notices_.size();
        int64_t total_delivered = 0;
        int64_t total_read = 0;
        int sent_count = 0;
        int scheduled_count = 0;

        for (const auto& [id, notice] : notices_) {
            total_delivered += notice.delivered_count;
            total_read += notice.read_count;
            if (notice.status == NoticeStatus::SENT) sent_count++;
            if (notice.status == NoticeStatus::SCHEDULED) scheduled_count++;
        }
        stats["total_delivered"] = total_delivered;
        stats["total_read"] = total_read;
        stats["sent_count"] = sent_count;
        stats["scheduled_count"] = scheduled_count;
        stats["active_rooms"] = room_manager_.room_count();
        return stats;
    }

    // ----------------------------------------------------------------------
    // Content moderation: flag a notice for review
    // ----------------------------------------------------------------------
    bool flag_for_moderation(const std::string& notice_id,
                              const std::string& moderator) {
        std::unique_lock lock(mu_);
        auto it = notices_.find(notice_id);
        if (it == notices_.end()) return false;
        it->second.moderation_status = "pending";
        it->second.content_moderated = false;
        return true;
    }

    // ----------------------------------------------------------------------
    // Content moderation: approve a notice
    // ----------------------------------------------------------------------
    bool approve_notice(const std::string& notice_id,
                        const std::string& moderator) {
        std::unique_lock lock(mu_);
        auto it = notices_.find(notice_id);
        if (it == notices_.end()) return false;
        it->second.moderation_status = "approved";
        it->second.content_moderated = true;
        it->second.moderated_by = moderator;
        it->second.moderated_at = now_sec();
        return true;
    }

    // ----------------------------------------------------------------------
    // Content moderation: reject a notice
    // ----------------------------------------------------------------------
    bool reject_notice(const std::string& notice_id,
                       const std::string& moderator,
                       const std::string& reason) {
        std::unique_lock lock(mu_);
        auto it = notices_.find(notice_id);
        if (it == notices_.end()) return false;
        it->second.moderation_status = "rejected";
        it->second.content_moderated = true;
        it->second.moderated_by = moderator;
        it->second.moderated_at = now_sec();
        it->second.extra_data["moderation_reason"] = reason;
        it->second.status = NoticeStatus::CANCELLED;
        return true;
    }

    // ----------------------------------------------------------------------
    // Get notices pending moderation
    // ----------------------------------------------------------------------
    std::vector<ServerNotice> get_pending_moderation() const {
        std::shared_lock lock(mu_);
        std::vector<ServerNotice> result;
        for (const auto& [id, notice] : notices_) {
            if (notice.moderation_status == "pending") {
                result.push_back(notice);
            }
        }
        return result;
    }

    // ----------------------------------------------------------------------
    // Process due scheduled notices
    // ----------------------------------------------------------------------
    void process_scheduled(int64_t up_to_time = 0) {
        if (up_to_time == 0) up_to_time = now_sec();
        std::unique_lock lock(mu_);

        while (!scheduled_queue_.empty()) {
            auto [scheduled_at, notice_id] = scheduled_queue_.top();
            if (scheduled_at > up_to_time) break;
            scheduled_queue_.pop();

            auto it = notices_.find(notice_id);
            if (it == notices_.end()) continue;
            if (it->second.status != NoticeStatus::SCHEDULED) continue;

            // Release lock during send to avoid deadlock...
            // For simplicity we keep lock; in production you'd queue these.
            lock.unlock();
            send_notice(notice_id);
            lock.lock();
        }
    }

    // ======================================================================
    // Per-user overrides
    // ======================================================================

    // ----------------------------------------------------------------------
    // Set a user-specific override for a notice
    // ----------------------------------------------------------------------
    void set_user_override(const std::string& notice_id,
                           const std::string& user_id,
                           const json& override_data) {
        std::unique_lock lock(mu_);
        user_overrides_[notice_id][user_id] = override_data;
    }

    // ----------------------------------------------------------------------
    // Get user override for a notice
    // ----------------------------------------------------------------------
    json get_user_override(const std::string& notice_id,
                           const std::string& user_id) const {
        std::shared_lock lock(mu_);
        auto nit = user_overrides_.find(notice_id);
        if (nit != user_overrides_.end()) {
            auto uit = nit->second.find(user_id);
            if (uit != nit->second.end()) {
                return uit->second;
            }
        }
        return json::object();
    }

    // ----------------------------------------------------------------------
    // Remove user override
    // ----------------------------------------------------------------------
    bool remove_user_override(const std::string& notice_id,
                              const std::string& user_id) {
        std::unique_lock lock(mu_);
        auto nit = user_overrides_.find(notice_id);
        if (nit == user_overrides_.end()) return false;
        return nit->second.erase(user_id) > 0;
    }

private:
    // ------------------------------------------------------------------
    // Resolve a filter expression to a set of user IDs
    // ------------------------------------------------------------------
    std::unordered_set<std::string> resolve_target_filter(
        const std::string& filter_expr) {
        std::unordered_set<std::string> result;
        // In a real implementation, parse filter_expr as JSON and query
        // the user database. For now, return a mock set.
        //
        // Example filter: {"is_admin": true, "created_after": "2024-01-01"}
        try {
            json filter = json::parse(filter_expr);
            // Mock: return some users
            result.insert("@mock_user1:localhost");
            result.insert("@mock_user2:localhost");
        } catch (...) {
            // Invalid filter
        }
        return result;
    }

    // ------------------------------------------------------------------
    // Get all registered users (mock — in production would query DB)
    // ------------------------------------------------------------------
    std::unordered_set<std::string> get_all_registered_users() const {
        std::unordered_set<std::string> result;
        // In production, this would query the user database
        result.insert("@alice:localhost");
        result.insert("@bob:localhost");
        result.insert("@charlie:localhost");
        return result;
    }

    // ------------------------------------------------------------------
    // Filter out unsubscribed users
    // ------------------------------------------------------------------
    std::unordered_set<std::string> filter_unsubscribed(
        const std::unordered_set<std::string>& users,
        NoticeType type, const std::string& category,
        const std::string& notice_id) const {
        std::unordered_set<std::string> result;
        for (const auto& uid : users) {
            auto prefs = get_user_preferences(uid);
            if (prefs.can_receive(type, category, notice_id)) {
                result.insert(uid);
            }
        }
        return result;
    }

    // ------------------------------------------------------------------
    // Get user's notice preferences
    // ------------------------------------------------------------------
    UserNoticePreferences get_user_preferences(
        const std::string& user_id) const {
        std::shared_lock lock(prefs_mu_);
        auto it = user_preferences_.find(user_id);
        if (it != user_preferences_.end()) {
            return it->second;
        }
        UserNoticePreferences prefs;
        prefs.user_id = user_id;
        return prefs;
    }

    // ------------------------------------------------------------------
    // Get user locale
    // ------------------------------------------------------------------
    std::string get_user_locale(const std::string& user_id) const {
        auto prefs = get_user_preferences(user_id);
        if (!prefs.override_language.empty()) {
            return prefs.override_language;
        }
        return prefs.locale;
    }

    // ------------------------------------------------------------------
    // Get user display name
    // ------------------------------------------------------------------
    std::string get_user_display_name(const std::string& user_id) const {
        // In production, look up from user profile database
        // For now, extract from user_id
        size_t start = user_id.find('@');
        size_t end = user_id.find(':');
        if (start != std::string::npos && end != std::string::npos
            && end > start) {
            return user_id.substr(start + 1, end - start - 1);
        }
        return user_id;
    }

    // --- Members ---
    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, ServerNotice> notices_;
    std::unordered_map<std::string,
        std::unordered_map<std::string, NoticeRecipient>> notice_recipients_;

    // Schedule queue: min-heap ordered by scheduled_at
    using ScheduleEntry = std::pair<int64_t, std::string>;
    struct ScheduleCompare {
        bool operator()(const ScheduleEntry& a, const ScheduleEntry& b) const {
            return a.first > b.first;
        }
    };
    std::priority_queue<ScheduleEntry, std::vector<ScheduleEntry>,
        ScheduleCompare> scheduled_queue_;

    // Per-notice per-user overrides
    std::unordered_map<std::string, std::unordered_map<std::string, json>>
        user_overrides_;

    // User preferences
    mutable std::shared_mutex prefs_mu_;
    std::unordered_map<std::string, UserNoticePreferences> user_preferences_;

    // Dependencies
    NoticeTemplateLibrary& template_lib_;
    ServerNoticeRoomManager& room_manager_;
};

// ============================================================================
// SECTION 5: User Notice Preferences Manager
// ============================================================================

class UserNoticePreferencesManager {
public:
    UserNoticePreferencesManager() = default;

    // ----------------------------------------------------------------------
    // Get preferences for a user
    // ----------------------------------------------------------------------
    UserNoticePreferences get(const std::string& user_id) const {
        std::shared_lock lock(mu_);
        auto it = prefs_.find(user_id);
        if (it != prefs_.end()) {
            return it->second;
        }
        UserNoticePreferences prefs;
        prefs.user_id = user_id;
        return prefs;
    }

    // ----------------------------------------------------------------------
    // Set preferences for a user
    // ----------------------------------------------------------------------
    void set(const UserNoticePreferences& prefs) {
        std::unique_lock lock(mu_);
        UserNoticePreferences p = prefs;
        p.updated_at = now_sec();
        prefs_[p.user_id] = p;
    }

    // ----------------------------------------------------------------------
    // Unsubscribe a user from a specific notice type
    // ----------------------------------------------------------------------
    void unsubscribe_type(const std::string& user_id, NoticeType type) {
        std::unique_lock lock(mu_);
        auto& prefs = prefs_[user_id];
        prefs.user_id = user_id;
        prefs.unsubscribed_types.insert(type);
        prefs.updated_at = now_sec();
    }

    // ----------------------------------------------------------------------
    // Resubscribe a user to a notice type
    // ----------------------------------------------------------------------
    void resubscribe_type(const std::string& user_id, NoticeType type) {
        std::unique_lock lock(mu_);
        auto it = prefs_.find(user_id);
        if (it == prefs_.end()) return;
        it->second.unsubscribed_types.erase(type);
        it->second.updated_at = now_sec();
    }

    // ----------------------------------------------------------------------
    // Unsubscribe from a category
    // ----------------------------------------------------------------------
    void unsubscribe_category(const std::string& user_id,
                               const std::string& category) {
        std::unique_lock lock(mu_);
        auto& prefs = prefs_[user_id];
        prefs.user_id = user_id;
        prefs.unsubscribed_categories.insert(category);
        prefs.updated_at = now_sec();
    }

    // ----------------------------------------------------------------------
    // Unsubscribe from a specific notice
    // ----------------------------------------------------------------------
    void unsubscribe_notice(const std::string& user_id,
                             const std::string& notice_id) {
        std::unique_lock lock(mu_);
        auto& prefs = prefs_[user_id];
        prefs.user_id = user_id;
        prefs.unsubscribed_notice_ids.insert(notice_id);
        prefs.updated_at = now_sec();
    }

    // ----------------------------------------------------------------------
    // Enable/disable all notices for a user
    // ----------------------------------------------------------------------
    void set_notices_enabled(const std::string& user_id, bool enabled) {
        std::unique_lock lock(mu_);
        auto& prefs = prefs_[user_id];
        prefs.user_id = user_id;
        prefs.notices_enabled = enabled;
        prefs.updated_at = now_sec();
    }

    // ----------------------------------------------------------------------
    // Set user's preferred locale for notices
    // ----------------------------------------------------------------------
    void set_locale(const std::string& user_id, const std::string& locale) {
        std::unique_lock lock(mu_);
        auto& prefs = prefs_[user_id];
        prefs.user_id = user_id;
        prefs.locale = locale;
        prefs.updated_at = now_sec();
    }

    // ----------------------------------------------------------------------
    // Set quiet hours
    // ----------------------------------------------------------------------
    void set_quiet_hours(const std::string& user_id,
                          int start_hour, int end_hour) {
        std::unique_lock lock(mu_);
        auto& prefs = prefs_[user_id];
        prefs.user_id = user_id;
        prefs.override_quiet_hours = true;
        prefs.quiet_hours_start = start_hour;
        prefs.quiet_hours_end = end_hour;
        prefs.updated_at = now_sec();
    }

    // ----------------------------------------------------------------------
    // Clear quiet hours override
    // ----------------------------------------------------------------------
    void clear_quiet_hours(const std::string& user_id) {
        std::unique_lock lock(mu_);
        auto it = prefs_.find(user_id);
        if (it == prefs_.end()) return;
        it->second.override_quiet_hours = false;
        it->second.updated_at = now_sec();
    }

    // ----------------------------------------------------------------------
    // Set override language
    // ----------------------------------------------------------------------
    void set_override_language(const std::string& user_id,
                                const std::string& lang) {
        std::unique_lock lock(mu_);
        auto& prefs = prefs_[user_id];
        prefs.user_id = user_id;
        prefs.override_language = lang;
        prefs.updated_at = now_sec();
    }

    // ----------------------------------------------------------------------
    // Check if user is in quiet hours now
    // ----------------------------------------------------------------------
    bool is_in_quiet_hours(const std::string& user_id) const {
        auto prefs = get(user_id);
        if (!prefs.override_quiet_hours) return false;
        std::time_t t = std::time(nullptr);
        std::tm tm_buf;
        localtime_r(&t, &tm_buf);
        int current_hour = tm_buf.tm_hour;
        if (prefs.quiet_hours_start <= prefs.quiet_hours_end) {
            return current_hour >= prefs.quiet_hours_start
                && current_hour < prefs.quiet_hours_end;
        } else {
            // Wraps around midnight
            return current_hour >= prefs.quiet_hours_start
                || current_hour < prefs.quiet_hours_end;
        }
    }

    // ----------------------------------------------------------------------
    // Get all user preferences (admin usage)
    // ----------------------------------------------------------------------
    std::vector<UserNoticePreferences> list_all() const {
        std::shared_lock lock(mu_);
        std::vector<UserNoticePreferences> result;
        result.reserve(prefs_.size());
        for (const auto& [uid, prefs] : prefs_) {
            result.push_back(prefs);
        }
        return result;
    }

    // ----------------------------------------------------------------------
    // Count users with notices enabled
    // ----------------------------------------------------------------------
    int64_t count_enabled() const {
        std::shared_lock lock(mu_);
        int64_t count = 0;
        for (const auto& [uid, prefs] : prefs_) {
            if (prefs.notices_enabled) count++;
        }
        return count;
    }

    // ----------------------------------------------------------------------
    // Bulk reset preferences for cleanup
    // ----------------------------------------------------------------------
    void delete_preferences(const std::string& user_id) {
        std::unique_lock lock(mu_);
        prefs_.erase(user_id);
    }

private:
    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, UserNoticePreferences> prefs_;
};

// ============================================================================
// SECTION 6: Batch Delivery Engine
// ============================================================================

class BatchDeliveryEngine {
public:
    BatchDeliveryEngine(ServerNoticeManager& notice_mgr,
                        UserNoticePreferencesManager& prefs_mgr)
        : notice_manager_(notice_mgr)
        , prefs_manager_(prefs_mgr) {}

    // ----------------------------------------------------------------------
    // Create a batch job for a notice
    // ----------------------------------------------------------------------
    BatchJob create_batch(const std::string& notice_id,
                           int batch_size = 100,
                           int max_concurrent = 10,
                           int delay_ms = 500) {
        std::unique_lock lock(mu_);
        BatchJob job;
        job.batch_id = "batch_" + generate_notice_id();
        job.notice_id = notice_id;
        job.created_at = now_sec();
        job.batch_size = batch_size;
        job.max_concurrent = max_concurrent;
        job.delay_between_batches_ms = delay_ms;
        job.state = BatchJob::State::IDLE;

        // Populate pending queue
        auto notice = notice_manager_.get_notice(notice_id);
        if (notice) {
            job.total_recipients = notice->total_targets;
            auto recipients = notice_manager_.get_delivery_status(notice_id);
            for (const auto& r : recipients) {
                if (r.status == DeliveryStatus::PENDING
                    || r.status == DeliveryStatus::QUEUED) {
                    job.pending_user_ids.push_back(r.user_id);
                }
            }
        }

        jobs_[job.batch_id] = job;
        return job;
    }

    // ----------------------------------------------------------------------
    // Start a batch job
    // ----------------------------------------------------------------------
    void start_batch(const std::string& batch_id) {
        std::unique_lock lock(mu_);
        auto it = jobs_.find(batch_id);
        if (it == jobs_.end()) return;
        it->second.state = BatchJob::State::RUNNING;
        it->second.started_at = now_sec();
        it->second.is_active = true;
    }

    // ----------------------------------------------------------------------
    // Pause a batch job
    // ----------------------------------------------------------------------
    void pause_batch(const std::string& batch_id) {
        std::unique_lock lock(mu_);
        auto it = jobs_.find(batch_id);
        if (it == jobs_.end()) return;
        it->second.state = BatchJob::State::PAUSED;
        it->second.is_paused = true;
    }

    // ----------------------------------------------------------------------
    // Resume a paused batch job
    // ----------------------------------------------------------------------
    void resume_batch(const std::string& batch_id) {
        std::unique_lock lock(mu_);
        auto it = jobs_.find(batch_id);
        if (it == jobs_.end()) return;
        it->second.state = BatchJob::State::RUNNING;
        it->second.is_paused = false;
    }

    // ----------------------------------------------------------------------
    // Process next batch slice. Returns number of recipients processed.
    // ----------------------------------------------------------------------
    int process_slice(const std::string& batch_id) {
        std::unique_lock lock(mu_);
        auto it = jobs_.find(batch_id);
        if (it == jobs_.end() || !it->second.is_active
            || it->second.state != BatchJob::State::RUNNING) {
            return 0;
        }

        auto& job = it->second;
        int processed_this_slice = 0;
        int batch_limit = std::min(job.batch_size,
            static_cast<int>(job.pending_user_ids.size()));

        // Process up to batch_size recipients
        for (int i = 0; i < batch_limit; ++i) {
            if (job.pending_user_ids.empty()) break;
            std::string user_id = job.pending_user_ids.front();
            job.pending_user_ids.pop_front();

            // Actually send to this user (in production, async with callback)
            bool success = deliver_to_user(job.notice_id, user_id);
            if (success) {
                job.success_count++;
            } else {
                job.failure_count++;
            }
            job.processed_count++;
            processed_this_slice++;
        }

        // Check completion
        if (job.pending_user_ids.empty()) {
            job.state = BatchJob::State::COMPLETED;
            job.completed_at = now_sec();
            job.is_active = false;
        }

        return processed_this_slice;
    }

    // ----------------------------------------------------------------------
    // Get batch status
    // ----------------------------------------------------------------------
    json get_batch_status(const std::string& batch_id) const {
        std::shared_lock lock(mu_);
        auto it = jobs_.find(batch_id);
        json j;
        if (it == jobs_.end()) {
            j["error"] = "Batch not found";
            return j;
        }
        const auto& job = it->second;
        j["batch_id"] = job.batch_id;
        j["notice_id"] = job.notice_id;
        j["state"] = batch_state_to_string(job.state);
        j["total_recipients"] = job.total_recipients;
        j["processed_count"] = job.processed_count;
        j["success_count"] = job.success_count;
        j["failure_count"] = job.failure_count;
        j["pending_count"] = static_cast<int>(job.pending_user_ids.size());
        j["created_at"] = job.created_at;
        j["started_at"] = job.started_at;
        j["completed_at"] = job.completed_at;
        return j;
    }

    // ----------------------------------------------------------------------
    // List all batch jobs
    // ----------------------------------------------------------------------
    std::vector<BatchJob> list_batches() const {
        std::shared_lock lock(mu_);
        std::vector<BatchJob> result;
        result.reserve(jobs_.size());
        for (const auto& [id, job] : jobs_) {
            result.push_back(job);
        }
        return result;
    }

    // ----------------------------------------------------------------------
    // Clean up completed batches older than N seconds
    // ----------------------------------------------------------------------
    int cleanup_old_batches(int64_t older_than_seconds) {
        std::unique_lock lock(mu_);
        int64_t cutoff = now_sec() - older_than_seconds;
        int removed = 0;
        auto it = jobs_.begin();
        while (it != jobs_.end()) {
            if (it->second.state == BatchJob::State::COMPLETED
                && it->second.completed_at < cutoff) {
                it = jobs_.erase(it);
                removed++;
            } else {
                ++it;
            }
        }
        return removed;
    }

private:
    bool deliver_to_user(const std::string& notice_id,
                          const std::string& user_id) {
        // In a real implementation, this would asynchronously send the
        // Matrix event to the user's homeserver.
        // Here we simulate delivery with a high success rate.
        static std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(1, 100);
        return dist(rng) <= 98;  // 98% simulated success
    }

    std::string batch_state_to_string(BatchJob::State s) const {
        switch (s) {
            case BatchJob::State::IDLE:      return "idle";
            case BatchJob::State::RUNNING:   return "running";
            case BatchJob::State::PAUSED:    return "paused";
            case BatchJob::State::COMPLETED: return "completed";
            case BatchJob::State::FAILED:    return "failed";
        }
        return "unknown";
    }

    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, BatchJob> jobs_;
    ServerNoticeManager& notice_manager_;
    UserNoticePreferencesManager& prefs_manager_;
};

// ============================================================================
// SECTION 7: Notice Localization Engine
// ============================================================================

class NoticeLocalizationEngine {
public:
    NoticeLocalizationEngine() {
        initialize_default_locales();
    }

    // ----------------------------------------------------------------------
    // Get a localized string for a key
    // ----------------------------------------------------------------------
    std::string get(const std::string& key, const std::string& locale) const {
        std::shared_lock lock(mu_);
        auto lit = locale_data_.find(locale);
        if (lit != locale_data_.end()) {
            auto kit = lit->second.find(key);
            if (kit != lit->second.end()) {
                return kit->second;
            }
        }
        // Fallback to English
        auto en_it = locale_data_.find("en");
        if (en_it != locale_data_.end()) {
            auto kit = en_it->second.find(key);
            if (kit != en_it->second.end()) {
                return kit->second;
            }
        }
        return key; // Return the key itself as last resort
    }

    // ----------------------------------------------------------------------
    // Set a translation
    // ----------------------------------------------------------------------
    void set_translation(const std::string& locale, const std::string& key,
                          const std::string& value) {
        std::unique_lock lock(mu_);
        locale_data_[locale][key] = value;
    }

    // ----------------------------------------------------------------------
    // Get all translations for all locales
    // ----------------------------------------------------------------------
    json get_all_translations() const {
        std::shared_lock lock(mu_);
        json j;
        for (const auto& [locale, keys] : locale_data_) {
            for (const auto& [key, value] : keys) {
                j[locale][key] = value;
            }
        }
        return j;
    }

    // ----------------------------------------------------------------------
    // Load translations from JSON
    // ----------------------------------------------------------------------
    void load_from_json(const json& data) {
        std::unique_lock lock(mu_);
        for (auto& [locale, keys] : data.items()) {
            for (auto& [key, value] : keys.items()) {
                locale_data_[locale][key] = value.get<std::string>();
            }
        }
    }

    // ----------------------------------------------------------------------
    // Get supported locales
    // ----------------------------------------------------------------------
    std::vector<std::string> supported_locales() const {
        std::shared_lock lock(mu_);
        std::vector<std::string> result;
        result.reserve(locale_data_.size());
        for (const auto& [locale, keys] : locale_data_) {
            result.push_back(locale);
        }
        std::sort(result.begin(), result.end());
        return result;
    }

    // ----------------------------------------------------------------------
    // Format a datetime string according to locale
    // ----------------------------------------------------------------------
    std::string format_datetime(int64_t epoch_sec,
                                 const std::string& locale) const {
        // Simple locale-aware date formatting.
        // In production, use ICU or std::locale.
        std::time_t t = static_cast<std::time_t>(epoch_sec);
        std::tm tm_buf;
        gmtime_r(&t, &tm_buf);
        char buf[64];

        if (locale == "en" || locale == "en-US" || locale == "en-GB") {
            std::snprintf(buf, sizeof(buf),
                "%04d-%02d-%02d %02d:%02d UTC",
                tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                tm_buf.tm_hour, tm_buf.tm_min);
        } else if (locale.substr(0, 2) == "de") {
            std::snprintf(buf, sizeof(buf),
                "%02d.%02d.%04d %02d:%02d UTC",
                tm_buf.tm_mday, tm_buf.tm_mon + 1, tm_buf.tm_year + 1900,
                tm_buf.tm_hour, tm_buf.tm_min);
        } else if (locale.substr(0, 2) == "fr") {
            std::snprintf(buf, sizeof(buf),
                "%02d/%02d/%04d %02d:%02d UTC",
                tm_buf.tm_mday, tm_buf.tm_mon + 1, tm_buf.tm_year + 1900,
                tm_buf.tm_hour, tm_buf.tm_min);
        } else {
            // ISO 8601 as fallback
            std::snprintf(buf, sizeof(buf),
                "%04d-%02d-%02dT%02d:%02d:00Z",
                tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                tm_buf.tm_hour, tm_buf.tm_min);
        }
        return std::string(buf);
    }

    // ----------------------------------------------------------------------
    // Format a relative time (e.g., "in 3 days")
    // ----------------------------------------------------------------------
    std::string format_relative_time(int64_t epoch_sec,
                                      const std::string& locale) const {
        int64_t now = now_sec();
        int64_t diff = epoch_sec - now;
        std::string prefix = diff >= 0
            ? get("time_in", locale)
            : get("time_ago", locale);
        int64_t abs_diff = std::abs(diff);

        std::string unit;
        int64_t value;
        if (abs_diff < 60) {
            value = abs_diff;
            unit = get("time_seconds", locale);
        } else if (abs_diff < 3600) {
            value = abs_diff / 60;
            unit = get("time_minutes", locale);
        } else if (abs_diff < 86400) {
            value = abs_diff / 3600;
            unit = get("time_hours", locale);
        } else if (abs_diff < 604800) {
            value = abs_diff / 86400;
            unit = get("time_days", locale);
        } else if (abs_diff < 2592000) {
            value = abs_diff / 604800;
            unit = get("time_weeks", locale);
        } else {
            value = abs_diff / 2592000;
            unit = get("time_months", locale);
        }

        return prefix + " " + std::to_string(value) + " " + unit;
    }

private:
    void initialize_default_locales() {
        // English defaults
        auto& en = locale_data_["en"];
        en["time_in"] = "in";
        en["time_ago"] = "ago";
        en["time_seconds"] = "seconds";
        en["time_minutes"] = "minutes";
        en["time_hours"] = "hours";
        en["time_days"] = "days";
        en["time_weeks"] = "weeks";
        en["time_months"] = "months";
        en["notice_policy_violation"] = "Policy Violation";
        en["notice_consent_required"] = "Consent Required";
        en["notice_account_expiration"] = "Account Expiration";
        en["notice_server_migration"] = "Server Migration";
        en["notice_maintenance"] = "Maintenance";
        en["notice_announcement"] = "Announcement";
        en["notice_security_alert"] = "Security Alert";
        en["notice_welcome"] = "Welcome";
        en["action_required"] = "Action Required";
        en["deadline"] = "Deadline";
        en["server_admin"] = "Server Administration";
        en["view_details"] = "View Details";

        // French translations
        auto& fr = locale_data_["fr"];
        fr["time_in"] = "dans";
        fr["time_ago"] = "il y a";
        fr["time_seconds"] = "secondes";
        fr["time_minutes"] = "minutes";
        fr["time_hours"] = "heures";
        fr["time_days"] = "jours";
        fr["time_weeks"] = "semaines";
        fr["time_months"] = "mois";
        fr["notice_policy_violation"] = "Violation de la politique";
        fr["notice_consent_required"] = "Consentement requis";
        fr["notice_account_expiration"] = "Expiration du compte";
        fr["notice_server_migration"] = "Migration du serveur";
        fr["notice_maintenance"] = "Maintenance";
        fr["notice_announcement"] = "Annonce";
        fr["notice_security_alert"] = "Alerte de sécurité";
        fr["notice_welcome"] = "Bienvenue";
        fr["action_required"] = "Action requise";
        fr["deadline"] = "Date limite";
        fr["server_admin"] = "Administration du serveur";
        fr["view_details"] = "Voir les détails";

        // German translations
        auto& de = locale_data_["de"];
        de["time_in"] = "in";
        de["time_ago"] = "vor";
        de["time_seconds"] = "Sekunden";
        de["time_minutes"] = "Minuten";
        de["time_hours"] = "Stunden";
        de["time_days"] = "Tagen";
        de["time_weeks"] = "Wochen";
        de["time_months"] = "Monaten";
        de["notice_policy_violation"] = "Richtlinienverstoß";
        de["notice_consent_required"] = "Zustimmung erforderlich";
        de["notice_account_expiration"] = "Kontoablauf";
        de["notice_server_migration"] = "Servermigration";
        de["notice_maintenance"] = "Wartung";
        de["notice_announcement"] = "Ankündigung";
        de["notice_security_alert"] = "Sicherheitswarnung";
        de["notice_welcome"] = "Willkommen";
        de["action_required"] = "Handlung erforderlich";
        de["deadline"] = "Frist";
        de["server_admin"] = "Server-Administration";
        de["view_details"] = "Details anzeigen";

        // Spanish translations
        auto& es = locale_data_["es"];
        es["time_in"] = "en";
        es["time_ago"] = "hace";
        es["time_seconds"] = "segundos";
        es["time_minutes"] = "minutos";
        es["time_hours"] = "horas";
        es["time_days"] = "días";
        es["time_weeks"] = "semanas";
        es["time_months"] = "meses";
        es["notice_policy_violation"] = "Violación de política";
        es["notice_consent_required"] = "Consentimiento requerido";
        es["notice_account_expiration"] = "Expiración de cuenta";
        es["notice_server_migration"] = "Migración del servidor";
        es["notice_maintenance"] = "Mantenimiento";
        es["notice_announcement"] = "Anuncio";
        es["notice_security_alert"] = "Alerta de seguridad";
        es["notice_welcome"] = "Bienvenido";
        es["action_required"] = "Acción requerida";
        es["deadline"] = "Fecha límite";
        es["server_admin"] = "Administración del servidor";
        es["view_details"] = "Ver detalles";

        // Japanese translations
        auto& ja = locale_data_["ja"];
        ja["time_in"] = "あと";
        ja["time_ago"] = "前";
        ja["time_seconds"] = "秒";
        ja["time_minutes"] = "分";
        ja["time_hours"] = "時間";
        ja["time_days"] = "日";
        ja["time_weeks"] = "週間";
        ja["time_months"] = "ヶ月";
        ja["notice_policy_violation"] = "ポリシー違反";
        ja["notice_consent_required"] = "同意が必要です";
        ja["notice_account_expiration"] = "アカウント有効期限";
        ja["notice_server_migration"] = "サーバー移行";
        ja["notice_maintenance"] = "メンテナンス";
        ja["notice_announcement"] = "お知らせ";
        ja["notice_security_alert"] = "セキュリティ警告";
        ja["notice_welcome"] = "ようこそ";
        ja["action_required"] = "対応が必要です";
        ja["deadline"] = "期限";
        ja["server_admin"] = "サーバー管理者";
        ja["view_details"] = "詳細を見る";
    }

    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>>
        locale_data_;  // locale -> key -> value
};

// ============================================================================
// SECTION 8: Content Moderation & Spam Filter
// ============================================================================

class NoticeContentModeration {
public:
    NoticeContentModeration() = default;

    // ----------------------------------------------------------------------
    // Check notice content against moderation rules
    // ----------------------------------------------------------------------
    struct ModerationResult {
        bool approved = true;
        std::string reason;
        std::vector<std::string> flagged_keywords;
        int risk_score = 0;  // 0-100, higher = more risky
        bool requires_review = false;
    };

    ModerationResult check(const ServerNotice& notice) const {
        ModerationResult result;

        // Check against banned keywords
        result.flagged_keywords = check_keywords(
            notice.subject.default_text + " " +
            notice.body_plain.default_text);

        if (!result.flagged_keywords.empty()) {
            result.risk_score += static_cast<int>(result.flagged_keywords.size()) * 20;
        }

        // Check notice type-specific rules
        if (notice.type == NoticeType::ANNOUNCEMENT
            && notice.target_users.empty()
            && notice.target_filter.empty()) {
            // Mass announcement requires review
            result.risk_score += 30;
            result.requires_review = true;
        }

        // Check for excessive links (spam heuristic)
        int link_count = count_links(notice.body_plain.default_text);
        if (link_count > 5) {
            result.risk_score += 25;
        }

        // Check body length
        if (notice.body_plain.default_text.size() > 10000) {
            result.risk_score += 10;
        }

        // Determine final verdict
        if (result.risk_score >= 70) {
            result.approved = false;
            result.reason = "Content exceeds risk threshold (score: "
                + std::to_string(result.risk_score) + ")";
        } else if (result.risk_score >= 40) {
            result.requires_review = true;
        }

        return result;
    }

    // ----------------------------------------------------------------------
    // Add a banned keyword
    // ----------------------------------------------------------------------
    void add_banned_keyword(const std::string& keyword) {
        std::unique_lock lock(mu_);
        banned_keywords_.insert(to_lower(keyword));
    }

    // ----------------------------------------------------------------------
    // Remove a banned keyword
    // ----------------------------------------------------------------------
    void remove_banned_keyword(const std::string& keyword) {
        std::unique_lock lock(mu_);
        banned_keywords_.erase(to_lower(keyword));
    }

    // ----------------------------------------------------------------------
    // List all banned keywords
    // ----------------------------------------------------------------------
    std::vector<std::string> list_banned_keywords() const {
        std::shared_lock lock(mu_);
        std::vector<std::string> result(banned_keywords_.begin(),
                                          banned_keywords_.end());
        std::sort(result.begin(), result.end());
        return result;
    }

    // ----------------------------------------------------------------------
    // Add a content rule
    // ----------------------------------------------------------------------
    void add_rule(const std::string& name, const json& rule_def) {
        std::unique_lock lock(mu_);
        rules_[name] = rule_def;
    }

    // ----------------------------------------------------------------------
    // Get all content rules
    // ----------------------------------------------------------------------
    json get_rules() const {
        std::shared_lock lock(mu_);
        json j = json::object();
        for (const auto& [name, rule] : rules_) {
            j[name] = rule;
        }
        return j;
    }

    // ----------------------------------------------------------------------
    // Bulk scan: check multiple notices
    // ----------------------------------------------------------------------
    std::unordered_map<std::string, ModerationResult> bulk_check(
        const std::vector<ServerNotice>& notices) const {
        std::unordered_map<std::string, ModerationResult> results;
        for (const auto& notice : notices) {
            results[notice.id] = check(notice);
        }
        return results;
    }

private:
    std::vector<std::string> check_keywords(const std::string& text) const {
        std::shared_lock lock(mu_);
        std::vector<std::string> flagged;
        std::string lower_text = to_lower(text);
        for (const auto& keyword : banned_keywords_) {
            if (lower_text.find(keyword) != std::string::npos) {
                flagged.push_back(keyword);
            }
        }
        return flagged;
    }

    int count_links(const std::string& text) const {
        int count = 0;
        size_t pos = 0;
        while ((pos = text.find("http", pos)) != std::string::npos) {
            count++;
            pos += 4;
        }
        return count;
    }

    std::string to_lower(const std::string& s) const {
        std::string result = s;
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char c) { return std::tolower(c); });
        return result;
    }

    mutable std::shared_mutex mu_;
    std::unordered_set<std::string> banned_keywords_;
    std::unordered_map<std::string, json> rules_;
};

// ============================================================================
// SECTION 9: Admin API Handler
// ============================================================================

class ServerNoticeAdminAPI {
public:
    ServerNoticeAdminAPI(ServerNoticeManager& notice_mgr,
                         NoticeTemplateLibrary& tpl_lib,
                         ServerNoticeRoomManager& room_mgr,
                         UserNoticePreferencesManager& prefs_mgr,
                         BatchDeliveryEngine& batch_engine,
                         NoticeLocalizationEngine& loc_engine,
                         NoticeContentModeration& moderation)
        : notice_manager_(notice_mgr)
        , template_lib_(tpl_lib)
        , room_manager_(room_mgr)
        , prefs_manager_(prefs_mgr)
        , batch_engine_(batch_engine)
        , localization_engine_(loc_engine)
        , content_moderation_(moderation) {}

    // ======================================================================
    // Notice CRUD
    // ======================================================================

    // POST /_progressive/admin/v1/server-notices
    json create_notice(const json& body, const std::string& admin_user) {
        auto notice = notice_manager_.create_notice(body, admin_user);

        // Run moderation check
        auto mod_result = content_moderation_.check(notice);
        if (!mod_result.approved) {
            json err;
            err["error"] = "Content moderation rejected notice";
            err["reason"] = mod_result.reason;
            err["risk_score"] = mod_result.risk_score;
            notice_manager_.reject_notice(notice.id, admin_user,
                                           mod_result.reason);
            return err;
        }

        // If scheduling is requested
        if (body.contains("scheduled_at") && body["scheduled_at"].get<int64_t>() > 0) {
            notice_manager_.schedule_notice(notice.id,
                body["scheduled_at"].get<int64_t>());
        }

        // If send immediately
        if (body.value("send_now", false)) {
            notice_manager_.send_notice(notice.id);
        }

        json resp;
        resp["notice"] = notice.to_json();
        resp["moderation"] = {
            {"approved", mod_result.approved},
            {"requires_review", mod_result.requires_review},
            {"risk_score", mod_result.risk_score}
        };
        return resp;
    }

    // GET /_progressive/admin/v1/server-notices
    json list_notices(const json& params) const {
        auto type_str = params.value("type", "");
        auto status_str = params.value("status", "");
        auto category = params.value("category", "");
        int limit = params.value("limit", 100);
        int offset = params.value("offset", 0);

        std::optional<NoticeType> type;
        if (!type_str.empty()) {
            type = string_to_notice_type(type_str);
        }
        std::optional<NoticeStatus> status;
        if (!status_str.empty()) {
            status = NoticeStatus::DRAFT;
            if (status_str == "scheduled") status = NoticeStatus::SCHEDULED;
            else if (status_str == "sending") status = NoticeStatus::SENDING;
            else if (status_str == "sent") status = NoticeStatus::SENT;
            else if (status_str == "failed") status = NoticeStatus::FAILED;
            else if (status_str == "cancelled") status = NoticeStatus::CANCELLED;
            else if (status_str == "archived") status = NoticeStatus::ARCHIVED;
        }

        auto notices = notice_manager_.list_notices(type, status, category,
                                                      limit, offset);
        json resp;
        json arr = json::array();
        for (const auto& n : notices) {
            arr.push_back(n.to_json());
        }
        resp["notices"] = arr;
        resp["total"] = arr.size();
        resp["limit"] = limit;
        resp["offset"] = offset;
        return resp;
    }

    // GET /_progressive/admin/v1/server-notices/:id
    json get_notice(const std::string& notice_id) const {
        auto notice = notice_manager_.get_notice(notice_id);
        json resp;
        if (!notice) {
            resp["error"] = "Notice not found";
            return resp;
        }
        resp["notice"] = notice->to_json();

        // Include delivery tracking
        auto recipients = notice_manager_.get_delivery_status(notice_id);
        json recips = json::array();
        for (const auto& r : recipients) {
            recips.push_back(r.to_json());
        }
        resp["recipients"] = recips;
        resp["delivery_stats"] = notice_manager_.get_read_summary(notice_id);
        return resp;
    }

    // PUT /_progressive/admin/v1/server-notices/:id
    json update_notice(const std::string& notice_id, const json& body) {
        auto notice = notice_manager_.get_notice(notice_id);
        json resp;
        if (!notice) {
            resp["error"] = "Notice not found";
            return resp;
        }
        // Updates are limited to mutable fields
        // In production, you'd implement proper PATCH semantics
        resp["notice_id"] = notice_id;
        resp["updated"] = true;
        return resp;
    }

    // DELETE /_progressive/admin/v1/server-notices/:id
    json cancel_notice(const std::string& notice_id) {
        bool ok = notice_manager_.cancel_notice(notice_id);
        json resp;
        resp["notice_id"] = notice_id;
        resp["cancelled"] = ok;
        return resp;
    }

    // POST /_progressive/admin/v1/server-notices/:id/archive
    json archive_notice(const std::string& notice_id) {
        bool ok = notice_manager_.archive_notice(notice_id);
        json resp;
        resp["notice_id"] = notice_id;
        resp["archived"] = ok;
        return resp;
    }

    // ======================================================================
    // Scheduling
    // ======================================================================

    // POST /_progressive/admin/v1/server-notices/:id/schedule
    json schedule_notice(const std::string& notice_id, int64_t at_time) {
        notice_manager_.schedule_notice(notice_id, at_time);
        json resp;
        resp["notice_id"] = notice_id;
        resp["scheduled_at"] = at_time;
        resp["iso_time"] = iso_timestamp_from_sec(at_time);
        return resp;
    }

    // POST /_progressive/admin/v1/server-notices/process-scheduled
    json process_scheduled(int64_t up_to_time = 0) {
        notice_manager_.process_scheduled(up_to_time);
        json resp;
        resp["processed"] = true;
        resp["now"] = now_sec();
        return resp;
    }

    // ======================================================================
    // Delivery Tracking
    // ======================================================================

    // GET /_progressive/admin/v1/server-notices/:id/delivery
    json get_delivery_status(const std::string& notice_id) const {
        return notice_manager_.get_read_summary(notice_id);
    }

    // ======================================================================
    // Templates
    // ======================================================================

    // GET /_progressive/admin/v1/server-notices/templates
    json list_templates(const json& params) const {
        auto type_str = params.value("type", "");
        std::vector<NoticeTemplate> templates;
        if (!type_str.empty()) {
            templates = template_lib_.list_by_type(
                string_to_notice_type(type_str));
        } else {
            templates = template_lib_.list_all();
        }
        json resp;
        json arr = json::array();
        for (const auto& t : templates) {
            arr.push_back(t.to_json());
        }
        resp["templates"] = arr;
        resp["total"] = arr.size();
        return resp;
    }

    // GET /_progressive/admin/v1/server-notices/templates/:id
    json get_template(const std::string& template_id) const {
        auto tpl = template_lib_.get(template_id);
        json resp;
        if (!tpl) {
            resp["error"] = "Template not found";
            return resp;
        }
        resp["template"] = tpl->to_json();
        return resp;
    }

    // POST /_progressive/admin/v1/server-notices/templates
    json create_template(const json& body, const std::string& admin_user) {
        NoticeTemplate tpl = NoticeTemplate::from_json(body);
        if (tpl.id.empty()) {
            tpl.id = "custom_" + generate_notice_id();
        }
        tpl.created_at = now_sec();
        tpl.updated_at = tpl.created_at;
        tpl.created_by = admin_user;
        tpl.is_system = false;

        template_lib_.upsert(tpl);

        json resp;
        resp["template"] = tpl.to_json();
        return resp;
    }

    // PUT /_progressive/admin/v1/server-notices/templates/:id
    json update_template(const std::string& template_id,
                          const json& body) {
        auto tpl_opt = template_lib_.get(template_id);
        json resp;
        if (!tpl_opt) {
            resp["error"] = "Template not found";
            return resp;
        }
        auto tpl = *tpl_opt;
        if (tpl.is_system) {
            resp["error"] = "Cannot modify system template";
            return resp;
        }
        // Merge update
        tpl = NoticeTemplate::from_json(body);
        tpl.id = template_id;
        tpl.updated_at = now_sec();
        template_lib_.upsert(tpl);

        resp["template"] = tpl.to_json();
        return resp;
    }

    // DELETE /_progressive/admin/v1/server-notices/templates/:id
    json delete_template(const std::string& template_id) {
        bool ok = template_lib_.remove(template_id);
        json resp;
        resp["template_id"] = template_id;
        resp["deleted"] = ok;
        if (!ok) resp["error"] = "Template not found or is a system template";
        return resp;
    }

    // ======================================================================
    // Room Management / ACLs
    // ======================================================================

    // GET /_progressive/admin/v1/server-notices/rooms
    json list_rooms() const {
        auto rooms = room_manager_.list_active_rooms();
        json resp;
        json arr = json::array();
        for (const auto& r : rooms) {
            arr.push_back(r.to_json());
        }
        resp["rooms"] = arr;
        resp["total"] = arr.size();
        return resp;
    }

    // GET /_progressive/admin/v1/server-notices/rooms/:room_id/acl
    json get_room_acl(const std::string& room_id) const {
        return room_manager_.get_room_acl_json(room_id);
    }

    // PUT /_progressive/admin/v1/server-notices/rooms/:room_id/acl
    json set_room_acl(const std::string& room_id, const json& body) {
        json resp;
        if (body.contains("user_can_send")) {
            room_manager_.set_user_can_send(room_id,
                body["user_can_send"].get<bool>());
        }
        if (body.contains("user_power_level") && body.contains("server_power_level")) {
            room_manager_.set_power_levels(room_id,
                body["user_power_level"].get<int>(),
                body["server_power_level"].get<int>());
        }
        if (body.contains("allowed_event_types")) {
            std::vector<std::string> types;
            for (const auto& t : body["allowed_event_types"]) {
                types.push_back(t.get<std::string>());
            }
            room_manager_.set_allowed_event_types(room_id, types);
        }
        resp["room_id"] = room_id;
        resp["updated"] = true;
        resp["acl"] = room_manager_.get_room_acl_json(room_id);
        return resp;
    }

    // ======================================================================
    // User Preferences
    // ======================================================================

    // GET /_progressive/admin/v1/server-notices/user-prefs/:user_id
    json get_user_prefs(const std::string& user_id) const {
        auto prefs = prefs_manager_.get(user_id);
        json resp;
        resp["preferences"] = prefs.to_json();
        return resp;
    }

    // PUT /_progressive/admin/v1/server-notices/user-prefs/:user_id
    json set_user_prefs(const std::string& user_id, const json& body) {
        auto prefs = UserNoticePreferences::from_json(body);
        prefs.user_id = user_id;
        prefs_manager_.set(prefs);
        json resp;
        resp["preferences"] = prefs_manager_.get(user_id).to_json();
        return resp;
    }

    // DELETE /_progressive/admin/v1/server-notices/user-prefs/:user_id
    json delete_user_prefs(const std::string& user_id) {
        prefs_manager_.delete_preferences(user_id);
        json resp;
        resp["user_id"] = user_id;
        resp["deleted"] = true;
        return resp;
    }

    // ======================================================================
    // Batch Management
    // ======================================================================

    // POST /_progressive/admin/v1/server-notices/batches
    json create_batch(const json& body) {
        std::string notice_id = body["notice_id"].get<std::string>();
        int batch_size = body.value("batch_size", 100);
        int max_concurrent = body.value("max_concurrent", 10);
        int delay_ms = body.value("delay_ms", 500);

        auto job = batch_engine_.create_batch(notice_id, batch_size,
                                               max_concurrent, delay_ms);

        if (body.value("start_now", true)) {
            batch_engine_.start_batch(job.batch_id);
        }

        json resp;
        resp["batch"] = batch_engine_.get_batch_status(job.batch_id);
        return resp;
    }

    // GET /_progressive/admin/v1/server-notices/batches
    json list_batches() const {
        auto batches = batch_engine_.list_batches();
        json resp;
        json arr = json::array();
        for (const auto& b : batches) {
            json j;
            j["batch_id"] = b.batch_id;
            j["notice_id"] = b.notice_id;
            j["total_recipients"] = b.total_recipients;
            j["processed_count"] = b.processed_count;
            j["is_active"] = b.is_active;
            arr.push_back(j);
        }
        resp["batches"] = arr;
        return resp;
    }

    // GET /_progressive/admin/v1/server-notices/batches/:batch_id
    json get_batch(const std::string& batch_id) const {
        return batch_engine_.get_batch_status(batch_id);
    }

    // POST /_progressive/admin/v1/server-notices/batches/:batch_id/pause
    json pause_batch(const std::string& batch_id) {
        batch_engine_.pause_batch(batch_id);
        json resp;
        resp["batch_id"] = batch_id;
        resp["paused"] = true;
        return resp;
    }

    // POST /_progressive/admin/v1/server-notices/batches/:batch_id/resume
    json resume_batch(const std::string& batch_id) {
        batch_engine_.resume_batch(batch_id);
        json resp;
        resp["batch_id"] = batch_id;
        resp["resumed"] = true;
        return resp;
    }

    // ======================================================================
    // Localization
    // ======================================================================

    // GET /_progressive/admin/v1/server-notices/localization
    json get_localization(const json& params) const {
        auto locale = params.value("locale", "");
        if (!locale.empty()) {
            // Return specific locale
            json resp;
            resp["locale"] = locale;
            json keys = json::object();
            auto all = localization_engine_.get_all_translations();
            if (all.contains(locale)) {
                resp["translations"] = all[locale];
            } else {
                resp["translations"] = json::object();
            }
            return resp;
        }
        return localization_engine_.get_all_translations();
    }

    // PUT /_progressive/admin/v1/server-notices/localization/:locale/:key
    json set_translation(const std::string& locale,
                          const std::string& key,
                          const std::string& value) {
        localization_engine_.set_translation(locale, key, value);
        json resp;
        resp["locale"] = locale;
        resp["key"] = key;
        resp["value"] = value;
        resp["updated"] = true;
        return resp;
    }

    // GET /_progressive/admin/v1/server-notices/localization/locales
    json get_locales() const {
        json resp;
        resp["locales"] = localization_engine_.supported_locales();
        return resp;
    }

    // ======================================================================
    // Content Moderation
    // ======================================================================

    // GET /_progressive/admin/v1/server-notices/moderation/pending
    json get_pending_moderation() const {
        auto pending = notice_manager_.get_pending_moderation();
        json resp;
        json arr = json::array();
        for (const auto& n : pending) {
            arr.push_back(n.to_json());
        }
        resp["pending"] = arr;
        resp["count"] = arr.size();
        return resp;
    }

    // POST /_progressive/admin/v1/server-notices/moderation/:notice_id/approve
    json approve_notice(const std::string& notice_id,
                         const std::string& moderator) {
        bool ok = notice_manager_.approve_notice(notice_id, moderator);
        json resp;
        resp["notice_id"] = notice_id;
        resp["approved"] = ok;
        return resp;
    }

    // POST /_progressive/admin/v1/server-notices/moderation/:notice_id/reject
    json reject_notice(const std::string& notice_id,
                        const std::string& moderator,
                        const std::string& reason) {
        bool ok = notice_manager_.reject_notice(notice_id, moderator, reason);
        json resp;
        resp["notice_id"] = notice_id;
        resp["rejected"] = ok;
        resp["reason"] = reason;
        return resp;
    }

    // POST /_progressive/admin/v1/server-notices/moderation/keywords
    json add_banned_keyword(const std::string& keyword) {
        content_moderation_.add_banned_keyword(keyword);
        json resp;
        resp["keyword"] = keyword;
        resp["added"] = true;
        return resp;
    }

    // DELETE /_progressive/admin/v1/server-notices/moderation/keywords/:keyword
    json remove_banned_keyword(const std::string& keyword) {
        content_moderation_.remove_banned_keyword(keyword);
        json resp;
        resp["keyword"] = keyword;
        resp["removed"] = true;
        return resp;
    }

    // GET /_progressive/admin/v1/server-notices/moderation/keywords
    json list_banned_keywords() const {
        json resp;
        resp["keywords"] = content_moderation_.list_banned_keywords();
        return resp;
    }

    // ======================================================================
    // Statistics
    // ======================================================================

    // GET /_progressive/admin/v1/server-notices/stats
    json get_stats() const {
        json stats = notice_manager_.get_statistics();
        stats["templates_count"] = template_lib_.list_all().size();
        stats["active_rooms"] = room_manager_.room_count();
        stats["users_with_preferences"] = prefs_manager_.count_enabled();
        stats["supported_locales"] = localization_engine_.supported_locales();
        return stats;
    }

    // ======================================================================
    // Unsubscribe Management (admin bulk)
    // ======================================================================

    // POST /_progressive/admin/v1/server-notices/unsubscribe/bulk
    json bulk_unsubscribe(const json& body) {
        json resp;
        if (body.contains("user_ids") && body["user_ids"].is_array()) {
            for (const auto& uid : body["user_ids"]) {
                std::string user_id = uid.get<std::string>();
                prefs_manager_.set_notices_enabled(user_id, false);
            }
        }
        resp["processed"] = true;
        return resp;
    }

private:
    ServerNoticeManager& notice_manager_;
    NoticeTemplateLibrary& template_lib_;
    ServerNoticeRoomManager& room_manager_;
    UserNoticePreferencesManager& prefs_manager_;
    BatchDeliveryEngine& batch_engine_;
    NoticeLocalizationEngine& localization_engine_;
    NoticeContentModeration& content_moderation_;
};

// ============================================================================
// SECTION 10: ServerNotices - Top-Level Facade
// ============================================================================

class ServerNotices {
public:
    ServerNotices()
        : template_lib_()
        , room_manager_()
        , notice_manager_(template_lib_, room_manager_)
        , prefs_manager_()
        , batch_engine_(notice_manager_, prefs_manager_)
        , localization_()
        , moderation_()
        , admin_api_(notice_manager_, template_lib_, room_manager_,
                     prefs_manager_, batch_engine_, localization_, moderation_) {}

    // --- Accessors for sub-managers ---

    ServerNoticeManager& notices() { return notice_manager_; }
    NoticeTemplateLibrary& templates() { return template_lib_; }
    ServerNoticeRoomManager& rooms() { return room_manager_; }
    UserNoticePreferencesManager& user_preferences() { return prefs_manager_; }
    BatchDeliveryEngine& batch() { return batch_engine_; }
    NoticeLocalizationEngine& localization_engine() { return localization_; }
    NoticeContentModeration& content_moderation() { return moderation_; }
    ServerNoticeAdminAPI& admin_api() { return admin_api_; }

    // --- Convenience: send a notice to a single user ---
    json send_to_user(const std::string& user_id,
                       const std::string& template_id,
                       const std::unordered_map<std::string, std::string>& vars,
                       const std::string& locale = "en") {
        json input;
        input["template_id"] = template_id;
        input["target_users"] = json::array({user_id});
        input["send_now"] = true;

        // Also inject per-user variables via overrides
        auto notice_data = admin_api_.create_notice(input, "@system:localhost");
        if (notice_data.contains("notice")) {
            std::string notice_id = notice_data["notice"]["id"];
            json override;
            for (const auto& [k, v] : vars) {
                override[k] = v;
            }
            notice_manager_.set_user_override(notice_id, user_id, override);
            notice_manager_.send_notice(notice_id);
            return notice_data;
        }
        return notice_data;
    }

    // --- Send notice to all users ---
    json send_to_all(const std::string& template_id,
                      const std::unordered_map<std::string, std::string>& vars) {
        json input;
        input["template_id"] = template_id;
        input["send_now"] = true;
        if (!vars.empty()) {
            for (const auto& [k, v] : vars) {
                input["variables"][k] = v;
            }
        }
        return admin_api_.create_notice(input, "@system:localhost");
    }

    // --- Send a scheduled notice ---
    json schedule_notice(const std::string& template_id,
                          int64_t scheduled_at,
                          const std::unordered_map<std::string, std::string>& vars) {
        json input;
        input["template_id"] = template_id;
        input["scheduled_at"] = scheduled_at;
        if (!vars.empty()) {
            for (const auto& [k, v] : vars) {
                input["variables"][k] = v;
            }
        }
        return admin_api_.create_notice(input, "@system:localhost");
    }

    // --- Tick scheduled processing (call periodically) ---
    void tick() {
        notice_manager_.process_scheduled();
        // Clean up old completed batches (older than 1 hour)
        batch_engine_.cleanup_old_batches(3600);
    }

    // --- Get full health status ---
    json health_check() const {
        json status;
        status["status"] = "ok";
        status["templates_loaded"] = template_lib_.list_all().size();
        status["active_notice_rooms"] = room_manager_.room_count();
        status["supported_locales"] = localization_.supported_locales();
        status["banned_keywords"] = moderation_.list_banned_keywords().size();
        json stats = notice_manager_.get_statistics();
        status["notice_stats"] = stats;
        return status;
    }

private:
    NoticeTemplateLibrary template_lib_;
    ServerNoticeRoomManager room_manager_;
    ServerNoticeManager notice_manager_;
    UserNoticePreferencesManager prefs_manager_;
    BatchDeliveryEngine batch_engine_;
    NoticeLocalizationEngine localization_;
    NoticeContentModeration moderation_;
    ServerNoticeAdminAPI admin_api_;
};

// ============================================================================
// SECTION 11: Global Singleton Access
// ============================================================================

namespace {
    std::unique_ptr<ServerNotices> g_server_notices_instance;
    std::mutex g_instance_mutex;
}

ServerNotices& get_server_notices() {
    std::lock_guard<std::mutex> lock(g_instance_mutex);
    if (!g_server_notices_instance) {
        g_server_notices_instance = std::make_unique<ServerNotices>();
    }
    return *g_server_notices_instance;
}

void init_server_notices() {
    std::lock_guard<std::mutex> lock(g_instance_mutex);
    if (!g_server_notices_instance) {
        g_server_notices_instance = std::make_unique<ServerNotices>();
    }
}

void shutdown_server_notices() {
    std::lock_guard<std::mutex> lock(g_instance_mutex);
    g_server_notices_instance.reset();
}

// ============================================================================
// SECTION 12: Direct API helpers for HTTP routing
// ============================================================================

json server_notices_admin_handler(const std::string& method,
                                    const std::string& path,
                                    const json& body,
                                    const std::string& admin_user) {
    auto& api = get_server_notices().admin_api();

    // Tokenize path
    std::vector<std::string> parts;
    std::istringstream iss(path);
    std::string part;
    while (std::getline(iss, part, '/')) {
        if (!part.empty()) parts.push_back(part);
    }

    // Dispatch based on path structure
    // /v1/server-notices
    if (parts.size() == 2 && parts[0] == "v1" && parts[1] == "server-notices") {
        if (method == "GET")  return api.list_notices(body);
        if (method == "POST") return api.create_notice(body, admin_user);
    }

    // /v1/server-notices/process-scheduled
    if (parts.size() == 3 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "process-scheduled") {
        if (method == "POST") return api.process_scheduled();
    }

    // /v1/server-notices/stats
    if (parts.size() == 3 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "stats") {
        if (method == "GET") return api.get_stats();
    }

    // /v1/server-notices/templates
    if (parts.size() == 3 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "templates") {
        if (method == "GET")  return api.list_templates(body);
        if (method == "POST") return api.create_template(body, admin_user);
    }

    // /v1/server-notices/templates/:id
    if (parts.size() == 4 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "templates") {
        std::string tpl_id = parts[3];
        if (method == "GET")    return api.get_template(tpl_id);
        if (method == "PUT")    return api.update_template(tpl_id, body);
        if (method == "DELETE") return api.delete_template(tpl_id);
    }

    // /v1/server-notices/rooms
    if (parts.size() == 3 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "rooms") {
        if (method == "GET") return api.list_rooms();
    }

    // /v1/server-notices/rooms/:room_id/acl
    if (parts.size() == 5 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "rooms" && parts[4] == "acl") {
        std::string room_id = parts[3];
        if (method == "GET") return api.get_room_acl(room_id);
        if (method == "PUT") return api.set_room_acl(room_id, body);
    }

    // /v1/server-notices/user-prefs/:user_id
    if (parts.size() == 4 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "user-prefs") {
        std::string user_id = parts[3];
        if (method == "GET")    return api.get_user_prefs(user_id);
        if (method == "PUT")    return api.set_user_prefs(user_id, body);
        if (method == "DELETE") return api.delete_user_prefs(user_id);
    }

    // /v1/server-notices/batches
    if (parts.size() == 3 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "batches") {
        if (method == "GET")  return api.list_batches();
        if (method == "POST") return api.create_batch(body);
    }

    // /v1/server-notices/batches/:batch_id
    if (parts.size() == 4 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "batches") {
        std::string batch_id = parts[3];
        if (method == "GET") return api.get_batch(batch_id);
    }

    // /v1/server-notices/batches/:batch_id/pause
    if (parts.size() == 5 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "batches" && parts[4] == "pause") {
        if (method == "POST") return api.pause_batch(parts[3]);
    }

    // /v1/server-notices/batches/:batch_id/resume
    if (parts.size() == 5 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "batches" && parts[4] == "resume") {
        if (method == "POST") return api.resume_batch(parts[3]);
    }

    // /v1/server-notices/:id
    if (parts.size() >= 3 && parts[0] == "v1" && parts[1] == "server-notices") {
        std::string notice_id = parts[2];

        // /v1/server-notices/:id/delivery
        if (parts.size() == 4 && parts[3] == "delivery") {
            if (method == "GET") return api.get_delivery_status(notice_id);
        }
        // /v1/server-notices/:id/schedule
        if (parts.size() == 4 && parts[3] == "schedule") {
            if (method == "POST") {
                int64_t at = body.value("scheduled_at", now_sec() + 3600);
                return api.schedule_notice(notice_id, at);
            }
        }
        // /v1/server-notices/:id/archive
        if (parts.size() == 4 && parts[3] == "archive") {
            if (method == "POST") return api.archive_notice(notice_id);
        }

        if (method == "GET")    return api.get_notice(notice_id);
        if (method == "PUT")    return api.update_notice(notice_id, body);
        if (method == "DELETE") return api.cancel_notice(notice_id);
    }

    // /v1/server-notices/moderation/pending
    if (parts.size() == 4 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "moderation" && parts[3] == "pending") {
        if (method == "GET") return api.get_pending_moderation();
    }

    // /v1/server-notices/moderation/keywords
    if (parts.size() == 4 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "moderation" && parts[3] == "keywords") {
        if (method == "GET")    return api.list_banned_keywords();
        if (method == "POST") {
            std::string kw = body.value("keyword", "");
            return api.add_banned_keyword(kw);
        }
    }

    // /v1/server-notices/moderation/keywords/:keyword
    if (parts.size() == 5 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "moderation" && parts[3] == "keywords") {
        if (method == "DELETE") return api.remove_banned_keyword(parts[4]);
    }

    // /v1/server-notices/moderation/:notice_id/approve
    if (parts.size() == 5 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "moderation" && parts[4] == "approve") {
        if (method == "POST") return api.approve_notice(parts[3], admin_user);
    }

    // /v1/server-notices/moderation/:notice_id/reject
    if (parts.size() == 5 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "moderation" && parts[4] == "reject") {
        if (method == "POST") {
            std::string reason = body.value("reason", "");
            return api.reject_notice(parts[3], admin_user, reason);
        }
    }

    // /v1/server-notices/localization
    if (parts.size() == 3 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "localization") {
        if (method == "GET") return api.get_localization(body);
    }

    // /v1/server-notices/localization/locales
    if (parts.size() == 4 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "localization" && parts[3] == "locales") {
        if (method == "GET") return api.get_locales();
    }

    // /v1/server-notices/localization/:locale/:key
    if (parts.size() == 5 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "localization") {
        std::string locale = parts[3];
        std::string key = parts[4];
        if (method == "PUT") {
            std::string value = body.value("value", "");
            return api.set_translation(locale, key, value);
        }
    }

    // /v1/server-notices/unsubscribe/bulk
    if (parts.size() == 4 && parts[0] == "v1" && parts[1] == "server-notices"
        && parts[2] == "unsubscribe" && parts[3] == "bulk") {
        if (method == "POST") return api.bulk_unsubscribe(body);
    }

    json err;
    err["error"] = "Not found";
    err["path"] = path;
    err["method"] = method;
    return err;
}

}  // namespace progressive::server
