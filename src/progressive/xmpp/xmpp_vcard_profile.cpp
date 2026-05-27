/*
 * progressive-server - XMPP vCard-temp, Avatar, and User Profile Implementation
 *
 * This file implements a comprehensive user profile and vCard system including:
 *   - vCard-temp (XEP-0054) full get/set with all standard vCard fields
 *   - vCard photo handling with binary data, MIME types, Base64 encode/decode
 *   - User Avatar (XEP-0084) via PEP publish to urn:xmpp:avatar:data node
 *   - User Avatar Metadata (XEP-0084) urn:xmpp:avatar:metadata PEP node
 *   - vCard-based Avatar (XEP-0153) SHA-1 hash in presence via vcard-temp:x:update
 *   - Avatar metadata notification to subscribers on change
 *   - Avatar data storage with size limits and MIME type validation
 *   - User Nickname (XEP-0172) via PEP nickname node
 *   - User Mood (XEP-0107) via PEP mood node with text, mood value
 *   - User Activity (XEP-0108) via PEP activity node with general/specific
 *   - User Tune (XEP-0118) via PEP tune node with artist, title, length, etc.
 *   - User Location (XEP-0080) via PEP geolocation node with lat/lon/alt/etc.
 *   - User Profile full get/set combining all profile data types
 *   - Profile field validation for all fields (length, format, value ranges)
 *   - Profile caching with TTL-based expiry for fast lookups
 *   - Profile federation via server-to-server (S2S) vCard and PEP requests
 *
 * Reference: ejabberd mod_vcard.erl, mod_vcard_xupdate.erl, mod_avatar.erl
 */

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <algorithm>
#include <sstream>
#include <mutex>
#include <shared_mutex>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <chrono>
#include <random>
#include <set>
#include <deque>
#include <queue>
#include <iomanip>
#include <iostream>
#include <atomic>
#include <stdexcept>
#include <regex>
#include <limits>
#include <cmath>
#include <utility>

namespace progressive {
namespace xmpp {

// ============================================================================
// Forward declarations
// ============================================================================

class VCardProfileManager;
class VCardParser;
class AvatarStore;
class ProfileCache;
class PEPProfilePublisher;
class ProfileFederationHandler;

// ============================================================================
// XMPP Namespace Constants
// ============================================================================

namespace profile_ns {
    constexpr const char* VCARD_TEMP          = "vcard-temp";
    constexpr const char* VCARD_UPDATE        = "vcard-temp:x:update";
    constexpr const char* AVATAR_DATA         = "urn:xmpp:avatar:data";
    constexpr const char* AVATAR_METADATA     = "urn:xmpp:avatar:metadata";
    constexpr const char* NICK                = "http://jabber.org/protocol/nick";
    constexpr const char* MOOD                = "http://jabber.org/protocol/mood";
    constexpr const char* ACTIVITY            = "http://jabber.org/protocol/activity";
    constexpr const char* TUNE                = "http://jabber.org/protocol/tune";
    constexpr const char* GEOLOC              = "http://jabber.org/protocol/geoloc";
    constexpr const char* PUBSUB              = "http://jabber.org/protocol/pubsub";
    constexpr const char* PEP                 = "http://jabber.org/protocol/pubsub#event";
    constexpr const char* DISCO_INFO          = "http://jabber.org/protocol/disco#info";
    constexpr const char* DISCO_ITEMS         = "http://jabber.org/protocol/disco#items";
    constexpr const char* JABBER_IQ_REGISTER  = "jabber:iq:register";
    constexpr const char* JABBER_IQ_LAST      = "jabber:iq:last";
    constexpr const char* JABBER_IQ_VERSION   = "jabber:iq:version";
}

// ============================================================================
// Internal XML / String Utility Namespace
// ============================================================================

namespace detail {
namespace {

// ---------------------------------------------------------------------------
// XML escaping utility
// ---------------------------------------------------------------------------
inline std::string xml_escape(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  result += "&amp;";  break;
            case '<':  result += "&lt;";   break;
            case '>':  result += "&gt;";   break;
            case '"':  result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default:   result += c;        break;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// XML attribute escaping (double quotes)
// ---------------------------------------------------------------------------
inline std::string xml_attr_escape(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  result += "&amp;";  break;
            case '<':  result += "&lt;";   break;
            case '"':  result += "&quot;"; break;
            default:   result += c;        break;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Generate a random hex string ID
// ---------------------------------------------------------------------------
inline std::string generate_id(const std::string& prefix = "") {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    uint64_t c = counter.fetch_add(1);
    std::ostringstream oss;
    oss << prefix << std::hex << dur << "-" << c;
    return oss.str();
}

// ---------------------------------------------------------------------------
// Current ISO8601 timestamp
// ---------------------------------------------------------------------------
inline std::string current_iso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::setfill('0')
        << (tm_buf.tm_year + 1900) << "-"
        << std::setw(2) << (tm_buf.tm_mon + 1) << "-"
        << std::setw(2) << tm_buf.tm_mday << "T"
        << std::setw(2) << tm_buf.tm_hour << ":"
        << std::setw(2) << tm_buf.tm_min << ":"
        << std::setw(2) << tm_buf.tm_sec << "Z";
    return oss.str();
}

// ---------------------------------------------------------------------------
// Current time as seconds since epoch
// ---------------------------------------------------------------------------
inline int64_t epoch_now() {
    return static_cast<int64_t>(std::time(nullptr));
}

// ---------------------------------------------------------------------------
// Case-insensitive string comparison
// ---------------------------------------------------------------------------
inline bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin(), b.end(),
        [](char ca, char cb) {
            return std::tolower(static_cast<unsigned char>(ca)) ==
                   std::tolower(static_cast<unsigned char>(cb));
        });
}

// ---------------------------------------------------------------------------
// Strip leading/trailing whitespace
// ---------------------------------------------------------------------------
inline std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])))
        ++start;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])))
        --end;
    return s.substr(start, end - start);
}

// ---------------------------------------------------------------------------
// Validate that a string contains only printable ASCII characters
// ---------------------------------------------------------------------------
inline bool is_printable_ascii(const std::string& s) {
    for (char c : s) {
        if (static_cast<unsigned char>(c) < 32 && c != '\n' && c != '\r' && c != '\t')
            return false;
        if (static_cast<unsigned char>(c) > 126) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Validate JID format (basic)
// ---------------------------------------------------------------------------
inline bool is_valid_jid_bare(const std::string& jid) {
    if (jid.empty() || jid.size() > 1023) return false;
    size_t at = jid.find('@');
    if (at == std::string::npos || at == 0 || at == jid.size() - 1)
        return false;
    std::string domain = jid.substr(at + 1);
    if (domain.find('/') != std::string::npos) return false; // no resource
    for (char c : domain) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-')
            return false;
    }
    return true;
}

} // anonymous namespace
} // namespace detail

// ============================================================================
// SHA-1 Implementation for Avatar Hash (XEP-0153)
// ============================================================================

namespace detail {
namespace {

class sha1 {
public:
    sha1() { reset(); }

    void reset() {
        h_[0] = 0x67452301;
        h_[1] = 0xEFCDAB89;
        h_[2] = 0x98BADCFE;
        h_[3] = 0x10325476;
        h_[4] = 0xC3D2E1F0;
        total_bits_ = 0;
        buf_index_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            block_[buf_index_++] = data[i];
            total_bits_ += 8;
            if (buf_index_ == 64) {
                transform_block();
                buf_index_ = 0;
            }
        }
    }

    void update(const std::string& s) {
        update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    void update(const std::vector<uint8_t>& data) {
        update(data.data(), data.size());
    }

    std::string hex_digest() {
        uint8_t hash[20];
        finalize_raw(hash);
        std::ostringstream oss;
        for (int i = 0; i < 20; ++i) {
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(hash[i]);
        }
        reset();
        return oss.str();
    }

    std::vector<uint8_t> raw_digest() {
        std::vector<uint8_t> hash(20);
        finalize_raw(hash.data());
        reset();
        return hash;
    }

    std::string base64_digest() {
        auto raw = raw_digest();
        return base64_encode_bytes(raw);
    }

    static std::string compute_hex(const std::string& input) {
        sha1 h;
        h.update(input);
        return h.hex_digest();
    }

    static std::string compute_hex(const std::vector<uint8_t>& input) {
        sha1 h;
        h.update(input);
        return h.hex_digest();
    }

private:
    // Base64 encode raw bytes
    static std::string base64_encode_bytes(const std::vector<uint8_t>& data) {
        static const char* chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        result.reserve(((data.size() + 2) / 3) * 4);
        for (size_t i = 0; i < data.size(); i += 3) {
            int n = (static_cast<int>(data[i]) << 16) |
                    ((i + 1 < data.size()) ? (static_cast<int>(data[i + 1]) << 8) : 0) |
                    ((i + 2 < data.size()) ? static_cast<int>(data[i + 2]) : 0);
            result += chars[(n >> 18) & 0x3F];
            result += chars[(n >> 12) & 0x3F];
            result += (i + 1 < data.size()) ? chars[(n >> 6) & 0x3F] : '=';
            result += (i + 2 < data.size()) ? chars[n & 0x3F] : '=';
        }
        return result;
    }

    void finalize_raw(uint8_t* out) {
        block_[buf_index_++] = 0x80;
        if (buf_index_ > 56) {
            while (buf_index_ < 64) block_[buf_index_++] = 0;
            transform_block();
            buf_index_ = 0;
        }
        while (buf_index_ < 56) block_[buf_index_++] = 0;
        uint64_t bits = total_bits_;
        for (int i = 7; i >= 0; --i) {
            block_[56 + i] = static_cast<uint8_t>(bits >> (i * 8));
        }
        transform_block();
        for (int i = 0; i < 5; ++i) {
            out[i * 4 + 0] = static_cast<uint8_t>((h_[i] >> 24) & 0xFF);
            out[i * 4 + 1] = static_cast<uint8_t>((h_[i] >> 16) & 0xFF);
            out[i * 4 + 2] = static_cast<uint8_t>((h_[i] >> 8) & 0xFF);
            out[i * 4 + 3] = static_cast<uint8_t>(h_[i] & 0xFF);
        }
    }

    uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    void transform_block() {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block_[i * 4]) << 24) |
                   (static_cast<uint32_t>(block_[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block_[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block_[i * 4 + 3]);
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e;
    }

    uint32_t h_[5];
    uint64_t total_bits_;
    uint8_t block_[64];
    int buf_index_;
};

} // anonymous namespace
} // namespace detail

// ============================================================================
// Base64 Encode / Decode Utilities
// ============================================================================

namespace detail {
namespace {

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::string base64_encode(const std::string& input) {
    return base64_encode(reinterpret_cast<const uint8_t*>(input.data()),
                         input.size());
}

inline std::string base64_encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        int n = (static_cast<int>(data[i]) << 16) |
                ((i + 1 < len) ? (static_cast<int>(data[i + 1]) << 8) : 0) |
                ((i + 2 < len) ? static_cast<int>(data[i + 2]) : 0);
        result += base64_chars[(n >> 18) & 0x3F];
        result += base64_chars[(n >> 12) & 0x3F];
        result += (i + 1 < len) ? base64_chars[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? base64_chars[n & 0x3F] : '=';
    }
    return result;
}

inline std::string base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

inline bool is_base64_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=';
}

inline std::vector<uint8_t> base64_decode(const std::string& input) {
    std::string clean;
    clean.reserve(input.size());
    for (char c : input) {
        if (is_base64_char(c)) clean += c;
    }

    auto decode_char = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::vector<uint8_t> result;
    result.reserve((clean.size() * 3) / 4);

    int val = 0, valb = -8;
    for (char c : clean) {
        if (c == '=') break;
        int d = decode_char(c);
        if (d == -1) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return result;
}

} // anonymous namespace
} // namespace detail

// ============================================================================
// Enumerations and Constants
// ============================================================================

// Mood values per XEP-0107
enum class MoodValue {
    AFRAID, AMAZED, AMOROUS, ANGRY, ANNOYED, ANXIOUS, AROUSED, ASHAMED,
    BORED, BRAVE, CALM, COLD, CONFUSED, CONTENT, CRAVING, CURIOUS,
    DEPRESSED, DISAPPOINTED, DISGUSTED, DISTRUSTFUL, EMBARRASSED,
    EXCITED, FLIRTATIOUS, FRUSTRATED, GRATEFUL, GRIEVING, GRUMPY,
    GUILTY, HAPPY, HOPEFUL, HOT, HUMBLED, HUMILIATED, HUNGRY,
    HURT, IMPRESSED, IN_AWE, IN_LOVE, INDIGNANT, INTERESTED,
    INTOXICATED, INVINCIBLE, JEALOUS, LONELY, LUSTFUL, MEAN, MISCHIEVOUS,
    NERVOUS, NEUTRAL, OFFENDED, OUTRAGED, PLAYFUL, PROUD, RELAXED,
    RELIEVED, REMORSEFUL, RESTLESS, SAD, SARCASTIC, SATISFIED,
    SERIOUS, SHOCKED, SHY, SICK, SLEEPY, SPONTANEOUS, STRESSED,
    STRONG, SURPRISED, THANKFUL, THIRSTY, TIRED, WEAK, WORRIED,
    UNKNOWN
};

// Activity general categories per XEP-0108
enum class ActivityGeneral {
    DOING_CHORES, DRINKING, EATING, EXERCISING, GROOMING,
    HAVING_APPOINTMENT, INACTIVE, RELAXING, TALKING, TRAVELING,
    UNDEFINED, WORKING, UNKNOWN
};

// Specific activity subtypes per XEP-0108
enum class ActivitySpecific {
    // Chores
    BUYING_GROCERIES, CLEANING, COOKING, DOING_MAINTENANCE,
    DOING_THE_DISHES, DOING_THE_LAUNDRY, GARDENING,
    RUNNING_AN_ERRAND, WALKING_THE_DOG,
    // Drinking
    DRINKING_ALCOHOL, DRINKING_COFFEE, DRINKING_TEA,
    // Eating
    EATING_A_MEAL, EATING_A_SNACK,
    // Exercising
    CYCLING, DANCING, HIKING, JOGGING, PLAYING_SPORTS,
    RUNNING, SKATING, SKIING, SNOWBOARDING, SPINNING,
    SWIMMING, TRAINING, WALKING, WORKING_OUT, YOGA,
    // Grooming
    AT_THE_SPA, BRUSHING_TEETH, COMBING_HAIR,
    GETTING_A_HAIRCUT, SHAVING, SHOWERING, TAKING_A_BATH,
    // Having appointment
    // Inactive
    DAY_OFF, HANGING_OUT, HIDING, ON_VACATION,
    PRAYING, SLEEPING, THINKING,
    // Relaxing
    FISHING, GAMING, GOING_OUT, PARTYING, READING,
    REHEARSING, SHOPPING, SMOKING, SOCIALIZING,
    SUNBATHING, WATCHING_A_MOVIE, WATCHING_TV,
    // Talking
    CHATTING, ON_THE_PHONE, TALKING_IN_PERSON,
    // Traveling
    COMMUTING, CYCLING_V2, DRIVING, IN_A_CAR,
    IN_A_TRAIN, ON_A_BUS, ON_A_PLANE, ON_A_TRIP,
    WALKING_V2,
    // Working
    CODING, IN_A_MEETING, PROGRAMMING, STUDYING,
    WRITING,
    NONE
};

// ============================================================================
// Profile Field Validation Limits
// ============================================================================

namespace profile_limits {
    constexpr size_t MAX_FULL_NAME       = 256;
    constexpr size_t MAX_NICKNAME        = 64;
    constexpr size_t MAX_EMAIL           = 254;
    constexpr size_t MAX_URL             = 2048;
    constexpr size_t MAX_PHONE           = 32;
    constexpr size_t MAX_TITLE           = 128;
    constexpr size_t MAX_ROLE            = 128;
    constexpr size_t MAX_ORG_NAME        = 128;
    constexpr size_t MAX_ORG_UNIT        = 128;
    constexpr size_t MAX_STREET          = 256;
    constexpr size_t MAX_LOCALITY        = 128;
    constexpr size_t MAX_REGION          = 128;
    constexpr size_t MAX_POSTAL_CODE     = 32;
    constexpr size_t MAX_COUNTRY         = 64;
    constexpr size_t MAX_DESCRIPTION     = 1024;
    constexpr size_t MAX_MOOD_TEXT       = 256;
    constexpr size_t MAX_TUNE_ARTIST     = 256;
    constexpr size_t MAX_TUNE_TITLE      = 256;
    constexpr size_t MAX_TUNE_SOURCE     = 1024;
    constexpr size_t MAX_TUNE_TRACK      = 128;
    constexpr size_t MAX_TUNE_URI        = 2048;
    constexpr size_t MAX_ACTIVITY_TEXT   = 256;
    constexpr size_t MAX_LOCATION_TEXT   = 256;
    constexpr size_t MAX_AVATAR_SIZE     = 8 * 1024 * 1024;  // 8 MB max avatar
    constexpr size_t MAX_VCARD_XML_SIZE  = 256 * 1024;       // 256 KB max vCard
    constexpr int    MAX_CACHE_SIZE      = 10000;            // Max cached profiles
    constexpr int64_t CACHE_TTL_SECONDS  = 300;              // 5 minute cache TTL
}

// ============================================================================
// Mood name mapping table (XEP-0107)
// ============================================================================

namespace {

const std::unordered_map<std::string, MoodValue> mood_name_to_value = {
    {"afraid",       MoodValue::AFRAID},
    {"amazed",       MoodValue::AMAZED},
    {"amorous",      MoodValue::AMOROUS},
    {"angry",        MoodValue::ANGRY},
    {"annoyed",      MoodValue::ANNOYED},
    {"anxious",      MoodValue::ANXIOUS},
    {"aroused",      MoodValue::AROUSED},
    {"ashamed",      MoodValue::ASHAMED},
    {"bored",        MoodValue::BORED},
    {"brave",        MoodValue::BRAVE},
    {"calm",         MoodValue::CALM},
    {"cold",         MoodValue::COLD},
    {"confused",     MoodValue::CONFUSED},
    {"content",      MoodValue::CONTENT},
    {"craving",      MoodValue::CRAVING},
    {"curious",      MoodValue::CURIOUS},
    {"depressed",    MoodValue::DEPRESSED},
    {"disappointed", MoodValue::DISAPPOINTED},
    {"disgusted",    MoodValue::DISGUSTED},
    {"distrustful",  MoodValue::DISTRUSTFUL},
    {"embarrassed",  MoodValue::EMBARRASSED},
    {"excited",      MoodValue::EXCITED},
    {"flirtatious",  MoodValue::FLIRTATIOUS},
    {"frustrated",   MoodValue::FRUSTRATED},
    {"grateful",     MoodValue::GRATEFUL},
    {"grieving",     MoodValue::GRIEVING},
    {"grumpy",       MoodValue::GRUMPY},
    {"guilty",       MoodValue::GUILTY},
    {"happy",        MoodValue::HAPPY},
    {"hopeful",      MoodValue::HOPEFUL},
    {"hot",          MoodValue::HOT},
    {"humbled",      MoodValue::HUMBLED},
    {"humiliated",   MoodValue::HUMILIATED},
    {"hungry",       MoodValue::HUNGRY},
    {"hurt",         MoodValue::HURT},
    {"impressed",    MoodValue::IMPRESSED},
    {"in_awe",       MoodValue::IN_AWE},
    {"in_love",      MoodValue::IN_LOVE},
    {"indignant",    MoodValue::INDIGNANT},
    {"interested",   MoodValue::INTERESTED},
    {"intoxicated",  MoodValue::INTOXICATED},
    {"invincible",   MoodValue::INVINCIBLE},
    {"jealous",      MoodValue::JEALOUS},
    {"lonely",       MoodValue::LONELY},
    {"lustful",      MoodValue::LUSTFUL},
    {"mean",         MoodValue::MEAN},
    {"mischievous",  MoodValue::MISCHIEVOUS},
    {"nervous",      MoodValue::NERVOUS},
    {"neutral",      MoodValue::NEUTRAL},
    {"offended",     MoodValue::OFFENDED},
    {"outraged",     MoodValue::OUTRAGED},
    {"playful",      MoodValue::PLAYFUL},
    {"proud",        MoodValue::PROUD},
    {"relaxed",      MoodValue::RELAXED},
    {"relieved",     MoodValue::RELIEVED},
    {"remorseful",   MoodValue::REMORSEFUL},
    {"restless",     MoodValue::RESTLESS},
    {"sad",          MoodValue::SAD},
    {"sarcastic",    MoodValue::SARCASTIC},
    {"satisfied",    MoodValue::SATISFIED},
    {"serious",      MoodValue::SERIOUS},
    {"shocked",      MoodValue::SHOCKED},
    {"shy",          MoodValue::SHY},
    {"sick",         MoodValue::SICK},
    {"sleepy",       MoodValue::SLEEPY},
    {"spontaneous",  MoodValue::SPONTANEOUS},
    {"stressed",     MoodValue::STRESSED},
    {"strong",       MoodValue::STRONG},
    {"surprised",    MoodValue::SURPRISED},
    {"thankful",     MoodValue::THANKFUL},
    {"thirsty",      MoodValue::THIRSTY},
    {"tired",        MoodValue::TIRED},
    {"weak",         MoodValue::WEAK},
    {"worried",      MoodValue::WORRIED},
};

const std::unordered_map<MoodValue, std::string> mood_value_to_name = []() {
    std::unordered_map<MoodValue, std::string> m;
    for (const auto& [name, val] : mood_name_to_value) {
        m[val] = name;
    }
    return m;
}();

const std::unordered_map<std::string, ActivityGeneral> activity_general_map = {
    {"doing_chores",      ActivityGeneral::DOING_CHORES},
    {"drinking",          ActivityGeneral::DRINKING},
    {"eating",            ActivityGeneral::EATING},
    {"exercising",        ActivityGeneral::EXERCISING},
    {"grooming",          ActivityGeneral::GROOMING},
    {"having_appointment",ActivityGeneral::HAVING_APPOINTMENT},
    {"inactive",          ActivityGeneral::INACTIVE},
    {"relaxing",          ActivityGeneral::RELAXING},
    {"talking",           ActivityGeneral::TALKING},
    {"traveling",         ActivityGeneral::TRAVELING},
    {"undefined",         ActivityGeneral::UNDEFINED},
    {"working",           ActivityGeneral::WORKING},
};

const std::unordered_map<ActivityGeneral, std::string> activity_general_to_name = []() {
    std::unordered_map<ActivityGeneral, std::string> m;
    for (const auto& [name, val] : activity_general_map) {
        m[val] = name;
    }
    return m;
}();

const std::unordered_map<std::string, ActivitySpecific> activity_specific_map = {
    // Chores
    {"buying_groceries",      ActivitySpecific::BUYING_GROCERIES},
    {"cleaning",              ActivitySpecific::CLEANING},
    {"cooking",               ActivitySpecific::COOKING},
    {"doing_maintenance",     ActivitySpecific::DOING_MAINTENANCE},
    {"doing_the_dishes",      ActivitySpecific::DOING_THE_DISHES},
    {"doing_the_laundry",     ActivitySpecific::DOING_THE_LAUNDRY},
    {"gardening",             ActivitySpecific::GARDENING},
    {"running_an_errand",     ActivitySpecific::RUNNING_AN_ERRAND},
    {"walking_the_dog",       ActivitySpecific::WALKING_THE_DOG},
    // Drinking
    {"drinking_alcohol",      ActivitySpecific::DRINKING_ALCOHOL},
    {"drinking_coffee",       ActivitySpecific::DRINKING_COFFEE},
    {"drinking_tea",          ActivitySpecific::DRINKING_TEA},
    // Eating
    {"eating_a_meal",         ActivitySpecific::EATING_A_MEAL},
    {"eating_a_snack",        ActivitySpecific::EATING_A_SNACK},
    // Exercising
    {"cycling",               ActivitySpecific::CYCLING},
    {"dancing",               ActivitySpecific::DANCING},
    {"hiking",                ActivitySpecific::HIKING},
    {"jogging",               ActivitySpecific::JOGGING},
    {"playing_sports",        ActivitySpecific::PLAYING_SPORTS},
    {"running",               ActivitySpecific::RUNNING},
    {"skating",               ActivitySpecific::SKATING},
    {"skiing",                ActivitySpecific::SKIING},
    {"snowboarding",          ActivitySpecific::SNOWBOARDING},
    {"spinning",              ActivitySpecific::SPINNING},
    {"swimming",              ActivitySpecific::SWIMMING},
    {"training",              ActivitySpecific::TRAINING},
    {"walking",               ActivitySpecific::WALKING},
    {"working_out",           ActivitySpecific::WORKING_OUT},
    {"yoga",                  ActivitySpecific::YOGA},
    // Grooming
    {"at_the_spa",            ActivitySpecific::AT_THE_SPA},
    {"brushing_teeth",        ActivitySpecific::BRUSHING_TEETH},
    {"combing_hair",          ActivitySpecific::COMBING_HAIR},
    {"getting_a_haircut",     ActivitySpecific::GETTING_A_HAIRCUT},
    {"shaving",               ActivitySpecific::SHAVING},
    {"showering",             ActivitySpecific::SHOWERING},
    {"taking_a_bath",         ActivitySpecific::TAKING_A_BATH},
    // Inactive
    {"day_off",               ActivitySpecific::DAY_OFF},
    {"hanging_out",           ActivitySpecific::HANGING_OUT},
    {"hiding",                ActivitySpecific::HIDING},
    {"on_vacation",           ActivitySpecific::ON_VACATION},
    {"praying",               ActivitySpecific::PRAYING},
    {"sleeping",              ActivitySpecific::SLEEPING},
    {"thinking",              ActivitySpecific::THINKING},
    // Relaxing
    {"fishing",               ActivitySpecific::FISHING},
    {"gaming",                ActivitySpecific::GAMING},
    {"going_out",             ActivitySpecific::GOING_OUT},
    {"partying",              ActivitySpecific::PARTYING},
    {"reading",               ActivitySpecific::READING},
    {"rehearsing",            ActivitySpecific::REHEARSING},
    {"shopping",              ActivitySpecific::SHOPPING},
    {"smoking",               ActivitySpecific::SMOKING},
    {"socializing",           ActivitySpecific::SOCIALIZING},
    {"sunbathing",            ActivitySpecific::SUNBATHING},
    {"watching_a_movie",      ActivitySpecific::WATCHING_A_MOVIE},
    {"watching_tv",           ActivitySpecific::WATCHING_TV},
    // Talking
    {"chatting",              ActivitySpecific::CHATTING},
    {"on_the_phone",          ActivitySpecific::ON_THE_PHONE},
    {"talking_in_person",     ActivitySpecific::TALKING_IN_PERSON},
    // Traveling
    {"commuting",             ActivitySpecific::COMMUTING},
    {"driving",               ActivitySpecific::DRIVING},
    {"in_a_car",              ActivitySpecific::IN_A_CAR},
    {"in_a_train",            ActivitySpecific::IN_A_TRAIN},
    {"on_a_bus",              ActivitySpecific::ON_A_BUS},
    {"on_a_plane",            ActivitySpecific::ON_A_PLANE},
    {"on_a_trip",             ActivitySpecific::ON_A_TRIP},
    // Working
    {"coding",                ActivitySpecific::CODING},
    {"in_a_meeting",          ActivitySpecific::IN_A_MEETING},
    {"programming",           ActivitySpecific::PROGRAMMING},
    {"studying",              ActivitySpecific::STUDYING},
    {"writing",               ActivitySpecific::WRITING},
};

const std::unordered_map<ActivitySpecific, std::string> activity_specific_to_name = []() {
    std::unordered_map<ActivitySpecific, std::string> m;
    for (const auto& [name, val] : activity_specific_map) {
        m[val] = name;
    }
    return m;
}();

} // anonymous namespace

// ============================================================================
// Core Data Structures
// ============================================================================

// ---------------------------------------------------------------------------
// VCardFull - Complete vCard-temp representation with all standard fields
// ---------------------------------------------------------------------------
struct VCardFull {
    std::string jid;
    std::string version;           // vCard version (2.1, 3.0, 4.0)
    std::string full_name;         // FN: formatted name
    std::string given_name;        // N: GIVEN
    std::string family_name;       // N: FAMILY
    std::string middle_name;       // N: MIDDLE
    std::string prefix;            // N: PREFIX (Mr., Mrs., Dr., etc.)
    std::string suffix;            // N: SUFFIX (Jr., Sr., III, etc.)
    std::string nickname;          // NICKNAME
    std::string email;             // EMAIL -> USERID
    std::string email_home;
    std::string email_work;
    std::string url;               // URL
    std::string url_home;
    std::string url_work;
    std::string phone_voice;       // TEL -> VOICE
    std::string phone_cell;        // TEL -> CELL
    std::string phone_work;        // TEL -> WORK
    std::string phone_home;        // TEL -> HOME
    std::string phone_fax;         // TEL -> FAX
    std::string title;             // TITLE
    std::string role;              // ROLE
    std::string org_name;          // ORG -> ORGNAME
    std::string org_unit;          // ORG -> ORGUNIT
    std::string birthday;          // BDAY (YYYY-MM-DD)
    std::string note;              // NOTE
    std::string description;       // DESC
    std::string categories;        // CATEGORIES (comma-separated)

    // Address: home
    std::string addr_home_street;
    std::string addr_home_locality;
    std::string addr_home_region;
    std::string addr_home_postal_code;
    std::string addr_home_country;

    // Address: work
    std::string addr_work_street;
    std::string addr_work_locality;
    std::string addr_work_region;
    std::string addr_work_postal_code;
    std::string addr_work_country;

    // Photo
    std::string photo_type;        // MIME type
    std::string photo_binval;      // Base64-encoded binary
    std::string photo_url;         // External photo URL

    // Logo
    std::string logo_type;
    std::string logo_binval;

    // Keys
    std::vector<std::pair<std::string, std::string>> public_keys; // type, data

    // Timestamps
    int64_t created_at;
    int64_t updated_at;
    int64_t revision;

    VCardFull() : created_at(0), updated_at(0), revision(0) {}

    /**
     * Serialize to vCard-temp XML.
     */
    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<vCard xmlns='vcard-temp'>";

        // VERSION
        if (!version.empty()) {
            oss << "<VERSION>" << detail::xml_escape(version) << "</VERSION>";
        }
        // FN
        if (!full_name.empty()) {
            oss << "<FN>" << detail::xml_escape(full_name) << "</FN>";
        }
        // N (structured name)
        if (!family_name.empty() || !given_name.empty()) {
            oss << "<N>"
                << "<FAMILY>" << detail::xml_escape(family_name) << "</FAMILY>"
                << "<GIVEN>" << detail::xml_escape(given_name) << "</GIVEN>"
                << "<MIDDLE>" << detail::xml_escape(middle_name) << "</MIDDLE>"
                << "<PREFIX>" << detail::xml_escape(prefix) << "</PREFIX>"
                << "<SUFFIX>" << detail::xml_escape(suffix) << "</SUFFIX>"
                << "</N>";
        }
        // NICKNAME
        if (!nickname.empty()) {
            oss << "<NICKNAME>" << detail::xml_escape(nickname) << "</NICKNAME>";
        }
        // EMAIL
        if (!email.empty()) {
            oss << "<EMAIL><USERID>" << detail::xml_escape(email)
                << "</USERID></EMAIL>";
        }
        if (!email_home.empty()) {
            oss << "<EMAIL><HOME/><USERID>" << detail::xml_escape(email_home)
                << "</USERID></EMAIL>";
        }
        if (!email_work.empty()) {
            oss << "<EMAIL><WORK/><USERID>" << detail::xml_escape(email_work)
                << "</USERID></EMAIL>";
        }
        // URL
        if (!url.empty()) {
            oss << "<URL>" << detail::xml_escape(url) << "</URL>";
        }
        // TEL
        auto write_tel = [&](const std::string& type, const std::string& num) {
            if (!num.empty()) {
                oss << "<TEL>";
                if (!type.empty()) oss << "<" << type << "/>";
                oss << "<NUMBER>" << detail::xml_escape(num) << "</NUMBER>";
                oss << "</TEL>";
            }
        };
        write_tel("VOICE", phone_voice);
        write_tel("CELL",  phone_cell);
        write_tel("WORK",  phone_work);
        write_tel("HOME",  phone_home);
        write_tel("FAX",   phone_fax);

        // TITLE / ROLE
        if (!title.empty()) {
            oss << "<TITLE>" << detail::xml_escape(title) << "</TITLE>";
        }
        if (!role.empty()) {
            oss << "<ROLE>" << detail::xml_escape(role) << "</ROLE>";
        }
        // ORG
        if (!org_name.empty() || !org_unit.empty()) {
            oss << "<ORG>"
                << "<ORGNAME>" << detail::xml_escape(org_name) << "</ORGNAME>";
            if (!org_unit.empty()) {
                oss << "<ORGUNIT>" << detail::xml_escape(org_unit) << "</ORGUNIT>";
            }
            oss << "</ORG>";
        }
        // BDAY
        if (!birthday.empty()) {
            oss << "<BDAY>" << detail::xml_escape(birthday) << "</BDAY>";
        }
        // NOTE / DESC
        if (!note.empty()) {
            oss << "<NOTE>" << detail::xml_escape(note) << "</NOTE>";
        }
        if (!description.empty()) {
            oss << "<DESC>" << detail::xml_escape(description) << "</DESC>";
        }
        // CATEGORIES
        if (!categories.empty()) {
            oss << "<CATEGORIES>" << detail::xml_escape(categories) << "</CATEGORIES>";
        }
        // ADR HOME
        if (!addr_home_street.empty() || !addr_home_locality.empty() ||
            !addr_home_region.empty() || !addr_home_country.empty()) {
            oss << "<ADR><HOME/>"
                << "<STREET>" << detail::xml_escape(addr_home_street) << "</STREET>"
                << "<LOCALITY>" << detail::xml_escape(addr_home_locality) << "</LOCALITY>"
                << "<REGION>" << detail::xml_escape(addr_home_region) << "</REGION>"
                << "<PCODE>" << detail::xml_escape(addr_home_postal_code) << "</PCODE>"
                << "<CTRY>" << detail::xml_escape(addr_home_country) << "</CTRY>"
                << "</ADR>";
        }
        // ADR WORK
        if (!addr_work_street.empty() || !addr_work_locality.empty() ||
            !addr_work_region.empty() || !addr_work_country.empty()) {
            oss << "<ADR><WORK/>"
                << "<STREET>" << detail::xml_escape(addr_work_street) << "</STREET>"
                << "<LOCALITY>" << detail::xml_escape(addr_work_locality) << "</LOCALITY>"
                << "<REGION>" << detail::xml_escape(addr_work_region) << "</REGION>"
                << "<PCODE>" << detail::xml_escape(addr_work_postal_code) << "</PCODE>"
                << "<CTRY>" << detail::xml_escape(addr_work_country) << "</CTRY>"
                << "</ADR>";
        }
        // PHOTO
        if (!photo_binval.empty() || !photo_url.empty()) {
            oss << "<PHOTO>";
            if (!photo_type.empty()) {
                oss << "<TYPE>" << detail::xml_escape(photo_type) << "</TYPE>";
            }
            if (!photo_binval.empty()) {
                oss << "<BINVAL>" << detail::xml_escape(photo_binval) << "</BINVAL>";
            }
            if (!photo_url.empty()) {
                oss << "<EXTVAL>" << detail::xml_escape(photo_url) << "</EXTVAL>";
            }
            oss << "</PHOTO>";
        }
        // LOGO
        if (!logo_binval.empty()) {
            oss << "<LOGO>";
            if (!logo_type.empty()) {
                oss << "<TYPE>" << detail::xml_escape(logo_type) << "</TYPE>";
            }
            oss << "<BINVAL>" << detail::xml_escape(logo_binval) << "</BINVAL>";
            oss << "</LOGO>";
        }
        // KEY
        for (const auto& [key_type, key_data] : public_keys) {
            oss << "<KEY><TYPE>" << detail::xml_escape(key_type) << "</TYPE>"
                << "<KEYVAL>" << detail::xml_escape(key_data) << "</KEYVAL></KEY>";
        }
        // REV
        if (revision > 0) {
            oss << "<REV>" << revision << "</REV>";
        }

        oss << "</vCard>";
        return oss.str();
    }

    /**
     * Serialize to minimal vCard (FN + NICKNAME + PHOTO only).
     * Used for PEP profile notifications.
     */
    std::string to_minimal_xml() const {
        std::ostringstream oss;
        oss << "<vCard xmlns='vcard-temp'>";
        if (!full_name.empty()) {
            oss << "<FN>" << detail::xml_escape(full_name) << "</FN>";
        }
        if (!nickname.empty()) {
            oss << "<NICKNAME>" << detail::xml_escape(nickname) << "</NICKNAME>";
        }
        if (!photo_binval.empty()) {
            oss << "<PHOTO>";
            if (!photo_type.empty()) {
                oss << "<TYPE>" << detail::xml_escape(photo_type) << "</TYPE>";
            }
            oss << "<BINVAL>" << detail::xml_escape(photo_binval) << "</BINVAL>";
            oss << "</PHOTO>";
        }
        oss << "</vCard>";
        return oss.str();
    }
};

// ---------------------------------------------------------------------------
// AvatarMetadata - XEP-0084 avatar metadata info
// ---------------------------------------------------------------------------
struct AvatarInfo {
    std::string id;            // Unique avatar ID
    std::string mime_type;     // e.g., "image/png", "image/jpeg"
    int64_t width;             // Width in pixels
    int64_t height;            // Height in pixels
    int64_t size_bytes;        // Size in bytes
    std::string sha1;          // SHA-1 hash of the image data
    std::string url;           // URL to retrieve the avatar (if not inline)

    AvatarInfo() : width(0), height(0), size_bytes(0) {}

    /**
     * Serialize to XEP-0084 metadata XML info element.
     */
    std::string to_metadata_xml() const {
        std::ostringstream oss;
        oss << "<info";
        if (!id.empty()) {
            oss << " id='" << detail::xml_attr_escape(id) << "'";
        }
        oss << " bytes='" << size_bytes << "'";
        if (!mime_type.empty()) {
            oss << " type='" << detail::xml_attr_escape(mime_type) << "'";
        }
        if (width > 0) oss << " width='" << width << "'";
        if (height > 0) oss << " height='" << height << "'";
        if (!sha1.empty()) {
            oss << ">";
            oss << "<hash xmlns='urn:xmpp:hashes:2' algo='sha-1'>"
                << detail::xml_escape(sha1) << "</hash>";
            oss << "</info>";
        } else {
            oss << "/>";
        }
        return oss.str();
    }
};

// ---------------------------------------------------------------------------
// AvatarMetadataSet - Full avatar metadata for a user (XEP-0084)
// ---------------------------------------------------------------------------
struct AvatarMetadataSet {
    std::vector<AvatarInfo> avatars;
    std::string pointer;   // Pointer to an avatar URL

    std::string to_metadata_xml() const {
        std::ostringstream oss;
        oss << "<metadata xmlns='urn:xmpp:avatar:metadata'>";
        for (const auto& info : avatars) {
            oss << info.to_metadata_xml();
        }
        if (!pointer.empty()) {
            oss << "<pointer>" << detail::xml_escape(pointer) << "</pointer>";
        }
        oss << "</metadata>";
        return oss.str();
    }

    std::optional<AvatarInfo> get_primary_avatar() const {
        if (!avatars.empty()) return avatars.front();
        return std::nullopt;
    }
};

// ---------------------------------------------------------------------------
// Mood (XEP-0107)
// ---------------------------------------------------------------------------
struct MoodInfo {
    MoodValue value;
    std::string text;  // Optional human-readable description

    MoodInfo() : value(MoodValue::UNKNOWN) {}

    std::string to_pep_payload_xml() const {
        std::ostringstream oss;
        oss << "<mood xmlns='http://jabber.org/protocol/mood'>";
        auto it = mood_value_to_name.find(value);
        if (it != mood_value_to_name.end()) {
            oss << "<" << it->second << "/>";
        }
        if (!text.empty()) {
            oss << "<text>" << detail::xml_escape(text) << "</text>";
        }
        oss << "</mood>";
        return oss.str();
    }
};

// ---------------------------------------------------------------------------
// Activity (XEP-0108)
// ---------------------------------------------------------------------------
struct ActivityInfo {
    ActivityGeneral general;
    ActivitySpecific specific;
    std::string text;  // Optional human-readable description

    ActivityInfo()
        : general(ActivityGeneral::UNKNOWN)
        , specific(ActivitySpecific::NONE) {}

    std::string to_pep_payload_xml() const {
        std::ostringstream oss;
        oss << "<activity xmlns='http://jabber.org/protocol/activity'>";

        auto gen_it = activity_general_to_name.find(general);
        if (gen_it != activity_general_to_name.end()) {
            oss << "<" << gen_it->second;
            auto spec_it = activity_specific_to_name.find(specific);
            if (spec_it != activity_specific_to_name.end() && specific != ActivitySpecific::NONE) {
                oss << "><" << spec_it->second << "/></" << gen_it->second << ">";
            } else {
                oss << "/>";
            }
        }
        if (!text.empty()) {
            oss << "<text>" << detail::xml_escape(text) << "</text>";
        }
        oss << "</activity>";
        return oss.str();
    }
};

// ---------------------------------------------------------------------------
// Tune (XEP-0118)
// ---------------------------------------------------------------------------
struct TuneInfo {
    std::string artist;
    std::string title;
    std::string source;    // Album
    std::string track;     // Track number (e.g., "4/12")
    int64_t length;        // Length in seconds
    int64_t rating;        // 1-10 rating
    std::string uri;       // URI of the tune (e.g., spotify:track:...)

    TuneInfo() : length(0), rating(0) {}

    std::string to_pep_payload_xml() const {
        std::ostringstream oss;
        oss << "<tune xmlns='http://jabber.org/protocol/tune'>";
        if (!artist.empty()) oss << "<artist>" << detail::xml_escape(artist) << "</artist>";
        if (!title.empty())  oss << "<title>" << detail::xml_escape(title) << "</title>";
        if (!source.empty()) oss << "<source>" << detail::xml_escape(source) << "</source>";
        if (!track.empty())  oss << "<track>" << detail::xml_escape(track) << "</track>";
        if (length > 0)      oss << "<length>" << length << "</length>";
        if (rating > 0 && rating <= 10) oss << "<rating>" << rating << "</rating>";
        if (!uri.empty())    oss << "<uri>" << detail::xml_escape(uri) << "</uri>";
        oss << "</tune>";
        return oss.str();
    }
};

// ---------------------------------------------------------------------------
// Geolocation (XEP-0080)
// ---------------------------------------------------------------------------
struct GeolocationInfo {
    double latitude;
    double longitude;
    double altitude;
    double speed;
    double bearing;
    double accuracy;
    std::string country;
    std::string region;
    std::string locality;
    std::string area;
    std::string street;
    std::string building;
    std::string floor;
    std::string room;
    std::string postal_code;
    std::string description;
    std::string timestamp;
    std::string uri;
    std::string tzo;           // Timezone offset
    std::string datum;         // Geodetic datum (e.g., "WGS84")

    GeolocationInfo()
        : latitude(std::numeric_limits<double>::quiet_NaN())
        , longitude(std::numeric_limits<double>::quiet_NaN())
        , altitude(std::numeric_limits<double>::quiet_NaN())
        , speed(std::numeric_limits<double>::quiet_NaN())
        , bearing(std::numeric_limits<double>::quiet_NaN())
        , accuracy(std::numeric_limits<double>::quiet_NaN()) {}

    bool has_basic_position() const {
        return !std::isnan(latitude) && !std::isnan(longitude);
    }

    std::string to_pep_payload_xml() const {
        std::ostringstream oss;
        oss << "<geoloc xmlns='http://jabber.org/protocol/geoloc'";
        if (!timestamp.empty()) {
            oss << " xml:lang='en'";
        }
        oss << ">";

        auto write_optional = [&](const char* tag, const std::string& val) {
            if (!val.empty()) {
                oss << "<" << tag << ">" << detail::xml_escape(val) << "</" << tag << ">";
            }
        };

        if (!std::isnan(latitude))  oss << "<lat>" << latitude << "</lat>";
        if (!std::isnan(longitude)) oss << "<lon>" << longitude << "</lon>";
        if (!std::isnan(altitude))  oss << "<alt>" << altitude << "</alt>";
        if (!std::isnan(speed))     oss << "<speed>" << speed << "</speed>";
        if (!std::isnan(bearing))   oss << "<bearing>" << bearing << "</bearing>";
        if (!std::isnan(accuracy))  oss << "<accuracy>" << accuracy << "</accuracy>";

        write_optional("country",    country);
        write_optional("region",     region);
        write_optional("locality",   locality);
        write_optional("area",       area);
        write_optional("street",     street);
        write_optional("building",   building);
        write_optional("floor",      floor);
        write_optional("room",       room);
        write_optional("postalcode", postal_code);
        write_optional("description",description);
        write_optional("timestamp",  timestamp);
        write_optional("uri",        uri);
        write_optional("tzo",        tzo);
        write_optional("datum",      datum);

        oss << "</geoloc>";
        return oss.str();
    }
};

// ---------------------------------------------------------------------------
// Full User Profile combining all data types
// ---------------------------------------------------------------------------
struct UserProfile {
    std::string jid;
    VCardFull vcard;
    AvatarMetadataSet avatar_metadata;
    std::vector<uint8_t> avatar_data;   // Raw avatar binary data
    std::string avatar_mime_type;
    MoodInfo mood;
    ActivityInfo activity;
    TuneInfo tune;
    GeolocationInfo geoloc;
    std::string nickname_pep;           // Nickname from PEP (XEP-0172)

    // Metadata
    int64_t cached_at;
    int64_t vcard_updated_at;
    int64_t avatar_updated_at;

    UserProfile() : cached_at(0), vcard_updated_at(0), avatar_updated_at(0) {}
};

// ============================================================================
// Profile Field Validator
// ============================================================================

class ProfileValidator {
public:
    struct ValidationError {
        std::string field;
        std::string message;
    };

    struct ValidationResult {
        bool valid;
        std::vector<ValidationError> errors;

        void add_error(const std::string& field, const std::string& msg) {
            valid = false;
            errors.push_back({field, msg});
        }
    };

    /**
     * Validate a full vCard against all constraints.
     */
    static ValidationResult validate_vcard(const VCardFull& vc) {
        ValidationResult result;

        // FN validation
        if (vc.full_name.size() > profile_limits::MAX_FULL_NAME) {
            result.add_error("full_name", "Full name exceeds maximum length of " +
                std::to_string(profile_limits::MAX_FULL_NAME));
        }

        // Nickname validation
        if (vc.nickname.size() > profile_limits::MAX_NICKNAME) {
            result.add_error("nickname", "Nickname exceeds maximum length of " +
                std::to_string(profile_limits::MAX_NICKNAME));
        }
        if (!vc.nickname.empty() && !detail::is_printable_ascii(vc.nickname)) {
            result.add_error("nickname", "Nickname contains non-printable characters");
        }

        // Email validation
        auto validate_email_field = [&](const std::string& email, const std::string& field) {
            if (email.size() > profile_limits::MAX_EMAIL) {
                result.add_error(field, "Email exceeds maximum length of " +
                    std::to_string(profile_limits::MAX_EMAIL));
            }
            if (!email.empty() && !validate_email_format(email)) {
                result.add_error(field, "Invalid email format: " + email);
            }
        };
        validate_email_field(vc.email, "email");
        validate_email_field(vc.email_home, "email_home");
        validate_email_field(vc.email_work, "email_work");

        // URL validation
        auto validate_url_field = [&](const std::string& url, const std::string& field) {
            if (url.size() > profile_limits::MAX_URL) {
                result.add_error(field, "URL exceeds maximum length of " +
                    std::to_string(profile_limits::MAX_URL));
            }
            if (!url.empty() && !validate_url_format(url)) {
                result.add_error(field, "Invalid URL format: " + url);
            }
        };
        validate_url_field(vc.url, "url");
        validate_url_field(vc.url_home, "url_home");
        validate_url_field(vc.url_work, "url_work");

        // Phone validation
        auto validate_phone = [&](const std::string& phone, const std::string& field) {
            if (phone.size() > profile_limits::MAX_PHONE) {
                result.add_error(field, "Phone exceeds maximum length of " +
                    std::to_string(profile_limits::MAX_PHONE));
            }
        };
        validate_phone(vc.phone_voice, "phone_voice");
        validate_phone(vc.phone_cell, "phone_cell");
        validate_phone(vc.phone_work, "phone_work");
        validate_phone(vc.phone_home, "phone_home");
        validate_phone(vc.phone_fax, "phone_fax");

        // Title / role
        if (vc.title.size() > profile_limits::MAX_TITLE) {
            result.add_error("title", "Title exceeds maximum length");
        }
        if (vc.role.size() > profile_limits::MAX_ROLE) {
            result.add_error("role", "Role exceeds maximum length");
        }

        // Organization
        if (vc.org_name.size() > profile_limits::MAX_ORG_NAME) {
            result.add_error("org_name", "Organization name exceeds maximum length");
        }
        if (vc.org_unit.size() > profile_limits::MAX_ORG_UNIT) {
            result.add_error("org_unit", "Organization unit exceeds maximum length");
        }

        // Address fields
        if (vc.addr_home_street.size() > profile_limits::MAX_STREET)
            result.add_error("addr_home_street", "Street exceeds maximum length");
        if (vc.addr_home_locality.size() > profile_limits::MAX_LOCALITY)
            result.add_error("addr_home_locality", "Locality exceeds maximum length");
        if (vc.addr_home_region.size() > profile_limits::MAX_REGION)
            result.add_error("addr_home_region", "Region exceeds maximum length");
        if (vc.addr_home_postal_code.size() > profile_limits::MAX_POSTAL_CODE)
            result.add_error("addr_home_postal_code", "Postal code exceeds maximum length");
        if (vc.addr_home_country.size() > profile_limits::MAX_COUNTRY)
            result.add_error("addr_home_country", "Country exceeds maximum length");

        if (vc.addr_work_street.size() > profile_limits::MAX_STREET)
            result.add_error("addr_work_street", "Street exceeds maximum length");
        if (vc.addr_work_locality.size() > profile_limits::MAX_LOCALITY)
            result.add_error("addr_work_locality", "Locality exceeds maximum length");
        if (vc.addr_work_region.size() > profile_limits::MAX_REGION)
            result.add_error("addr_work_region", "Region exceeds maximum length");
        if (vc.addr_work_postal_code.size() > profile_limits::MAX_POSTAL_CODE)
            result.add_error("addr_work_postal_code", "Postal code exceeds maximum length");
        if (vc.addr_work_country.size() > profile_limits::MAX_COUNTRY)
            result.add_error("addr_work_country", "Country exceeds maximum length");

        // Description
        if (vc.description.size() > profile_limits::MAX_DESCRIPTION) {
            result.add_error("description", "Description exceeds maximum length");
        }

        // Photo validation
        if (!vc.photo_binval.empty()) {
            // Validate Base64 format
            if (!validate_base64(vc.photo_binval)) {
                result.add_error("photo_binval", "Photo data is not valid Base64");
            }
            // Check decoded size
            auto decoded = detail::base64_decode(vc.photo_binval);
            if (decoded.size() > profile_limits::MAX_AVATAR_SIZE) {
                result.add_error("photo_binval", "Avatar exceeds maximum size of " +
                    std::to_string(profile_limits::MAX_AVATAR_SIZE / (1024*1024)) + " MB");
            }
        }

        // Validate photo MIME type
        if (!vc.photo_type.empty() && !validate_mime_type(vc.photo_type)) {
            result.add_error("photo_type", "Invalid MIME type: " + vc.photo_type);
        }

        // Validate birthday format (YYYY-MM-DD or YYYYMMDD)
        if (!vc.birthday.empty() && !validate_birthday(vc.birthday)) {
            result.add_error("birthday", "Invalid birthday format, expected YYYY-MM-DD");
        }

        return result;
    }

    /**
     * Validate mood info.
     */
    static ValidationResult validate_mood(const MoodInfo& mood) {
        ValidationResult result;
        if (mood.text.size() > profile_limits::MAX_MOOD_TEXT) {
            result.add_error("mood_text", "Mood text exceeds maximum length");
        }
        return result;
    }

    /**
     * Validate activity info.
     */
    static ValidationResult validate_activity(const ActivityInfo& activity) {
        ValidationResult result;
        if (activity.text.size() > profile_limits::MAX_ACTIVITY_TEXT) {
            result.add_error("activity_text", "Activity text exceeds maximum length");
        }
        return result;
    }

    /**
     * Validate tune info.
     */
    static ValidationResult validate_tune(const TuneInfo& tune) {
        ValidationResult result;
        if (tune.artist.size() > profile_limits::MAX_TUNE_ARTIST)
            result.add_error("tune_artist", "Artist exceeds maximum length");
        if (tune.title.size() > profile_limits::MAX_TUNE_TITLE)
            result.add_error("tune_title", "Title exceeds maximum length");
        if (tune.source.size() > profile_limits::MAX_TUNE_SOURCE)
            result.add_error("tune_source", "Source exceeds maximum length");
        if (tune.track.size() > profile_limits::MAX_TUNE_TRACK)
            result.add_error("tune_track", "Track exceeds maximum length");
        if (tune.uri.size() > profile_limits::MAX_TUNE_URI)
            result.add_error("tune_uri", "URI exceeds maximum length");
        if (tune.rating < 0 || tune.rating > 10)
            result.add_error("tune_rating", "Rating must be 0-10");
        if (tune.length < 0)
            result.add_error("tune_length", "Length must be non-negative");
        return result;
    }

    /**
     * Validate geolocation info.
     */
    static ValidationResult validate_geolocation(const GeolocationInfo& geo) {
        ValidationResult result;
        if (!std::isnan(geo.latitude) && (geo.latitude < -90.0 || geo.latitude > 90.0)) {
            result.add_error("latitude", "Latitude must be between -90 and 90");
        }
        if (!std::isnan(geo.longitude) && (geo.longitude < -180.0 || geo.longitude > 180.0)) {
            result.add_error("longitude", "Longitude must be between -180 and 180");
        }
        if (!std::isnan(geo.accuracy) && geo.accuracy < 0) {
            result.add_error("accuracy", "Accuracy must be non-negative");
        }
        if (!std::isnan(geo.speed) && geo.speed < 0) {
            result.add_error("speed", "Speed must be non-negative");
        }
        if (!std::isnan(geo.bearing) && (geo.bearing < 0.0 || geo.bearing > 360.0)) {
            result.add_error("bearing", "Bearing must be between 0 and 360");
        }
        if (geo.description.size() > profile_limits::MAX_LOCATION_TEXT) {
            result.add_error("description", "Location description exceeds maximum length");
        }
        return result;
    }

    /**
     * Validate avatar data.
     */
    static ValidationResult validate_avatar_data(const std::vector<uint8_t>& data,
                                                  const std::string& mime_type) {
        ValidationResult result;
        if (data.size() > profile_limits::MAX_AVATAR_SIZE) {
            result.add_error("avatar_data", "Avatar exceeds maximum size of " +
                std::to_string(profile_limits::MAX_AVATAR_SIZE / (1024*1024)) + " MB");
        }
        if (data.empty()) {
            result.add_error("avatar_data", "Avatar data is empty");
        }
        if (mime_type.empty()) {
            result.add_error("avatar_mime_type", "MIME type is required");
        }
        if (!mime_type.empty() && !validate_mime_type(mime_type)) {
            result.add_error("avatar_mime_type", "Invalid MIME type: " + mime_type);
        }
        return result;
    }

    /**
     * Validate nickname for PEP (XEP-0172).
     */
    static ValidationResult validate_nickname(const std::string& nick) {
        ValidationResult result;
        if (nick.empty()) {
            result.add_error("nickname", "Nickname cannot be empty");
        }
        if (nick.size() > profile_limits::MAX_NICKNAME) {
            result.add_error("nickname", "Nickname exceeds maximum length of " +
                std::to_string(profile_limits::MAX_NICKNAME));
        }
        if (!detail::is_printable_ascii(nick)) {
            result.add_error("nickname", "Nickname contains non-printable characters");
        }
        return result;
    }

private:
    static bool validate_email_format(const std::string& email) {
        // Basic email validation
        size_t at_pos = email.find('@');
        if (at_pos == std::string::npos || at_pos == 0 || at_pos == email.size() - 1)
            return false;
        size_t dot_pos = email.find('.', at_pos);
        if (dot_pos == std::string::npos || dot_pos == email.size() - 1)
            return false;
        for (char c : email) {
            if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126)
                return false;
        }
        return true;
    }

    static bool validate_url_format(const std::string& url) {
        return url.find("://") != std::string::npos && url.size() > 6;
    }

    static bool validate_base64(const std::string& s) {
        if (s.size() % 4 != 0) return false;
        for (size_t i = 0; i < s.size(); ++i) {
            if (!detail::is_base64_char(s[i])) return false;
            if (s[i] == '=' && i < s.size() - 2) return false;
        }
        return true;
    }

    static bool validate_mime_type(const std::string& mime) {
        size_t slash = mime.find('/');
        if (slash == std::string::npos || slash == 0 || slash == mime.size() - 1)
            return false;
        // Accept common image types
        std::string type = mime.substr(0, slash);
        std::string subtype = mime.substr(slash + 1);
        if (type != "image") return false;
        return !subtype.empty() && subtype.size() <= 64;
    }

    static bool validate_birthday(const std::string& bday) {
        if (bday.size() != 10 && bday.size() != 8) return false;
        // YYYY-MM-DD
        if (bday.size() == 10) {
            if (bday[4] != '-' || bday[7] != '-') return false;
            try {
                int y = std::stoi(bday.substr(0, 4));
                int m = std::stoi(bday.substr(5, 2));
                int d = std::stoi(bday.substr(8, 2));
                if (y < 1900 || y > 2100 || m < 1 || m > 12 || d < 1 || d > 31)
                    return false;
            } catch (...) { return false; }
        }
        return true;
    }
};

// ============================================================================
// VCard XML Parser
// ============================================================================

class VCardParser {
public:
    /**
     * Extract text content from a simple XML tag.
     * Used by both VCardParser and PEPPayloadParser.
     */
    static std::string parse_text_tag(const std::string& xml, const std::string& tag);

    /**
     * Parse a vCard from raw XML string.
     * This is a lightweight parser - for production use a proper XML parser.
     */
    static std::optional<VCardFull> parse(const std::string& xml) {
        VCardFull vc;
        if (xml.empty()) return vc;

        // Extract text content between tags
        auto get_tag_content = [&](const std::string& tag, const std::string& haystack)
            -> std::optional<std::string> {
            std::string open = "<" + tag;
            size_t start = haystack.find(open);
            if (start == std::string::npos) return std::nullopt;

            // Find the closing '>' for the opening tag
            start = haystack.find('>', start);
            if (start == std::string::npos) return std::nullopt;
            ++start;

            std::string close = "</" + tag + ">";
            size_t end = haystack.find(close, start);
            if (end == std::string::npos) return std::nullopt;

            return haystack.substr(start, end - start);
        };

        // Get content and trim
        auto get_text = [&](const std::string& tag) -> std::string {
            auto content = get_tag_content(tag, xml);
            if (!content.has_value()) return "";
            return detail::trim(content.value());
        };

        vc.full_name = get_text("FN");
        vc.nickname = get_text("NICKNAME");
        vc.version = get_text("VERSION");
        vc.title = get_text("TITLE");
        vc.role = get_text("ROLE");
        vc.note = get_text("NOTE");
        vc.description = get_text("DESC");
        vc.categories = get_text("CATEGORIES");
        vc.birthday = get_text("BDAY");
        vc.url = get_text("URL");

        // Parse N (structured name)
        auto n_content = get_tag_content("N", xml);
        if (n_content.has_value()) {
            vc.family_name = get_text_in_content("FAMILY", n_content.value());
            vc.given_name  = get_text_in_content("GIVEN", n_content.value());
            vc.middle_name = get_text_in_content("MIDDLE", n_content.value());
            vc.prefix      = get_text_in_content("PREFIX", n_content.value());
            vc.suffix      = get_text_in_content("SUFFIX", n_content.value());
        }

        // Parse ORG
        auto org_content = get_tag_content("ORG", xml);
        if (org_content.has_value()) {
            vc.org_name = get_text_in_content("ORGNAME", org_content.value());
            vc.org_unit = get_text_in_content("ORGUNIT", org_content.value());
        }

        // Parse PHOTO
        auto photo_content = get_tag_content("PHOTO", xml);
        if (photo_content.has_value()) {
            vc.photo_type  = get_text_in_content("TYPE", photo_content.value());
            vc.photo_binval = get_text_in_content("BINVAL", photo_content.value());
            vc.photo_url   = get_text_in_content("EXTVAL", photo_content.value());
        }

        // Parse LOGO
        auto logo_content = get_tag_content("LOGO", xml);
        if (logo_content.has_value()) {
            vc.logo_type  = get_text_in_content("TYPE", logo_content.value());
            vc.logo_binval = get_text_in_content("BINVAL", logo_content.value());
        }

        // Parse EMAIL fields
        vc.email = parse_email(xml, "");
        vc.email_home = parse_email(xml, "HOME");
        vc.email_work = parse_email(xml, "WORK");

        // Parse TEL fields
        vc.phone_voice = parse_tel(xml, "VOICE");
        vc.phone_cell  = parse_tel(xml, "CELL");
        vc.phone_work  = parse_tel(xml, "WORK");
        vc.phone_home  = parse_tel(xml, "HOME");
        vc.phone_fax   = parse_tel(xml, "FAX");

        // Parse ADR HOME
        auto adr_home = parse_adr(xml, "HOME");
        vc.addr_home_street     = adr_home.first;
        vc.addr_home_locality   = adr_home.second.locality;
        vc.addr_home_region     = adr_home.second.region;
        vc.addr_home_postal_code = adr_home.second.pcode;
        vc.addr_home_country    = adr_home.second.country;

        // Parse ADR WORK
        auto adr_work = parse_adr(xml, "WORK");
        vc.addr_work_street     = adr_work.first;
        vc.addr_work_locality   = adr_work.second.locality;
        vc.addr_work_region     = adr_work.second.region;
        vc.addr_work_postal_code = adr_work.second.pcode;
        vc.addr_work_country    = adr_work.second.country;

        // Parse KEY
        vc.public_keys = parse_keys(xml);

        return vc;
    }

private:
    struct AddressComponents {
        std::string street;
        std::string locality;
        std::string region;
        std::string pcode;
        std::string country;
    };

    static std::string get_text_in_content(const std::string& tag, const std::string& content) {
        std::string open = "<" + tag;
        size_t start = content.find(open);
        if (start == std::string::npos) return "";

        // Handle self-closing
        size_t close_self = content.find("/>", start);
        if (close_self != std::string::npos) {
            // Check if more content after
        }

        start = content.find('>', start);
        if (start == std::string::npos) return "";
        ++start;

        std::string close = "</" + tag + ">";
        size_t end = content.find(close, start);
        if (end == std::string::npos) return "";

        return detail::trim(content.substr(start, end - start));
    }

    static std::string parse_email(const std::string& xml, const std::string& type_hint) {
        // Find EMAIL blocks and match by child type
        size_t pos = 0;
        while (true) {
            size_t email_start = xml.find("<EMAIL>", pos);
            if (email_start == std::string::npos) break;
            size_t email_end = xml.find("</EMAIL>", email_start);
            if (email_end == std::string::npos) break;

            std::string email_block = xml.substr(email_start, email_end - email_start + 8);

            bool has_type = false;
            if (type_hint.empty()) {
                // Look for EMAIL without HOME/WORK
                if (email_block.find("<HOME/>") == std::string::npos &&
                    email_block.find("<WORK/>") == std::string::npos) {
                    has_type = true;
                }
            } else {
                if (email_block.find("<" + type_hint + "/>") != std::string::npos) {
                    has_type = true;
                }
            }

            if (has_type) {
                return get_text_in_content("USERID", email_block);
            }

            pos = email_end + 8;
        }
        return "";
    }

    static std::string parse_tel(const std::string& xml, const std::string& type_hint) {
        size_t pos = 0;
        while (true) {
            size_t tel_start = xml.find("<TEL>", pos);
            if (tel_start == std::string::npos) break;
            size_t tel_end = xml.find("</TEL>", tel_start);
            if (tel_end == std::string::npos) break;

            std::string tel_block = xml.substr(tel_start, tel_end - tel_start + 6);
            if (tel_block.find("<" + type_hint + "/>") != std::string::npos) {
                return get_text_in_content("NUMBER", tel_block);
            }
            pos = tel_end + 6;
        }
        return "";
    }

    static std::pair<std::string, AddressComponents> parse_adr(
        const std::string& xml, const std::string& type_hint)
    {
        size_t pos = 0;
        while (true) {
            size_t adr_start = xml.find("<ADR>", pos);
            if (adr_start == std::string::npos) break;
            size_t adr_end = xml.find("</ADR>", adr_start);
            if (adr_end == std::string::npos) break;

            std::string adr_block = xml.substr(adr_start, adr_end - adr_start + 6);
            if (adr_block.find("<" + type_hint + "/>") != std::string::npos) {
                AddressComponents comp;
                comp.street   = get_text_in_content("STREET", adr_block);
                comp.locality = get_text_in_content("LOCALITY", adr_block);
                comp.region   = get_text_in_content("REGION", adr_block);
                comp.pcode    = get_text_in_content("PCODE", adr_block);
                comp.country  = get_text_in_content("CTRY", adr_block);

                // STREET is the "main" content
                std::string street = comp.street;
                // Also check EXTDDR for extended address
                std::string extaddr = get_text_in_content("EXTDDR", adr_block);
                if (!extaddr.empty()) {
                    street = street.empty() ? extaddr : extaddr + "\n" + street;
                }
                return {street, comp};
            }
            pos = adr_end + 6;
        }
        return {"", AddressComponents{}};
    }

    static std::vector<std::pair<std::string, std::string>> parse_keys(
        const std::string& xml)
    {
        std::vector<std::pair<std::string, std::string>> keys;
        size_t pos = 0;
        while (true) {
            size_t key_start = xml.find("<KEY>", pos);
            if (key_start == std::string::npos) break;
            size_t key_end = xml.find("</KEY>", key_start);
            if (key_end == std::string::npos) break;

            std::string key_block = xml.substr(key_start, key_end - key_start + 6);
            std::string type = get_text_in_content("TYPE", key_block);
            std::string data = get_text_in_content("KEYVAL", key_block);
            if (!data.empty()) {
                keys.emplace_back(type, data);
            }
            pos = key_end + 6;
        }
        return keys;
    }
};

// ============================================================================
// PEP Payload Parsers (Mood, Activity, Tune, Geolocation, Nickname)
// ============================================================================

class PEPPayloadParser {
public:
    static std::optional<MoodInfo> parse_mood(const std::string& xml) {
        MoodInfo mood;
        if (xml.empty()) return mood;

        // Extract the specific mood element
        for (const auto& [name, val] : mood_name_to_value) {
            if (xml.find("<" + name + "/>") != std::string::npos ||
                xml.find("<" + name + " ") != std::string::npos) {
                mood.value = val;
                break;
            }
        }

        // Extract optional text
        mood.text = VCardParser::parse_text_tag(xml, "text");
        return mood;
    }

    static std::optional<ActivityInfo> parse_activity(const std::string& xml) {
        ActivityInfo activity;
        if (xml.empty()) return activity;

        // Look for general activity tag
        for (const auto& [name, val] : activity_general_map) {
            if (xml.find("<" + name) != std::string::npos) {
                activity.general = val;
                // Look for specific nested tag
                for (const auto& [sname, sval] : activity_specific_map) {
                    if (xml.find("<" + sname + "/>") != std::string::npos) {
                        activity.specific = sval;
                        break;
                    }
                }
                break;
            }
        }

        activity.text = VCardParser::parse_text_tag(xml, "text");
        return activity;
    }

    static std::optional<TuneInfo> parse_tune(const std::string& xml) {
        TuneInfo tune;
        if (xml.empty()) return tune;

        tune.artist = VCardParser::parse_text_tag(xml, "artist");
        tune.title  = VCardParser::parse_text_tag(xml, "title");
        tune.source = VCardParser::parse_text_tag(xml, "source");
        tune.track  = VCardParser::parse_text_tag(xml, "track");
        tune.uri    = VCardParser::parse_text_tag(xml, "uri");

        std::string len_str = VCardParser::parse_text_tag(xml, "length");
        if (!len_str.empty()) {
            try { tune.length = std::stoll(len_str); } catch (...) {}
        }

        std::string rating_str = VCardParser::parse_text_tag(xml, "rating");
        if (!rating_str.empty()) {
            try { tune.rating = std::stoll(rating_str); } catch (...) {}
        }
        return tune;
    }

    static std::optional<GeolocationInfo> parse_geoloc(const std::string& xml) {
        GeolocationInfo geo;
        if (xml.empty()) return geo;

        auto parse_double = [&](const std::string& tag) -> double {
            std::string s = VCardParser::parse_text_tag(xml, tag);
            if (s.empty()) return std::numeric_limits<double>::quiet_NaN();
            try { return std::stod(s); } catch (...) {
                return std::numeric_limits<double>::quiet_NaN();
            }
        };

        geo.latitude  = parse_double("lat");
        geo.longitude = parse_double("lon");
        geo.altitude  = parse_double("alt");
        geo.speed     = parse_double("speed");
        geo.bearing   = parse_double("bearing");
        geo.accuracy  = parse_double("accuracy");

        geo.country     = VCardParser::parse_text_tag(xml, "country");
        geo.region      = VCardParser::parse_text_tag(xml, "region");
        geo.locality    = VCardParser::parse_text_tag(xml, "locality");
        geo.area        = VCardParser::parse_text_tag(xml, "area");
        geo.street      = VCardParser::parse_text_tag(xml, "street");
        geo.building    = VCardParser::parse_text_tag(xml, "building");
        geo.floor       = VCardParser::parse_text_tag(xml, "floor");
        geo.room        = VCardParser::parse_text_tag(xml, "room");
        geo.postal_code = VCardParser::parse_text_tag(xml, "postalcode");
        geo.description = VCardParser::parse_text_tag(xml, "description");
        geo.timestamp   = VCardParser::parse_text_tag(xml, "timestamp");
        geo.uri         = VCardParser::parse_text_tag(xml, "uri");
        geo.tzo         = VCardParser::parse_text_tag(xml, "tzo");
        geo.datum       = VCardParser::parse_text_tag(xml, "datum");

        return geo;
    }

    static std::string parse_nickname(const std::string& xml) {
        return VCardParser::parse_text_tag(xml, "nick");
    }
};

// Extend VCardParser with public helper
// This is a forward-compatible hack in this single-file design
inline std::string VCardParser::parse_text_tag(const std::string& xml, const std::string& tag) {
    std::string open = "<" + tag;
    size_t start = xml.find(open);
    if (start == std::string::npos) return "";
    start = xml.find('>', start);
    if (start == std::string::npos) return "";
    ++start;
    std::string close = "</" + tag + ">";
    size_t end = xml.find(close, start);
    if (end == std::string::npos) return "";
    return detail::trim(xml.substr(start, end - start));
}

// ============================================================================
// Profile Cache
// ============================================================================

class ProfileCache {
public:
    ProfileCache() = default;

    /**
     * Store a profile in the cache.
     */
    void put(const std::string& jid, const UserProfile& profile) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto& entry = cache_[jid];
        entry.profile = std::make_shared<UserProfile>(profile);
        entry.profile->cached_at = detail::epoch_now();
        entry.last_access = entry.profile->cached_at;

        // Evict if over capacity
        if (cache_.size() > static_cast<size_t>(profile_limits::MAX_CACHE_SIZE)) {
            evict_one();
        }
    }

    /**
     * Get a profile from the cache. Returns nullptr if not found or expired.
     */
    std::shared_ptr<UserProfile> get(const std::string& jid) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = cache_.find(jid);
        if (it == cache_.end()) return nullptr;

        int64_t now = detail::epoch_now();
        int64_t age = now - it->second.profile->cached_at;
        if (age > profile_limits::CACHE_TTL_SECONDS) {
            // Expired - don't evict immediately, but return null
            return nullptr;
        }

        it->second.last_access = now;
        return it->second.profile;
    }

    /**
     * Invalidate a cached profile for a JID.
     */
    void invalidate(const std::string& jid) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        cache_.erase(jid);
    }

    /**
     * Invalidate all cached profiles (e.g., on configuration change).
     */
    void invalidate_all() {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        cache_.clear();
    }

    /**
     * Update avatar metadata cache entry for a JID.
     */
    void update_avatar_metadata(const std::string& jid, const AvatarMetadataSet& metadata) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = cache_.find(jid);
        if (it != cache_.end()) {
            it->second.profile->avatar_metadata = metadata;
            it->second.profile->avatar_updated_at = detail::epoch_now();
            it->second.profile->cached_at = detail::epoch_now();
        }
    }

    /**
     * Update mood cache entry.
     */
    void update_mood(const std::string& jid, const MoodInfo& mood) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = cache_.find(jid);
        if (it != cache_.end()) {
            it->second.profile->mood = mood;
            it->second.profile->cached_at = detail::epoch_now();
        }
    }

    /**
     * Update activity cache entry.
     */
    void update_activity(const std::string& jid, const ActivityInfo& activity) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = cache_.find(jid);
        if (it != cache_.end()) {
            it->second.profile->activity = activity;
            it->second.profile->cached_at = detail::epoch_now();
        }
    }

    /**
     * Update tune cache entry.
     */
    void update_tune(const std::string& jid, const TuneInfo& tune) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = cache_.find(jid);
        if (it != cache_.end()) {
            it->second.profile->tune = tune;
            it->second.profile->cached_at = detail::epoch_now();
        }
    }

    /**
     * Update geolocation cache entry.
     */
    void update_geoloc(const std::string& jid, const GeolocationInfo& geo) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = cache_.find(jid);
        if (it != cache_.end()) {
            it->second.profile->geoloc = geo;
            it->second.profile->cached_at = detail::epoch_now();
        }
    }

    /**
     * Update nickname cache entry (from PEP).
     */
    void update_nickname(const std::string& jid, const std::string& nick) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = cache_.find(jid);
        if (it != cache_.end()) {
            it->second.profile->nickname_pep = nick;
            it->second.profile->cached_at = detail::epoch_now();
        }
    }

    /**
     * Get cache stats.
     */
    struct CacheStats {
        size_t size;
        size_t max_size;
        int64_t ttl_seconds;
        int64_t hit_count;
        int64_t miss_count;
    };

    CacheStats stats() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return {
            cache_.size(),
            static_cast<size_t>(profile_limits::MAX_CACHE_SIZE),
            profile_limits::CACHE_TTL_SECONDS,
            hits_,
            misses_
        };
    }

    /**
     * Register a cache hit/miss.
     */
    void record_hit()   { ++hits_; }
    void record_miss()  { ++misses_; }

    /**
     * Get all cached JIDs (for debugging/monitoring).
     */
    std::vector<std::string> get_cached_jids() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> result;
        result.reserve(cache_.size());
        for (const auto& [jid, _] : cache_) {
            result.push_back(jid);
        }
        return result;
    }

private:
    struct CacheEntry {
        std::shared_ptr<UserProfile> profile;
        int64_t last_access;
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
    mutable std::atomic<int64_t> hits_{0};
    mutable std::atomic<int64_t> misses_{0};

    void evict_one() {
        int64_t oldest_time = std::numeric_limits<int64_t>::max();
        std::string oldest_jid;
        for (const auto& [jid, entry] : cache_) {
            if (entry.last_access < oldest_time) {
                oldest_time = entry.last_access;
                oldest_jid = jid;
            }
        }
        if (!oldest_jid.empty()) {
            cache_.erase(oldest_jid);
        }
    }
};

// ============================================================================
// Avatar Data Store
// ============================================================================

class AvatarStore {
public:
    AvatarStore() = default;

    /**
     * Store avatar data for a JID.
     * Returns the SHA-1 hash of the avatar data.
     */
    std::string store_avatar(const std::string& jid,
                              const std::vector<uint8_t>& data,
                              const std::string& mime_type) {
        detail::sha1 hasher;
        hasher.update(data);
        std::string sha1_hash = hasher.hex_digest();

        std::unique_lock<std::shared_mutex> lock(mutex_);

        AvatarEntry entry;
        entry.data = data;
        entry.mime_type = mime_type;
        entry.sha1 = sha1_hash;
        entry.size_bytes = static_cast<int64_t>(data.size());
        entry.stored_at = detail::epoch_now();

        avatar_data_[jid] = std::move(entry);

        // Also index by hash for dedup lookup
        hash_to_jid_[sha1_hash] = jid;

        update_metadata(jid, entry);
        return sha1_hash;
    }

    /**
     * Get avatar data for a JID.
     */
    std::optional<std::vector<uint8_t>> get_avatar_data(const std::string& jid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = avatar_data_.find(jid);
        if (it != avatar_data_.end()) {
            return it->second.data;
        }
        return std::nullopt;
    }

    /**
     * Get avatar data by SHA-1 hash.
     */
    std::optional<std::vector<uint8_t>> get_avatar_by_hash(const std::string& sha1_hash) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto jid_it = hash_to_jid_.find(sha1_hash);
        if (jid_it != hash_to_jid_.end()) {
            auto data_it = avatar_data_.find(jid_it->second);
            if (data_it != avatar_data_.end()) {
                return data_it->second.data;
            }
        }
        return std::nullopt;
    }

    /**
     * Get avatar MIME type for a JID.
     */
    std::string get_avatar_mime_type(const std::string& jid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = avatar_data_.find(jid);
        if (it != avatar_data_.end()) {
            return it->second.mime_type;
        }
        return "";
    }

    /**
     * Get the SHA-1 hash of the avatar for a JID.
     */
    std::string get_avatar_hash(const std::string& jid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = avatar_data_.find(jid);
        if (it != avatar_data_.end()) {
            return it->second.sha1;
        }
        return "";
    }

    /**
     * Get avatar metadata for a JID.
     */
    std::optional<AvatarMetadataSet> get_avatar_metadata(const std::string& jid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = avatar_metadata_.find(jid);
        if (it != avatar_metadata_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Check if a JID has an avatar.
     */
    bool has_avatar(const std::string& jid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return avatar_data_.find(jid) != avatar_data_.end();
    }

    /**
     * Delete avatar for a JID.
     */
    void delete_avatar(const std::string& jid) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto it = avatar_data_.find(jid);
        if (it != avatar_data_.end()) {
            hash_to_jid_.erase(it->second.sha1);
            avatar_data_.erase(it);
        }
        avatar_metadata_.erase(jid);
    }

    /**
     * Get the number of stored avatars.
     */
    size_t avatar_count() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return avatar_data_.size();
    }

private:
    struct AvatarEntry {
        std::vector<uint8_t> data;
        std::string mime_type;
        std::string sha1;
        int64_t size_bytes;
        int64_t stored_at;
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, AvatarEntry> avatar_data_;
    std::unordered_map<std::string, std::string> hash_to_jid_; // sha1 -> jid
    std::unordered_map<std::string, AvatarMetadataSet> avatar_metadata_;

    void update_metadata(const std::string& jid, const AvatarEntry& entry) {
        AvatarInfo info;
        info.id = std::to_string(entry.stored_at);
        info.mime_type = entry.mime_type;
        info.size_bytes = entry.size_bytes;
        info.sha1 = entry.sha1;
        info.width = 0;   // Unknown - would need image decoding
        info.height = 0;

        AvatarMetadataSet meta;
        meta.avatars.push_back(info);
        avatar_metadata_[jid] = std::move(meta);
    }
};

// ============================================================================
// VCard-temp Manager (XEP-0054)
// ============================================================================

class VCardManager {
public:
    explicit VCardManager(AvatarStore& avatar_store, ProfileCache& cache)
        : avatar_store_(avatar_store), cache_(cache) {}

    /**
     * Store a full vCard for a user.
     * Returns validation errors if any.
     */
    ProfileValidator::ValidationResult set_vcard(const std::string& jid, const VCardFull& vcard) {
        auto result = ProfileValidator::validate_vcard(vcard);
        if (!result.valid) {
            return result;
        }

        std::unique_lock<std::shared_mutex> lock(mutex_);

        VCardFull stored = vcard;
        stored.jid = jid;
        stored.updated_at = detail::epoch_now();
        if (stored.created_at == 0) {
            stored.created_at = stored.updated_at;
        }
        stored.revision = stored.revision + 1;

        // If photo data changed, update avatar hash
        if (!stored.photo_binval.empty()) {
            auto decoded = detail::base64_decode(stored.photo_binval);
            detail::sha1 hasher;
            hasher.update(decoded);
            vcard_avatar_hashes_[jid] = hasher.hex_digest();

            // Also store in AvatarStore
            avatar_store_.store_avatar(jid, decoded, stored.photo_type);
        } else if (stored.photo_binval.empty() && vcard.photo_binval.empty()) {
            // Photo explicitly removed
            vcard_avatar_hashes_.erase(jid);
        }

        vcards_[jid] = stored;

        // Invalidate cache
        cache_.invalidate(jid);

        return result; // valid
    }

    /**
     * Get a vCard for a user.
     */
    std::optional<VCardFull> get_vcard(const std::string& jid) {
        // Check cache first
        auto cached = cache_.get(jid);
        if (cached) {
            cache_.record_hit();
            return cached->vcard;
        }
        cache_.record_miss();

        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = vcards_.find(jid);
        if (it != vcards_.end()) {
            // Populate cache
            UserProfile profile;
            profile.jid = jid;
            profile.vcard = it->second;
            cache_.put(jid, profile);
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Delete a vCard.
     */
    void delete_vcard(const std::string& jid) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        vcards_.erase(jid);
        vcard_avatar_hashes_.erase(jid);
        avatar_store_.delete_avatar(jid);
        cache_.invalidate(jid);
    }

    /**
     * Get vCard avatar hash (XEP-0153) for presence updates.
     */
    std::string get_vcard_avatar_hash(const std::string& jid) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = vcard_avatar_hashes_.find(jid);
        if (it != vcard_avatar_hashes_.end()) {
            return it->second;
        }
        return "";
    }

    /**
     * Build vCard-temp:x:update element for presence.
     */
    std::string build_vcard_update_xml(const std::string& jid) {
        std::string hash = get_vcard_avatar_hash(jid);
        std::ostringstream oss;
        oss << "<x xmlns='vcard-temp:x:update'><photo>";
        if (!hash.empty()) {
            oss << detail::xml_escape(hash);
        }
        oss << "</photo></x>";
        return oss.str();
    }

    /**
     * Get vCard count.
     */
    size_t vcard_count() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return vcards_.size();
    }

    /**
     * Search vCards by name/nickname.
     */
    std::vector<std::string> search_vcards(const std::string& query) {
        std::vector<std::string> results;
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::string lower_query = query;
        std::transform(lower_query.begin(), lower_query.end(),
                       lower_query.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        for (const auto& [jid, vc] : vcards_) {
            std::string fn_lower = vc.full_name;
            std::string nick_lower = vc.nickname;
            std::transform(fn_lower.begin(), fn_lower.end(), fn_lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            std::transform(nick_lower.begin(), nick_lower.end(), nick_lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });

            if (fn_lower.find(lower_query) != std::string::npos ||
                nick_lower.find(lower_query) != std::string::npos) {
                results.push_back(jid);
            }
        }
        return results;
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, VCardFull> vcards_;
    std::unordered_map<std::string, std::string> vcard_avatar_hashes_;
    AvatarStore& avatar_store_;
    ProfileCache& cache_;
};

// ============================================================================
// PEP Profile Publisher (XEP-0163)
// Handles publishing user profile data via PEP
// ============================================================================

class PEPProfilePublisher {
public:
    PEPProfilePublisher(AvatarStore& avatar_store, ProfileCache& cache)
        : avatar_store_(avatar_store), cache_(cache) {}

    /**
     * Type for publication callback - called when something is published.
     * Parameters: jid, node_name, item_id, payload_xml
     */
    using PublishCallback = std::function<void(const std::string&, const std::string&,
                                                const std::string&, const std::string&)>;

    /**
     * Set the callback for publish events.
     */
    void set_publish_callback(PublishCallback cb) {
        std::unique_lock<std::mutex> lock(mutex_);
        publish_callback_ = std::move(cb);
    }

    // =========================================================================
    // User Avatar (XEP-0084) - Avatar Data Publication
    // =========================================================================

    /**
     * Publish avatar data via PEP to urn:xmpp:avatar:data node.
     * Returns the item_id and SHA-1 hash as a pair.
     */
    std::pair<std::string, std::string> publish_avatar_data(
        const std::string& jid,
        const std::vector<uint8_t>& avatar_data,
        const std::string& mime_type)
    {
        auto val_result = ProfileValidator::validate_avatar_data(avatar_data, mime_type);
        if (!val_result.valid) {
            return {"", ""};  // Invalid
        }

        // Store in AvatarStore
        std::string sha1 = avatar_store_.store_avatar(jid, avatar_data, mime_type);

        // Build avatar data payload
        std::string base64_data = detail::base64_encode(avatar_data);
        std::string payload;
        {
            std::ostringstream oss;
            oss << "<data xmlns='urn:xmpp:avatar:data'>"
                << base64_data
                << "</data>";
            payload = oss.str();
        }

        std::string item_id = detail::generate_id("avatar-data-");

        // Store in PEP node state
        {
            std::unique_lock<std::mutex> lock(mutex_);
            pep_nodes_["urn:xmpp:avatar:data"][jid] = {
                item_id, payload, detail::epoch_now()
            };
        }

        // Trigger callback
        invoke_callback(jid, "urn:xmpp:avatar:data", item_id, payload);

        // Also publish metadata automatically
        publish_avatar_metadata_internal(jid, mime_type, sha1,
            static_cast<int64_t>(avatar_data.size()));

        return {item_id, sha1};
    }

    /**
     * Publish avatar metadata to urn:xmpp:avatar:metadata node.
     */
    void publish_avatar_metadata(const std::string& jid,
                                  const AvatarMetadataSet& metadata)
    {
        std::string payload = metadata.to_metadata_xml();
        std::string item_id = detail::generate_id("avatar-meta-");

        {
            std::unique_lock<std::mutex> lock(mutex_);
            pep_nodes_["urn:xmpp:avatar:metadata"][jid] = {
                item_id, payload, detail::epoch_now()
            };
        }

        avatar_metadata_store_[jid] = metadata;

        invoke_callback(jid, "urn:xmpp:avatar:metadata", item_id, payload);
    }

    /**
     * Get stored avatar metadata for a JID.
     */
    std::optional<AvatarMetadataSet> get_avatar_metadata(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = avatar_metadata_store_.find(jid);
        if (it != avatar_metadata_store_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Disable avatars (publish empty metadata).
     */
    void disable_avatars(const std::string& jid) {
        AvatarMetadataSet empty;
        publish_avatar_metadata(jid, empty);
        avatar_store_.delete_avatar(jid);
    }

    // =========================================================================
    // User Nickname (XEP-0172)
    // =========================================================================

    /**
     * Publish nickname via PEP to http://jabber.org/protocol/nick node.
     */
    bool publish_nickname(const std::string& jid, const std::string& nickname) {
        auto val_result = ProfileValidator::validate_nickname(nickname);
        if (!val_result.valid) {
            return false;
        }

        std::string payload;
        {
            std::ostringstream oss;
            oss << "<nick xmlns='http://jabber.org/protocol/nick'>"
                << detail::xml_escape(nickname)
                << "</nick>";
            payload = oss.str();
        }

        std::string item_id = detail::generate_id("nick-");

        {
            std::unique_lock<std::mutex> lock(mutex_);
            pep_nodes_[profile_ns::NICK][jid] = {
                item_id, payload, detail::epoch_now()
            };
            nicknames_[jid] = nickname;
        }

        invoke_callback(jid, profile_ns::NICK, item_id, payload);
        cache_.update_nickname(jid, nickname);
        return true;
    }

    /**
     * Get stored nickname for a JID.
     */
    std::string get_nickname(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = nicknames_.find(jid);
        if (it != nicknames_.end()) {
            return it->second;
        }
        return "";
    }

    // =========================================================================
    // User Mood (XEP-0107)
    // =========================================================================

    /**
     * Publish mood via PEP to http://jabber.org/protocol/mood node.
     */
    bool publish_mood(const std::string& jid, const MoodInfo& mood) {
        auto val_result = ProfileValidator::validate_mood(mood);
        if (!val_result.valid) {
            return false;
        }

        std::string payload = mood.to_pep_payload_xml();
        std::string item_id = detail::generate_id("mood-");

        {
            std::unique_lock<std::mutex> lock(mutex_);
            pep_nodes_[profile_ns::MOOD][jid] = {
                item_id, payload, detail::epoch_now()
            };
            moods_[jid] = mood;
        }

        invoke_callback(jid, profile_ns::MOOD, item_id, payload);
        cache_.update_mood(jid, mood);
        return true;
    }

    /**
     * Get stored mood for a JID.
     */
    std::optional<MoodInfo> get_mood(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = moods_.find(jid);
        if (it != moods_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Clear mood (stop publishing).
     */
    void clear_mood(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        moods_.erase(jid);
        pep_nodes_[profile_ns::MOOD].erase(jid);
    }

    // =========================================================================
    // User Activity (XEP-0108)
    // =========================================================================

    /**
     * Publish activity via PEP.
     */
    bool publish_activity(const std::string& jid, const ActivityInfo& activity) {
        auto val_result = ProfileValidator::validate_activity(activity);
        if (!val_result.valid) {
            return false;
        }

        std::string payload = activity.to_pep_payload_xml();
        std::string item_id = detail::generate_id("activity-");

        {
            std::unique_lock<std::mutex> lock(mutex_);
            pep_nodes_[profile_ns::ACTIVITY][jid] = {
                item_id, payload, detail::epoch_now()
            };
            activities_[jid] = activity;
        }

        invoke_callback(jid, profile_ns::ACTIVITY, item_id, payload);
        cache_.update_activity(jid, activity);
        return true;
    }

    /**
     * Get stored activity for a JID.
     */
    std::optional<ActivityInfo> get_activity(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = activities_.find(jid);
        if (it != activities_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Clear activity.
     */
    void clear_activity(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        activities_.erase(jid);
        pep_nodes_[profile_ns::ACTIVITY].erase(jid);
    }

    // =========================================================================
    // User Tune (XEP-0118)
    // =========================================================================

    /**
     * Publish tune via PEP.
     */
    bool publish_tune(const std::string& jid, const TuneInfo& tune) {
        auto val_result = ProfileValidator::validate_tune(tune);
        if (!val_result.valid) {
            return false;
        }

        std::string payload = tune.to_pep_payload_xml();
        std::string item_id = detail::generate_id("tune-");

        {
            std::unique_lock<std::mutex> lock(mutex_);
            pep_nodes_[profile_ns::TUNE][jid] = {
                item_id, payload, detail::epoch_now()
            };
            tunes_[jid] = tune;
        }

        invoke_callback(jid, profile_ns::TUNE, item_id, payload);
        cache_.update_tune(jid, tune);
        return true;
    }

    /**
     * Get stored tune for a JID.
     */
    std::optional<TuneInfo> get_tune(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = tunes_.find(jid);
        if (it != tunes_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Clear tune (stop publishing).
     */
    void clear_tune(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        tunes_.erase(jid);
        pep_nodes_[profile_ns::TUNE].erase(jid);
    }

    // =========================================================================
    // User Location (XEP-0080)
    // =========================================================================

    /**
     * Publish geolocation via PEP.
     */
    bool publish_geoloc(const std::string& jid, const GeolocationInfo& geo) {
        auto val_result = ProfileValidator::validate_geolocation(geo);
        if (!val_result.valid) {
            return false;
        }

        std::string payload = geo.to_pep_payload_xml();
        std::string item_id = detail::generate_id("geoloc-");

        {
            std::unique_lock<std::mutex> lock(mutex_);
            pep_nodes_[profile_ns::GEOLOC][jid] = {
                item_id, payload, detail::epoch_now()
            };
            geolocs_[jid] = geo;
        }

        invoke_callback(jid, profile_ns::GEOLOC, item_id, payload);
        cache_.update_geoloc(jid, geo);
        return true;
    }

    /**
     * Get stored geolocation for a JID.
     */
    std::optional<GeolocationInfo> get_geoloc(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = geolocs_.find(jid);
        if (it != geolocs_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Clear geolocation.
     */
    void clear_geoloc(const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        geolocs_.erase(jid);
        pep_nodes_[profile_ns::GEOLOC].erase(jid);
    }

    // =========================================================================
    // Get last published item for a PEP node
    // =========================================================================

    struct PEPItem {
        std::string id;
        std::string payload;
        int64_t published_at;
    };

    std::optional<PEPItem> get_last_item(const std::string& node, const std::string& jid) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto node_it = pep_nodes_.find(node);
        if (node_it != pep_nodes_.end()) {
            auto jid_it = node_it->second.find(jid);
            if (jid_it != node_it->second.end()) {
                return jid_it->second;
            }
        }
        return std::nullopt;
    }

    /**
     * Get all PEP nodes for a JID.
     */
    std::vector<std::string> get_nodes_for_jid(const std::string& jid) {
        std::vector<std::string> nodes;
        std::unique_lock<std::mutex> lock(mutex_);
        for (const auto& [node_name, user_map] : pep_nodes_) {
            if (user_map.find(jid) != user_map.end()) {
                nodes.push_back(node_name);
            }
        }
        return nodes;
    }

private:
    mutable std::mutex mutex_;
    // node_name -> (jid -> PEPItem)
    std::unordered_map<std::string, std::unordered_map<std::string, PEPItem>> pep_nodes_;

    // Individual data stores
    std::unordered_map<std::string, std::string> nicknames_;
    std::unordered_map<std::string, MoodInfo> moods_;
    std::unordered_map<std::string, ActivityInfo> activities_;
    std::unordered_map<std::string, TuneInfo> tunes_;
    std::unordered_map<std::string, GeolocationInfo> geolocs_;
    std::unordered_map<std::string, AvatarMetadataSet> avatar_metadata_store_;

    AvatarStore& avatar_store_;
    ProfileCache& cache_;
    PublishCallback publish_callback_;

    void invoke_callback(const std::string& jid, const std::string& node,
                         const std::string& item_id, const std::string& payload) {
        if (publish_callback_) {
            publish_callback_(jid, node, item_id, payload);
        }
    }

    void publish_avatar_metadata_internal(const std::string& jid,
                                           const std::string& mime_type,
                                           const std::string& sha1,
                                           int64_t size_bytes) {
        AvatarInfo info;
        info.id = detail::generate_id("");
        info.mime_type = mime_type;
        info.size_bytes = size_bytes;
        info.sha1 = sha1;
        info.width = 0;
        info.height = 0;

        AvatarMetadataSet meta;
        meta.avatars.push_back(info);

        publish_avatar_metadata(jid, meta);
    }
};

// ============================================================================
// Profile Federation Handler (S2S)
// ============================================================================

class ProfileFederationHandler {
public:
    ProfileFederationHandler(VCardManager& vcard_mgr,
                              PEPProfilePublisher& pep_publisher,
                              AvatarStore& avatar_store)
        : vcard_mgr_(vcard_mgr)
        , pep_publisher_(pep_publisher)
        , avatar_store_(avatar_store) {}

    /**
     * Type for sending a stanza to a remote server.
     * Parameters: from_domain, to_domain, xml_stanza
     * Returns: true if sent successfully
     */
    using SendStanzaFunc = std::function<bool(const std::string&,
                                               const std::string&,
                                               const std::string&)>;

    /**
     * Set the S2S stanza sender function.
     */
    void set_s2s_sender(SendStanzaFunc sender) {
        std::unique_lock<std::mutex> lock(mutex_);
        s2s_sender_ = std::move(sender);
    }

    /**
     * Request a vCard from a remote server.
     * Sends a vcard-temp IQ to the remote JID's server.
     */
    std::string request_remote_vcard(const std::string& requester_jid,
                                      const std::string& remote_jid) {
        std::string id = detail::generate_id("s2s-vcard-");
        std::string iq;
        {
            std::ostringstream oss;
            oss << "<iq type='get' id='" << detail::xml_attr_escape(id) << "'"
                << " from='" << detail::xml_attr_escape(requester_jid) << "'"
                << " to='" << detail::xml_attr_escape(remote_jid) << "'>"
                << "<vCard xmlns='vcard-temp'/>"
                << "</iq>";
            iq = oss.str();
        }

        // Extract domain from remote JID
        std::string remote_domain = extract_domain(remote_jid);
        std::string local_domain = extract_domain(requester_jid);

        {
            std::unique_lock<std::mutex> lock(mutex_);
            pending_requests_[id] = {
                requester_jid, remote_jid, "vcard",
                detail::epoch_now()
            };
        }

        if (s2s_sender_) {
            s2s_sender_(local_domain, remote_domain, iq);
        }

        return id;
    }

    /**
     * Request PEP node items from a remote server.
     */
    std::string request_remote_pep(const std::string& requester_jid,
                                    const std::string& remote_jid,
                                    const std::string& pep_node) {
        std::string id = detail::generate_id("s2s-pep-");
        std::string iq;
        {
            std::ostringstream oss;
            oss << "<iq type='get' id='" << detail::xml_attr_escape(id) << "'"
                << " from='" << detail::xml_attr_escape(requester_jid) << "'"
                << " to='" << detail::xml_attr_escape(remote_jid) << "'>"
                << "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                << "<items node='" << detail::xml_attr_escape(pep_node) << "'/>"
                << "</pubsub>"
                << "</iq>";
            iq = oss.str();
        }

        std::string remote_domain = extract_domain(remote_jid);
        std::string local_domain = extract_domain(requester_jid);

        {
            std::unique_lock<std::mutex> lock(mutex_);
            pending_requests_[id] = {
                requester_jid, remote_jid, "pep:" + pep_node,
                detail::epoch_now()
            };
        }

        if (s2s_sender_) {
            s2s_sender_(local_domain, remote_domain, iq);
        }

        return id;
    }

    /**
     * Request remote avatar data by hash.
     */
    std::string request_remote_avatar(const std::string& requester_jid,
                                       const std::string& remote_jid,
                                       const std::string& sha1_hash) {
        std::string id = detail::generate_id("s2s-avatar-");
        std::string iq;
        {
            std::ostringstream oss;
            oss << "<iq type='get' id='" << detail::xml_attr_escape(id) << "'"
                << " from='" << detail::xml_attr_escape(requester_jid) << "'"
                << " to='" << detail::xml_attr_escape(remote_jid) << "'>"
                << "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                << "<items node='urn:xmpp:avatar:data'>"
                << "<item id='" << detail::xml_attr_escape(sha1_hash) << "'/>"
                << "</items>"
                << "</pubsub>"
                << "</iq>";
            iq = oss.str();
        }

        std::string remote_domain = extract_domain(remote_jid);
        std::string local_domain = extract_domain(requester_jid);

        {
            std::unique_lock<std::mutex> lock(mutex_);
            pending_requests_[id] = {
                requester_jid, remote_jid, "avatar:" + sha1_hash,
                detail::epoch_now()
            };
        }

        if (s2s_sender_) {
            s2s_sender_(local_domain, remote_domain, iq);
        }

        return id;
    }

    /**
     * Handle an incoming federated vCard request.
     * Returns the IQ result XML to send back.
     */
    std::string handle_incoming_vcard_request(const std::string& from_jid,
                                               const std::string& to_jid,
                                               const std::string& request_id) {
        auto vcard = vcard_mgr_.get_vcard(to_jid);
        std::ostringstream oss;
        oss << "<iq type='result' id='" << detail::xml_attr_escape(request_id) << "'"
            << " from='" << detail::xml_attr_escape(to_jid) << "'"
            << " to='" << detail::xml_attr_escape(from_jid) << "'>";
        if (vcard.has_value()) {
            oss << vcard->to_xml();
        } else {
            oss << "<vCard xmlns='vcard-temp'/>";
        }
        oss << "</iq>";
        return oss.str();
    }

    /**
     * Handle an incoming federated PEP items request.
     */
    std::string handle_incoming_pep_request(const std::string& from_jid,
                                             const std::string& to_jid,
                                             const std::string& request_id,
                                             const std::string& pep_node) {
        auto item = pep_publisher_.get_last_item(pep_node, to_jid);

        std::ostringstream oss;
        oss << "<iq type='result' id='" << detail::xml_attr_escape(request_id) << "'"
            << " from='" << detail::xml_attr_escape(to_jid) << "'"
            << " to='" << detail::xml_attr_escape(from_jid) << "'>"
            << "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
            << "<items node='" << detail::xml_attr_escape(pep_node) << "'>";
        if (item.has_value()) {
            oss << "<item id='" << detail::xml_attr_escape(item->id) << "'>"
                << item->payload << "</item>";
        }
        oss << "</items></pubsub></iq>";
        return oss.str();
    }

    /**
     * Handle incoming IQ result from a remote server.
     * Processes the response and stores/forwards accordingly.
     */
    bool handle_federated_response(const std::string& request_id,
                                    const std::string& xml_response) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = pending_requests_.find(request_id);
        if (it == pending_requests_.end()) {
            return false;  // Unknown request
        }

        PendingRequest req = it->second;
        pending_requests_.erase(it);
        lock.unlock();

        if (req.request_type == "vcard") {
            return handle_vcard_response(req.remote_jid, xml_response);
        } else if (req.request_type.find("pep:") == 0) {
            std::string node = req.request_type.substr(4);
            return handle_pep_response(req.remote_jid, node, xml_response);
        } else if (req.request_type.find("avatar:") == 0) {
            return handle_avatar_response(req.remote_jid, xml_response);
        }

        return true;
    }

    /**
     * Get count of pending federation requests.
     */
    size_t pending_count() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return pending_requests_.size();
    }

    /**
     * Clean up stale pending requests (older than timeout seconds).
     */
    void cleanup_stale_requests(int64_t timeout_seconds = 60) {
        std::unique_lock<std::mutex> lock(mutex_);
        int64_t now = detail::epoch_now();
        auto it = pending_requests_.begin();
        while (it != pending_requests_.end()) {
            if (now - it->second.created_at > timeout_seconds) {
                it = pending_requests_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    struct PendingRequest {
        std::string requester_jid;
        std::string remote_jid;
        std::string request_type;
        int64_t created_at;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, PendingRequest> pending_requests_;
    VCardManager& vcard_mgr_;
    PEPProfilePublisher& pep_publisher_;
    AvatarStore& avatar_store_;
    SendStanzaFunc s2s_sender_;

    static std::string extract_domain(const std::string& jid) {
        size_t at = jid.find('@');
        if (at != std::string::npos) {
            std::string domain = jid.substr(at + 1);
            size_t slash = domain.find('/');
            if (slash != std::string::npos) {
                return domain.substr(0, slash);
            }
            return domain;
        }
        return jid;
    }

    bool handle_vcard_response(const std::string& remote_jid,
                                const std::string& xml) {
        auto parsed = VCardParser::parse(xml);
        if (parsed.has_value()) {
            vcard_mgr_.set_vcard(remote_jid, parsed.value());
            return true;
        }
        return false;
    }

    bool handle_pep_response(const std::string& remote_jid,
                              const std::string& node,
                              const std::string& xml) {
        // Extract the payload from the pubsub items response
        std::string payload = VCardParser::parse_text_tag(xml, "item");

        if (node == profile_ns::MOOD && !payload.empty()) {
            auto parsed = PEPPayloadParser::parse_mood(payload);
            if (parsed.has_value()) {
                pep_publisher_.publish_mood(remote_jid, parsed.value());
            }
        } else if (node == profile_ns::ACTIVITY && !payload.empty()) {
            auto parsed = PEPPayloadParser::parse_activity(payload);
            if (parsed.has_value()) {
                pep_publisher_.publish_activity(remote_jid, parsed.value());
            }
        } else if (node == profile_ns::TUNE && !payload.empty()) {
            auto parsed = PEPPayloadParser::parse_tune(payload);
            if (parsed.has_value()) {
                pep_publisher_.publish_tune(remote_jid, parsed.value());
            }
        } else if (node == profile_ns::GEOLOC && !payload.empty()) {
            auto parsed = PEPPayloadParser::parse_geoloc(payload);
            if (parsed.has_value()) {
                pep_publisher_.publish_geoloc(remote_jid, parsed.value());
            }
        } else if (node == profile_ns::NICK && !payload.empty()) {
            std::string nick = PEPPayloadParser::parse_nickname(payload);
            if (!nick.empty()) {
                pep_publisher_.publish_nickname(remote_jid, nick);
            }
        }

        return true;
    }

    bool handle_avatar_response(const std::string& remote_jid,
                                 const std::string& xml) {
        std::string item_content = VCardParser::parse_text_tag(xml, "item");
        if (item_content.empty()) return false;

        // Extract the data element from avatar data
        std::string data_content = VCardParser::parse_text_tag(item_content, "data");
        if (data_content.empty()) return false;

        auto decoded = detail::base64_decode(data_content);
        if (!decoded.empty()) {
            std::string sha1 = avatar_store_.store_avatar(remote_jid, decoded, "image/png");
            return !sha1.empty();
        }
        return false;
    }
};

// ============================================================================
// VCardProfileManager - Main orchestrator class
// ============================================================================

class VCardProfileManager {
public:
    VCardProfileManager()
        : avatar_store_()
        , cache_()
        , vcard_mgr_(avatar_store_, cache_)
        , pep_publisher_(avatar_store_, cache_)
        , federation_(vcard_mgr_, pep_publisher_, avatar_store_) {}

    // =========================================================================
    // Access to sub-managers
    // =========================================================================

    VCardManager& vcard()           { return vcard_mgr_; }
    const VCardManager& vcard() const { return vcard_mgr_; }

    PEPProfilePublisher& pep()           { return pep_publisher_; }
    const PEPProfilePublisher& pep() const { return pep_publisher_; }

    ProfileFederationHandler& federation()           { return federation_; }
    const ProfileFederationHandler& federation() const { return federation_; }

    AvatarStore& avatars()           { return avatar_store_; }
    const AvatarStore& avatars() const { return avatar_store_; }

    ProfileCache& cache()           { return cache_; }
    const ProfileCache& cache() const { return cache_; }

    // =========================================================================
    // Full profile operations
    // =========================================================================

    /**
     * Get the complete user profile combining all data sources.
     */
    UserProfile get_full_profile(const std::string& jid) {
        UserProfile profile;
        profile.jid = jid;

        // Check cache first
        auto cached = cache_.get(jid);
        if (cached) {
            cache_.record_hit();
            return *cached;
        }
        cache_.record_miss();

        // vCard
        auto vcard = vcard_mgr_.get_vcard(jid);
        if (vcard.has_value()) {
            profile.vcard = vcard.value();
            profile.vcard_updated_at = vcard->updated_at;
        }

        // Avatar
        auto avatar_meta = avatar_store_.get_avatar_metadata(jid);
        if (avatar_meta.has_value()) {
            profile.avatar_metadata = avatar_meta.value();
        }
        auto avatar_data = avatar_store_.get_avatar_data(jid);
        if (avatar_data.has_value()) {
            profile.avatar_data = avatar_data.value();
            profile.avatar_mime_type = avatar_store_.get_avatar_mime_type(jid);
            profile.avatar_updated_at = detail::epoch_now();
        }

        // PEP data
        auto mood = pep_publisher_.get_mood(jid);
        if (mood.has_value()) {
            profile.mood = mood.value();
        }

        auto activity = pep_publisher_.get_activity(jid);
        if (activity.has_value()) {
            profile.activity = activity.value();
        }

        auto tune = pep_publisher_.get_tune(jid);
        if (tune.has_value()) {
            profile.tune = tune.value();
        }

        auto geoloc = pep_publisher_.get_geoloc(jid);
        if (geoloc.has_value()) {
            profile.geoloc = geoloc.value();
        }

        profile.nickname_pep = pep_publisher_.get_nickname(jid);

        // Store in cache
        cache_.put(jid, profile);
        return profile;
    }

    /**
     * Set complete user profile from a UserProfile struct.
     */
    ProfileValidator::ValidationResult set_full_profile(const std::string& jid,
                                                         const UserProfile& profile) {
        ProfileValidator::ValidationResult result;

        // Validate and set vCard
        auto vcard_result = vcard_mgr_.set_vcard(jid, profile.vcard);
        if (!vcard_result.valid) {
            result.errors.insert(result.errors.end(),
                vcard_result.errors.begin(), vcard_result.errors.end());
            result.valid = false;
        }

        // Set avatar if provided
        if (!profile.avatar_data.empty()) {
            pep_publisher_.publish_avatar_data(
                jid, profile.avatar_data, profile.avatar_mime_type);
        }

        // Set PEP data
        if (profile.mood.value != MoodValue::UNKNOWN) {
            pep_publisher_.publish_mood(jid, profile.mood);
        }

        if (profile.activity.general != ActivityGeneral::UNKNOWN) {
            pep_publisher_.publish_activity(jid, profile.activity);
        }

        if (!profile.tune.artist.empty() || !profile.tune.title.empty()) {
            pep_publisher_.publish_tune(jid, profile.tune);
        }

        if (profile.geoloc.has_basic_position()) {
            pep_publisher_.publish_geoloc(jid, profile.geoloc);
        }

        if (!profile.nickname_pep.empty()) {
            pep_publisher_.publish_nickname(jid, profile.nickname_pep);
        }

        // Invalidate cache to force refresh
        cache_.invalidate(jid);

        return result;
    }

    /**
     * Delete all profile data for a user.
     */
    void delete_profile(const std::string& jid) {
        vcard_mgr_.delete_vcard(jid);
        avatar_store_.delete_avatar(jid);
        pep_publisher_.clear_mood(jid);
        pep_publisher_.clear_activity(jid);
        pep_publisher_.clear_tune(jid);
        pep_publisher_.clear_geoloc(jid);
        pep_publisher_.disable_avatars(jid);
        cache_.invalidate(jid);
    }

    // =========================================================================
    // Avatar hash for presence (XEP-0153)
    // =========================================================================

    /**
     * Get the avatar hash to include in presence stanzas.
     * Priority: XEP-0084 avatar > XEP-0054 vCard photo > none
     */
    std::string get_avatar_hash_for_presence(const std::string& jid) {
        // Check XEP-0084 avatar metadata first
        auto meta = avatar_store_.get_avatar_metadata(jid);
        if (meta.has_value()) {
            auto primary = meta->get_primary_avatar();
            if (primary.has_value() && !primary->sha1.empty()) {
                return primary->sha1;
            }
        }
        // Fall back to vCard avatar
        return vcard_mgr_.get_vcard_avatar_hash(jid);
    }

    /**
     * Build the vCard-temp:x:update presence element.
     */
    std::string build_presence_vcard_update(const std::string& jid) {
        return vcard_mgr_.build_vcard_update_xml(jid);
    }

    // =========================================================================
    // S2S Federation setup
    // =========================================================================

    /**
     * Set the S2S stanza sender for profile federation.
     */
    void set_s2s_sender(ProfileFederationHandler::SendStanzaFunc sender) {
        federation_.set_s2s_sender(std::move(sender));
    }

    /**
     * Discover and fetch remote user profile.
     */
    std::string discover_remote_profile(const std::string& local_jid,
                                         const std::string& remote_jid) {
        // First request vCard
        std::string req_id = federation_.request_remote_vcard(local_jid, remote_jid);

        // Then request PEP nodes commonly used for profiles
        federation_.request_remote_pep(local_jid, remote_jid, profile_ns::NICK);
        federation_.request_remote_pep(local_jid, remote_jid, "urn:xmpp:avatar:metadata");

        return req_id;
    }

    // =========================================================================
    // Statistics
    // =========================================================================

    struct ManagerStats {
        size_t vcard_count;
        size_t avatar_count;
        size_t cache_entries;
        int64_t cache_hits;
        int64_t cache_misses;
        size_t pending_s2s_requests;
    };

    ManagerStats get_stats() const {
        auto cache_stats = cache_.stats();
        return {
            vcard_mgr_.vcard_count(),
            avatar_store_.avatar_count(),
            cache_stats.size,
            cache_stats.hit_count,
            cache_stats.miss_count,
            federation_.pending_count()
        };
    }

private:
    AvatarStore avatar_store_;
    ProfileCache cache_;
    VCardManager vcard_mgr_;
    PEPProfilePublisher pep_publisher_;
    ProfileFederationHandler federation_;
};

// ============================================================================
// Legacy/Adapter API for existing code integration
// Provides compatibility wrappers for the existing xmpp_server.hpp API
// ============================================================================

namespace legacy {

/**
 * Adapter to map between VCardFull and the JSON-based vCard API
 * used in xmpp_server.hpp.
 */
class VCardJsonAdapter {
public:
    /**
     * Convert VCardFull to JSON representation.
     */
    static nlohmann::json to_json(const VCardFull& vc) {
        nlohmann::json j;
        j["version"]       = vc.version;
        j["full_name"]     = vc.full_name;
        j["given_name"]    = vc.given_name;
        j["family_name"]   = vc.family_name;
        j["middle_name"]   = vc.middle_name;
        j["prefix"]        = vc.prefix;
        j["suffix"]        = vc.suffix;
        j["nickname"]      = vc.nickname;
        j["email"]         = vc.email;
        j["email_home"]    = vc.email_home;
        j["email_work"]    = vc.email_work;
        j["url"]           = vc.url;
        j["phone_voice"]   = vc.phone_voice;
        j["phone_cell"]    = vc.phone_cell;
        j["phone_work"]    = vc.phone_work;
        j["phone_home"]    = vc.phone_home;
        j["phone_fax"]     = vc.phone_fax;
        j["title"]         = vc.title;
        j["role"]          = vc.role;
        j["org_name"]      = vc.org_name;
        j["org_unit"]      = vc.org_unit;
        j["birthday"]      = vc.birthday;
        j["note"]          = vc.note;
        j["description"]   = vc.description;
        j["photo_type"]    = vc.photo_type;
        j["photo_binval"]  = vc.photo_binval;
        j["photo_url"]     = vc.photo_url;

        // Addresses as nested objects
        nlohmann::json addr_home;
        addr_home["street"]      = vc.addr_home_street;
        addr_home["locality"]    = vc.addr_home_locality;
        addr_home["region"]      = vc.addr_home_region;
        addr_home["postal_code"] = vc.addr_home_postal_code;
        addr_home["country"]     = vc.addr_home_country;
        j["address_home"]        = addr_home;

        nlohmann::json addr_work;
        addr_work["street"]      = vc.addr_work_street;
        addr_work["locality"]    = vc.addr_work_locality;
        addr_work["region"]      = vc.addr_work_region;
        addr_work["postal_code"] = vc.addr_work_postal_code;
        addr_work["country"]     = vc.addr_work_country;
        j["address_work"]        = addr_work;

        j["created_at"]    = vc.created_at;
        j["updated_at"]    = vc.updated_at;
        j["revision"]      = vc.revision;

        return j;
    }

    /**
     * Convert JSON to VCardFull.
     */
    static VCardFull from_json(const nlohmann::json& j) {
        VCardFull vc;
        auto get_str = [&](const std::string& key) -> std::string {
            if (j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
            return "";
        };
        auto get_int = [&](const std::string& key) -> int64_t {
            if (j.contains(key) && j[key].is_number()) return j[key].get<int64_t>();
            return 0;
        };

        vc.version      = get_str("version");
        vc.full_name    = get_str("full_name");
        vc.given_name   = get_str("given_name");
        vc.family_name  = get_str("family_name");
        vc.middle_name  = get_str("middle_name");
        vc.prefix       = get_str("prefix");
        vc.suffix       = get_str("suffix");
        vc.nickname     = get_str("nickname");
        vc.email        = get_str("email");
        vc.email_home   = get_str("email_home");
        vc.email_work   = get_str("email_work");
        vc.url          = get_str("url");
        vc.phone_voice  = get_str("phone_voice");
        vc.phone_cell   = get_str("phone_cell");
        vc.phone_work   = get_str("phone_work");
        vc.phone_home   = get_str("phone_home");
        vc.phone_fax    = get_str("phone_fax");
        vc.title        = get_str("title");
        vc.role         = get_str("role");
        vc.org_name     = get_str("org_name");
        vc.org_unit     = get_str("org_unit");
        vc.birthday     = get_str("birthday");
        vc.note         = get_str("note");
        vc.description  = get_str("description");
        vc.photo_type   = get_str("photo_type");
        vc.photo_binval = get_str("photo_binval");
        vc.photo_url    = get_str("photo_url");

        if (j.contains("address_home")) {
            vc.addr_home_street      = get_str_from_obj(j["address_home"], "street");
            vc.addr_home_locality    = get_str_from_obj(j["address_home"], "locality");
            vc.addr_home_region      = get_str_from_obj(j["address_home"], "region");
            vc.addr_home_postal_code = get_str_from_obj(j["address_home"], "postal_code");
            vc.addr_home_country     = get_str_from_obj(j["address_home"], "country");
        }
        if (j.contains("address_work")) {
            vc.addr_work_street      = get_str_from_obj(j["address_work"], "street");
            vc.addr_work_locality    = get_str_from_obj(j["address_work"], "locality");
            vc.addr_work_region      = get_str_from_obj(j["address_work"], "region");
            vc.addr_work_postal_code = get_str_from_obj(j["address_work"], "postal_code");
            vc.addr_work_country     = get_str_from_obj(j["address_work"], "country");
        }

        vc.created_at = get_int("created_at");
        vc.updated_at = get_int("updated_at");
        vc.revision   = get_int("revision");

        return vc;
    }

private:
    static std::string get_str_from_obj(const nlohmann::json& obj,
                                         const std::string& key) {
        if (obj.contains(key) && obj[key].is_string())
            return obj[key].get<std::string>();
        return "";
    }
};

} // namespace legacy

// ============================================================================
// Global VCardProfileManager instance (singleton pattern)
// ============================================================================

namespace {

std::unique_ptr<VCardProfileManager> g_profile_manager;
std::mutex g_profile_manager_mutex;

} // anonymous namespace

/**
 * Get or create the singleton VCardProfileManager.
 */
VCardProfileManager& get_profile_manager() {
    std::lock_guard<std::mutex> lock(g_profile_manager_mutex);
    if (!g_profile_manager) {
        g_profile_manager = std::make_unique<VCardProfileManager>();
    }
    return *g_profile_manager;
}

/**
 * Reset the singleton (for testing).
 */
void reset_profile_manager() {
    std::lock_guard<std::mutex> lock(g_profile_manager_mutex);
    g_profile_manager.reset();
}

// ============================================================================
// Convenience Free Functions
// ============================================================================

/**
 * Quick vCard get - returns JSON representation.
 */
nlohmann::json get_vcard_json(const std::string& jid) {
    auto& mgr = get_profile_manager();
    auto vc = mgr.vcard().get_vcard(jid);
    if (vc.has_value()) {
        return legacy::VCardJsonAdapter::to_json(vc.value());
    }
    return nlohmann::json::object();
}

/**
 * Quick vCard set from JSON representation.
 */
ProfileValidator::ValidationResult set_vcard_json(const std::string& jid,
                                                    const nlohmann::json& vcard_json) {
    auto& mgr = get_profile_manager();
    VCardFull vc = legacy::VCardJsonAdapter::from_json(vcard_json);
    return mgr.vcard().set_vcard(jid, vc);
}

/**
 * Quick avatar set from raw bytes.
 */
std::string set_avatar_bytes(const std::string& jid,
                               const std::vector<uint8_t>& data,
                               const std::string& mime_type) {
    auto& mgr = get_profile_manager();
    auto [item_id, sha1] = mgr.pep().publish_avatar_data(jid, data, mime_type);
    return sha1;
}

/**
 * Quick avatar get - returns base64-encoded data.
 */
std::string get_avatar_base64(const std::string& jid) {
    auto& mgr = get_profile_manager();
    auto data = mgr.avatars().get_avatar_data(jid);
    if (data.has_value()) {
        return detail::base64_encode(data.value());
    }
    return "";
}

/**
 * Quick user profile set from JSON representation.
 */
ProfileValidator::ValidationResult set_profile_json(const std::string& jid,
                                                      const nlohmann::json& profile_json) {
    UserProfile profile;
    profile.jid = jid;

    if (profile_json.contains("vcard")) {
        profile.vcard = legacy::VCardJsonAdapter::from_json(profile_json["vcard"]);
    }

    auto& mgr = get_profile_manager();
    return mgr.set_full_profile(jid, profile);
}

/**
 * Quick user profile get as JSON.
 */
nlohmann::json get_profile_json(const std::string& jid) {
    auto& mgr = get_profile_manager();
    auto profile = mgr.get_full_profile(jid);

    nlohmann::json j;
    j["jid"] = profile.jid;
    j["vcard"] = legacy::VCardJsonAdapter::to_json(profile.vcard);

    // Avatar
    if (!profile.avatar_data.empty()) {
        j["avatar_base64"] = detail::base64_encode(profile.avatar_data);
        j["avatar_mime_type"] = profile.avatar_mime_type;
    }

    // Mood
    if (profile.mood.value != MoodValue::UNKNOWN) {
        auto it = mood_value_to_name.find(profile.mood.value);
        if (it != mood_value_to_name.end()) {
            j["mood"] = it->second;
        }
        if (!profile.mood.text.empty()) {
            j["mood_text"] = profile.mood.text;
        }
    }

    // Activity
    if (profile.activity.general != ActivityGeneral::UNKNOWN) {
        auto gen_it = activity_general_to_name.find(profile.activity.general);
        if (gen_it != activity_general_to_name.end()) {
            j["activity_general"] = gen_it->second;
        }
        if (profile.activity.specific != ActivitySpecific::NONE) {
            auto spec_it = activity_specific_to_name.find(profile.activity.specific);
            if (spec_it != activity_specific_to_name.end()) {
                j["activity_specific"] = spec_it->second;
            }
        }
        if (!profile.activity.text.empty()) {
            j["activity_text"] = profile.activity.text;
        }
    }

    // Tune
    if (!profile.tune.artist.empty() || !profile.tune.title.empty()) {
        j["tune_artist"] = profile.tune.artist;
        j["tune_title"]  = profile.tune.title;
        if (!profile.tune.source.empty()) j["tune_source"] = profile.tune.source;
        if (!profile.tune.track.empty())  j["tune_track"]  = profile.tune.track;
        if (profile.tune.length > 0)      j["tune_length"] = profile.tune.length;
        if (profile.tune.rating > 0)      j["tune_rating"] = profile.tune.rating;
        if (!profile.tune.uri.empty())    j["tune_uri"]    = profile.tune.uri;
    }

    // Geolocation
    if (profile.geoloc.has_basic_position()) {
        j["geoloc_lat"]  = profile.geoloc.latitude;
        j["geoloc_lon"]  = profile.geoloc.longitude;
        if (!std::isnan(profile.geoloc.altitude)) j["geoloc_alt"] = profile.geoloc.altitude;
        if (!profile.geoloc.locality.empty()) j["geoloc_locality"] = profile.geoloc.locality;
        if (!profile.geoloc.country.empty())  j["geoloc_country"]  = profile.geoloc.country;
    }

    // Nickname
    if (!profile.nickname_pep.empty()) {
        j["nickname"] = profile.nickname_pep;
    }

    // Metadata
    j["cached_at"]       = profile.cached_at;
    j["vcard_updated"]   = profile.vcard_updated_at;
    j["avatar_updated"]  = profile.avatar_updated_at;

    return j;
}

// ============================================================================
// Avatar metadata notification broadcaster
// ============================================================================

class AvatarNotificationBroadcaster {
public:
    using NotificationCallback = std::function<void(const std::string& jid,
                                                      const AvatarMetadataSet&)>;

    /**
     * Register a callback to be notified when avatar metadata changes.
     */
    void subscribe(NotificationCallback cb) {
        std::unique_lock<std::mutex> lock(mutex_);
        subscribers_.push_back(std::move(cb));
    }

    /**
     * Notify all subscribers that a user's avatar metadata has changed.
     */
    void notify_avatar_change(const std::string& jid, const AvatarMetadataSet& metadata) {
        std::unique_lock<std::mutex> lock(mutex_);
        for (auto& sub : subscribers_) {
            if (sub) {
                sub(jid, metadata);
            }
        }
    }

    /**
     * Remove all subscribers.
     */
    void clear() {
        std::unique_lock<std::mutex> lock(mutex_);
        subscribers_.clear();
    }

    /**
     * Get number of subscribers.
     */
    size_t subscriber_count() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return subscribers_.size();
    }

private:
    mutable std::mutex mutex_;
    std::vector<NotificationCallback> subscribers_;
};

// ============================================================================
// Global notification broadcaster singleton
// ============================================================================

namespace {

std::unique_ptr<AvatarNotificationBroadcaster> g_notification_broadcaster;
std::mutex g_notification_broadcaster_mutex;

} // anonymous namespace

AvatarNotificationBroadcaster& get_avatar_notification_broadcaster() {
    std::lock_guard<std::mutex> lock(g_notification_broadcaster_mutex);
    if (!g_notification_broadcaster) {
        g_notification_broadcaster = std::make_unique<AvatarNotificationBroadcaster>();
    }
    return *g_notification_broadcaster;
}

} // namespace xmpp
} // namespace progressive
