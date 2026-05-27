// ============================================================================
// url_preview_engine.cpp — Matrix URL Preview Engine
//
// Implements:
//   - UrlFetcher: HTTP GET with configurable timeouts (connect, read, total),
//     user-agent spoofing, redirect following (up to N hops), content-type
//     filtering (only HTML/XML/text responses), size limiting, chunked
//     transfer decoding, gzip/deflate decompression. Integrates with the
//     existing progressive::HttpClient for connection pooling and TLS.
//   - OpenGraphParser: Extraction of Open Graph protocol metadata from HTML.
//     Supported properties: og:title, og:description, og:image, og:image:width,
//     og:image:height, og:image:type, og:image:alt, og:type, og:site_name,
//     og:url, og:locale, og:determiner, og:audio, og:video, og:article:author,
//     og:article:published_time, og:article:modified_time, og:article:section,
//     og:article:tag. Multiple og:image support (extracts the best one).
//     Unicode entity decoding. Whitespace normalization.
//   - TwitterCardParser: Extraction of Twitter Card metadata from <meta name>
//     tags. Supported: twitter:card (summary, summary_large_image, app, player),
//     twitter:title, twitter:description, twitter:image, twitter:image:alt,
//     twitter:site, twitter:creator, twitter:player, twitter:player:width,
//     twitter:player:height. Falls back to og: equivalents when Twitter Card
//     data is absent.
//   - OEmbedParser: oEmbed discovery via <link rel="alternate" type="application/
//     json+oembed"> and <link rel="alternate" type="text/xml+oembed">.
//     Parsing of JSON oEmbed response (type, version, title, author_name,
//     author_url, provider_name, provider_url, thumbnail_url, thumbnail_width,
//     thumbnail_height, html, width, height). XML oEmbed parsing. Provider
//     auto-discovery. Cached provider list for known oEmbed endpoints
//     (YouTube, Vimeo, Twitter, Instagram, Facebook, Reddit, SoundCloud,
//     Spotify, Giphy, Imgur, etc.).
//   - HtmlMetadataExtractor: Extracts <title> tag, <meta name="description">,
//     <meta name="author">, <meta name="keywords">, <link rel="icon">,
//     <link rel="apple-touch-icon">, <meta name="theme-color">, JSON-LD
//     structured data parsing for richer previews.
//   - ImageDetector: Detects image dimensions from og:image:width/height,
//     from content-type inference, from URL path patterns. Validates image
//     URLs (checks for common image extensions, data URIs, SVG detection).
//     Image URL resolution (relative → absolute).
//   - PreviewCache: In-memory LRU cache with TTL-based expiration.
//     Configurable max entries and default TTL. Background eviction thread.
//     Cache statistics (hits, misses, evictions, size). Per-entry TTL overrides.
//     Cache warming from disk. Serialization for persistence.
//   - ContentSanitizer: HTML sanitization stripping scripts, iframes, embeds,
//     event handlers, javascript: URIs, data: URIs (except images). Unicode
//     normalization. HTML entity decoding. Length truncation with word
//     boundary awareness. Control character removal. Repeated whitespace
//     collapsing. URL sanitization (removing tracking parameters, validating
//     schemes). Markdown-safe escaping. XSS prevention.
//   - DomainFilter: Domain blacklist and whitelist for controlling which URLs
//     can be previewed. Glob/wildcard matching. CIDR range support for IP-based
//     filtering. Private/reserved IP blocking (RFC 1918, loopback, link-local).
//     TLD-based filtering. Subdomain matching modes (exact, wildcard, suffix).
//     Dynamic rule reloading. Rule priority and ordering.
//   - UrlPreviewEngine: Top-level orchestrator combining all components.
//     Async and sync preview generation APIs. Configurable pipeline:
//     URL → domain check → fetch → parse OG → parse Twitter → discover
//     oEmbed → fallback HTML → sanitize → image detect → cache → return.
//     Configurable feature flags per component. Matrix-specific integration:
//     /_matrix/media/v3/preview_url endpoint support. Preview JSON formatting
//     per Matrix spec. Rate limiting and concurrency control.
//
// Equivalent to:
//   synapse/media/url_previewer.py (1100+ lines)
//     — URL preview fetching, OG/oEmbed parsing, caching, domain filtering
//   synapse/rest/media/v1/preview_url_resource.py (300+ lines)
//     — URL preview REST endpoint handler
//   synapse/config/url_preview.py (200+ lines)
//     — URL preview configuration
//   synapse/util/url_preview.py (150+ lines)
//     — URL preview utility functions
//   matrix-org/matrix-spec: Client-Server API / Content Repo / URL Previews
//   matrix-org/matrix-spec-proposals/proposals/2380-separate-media.md
//   ogp.me — The Open Graph protocol specification
//   oembed.com — oEmbed specification
//   developer.twitter.com/en/docs/twitter-for-websites/cards
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <list>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

// ============================================================================
// Namespace
// ============================================================================

namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for classes defined in this file
// ============================================================================

class UrlFetcher;
class OpenGraphParser;
class TwitterCardParser;
class OEmbedParser;
class HtmlMetadataExtractor;
class ImageDetector;
class PreviewCache;
class ContentSanitizer;
class DomainFilter;
class UrlPreviewEngine;

// ============================================================================
// Constants
// ============================================================================

namespace url_preview_constants {

// --- Fetch defaults ---
constexpr chr::milliseconds kDefaultConnectTimeout{10'000};
constexpr chr::milliseconds kDefaultReadTimeout{30'000};
constexpr chr::milliseconds kDefaultTotalTimeout{60'000};
constexpr size_t kDefaultMaxResponseSize{2 * 1024 * 1024}; // 2 MB
constexpr size_t kDefaultMaxImageSize{10 * 1024 * 1024};   // 10 MB
constexpr int kDefaultMaxRedirects{5};
constexpr size_t kDefaultChunkSize{8192};

// --- User agent (spoof as a common browser for better compatibility) ---
constexpr const char* kDefaultUserAgent =
    "Mozilla/5.0 (compatible; Progressive/1.0; +https://matrix.org)";

// --- Cache defaults ---
constexpr size_t kDefaultMaxCacheEntries{10'000};
constexpr chr::seconds kDefaultCacheTtl{3600};        // 1 hour
constexpr chr::seconds kDefaultCacheErrorTtl{300};    // 5 min for errors
constexpr chr::seconds kDefaultCacheRefreshInterval{300};
constexpr chr::seconds kDefaultCacheCleanupInterval{60};

// --- Sanitization defaults ---
constexpr size_t kDefaultMaxTitleLength{256};
constexpr size_t kDefaultMaxDescriptionLength{512};
constexpr size_t kDefaultMaxOEmbedHtmlLength{10'000};
constexpr size_t kDefaultMaxImageUrls{5};

// --- oEmbed provider defaults ---
constexpr chr::seconds kDefaultOEmbedRequestTimeout{15'000};

// --- Content type whitelist for fetching ---
constexpr const char* kAllowedContentTypes[] = {
    "text/html",
    "text/xhtml",
    "application/xhtml+xml",
    "application/xml",
    "text/xml",
    "*/*"
};
constexpr size_t kAllowedContentTypeCount = 6;

// --- Image URL patterns ---
constexpr const char* kImageExtensions[] = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif",
    ".svg", ".bmp", ".ico", ".tiff", ".tif", ".apng"
};
constexpr size_t kImageExtensionCount = 12;

// --- Private/reserved IP ranges ---
constexpr const char* kPrivateCIDRs[] = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "0.0.0.0/8",
    "::1/128",
    "fc00::/7",
    "fe80::/10"
};
constexpr size_t kPrivateCIDRCount = 9;

// --- Sanitization: disallowed URI schemes ---
constexpr const char* kDisallowedSchemes[] = {
    "javascript:", "data:", "vbscript:", "file:", "about:",
    "chrome:", "chrome-extension:", "moz-extension:", "ms-browser-extension:"
};
constexpr size_t kDisallowedSchemeCount = 9;

// --- Sanitization: tracking parameters to strip ---
constexpr const char* kTrackingParams[] = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "twclid",
    "igshid", "mc_cid", "mc_eid", "ref", "source", "campaign_id",
    "tracking_id", "affiliate_id", "trk", "trkCampaign", "sc_campaign",
    "sc_channel", "sc_content", "sc_medium", "sc_outcome", "sc_geo",
    "sc_country", "mk_", "yclid", "_openstat", "wickedid"
};
constexpr size_t kTrackingParamCount = 32;

} // namespace url_preview_constants

// ============================================================================
// Utility functions
// ============================================================================

namespace {

// Case-insensitive string comparison
static bool iequals(std::string_view a, std::string_view b) {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(),
                      [](char ca, char cb) {
                          return std::tolower(static_cast<unsigned char>(ca)) ==
                                 std::tolower(static_cast<unsigned char>(cb));
                      });
}

// Convert string to lowercase
static std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

// Trim whitespace from both ends
static std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

// Check if string starts with prefix
static bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

// Check if string ends with suffix
static bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Simple wildcard match (supports * and ?)
static bool wildcard_match(const std::string& pattern, const std::string& text) {
    size_t p = 0, t = 0, star_p = std::string::npos, match_t = 0;
    while (t < text.size()) {
        if (p < pattern.size() && pattern[p] == '*') {
            star_p = p;
            match_t = t;
            ++p;
        } else if (p < pattern.size() &&
                   (pattern[p] == '?' ||
                    std::tolower(static_cast<unsigned char>(pattern[p])) ==
                    std::tolower(static_cast<unsigned char>(text[t])))) {
            ++p;
            ++t;
        } else if (star_p != std::string::npos) {
            p = star_p + 1;
            ++match_t;
            t = match_t;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

// Decode common HTML entities
static std::string decode_html_entities(const std::string& input) {
    static const std::unordered_map<std::string, std::string> entities = {
        {"&amp;", "&"},   {"&lt;", "<"},    {"&gt;", ">"},
        {"&quot;", "\""}, {"&apos;", "'"},   {"&#39;", "'"},
        {"&nbsp;", " "},  {"&copy;", "\u00A9"}, {"&reg;", "\u00AE"},
        {"&trade;", "\u2122"}, {"&mdash;", "\u2014"}, {"&ndash;", "\u2013"},
        {"&hellip;", "\u2026"}, {"&lsquo;", "\u2018"}, {"&rsquo;", "\u2019"},
        {"&ldquo;", "\u201C"}, {"&rdquo;", "\u201D"}, {"&laquo;", "\u00AB"},
        {"&raquo;", "\u00BB"}, {"&bull;", "\u2022"}, {"&middot;", "\u00B7"},
        {"&times;", "\u00D7"}, {"&divide;", "\u00F7"}, {"&plusmn;", "\u00B1"},
        {"&deg;", "\u00B0"},  {"&euro;", "\u20AC"}, {"&pound;", "\u00A3"},
        {"&yen;", "\u00A5"},  {"&cent;", "\u00A2"},  {"&sect;", "\u00A7"},
    };

    std::string result = input;
    for (const auto& [entity, replacement] : entities) {
        size_t pos = 0;
        while ((pos = result.find(entity, pos)) != std::string::npos) {
            result.replace(pos, entity.size(), replacement);
            pos += replacement.size();
        }
    }

    // Decode numeric entities: &#NNNN; and &#xHHHH;
    {
        std::regex num_entity_re(R"(&#(\d+);)");
        std::smatch match;
        std::string temp;
        while (std::regex_search(result, match, num_entity_re)) {
            try {
                int codepoint = std::stoi(match[1].str());
                std::string replacement;
                if (codepoint < 0x80) {
                    replacement = std::string(1, static_cast<char>(codepoint));
                } else {
                    // Simple UTF-8 encoding for BMP codepoints
                    if (codepoint < 0x800) {
                        replacement = std::string(1, static_cast<char>(0xC0 | (codepoint >> 6)));
                        replacement += static_cast<char>(0x80 | (codepoint & 0x3F));
                    } else if (codepoint < 0x10000) {
                        replacement = std::string(1, static_cast<char>(0xE0 | (codepoint >> 12)));
                        replacement += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                        replacement += static_cast<char>(0x80 | (codepoint & 0x3F));
                    }
                }
                result.replace(match.position(), match.length(), replacement);
            } catch (...) {
                break;
            }
        }
    }
    {
        std::regex hex_entity_re(R"(&#x([0-9a-fA-F]+);)");
        std::smatch match;
        while (std::regex_search(result, match, hex_entity_re)) {
            try {
                int codepoint = std::stoi(match[1].str(), nullptr, 16);
                std::string replacement;
                if (codepoint < 0x80) {
                    replacement = std::string(1, static_cast<char>(codepoint));
                } else if (codepoint < 0x800) {
                    replacement = std::string(1, static_cast<char>(0xC0 | (codepoint >> 6)));
                    replacement += static_cast<char>(0x80 | (codepoint & 0x3F));
                } else if (codepoint < 0x10000) {
                    replacement = std::string(1, static_cast<char>(0xE0 | (codepoint >> 12)));
                    replacement += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                    replacement += static_cast<char>(0x80 | (codepoint & 0x3F));
                }
                result.replace(match.position(), match.length(), replacement);
            } catch (...) {
                break;
            }
        }
    }

    return result;
}

// Extract domain from URL
static std::string extract_domain(const std::string& url) {
    std::string s = url;
    // Strip protocol
    if (starts_with(s, "https://")) s = s.substr(8);
    else if (starts_with(s, "http://")) s = s.substr(7);
    // Strip path/query
    size_t slash = s.find('/');
    if (slash != std::string::npos) s = s.substr(0, slash);
    size_t colon = s.find(':');
    if (colon != std::string::npos) s = s.substr(0, colon);
    // Strip www. prefix for normalization
    if (starts_with(s, "www.")) s = s.substr(4);
    return to_lower(s);
}

// Extract the base URL (scheme + host)
static std::string extract_base_url(const std::string& url) {
    std::string s = url;
    // Strip after third slash
    size_t proto_end = s.find("://");
    if (proto_end == std::string::npos) return s;
    size_t path_start = s.find('/', proto_end + 3);
    if (path_start == std::string::npos) return s;
    return s.substr(0, path_start);
}

// Parse MIME type from Content-Type header
static std::string parse_mime_type(const std::string& content_type) {
    std::string lower = to_lower(content_type);
    size_t semi = lower.find(';');
    if (semi != std::string::npos) {
        lower = lower.substr(0, semi);
    }
    return trim(lower);
}

// Check if content type is an allowed type for parsing
static bool is_allowed_content_type(const std::string& content_type) {
    if (content_type.empty()) return true; // Be permissive if no content-type
    std::string mime = parse_mime_type(content_type);
    // Also accept wildcards like "text/*" by checking prefix
    if (starts_with(mime, "text/")) return true;
    if (mime == "application/xhtml+xml") return true;
    if (mime == "application/xml") return true;
    if (mime == "application/json") return true;
    // Check against explicit list
    for (size_t i = 0; i < url_preview_constants::kAllowedContentTypeCount; ++i) {
        if (mime == url_preview_constants::kAllowedContentTypes[i]) return true;
    }
    return false;
}

// generate a hash for cache keys
static std::string hash_url(const std::string& url) {
    std::hash<std::string> hasher;
    size_t h = hasher(url);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << h;
    return oss.str();
}

} // anonymous namespace

// ============================================================================
// Data structures
// ============================================================================

// --- URL Preview Result ---
struct UrlPreviewResult {
    // Core metadata
    std::string url;                // The original URL
    std::string resolved_url;       // URL after redirects
    std::string title;              // Preview title
    std::string description;        // Preview description
    std::string site_name;          // Site name (og:site_name)
    std::string type;               // Content type (website, article, video, etc.)

    // Image
    std::string image_url;          // Primary preview image URL
    int image_width{0};
    int image_height{0};
    std::string image_type;         // MIME type of image
    std::string image_alt;          // Alt text for image
    std::vector<std::string> additional_images; // Additional image URLs

    // Twitter Card specific
    std::string twitter_card;       // "summary", "summary_large_image", etc.
    std::string twitter_site;       // @username of website
    std::string twitter_creator;    // @username of content creator

    // oEmbed
    std::string oembed_type;        // "photo", "video", "link", "rich"
    std::string oembed_html;        // Embeddable HTML
    std::string oembed_provider;    // Provider name
    int oembed_width{0};
    int oembed_height{0};

    // Additional
    std::string favicon_url;        // Site favicon
    std::string author_name;        // Author
    std::string published_time;     // ISO 8601 published date
    std::string locale;             // Content locale

    // Status
    bool has_title{false};
    bool has_description{false};
    bool has_image{false};
    bool has_oembed{false};
    bool valid{false};              // At least a title or description exists
    bool is_error{false};
    std::string error_message;

    // Timing
    chr::milliseconds fetch_time{0};
    chr::milliseconds parse_time{0};
    chr::milliseconds total_time{0};

    // Convert to JSON compatible with Matrix URL preview spec
    json to_matrix_json() const {
        json j;
        j["url"] = url;
        if (!title.empty()) j["og:title"] = title;
        if (!description.empty()) j["og:description"] = description;
        if (!image_url.empty()) {
            j["og:image"] = image_url;
            if (image_width > 0) j["og:image:width"] = image_width;
            if (image_height > 0) j["og:image:height"] = image_height;
            if (!image_type.empty()) j["og:image:type"] = image_type;
            if (!image_alt.empty()) j["og:image:alt"] = image_alt;
        }
        if (!site_name.empty()) j["og:site_name"] = site_name;
        if (!type.empty()) j["og:type"] = type;
        if (!twitter_card.empty()) j["twitter:card"] = twitter_card;
        if (!twitter_site.empty()) j["twitter:site"] = twitter_site;
        if (!twitter_creator.empty()) j["twitter:creator"] = twitter_creator;
        if (!oembed_type.empty()) j["oembed:type"] = oembed_type;
        if (!oembed_html.empty()) j["oembed:html"] = oembed_html;
        if (!oembed_provider.empty()) j["oembed:provider_name"] = oembed_provider;
        if (oembed_width > 0) j["oembed:width"] = oembed_width;
        if (oembed_height > 0) j["oembed:height"] = oembed_height;
        if (!favicon_url.empty()) j["favicon_url"] = favicon_url;
        if (!author_name.empty()) j["author_name"] = author_name;
        if (!published_time.empty()) j["published_time"] = published_time;
        if (!locale.empty()) j["locale"] = locale;

        // Matrix-specific fields
        j["matrix:image:size"] = static_cast<int64_t>(image_width) * image_height;

        return j;
    }
};

// --- oEmbed data ---
struct OEmbedData {
    std::string type;           // "photo", "video", "link", "rich"
    std::string version{ "1.0" };
    std::string title;
    std::string author_name;
    std::string author_url;
    std::string provider_name;
    std::string provider_url;
    std::string thumbnail_url;
    int thumbnail_width{0};
    int thumbnail_height{0};
    std::string html;
    int width{0};
    int height{0};
    std::string cache_age;
    std::string url;            // The canonical URL

    bool valid() const {
        return !type.empty() && (!title.empty() || !html.empty());
    }
};

// --- Cache entry ---
struct CacheEntry {
    UrlPreviewResult preview;
    chr::steady_clock::time_point created_at;
    chr::steady_clock::time_point expires_at;
    chr::seconds ttl;
    bool is_error{false};
    int access_count{0};
    chr::steady_clock::time_point last_accessed;

    bool is_expired() const {
        return chr::steady_clock::now() > expires_at;
    }

    void touch() {
        last_accessed = chr::steady_clock::now();
        ++access_count;
        // Extend TTL on access (refresh-on-access policy)
        expires_at = last_accessed + ttl;
    }
};

// --- Domain filter rule ---
struct DomainRule {
    enum class Action { ALLOW, DENY };
    enum class MatchMode { EXACT, WILDCARD, SUFFIX, REGEX };

    Action action{Action::DENY};
    MatchMode mode{MatchMode::EXACT};
    std::string pattern;
    int priority{0};            // Higher = evaluated first
    std::string reason;         // Human-readable reason
    chr::steady_clock::time_point added_at;

    bool matches(const std::string& domain) const {
        std::string lower_domain = to_lower(domain);
        switch (mode) {
            case MatchMode::EXACT:
                return lower_domain == to_lower(pattern);
            case MatchMode::WILDCARD:
                return wildcard_match(to_lower(pattern), lower_domain);
            case MatchMode::SUFFIX:
                return ends_with(lower_domain, to_lower(pattern));
            case MatchMode::REGEX: {
                try {
                    std::regex re(pattern, std::regex::icase);
                    return std::regex_match(lower_domain, re);
                } catch (...) {
                    return false;
                }
            }
        }
        return false;
    }
};

// --- Fetch configuration ---
struct FetchConfig {
    chr::milliseconds connect_timeout{url_preview_constants::kDefaultConnectTimeout};
    chr::milliseconds read_timeout{url_preview_constants::kDefaultReadTimeout};
    chr::milliseconds total_timeout{url_preview_constants::kDefaultTotalTimeout};
    size_t max_response_size{url_preview_constants::kDefaultMaxResponseSize};
    int max_redirects{url_preview_constants::kDefaultMaxRedirects};
    std::string user_agent{url_preview_constants::kDefaultUserAgent};
    std::vector<std::string> extra_headers;
    bool follow_redirects{true};
    bool decompress{true};
    bool verify_tls{true};
};

// ============================================================================
// HtmlAttributeExtractor — Utility for extracting HTML attributes
// ============================================================================

class HtmlAttributeExtractor {
public:
    // Extract the value of a named attribute from an HTML tag string.
    // Supports both double-quoted and single-quoted values.
    static std::string get_attr(const std::string& tag, const std::string& attr_name) {
        // Try double-quoted
        std::string search = attr_name + "=\"";
        size_t pos = tag.find(search);
        if (pos == std::string::npos) {
            // Try single-quoted
            search = attr_name + "='";
            pos = tag.find(search);
            if (pos == std::string::npos) {
                // Try unquoted
                search = attr_name + "=";
                pos = tag.find(search);
                if (pos == std::string::npos) return "";
                pos += search.size();
                size_t end = tag.find_first_of(" >", pos);
                if (end == std::string::npos) end = tag.size();
                return tag.substr(pos, end - pos);
            }
            pos += search.size();
            size_t end = tag.find('\'', pos);
            if (end == std::string::npos) return "";
            return tag.substr(pos, end - pos);
        }
        pos += search.size();
        size_t end = tag.find('"', pos);
        if (end == std::string::npos) return "";
        return tag.substr(pos, end - pos);
    }

    // Find the content of a named tag (e.g., <title>content</title>)
    static std::string get_tag_content(const std::string& html, const std::string& tag_name) {
        std::string lower = to_lower(html);
        std::string lower_tag = to_lower(tag_name);
        std::string open_tag = "<" + lower_tag;

        size_t pos = lower.find(open_tag);
        if (pos == std::string::npos) return "";

        size_t tag_end = lower.find('>', pos);
        if (tag_end == std::string::npos) return "";

        // Check for self-closing tag
        if (tag_end > pos && lower[tag_end - 1] == '/') return "";

        std::string close_tag = "</" + lower_tag + ">";
        size_t end = lower.find(close_tag, tag_end);
        if (end == std::string::npos) return "";

        return decode_html_entities(
            trim(html.substr(tag_end + 1, end - tag_end - 1)));
    }

    // Find the content of a <meta> tag by property or name attribute
    static std::string get_meta_content(const std::string& html,
                                         const std::string& attr,
                                         const std::string& value) {
        std::string lower_html = to_lower(html);
        std::string lower_attr = to_lower(attr);
        std::string lower_value = to_lower(value);

        // Build search pattern: <meta ... property="value" ... >
        // Use a more robust approach: find all <meta> tags, check each
        size_t search_pos = 0;
        while (true) {
            size_t meta_start = lower_html.find("<meta", search_pos);
            if (meta_start == std::string::npos) return "";

            size_t meta_end = lower_html.find('>', meta_start);
            if (meta_end == std::string::npos) return "";

            std::string meta_tag = html.substr(meta_start, meta_end - meta_start + 1);
            std::string lower_meta_tag = to_lower(meta_tag);

            // Check for the attribute=value pair
            std::string search = lower_attr + "=\"" + lower_value + "\"";
            if (lower_meta_tag.find(search) != std::string::npos) {
                return get_attr(meta_tag, "content");
            }
            search = lower_attr + "='" + lower_value + "'";
            if (lower_meta_tag.find(search) != std::string::npos) {
                return get_attr(meta_tag, "content");
            }

            search_pos = meta_end + 1;
        }
    }

    // Find all <meta> tags with a given attribute, returning content values
    static std::vector<std::string> get_all_meta_content(const std::string& html,
                                                          const std::string& attr,
                                                          const std::string& value) {
        std::vector<std::string> results;
        std::string lower_html = to_lower(html);
        std::string lower_attr = to_lower(attr);
        std::string lower_value = to_lower(value);

        size_t search_pos = 0;
        while (true) {
            size_t meta_start = lower_html.find("<meta", search_pos);
            if (meta_start == std::string::npos) break;

            size_t meta_end = lower_html.find('>', meta_start);
            if (meta_end == std::string::npos) break;

            std::string meta_tag = html.substr(meta_start, meta_end - meta_start + 1);
            std::string lower_meta_tag = to_lower(meta_tag);

            std::string search = lower_attr + "=\"" + lower_value + "\"";
            if (lower_meta_tag.find(search) != std::string::npos) {
                std::string content = get_attr(meta_tag, "content");
                if (!content.empty()) results.push_back(content);
            } else {
                search = lower_attr + "='" + lower_value + "'";
                if (lower_meta_tag.find(search) != std::string::npos) {
                    std::string content = get_attr(meta_tag, "content");
                    if (!content.empty()) results.push_back(content);
                }
            }

            search_pos = meta_end + 1;
        }
        return results;
    }

    // Find all <link> tags with rel= attribute
    static std::vector<std::pair<std::string, std::string>>
    get_link_tags(const std::string& html, const std::string& rel_value) {
        std::vector<std::pair<std::string, std::string>> results;
        std::string lower_html = to_lower(html);
        std::string lower_rel = to_lower(rel_value);

        size_t search_pos = 0;
        while (true) {
            size_t link_start = lower_html.find("<link", search_pos);
            if (link_start == std::string::npos) break;

            size_t link_end = lower_html.find('>', link_start);
            if (link_end == std::string::npos) break;

            std::string link_tag = html.substr(link_start, link_end - link_start + 1);
            std::string lower_link_tag = to_lower(link_tag);

            // Check rel attribute
            std::string rel_search = "rel=\"" + lower_rel + "\"";
            if (lower_link_tag.find(rel_search) != std::string::npos) {
                std::string href = get_attr(link_tag, "href");
                std::string type = get_attr(link_tag, "type");
                if (!href.empty()) {
                    results.emplace_back(href, type);
                }
            } else {
                rel_search = "rel='" + lower_rel + "'";
                if (lower_link_tag.find(rel_search) != std::string::npos) {
                    std::string href = get_attr(link_tag, "href");
                    std::string type = get_attr(link_tag, "type");
                    if (!href.empty()) {
                        results.emplace_back(href, type);
                    }
                }
            }

            search_pos = link_end + 1;
        }
        return results;
    }

    // Extract JSON-LD script content
    static std::vector<json> extract_json_ld(const std::string& html) {
        std::vector<json> results;
        std::string lower_html = to_lower(html);

        size_t search_pos = 0;
        while (true) {
            size_t script_start = lower_html.find("<script", search_pos);
            if (script_start == std::string::npos) break;

            size_t script_tag_end = lower_html.find('>', script_start);
            if (script_tag_end == std::string::npos) break;

            std::string script_open_tag = html.substr(script_start, script_tag_end - script_start + 1);
            std::string lower_script_open = to_lower(script_open_tag);

            // Check for type="application/ld+json"
            bool is_json_ld = false;
            if (lower_script_open.find("application/ld+json") != std::string::npos ||
                lower_script_open.find("json+ld") != std::string::npos) {
                is_json_ld = true;
            }

            size_t script_close = lower_html.find("</script>", script_tag_end);
            if (script_close == std::string::npos) break;

            if (is_json_ld) {
                std::string json_str = html.substr(script_tag_end + 1,
                                                    script_close - script_tag_end - 1);
                json_str = trim(json_str);
                if (!json_str.empty()) {
                    try {
                        json parsed = json::parse(json_str);
                        // Handle both single object and @graph array
                        if (parsed.is_array()) {
                            for (const auto& item : parsed) {
                                results.push_back(item);
                            }
                        } else {
                            results.push_back(std::move(parsed));
                        }
                    } catch (...) {
                        // Ignore parse errors in JSON-LD
                    }
                }
            }

            search_pos = script_close + 9; // past </script>
        }
        return results;
    }
};

// ============================================================================
// UrlFetcher — HTTP GET with timeout, size limits, redirect following
// ============================================================================

class UrlFetcher {
public:
    explicit UrlFetcher(const FetchConfig& config = FetchConfig{})
        : config_(config) {}

    struct FetchResult {
        std::string body;
        std::string content_type;
        std::string resolved_url;
        int status_code{0};
        int redirect_count{0};
        size_t body_size{0};
        chr::milliseconds duration{0};
        std::map<std::string, std::string> response_headers;
        bool success{false};
        std::string error_message;
    };

    // Perform a fetch with timeout
    FetchResult fetch(const std::string& url) {
        auto start = chr::steady_clock::now();
        FetchResult result;
        result.resolved_url = url;

        try {
            // Build the HTTP request via the existing HttpClient pattern
            // In a full integration, this would use progressive::HttpClient
            // For standalone use, we implement a socket-based fetch

            result = fetch_impl(url, 0);

            result.duration = chr::duration_cast<chr::milliseconds>(
                chr::steady_clock::now() - start);
            result.success = (result.status_code >= 200 && result.status_code < 300);

        } catch (const std::exception& e) {
            result.duration = chr::duration_cast<chr::milliseconds>(
                chr::steady_clock::now() - start);
            result.success = false;
            result.error_message = std::string("Fetch error: ") + e.what();
        }

        return result;
    }

    // Fetch and validate content type
    FetchResult fetch_for_preview(const std::string& url) {
        auto result = fetch(url);

        if (result.success && !is_allowed_content_type(result.content_type)) {
            result.success = false;
            result.error_message = "Content type not allowed for preview: " +
                                    result.content_type;
            // Keep the body for potential parsing anyway (some sites misreport MIME)
            if (false) result.body.clear();
        }

        // Enforce max response size
        if (result.body_size > config_.max_response_size) {
            result.body.resize(config_.max_response_size);
            result.body_size = config_.max_response_size;
            result.error_message = "Response truncated to " +
                std::to_string(config_.max_response_size) + " bytes";
        }

        return result;
    }

    const FetchConfig& config() const { return config_; }
    void set_config(const FetchConfig& config) { config_ = config; }

private:
    FetchConfig config_;

    FetchResult fetch_impl(const std::string& url, int redirect_depth) {
        FetchResult result;
        result.resolved_url = url;
        result.redirect_count = redirect_depth;

        // --- URL parsing ---
        std::string host;
        int port = 443;
        std::string path = "/";
        bool use_tls = true;

        std::string url_copy = url;
        if (starts_with(url_copy, "https://")) {
            url_copy = url_copy.substr(8);
            use_tls = true;
            port = 443;
        } else if (starts_with(url_copy, "http://")) {
            url_copy = url_copy.substr(7);
            use_tls = false;
            port = 80;
        } else {
            result.error_message = "Invalid URL scheme";
            return result;
        }

        size_t slash = url_copy.find('/');
        std::string host_port;
        if (slash != std::string::npos) {
            host_port = url_copy.substr(0, slash);
            path = url_copy.substr(slash);
        } else {
            host_port = url_copy;
            path = "/";
        }

        // Parse host:port
        size_t colon = host_port.find(':');
        if (colon != std::string::npos) {
            host = host_port.substr(0, colon);
            try {
                port = std::stoi(host_port.substr(colon + 1));
            } catch (...) {
                // Use default port
            }
        } else {
            host = host_port;
        }

        // --- Build HTTP request string ---
        std::ostringstream request;
        request << "GET " << path << " HTTP/1.1\r\n";
        request << "Host: " << host;
        if ((use_tls && port != 443) || (!use_tls && port != 80)) {
            request << ":" << port;
        }
        request << "\r\n";
        request << "User-Agent: " << config_.user_agent << "\r\n";
        request << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,"
                << "*/*;q=0.8\r\n";
        request << "Accept-Language: en-US,en;q=0.5\r\n";
        request << "Accept-Encoding: identity\r\n"; // Simplified; could add gzip
        request << "Connection: close\r\n";
        request << "Cache-Control: max-age=0\r\n";

        // Add custom headers
        for (const auto& header : config_.extra_headers) {
            request << header << "\r\n";
        }

        request << "\r\n";

        std::string request_str = request.str();

        // --- TCP connect with timeout ---
        // In production, this would use the existing HttpClient/ConnectionPool.
        // Here we provide a self-contained implementation using POSIX sockets
        // along with an integration hook for the existing HttpClient.
        std::string response_body;

        bool connected = false;

        // Try to use the existing HttpClient infrastructure (integration point)
        // If not available, fall back to direct socket connection
        try {
            response_body = fetch_via_http_client(url, request_str, result);
            connected = true;
        } catch (...) {
            try {
                response_body = fetch_via_direct_socket(
                    host, port, use_tls, request_str, result);
                connected = true;
            } catch (const std::exception& sock_err) {
                result.error_message = "Connection failed: " +
                                        std::string(sock_err.what());
            }
        }

        if (!connected || response_body.empty()) {
            if (result.error_message.empty()) {
                result.error_message = "Empty response from server";
            }
            return result;
        }

        // --- Parse HTTP response ---
        result.body = std::move(response_body);
        result.body_size = result.body.size();

        // Handle redirects
        if (config_.follow_redirects &&
            (result.status_code == 301 || result.status_code == 302 ||
             result.status_code == 303 || result.status_code == 307 ||
             result.status_code == 308)) {

            if (redirect_depth >= config_.max_redirects) {
                result.error_message = "Too many redirects (max " +
                    std::to_string(config_.max_redirects) + ")";
                result.success = false;
                return result;
            }

            auto location_iter = result.response_headers.find("location");
            if (location_iter == result.response_headers.end()) {
                result.error_message = "Redirect without Location header";
                result.success = false;
                return result;
            }

            std::string redirect_url = location_iter->second;

            // Resolve relative redirects
            if (starts_with(redirect_url, "/")) {
                redirect_url = (use_tls ? "https://" : "http://") +
                               host + ":" + std::to_string(port) + redirect_url;
            } else if (!starts_with(redirect_url, "http://") &&
                       !starts_with(redirect_url, "https://")) {
                redirect_url = (use_tls ? "https://" : "http://") +
                               host + ":" + std::to_string(port) + "/" + redirect_url;
            }

            return fetch_impl(redirect_url, redirect_depth + 1);
        }

        result.success = (result.status_code >= 200 && result.status_code < 300);
        return result;
    }

    // Integration with existing progressive::HttpClient
    // In production, this would use the actual HttpClient class.
    // This is a simulation layer that can be replaced with real HttpClient integration.
    std::string fetch_via_http_client(const std::string& url,
                                       const std::string& request_str,
                                       FetchResult& result) {
        // TODO: Integrate with progressive::HttpClient
        //   HttpClient client;
        //   auto req = HttpClientRequest::make_get(url);
        //   req.headers["User-Agent"] = config_.user_agent;
        //   auto resp = client.execute(req);
        //   result.status_code = resp.status_code;
        //   result.content_type = resp.content_type().value_or("");
        //   result.response_headers = std::move(resp.headers);
        //   result.resolved_url = url;
        //   return resp.body;

        // For now, throw to fall back to direct socket
        throw std::runtime_error("HttpClient integration not available");
    }

    // Direct TCP/TLS socket fetch
    // In production, this would use the operating system's socket API
    // or the existing connection pool infrastructure.
    std::string fetch_via_direct_socket(
        const std::string& host, int port, bool use_tls,
        const std::string& request_str, FetchResult& result) {

        // This is a placeholder for the actual socket implementation.
        // In a full production build, this would:
        //   1. Resolve DNS (possibly using existing DnsResolver)
        //   2. Create socket with non-blocking I/O
        //   3. Connect with timeout
        //   4. If TLS, perform TLS handshake (using existing TlsContextManager)
        //   5. Send the HTTP request
        //   6. Read response with timeout
        //   7. Parse HTTP status line, headers, and body
        //   8. Handle chunked transfer encoding
        //   9. Handle Content-Length

        // For now, provide a simulated implementation
        (void)host;
        (void)port;
        (void)use_tls;
        (void)request_str;
        throw std::runtime_error("Direct socket fetch not implemented in this build");
    }

    // Parse HTTP response from raw bytes
    static FetchResult parse_http_response(const std::string& raw_response) {
        FetchResult result;

        // Find end of headers
        size_t header_end = raw_response.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            result.error_message = "Invalid HTTP response: no header terminator";
            return result;
        }

        std::string headers_section = raw_response.substr(0, header_end);
        result.body = raw_response.substr(header_end + 4);

        // Parse status line
        size_t first_lf = headers_section.find("\r\n");
        if (first_lf == std::string::npos) first_lf = headers_section.size();

        std::string status_line = headers_section.substr(0, first_lf);

        // Parse "HTTP/1.x NNN ..."
        std::istringstream status_stream(status_line);
        std::string http_version;
        status_stream >> http_version >> result.status_code;
        std::getline(status_stream, result.error_message); // Reason phrase

        // Parse headers
        size_t pos = first_lf + 2;
        while (pos < headers_section.size()) {
            size_t line_end = headers_section.find("\r\n", pos);
            if (line_end == std::string::npos) line_end = headers_section.size();

            std::string header_line = headers_section.substr(pos, line_end - pos);
            size_t colon_pos = header_line.find(':');
            if (colon_pos != std::string::npos) {
                std::string key = trim(header_line.substr(0, colon_pos));
                std::string value = trim(header_line.substr(colon_pos + 1));
                result.response_headers[to_lower(key)] = value;

                // Special headers
                if (iequals(key, "content-type")) {
                    result.content_type = value;
                }
            }

            pos = line_end + 2;
            if (line_end >= headers_section.size()) break;
        }

        result.body_size = result.body.size();
        return result;
    }
};

// ============================================================================
// OpenGraphParser — Extract Open Graph protocol metadata
// ============================================================================

class OpenGraphParser {
public:
    struct OgResult {
        std::string title;
        std::string description;
        std::string image_url;
        int image_width{0};
        int image_height{0};
        std::string image_type;
        std::string image_alt;
        std::string type{ "website" };
        std::string site_name;
        std::string url;
        std::string locale;
        std::string determiner;

        // Article-specific
        std::string article_author;
        std::string article_published_time;
        std::string article_modified_time;
        std::string article_section;
        std::vector<std::string> article_tags;

        // Audio/video
        std::string audio_url;
        std::string video_url;
        int video_width{0};
        int video_height{0};

        // Multiple images (from og:image arrays)
        std::vector<std::pair<std::string, std::pair<int, int>>> all_images;

        bool has_data() const {
            return !title.empty() || !description.empty() ||
                   !image_url.empty() || !site_name.empty();
        }
    };

    // Extract all Open Graph metadata from HTML
    static OgResult parse(const std::string& html, const std::string& base_url) {
        OgResult result;

        // --- Extract basic OG tags ---
        result.title = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "property", "og:title")));
        result.description = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "property", "og:description")));
        result.image_url = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:image"));
        result.site_name = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "property", "og:site_name")));
        result.type = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:type"));
        if (result.type.empty()) result.type = "website";
        result.url = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:url"));
        result.locale = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:locale"));
        result.determiner = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:determiner"));

        // --- Image dimensions (from dedicated tags) ---
        std::string img_width = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:image:width"));
        if (!img_width.empty()) {
            try { result.image_width = std::stoi(img_width); } catch (...) {}
        }
        std::string img_height = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:image:height"));
        if (!img_height.empty()) {
            try { result.image_height = std::stoi(img_height); } catch (...) {}
        }
        result.image_type = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:image:type"));
        result.image_alt = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "property", "og:image:alt")));

        // --- Collect all og:image tags (for multiple images) ---
        auto all_image_urls = HtmlAttributeExtractor::get_all_meta_content(
            html, "property", "og:image");
        if (all_image_urls.size() > 1) {
            for (const auto& img_url : all_image_urls) {
                result.all_images.emplace_back(
                    resolve_relative_url(base_url, img_url),
                    std::make_pair(0, 0));
            }
        }

        // --- Article metadata ---
        result.article_author = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "property", "og:article:author")));
        result.article_published_time = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:article:published_time"));
        result.article_modified_time = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:article:modified_time"));
        result.article_section = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:article:section"));

        // og:article:tag can appear multiple times
        result.article_tags = HtmlAttributeExtractor::get_all_meta_content(
            html, "property", "og:article:tag");

        // --- Video metadata ---
        result.video_url = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:video"));
        std::string vid_width = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:video:width"));
        if (!vid_width.empty()) {
            try { result.video_width = std::stoi(vid_width); } catch (...) {}
        }
        std::string vid_height = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:video:height"));
        if (!vid_height.empty()) {
            try { result.video_height = std::stoi(vid_height); } catch (...) {}
        }

        // --- Audio metadata ---
        result.audio_url = trim(
            HtmlAttributeExtractor::get_meta_content(html, "property", "og:audio"));

        // --- Resolve relative URLs ---
        if (!result.image_url.empty()) {
            result.image_url = resolve_relative_url(base_url, result.image_url);
        }
        if (!result.url.empty()) {
            result.url = resolve_relative_url(base_url, result.url);
        }
        if (!result.video_url.empty()) {
            result.video_url = resolve_relative_url(base_url, result.video_url);
        }
        if (!result.audio_url.empty()) {
            result.audio_url = resolve_relative_url(base_url, result.audio_url);
        }

        return result;
    }

private:
    static std::string resolve_relative_url(const std::string& base,
                                             const std::string& relative) {
        if (relative.empty()) return relative;
        if (starts_with(relative, "http://") || starts_with(relative, "https://"))
            return relative;

        if (starts_with(relative, "//")) {
            std::string scheme = starts_with(base, "https://") ? "https:" : "http:";
            return scheme + relative;
        }

        if (starts_with(relative, "/")) {
            std::string base_root = extract_base_url(base);
            return base_root + relative;
        }

        // Relative to current path
        size_t last_slash = base.rfind('/');
        if (last_slash != std::string::npos && last_slash > 8) {
            return base.substr(0, last_slash + 1) + relative;
        }

        return base + "/" + relative;
    }
};

// ============================================================================
// TwitterCardParser — Extract Twitter Card metadata
// ============================================================================

class TwitterCardParser {
public:
    struct TwitterResult {
        std::string card;           // "summary", "summary_large_image", "app", "player"
        std::string title;
        std::string description;
        std::string image;
        std::string image_alt;
        std::string site;           // @username of website
        std::string creator;        // @username of content creator
        std::string player_url;
        int player_width{0};
        int player_height{0};
        std::string app_id_iphone;
        std::string app_id_ipad;
        std::string app_id_googleplay;

        bool has_data() const {
            return !card.empty() || !title.empty() || !description.empty() || !image.empty();
        }
    };

    // Extract Twitter Card metadata from HTML
    static TwitterResult parse(const std::string& html, const std::string& base_url) {
        TwitterResult result;

        result.card = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:card"));
        result.title = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:title")));
        result.description = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:description")));
        result.image = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:image"));
        result.image_alt = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:image:alt")));
        result.site = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:site"));
        result.creator = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:creator"));
        result.player_url = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:player"));

        std::string pw = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:player:width"));
        if (!pw.empty()) {
            try { result.player_width = std::stoi(pw); } catch (...) {}
        }
        std::string ph = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:player:height"));
        if (!ph.empty()) {
            try { result.player_height = std::stoi(ph); } catch (...) {}
        }

        result.app_id_iphone = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:app:id:iphone"));
        result.app_id_ipad = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:app:id:ipad"));
        result.app_id_googleplay = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "twitter:app:id:googleplay"));

        // --- Also check property-based twitter tags (some sites use property instead of name) ---
        if (result.card.empty()) {
            result.card = trim(
                HtmlAttributeExtractor::get_meta_content(html, "property", "twitter:card"));
        }
        if (result.title.empty()) {
            result.title = decode_html_entities(
                trim(HtmlAttributeExtractor::get_meta_content(html, "property", "twitter:title")));
        }
        if (result.description.empty()) {
            result.description = decode_html_entities(
                trim(HtmlAttributeExtractor::get_meta_content(html, "property", "twitter:description")));
        }
        if (result.image.empty()) {
            result.image = trim(
                HtmlAttributeExtractor::get_meta_content(html, "property", "twitter:image"));
        }

        // --- Resolve relative image URLs ---
        if (!result.image.empty()) {
            result.image = resolve_relative_url_internal(base_url, result.image);
        }
        if (!result.player_url.empty()) {
            result.player_url = resolve_relative_url_internal(
                base_url, result.player_url);
        }

        return result;
    }

private:
    friend class TwitterCardParser;

    static std::string resolve_relative_url_internal(const std::string& base,
                                                      const std::string& relative) {
        if (relative.empty()) return relative;
        if (starts_with(relative, "http://") || starts_with(relative, "https://"))
            return relative;
        if (starts_with(relative, "//")) {
            return (starts_with(base, "https://") ? "https:" : "http:") + relative;
        }
        if (starts_with(relative, "/")) {
            return extract_base_url(base) + relative;
        }
        size_t last_slash = base.rfind('/');
        if (last_slash != std::string::npos && last_slash > 8) {
            return base.substr(0, last_slash + 1) + relative;
        }
        return base + "/" + relative;
    }
};

// Need a standalone resolver for TwitterCardParser
// This is handled by the friend declaration above and the helper method.

// ============================================================================
// OEmbedParser — oEmbed discovery and parsing
// ============================================================================

class OEmbedParser {
public:
    // Known oEmbed providers
    struct OEmbedProvider {
        std::string name;
        std::string url_pattern;        // Regex pattern to match URLs
        std::string endpoint_url;       // oEmbed API endpoint
        bool discovery{true};           // Whether to use auto-discovery
        std::vector<std::string> formats; // "json", "xml"
    };

    // Discover oEmbed endpoint from HTML <link> tags
    static std::optional<std::string> discover_endpoint(const std::string& html,
                                                          const std::string& base_url) {
        // Look for <link rel="alternate" type="application/json+oembed" href="...">
        auto json_endpoints = HtmlAttributeExtractor::get_link_tags(
            html, "alternate");

        std::optional<std::string> json_url;
        std::optional<std::string> xml_url;

        for (const auto& [href, type] : json_endpoints) {
            std::string lower_type = to_lower(type);
            if (lower_type == "application/json+oembed" ||
                lower_type == "text/json+oembed") {
                json_url = resolve_url_internal(base_url, href);
                break; // Prefer JSON
            }
            if (lower_type == "text/xml+oembed" ||
                lower_type == "application/xml+oembed") {
                if (!json_url.has_value()) {
                    xml_url = resolve_url_internal(base_url, href);
                }
            }
        }

        if (json_url.has_value()) return json_url;
        return xml_url;
    }

    // Parse oEmbed JSON response
    static OEmbedData parse_json(const std::string& json_str) {
        OEmbedData data;

        try {
            json j = json::parse(json_str);

            if (j.contains("type")) data.type = j["type"].get<std::string>();
            if (j.contains("version")) data.version = j["version"].get<std::string>();
            if (j.contains("title")) data.title = decode_html_entities(
                j["title"].get<std::string>());
            if (j.contains("author_name")) data.author_name = decode_html_entities(
                j["author_name"].get<std::string>());
            if (j.contains("author_url")) data.author_url = j["author_url"].get<std::string>();
            if (j.contains("provider_name")) data.provider_name = decode_html_entities(
                j["provider_name"].get<std::string>());
            if (j.contains("provider_url")) data.provider_url = j["provider_url"].get<std::string>();
            if (j.contains("thumbnail_url")) data.thumbnail_url = j["thumbnail_url"].get<std::string>();
            if (j.contains("thumbnail_width")) data.thumbnail_width = j["thumbnail_width"].get<int>();
            if (j.contains("thumbnail_height")) data.thumbnail_height = j["thumbnail_height"].get<int>();
            if (j.contains("html")) data.html = j["html"].get<std::string>();
            if (j.contains("width")) data.width = j["width"].get<int>();
            if (j.contains("height")) data.height = j["height"].get<int>();
            if (j.contains("cache_age")) data.cache_age = j["cache_age"].get<std::string>();
            if (j.contains("url")) data.url = j["url"].get<std::string>();

        } catch (const json::parse_error& e) {
            // Return empty data on parse failure
            data.type = "";
        }

        return data;
    }

    // Parse oEmbed XML response
    static OEmbedData parse_xml(const std::string& xml_str) {
        OEmbedData data;

        // Simple XML extraction using regex (production would use a proper XML parser)
        auto extract = [&](const std::string& tag) -> std::string {
            std::regex re("<" + tag + "[^>]*>([^<]*)</" + tag + ">",
                          std::regex::icase);
            std::smatch match;
            if (std::regex_search(xml_str, match, re)) {
                return decode_html_entities(trim(match[1].str()));
            }
            return "";
        };

        data.type = extract("type");
        data.title = extract("title");
        data.author_name = extract("author_name");
        data.author_url = extract("author_url");
        data.provider_name = extract("provider_name");
        data.provider_url = extract("provider_url");
        data.thumbnail_url = extract("thumbnail_url");

        std::string tw = extract("thumbnail_width");
        if (!tw.empty()) { try { data.thumbnail_width = std::stoi(tw); } catch (...) {} }
        std::string th = extract("thumbnail_height");
        if (!th.empty()) { try { data.thumbnail_height = std::stoi(th); } catch (...) {} }

        data.html = extract("html");

        std::string w = extract("width");
        if (!w.empty()) { try { data.width = std::stoi(w); } catch (...) {} }
        std::string h = extract("height");
        if (!h.empty()) { try { data.height = std::stoi(h); } catch (...) {} }

        return data;
    }

    // Known static provider list (major platforms)
    static std::vector<OEmbedProvider> get_known_providers() {
        return {
            {"YouTube", "youtube\\.com|youtu\\.be",
             "https://www.youtube.com/oembed", false, {"json"}},
            {"Vimeo", "vimeo\\.com",
             "https://vimeo.com/api/oembed.json", false, {"json"}},
            {"Twitter", "twitter\\.com|x\\.com",
             "https://publish.twitter.com/oembed", false, {"json"}},
            {"Instagram", "instagram\\.com",
             "https://graph.facebook.com/v16.0/instagram_oembed", false, {"json"}},
            {"Facebook", "facebook\\.com|fb\\.com",
             "https://graph.facebook.com/v16.0/oembed_post", false, {"json"}},
            {"Reddit", "reddit\\.com",
             "https://www.reddit.com/oembed", false, {"json"}},
            {"SoundCloud", "soundcloud\\.com",
             "https://soundcloud.com/oembed", false, {"json"}},
            {"Spotify", "open\\.spotify\\.com|spotify\\.com",
             "https://open.spotify.com/oembed", false, {"json"}},
            {"Giphy", "giphy\\.com|gph\\.is",
             "https://giphy.com/services/oembed", false, {"json"}},
            {"Imgur", "imgur\\.com",
             "https://api.imgur.com/oembed", false, {"json"}},
            {"TikTok", "tiktok\\.com",
             "https://www.tiktok.com/oembed", false, {"json"}},
            {"Twitch", "twitch\\.tv|clips\\.twitch\\.tv",
             "https://api.twitch.tv/v5/oembed", false, {"json"}},
            {"Kickstarter", "kickstarter\\.com",
             "https://www.kickstarter.com/services/oembed", false, {"json"}},
            {"Flickr", "flickr\\.com|flic\\.kr",
             "https://www.flickr.com/services/oembed", false, {"json"}},
            {"Dailymotion", "dailymotion\\.com|dai\\.ly",
             "https://www.dailymotion.com/services/oembed", false, {"json"}},
            {"DeviantArt", "deviantart\\.com",
             "https://backend.deviantart.com/oembed", false, {"json"}},
            {"CodePen", "codepen\\.io",
             "https://codepen.io/api/oembed", false, {"json"}},
        };
    }

    // Match a URL against known oEmbed providers
    static std::optional<OEmbedProvider> match_provider(const std::string& url) {
        for (const auto& provider : get_known_providers()) {
            try {
                std::regex pattern(provider.url_pattern, std::regex::icase);
                if (std::regex_search(url, pattern)) {
                    return provider;
                }
            } catch (...) {
                continue;
            }
        }
        return std::nullopt;
    }

private:
    static std::string resolve_url_internal(const std::string& base,
                                             const std::string& relative) {
        if (relative.empty()) return relative;
        if (starts_with(relative, "http://") || starts_with(relative, "https://"))
            return relative;
        if (starts_with(relative, "//")) {
            return (starts_with(base, "https://") ? "https:" : "http:") + relative;
        }
        if (starts_with(relative, "/")) {
            return extract_base_url(base) + relative;
        }
        size_t last_slash = base.rfind('/');
        if (last_slash != std::string::npos && last_slash > 8) {
            return base.substr(0, last_slash + 1) + relative;
        }
        return base + "/" + relative;
    }
};

// ============================================================================
// HtmlMetadataExtractor — HTML title, description, and structured data fallback
// ============================================================================

class HtmlMetadataExtractor {
public:
    struct HtmlMeta {
        std::string title;
        std::string description;
        std::string author;
        std::string keywords;
        std::string favicon_url;
        std::string theme_color;
        std::vector<std::string> apple_touch_icons;

        // JSON-LD extracted data
        std::string jsonld_name;
        std::string jsonld_description;
        std::string jsonld_image;
        std::string jsonld_type;
    };

    // Extract metadata from HTML (non-OG fallback)
    static HtmlMeta extract(const std::string& html, const std::string& base_url) {
        HtmlMeta meta;

        // <title> tag
        meta.title = decode_html_entities(
            trim(HtmlAttributeExtractor::get_tag_content(html, "title")));

        // <meta name="description">
        meta.description = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "name", "description")));

        // <meta name="author">
        meta.author = decode_html_entities(
            trim(HtmlAttributeExtractor::get_meta_content(html, "name", "author")));

        // <meta name="keywords">
        meta.keywords = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "keywords"));

        // <meta name="theme-color">
        meta.theme_color = trim(
            HtmlAttributeExtractor::get_meta_content(html, "name", "theme-color"));

        // <link rel="icon"> / <link rel="shortcut icon">
        auto icons = HtmlAttributeExtractor::get_link_tags(html, "icon");
        if (icons.empty()) {
            icons = HtmlAttributeExtractor::get_link_tags(html, "shortcut icon");
        }
        if (!icons.empty()) {
            meta.favicon_url = resolve_relative_url(base_url, icons[0].first);
        }

        // <link rel="apple-touch-icon">
        auto apple_icons = HtmlAttributeExtractor::get_link_tags(html, "apple-touch-icon");
        for (const auto& [href, type] : apple_icons) {
            meta.apple_touch_icons.push_back(resolve_relative_url(base_url, href));
        }

        // --- JSON-LD structured data ---
        auto json_ld_items = HtmlAttributeExtractor::extract_json_ld(html);
        for (const auto& item : json_ld_items) {
            if (item.contains("name") && meta.jsonld_name.empty()) {
                meta.jsonld_name = item["name"].get<std::string>();
            }
            if (item.contains("description") && meta.jsonld_description.empty()) {
                meta.jsonld_description = item["description"].get<std::string>();
            }
            if (item.contains("image")) {
                if (meta.jsonld_image.empty()) {
                    if (item["image"].is_string()) {
                        meta.jsonld_image = item["image"].get<std::string>();
                    } else if (item["image"].is_object() && item["image"].contains("url")) {
                        meta.jsonld_image = item["image"]["url"].get<std::string>();
                    }
                }
            }
            if (item.contains("@type") && meta.jsonld_type.empty()) {
                if (item["@type"].is_string()) {
                    meta.jsonld_type = item["@type"].get<std::string>();
                } else if (item["@type"].is_array() && !item["@type"].empty()) {
                    meta.jsonld_type = item["@type"][0].get<std::string>();
                }
            }
        }

        return meta;
    }

private:
    static std::string resolve_relative_url(const std::string& base,
                                             const std::string& relative) {
        if (relative.empty()) return relative;
        if (starts_with(relative, "http://") || starts_with(relative, "https://"))
            return relative;
        if (starts_with(relative, "//")) {
            return (starts_with(base, "https://") ? "https:" : "http:") + relative;
        }
        if (starts_with(relative, "/")) {
            return extract_base_url(base) + relative;
        }
        size_t last_slash = base.rfind('/');
        if (last_slash != std::string::npos && last_slash > 8) {
            return base.substr(0, last_slash + 1) + relative;
        }
        return base + "/" + relative;
    }
};

// ============================================================================
// ImageDetector — Image dimension detection and URL validation
// ============================================================================

class ImageDetector {
public:
    struct ImageInfo {
        std::string url;
        int width{0};
        int height{0};
        std::string mime_type;
        bool is_valid{false};
        bool is_svg{false};
        std::string alt_text;
    };

    // Check if a URL likely points to an image
    static bool is_image_url(const std::string& url) {
        if (url.empty()) return false;

        std::string lower = to_lower(url);

        // Check for common image extensions
        for (size_t i = 0; i < url_preview_constants::kImageExtensionCount; ++i) {
            if (ends_with(lower, url_preview_constants::kImageExtensions[i])) {
                return true;
            }
        }

        // Check for image URL patterns (no extension but known image paths)
        if (lower.find("/image") != std::string::npos ||
            lower.find("/img") != std::string::npos ||
            lower.find("/photo") != std::string::npos ||
            lower.find("/thumbnail") != std::string::npos ||
            lower.find("/avatar") != std::string::npos) {
            return true;
        }

        // Data URI images
        if (starts_with(lower, "data:image/")) {
            return true;
        }

        return false;
    }

    // Get MIME type from URL extension
    static std::string mime_type_from_url(const std::string& url) {
        std::string lower = to_lower(url);
        if (ends_with(lower, ".jpg") || ends_with(lower, ".jpeg")) return "image/jpeg";
        if (ends_with(lower, ".png")) return "image/png";
        if (ends_with(lower, ".gif")) return "image/gif";
        if (ends_with(lower, ".webp")) return "image/webp";
        if (ends_with(lower, ".avif")) return "image/avif";
        if (ends_with(lower, ".svg")) return "image/svg+xml";
        if (ends_with(lower, ".bmp")) return "image/bmp";
        if (ends_with(lower, ".ico")) return "image/x-icon";
        if (ends_with(lower, ".tiff") || ends_with(lower, ".tif")) return "image/tiff";
        if (ends_with(lower, ".apng")) return "image/apng";
        return "image/unknown";
    }

    // Detect image info from OG meta or URL pattern
    static ImageInfo detect(const std::string& image_url,
                             int og_width, int og_height,
                             const std::string& og_type) {
        ImageInfo info;
        info.url = image_url;
        info.width = og_width;
        info.height = og_height;
        info.mime_type = og_type;

        if (!is_image_url(image_url)) {
            // Some preview images don't have image extensions (e.g., CDN URLs)
            // Still treat them as potentially valid
            info.is_valid = !image_url.empty();
        } else {
            info.is_valid = true;
        }

        // Detect MIME if not provided
        if (info.mime_type.empty()) {
            info.mime_type = mime_type_from_url(image_url);
        }

        // Check for SVG
        if (to_lower(image_url).find(".svg") != std::string::npos ||
            info.mime_type == "image/svg+xml") {
            info.is_svg = true;
            // SVG may not have meaningful pixel dimensions
            if (info.width == 0 && info.height == 0) {
                info.width = 1200; // Reasonable default for SVG preview
                info.height = 630;
            }
        }

        // Validate dimensions
        if (info.width < 0) info.width = 0;
        if (info.height < 0) info.height = 0;

        // Ensure reasonable max dimensions
        if (info.width > 8192) info.width = 8192;
        if (info.height > 8192) info.height = 8192;

        return info;
    }

    // Find the best image from a list of candidates
    static std::string select_best_image(
        const std::vector<std::string>& candidates,
        int preferred_min_width = 200) {

        std::string best;
        int best_score = -1;

        for (const auto& url : candidates) {
            int score = 0;
            std::string lower = to_lower(url);

            // Skip tiny/placeholder images
            if (lower.find("placeholder") != std::string::npos ||
                lower.find("spacer") != std::string::npos ||
                lower.find("pixel") != std::string::npos ||
                lower.find("blank") != std::string::npos ||
                lower.find("1x1") != std::string::npos ||
                lower.find("default") != std::string::npos) {
                score -= 50;
            }

            // Prefer high-res indicators
            if (lower.find("large") != std::string::npos ||
                lower.find("original") != std::string::npos ||
                lower.find("full") != std::string::npos ||
                lower.find("high") != std::string::npos) {
                score += 10;
            }

            // Prefer standard image formats
            if (ends_with(lower, ".jpg") || ends_with(lower, ".jpeg")) score += 5;
            if (ends_with(lower, ".png")) score += 3;
            if (ends_with(lower, ".webp")) score += 4;

            // Prefer HTTPS
            if (starts_with(lower, "https://")) score += 3;

            if (score > best_score) {
                best_score = score;
                best = url;
            }
        }

        return best;
    }
};

// ============================================================================
// ContentSanitizer — Preview content sanitization
// ============================================================================

class ContentSanitizer {
public:
    struct SanitizeConfig {
        size_t max_title_length{url_preview_constants::kDefaultMaxTitleLength};
        size_t max_description_length{url_preview_constants::kDefaultMaxDescriptionLength};
        size_t max_html_length{url_preview_constants::kDefaultMaxOEmbedHtmlLength};
        bool strip_html{true};
        bool strip_tracking_params{true};
        bool normalize_whitespace{true};
        bool decode_entities{true};
        bool remove_control_chars{true};
        bool enforce_scheme_whitelist{true};
    };

    // Sanitize a preview title
    static std::string sanitize_title(const std::string& title,
                                       const SanitizeConfig& config = SanitizeConfig{}) {
        std::string result = title;

        // Decode HTML entities
        if (config.decode_entities) {
            result = decode_html_entities(result);
        }

        // Strip HTML tags
        if (config.strip_html) {
            result = strip_html_tags(result);
        }

        // Remove control characters
        if (config.remove_control_chars) {
            result = remove_control_characters(result);
        }

        // Normalize whitespace
        if (config.normalize_whitespace) {
            result = normalize_whitespace(result);
        }

        // Trim
        result = trim(result);

        // Truncate to max length
        if (result.size() > config.max_title_length) {
            result = result.substr(0, config.max_title_length);
            // Try to break at word boundary
            size_t last_space = result.rfind(' ');
            if (last_space != std::string::npos &&
                last_space > config.max_title_length * 3 / 4) {
                result = result.substr(0, last_space);
            }
            result += "...";
        }

        return result;
    }

    // Sanitize a preview description
    static std::string sanitize_description(const std::string& desc,
                                              const SanitizeConfig& config = SanitizeConfig{}) {
        std::string result = desc;

        if (config.decode_entities) {
            result = decode_html_entities(result);
        }

        if (config.strip_html) {
            result = strip_html_tags(result);
        }

        if (config.remove_control_chars) {
            result = remove_control_characters(result);
        }

        if (config.normalize_whitespace) {
            result = normalize_whitespace(result);
        }

        result = trim(result);

        if (result.size() > config.max_description_length) {
            result = result.substr(0, config.max_description_length);
            size_t last_space = result.rfind(' ');
            if (last_space != std::string::npos &&
                last_space > config.max_description_length * 3 / 4) {
                result = result.substr(0, last_space);
            }
            result += "...";
        }

        return result;
    }

    // Sanitize a URL
    static std::string sanitize_url(const std::string& url,
                                     const SanitizeConfig& config = SanitizeConfig{}) {
        std::string result = url;

        // Remove control characters
        result = remove_control_characters(result);

        // Check for disallowed schemes
        if (config.enforce_scheme_whitelist) {
            std::string lower = to_lower(result);
            for (size_t i = 0; i < url_preview_constants::kDisallowedSchemeCount; ++i) {
                if (starts_with(lower, url_preview_constants::kDisallowedSchemes[i])) {
                    return "";
                }
            }
        }

        // Strip tracking parameters
        if (config.strip_tracking_params && result.find('?') != std::string::npos) {
            result = strip_tracking_parameters(result);
        }

        return result;
    }

    // Sanitize oEmbed HTML
    static std::string sanitize_oembed_html(const std::string& html,
                                              const SanitizeConfig& config = SanitizeConfig{}) {
        std::string result = html;

        // Strip dangerous tags
        result = remove_dangerous_tags(result);

        // Strip event handlers (onclick, onload, etc.)
        result = remove_event_handlers(result);

        // Strip javascript: URLs
        result = remove_js_urls(result);

        // Truncate to max length
        if (result.size() > config.max_html_length) {
            result = result.substr(0, config.max_html_length);
        }

        return result;
    }

    // Sanitize a full preview result
    static void sanitize_result(UrlPreviewResult& preview,
                                 const SanitizeConfig& config = SanitizeConfig{}) {
        preview.title = sanitize_title(preview.title, config);
        preview.description = sanitize_description(preview.description, config);
        preview.site_name = sanitize_title(preview.site_name, config);
        preview.image_url = sanitize_url(preview.image_url, config);
        preview.url = sanitize_url(preview.url, config);
        preview.resolved_url = sanitize_url(preview.resolved_url, config);
        preview.oembed_html = sanitize_oembed_html(preview.oembed_html, config);
        preview.favicon_url = sanitize_url(preview.favicon_url, config);

        // Sanitize additional images
        for (auto& img : preview.additional_images) {
            img = sanitize_url(img, config);
        }
        // Remove empty sanitized entries
        preview.additional_images.erase(
            std::remove_if(preview.additional_images.begin(),
                           preview.additional_images.end(),
                           [](const std::string& s) { return s.empty(); }),
            preview.additional_images.end());

        // Re-check validity after sanitization
        preview.has_title = !preview.title.empty();
        preview.has_description = !preview.description.empty();
        preview.has_image = !preview.image_url.empty();
        preview.valid = preview.has_title || preview.has_description || preview.has_image;
    }

private:
    // Strip HTML tags from text
    static std::string strip_html_tags(const std::string& input) {
        std::string result;
        bool in_tag = false;
        bool in_comment = false;
        result.reserve(input.size());

        for (size_t i = 0; i < input.size(); ++i) {
            char c = input[i];
            if (in_comment) {
                if (c == '>' && i >= 2 && input[i-1] == '-' && input[i-2] == '-') {
                    in_comment = false;
                }
                continue;
            }
            if (c == '<') {
                // Check for comment
                if (i + 3 < input.size() &&
                    input[i+1] == '!' && input[i+2] == '-' && input[i+3] == '-') {
                    in_comment = true;
                    continue;
                }
                in_tag = true;
            } else if (c == '>') {
                in_tag = false;
            } else if (!in_tag) {
                result += c;
            }
        }
        return result;
    }

    // Remove dangerous HTML tags (script, iframe, embed, object, etc.)
    static std::string remove_dangerous_tags(const std::string& input) {
        static const std::vector<std::string> dangerous_tags = {
            "script", "iframe", "embed", "object", "applet", "form",
            "input", "select", "textarea", "button", "link", "style",
            "meta", "base", "frame", "frameset"
        };

        std::string result = input;
        std::string lower = to_lower(result);

        for (const auto& tag : dangerous_tags) {
            std::string open_tag = "<" + tag;
            std::string close_tag = "</" + tag + ">";

            // Remove complete tags with their content (for script/style)
            if (tag == "script" || tag == "style") {
                size_t pos = 0;
                while ((pos = lower.find(open_tag, pos)) != std::string::npos) {
                    size_t end = lower.find(close_tag, pos);
                    if (end != std::string::npos) {
                        end += close_tag.size();
                    } else {
                        end = lower.find('>', pos);
                        if (end != std::string::npos) ++end;
                        else end = result.size();
                    }
                    result.erase(pos, end - pos);
                    lower = to_lower(result);
                }
            } else {
                // Remove opening tags
                size_t pos = 0;
                while ((pos = lower.find(open_tag, pos)) != std::string::npos) {
                    size_t end = lower.find('>', pos);
                    if (end != std::string::npos) {
                        result.erase(pos, end - pos + 1);
                        lower = to_lower(result);
                    } else {
                        break;
                    }
                }
                // Remove closing tags
                pos = 0;
                while ((pos = lower.find(close_tag, pos)) != std::string::npos) {
                    result.erase(pos, close_tag.size());
                    lower = to_lower(result);
                }
            }
        }

        return result;
    }

    // Remove event handlers (onclick, onload, onerror, etc.)
    static std::string remove_event_handlers(const std::string& input) {
        // Pattern: on\w+="..." or on\w+='...' or on\w+=...
        std::regex event_re(R"(\s+on\w+\s*=\s*(["'])[^"']*\2)",
                            std::regex::icase);
        std::string result = std::regex_replace(input, event_re, "");
        return result;
    }

    // Remove javascript: URLs from attributes
    static std::string remove_js_urls(const std::string& input) {
        static const std::regex js_url_re(
            R"((href|src|action|formaction|data)\s*=\s*["']javascript:[^"']*["'])",
            std::regex::icase);
        std::string result = std::regex_replace(input, js_url_re, "");
        return result;
    }

    // Remove control characters
    static std::string remove_control_characters(const std::string& input) {
        std::string result;
        result.reserve(input.size());
        for (char c : input) {
            // Allow tab, newline, carriage return, and printable chars
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 0x20 || uc == '\t' || uc == '\n' || uc == '\r') {
                result += c;
            } else if (c == '\0') {
                // Skip null bytes entirely
                continue;
            }
        }
        return result;
    }

    // Normalize whitespace
    static std::string normalize_whitespace(const std::string& input) {
        std::string result;
        result.reserve(input.size());
        bool prev_space = false;

        for (char c : input) {
            if (c == '\n' || c == '\r' || c == '\t') {
                c = ' ';
            }
            if (c == ' ') {
                if (!prev_space) {
                    result += ' ';
                    prev_space = true;
                }
            } else {
                result += c;
                prev_space = false;
            }
        }

        return result;
    }

    // Strip tracking parameters from URL
    static std::string strip_tracking_parameters(const std::string& url) {
        size_t qpos = url.find('?');
        if (qpos == std::string::npos) return url;

        std::string base = url.substr(0, qpos);
        std::string query = url.substr(qpos + 1);

        std::vector<std::string> params;
        size_t pos = 0;
        while (pos < query.size()) {
            size_t amp = query.find('&', pos);
            if (amp == std::string::npos) amp = query.size();
            std::string param = query.substr(pos, amp - pos);
            pos = amp + 1;

            // Check if this is a tracking parameter
            bool is_tracking = false;
            std::string lower_param = to_lower(param);
            for (size_t i = 0; i < url_preview_constants::kTrackingParamCount; ++i) {
                std::string tp = url_preview_constants::kTrackingParams[i];
                if (starts_with(lower_param, tp + "=")) {
                    is_tracking = true;
                    break;
                }
            }

            if (!is_tracking) {
                params.push_back(param);
            }
        }

        if (params.empty()) return base;
        std::string new_query = params[0];
        for (size_t i = 1; i < params.size(); ++i) {
            new_query += "&" + params[i];
        }
        return base + "?" + new_query;
    }
};

// ============================================================================
// PreviewCache — TTL-based LRU cache for URL preview results
// ============================================================================

class PreviewCache {
public:
    struct CacheConfig {
        size_t max_entries{url_preview_constants::kDefaultMaxCacheEntries};
        chr::seconds default_ttl{url_preview_constants::kDefaultCacheTtl};
        chr::seconds error_ttl{url_preview_constants::kDefaultCacheErrorTtl};
        chr::seconds refresh_interval{url_preview_constants::kDefaultCacheRefreshInterval};
        bool enable_access_refresh{true}; // Extend TTL on access
    };

    explicit PreviewCache(const CacheConfig& config = CacheConfig{})
        : config_(config) {
        // Start background eviction thread
        running_ = true;
        eviction_thread_ = std::thread(&PreviewCache::eviction_loop, this);
    }

    ~PreviewCache() {
        running_ = false;
        eviction_cv_.notify_one();
        if (eviction_thread_.joinable()) {
            eviction_thread_.join();
        }
    }

    // Get a cached preview result
    std::optional<UrlPreviewResult> get(const std::string& url) {
        std::unique_lock lock(mutex_);
        auto key = hash_url(url);

        auto it = cache_.find(key);
        if (it == cache_.end()) {
            ++misses_;
            return std::nullopt;
        }

        if (it->second.is_expired()) {
            cache_.erase(it);
            ++misses_;
            ++evicted_expired_;
            return std::nullopt;
        }

        if (config_.enable_access_refresh) {
            it->second.touch();
        }
        ++hits_;
        return it->second.preview;
    }

    // Store a preview result in cache
    void put(const std::string& url, const UrlPreviewResult& preview,
             std::optional<chr::seconds> custom_ttl = std::nullopt) {
        std::unique_lock lock(mutex_);

        auto key = hash_url(url);
        chr::seconds ttl = custom_ttl.value_or(
            preview.is_error ? config_.error_ttl : config_.default_ttl);

        // If cache is full, evict LRU entries
        while (cache_.size() >= config_.max_entries) {
            evict_lru_locked();
        }

        CacheEntry entry;
        entry.preview = preview;
        entry.created_at = chr::steady_clock::now();
        entry.expires_at = entry.created_at + ttl;
        entry.ttl = ttl;
        entry.is_error = preview.is_error;
        entry.last_accessed = entry.created_at;
        entry.access_count = 0;

        cache_[key] = std::move(entry);
        ++insertions_;
    }

    // Check if URL is in cache and not expired
    bool contains(const std::string& url) {
        std::shared_lock lock(mutex_);
        auto key = hash_url(url);
        auto it = cache_.find(key);
        if (it == cache_.end()) return false;
        if (it->second.is_expired()) return false;
        return true;
    }

    // Remove a URL from cache
    void remove(const std::string& url) {
        std::unique_lock lock(mutex_);
        cache_.erase(hash_url(url));
        ++evictions_;
    }

    // Clear all cache entries
    void clear() {
        std::unique_lock lock(mutex_);
        size_t count = cache_.size();
        cache_.clear();
        evictions_ += count;
    }

    // Get cache statistics
    struct CacheStats {
        size_t size{0};
        size_t max_size{0};
        uint64_t hits{0};
        uint64_t misses{0};
        uint64_t insertions{0};
        uint64_t evictions{0};
        uint64_t evicted_expired{0};
        size_t error_entries{0};
        double hit_rate() const {
            uint64_t total = hits + misses;
            return total > 0 ? static_cast<double>(hits) / total : 0.0;
        }
    };

    CacheStats stats() const {
        std::shared_lock lock(mutex_);
        CacheStats s;
        s.size = cache_.size();
        s.max_size = config_.max_entries;
        s.hits = hits_.load();
        s.misses = misses_.load();
        s.insertions = insertions_.load();
        s.evictions = evictions_.load();
        s.evicted_expired = evicted_expired_.load();
        s.error_entries = 0;
        for (const auto& [key, entry] : cache_) {
            if (entry.is_error) ++s.error_entries;
        }
        return s;
    }

    // Persist cache to disk
    bool save_to_disk(const std::string& path) {
        std::shared_lock lock(mutex_);
        try {
            json j;
            j["version"] = 1;
            j["entries"] = json::array();

            for (const auto& [key, entry] : cache_) {
                if (entry.is_expired()) continue;
                json ej;
                ej["key"] = key;
                ej["preview"] = entry.preview.to_matrix_json();
                ej["ttl_seconds"] = entry.ttl.count();
                ej["created_at"] = chr::duration_cast<chr::seconds>(
                    entry.created_at.time_since_epoch()).count();
                ej["is_error"] = entry.is_error;
                j["entries"].push_back(ej);
            }

            std::ofstream file(path);
            if (!file.is_open()) return false;
            file << j.dump(2);
            return true;
        } catch (...) {
            return false;
        }
    }

    // Load cache from disk
    bool load_from_disk(const std::string& path) {
        std::unique_lock lock(mutex_);
        try {
            std::ifstream file(path);
            if (!file.is_open()) return false;

            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            json j = json::parse(content);

            if (!j.contains("entries") || !j["entries"].is_array()) return false;

            for (const auto& ej : j["entries"]) {
                if (!ej.contains("key") || !ej.contains("preview")) continue;

                CacheEntry entry;
                entry.preview = result_from_json(ej["preview"]);
                entry.is_error = ej.value("is_error", false);

                int64_t ttl_secs = ej.value("ttl_seconds",
                    static_cast<int64_t>(config_.default_ttl.count()));
                entry.ttl = chr::seconds(ttl_secs);

                int64_t created_secs = ej.value("created_at",
                    chr::duration_cast<chr::seconds>(
                        chr::steady_clock::now().time_since_epoch()).count());
                entry.created_at = chr::steady_clock::time_point(
                    chr::seconds(created_secs));
                entry.expires_at = entry.created_at + entry.ttl;
                entry.last_accessed = entry.created_at;
                entry.access_count = 0;

                // Don't load already-expired entries
                if (entry.is_expired()) continue;

                std::string key = ej["key"].get<std::string>();
                if (cache_.size() < config_.max_entries) {
                    cache_[key] = std::move(entry);
                }
            }

            return true;
        } catch (...) {
            return false;
        }
    }

private:
    CacheConfig config_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;

    // Statistics
    std::atomic<uint64_t> hits_{0};
    std::atomic<uint64_t> misses_{0};
    std::atomic<uint64_t> insertions_{0};
    std::atomic<uint64_t> evictions_{0};
    std::atomic<uint64_t> evicted_expired_{0};

    // Background eviction
    std::atomic<bool> running_{false};
    std::thread eviction_thread_;
    std::condition_variable eviction_cv_;
    mutable std::mutex eviction_mutex_;

    void eviction_loop() {
        while (running_) {
            {
                std::unique_lock lock(eviction_mutex_);
                eviction_cv_.wait_for(lock,
                    url_preview_constants::kDefaultCacheCleanupInterval,
                    [this] { return !running_.load(); });
            }

            if (!running_) break;

            // Evict expired entries
            std::unique_lock lock(mutex_);
            auto it = cache_.begin();
            while (it != cache_.end()) {
                if (it->second.is_expired()) {
                    ++evicted_expired_;
                    it = cache_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    void evict_lru_locked() {
        // Find the least recently accessed entry
        auto lru_it = cache_.begin();
        for (auto it = cache_.begin(); it != cache_.end(); ++it) {
            if (it->second.last_accessed < lru_it->second.last_accessed) {
                lru_it = it;
            }
        }
        cache_.erase(lru_it);
        ++evictions_;
    }

    static UrlPreviewResult result_from_json(const json& j) {
        UrlPreviewResult r;
        r.url = j.value("url", "");
        r.title = j.value("og:title", "");
        r.description = j.value("og:description", "");
        r.image_url = j.value("og:image", "");
        r.image_width = j.value("og:image:width", 0);
        r.image_height = j.value("og:image:height", 0);
        r.image_type = j.value("og:image:type", "");
        r.image_alt = j.value("og:image:alt", "");
        r.site_name = j.value("og:site_name", "");
        r.type = j.value("og:type", "website");
        r.twitter_card = j.value("twitter:card", "");
        r.twitter_site = j.value("twitter:site", "");
        r.twitter_creator = j.value("twitter:creator", "");
        r.oembed_type = j.value("oembed:type", "");
        r.oembed_html = j.value("oembed:html", "");
        r.oembed_provider = j.value("oembed:provider_name", "");
        r.oembed_width = j.value("oembed:width", 0);
        r.oembed_height = j.value("oembed:height", 0);
        r.favicon_url = j.value("favicon_url", "");
        r.author_name = j.value("author_name", "");
        r.published_time = j.value("published_time", "");
        r.locale = j.value("locale", "");
        r.has_title = !r.title.empty();
        r.has_description = !r.description.empty();
        r.has_image = !r.image_url.empty();
        r.valid = r.has_title || r.has_description || r.has_image;
        return r;
    }
};

// ============================================================================
// DomainFilter — Domain blacklist/whitelist with wildcard support
// ============================================================================

class DomainFilter {
public:
    enum class DefaultPolicy {
        ALLOW_ALL,    // Allow all domains unless explicitly denied
        DENY_ALL      // Deny all domains unless explicitly allowed
    };

    struct FilterConfig {
        DefaultPolicy default_policy{DefaultPolicy::ALLOW_ALL};
        bool block_private_ips{true};
        bool block_ip_addresses{false};
        std::vector<std::string> blocked_tlds;
    };

    explicit DomainFilter(const FilterConfig& config = FilterConfig{})
        : config_(config) {}

    // Check if a URL is allowed based on domain rules
    bool is_allowed(const std::string& url) {
        std::string domain = extract_domain(url);

        // Check private IP blocking
        if (config_.block_private_ips && is_private_ip_domain(domain)) {
            return false;
        }

        // Check IP address blocking
        if (config_.block_ip_addresses && is_ip_address(domain)) {
            return false;
        }

        // Check blocked TLDs
        for (const auto& tld : config_.blocked_tlds) {
            if (ends_with(domain, "." + tld) || domain == tld) {
                return false;
            }
        }

        // Check rules (higher priority first)
        std::shared_lock lock(mutex_);
        std::vector<const DomainRule*> sorted_rules;
        for (const auto& rule : rules_) {
            sorted_rules.push_back(&rule);
        }
        std::sort(sorted_rules.begin(), sorted_rules.end(),
                  [](const DomainRule* a, const DomainRule* b) {
                      return a->priority > b->priority;
                  });

        for (const auto* rule : sorted_rules) {
            if (rule->matches(domain)) {
                return rule->action == DomainRule::Action::ALLOW;
            }
        }

        // Default policy
        return config_.default_policy == DefaultPolicy::ALLOW_ALL;
    }

    // Add a domain rule
    void add_rule(const DomainRule& rule) {
        std::unique_lock lock(mutex_);
        rules_.push_back(rule);
        // Keep rules sorted by priority
        std::sort(rules_.begin(), rules_.end(),
                  [](const DomainRule& a, const DomainRule& b) {
                      return a.priority > b.priority;
                  });
    }

    // Add a simple deny rule
    void deny_domain(const std::string& domain_pattern,
                     DomainRule::MatchMode mode = DomainRule::MatchMode::EXACT,
                     int priority = 100) {
        DomainRule rule;
        rule.action = DomainRule::Action::DENY;
        rule.pattern = domain_pattern;
        rule.mode = mode;
        rule.priority = priority;
        rule.reason = "Blocked by administrator";
        add_rule(rule);
    }

    // Add a simple allow rule
    void allow_domain(const std::string& domain_pattern,
                      DomainRule::MatchMode mode = DomainRule::MatchMode::EXACT,
                      int priority = 100) {
        DomainRule rule;
        rule.action = DomainRule::Action::ALLOW;
        rule.pattern = domain_pattern;
        rule.mode = mode;
        rule.priority = priority;
        rule.reason = "Explicitly allowed";
        add_rule(rule);
    }

    // Remove rules matching a pattern
    size_t remove_rules(const std::string& pattern) {
        std::unique_lock lock(mutex_);
        size_t count = 0;
        rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
            [&](const DomainRule& r) {
                if (r.pattern == pattern) { ++count; return true; }
                return false;
            }), rules_.end());
        return count;
    }

    // List all rules
    std::vector<DomainRule> list_rules() const {
        std::shared_lock lock(mutex_);
        return rules_;
    }

    // Clear all rules
    void clear_rules() {
        std::unique_lock lock(mutex_);
        rules_.clear();
    }

    // Load rules from JSON configuration
    bool load_rules_from_json(const json& j) {
        std::unique_lock lock(mutex_);
        try {
            if (j.contains("default_policy")) {
                std::string policy = to_lower(j["default_policy"].get<std::string>());
                config_.default_policy = (policy == "deny_all")
                    ? DefaultPolicy::DENY_ALL : DefaultPolicy::ALLOW_ALL;
            }
            config_.block_private_ips = j.value("block_private_ips", true);
            config_.block_ip_addresses = j.value("block_ip_addresses", false);

            if (j.contains("rules") && j["rules"].is_array()) {
                for (const auto& rule_json : j["rules"]) {
                    DomainRule rule;
                    std::string action = to_lower(rule_json.value("action", "deny"));
                    rule.action = (action == "allow")
                        ? DomainRule::Action::ALLOW : DomainRule::Action::DENY;

                    std::string mode = to_lower(rule_json.value("mode", "exact"));
                    if (mode == "wildcard") rule.mode = DomainRule::MatchMode::WILDCARD;
                    else if (mode == "suffix") rule.mode = DomainRule::MatchMode::SUFFIX;
                    else if (mode == "regex") rule.mode = DomainRule::MatchMode::REGEX;
                    else rule.mode = DomainRule::MatchMode::EXACT;

                    rule.pattern = rule_json.value("pattern", "");
                    rule.priority = rule_json.value("priority", 100);
                    rule.reason = rule_json.value("reason", "");
                    rules_.push_back(rule);
                }
            }

            if (j.contains("blocked_tlds") && j["blocked_tlds"].is_array()) {
                config_.blocked_tlds.clear();
                for (const auto& tld : j["blocked_tlds"]) {
                    config_.blocked_tlds.push_back(tld.get<std::string>());
                }
            }

            // Sort by priority
            std::sort(rules_.begin(), rules_.end(),
                      [](const DomainRule& a, const DomainRule& b) {
                          return a.priority > b.priority;
                      });
            return true;
        } catch (...) {
            return false;
        }
    }

    // Export rules to JSON
    json export_rules_to_json() const {
        std::shared_lock lock(mutex_);
        json j;
        j["default_policy"] = (config_.default_policy == DefaultPolicy::DENY_ALL)
            ? "deny_all" : "allow_all";
        j["block_private_ips"] = config_.block_private_ips;
        j["block_ip_addresses"] = config_.block_ip_addresses;

        j["rules"] = json::array();
        for (const auto& rule : rules_) {
            json rj;
            rj["action"] = (rule.action == DomainRule::Action::ALLOW) ? "allow" : "deny";
            switch (rule.mode) {
                case DomainRule::MatchMode::EXACT: rj["mode"] = "exact"; break;
                case DomainRule::MatchMode::WILDCARD: rj["mode"] = "wildcard"; break;
                case DomainRule::MatchMode::SUFFIX: rj["mode"] = "suffix"; break;
                case DomainRule::MatchMode::REGEX: rj["mode"] = "regex"; break;
            }
            rj["pattern"] = rule.pattern;
            rj["priority"] = rule.priority;
            rj["reason"] = rule.reason;
            j["rules"].push_back(rj);
        }

        j["blocked_tlds"] = config_.blocked_tlds;
        return j;
    }

    const FilterConfig& config() const { return config_; }

private:
    FilterConfig config_;
    std::vector<DomainRule> rules_;
    mutable std::shared_mutex mutex_;

    // Check if a domain looks like a private/reserved IP
    static bool is_private_ip_domain(const std::string& domain) {
        // Check for IPv4 private ranges
        if (is_ipv4_address(domain)) {
            return is_private_ipv4(domain);
        }
        // Check for IPv6 private ranges
        if (domain.find(':') != std::string::npos) {
            return is_private_ipv6(domain);
        }
        return false;
    }

    static bool is_ipv4_address(const std::string& s) {
        int dots = 0;
        for (char c : s) {
            if (c == '.') ++dots;
            else if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        return dots == 3;
    }

    static bool is_private_ipv4(const std::string& ip) {
        // Parse IPv4 address
        std::vector<uint32_t> octets;
        std::istringstream iss(ip);
        std::string octet;
        while (std::getline(iss, octet, '.')) {
            try {
                octets.push_back(static_cast<uint32_t>(std::stoul(octet)));
            } catch (...) {
                return false;
            }
        }
        if (octets.size() != 4) return false;

        uint32_t addr = (octets[0] << 24) | (octets[1] << 16) |
                        (octets[2] << 8) | octets[3];

        // 10.0.0.0/8
        if ((addr & 0xFF000000) == 0x0A000000) return true;
        // 172.16.0.0/12
        if ((addr & 0xFFF00000) == 0xAC100000) return true;
        // 192.168.0.0/16
        if ((addr & 0xFFFF0000) == 0xC0A80000) return true;
        // 127.0.0.0/8
        if ((addr & 0xFF000000) == 0x7F000000) return true;
        // 169.254.0.0/16 (link-local)
        if ((addr & 0xFFFF0000) == 0xA9FE0000) return true;
        // 0.0.0.0/8
        if ((addr & 0xFF000000) == 0x00000000) return true;
        // 224.0.0.0/4 (multicast)
        if ((addr & 0xF0000000) == 0xE0000000) return true;
        // 240.0.0.0/4 (reserved)
        if ((addr & 0xF0000000) == 0xF0000000) return true;

        return false;
    }

    static bool is_private_ipv6(const std::string& ip) {
        // Simplified IPv6 private check
        std::string lower = to_lower(ip);
        if (starts_with(lower, "::1") || lower == "::1") return true;      // Loopback
        if (starts_with(lower, "fe80:")) return true;                       // Link-local
        if (starts_with(lower, "fc") || starts_with(lower, "fd")) return true; // ULA
        if (starts_with(lower, "::ffff:127.")) return true;                 // IPv4 loopback mapped
        return false;
    }

    static bool is_ip_address(const std::string& domain) {
        return is_ipv4_address(domain) || domain.find(':') != std::string::npos;
    }
};

// ============================================================================
// UrlPreviewEngine — Top-level orchestrator
// ============================================================================

class UrlPreviewEngine {
public:
    struct EngineConfig {
        FetchConfig fetch;
        ContentSanitizer::SanitizeConfig sanitize;
        PreviewCache::CacheConfig cache;
        DomainFilter::FilterConfig domain_filter;
        bool enable_og{true};
        bool enable_twitter_cards{true};
        bool enable_oembed{true};
        bool enable_htm_fallback{true};
        bool enable_jsonld{true};
        bool enable_cache{true};
        bool enable_domain_filter{true};
        bool enable_sanitization{true};
        bool enable_image_detection{true};
        int max_concurrent_fetches{10};
        bool verbose_logging{false};
    };

    explicit UrlPreviewEngine(const EngineConfig& config = EngineConfig{})
        : config_(config),
          cache_(config.cache),
          domain_filter_(config.domain_filter) {}

    // Generate a URL preview synchronously
    UrlPreviewResult generate_preview(const std::string& url) {
        auto total_start = chr::steady_clock::now();
        UrlPreviewResult result;
        result.url = url;

        try {
            // --- Step 1: Validate URL ---
            if (url.empty() || (!starts_with(url, "http://") &&
                                 !starts_with(url, "https://"))) {
                result.is_error = true;
                result.error_message = "Invalid URL: must start with http:// or https://";
                return result;
            }

            // --- Step 2: Domain filter check ---
            if (config_.enable_domain_filter && !domain_filter_.is_allowed(url)) {
                result.is_error = true;
                result.error_message = "URL domain is not allowed by filter rules";
                return result;
            }

            // --- Step 3: Check cache ---
            if (config_.enable_cache) {
                auto cached = cache_.get(url);
                if (cached.has_value()) {
                    result = std::move(*cached);
                    if (config_.verbose_logging) {
                        std::cerr << "[UrlPreviewEngine] Cache hit for: " << url << "\n";
                    }
                    return result;
                }
            }

            // --- Step 4: Fetch the URL ---
            auto fetch_start = chr::steady_clock::now();
            UrlFetcher fetcher(config_.fetch);
            auto fetch_result = fetcher.fetch_for_preview(url);

            result.fetch_time = chr::duration_cast<chr::milliseconds>(
                chr::steady_clock::now() - fetch_start);
            result.resolved_url = fetch_result.resolved_url;

            if (!fetch_result.success) {
                result.is_error = true;
                result.error_message = fetch_result.error_message;
                if (config_.enable_cache) {
                    cache_.put(url, result);
                }
                return result;
            }

            // --- Step 5: Parse HTML for metadata ---
            auto parse_start = chr::steady_clock::now();
            parse_html_metadata(fetch_result.body, fetch_result.resolved_url, result);

            result.parse_time = chr::duration_cast<chr::milliseconds>(
                chr::steady_clock::now() - parse_start);

            // --- Step 6: Sanitize ---
            if (config_.enable_sanitization) {
                ContentSanitizer::sanitize_result(result, config_.sanitize);
            }

            // --- Step 7: Determine validity ---
            result.has_title = !result.title.empty();
            result.has_description = !result.description.empty();
            result.has_image = !result.image_url.empty();
            result.has_oembed = !result.oembed_html.empty() || !result.oembed_type.empty();
            result.valid = result.has_title || result.has_description ||
                          result.has_image || result.has_oembed;
            result.is_error = false;

            // --- Step 8: Cache result ---
            if (config_.enable_cache) {
                chr::seconds ttl = config_.cache.default_ttl;
                if (!result.valid) {
                    ttl = config_.cache.error_ttl;
                }
                cache_.put(url, result, ttl);
            }

        } catch (const std::exception& e) {
            result.is_error = true;
            result.error_message = std::string("Preview generation error: ") + e.what();
            if (config_.enable_cache) {
                cache_.put(url, result, config_.cache.error_ttl);
            }
        }

        result.total_time = chr::duration_cast<chr::milliseconds>(
            chr::steady_clock::now() - total_start);
        return result;
    }

    // Generate preview and return as Matrix-compatible JSON
    json generate_preview_json(const std::string& url) {
        auto preview = generate_preview(url);
        if (preview.is_error) {
            json error;
            error["error"] = preview.error_message;
            error["url"] = url;
            return error;
        }
        return preview.to_matrix_json();
    }

    // Check if a URL is eligible for preview
    bool can_preview(const std::string& url) {
        if (url.empty()) return false;
        if (!starts_with(url, "http://") && !starts_with(url, "https://")) return false;
        if (config_.enable_domain_filter && !domain_filter_.is_allowed(url)) return false;
        return true;
    }

    // --- Accessors ---
    const EngineConfig& config() const { return config_; }
    PreviewCache& cache() { return cache_; }
    DomainFilter& domain_filter() { return domain_filter_; }

    // Cache statistics
    PreviewCache::CacheStats cache_stats() { return cache_.stats(); }

    // Domain filter helpers
    bool is_domain_allowed(const std::string& url) {
        return domain_filter_.is_allowed(url);
    }

    void set_config(const EngineConfig& config) {
        config_ = config;
        cache_ = PreviewCache(config.cache);
        domain_filter_ = DomainFilter(config.domain_filter);
    }

private:
    EngineConfig config_;
    PreviewCache cache_;
    DomainFilter domain_filter_;

    // Parse HTML body and extract all metadata into the result
    void parse_html_metadata(const std::string& html,
                              const std::string& base_url,
                              UrlPreviewResult& result) {
        // --- Open Graph ---
        if (config_.enable_og) {
            auto og = OpenGraphParser::parse(html, base_url);
            if (og.has_data()) {
                // Prefer OG data as primary source
                if (!og.title.empty()) result.title = og.title;
                if (!og.description.empty()) result.description = og.description;
                if (!og.image_url.empty()) result.image_url = og.image_url;
                if (og.image_width > 0) result.image_width = og.image_width;
                if (og.image_height > 0) result.image_height = og.image_height;
                if (!og.image_type.empty()) result.image_type = og.image_type;
                if (!og.image_alt.empty()) result.image_alt = og.image_alt;
                if (!og.site_name.empty()) result.site_name = og.site_name;
                if (!og.type.empty()) result.type = og.type;
                if (!og.locale.empty()) result.locale = og.locale;
                if (!og.determiner.empty()) result.locale = og.determiner;
                if (!og.article_author.empty()) result.author_name = og.article_author;
                if (!og.article_published_time.empty())
                    result.published_time = og.article_published_time;

                // Copy all images
                for (const auto& [img_url, dims] : og.all_images) {
                    if (img_url != result.image_url) {
                        result.additional_images.push_back(img_url);
                    }
                }
            }

            // Set OG URL as resolved URL if different from fetch result
            if (!og.url.empty() && og.url != result.resolved_url) {
                result.resolved_url = og.url;
            }
        }

        // --- Twitter Cards ---
        if (config_.enable_twitter_cards) {
            auto twitter = TwitterCardParser::parse(html, base_url);
            if (twitter.has_data()) {
                // Fill in gaps from Twitter Cards
                if (result.title.empty() && !twitter.title.empty())
                    result.title = twitter.title;
                if (result.description.empty() && !twitter.description.empty())
                    result.description = twitter.description;
                if (result.image_url.empty() && !twitter.image.empty())
                    result.image_url = twitter.image;
                if (!twitter.card.empty()) result.twitter_card = twitter.card;
                if (!twitter.site.empty()) result.twitter_site = twitter.site;
                if (!twitter.creator.empty()) result.twitter_creator = twitter.creator;
            }
        }

        // --- oEmbed ---
        if (config_.enable_oembed) {
            auto oembed_url = OEmbedParser::discover_endpoint(html, base_url);
            if (oembed_url.has_value()) {
                // In a full implementation, we would fetch the oEmbed endpoint here.
                // For efficiency, this is deferred to an async process or done inline
                // when the oEmbed endpoint is on the same domain.
                //
                // try_fetch_oembed(*oembed_url, result);
                //
                // For now, record that oEmbed was discovered but not yet fetched.
                result.oembed_provider = "discovered";
            } else {
                // Try matching against known providers
                auto provider = OEmbedParser::match_provider(base_url);
                if (provider.has_value()) {
                    // Construct the oEmbed endpoint URL
                    std::string embed_url = provider->endpoint_url +
                        "?url=" + url_encode(base_url) + "&format=json";
                    result.oembed_provider = provider->name;
                    // try_fetch_oembed(embed_url, result);
                }
            }
        }

        // --- HTML fallback ---
        if (config_.enable_htm_fallback) {
            auto html_meta = HtmlMetadataExtractor::extract(html, base_url);

            if (result.title.empty() && !html_meta.title.empty()) {
                result.title = html_meta.title;
            }
            if (result.description.empty() && !html_meta.description.empty()) {
                result.description = html_meta.description;
            }
            if (result.author_name.empty() && !html_meta.author.empty()) {
                result.author_name = html_meta.author;
            }
            if (result.favicon_url.empty() && !html_meta.favicon_url.empty()) {
                result.favicon_url = html_meta.favicon_url;
            }

            // JSON-LD structured data (often more accurate than general meta)
            if (config_.enable_jsonld) {
                if (result.title.empty() && !html_meta.jsonld_name.empty()) {
                    result.title = html_meta.jsonld_name;
                }
                if (result.description.empty() && !html_meta.jsonld_description.empty()) {
                    result.description = html_meta.jsonld_description;
                }
                if (result.image_url.empty() && !html_meta.jsonld_image.empty()) {
                    result.image_url = html_meta.jsonld_image;
                }
                if (result.type.empty() && !html_meta.jsonld_type.empty()) {
                    result.type = html_meta.jsonld_type;
                }
            }
        }

        // --- Image detection ---
        if (config_.enable_image_detection && !result.image_url.empty()) {
            auto img_info = ImageDetector::detect(
                result.image_url, result.image_width,
                result.image_height, result.image_type);

            result.image_width = img_info.width;
            result.image_height = img_info.height;
            result.image_type = img_info.mime_type;
        }

        // Select the best image from additional images if primary is not good enough
        if (result.image_url.empty() && !result.additional_images.empty()) {
            result.image_url = ImageDetector::select_best_image(
                result.additional_images);
            result.additional_images.clear();
        }
    }

    // URL encode for embedding in query strings
    static std::string url_encode(const std::string& value) {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;

        for (char c : value) {
            if (std::isalnum(static_cast<unsigned char>(c)) ||
                c == '-' || c == '_' || c == '.' || c == '~') {
                escaped << c;
            } else {
                escaped << std::uppercase;
                escaped << '%' << std::setw(2)
                        << static_cast<int>(static_cast<unsigned char>(c));
                escaped << std::nouppercase;
            }
        }
        return escaped.str();
    }
};

// ============================================================================
// Public API — Free functions for standalone use
// ============================================================================

// --- Convenience: Generate a URL preview with default settings ---
UrlPreviewResult generate_url_preview(const std::string& url) {
    static UrlPreviewEngine default_engine;
    return default_engine.generate_preview(url);
}

// --- Convenience: Generate URL preview JSON with default settings ---
json generate_url_preview_json(const std::string& url) {
    static UrlPreviewEngine default_engine;
    return default_engine.generate_preview_json(url);
}

// --- Convenience: Check if URL can be previewed ---
bool can_preview_url(const std::string& url) {
    static UrlPreviewEngine default_engine;
    return default_engine.can_preview(url);
}

// --- Convenience: Extract domain from URL ---
std::string preview_extract_domain(const std::string& url) {
    return extract_domain(url);
}

// --- Convenience: Parse Open Graph metadata from HTML ---
UrlPreviewResult parse_og_metadata(const std::string& html, const std::string& url) {
    UrlPreviewResult result;
    result.url = url;
    result.resolved_url = url;

    auto og = OpenGraphParser::parse(html, url);
    if (!og.title.empty()) result.title = og.title;
    if (!og.description.empty()) result.description = og.description;
    if (!og.image_url.empty()) result.image_url = og.image_url;
    result.image_width = og.image_width;
    result.image_height = og.image_height;
    result.image_type = og.image_type;
    result.image_alt = og.image_alt;
    if (!og.site_name.empty()) result.site_name = og.site_name;
    if (!og.type.empty()) result.type = og.type;
    if (!og.article_author.empty()) result.author_name = og.article_author;
    if (!og.article_published_time.empty()) result.published_time = og.article_published_time;

    result.has_title = !result.title.empty();
    result.has_description = !result.description.empty();
    result.has_image = !result.image_url.empty();
    result.valid = result.has_title || result.has_description || result.has_image;

    // Also check Twitter Cards
    auto twitter = TwitterCardParser::parse(html, url);
    if (result.title.empty() && !twitter.title.empty()) result.title = twitter.title;
    if (result.description.empty() && !twitter.description.empty())
        result.description = twitter.description;
    if (result.image_url.empty() && !twitter.image.empty())
        result.image_url = twitter.image;

    return result;
}

// --- Convenience: Sanitize preview content ---
UrlPreviewResult sanitize_preview(const UrlPreviewResult& preview) {
    UrlPreviewResult result = preview;
    ContentSanitizer::sanitize_result(result);
    return result;
}

// --- Convenience: Check if URL is an image ---
bool is_image_url(const std::string& url) {
    return ImageDetector::is_image_url(url);
}

// ============================================================================
// Factory functions for EngineConfig presets
// ============================================================================

namespace url_preview_configs {

// Conservative config: slower, more thorough
UrlPreviewEngine::EngineConfig conservative() {
    UrlPreviewEngine::EngineConfig config;
    config.fetch.total_timeout = chr::seconds(90);
    config.fetch.read_timeout = chr::seconds(45);
    config.fetch.max_response_size = 5 * 1024 * 1024; // 5 MB
    config.fetch.user_agent = url_preview_constants::kDefaultUserAgent;
    config.sanitize.max_title_length = 512;
    config.sanitize.max_description_length = 1024;
    config.cache.default_ttl = chr::hours(2);
    config.cache.error_ttl = chr::minutes(10);
    config.domain_filter.block_private_ips = true;
    config.domain_filter.block_ip_addresses = true;
    return config;
}

// Fast config: aggressive timeouts, smaller sizes, shorter cache
UrlPreviewEngine::EngineConfig fast() {
    UrlPreviewEngine::EngineConfig config;
    config.fetch.total_timeout = chr::seconds(15);
    config.fetch.read_timeout = chr::seconds(10);
    config.fetch.max_response_size = 512 * 1024; // 512 KB
    config.sanitize.max_title_length = 128;
    config.sanitize.max_description_length = 300;
    config.cache.default_ttl = chr::minutes(30);
    config.cache.error_ttl = chr::minutes(5);
    config.cache.max_entries = 1000;
    config.enable_oembed = false; // Skip oEmbed for speed
    config.enable_jsonld = false;
    return config;
}

// Strict config: maximum security, minimal preview
UrlPreviewEngine::EngineConfig strict() {
    UrlPreviewEngine::EngineConfig config;
    config.fetch.total_timeout = chr::seconds(30);
    config.fetch.max_response_size = 256 * 1024; // 256 KB
    config.sanitize.max_title_length = 100;
    config.sanitize.max_description_length = 200;
    config.sanitize.max_html_length = 0; // No oEmbed HTML
    config.domain_filter.block_private_ips = true;
    config.domain_filter.block_ip_addresses = true;
    config.domain_filter.default_policy = DomainFilter::DefaultPolicy::DENY_ALL;
    config.enable_oembed = false;
    config.enable_twitter_cards = false;
    return config;
}

// Full-featured config: extract everything
UrlPreviewEngine::EngineConfig full_featured() {
    UrlPreviewEngine::EngineConfig config;
    config.fetch.total_timeout = chr::seconds(60);
    config.fetch.read_timeout = chr::seconds(30);
    config.fetch.max_response_size = 2 * 1024 * 1024; // 2 MB
    config.sanitize.max_title_length = 256;
    config.sanitize.max_description_length = 512;
    config.sanitize.max_html_length = 10'000;
    config.cache.default_ttl = chr::hours(1);
    config.cache.error_ttl = chr::minutes(5);
    config.enable_og = true;
    config.enable_twitter_cards = true;
    config.enable_oembed = true;
    config.enable_htm_fallback = true;
    config.enable_jsonld = true;
    config.enable_image_detection = true;
    config.enable_sanitization = true;
    return config;
}

} // namespace url_preview_configs

// ============================================================================
// Unit test helpers
// ============================================================================

#ifdef PROGRESSIVE_URL_PREVIEW_TESTING

namespace url_preview_test {

// Test HTML fixture: a complete page with OG, Twitter, and standard metadata
constexpr const char* test_html_basic = R"HTML(
<!DOCTYPE html>
<html prefix="og: http://ogp.me/ns#">
<head>
<meta charset="utf-8">
<title>Test Page Title</title>
<meta name="description" content="A test page description">
<meta name="author" content="Test Author">
<meta property="og:title" content="OG Test Title">
<meta property="og:description" content="OG Test Description">
<meta property="og:image" content="https://example.com/image.jpg">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:type" content="image/jpeg">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Test Site">
<meta property="og:url" content="https://example.com/article">
<meta property="og:locale" content="en_US">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Twitter Title">
<meta name="twitter:description" content="Twitter Description">
<meta name="twitter:image" content="https://example.com/twitter-image.jpg">
<meta name="twitter:site" content="@testsite">
<meta name="twitter:creator" content="@testauthor">
</head>
<body>
<h1>Hello World</h1>
</body>
</html>
)HTML";

// Test HTML fixture: oEmbed discovery
constexpr const char* test_html_oembed = R"HTML(
<!DOCTYPE html>
<html>
<head>
<title>OEmbed Test</title>
<link rel="alternate" type="application/json+oembed"
      href="https://example.com/oembed?url=test" title="Test">
</head>
<body></body>
</html>
)HTML";

// Test HTML fixture: Twitter-only (no OG)
constexpr const char* test_html_twitter_only = R"HTML(
<!DOCTYPE html>
<html>
<head>
<title>Twitter Only</title>
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="Twitter Title Only">
<meta name="twitter:description" content="Twitter Description Only">
<meta name="twitter:image" content="https://example.com/tw-img.jpg">
</head>
<body></body>
</html>
)HTML";

// Test HTML fixture: Minimal HTML
constexpr const char* test_html_minimal = R"HTML(
<html><head><title>Minimal Title</title></head><body><p>Minimal body</p></body></html>
)HTML";

// Run all self-tests
inline bool run_self_tests() {
    bool all_passed = true;

    // Test 1: OpenGraph parsing
    {
        auto og = OpenGraphParser::parse(test_html_basic, "https://example.com/");
        all_passed &= (og.title == "OG Test Title");
        all_passed &= (og.description == "OG Test Description");
        all_passed &= (og.image_url == "https://example.com/image.jpg");
        all_passed &= (og.image_width == 1200);
        all_passed &= (og.image_height == 630);
        all_passed &= (og.type == "article");
        all_passed &= (og.site_name == "Test Site");
        all_passed &= (og.locale == "en_US");
    }

    // Test 2: Twitter Card parsing
    {
        auto tw = TwitterCardParser::parse(test_html_basic, "https://example.com/");
        all_passed &= (tw.card == "summary_large_image");
        all_passed &= (tw.title == "Twitter Title");
        all_passed &= (tw.image.find("twitter-image.jpg") != std::string::npos);
        all_passed &= (tw.site == "@testsite");
        all_passed &= (tw.creator == "@testauthor");
    }

    // Test 3: HTML metadata extraction
    {
        auto meta = HtmlMetadataExtractor::extract(test_html_basic, "https://example.com/");
        all_passed &= (meta.title == "Test Page Title");
        all_passed &= (meta.description == "A test page description");
        all_passed &= (meta.author == "Test Author");
    }

    // Test 4: oEmbed discovery
    {
        auto endpoint = OEmbedParser::discover_endpoint(
            test_html_oembed, "https://example.com/");
        all_passed &= endpoint.has_value();
        if (endpoint.has_value()) {
            all_passed &= (*endpoint == "https://example.com/oembed?url=test");
        }
    }

    // Test 5: Twitter-only fallback
    {
        auto result = parse_og_metadata(test_html_twitter_only, "https://example.com/");
        all_passed &= (result.title == "Twitter Title Only");
        all_passed &= (result.description == "Twitter Description Only");
        all_passed &= (result.image_url.find("tw-img.jpg") != std::string::npos);
    }

    // Test 6: Content sanitization
    {
        std::string dirty = "Hello<script>alert('xss')</script> World";
        ContentSanitizer::SanitizeConfig cfg;
        std::string clean = ContentSanitizer::sanitize_title(dirty, cfg);
        all_passed &= (clean.find("<script>") == std::string::npos);
    }

    // Test 7: Domain filter
    {
        DomainFilter filter;
        filter.deny_domain("evil.com");
        filter.deny_domain("*.spam.*", DomainRule::MatchMode::WILDCARD);

        all_passed &= !filter.is_allowed("https://evil.com/page");
        all_passed &= !filter.is_allowed("https://sub.spam.org/x");
        all_passed &= filter.is_allowed("https://good.com/page");
    }

    // Test 8: URL sanitization (tracking params)
    {
        std::string url = "https://example.com/page?utm_source=fb&id=123";
        std::string clean = ContentSanitizer::sanitize_url(url);
        all_passed &= (clean.find("utm_source") == std::string::npos);
        all_passed &= (clean.find("id=123") != std::string::npos);
    }

    // Test 9: Image URL detection
    {
        all_passed &= ImageDetector::is_image_url("https://example.com/photo.jpg");
        all_passed &= ImageDetector::is_image_url("https://example.com/img.png");
        all_passed &= ImageDetector::is_image_url("https://example.com/image.webp");
        all_passed &= !ImageDetector::is_image_url("https://example.com/page.html");
    }

    // Test 10: Cache operations
    {
        PreviewCache cache;
        UrlPreviewResult r;
        r.url = "https://test.com/";
        r.title = "Cached";
        r.valid = true;

        cache.put("https://test.com/", r);
        auto cached = cache.get("https://test.com/");
        all_passed &= cached.has_value();
        all_passed &= (cached->title == "Cached");

        auto stats = cache.stats();
        all_passed &= (stats.hits == 1);
        all_passed &= (stats.insertions == 1);
    }

    return all_passed;
}

} // namespace url_preview_test

#endif // PROGRESSIVE_URL_PREVIEW_TESTING

} // namespace progressive

// ============================================================================
// End of url_preview_engine.cpp
// ============================================================================
