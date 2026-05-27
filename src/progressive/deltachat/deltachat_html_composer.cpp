// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Progressive Server Contributors
//
// DeltaChat HTML Composer
// Complete HTML email rendering, rich text composer, message quoting,
// markdown conversion, emoji expansion, and MIME multipart/alternative builder.
// Includes: HTML-to-plaintext with quote detection, plaintext-to-HTML,
//           rich text composer (bold, italic, links, lists, code blocks),
//           message quoting with attribution, forwarded message formatting,
//           system message formatting, HTML sanitization, CSS inlining,
//           responsive email template, multipart/alternative MIME builder,
//           quote folding, inline image handling, signature separator
//           detection, markdown-to-HTML converter, emoji shortcode expansion.

#include <algorithm>
#include <array>
#include <cctype>
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
#include <map>
#include <memory>
#include <mutex>
#include <optional>
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

namespace progressive {
namespace deltachat {

// ============================================================================
// Constants and Configuration
// ============================================================================

namespace html_config {

// Maximum length for quoted text before folding
constexpr size_t kMaxQuoteLength = 2000;

// Maximum lines in a visible quote before folding
constexpr int kMaxQuoteLines = 15;

// Maximum depth of nested quotes
constexpr int kMaxQuoteDepth = 5;

// Signature separator patterns
constexpr const char* kSignatureSeparator = "\n-- \n";
constexpr const char* kSignatureSeparatorAlt = "\n--\n";
constexpr const char* kDashDashSpace = "-- ";

// HTML tags considered block-level
constexpr const char* kBlockTags[] = {
    "p", "div", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "table", "tr", "pre", "br", "hr", "section",
    "article", "header", "footer", "nav", "main", "aside"
};

// HTML tags considered inline
constexpr const char* kInlineTags[] = {
    "b", "strong", "i", "em", "u", "s", "del", "ins", "a", "span",
    "code", "small", "mark", "sub", "sup", "abbr", "cite", "q"
};

// Allowed HTML tags for sanitization
const std::unordered_set<std::string> kAllowedTags = {
    "b", "strong", "i", "em", "u", "s", "del", "ins", "a", "span",
    "code", "pre", "blockquote", "p", "div", "br", "hr",
    "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
    "img", "table", "tr", "td", "th", "thead", "tbody",
    "small", "mark", "sub", "sup"
};

// Allowed attributes per tag for sanitization
const std::unordered_map<std::string, std::vector<std::string>> kAllowedAttrs = {
    {"a", {"href", "title", "rel"}},
    {"img", {"src", "alt", "width", "height", "style"}},
    {"td", {"colspan", "rowspan", "style", "align"}},
    {"th", {"colspan", "rowspan", "style", "align"}},
    {"table", {"style", "border", "cellpadding", "cellspacing"}},
    {"span", {"style"}},
    {"div", {"style"}},
    {"p", {"style"}},
    {"blockquote", {"style", "cite"}},
    {"pre", {"style"}},
    {"code", {"style"}},
};

// Default email CSS
constexpr const char* kDefaultEmailCSS = R"CSS(
body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont,
    'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    font-size: 14px; line-height: 1.5; color: #1a1a1a;
    background-color: #f5f5f5; }
.email-container { max-width: 600px; margin: 0 auto; background: #ffffff;
    border-radius: 8px; overflow: hidden; }
.email-header { padding: 16px 20px; background: #f8f9fa; border-bottom: 1px solid #e0e0e0; }
.email-body { padding: 20px; }
.email-footer { padding: 12px 20px; background: #f8f9fa; border-top: 1px solid #e0e0e0;
    font-size: 12px; color: #888; }
blockquote { margin: 8px 0; padding: 8px 16px; border-left: 3px solid #1e90ff;
    background: #f0f7ff; color: #555; }
pre { background: #2d2d2d; color: #e0e0e0; padding: 12px 16px; border-radius: 6px;
    overflow-x: auto; font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 13px; line-height: 1.4; }
code { font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 13px; background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
pre code { background: none; padding: 0; }
a { color: #1e90ff; text-decoration: none; }
a:hover { text-decoration: underline; }
img { max-width: 100%; height: auto; }
hr { border: none; border-top: 1px solid #e0e0e0; margin: 16px 0; }
ul, ol { padding-left: 24px; margin: 8px 0; }
li { margin: 4px 0; }
h1, h2, h3, h4, h5, h6 { margin: 16px 0 8px; line-height: 1.3; }
h1 { font-size: 22px; } h2 { font-size: 20px; } h3 { font-size: 18px; }
.quote-collapsed { max-height: 60px; overflow: hidden; position: relative; }
.quote-collapsed::after { content: ''; position: absolute; bottom: 0; left: 0; right: 0;
    height: 30px; background: linear-gradient(transparent, #f0f7ff); }
.quote-toggle { display: inline-block; cursor: pointer; color: #1e90ff;
    font-size: 12px; margin-top: 4px; user-select: none; }
.quote-toggle:hover { text-decoration: underline; }
.system-msg { color: #888; font-style: italic; font-size: 13px; text-align: center;
    padding: 8px 0; }
.forwarded-header { padding: 8px 16px; background: #e8f0fe; border-left: 3px solid #1e90ff;
    margin: 8px 0; font-size: 12px; color: #555; }
.attribution { font-size: 12px; color: #888; margin-bottom: 4px; }
.emoji { font-size: 1.2em; vertical-align: middle; }
.signature-sep { border: none; border-top: 1px dashed #ccc; margin: 16px 0 8px; }
.inline-image { max-width: 100%; border-radius: 4px; margin: 8px 0; }
@media only screen and (max-width: 600px) {
    .email-container { max-width: 100%; border-radius: 0; }
    .email-body { padding: 12px; }
    blockquote { padding: 8px 12px; }
    pre { padding: 8px 12px; font-size: 12px; }
}
)CSS";

// Responsive email HTML template
constexpr const char* kEmailTemplate = R"TEMPLATE(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>{{SUBJECT}}</title>
<style>{{CSS}}</style>
</head>
<body>
<div class="email-container">
{{CONTENT}}
</div>
</body>
</html>
)TEMPLATE";

}  // namespace html_config

// ============================================================================
// Utility Functions
// ============================================================================

namespace {

// Escape HTML special characters
std::string escape_html(const std::string& text) {
    std::string result;
    result.reserve(text.size() * 1.1);
    for (char c : text) {
        switch (c) {
            case '&': result += "&amp;"; break;
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&#39;"; break;
            default: result += c; break;
        }
    }
    return result;
}

// Unescape HTML entities back to characters
std::string unescape_html(const std::string& text) {
    std::string result = text;
    // Named entities
    static const std::pair<const char*, char> kEntities[] = {
        {"&amp;", '&'}, {"&lt;", '<'}, {"&gt;", '>'},
        {"&quot;", '"'}, {"&#39;", '\''}, {"&apos;", '\''},
        {"&nbsp;", ' '}, {"&ndash;", '-'}, {"&mdash;", '-'},
        {"&lsquo;", '\''}, {"&rsquo;", '\''}, {"&ldquo;", '"'},
        {"&rdquo;", '"'}, {"&hellip;", '.'}, {"&copy;", 'c'},
        {"&reg;", 'r'}, {"&trade;", 't'}
    };
    for (const auto& [entity, ch] : kEntities) {
        size_t pos = 0;
        while ((pos = result.find(entity, pos)) != std::string::npos) {
            result.replace(pos, std::string(entity).length(), 1, ch);
            pos += 1;
        }
    }
    // Numeric entities
    std::regex num_re("&#(\\d+);");
    std::smatch match;
    while (std::regex_search(result, match, num_re)) {
        int code = std::stoi(match[1].str());
        char ch = static_cast<char>(code);
        result.replace(match.position(), match.length(), 1, ch);
    }
    std::regex hex_re("&#x([0-9a-fA-F]+);");
    while (std::regex_search(result, match, hex_re)) {
        int code = std::stoi(match[1].str(), nullptr, 16);
        char ch = static_cast<char>(code);
        result.replace(match.position(), match.length(), 1, ch);
    }
    return result;
}

// Trim leading whitespace
std::string ltrim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r\f\v");
    return (start == std::string::npos) ? "" : s.substr(start);
}

// Trim trailing whitespace
std::string rtrim(const std::string& s) {
    size_t end = s.find_last_not_of(" \t\n\r\f\v");
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

// Trim both ends
std::string trim(const std::string& s) {
    return ltrim(rtrim(s));
}

// Check if a string starts with a prefix
bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

// Check if a string ends with a suffix
bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Convert string to lowercase
std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

// Convert string to uppercase
std::string to_upper(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return result;
}

// Replace all occurrences of a substring
std::string replace_all(const std::string& str, const std::string& from,
                        const std::string& to) {
    if (from.empty()) return str;
    std::string result = str;
    size_t pos = 0;
    while ((pos = result.find(from, pos)) != std::string::npos) {
        result.replace(pos, from.length(), to);
        pos += to.length();
    }
    return result;
}

// URL-encode a string
std::string url_encode(const std::string& value) {
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

// Split a string by delimiter
std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream token_stream(s);
    while (std::getline(token_stream, token, delim)) {
        tokens.push_back(token);
    }
    return tokens;
}

// Join strings with a delimiter
std::string join(const std::vector<std::string>& parts, const std::string& delim) {
    if (parts.empty()) return "";
    std::ostringstream ss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) ss << delim;
        ss << parts[i];
    }
    return ss.str();
}

// Generate a unique boundary string for MIME
std::string generate_boundary() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    uint64_t id = now ^ (counter.fetch_add(1) << 16);
    std::ostringstream ss;
    ss << std::hex << id;
    return "=_boundary_" + ss.str() + "_";
}

// Generate a unique Content-ID for inline images
std::string generate_content_id(const std::string& filename) {
    static std::atomic<uint64_t> cid_counter{0};
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    uint64_t id = now ^ (cid_counter.fetch_add(1) << 16);
    std::ostringstream ss;
    ss << std::hex << id;
    return "img_" + ss.str() + "@delta";
}

// Base64 encode
std::string base64_encode(const std::string& input) {
    static const char* kBase64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(kBase64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        result.push_back(kBase64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (result.size() % 4)
        result.push_back('=');
    return result;
}

}  // namespace

// ============================================================================
// Signature Separator Detection
// ============================================================================

class SignatureDetector {
public:
    struct SignatureInfo {
        bool has_signature = false;
        size_t signature_pos = std::string::npos;
        std::string signature_text;
        std::string text_before;
    };

    // Detect signature separator in plain text
    static SignatureInfo detect_plain(const std::string& text) {
        SignatureInfo info;
        info.text_before = text;

        // Look for standard signature separator "\n-- \n"
        size_t pos = text.rfind(html_config::kSignatureSeparator);
        if (pos != std::string::npos) {
            info.has_signature = true;
            info.signature_pos = pos;
            info.text_before = text.substr(0, pos);
            info.signature_text = text.substr(pos + strlen(html_config::kSignatureSeparator));
            return info;
        }

        // Look for alternate "\n--\n" (some clients use this)
        pos = text.rfind(html_config::kSignatureSeparatorAlt);
        if (pos != std::string::npos && pos > 0) {
            // Only if it's not the very start
            info.has_signature = true;
            info.signature_pos = pos;
            info.text_before = text.substr(0, pos);
            info.signature_text = text.substr(pos + strlen(html_config::kSignatureSeparatorAlt));
            return info;
        }

        return info;
    }

    // Detect signature separator in HTML
    static SignatureInfo detect_html(const std::string& html) {
        SignatureInfo info;
        info.text_before = html;

        // Common HTML signature separator patterns
        static const std::vector<std::string> kHtmlSignatures = {
            "<hr", "<div class=\"signature\"",
            "<span class=\"signature\"", "class=\"gmail_signature\"",
            "<div id=\"signature\"", "<!-- signature -->",
            "<p>-- <br>", "--&nbsp;<br>", "&ndash;&nbsp;<br>"
        };

        size_t best_pos = std::string::npos;
        for (const auto& sig_pattern : kHtmlSignatures) {
            size_t pos = html.rfind(sig_pattern);
            if (pos != std::string::npos) {
                // Find the closest to the end (last signature)
                if (best_pos == std::string::npos || pos > best_pos) {
                    best_pos = pos;
                }
            }
        }

        if (best_pos != std::string::npos) {
            info.has_signature = true;
            info.signature_pos = best_pos;
            info.text_before = html.substr(0, best_pos);
            info.signature_text = html.substr(best_pos);
        }

        return info;
    }

    // Remove signature from plain text
    static std::string remove_signature(const std::string& text) {
        SignatureInfo info = detect_plain(text);
        return info.has_signature ? info.text_before : text;
    }

    // Remove signature from HTML
    static std::string remove_signature_html(const std::string& html) {
        SignatureInfo info = detect_html(html);
        return info.has_signature ? info.text_before : html;
    }
};

// ============================================================================
// HTML Sanitization
// ============================================================================

class HtmlSanitizer {
public:
    // Sanitize HTML for safe display, allowing only a whitelist of tags/attrs
    static std::string sanitize(const std::string& html) {
        std::string result;
        result.reserve(html.size());

        enum class State { Text, Tag, AttrName, AttrValue, AttrValueQuote };
        State state = State::Text;

        std::string current_tag;
        std::string current_attr_name;
        std::string current_attr_value;
        char quote_char = '"';
        bool tag_allowed = false;

        size_t i = 0;
        while (i < html.size()) {
            char c = html[i];

            switch (state) {
                case State::Text:
                    if (c == '<') {
                        state = State::Tag;
                        current_tag.clear();
                        tag_allowed = false;
                    } else {
                        result += c;
                    }
                    break;

                case State::Tag: {
                    if (c == '>' || c == ' ' || c == '\t' || c == '\n') {
                        // Tag name complete
                        std::string tag_lower = to_lower(current_tag);

                        // Check if it's a closing tag
                        bool is_closing = !current_tag.empty() && current_tag[0] == '/';
                        std::string clean_tag = is_closing ?
                            to_lower(current_tag.substr(1)) : tag_lower;

                        if (html_config::kAllowedTags.count(clean_tag)) {
                            tag_allowed = true;
                            if (is_closing) {
                                result += "</" + clean_tag + ">";
                            } else {
                                result += "<" + clean_tag;
                            }
                        } else {
                            tag_allowed = false;
                            // For block tags not allowed, still add a line break
                            if (isBlockTag(clean_tag)) {
                                result += "\n";
                            }
                        }

                        if (c == '>') {
                            if (tag_allowed && !is_closing) {
                                result += ">";
                            }
                            state = State::Text;
                        } else {
                            state = State::AttrName;
                            current_attr_name.clear();
                        }
                    } else if (c == '/' && i + 1 < html.size() && html[i + 1] == '>') {
                        // Self-closing tag
                        std::string tag_lower = to_lower(current_tag);
                        if (html_config::kAllowedTags.count(tag_lower)) {
                            result += "<" + tag_lower + " />";
                        } else if (isBlockTag(tag_lower)) {
                            result += "\n";
                        }
                        ++i;  // skip '>'
                        state = State::Text;
                    } else {
                        current_tag += c;
                    }
                    break;
                }

                case State::AttrName: {
                    if (c == '=') {
                        // Value coming
                        state = State::AttrValue;
                        current_attr_value.clear();
                    } else if (c == '>' || c == ' ') {
                        // Boolean attribute or end of attributes
                        if (!current_attr_name.empty() && tag_allowed) {
                            std::string clean_tag = to_lower(
                                (!current_tag.empty() && current_tag[0] == '/') ?
                                current_tag.substr(1) : current_tag);
                            if (isAttrAllowed(clean_tag, current_attr_name)) {
                                result += " " + to_lower(current_attr_name);
                            }
                        }
                        current_attr_name.clear();
                        if (c == '>') {
                            if (tag_allowed) result += ">";
                            state = State::Text;
                        }
                    } else if (c == '/') {
                        // Self-closing
                        if (!current_attr_name.empty() && tag_allowed) {
                            std::string clean_tag = to_lower(
                                (!current_tag.empty() && current_tag[0] == '/') ?
                                current_tag.substr(1) : current_tag);
                            if (isAttrAllowed(clean_tag, current_attr_name)) {
                                result += " " + to_lower(current_attr_name);
                            }
                        }
                        if (tag_allowed) result += " />";
                        state = State::Text;
                    } else if (!std::isspace(static_cast<unsigned char>(c))) {
                        current_attr_name += c;
                    }
                    break;
                }

                case State::AttrValue: {
                    if (c == '"' || c == '\'') {
                        quote_char = c;
                        state = State::AttrValueQuote;
                    } else if (c == '>' || std::isspace(static_cast<unsigned char>(c))) {
                        // Unquoted value ended
                        if (!current_attr_name.empty() && !current_attr_value.empty() && tag_allowed) {
                            std::string clean_tag = to_lower(
                                (!current_tag.empty() && current_tag[0] == '/') ?
                                current_tag.substr(1) : current_tag);
                            if (isAttrAllowed(clean_tag, current_attr_name)) {
                                result += " " + to_lower(current_attr_name) +
                                          "=\"" + sanitize_attr_value(current_attr_value) + "\"";
                            }
                        }
                        current_attr_name.clear();
                        current_attr_value.clear();
                        if (c == '>') {
                            if (tag_allowed) result += ">";
                            state = State::Text;
                        } else {
                            state = State::AttrName;
                        }
                    } else {
                        current_attr_value += c;
                    }
                    break;
                }

                case State::AttrValueQuote: {
                    if (c == quote_char) {
                        // End of quoted value
                        if (!current_attr_name.empty() && tag_allowed) {
                            std::string clean_tag = to_lower(
                                (!current_tag.empty() && current_tag[0] == '/') ?
                                current_tag.substr(1) : current_tag);
                            if (isAttrAllowed(clean_tag, current_attr_name)) {
                                result += " " + to_lower(current_attr_name) +
                                          "=\"" + sanitize_attr_value(current_attr_value) + "\"";
                            }
                        }
                        current_attr_name.clear();
                        current_attr_value.clear();
                        state = State::AttrName;
                    } else {
                        current_attr_value += c;
                    }
                    break;
                }
            }
            ++i;
        }

        // Handle any remaining partial state - just append remaining text
        if (state == State::Text) {
            // Already handled
        }

        return result;
    }

    // Strip all HTML tags, returning plain text
    static std::string strip_tags(const std::string& html) {
        std::string result;
        result.reserve(html.size());
        bool in_tag = false;
        bool in_style_or_script = false;
        std::string tag_stack;

        for (size_t i = 0; i < html.size(); ++i) {
            char c = html[i];

            if (in_style_or_script) {
                // Track the current tag depth
                if (c == '<' && i + 1 < html.size()) {
                    if (html[i + 1] == '/') {
                        // Closing tag
                        size_t end = html.find('>', i);
                        if (end != std::string::npos) {
                            std::string tag = to_lower(html.substr(i + 2, end - i - 2));
                            if (tag == tag_stack) {
                                in_style_or_script = false;
                                tag_stack.clear();
                            }
                            i = end;
                        }
                    }
                }
                continue;
            }

            if (c == '<') {
                in_tag = true;
                // Check for style/script
                if (i + 6 < html.size() &&
                    (to_lower(html.substr(i + 1, 5)) == "style" ||
                     to_lower(html.substr(i + 1, 6)) == "script")) {
                    in_style_or_script = true;
                    tag_stack = to_lower(html.substr(i + 1,
                        html.find_first_of(" >", i) - i - 1));
                }
                continue;
            }

            if (c == '>') {
                in_tag = false;
                // Add whitespace for block tags
                continue;
            }

            if (!in_tag) {
                result += c;
            }
        }

        // Collapse whitespace
        std::string collapsed;
        collapsed.reserve(result.size());
        bool last_was_space = true;
        for (char c : result) {
            if (std::isspace(static_cast<unsigned char>(c))) {
                if (!last_was_space) {
                    collapsed += ' ';
                    last_was_space = true;
                }
            } else {
                collapsed += c;
                last_was_space = false;
            }
        }

        return trim(collapsed);
    }

private:
    static bool isBlockTag(const std::string& tag) {
        for (const auto& bt : html_config::kBlockTags) {
            if (tag == bt) return true;
        }
        return false;
    }

    static bool isAttrAllowed(const std::string& tag, const std::string& attr) {
        auto it = html_config::kAllowedAttrs.find(tag);
        if (it == html_config::kAllowedAttrs.end()) return false;
        std::string attr_lower = to_lower(attr);
        for (const auto& allowed : it->second) {
            if (attr_lower == allowed) return true;
        }
        return false;
    }

    static std::string sanitize_attr_value(const std::string& value) {
        // Escape quotes and remove javascript: URLs
        if (starts_with(to_lower(trim(value)), "javascript:")) {
            return "";
        }
        std::string result;
        for (char c : value) {
            if (c == '"') result += "&quot;";
            else if (c == '\'') result += "&#39;";
            else if (c == '<') result += "&lt;";
            else if (c == '>') result += "&gt;";
            else result += c;
        }
        return result;
    }
};

// ============================================================================
// Quote Detection and Folding
// ============================================================================

class QuoteDetector {
public:
    struct QuoteBlock {
        std::string text;
        int depth = 0;
        bool is_collapsed = false;
        std::string attribution;
    };

    struct QuoteAnalysis {
        std::vector<QuoteBlock> quotes;
        std::string main_text;
        bool has_quotes = false;
    };

    // Detect and extract quoted text from plain text (email quoting with >)
    static QuoteAnalysis analyze_plain(const std::string& text) {
        QuoteAnalysis analysis;
        std::istringstream stream(text);
        std::string line;
        std::string current_main;
        QuoteBlock current_quote;
        int last_depth = 0;

        while (std::getline(stream, line)) {
            int depth = 0;
            size_t pos = 0;

            // Count leading '>' characters
            while (pos < line.size() && line[pos] == '>') {
                ++pos;
                ++depth;
            }

            // Skip space after '>' chain
            if (pos < line.size() && line[pos] == ' ') {
                ++pos;
            }

            std::string content = line.substr(pos);

            if (depth > 0) {
                if (current_quote.text.empty()) {
                    // Start new quote block
                    current_quote.depth = depth;
                    current_quote.text = content;
                } else if (depth == current_quote.depth) {
                    // Continue same quote level
                    current_quote.text += "\n" + content;
                } else if (depth > current_quote.depth) {
                    // Nested quote - append to current
                    current_quote.text += "\n" + std::string(depth, '>') + " " + content;
                } else {
                    // New quote at different level
                    if (!current_quote.text.empty()) {
                        analysis.quotes.push_back(current_quote);
                        current_quote = QuoteBlock{};
                    }
                    current_quote.text = content;
                    current_quote.depth = depth;
                }
                analysis.has_quotes = true;
            } else {
                // Non-quoted line
                if (!current_quote.text.empty()) {
                    analysis.quotes.push_back(current_quote);
                    current_quote = QuoteBlock{};
                }
                if (!current_main.empty()) current_main += "\n";
                current_main += content;
            }
            last_depth = depth;
        }

        // Don't forget the last quote
        if (!current_quote.text.empty()) {
            analysis.quotes.push_back(current_quote);
        }

        analysis.main_text = current_main;
        return analysis;
    }

    // Detect quotes in HTML (blockquote tags)
    static QuoteAnalysis analyze_html(const std::string& html) {
        QuoteAnalysis analysis;

        // Simple extraction of blockquote content
        std::regex bq_re("<blockquote[^>]*>(.*?)</blockquote>",
                         std::regex::icase | std::regex::dotall);
        std::string working = html;

        std::smatch match;
        std::string::const_iterator search_start(working.cbegin());
        while (std::regex_search(search_start, working.cend(), match, bq_re)) {
            QuoteBlock block;
            block.text = match[1].str();
            block.depth = 1;
            analysis.quotes.push_back(block);
            analysis.has_quotes = true;
            search_start = match.suffix().first;
        }

        // Extract text outside blockquotes
        analysis.main_text = std::regex_replace(html, bq_re, "",
            std::regex_constants::format_default);
        analysis.main_text = HtmlSanitizer::strip_tags(analysis.main_text);

        return analysis;
    }

    // Fold long quotes for display (return collapsed HTML)
    static std::string fold_quotes_html(const std::string& quote_html,
                                        int max_lines = html_config::kMaxQuoteLines,
                                        size_t max_length = html_config::kMaxQuoteLength) {
        // Count lines in the quote
        int line_count = 0;
        for (char c : quote_html) {
            if (c == '\n') ++line_count;
        }

        bool should_fold = line_count > max_lines || quote_html.size() > max_length;

        if (!should_fold) {
            return quote_html;
        }

        // Create collapsed quote with toggle
        std::ostringstream ss;
        ss << "<div class=\"quote-collapsed\" data-quote-id=\"" << std::time(nullptr) << "\">\n";
        ss << quote_html;
        ss << "</div>\n";
        ss << "<span class=\"quote-toggle\" onclick=\"this.previousElementSibling.classList.toggle('quote-collapsed');"
           << "this.textContent=this.previousElementSibling.classList.contains('quote-collapsed')?'[Show quoted text]':'[Hide quoted text]';\">"
           << "[Show quoted text]</span>";
        return ss.str();
    }

    // Build quoting attribution line
    static std::string build_attribution(const std::string& author,
                                         const std::string& timestamp) {
        std::ostringstream ss;
        ss << "<div class=\"attribution\">";
        if (!author.empty()) {
            ss << "On " << timestamp << ", " << escape_html(author) << " wrote:";
        } else {
            ss << "On " << timestamp << ":";
        }
        ss << "</div>";
        return ss.str();
    }
};

// ============================================================================
// HTML to Plain Text Converter
// ============================================================================

class HtmlToPlainText {
public:
    // Convert HTML to plain text preserving basic structure
    static std::string convert(const std::string& html) {
        std::string result;
        result.reserve(html.size());

        enum class Mode { Normal, Pre, Style };
        Mode mode = Mode::Normal;
        std::string tag_buffer;
        bool in_tag = false;
        bool needs_newline = false;
        int list_depth = 0;
        std::string link_url;
        std::string link_text;
        bool in_link = false;
        bool in_heading = false;
        int consecutive_newlines = 0;

        for (size_t i = 0; i < html.size(); ++i) {
            char c = html[i];

            if (mode == Mode::Style) {
                if (c == '<' && i + 7 < html.size() &&
                    to_lower(html.substr(i, 8)) == "</style>") {
                    mode = Mode::Normal;
                    i += 7;
                }
                continue;
            }

            if (mode == Mode::Pre) {
                if (c == '<' && i + 5 < html.size() &&
                    to_lower(html.substr(i, 6)) == "</pre>") {
                    mode = Mode::Normal;
                    result += "\n";
                    i += 5;
                    needs_newline = true;
                    continue;
                }
                if (c == '<' && i + 3 < html.size() &&
                    to_lower(html.substr(i, 4)) == "<br") {
                    result += "\n";
                    continue;
                }
                if (in_tag) {
                    if (c == '>') {
                        in_tag = false;
                        tag_buffer.clear();
                    }
                    continue;
                }
                if (c == '<') {
                    in_tag = true;
                    continue;
                }
                result += c;
                continue;
            }

            // Normal mode
            if (c == '<') {
                in_tag = true;
                tag_buffer.clear();

                // Check special tags
                if (i + 6 < html.size() &&
                    to_lower(html.substr(i + 1, 5)) == "style") {
                    mode = Mode::Style;
                    ++i;  // will be handled on next iteration
                    in_tag = false;
                    continue;
                }
                if (i + 4 < html.size() &&
                    to_lower(html.substr(i + 1, 3)) == "pre") {
                    mode = Mode::Pre;
                    result += "\n";
                    in_tag = false;
                    // Find end of pre tag
                    size_t end_tag = html.find('>', i);
                    if (end_tag != std::string::npos) i = end_tag;
                    continue;
                }
                continue;
            }

            if (in_tag) {
                if (c == '>') {
                    in_tag = false;
                    std::string tag = to_lower(tag_buffer);

                    // Handle closing tags
                    if (!tag.empty() && tag[0] == '/') {
                        std::string closing = tag.substr(1);

                        if (closing == "p" || closing == "div" ||
                            closing == "h1" || closing == "h2" ||
                            closing == "h3" || closing == "h4" ||
                            closing == "h5" || closing == "h6") {
                            result += "\n\n";
                            in_heading = false;
                        } else if (closing == "li") {
                            result += "\n";
                        } else if (closing == "ul" || closing == "ol") {
                            if (list_depth > 0) --list_depth;
                            result += "\n";
                        } else if (closing == "br" || tag == "br/") {
                            result += "\n";
                        } else if (closing == "tr") {
                            result += "\n";
                        } else if (closing == "td" || closing == "th") {
                            result += "\t";
                        } else if (closing == "blockquote") {
                            result += "\n";
                        } else if (closing == "a") {
                            if (in_link && !link_url.empty() && !link_text.empty()) {
                                if (link_text != link_url) {
                                    result += " [" + link_url + "]";
                                }
                            }
                            in_link = false;
                            link_url.clear();
                            link_text.clear();
                        }
                        continue;
                    }

                    // Opening tags
                    if (tag == "br" || tag == "br/") {
                        result += "\n";
                    } else if (tag == "p" || tag == "div" || tag == "blockquote") {
                        if (needs_newline) result += "\n";
                        needs_newline = true;
                    } else if (tag == "h1" || tag == "h2" || tag == "h3" ||
                               tag == "h4" || tag == "h5" || tag == "h6") {
                        result += "\n\n";
                        in_heading = true;
                    } else if (tag == "li") {
                        result += "\n";
                        for (int d = 0; d < list_depth; ++d) result += "  ";
                        result += "* ";
                    } else if (tag == "hr") {
                        result += "\n---\n";
                    } else if (tag == "img") {
                        // Extract alt text
                        std::string alt = extract_attr(tag_buffer, "alt");
                        if (!alt.empty()) {
                            result += "[" + alt + "]";
                        } else {
                            result += "[Image]";
                        }
                    } else if (starts_with(tag, "a ")) {
                        in_link = true;
                        link_url = extract_attr(tag_buffer, "href");
                        link_text.clear();
                    } else if (tag == "ul" || tag == "ol") {
                        ++list_depth;
                        result += "\n";
                    }

                    tag_buffer.clear();
                } else {
                    tag_buffer += c;
                }
                continue;
            }

            // Handle entities
            if (c == '&') {
                size_t semi = html.find(';', i);
                if (semi != std::string::npos && semi - i < 20) {
                    std::string entity = html.substr(i, semi - i + 1);
                    if (entity == "&amp;") result += '&';
                    else if (entity == "&lt;") result += '<';
                    else if (entity == "&gt;") result += '>';
                    else if (entity == "&quot;") result += '"';
                    else if (entity == "&apos;") result += '\'';
                    else if (entity == "&nbsp;") result += ' ';
                    else if (entity == "&ndash;") result += '-';
                    else if (entity == "&mdash;") result += '-';
                    else if (entity == "&copy;") result += "(c)";
                    else if (entity == "&reg;") result += "(R)";
                    else if (entity == "&trade;") result += "(TM)";
                    else {
                        // Try numeric entity
                        if (starts_with(entity, "&#x") || starts_with(entity, "&#X")) {
                            int code = std::stoi(entity.substr(3, entity.size() - 4), nullptr, 16);
                            result += static_cast<char>(code);
                        } else if (starts_with(entity, "&#")) {
                            int code = std::stoi(entity.substr(2, entity.size() - 3));
                            result += static_cast<char>(code);
                        } else {
                            result += entity;
                        }
                    }
                    i = semi;
                    continue;
                }
            }

            // Regular character
            if (!std::isspace(static_cast<unsigned char>(c))) {
                if (in_link) {
                    link_text += c;
                }
                result += c;
                needs_newline = false;
                consecutive_newlines = 0;
            } else if (c == '\n') {
                if (consecutive_newlines < 2) {
                    result += c;
                    ++consecutive_newlines;
                }
            } else {
                result += c;
            }
        }

        // Clean up extra whitespace
        std::string cleaned;
        cleaned.reserve(result.size());
        int newline_count = 0;
        for (char c : result) {
            if (c == '\n') {
                ++newline_count;
                if (newline_count <= 2) {
                    cleaned += c;
                }
            } else {
                newline_count = 0;
                cleaned += c;
            }
        }

        return trim(cleaned);
    }

private:
    static std::string extract_attr(const std::string& tag_buffer, const std::string& attr_name) {
        std::string tag_lower = to_lower(tag_buffer);
        std::string attr_lower = to_lower(attr_name) + "=";

        size_t pos = tag_lower.find(attr_lower);
        if (pos == std::string::npos) return "";

        pos += attr_lower.size();
        if (pos >= tag_buffer.size()) return "";

        char quote = tag_buffer[pos];
        size_t start = pos;
        size_t end;

        if (quote == '"' || quote == '\'') {
            start = pos + 1;
            end = tag_buffer.find(quote, start);
        } else {
            end = tag_buffer.find_first_of(" >", start);
        }

        if (end == std::string::npos) end = tag_buffer.size();
        return tag_buffer.substr(start, end - start);
    }
};

// ============================================================================
// Plain Text to HTML Converter
// ============================================================================

class PlainTextToHtml {
public:
    // Convert plain text to basic HTML
    static std::string convert(const std::string& text, bool detect_urls = true) {
        std::ostringstream ss;
        ss << "<div style=\"white-space: pre-wrap; word-wrap: break-word;\">";

        if (detect_urls) {
            ss << linkify(text);
        } else {
            ss << escape_html(text);
        }

        ss << "</div>";
        return ss.str();
    }

    // Convert plain text to a rich HTML representation
    static std::string convert_rich(const std::string& text) {
        // First, detect and format URLs
        std::string html = linkify(text);

        // Handle line breaks by wrapping in paragraphs
        std::vector<std::string> lines = split(html, '\n');
        std::ostringstream ss;

        bool in_paragraph = false;
        for (const auto& line : lines) {
            std::string trimmed = trim(line);
            if (trimmed.empty()) {
                if (in_paragraph) {
                    ss << "</p>\n";
                    in_paragraph = false;
                }
                continue;
            }

            if (!in_paragraph) {
                ss << "<p>";
                in_paragraph = true;
            } else {
                ss << "<br>\n";
            }
            ss << trimmed;
        }

        if (in_paragraph) {
            ss << "</p>";
        }

        return ss.str();
    }

private:
    // Auto-linkify URLs in text
    static std::string linkify(const std::string& text) {
        std::string result;
        result.reserve(text.size() * 1.1);

        // RFC 3986 based URL regex
        static const std::regex url_re(
            R"(\b(https?://|ftp://|mailto:)[^\s<>"']+[^\s<>"',.;:!?)\]}])",
            std::regex::icase
        );

        std::string escaped = escape_html(text);

        std::sregex_iterator iter(escaped.begin(), escaped.end(), url_re);
        std::sregex_iterator end;
        size_t last_pos = 0;

        for (; iter != end; ++iter) {
            // Append text before the URL
            result += escaped.substr(last_pos, iter->position() - last_pos);

            std::string url = iter->str();
            std::string display_url = url;
            if (display_url.size() > 50) {
                display_url = display_url.substr(0, 47) + "...";
            }

            result += "<a href=\"" + url + "\" rel=\"nofollow\">" +
                      escape_html(display_url) + "</a>";

            last_pos = iter->position() + iter->length();
        }

        // Append remaining text
        result += escaped.substr(last_pos);

        return result;
    }
};

// ============================================================================
// Rich Text Composer
// ============================================================================

class RichTextComposer {
public:
    // Apply bold formatting
    static std::string bold(const std::string& text) {
        return "<strong>" + escape_html(text) + "</strong>";
    }

    // Apply italic formatting
    static std::string italic(const std::string& text) {
        return "<em>" + escape_html(text) + "</em>";
    }

    // Apply underline formatting
    static std::string underline(const std::string& text) {
        return "<u>" + escape_html(text) + "</u>";
    }

    // Apply strikethrough formatting
    static std::string strikethrough(const std::string& text) {
        return "<s>" + escape_html(text) + "</s>";
    }

    // Create a link
    static std::string link(const std::string& text, const std::string& url) {
        return "<a href=\"" + escape_html(url) + "\">" +
               escape_html(text) + "</a>";
    }

    // Create an inline code span
    static std::string code(const std::string& text) {
        return "<code>" + escape_html(text) + "</code>";
    }

    // Create a code block
    static std::string code_block(const std::string& text,
                                  const std::string& language = "") {
        std::ostringstream ss;
        ss << "<pre><code";
        if (!language.empty()) {
            ss << " class=\"language-" << escape_html(language) << "\"";
        }
        ss << ">" << escape_html(text) << "</code></pre>";
        return ss.str();
    }

    // Create an unordered list
    static std::string unordered_list(const std::vector<std::string>& items) {
        std::ostringstream ss;
        ss << "<ul>\n";
        for (const auto& item : items) {
            ss << "  <li>" << item << "</li>\n";
        }
        ss << "</ul>";
        return ss.str();
    }

    // Create an ordered list
    static std::string ordered_list(const std::vector<std::string>& items,
                                    int start = 1) {
        std::ostringstream ss;
        ss << "<ol";
        if (start != 1) ss << " start=\"" << start << "\"";
        ss << ">\n";
        for (const auto& item : items) {
            ss << "  <li>" << item << "</li>\n";
        }
        ss << "</ol>";
        return ss.str();
    }

    // Create a heading
    static std::string heading(const std::string& text, int level = 1) {
        if (level < 1) level = 1;
        if (level > 6) level = 6;
        return "<h" + std::to_string(level) + ">" +
               escape_html(text) + "</h" + std::to_string(level) + ">";
    }

    // Create a horizontal rule
    static std::string horizontal_rule() {
        return "<hr>";
    }

    // Create a blockquote
    static std::string blockquote(const std::string& text) {
        return "<blockquote>" + text + "</blockquote>";
    }

    // Create a line break
    static std::string line_break() {
        return "<br>";
    }

    // Create a paragraph
    static std::string paragraph(const std::string& text) {
        return "<p>" + text + "</p>";
    }

    // Create a span with custom style
    static std::string styled_span(const std::string& text, const std::string& css) {
        return "<span style=\"" + escape_html(css) + "\">" +
               text + "</span>";
    }

    // Create a div with custom style
    static std::string styled_div(const std::string& content, const std::string& css) {
        return "<div style=\"" + escape_html(css) + "\">" + content + "</div>";
    }

    // Wrap content in a table row
    static std::string table_row(const std::vector<std::string>& cells,
                                 bool is_header = false) {
        std::ostringstream ss;
        ss << "<tr>";
        for (const auto& cell : cells) {
            if (is_header) {
                ss << "<th>" << cell << "</th>";
            } else {
                ss << "<td>" << cell << "</td>";
            }
        }
        ss << "</tr>";
        return ss.str();
    }

    // Create a table
    static std::string table(const std::vector<std::vector<std::string>>& rows,
                             const std::vector<std::string>& headers = {},
                             const std::string& css = "") {
        std::ostringstream ss;
        ss << "<table";
        if (!css.empty()) ss << " style=\"" << escape_html(css) << "\"";
        ss << ">\n";

        if (!headers.empty()) {
            ss << "  <thead>\n";
            ss << "    " << table_row(headers, true) << "\n";
            ss << "  </thead>\n";
        }

        ss << "  <tbody>\n";
        for (const auto& row : rows) {
            ss << "    " << table_row(row) << "\n";
        }
        ss << "  </tbody>\n";
        ss << "</table>";
        return ss.str();
    }

    // Build a complete rich-text document
    static std::string build_document(
        const std::vector<std::pair<std::string, std::string>>& elements) {
        // elements is a list of {type, content} pairs
        // types: "h1"-"h6", "p", "ul", "ol", "blockquote", "pre", "hr", "raw"
        std::ostringstream ss;
        for (const auto& [type, content] : elements) {
            if (type == "h1") ss << heading(content, 1);
            else if (type == "h2") ss << heading(content, 2);
            else if (type == "h3") ss << heading(content, 3);
            else if (type == "h4") ss << heading(content, 4);
            else if (type == "h5") ss << heading(content, 5);
            else if (type == "h6") ss << heading(content, 6);
            else if (type == "p") ss << paragraph(content);
            else if (type == "blockquote") ss << blockquote(content);
            else if (type == "pre") ss << code_block(content);
            else if (type == "hr") ss << horizontal_rule();
            else if (type == "raw") ss << content;
            else ss << paragraph(content);  // default to paragraph
        }
        return ss.str();
    }
};

// ============================================================================
// Message Quoting
// ============================================================================

class MessageQuoter {
public:
    struct QuotedMessage {
        std::string text;
        std::string author;
        std::string timestamp;
        bool is_html = false;
    };

    // Format a quoted reply in plain text (email-style >)
    static std::string format_plain_quote(const std::string& text,
                                          const std::string& author,
                                          const std::string& timestamp) {
        std::ostringstream ss;

        // Write attribution
        if (!author.empty() || !timestamp.empty()) {
            if (!author.empty() && !timestamp.empty()) {
                ss << "On " << timestamp << ", " << author << " wrote:\n";
            } else if (!timestamp.empty()) {
                ss << "On " << timestamp << ":\n";
            }
        }

        // Quote each line
        std::istringstream stream(text);
        std::string line;
        while (std::getline(stream, line)) {
            ss << "> " << line << "\n";
        }

        return ss.str();
    }

    // Format a quoted reply in HTML
    static std::string format_html_quote(const std::string& text,
                                         const std::string& author,
                                         const std::string& timestamp,
                                         bool is_html_source = false) {
        std::ostringstream ss;

        // Attribution line
        if (!author.empty() || !timestamp.empty()) {
            ss << "<div class=\"attribution\">";
            if (!author.empty() && !timestamp.empty()) {
                ss << "On " << escape_html(timestamp) << ", "
                   << "<strong>" << escape_html(author) << "</strong> wrote:";
            } else if (!timestamp.empty()) {
                ss << "On " << escape_html(timestamp) << ":";
            }
            ss << "</div>\n";
        }

        // Quoted content
        ss << "<blockquote>\n";
        if (is_html_source) {
            // Already HTML - sanitize and include
            ss << HtmlSanitizer::sanitize(text);
        } else {
            // Plain text - convert
            ss << PlainTextToHtml::convert(text);
        }
        ss << "\n</blockquote>";

        return ss.str();
    }

    // Format the full reply message (new text + quoted old text)
    static std::string build_reply_html(const std::string& new_text,
                                        const QuotedMessage& quoted) {
        std::ostringstream ss;

        // New message content
        ss << "<div class=\"reply-content\">\n";
        ss << PlainTextToHtml::convert(new_text);
        ss << "\n</div>\n\n";

        // Quoted old message
        ss << format_html_quote(quoted.text, quoted.author,
                                quoted.timestamp, quoted.is_html);

        return ss.str();
    }

    // Build full reply in plain text
    static std::string build_reply_plain(const std::string& new_text,
                                         const QuotedMessage& quoted) {
        std::ostringstream ss;

        ss << new_text << "\n\n";
        ss << format_plain_quote(quoted.text, quoted.author, quoted.timestamp);

        return ss.str();
    }

    // Format a multi-level nested quote
    static std::string format_nested_quote_html(
        const std::vector<QuotedMessage>& messages) {
        std::ostringstream ss;

        for (const auto& msg : messages) {
            ss << format_html_quote(msg.text, msg.author,
                                    msg.timestamp, msg.is_html);
        }

        return ss.str();
    }

    // Detect and separate new reply text from quoted text
    struct ReplySplit {
        std::string new_text;
        std::string quoted_text;
        std::string attribution;
    };

    static ReplySplit split_reply(const std::string& full_text) {
        ReplySplit result;

        // Look for common reply separators
        static const std::vector<std::string> kSeparators = {
            "\n> ", "\n\n> ", "\nOn ", "\n\nOn ",
            "\nAm ", "\n\nAm ", "\nLe ", "\n\nLe ",
            "\n-----Original Message-----",
            "\n\n-----Original Message-----"
        };

        size_t best_pos = std::string::npos;
        for (const auto& sep : kSeparators) {
            size_t pos = full_text.find(sep);
            if (pos != std::string::npos) {
                if (best_pos == std::string::npos || pos < best_pos) {
                    best_pos = pos;
                }
            }
        }

        if (best_pos != std::string::npos) {
            result.new_text = trim(full_text.substr(0, best_pos));

            // Skip past the separator
            size_t quote_start = best_pos;
            // Skip newlines before separator
            while (quote_start > 0 && full_text[quote_start - 1] == '\n') {
                --quote_start;
            }
            result.new_text = trim(full_text.substr(0, quote_start));
            result.quoted_text = trim(full_text.substr(best_pos));
        } else {
            result.new_text = full_text;
        }

        return result;
    }
};

// ============================================================================
// Forwarded Message Formatting
// ============================================================================

class ForwardedMessageFormatter {
public:
    struct ForwardedMsg {
        std::string text;
        std::string author;
        std::string timestamp;
        std::string subject;
        std::vector<std::string> attachment_names;
        bool is_html = false;
    };

    // Format a single forwarded message (plain text)
    static std::string format_plain(const ForwardedMsg& msg) {
        std::ostringstream ss;

        ss << "---------- Forwarded message ----------\n";
        if (!msg.author.empty()) {
            ss << "From: " << msg.author << "\n";
        }
        if (!msg.timestamp.empty()) {
            ss << "Date: " << msg.timestamp << "\n";
        }
        if (!msg.subject.empty()) {
            ss << "Subject: " << msg.subject << "\n";
        }
        if (!msg.attachment_names.empty()) {
            ss << "Attachments: ";
            for (size_t i = 0; i < msg.attachment_names.size(); ++i) {
                if (i > 0) ss << ", ";
                ss << msg.attachment_names[i];
            }
            ss << "\n";
        }
        ss << "\n";

        if (msg.is_html) {
            ss << HtmlToPlainText::convert(msg.text);
        } else {
            ss << msg.text;
        }

        return ss.str();
    }

    // Format a single forwarded message (HTML)
    static std::string format_html(const ForwardedMsg& msg) {
        std::ostringstream ss;

        ss << "<div class=\"forwarded-header\">\n";
        ss << "  <strong>\360\237\223\250 Forwarded message</strong><br>\n";
        if (!msg.author.empty()) {
            ss << "  <strong>From:</strong> " << escape_html(msg.author) << "<br>\n";
        }
        if (!msg.timestamp.empty()) {
            ss << "  <strong>Date:</strong> " << escape_html(msg.timestamp) << "<br>\n";
        }
        if (!msg.subject.empty()) {
            ss << "  <strong>Subject:</strong> " << escape_html(msg.subject) << "<br>\n";
        }
        if (!msg.attachment_names.empty()) {
            ss << "  <strong>Attachments:</strong> ";
            for (size_t i = 0; i < msg.attachment_names.size(); ++i) {
                if (i > 0) ss << ", ";
                ss << escape_html(msg.attachment_names[i]);
            }
            ss << "<br>\n";
        }
        ss << "</div>\n\n";

        if (msg.is_html) {
            ss << "<div style=\"padding: 8px 16px;\">\n";
            ss << HtmlSanitizer::sanitize(msg.text);
            ss << "\n</div>";
        } else {
            ss << "<div style=\"padding: 8px 16px; white-space: pre-wrap;\">\n";
            ss << escape_html(msg.text);
            ss << "\n</div>";
        }

        return ss.str();
    }

    // Format multiple forwarded messages as a conversation
    static std::string format_conversation_html(
        const std::vector<ForwardedMsg>& messages) {
        std::ostringstream ss;

        ss << "<div class=\"forwarded-header\" style=\"margin-bottom: 12px;\">\n";
        ss << "  <strong>\360\237\223\250 Forwarded conversation</strong><br>\n";
        ss << "  " << messages.size() << " messages\n";
        ss << "</div>\n\n";

        for (const auto& msg : messages) {
            ss << "<div style=\"margin: 8px 0; padding: 8px 12px; "
               << "border-left: 2px solid #ddd;\">\n";
            ss << "  <div style=\"font-size: 12px; color: #888; margin-bottom: 4px;\">\n";
            if (!msg.author.empty()) {
                ss << "    <strong>" << escape_html(msg.author) << "</strong>";
            }
            if (!msg.timestamp.empty()) {
                if (!msg.author.empty()) ss << " \302\267 ";
                ss << escape_html(msg.timestamp);
            }
            ss << "\n  </div>\n";

            if (msg.is_html) {
                ss << "  " << HtmlSanitizer::sanitize(msg.text) << "\n";
            } else {
                ss << "  <div style=\"white-space: pre-wrap;\">"
                   << escape_html(msg.text) << "</div>\n";
            }
            ss << "</div>\n";
        }

        return ss.str();
    }
};

// ============================================================================
// System Message Formatting
// ============================================================================

class SystemMessageFormatter {
public:
    // System message types
    enum class Type {
        MemberAdded,
        MemberRemoved,
        GroupNameChanged,
        GroupImageChanged,
        GroupImageDeleted,
        ChatProtectionEnabled,
        ChatProtectionDisabled,
        EphemeralTimerChanged,
        EphemeralTimerDisabled,
        LocationEnabled,
        LocationDisabled,
        VideoChatInvitation,
        WebxdcInstance,
        MessageDeleted,
        ChatCreated,
        Custom
    };

    // Format a system message in HTML
    static std::string format_html(Type type,
                                    const std::vector<std::string>& params = {}) {
        std::string message = get_message(type, params);
        std::ostringstream ss;
        ss << "<div class=\"system-msg\">";
        ss << "<span>" << escape_html(message) << "</span>";
        ss << "</div>";
        return ss.str();
    }

    // Format a system message in plain text
    static std::string format_plain(Type type,
                                     const std::vector<std::string>& params = {}) {
        return get_message(type, params);
    }

    // Format a system message with an icon
    static std::string format_html_with_icon(Type type,
                                              const std::string& icon,
                                              const std::vector<std::string>& params = {}) {
        std::string message = get_message(type, params);
        std::ostringstream ss;
        ss << "<div class=\"system-msg\">";
        ss << "<span class=\"emoji\">" << icon << "</span> ";
        ss << "<span>" << escape_html(message) << "</span>";
        ss << "</div>";
        return ss.str();
    }

    // Get a localized-like message string
    static std::string get_message(Type type,
                                    const std::vector<std::string>& params = {}) {
        auto p = [&](size_t i) -> std::string {
            return i < params.size() ? params[i] : "";
        };

        switch (type) {
            case Type::MemberAdded:
                return "Member " + p(0) + " added to group.";
            case Type::MemberRemoved:
                return p(0) + " removed " + p(1) + " from group.";
            case Type::GroupNameChanged:
                return "Group name changed from \"" + p(0) + "\" to \"" + p(1) + "\".";
            case Type::GroupImageChanged:
                return p(0) + " changed the group image.";
            case Type::GroupImageDeleted:
                return p(0) + " removed the group image.";
            case Type::ChatProtectionEnabled:
                return p(0) + " enabled chat protection.";
            case Type::ChatProtectionDisabled:
                return p(0) + " disabled chat protection.";
            case Type::EphemeralTimerChanged:
                return "Disappearing messages timer set to " + p(0) + ".";
            case Type::EphemeralTimerDisabled:
                return "Disappearing messages timer disabled.";
            case Type::LocationEnabled:
                return p(0) + " enabled location streaming.";
            case Type::LocationDisabled:
                return p(0) + " disabled location streaming.";
            case Type::VideoChatInvitation:
                return "Video chat invitation: " + p(0);
            case Type::WebxdcInstance:
                return "App \"" + p(0) + "\" started.";
            case Type::MessageDeleted:
                return "This message was deleted.";
            case Type::ChatCreated:
                return "Chat created.";
            case Type::Custom:
                return p(0);
            default:
                return "";
        }
    }

    // Build system message with action buttons (HTML)
    static std::string format_action_html(Type type,
                                           const std::vector<std::string>& params,
                                           const std::vector<std::pair<std::string, std::string>>& actions) {
        // actions: {label, action_id}
        std::ostringstream ss;
        ss << "<div class=\"system-msg\" style=\"padding: 12px 0;\">\n";
        ss << "  <div>" << escape_html(get_message(type, params)) << "</div>\n";

        if (!actions.empty()) {
            ss << "  <div style=\"margin-top: 8px;\">\n";
            for (const auto& [label, action_id] : actions) {
                ss << "    <span style=\"display: inline-block; padding: 4px 12px; "
                   << "margin: 2px 4px; background: #e8f0fe; border-radius: 4px; "
                   << "cursor: pointer; font-size: 13px;\" "
                   << "data-action=\"" << escape_html(action_id) << "\">"
                   << escape_html(label) << "</span>\n";
            }
            ss << "  </div>\n";
        }

        ss << "</div>";
        return ss.str();
    }
};

// ============================================================================
// CSS Inlining
// ============================================================================

class CssInliner {
public:
    // Inline CSS styles into HTML elements for maximum email client compatibility
    static std::string inline_css(const std::string& html,
                                   const std::string& css) {
        // Parse CSS rules
        auto rules = parse_css(css);

        // Apply rules by walking HTML and matching selectors
        return apply_rules(html, rules);
    }

    // Wrap content in a responsive email template with inlined CSS
    static std::string wrap_email_template(const std::string& content,
                                            const std::string& subject = "",
                                            const std::string& custom_css = "") {
        std::string css = custom_css.empty() ?
            html_config::kDefaultEmailCSS : custom_css;

        std::string template_html = html_config::kEmailTemplate;

        // Replace template variables
        template_html = replace_all(template_html, "{{SUBJECT}}", escape_html(subject));
        template_html = replace_all(template_html, "{{CSS}}", css);

        // Insert content
        std::string content_html = "<div class=\"email-header\">\n";
        if (!subject.empty()) {
            content_html += "  <h2 style=\"margin: 0; font-size: 16px;\">"
                          + escape_html(subject) + "</h2>\n";
        }
        content_html += "</div>\n";
        content_html += "<div class=\"email-body\">\n";
        content_html += content;
        content_html += "\n</div>\n";
        content_html += "<div class=\"email-footer\">\n";
        content_html += "  <span>Sent with Delta Chat</span>\n";
        content_html += "</div>";

        template_html = replace_all(template_html, "{{CONTENT}}", content_html);

        return template_html;
    }

private:
    struct CssRule {
        std::string selector;
        std::map<std::string, std::string> properties;
    };

    static std::vector<CssRule> parse_css(const std::string& css) {
        std::vector<CssRule> rules;

        // Remove comments
        std::string cleaned = css;
        size_t comment_start;
        while ((comment_start = cleaned.find("/*")) != std::string::npos) {
            size_t comment_end = cleaned.find("*/", comment_start + 2);
            if (comment_end != std::string::npos) {
                cleaned.erase(comment_start, comment_end - comment_start + 2);
            } else {
                break;
            }
        }

        // Parse rules
        std::regex rule_re(R"(\s*([^{]+)\s*\{\s*([^}]*)\s*\})");
        std::sregex_iterator iter(cleaned.begin(), cleaned.end(), rule_re);
        std::sregex_iterator end;

        for (; iter != end; ++iter) {
            CssRule rule;
            rule.selector = trim(iter->str(1));

            std::string props = iter->str(2);
            std::regex prop_re(R"(([a-zA-Z-]+)\s*:\s*([^;]+);?)");
            std::sregex_iterator prop_iter(props.begin(), props.end(), prop_re);

            for (; prop_iter != end; ++prop_iter) {
                std::string prop_name = trim(prop_iter->str(1));
                std::string prop_value = trim(prop_iter->str(2));
                rule.properties[prop_name] = prop_value;
            }

            rules.push_back(rule);
        }

        return rules;
    }

    static std::string apply_rules(const std::string& html,
                                    const std::vector<CssRule>& rules) {
        if (rules.empty()) return html;

        // Build a tag-to-style map from the rules
        // This is a simplified approach; a full CSS inliner would need
        // a proper selector engine. For email purposes, we handle common cases.

        std::map<std::string, std::string> tag_styles;
        std::map<std::string, std::string> class_styles;

        for (const auto& rule : rules) {
            std::string style_str;
            for (const auto& [prop, val] : rule.properties) {
                style_str += prop + ": " + val + "; ";
            }
            style_str = trim(style_str);

            std::string sel = trim(rule.selector);
            if (starts_with(sel, ".")) {
                // Class selector
                class_styles[sel.substr(1)] = style_str;
            } else if (sel.find('.') == std::string::npos &&
                       sel.find('#') == std::string::npos &&
                       sel.find(' ') == std::string::npos &&
                       sel.find(':') == std::string::npos) {
                // Simple tag selector
                std::string tag = to_lower(sel);
                if (tag_styles.find(tag) == tag_styles.end()) {
                    tag_styles[tag] = style_str;
                } else {
                    tag_styles[tag] += " " + style_str;
                }
            }
        }

        // Apply styles by walking the HTML
        std::ostringstream result;
        size_t i = 0;
        bool in_tag = false;
        std::string tag_name;

        while (i < html.size()) {
            if (html[i] == '<') {
                // Start of tag - buffer it
                size_t tag_start = i;
                size_t tag_end = html.find('>', i);
                if (tag_end == std::string::npos) {
                    result += html.substr(i);
                    break;
                }

                std::string full_tag = html.substr(tag_start, tag_end - tag_start + 1);
                i = tag_end + 1;

                // Extract tag name
                std::string tag_content = full_tag.substr(1,
                    full_tag.size() - 2);  // remove < and >
                size_t name_end = tag_content.find_first_of(" \t\n/>");
                std::string tag_name = to_lower(
                    name_end == std::string::npos ? tag_content : tag_content.substr(0, name_end));

                // Check if tag already has a style attribute
                bool has_style = full_tag.find("style=") != std::string::npos;
                bool has_class = full_tag.find("class=") != std::string::npos;

                if (!has_style && (tag_styles.count(tag_name) || has_class)) {
                    std::string new_style;

                    // Add tag-based style
                    if (tag_styles.count(tag_name)) {
                        new_style += tag_styles[tag_name];
                    }

                    // Add class-based styles
                    if (has_class) {
                        std::string class_attr = extract_attr_value(full_tag, "class");
                        auto classes = split(class_attr, ' ');
                        for (const auto& cls : classes) {
                            std::string clean_cls = trim(cls);
                            if (class_styles.count(clean_cls)) {
                                if (!new_style.empty()) new_style += " ";
                                new_style += class_styles[clean_cls];
                            }
                        }
                    }

                    if (!new_style.empty()) {
                        // Insert style attribute before closing >
                        size_t insert_pos = full_tag.size() - 1;
                        if (full_tag[insert_pos - 1] == '/') {
                            --insert_pos;
                        }
                        full_tag.insert(insert_pos, " style=\"" + new_style + "\"");
                    }
                }

                result << full_tag;
            } else {
                result << html[i];
                ++i;
            }
        }

        return result.str();
    }

    static std::string extract_attr_value(const std::string& tag,
                                           const std::string& attr_name) {
        std::string tag_lower = to_lower(tag);
        std::string attr_lower = to_lower(attr_name) + "=\"";
        size_t pos = tag_lower.find(attr_lower);
        if (pos == std::string::npos) {
            attr_lower = to_lower(attr_name) + "='";
            pos = tag_lower.find(attr_lower);
            if (pos == std::string::npos) return "";
        }

        pos += attr_lower.size();
        char quote = tag[pos - 1];
        size_t end = tag.find(quote, pos);
        if (end == std::string::npos) return "";
        return tag.substr(pos, end - pos);
    }
};

// ============================================================================
// Multipart/Alternative MIME Builder
// ============================================================================

class MultipartMimeBuilder {
public:
    struct MimePart {
        std::string content_type;
        std::string charset = "UTF-8";
        std::string content_transfer_encoding = "quoted-printable";
        std::string content_id;
        std::string content_disposition;
        std::string filename;
        std::string data;
        bool is_attachment = false;
    };

    struct MimeMessage {
        std::string subject;
        std::string from;
        std::string to;
        std::string cc;
        std::string bcc;
        std::string date;
        std::string message_id;
        std::string in_reply_to;
        std::string references;
        std::string plain_text;
        std::string html_text;
        std::vector<MimePart> attachments;
        std::vector<MimePart> inline_images;
        std::map<std::string, std::string> extra_headers;
    };

    // Build a complete MIME message with multipart/alternative
    static std::string build(const MimeMessage& msg) {
        bool has_attachments = !msg.attachments.empty() || !msg.inline_images.empty();
        bool has_both = !msg.plain_text.empty() && !msg.html_text.empty();

        std::string boundary_outer = generate_boundary();
        std::string boundary_alt = generate_boundary();
        std::string boundary_related = generate_boundary();

        std::ostringstream ss;

        // Headers
        ss << build_headers(msg);

        if (has_attachments) {
            ss << "Content-Type: multipart/mixed; boundary=\"" << boundary_outer << "\"\r\n";
        } else if (has_both) {
            ss << "Content-Type: multipart/alternative; boundary=\""
               << boundary_alt << "\"\r\n";
        } else if (!msg.html_text.empty()) {
            ss << "Content-Type: text/html; charset=UTF-8\r\n";
            ss << "Content-Transfer-Encoding: quoted-printable\r\n";
        } else {
            ss << "Content-Type: text/plain; charset=UTF-8\r\n";
            ss << "Content-Transfer-Encoding: quoted-printable\r\n";
        }
        ss << "\r\n";

        if (has_attachments) {
            // Outer multipart/mixed
            ss << "--" << boundary_outer << "\r\n";

            if (has_both) {
                // Inner multipart/alternative
                ss << "Content-Type: multipart/alternative; boundary=\""
                   << boundary_alt << "\"\r\n\r\n";
                ss << "--" << boundary_alt << "\r\n";
                ss << "Content-Type: text/plain; charset=UTF-8\r\n";
                ss << "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
                ss << encode_quoted_printable(msg.plain_text) << "\r\n";
                ss << "--" << boundary_alt << "\r\n";
                ss << "Content-Type: text/html; charset=UTF-8\r\n";
                ss << "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
                ss << encode_quoted_printable(msg.html_text) << "\r\n";
                ss << "--" << boundary_alt << "--\r\n";
            } else if (!msg.html_text.empty()) {
                ss << "Content-Type: text/html; charset=UTF-8\r\n";
                ss << "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
                ss << encode_quoted_printable(msg.html_text) << "\r\n";
            } else {
                ss << "Content-Type: text/plain; charset=UTF-8\r\n";
                ss << "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
                ss << encode_quoted_printable(msg.plain_text) << "\r\n";
            }

            // Inline images
            for (const auto& img : msg.inline_images) {
                ss << "--" << boundary_outer << "\r\n";
                ss << build_part_headers(img) << "\r\n";
                ss << encode_base64_content(img.data) << "\r\n";
            }

            // Attachments
            for (const auto& att : msg.attachments) {
                ss << "--" << boundary_outer << "\r\n";
                ss << build_part_headers(att) << "\r\n";
                ss << encode_base64_content(att.data) << "\r\n";
            }

            ss << "--" << boundary_outer << "--\r\n";
        } else if (has_both) {
            // Just multipart/alternative
            ss << "--" << boundary_alt << "\r\n";
            ss << "Content-Type: text/plain; charset=UTF-8\r\n";
            ss << "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
            ss << encode_quoted_printable(msg.plain_text) << "\r\n";
            ss << "--" << boundary_alt << "\r\n";
            ss << "Content-Type: text/html; charset=UTF-8\r\n";
            ss << "Content-Transfer-Encoding: quoted-printable\r\n\r\n";
            ss << encode_quoted_printable(msg.html_text) << "\r\n";
            ss << "--" << boundary_alt << "--\r\n";
        } else if (!msg.html_text.empty()) {
            ss << encode_quoted_printable(msg.html_text) << "\r\n";
        } else {
            ss << encode_quoted_printable(msg.plain_text) << "\r\n";
        }

        return ss.str();
    }

    // Build only the headers portion
    static std::string build_headers(const MimeMessage& msg) {
        std::ostringstream ss;

        ss << "From: " << msg.from << "\r\n";
        ss << "To: " << msg.to << "\r\n";
        if (!msg.cc.empty()) ss << "Cc: " << msg.cc << "\r\n";
        if (!msg.bcc.empty()) ss << "Bcc: " << msg.bcc << "\r\n";
        if (!msg.subject.empty()) {
            ss << "Subject: " << encode_header(msg.subject) << "\r\n";
        }
        if (!msg.date.empty()) {
            ss << "Date: " << msg.date << "\r\n";
        } else {
            ss << "Date: " << format_rfc2822_date() << "\r\n";
        }
        if (!msg.message_id.empty()) ss << "Message-ID: " << msg.message_id << "\r\n";
        if (!msg.in_reply_to.empty()) ss << "In-Reply-To: " << msg.in_reply_to << "\r\n";
        if (!msg.references.empty()) ss << "References: " << msg.references << "\r\n";
        ss << "MIME-Version: 1.0\r\n";

        // Extra headers
        for (const auto& [key, value] : msg.extra_headers) {
            ss << key << ": " << value << "\r\n";
        }

        return ss.str();
    }

    // Build MIME part headers for an attachment/inline image
    static std::string build_part_headers(const MimePart& part) {
        std::ostringstream ss;

        ss << "Content-Type: " << part.content_type;
        if (!part.charset.empty() && part.content_type.find("text/") == 0) {
            ss << "; charset=" << part.charset;
        }
        if (!part.filename.empty()) {
            ss << "; name=\"" << part.filename << "\"";
        }
        ss << "\r\n";

        ss << "Content-Transfer-Encoding: " << part.content_transfer_encoding << "\r\n";

        if (!part.content_id.empty()) {
            ss << "Content-ID: <" << part.content_id << ">\r\n";
        }

        if (!part.content_disposition.empty()) {
            ss << "Content-Disposition: " << part.content_disposition;
            if (!part.filename.empty()) {
                ss << "; filename=\"" << part.filename << "\"";
            }
            ss << "\r\n";
        } else if (!part.filename.empty()) {
            std::string disposition = part.is_attachment ? "attachment" : "inline";
            ss << "Content-Disposition: " << disposition
               << "; filename=\"" << part.filename << "\"\r\n";
        }

        return ss.str();
    }

    // Create an HTML part containing inline images
    static std::string build_html_with_inline_images(
        const std::string& html,
        const std::vector<std::pair<std::string, std::string>>& images) {
        // images: {cid, local_path}
        std::string result = html;

        for (const auto& [cid, path] : images) {
            std::string cid_ref = "cid:" + cid;
            result = replace_all(result, "{{IMG:" + cid + "}}", cid_ref);
        }

        return result;
    }

private:
    // Encode a string for email headers (RFC 2047)
    static std::string encode_header(const std::string& text) {
        // Check if encoding is needed
        bool needs_encode = false;
        for (unsigned char c : text) {
            if (c > 127 || c < 32 || c == '=' || c == '?' || c == '_') {
                needs_encode = true;
                break;
            }
        }

        if (!needs_encode) return text;

        // Use base64 encoding for the header value
        std::string encoded = base64_encode(text);
        return "=?UTF-8?B?" + encoded + "?=";
    }

    // Quoted-printable encoding
    static std::string encode_quoted_printable(const std::string& input) {
        std::ostringstream ss;
        int line_len = 0;

        for (unsigned char c : input) {
            if (c == '\r') continue;  // Skip CR in CRLF

            if (c == '\n') {
                ss << "\r\n";
                line_len = 0;
            } else if ((c >= 33 && c <= 60) || (c >= 62 && c <= 126) ||
                       c == ' ' || c == '\t') {
                // Printable ASCII (excluding '=')
                if (line_len >= 75) {
                    ss << "=\r\n";
                    line_len = 0;
                }
                ss << c;
                ++line_len;
            } else {
                if (line_len >= 73) {
                    ss << "=\r\n";
                    line_len = 0;
                }
                ss << '=' << std::uppercase << std::hex << std::setw(2)
                   << std::setfill('0') << static_cast<int>(c)
                   << std::nouppercase;
                line_len += 3;
            }
        }

        return ss.str();
    }

    // Encode binary content as base64 with line wrapping
    static std::string encode_base64_content(const std::string& data) {
        std::string encoded = base64_encode(data);
        std::ostringstream ss;

        for (size_t i = 0; i < encoded.size(); i += 76) {
            if (i > 0) ss << "\r\n";
            ss << encoded.substr(i, 76);
        }

        return ss.str();
    }

    // Format current time as RFC 2822
    static std::string format_rfc2822_date() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        struct tm tm_info;
        gmtime_r(&time, &tm_info);

        static const char* kDays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
        static const char* kMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

        char buf[128];
        snprintf(buf, sizeof(buf),
                 "%s, %02d %s %04d %02d:%02d:%02d +0000",
                 kDays[tm_info.tm_wday], tm_info.tm_mday, kMonths[tm_info.tm_mon],
                 tm_info.tm_year + 1900, tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);

        return buf;
    }
};

// ============================================================================
// Inline Image Handler
// ============================================================================

class InlineImageHandler {
public:
    struct ImageInfo {
        std::string content_id;
        std::string mime_type;
        std::string filename;
        std::string data;         // raw bytes
        int width = 0;
        int height = 0;
        std::string alt_text;
    };

    // Generate an HTML img tag for an inline image
    static std::string generate_img_tag(const ImageInfo& info,
                                         int max_width = 0) {
        std::ostringstream ss;
        ss << "<img src=\"cid:" << escape_html(info.content_id) << "\"";
        ss << " alt=\"" << escape_html(info.alt_text.empty() ? info.filename : info.alt_text) << "\"";

        if (info.width > 0 && info.height > 0) {
            if (max_width > 0 && info.width > max_width) {
                float ratio = static_cast<float>(max_width) / info.width;
                int new_height = static_cast<int>(info.height * ratio);
                ss << " width=\"" << max_width << "\" height=\"" << new_height << "\"";
            } else {
                ss << " width=\"" << info.width << "\" height=\"" << info.height << "\"";
            }
        }

        ss << " style=\"max-width: 100%; height: auto; border-radius: 4px;\"";
        ss << " class=\"inline-image\">";
        return ss.str();
    }

    // Create a MimePart for an inline image
    static MultipartMimeBuilder::MimePart create_mime_part(const ImageInfo& info) {
        MultipartMimeBuilder::MimePart part;
        part.content_type = info.mime_type;
        part.content_transfer_encoding = "base64";
        part.content_id = info.content_id;
        part.content_disposition = "inline";
        part.filename = info.filename;
        part.data = info.data;
        part.is_attachment = false;
        return part;
    }

    // Guess MIME type from filename extension
    static std::string guess_mime_type(const std::string& filename) {
        std::string lower = to_lower(filename);
        size_t dot = lower.rfind('.');
        if (dot == std::string::npos) return "application/octet-stream";

        std::string ext = lower.substr(dot + 1);
        if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
        if (ext == "png") return "image/png";
        if (ext == "gif") return "image/gif";
        if (ext == "webp") return "image/webp";
        if (ext == "svg") return "image/svg+xml";
        if (ext == "bmp") return "image/bmp";
        if (ext == "ico") return "image/x-icon";
        if (ext == "tiff" || ext == "tif") return "image/tiff";
        return "application/octet-stream";
    }

    // Extract inline image references from HTML
    static std::vector<std::string> extract_cids(const std::string& html) {
        std::vector<std::string> cids;
        std::regex cid_re(R"(src="cid:([^"]+)")", std::regex::icase);

        std::sregex_iterator iter(html.begin(), html.end(), cid_re);
        std::sregex_iterator end;

        for (; iter != end; ++iter) {
            cids.push_back(iter->str(1));
        }

        return cids;
    }

    // Replace cid: references with actual image data (base64 data URIs) for display
    static std::string embed_images_as_data_uris(
        const std::string& html,
        const std::map<std::string, ImageInfo>& images) {
        std::string result = html;

        for (const auto& [cid, info] : images) {
            std::string cid_ref = "cid:" + cid;
            std::string data_uri = "data:" + info.mime_type + ";base64," +
                                   base64_encode(info.data);

            result = replace_all(result, cid_ref, data_uri);
        }

        return result;
    }
};

// ============================================================================
// Markdown to HTML Converter
// ============================================================================

class MarkdownToHtml {
public:
    // Convert Markdown text to HTML
    static std::string convert(const std::string& markdown) {
        std::string result;
        result.reserve(markdown.size() * 1.2);

        std::vector<std::string> lines = split(markdown, '\n');

        enum class BlockState {
            Normal,
            Paragraph,
            CodeBlock,
            UnorderedList,
            OrderedList,
            Blockquote,
            Heading
        };

        BlockState state = BlockState::Normal;
        std::string code_language;
        std::string current_para;

        auto flush_paragraph = [&]() {
            if (!current_para.empty()) {
                result += "<p>" + process_inline_formatting(current_para) + "</p>\n";
                current_para.clear();
            }
        };

        for (size_t line_idx = 0; line_idx < lines.size(); ++line_idx) {
            std::string line = lines[line_idx];
            std::string trimmed = trim(line);

            // Code block detection (fenced)
            if (starts_with(trimmed, "```")) {
                if (state == BlockState::CodeBlock) {
                    result += "</code></pre>\n";
                    state = BlockState::Normal;
                } else {
                    flush_paragraph();
                    code_language = trim(trimmed.substr(3));
                    result += "<pre><code";
                    if (!code_language.empty()) {
                        result += " class=\"language-" + escape_html(code_language) + "\"";
                    }
                    result += ">\n";
                    state = BlockState::CodeBlock;
                }
                continue;
            }

            if (state == BlockState::CodeBlock) {
                result += escape_html(line) + "\n";
                continue;
            }

            // Empty line
            if (trimmed.empty()) {
                flush_paragraph();
                if (state == BlockState::UnorderedList) {
                    result += "</ul>\n";
                    state = BlockState::Normal;
                } else if (state == BlockState::OrderedList) {
                    result += "</ol>\n";
                    state = BlockState::Normal;
                } else if (state == BlockState::Blockquote) {
                    result += "</blockquote>\n";
                    state = BlockState::Normal;
                }
                continue;
            }

            // Heading
            if (starts_with(trimmed, "#")) {
                flush_paragraph();
                int level = 0;
                while (level < 6 && level < static_cast<int>(trimmed.size()) &&
                       trimmed[level] == '#') {
                    ++level;
                }

                std::string heading_text = trim(trimmed.substr(level));

                // Check for closing #s
                if (ends_with(heading_text, "#")) {
                    size_t end_hash = heading_text.find_last_not_of("#");
                    if (end_hash != std::string::npos) {
                        heading_text = trim(heading_text.substr(0, end_hash + 1));
                    }
                }

                result += "<h" + std::to_string(level) + ">" +
                          process_inline_formatting(heading_text) +
                          "</h" + std::to_string(level) + ">\n";
                state = BlockState::Heading;
                continue;
            }

            // Horizontal rule
            if (trimmed == "---" || trimmed == "***" || trimmed == "___" ||
                trimmed == "- - -" || trimmed == "* * *") {
                flush_paragraph();
                result += "<hr>\n";
                state = BlockState::Normal;
                continue;
            }

            // Blockquote
            if (starts_with(trimmed, "> ")) {
                if (state != BlockState::Blockquote) {
                    flush_paragraph();
                    result += "<blockquote>\n";
                    state = BlockState::Blockquote;
                }

                std::string quote_content = trimmed.substr(2);
                result += "<p>" + process_inline_formatting(quote_content) + "</p>\n";
                continue;
            }

            // Unordered list
            if (starts_with(trimmed, "* ") || starts_with(trimmed, "- ") ||
                starts_with(trimmed, "+ ")) {
                if (state != BlockState::UnorderedList) {
                    flush_paragraph();
                    result += "<ul>\n";
                    state = BlockState::UnorderedList;
                }

                std::string item = trim(trimmed.substr(2));
                result += "<li>" + process_inline_formatting(item) + "</li>\n";
                continue;
            }

            // Ordered list
            std::regex ol_re(R"(^(\d+)\.\s+(.+))");
            std::smatch ol_match;
            if (std::regex_match(trimmed, ol_match, ol_re)) {
                if (state != BlockState::OrderedList) {
                    flush_paragraph();
                    result += "<ol>\n";
                    state = BlockState::OrderedList;
                }

                std::string item = ol_match[2].str();
                result += "<li>" + process_inline_formatting(item) + "</li>\n";
                continue;
            }

            // Regular paragraph
            if (state == BlockState::Normal || state == BlockState::Heading) {
                state = BlockState::Paragraph;
            }

            if (!current_para.empty()) {
                current_para += " ";
            }
            current_para += trimmed;
        }

        // Flush remaining state
        flush_paragraph();
        if (state == BlockState::CodeBlock) {
            result += "</code></pre>\n";
        } else if (state == BlockState::UnorderedList) {
            result += "</ul>\n";
        } else if (state == BlockState::OrderedList) {
            result += "</ol>\n";
        } else if (state == BlockState::Blockquote) {
            result += "</blockquote>\n";
        }

        return result;
    }

private:
    // Process inline formatting: bold, italic, code, links, images
    static std::string process_inline_formatting(const std::string& text) {
        std::string result = escape_html(text);

        // Images: ![alt](url)
        std::regex img_re(R"(!\[([^\]]*)\]\(([^)]+)\))");
        result = std::regex_replace(result, img_re,
            "<img src=\"$2\" alt=\"$1\" style=\"max-width:100%;\">");

        // Links: [text](url)
        std::regex link_re(R"(\[([^\]]+)\]\(([^)]+)\))");
        result = std::regex_replace(result, link_re,
            "<a href=\"$2\">$1</a>");

        // Bold: **text** or __text__
        std::regex bold_re(R"(\*\*([^*]+)\*\*)");
        result = std::regex_replace(result, bold_re, "<strong>$1</strong>");

        std::regex bold_re2(R"(__([^_]+)__)");
        result = std::regex_replace(result, bold_re2, "<strong>$1</strong>");

        // Italic: *text* or _text_
        std::regex italic_re(R"(\*([^*]+)\*)");
        result = std::regex_replace(result, italic_re, "<em>$1</em>");

        std::regex italic_re2(R"(_([^_]+)_)");
        result = std::regex_replace(result, italic_re2, "<em>$1</em>");

        // Inline code: `text`
        std::regex code_re(R"(`([^`]+)`)");
        result = std::regex_replace(result, code_re, "<code>$1</code>");

        // Strikethrough: ~~text~~
        std::regex strike_re(R"(~~([^~]+)~~)");
        result = std::regex_replace(result, strike_re, "<s>$1</s>");

        return result;
    }
};

// ============================================================================
// Emoji Shortcode Expander
// ============================================================================

class EmojiExpander {
public:
    // Expand common emoji shortcodes to Unicode emoji
    static std::string expand(const std::string& text) {
        std::string result;
        result.reserve(text.size());

        size_t i = 0;
        while (i < text.size()) {
            if (text[i] == ':' && i + 2 < text.size()) {
                // Look for closing colon
                size_t end = text.find(':', i + 1);
                if (end != std::string::npos && end > i + 1) {
                    std::string shortcode = text.substr(i + 1, end - i - 1);
                    auto it = kEmojiMap.find(shortcode);
                    if (it != kEmojiMap.end()) {
                        result += it->second;
                        i = end + 1;
                        continue;
                    }
                }
            }
            result += text[i];
            ++i;
        }

        return result;
    }

    // Expand shortcodes with HTML span for consistent rendering
    static std::string expand_html(const std::string& text) {
        std::string result;
        result.reserve(text.size());

        size_t i = 0;
        while (i < text.size()) {
            if (text[i] == ':' && i + 2 < text.size()) {
                size_t end = text.find(':', i + 1);
                if (end != std::string::npos && end > i + 1) {
                    std::string shortcode = text.substr(i + 1, end - i - 1);
                    auto it = kEmojiMap.find(shortcode);
                    if (it != kEmojiMap.end()) {
                        result += "<span class=\"emoji\" title=\"" +
                                  escape_html(shortcode) + "\">" +
                                  it->second + "</span>";
                        i = end + 1;
                        continue;
                    }
                }
            }
            result += text[i];
            ++i;
        }

        return result;
    }

    // Check if a shortcode is known
    static bool is_known_shortcode(const std::string& shortcode) {
        return kEmojiMap.find(shortcode) != kEmojiMap.end();
    }

    // Get emoji from shortcode
    static std::string get_emoji(const std::string& shortcode) {
        auto it = kEmojiMap.find(shortcode);
        return it != kEmojiMap.end() ? it->second : "";
    }

private:
    static const std::unordered_map<std::string, std::string> kEmojiMap;
};

// Emoji map initialization
const std::unordered_map<std::string, std::string> EmojiExpander::kEmojiMap = {
    // Smileys
    {":smile:", "\360\237\230\204"}, {":grinning:", "\360\237\230\200"},
    {":joy:", "\360\237\230\202"}, {":rofl:", "\360\237\244\243"},
    {":wink:", "\360\237\230\211"}, {":blush:", "\360\237\230\212"},
    {":heart_eyes:", "\360\237\230\215"}, {":kissing_heart:", "\360\237\230\230"},
    {":stuck_out_tongue:", "\360\237\230\233"}, {":thinking:", "\360\237\244\224"},
    {":neutral_face:", "\360\237\230\220"}, {":expressionless:", "\360\237\230\221"},
    {":unamused:", "\360\237\230\222"}, {":roll_eyes:", "\360\237\231\204"},
    {":sweat_smile:", "\360\237\230\205"}, {":innocent:", "\360\237\230\207"},
    {":slight_smile:", "\360\237\231\202"}, {":upside_down:", "\360\237\231\203"},
    {":relaxed:", "\360\237\230\214"}, {":yum:", "\360\237\230\213"},
    {":relieved:", "\360\237\230\214"}, {":heart:", "\360\237\230\215"},
    {":sunglasses:", "\360\237\230\216"}, {":smirk:", "\360\237\230\217"},
    {":cry:", "\360\237\230\242"}, {":sob:", "\360\237\230\255"},
    {":angry:", "\360\237\230\240"}, {":rage:", "\360\237\230\241"},
    {":triumph:", "\360\237\230\244"}, {":disappointed:", "\360\237\230\236"},
    {":fearful:", "\360\237\230\250"}, {":weary:", "\360\237\230\251"},
    {":tired_face:", "\360\237\230\253"}, {":sleeping:", "\360\237\230\264"},
    {":mask:", "\360\237\230\267"}, {":dizzy_face:", "\360\237\230\265"},
    {":hot_face:", "\360\237\245\265"}, {":cold_face:", "\360\237\245\266"},
    {":scream:", "\360\237\230\261"}, {":confounded:", "\360\237\230\226"},
    {":flushed:", "\360\237\230\263"}, {":pleading_face:", "\360\237\245\272"},
    {":pensive:", "\360\237\230\224"}, {":sleepy:", "\360\237\230\252"},
    {":drooling_face:", "\360\237\244\244"}, {":shushing_face:", "\360\237\244\253"},
    {":hand_over_mouth:", "\360\237\244\255"}, {":face_with_monocle:", "\360\237\247\220"},
    {":nerd:", "\360\237\244\223"}, {":cowboy:", "\360\237\244\240"},
    {":clown:", "\360\237\244\241"}, {":lying_face:", "\360\237\244\245"},
    {":zipper_mouth:", "\360\237\244\220"}, {":money_mouth:", "\360\237\244\221"},
    {":thermometer_face:", "\360\237\244\222"}, {":hugging:", "\360\237\244\227"},
    {":partying_face:", "\360\237\245\263"}, {":woozy:", "\360\237\245\264"},
    {":exploding_head:", "\360\237\244\257"}, {":face_with_symbols:", "\360\237\244\254"},
    {":rage:", "\360\237\230\241"}, {":yawning_face:", "\360\237\245\261"},

    // Gestures
    {":wave:", "\360\237\221\213"}, {":raised_back_of_hand:", "\360\237\244\232"},
    {":hand:", "\360\237\234\220"}, {":spock:", "\360\237\226\226"},
    {":ok_hand:", "\360\237\221\214"}, {":pinching_hand:", "\360\237\244\217"},
    {":v:", "\342\234\214"}, {":crossed_fingers:", "\360\237\244\236"},
    {":love_you_gesture:", "\360\237\244\237"}, {":metal:", "\360\237\244\230"},
    {":call_me:", "\360\237\244\231"}, {":point_left:", "\360\237\221\210"},
    {":point_right:", "\360\237\221\211"}, {":point_up_2:", "\360\237\221\206"},
    {":point_down:", "\360\237\221\207"}, {":point_up:", "\342\230\235"},
    {":thumbsup:", "\360\237\221\215"}, {":thumbsdown:", "\360\237\221\216"},
    {":fist:", "\342\234\212"}, {":punch:", "\360\237\221\212"},
    {":clap:", "\360\237\221\217"}, {":raised_hands:", "\360\237\231\214"},
    {":open_hands:", "\360\237\220\220"}, {":palms_up:", "\360\237\244\262"},
    {":handshake:", "\360\237\244\235"}, {":pray:", "\360\237\231\217"},
    {":writing_hand:", "\342\234\215"}, {":nail_care:", "\360\237\222\205"},
    {":selfie:", "\360\237\244\263"}, {":muscle:", "\360\237\222\252"},
    {":leg:", "\360\237\246\265"}, {":foot:", "\360\237\246\266"},
    {":ear:", "\360\237\221\202"}, {":nose:", "\360\237\221\203"},
    {":brain:", "\360\237\247\240"}, {":mechanical_arm:", "\360\237\246\276"},
    {":mechanical_leg:", "\360\237\246\277"},

    // Hearts
    {":red_heart:", "\342\235\244"}, {":orange_heart:", "\360\237\247\241"},
    {":yellow_heart:", "\360\237\222\233"}, {":green_heart:", "\360\237\222\232"},
    {":blue_heart:", "\360\237\222\231"}, {":purple_heart:", "\360\237\222\234"},
    {":black_heart:", "\360\237\226\244"}, {":white_heart:", "\360\237\244\215"},
    {":brown_heart:", "\360\237\244\216"}, {":broken_heart:", "\360\237\222\224"},
    {":heart_exclamation:", "\342\235\243"}, {":two_hearts:", "\360\237\222\225"},
    {":revolving_hearts:", "\360\237\222\236"}, {":heartbeat:", "\360\237\222\223"},
    {":heartpulse:", "\360\237\222\227"}, {":sparkling_heart:", "\360\237\222\226"},
    {":cupid:", "\360\237\222\230"}, {":gift_heart:", "\360\237\222\235"},
    {":heart_decoration:", "\360\237\222\237"},

    // Common symbols
    {":heavy_check_mark:", "\342\234\224"}, {":x:", "\342\235\214"},
    {":warning:", "\342\232\240"}, {":no_entry:", "\342\233\224"},
    {":question:", "\342\235\223"}, {":grey_question:", "\342\235\224"},
    {":exclamation:", "\342\235\227"}, {":grey_exclamation:", "\342\235\225"},
    {":zzz:", "\360\237\222\244"}, {":anger:", "\360\237\222\242"},
    {":boom:", "\360\237\222\245"}, {":dizzy:", "\360\237\222\253"},
    {":sweat_drops:", "\360\237\222\246"}, {":dash:", "\360\237\222\250"},
    {":hole:", "\360\237\225\263"}, {":bomb:", "\360\237\222\243"},
    {":speech_balloon:", "\360\237\222\254"}, {":thought_balloon:", "\360\237\222\255"},
    {":eye_in_speech:", "\360\237\221\201\342\200\215\360\237\227\250"},

    // Arrows
    {":arrow_right:", "\342\236\241"}, {":arrow_left:", "\342\254\205"},
    {":arrow_up:", "\342\254\206"}, {":arrow_down:", "\342\254\207"},
    {":arrow_upper_right:", "\342\206\227"}, {":arrow_lower_right:", "\342\206\230"},
    {":arrow_lower_left:", "\342\206\231"}, {":arrow_upper_left:", "\342\206\226"},
    {":arrow_up_down:", "\342\206\225"}, {":left_right_arrow:", "\342\206\224"},
    {":leftwards_arrow_with_hook:", "\342\206\252"}, {":arrow_right_hook:", "\342\206\252"},
    {":arrow_forward:", "\342\226\266"}, {":arrow_backward:", "\342\227\200"},
    {":arrow_up_small:", "\360\237\224\204"}, {":arrow_down_small:", "\360\237\224\205"},
    {":arrow_double_up:", "\342\217\253"}, {":arrow_double_down:", "\342\217\254"},
    {":arrows_counterclockwise:", "\360\237\224\204"},

    // Time
    {":hourglass:", "\342\214\233"}, {":hourglass_flowing_sand:", "\342\217\263"},
    {":watch:", "\342\214\232"}, {":alarm_clock:", "\342\217\260"},
    {":stopwatch:", "\342\217\261"}, {":timer:", "\342\217\262"},
    {":clock:", "\360\237\225\220"}, {":calendar:", "\360\237\223\206"},
    {":calendar_spiral:", "\360\237\227\223"},

    // Weather
    {":sunny:", "\342\230\200"}, {":cloud:", "\342\230\201"},
    {":umbrella:", "\342\230\224"}, {":snowman:", "\342\233\204"},
    {":comet:", "\342\230\204"}, {":zap:", "\342\232\241"},
    {":fire:", "\360\237\224\245"}, {":droplet:", "\360\237\222\247"},
    {":ocean:", "\360\237\214\212"}, {":snowflake:", "\342\235\204"},
    {":partly_sunny:", "\342\233\205"}, {":rainbow:", "\360\237\214\210"},
    {":tornado:", "\360\237\214\252"}, {":fog:", "\360\237\214\253"},
    {":wind_face:", "\360\237\214\254"}, {":cyclone:", "\360\237\214\252"},

    // Animals
    {":dog:", "\360\237\220\266"}, {":cat:", "\360\237\220\261"},
    {":mouse:", "\360\237\220\255"}, {":hamster:", "\360\237\220\271"},
    {":rabbit:", "\360\237\220\260"}, {":fox:", "\360\237\246\212"},
    {":bear:", "\360\237\220\273"}, {":panda:", "\360\237\220\274"},
    {":koala:", "\360\237\220\250"}, {":tiger:", "\360\237\220\257"},
    {":lion:", "\360\237\246\201"}, {":cow:", "\360\237\220\256"},
    {":pig:", "\360\237\220\267"}, {":frog:", "\360\237\220\270"},
    {":monkey:", "\360\237\220\222"}, {":chicken:", "\360\237\220\224"},
    {":penguin:", "\360\237\220\247"}, {":bird:", "\360\237\220\246"},
    {":eagle:", "\360\237\246\205"}, {":duck:", "\360\237\246\206"},
    {":owl:", "\360\237\246\211"}, {":bat:", "\360\237\246\207"},
    {":wolf:", "\360\237\220\272"}, {":unicorn:", "\360\237\246\204"},
    {":whale:", "\360\237\220\263"}, {":dolphin:", "\360\237\220\254"},
    {":fish:", "\360\237\220\237"}, {":tropical_fish:", "\360\237\220\240"},
    {":blowfish:", "\360\237\220\241"}, {":shark:", "\360\237\246\210"},
    {":octopus:", "\360\237\220\231"}, {":shell:", "\360\237\220\232"},
    {":snail:", "\360\237\220\214"}, {":butterfly:", "\360\237\246\213"},
    {":bug:", "\360\237\220\233"}, {":ant:", "\360\237\220\234"},
    {":bee:", "\360\237\220\235"}, {":lady_beetle:", "\360\237\220\236"},
    {":spider:", "\360\237\225\267"}, {":scorpion:", "\360\237\246\202"},
    {":snake:", "\360\237\220\215"}, {":lizard:", "\360\237\246\216"},
    {":t-rex:", "\360\237\246\226"}, {":sauropod:", "\360\237\246\225"},

    // Food
    {":apple:", "\360\237\215\216"}, {":green_apple:", "\360\237\215\217"},
    {":orange:", "\360\237\215\212"}, {":lemon:", "\360\237\215\213"},
    {":banana:", "\360\237\215\214"}, {":watermelon:", "\360\237\215\211"},
    {":grapes:", "\360\237\215\207"}, {":strawberry:", "\360\237\215\223"},
    {":cherries:", "\360\237\215\222"}, {":peach:", "\360\237\215\221"},
    {":pear:", "\360\237\215\220"}, {":pineapple:", "\360\237\215\215"},
    {":coconut:", "\360\237\245\245"}, {":kiwi:", "\360\237\245\235"},
    {":mango:", "\360\237\245\255"}, {":avocado:", "\360\237\245\221"},
    {":broccoli:", "\360\237\245\246"}, {":tomato:", "\360\237\215\205"},
    {":eggplant:", "\360\237\215\206"}, {":corn:", "\360\237\214\275"},
    {":carrot:", "\360\237\245\225"}, {":potato:", "\360\237\245\224"},
    {":garlic:", "\360\237\247\204"}, {":onion:", "\360\237\247\205"},
    {":cucumber:", "\360\237\245\222"}, {":mushroom:", "\360\237\215\204"},
    {":peanuts:", "\360\237\245\234"}, {":chestnut:", "\360\237\214\260"},
    {":bread:", "\360\237\215\236"}, {":croissant:", "\360\237\245\220"},
    {":baguette:", "\360\237\245\226"}, {":pretzel:", "\360\237\245\250"},
    {":cheese:", "\360\237\247\200"}, {":egg:", "\360\237\245\232"},
    {":bacon:", "\360\237\245\223"}, {":pancakes:", "\360\237\245\236"},
    {":waffle:", "\360\237\247\207"}, {":pizza:", "\360\237\215\225"},
    {":hamburger:", "\360\237\215\224"}, {":fries:", "\360\237\215\237"},
    {":hotdog:", "\360\237\214\255"}, {":sandwich:", "\360\237\245\252"},
    {":taco:", "\360\237\214\256"}, {":burrito:", "\360\237\214\257"},
    {":sushi:", "\360\237\215\243"}, {":rice:", "\360\237\215\232"},
    {":ramen:", "\360\237\215\234"}, {":spaghetti:", "\360\237\215\235"},
    {":curry:", "\360\237\215\233"}, {":stew:", "\360\237\215\262"},
    {":salad:", "\360\237\245\227"}, {":popcorn:", "\360\237\215\277"},
    {":cake:", "\360\237\215\260"}, {":cookie:", "\360\237\215\252"},
    {":chocolate:", "\360\237\215\253"}, {":candy:", "\360\237\215\254"},
    {":lollipop:", "\360\237\215\255"}, {":ice_cream:", "\360\237\215\250"},
    {":doughnut:", "\360\237\215\251"}, {":cupcake:", "\360\237\247\201"},
    {":coffee:", "\342\230\225"}, {":tea:", "\360\237\215\265"},
    {":beer:", "\360\237\215\272"}, {":wine:", "\360\237\215\267"},
    {":cocktail:", "\360\237\215\270"}, {":tropical_drink:", "\360\237\215\271"},
    {":bubble_tea:", "\360\237\247\213"}, {":juice:", "\360\237\247\203"},
    {":milk:", "\360\237\245\233"}, {":baby_bottle:", "\360\237\215\274"},

    // Activities
    {":soccer:", "\342\232\275"}, {":basketball:", "\360\237\217\200"},
    {":football:", "\360\237\217\210"}, {":baseball:", "\342\232\276"},
    {":tennis:", "\360\237\216\276"}, {":volleyball:", "\360\237\217\220"},
    {":rugby:", "\360\237\217\211"}, {":8ball:", "\360\237\216\261"},
    {":golf:", "\342\233\263"}, {":ping_pong:", "\360\237\217\223"},
    {":badminton:", "\360\237\217\270"}, {":boxing_glove:", "\360\237\245\212"},
    {":martial_arts:", "\360\237\245\213"}, {":goal:", "\360\237\245\205"},
    {":dart:", "\360\237\216\257"}, {":bowling:", "\360\237\216\263"},
    {":game_die:", "\360\237\216\262"}, {":chess_pawn:", "\342\231\237"},
    {":performing_arts:", "\360\237\216\255"}, {":art:", "\360\237\216\250"},
    {":musical_score:", "\360\237\216\274"}, {":microphone:", "\360\237\216\244"},
    {":headphones:", "\360\237\216\247"}, {":saxophone:", "\360\237\216\267"},
    {":guitar:", "\360\237\216\270"}, {":trumpet:", "\360\237\216\272"},
    {":violin:", "\360\237\216\273"}, {":drum:", "\360\237\245\201"},
    {":clapper:", "\360\237\216\254"}, {":video_game:", "\360\237\216\256"},
    {":slot_machine:", "\360\237\216\260"}, {":jigsaw:", "\360\237\247\251"},

    // Travel & places
    {":car:", "\360\237\232\227"}, {":taxi:", "\360\237\232\225"},
    {":bus:", "\360\237\232\214"}, {":trolleybus:", "\360\237\232\216"},
    {":ambulance:", "\360\237\232\221"}, {":fire_engine:", "\360\237\232\222"},
    {":police_car:", "\360\237\232\223"}, {":bike:", "\360\237\232\262"},
    {":motorcycle:", "\360\237\217\215"}, {":airplane:", "\342\234\210"},
    {":helicopter:", "\360\237\232\201"}, {":rocket:", "\360\237\232\200"},
    {":ship:", "\360\237\232\242"}, {":sailboat:", "\342\233\265"},
    {":speedboat:", "\360\237\232\244"}, {":train:", "\360\237\232\206"},
    {":metro:", "\360\237\232\207"}, {":station:", "\360\237\232\211"},
    {":fuelpump:", "\342\233\275"}, {":construction:", "\360\237\232\247"},
    {":house:", "\360\237\217\240"}, {":office:", "\360\237\217\242"},
    {":school:", "\360\237\217\253"}, {":hospital:", "\360\237\217\245"},
    {":bank:", "\360\237\217\246"}, {":hotel:", "\360\237\217\250"},
    {":church:", "\342\233\252"}, {":mosque:", "\360\237\225\214"},
    {":synagogue:", "\360\237\225\215"}, {":mount_fuji:", "\360\237\227\273"},
    {":beach:", "\360\237\217\226"}, {":desert:", "\360\237\217\234"},
    {":island:", "\360\237\217\235"}, {":camping:", "\360\237\217\225"},
    {":tent:", "\342\233\272"}, {":cityscape:", "\360\237\217\231"},
    {":sunrise:", "\360\237\214\205"}, {":sunset:", "\360\237\214\206"},
    {":night_with_stars:", "\360\237\214\203"}, {":milky_way:", "\360\237\214\214"},
    {":globe:", "\360\237\214\215"}, {":map:", "\360\237\227\272"},
    {":compass:", "\360\237\247\255"}, {":earth_americas:", "\360\237\214\216"},

    // Objects
    {":phone:", "\360\237\223\261"}, {":computer:", "\360\237\222\273"},
    {":desktop:", "\360\237\226\245"}, {":keyboard:", "\342\214\250"},
    {":printer:", "\360\237\226\250"}, {":mouse_three_button:", "\360\237\226\261"},
    {":trackball:", "\360\237\226\262"}, {":camera:", "\360\237\223\267"},
    {":video_camera:", "\360\237\223\271"}, {":tv:", "\360\237\223\272"},
    {":radio:", "\360\237\223\273"}, {":battery:", "\360\237\224\213"},
    {":electric_plug:", "\360\237\224\214"}, {":bulb:", "\360\237\222\241"},
    {":flashlight:", "\360\237\224\246"}, {":candle:", "\360\237\225\257"},
    {":money_bag:", "\360\237\222\260"}, {":credit_card:", "\360\237\222\263"},
    {":gem:", "\360\237\222\216"}, {":wrench:", "\360\237\224\247"},
    {":hammer:", "\360\237\224\250"}, {":pick:", "\342\233\217"},
    {":nut_and_bolt:", "\360\237\224\251"}, {":gear:", "\342\232\231"},
    {":chains:", "\342\233\223"}, {":magnet:", "\360\237\247\262"},
    {":test_tube:", "\360\237\247\252"}, {":microscope:", "\360\237\224\254"},
    {":telescope:", "\360\237\224\255"}, {":satellite:", "\360\237\233\260"},
    {":syringe:", "\360\237\222\211"}, {":pill:", "\360\237\222\212"},
    {":thermometer:", "\360\237\214\241"}, {":toilet:", "\360\237\232\275"},
    {":shower:", "\360\237\232\277"}, {":bathtub:", "\360\237\233\201"},
    {":soap:", "\360\237\247\274"}, {":toothbrush:", "\360\237\252\245"},
    {":key:", "\360\237\224\221"}, {":lock:", "\360\237\224\222"},
    {":unlock:", "\360\237\224\223"}, {":pen:", "\360\237\226\212"},
    {":pencil:", "\342\234\217"}, {":book:", "\360\237\223\226"},
    {":books:", "\360\237\223\232"}, {":notebook:", "\360\237\223\223"},
    {":newspaper:", "\360\237\223\260"}, {":bookmark:", "\360\237\224\226"},
    {":label:", "\360\237\217\267"}, {":paperclip:", "\360\237\223\216"},
    {":pushpin:", "\360\237\223\214"}, {":round_pushpin:", "\360\237\223\215"},
    {":scissors:", "\342\234\202"}, {":ruler:", "\360\237\223\217"},
    {":triangular_ruler:", "\360\237\223\220"}, {":wastebasket:", "\360\237\227\221"},
    {":package:", "\360\237\223\246"}, {":mailbox:", "\360\237\223\253"},
    {":envelope:", "\342\234\211"}, {":incoming_envelope:", "\360\237\223\250"},
    {":bell:", "\360\237\224\224"}, {":no_bell:", "\360\237\224\225"},
    {":loudspeaker:", "\360\237\223\242"}, {":mega:", "\360\237\223\243"},

    // Nature
    {":seedling:", "\360\237\214\261"}, {":evergreen_tree:", "\360\237\214\262"},
    {":deciduous_tree:", "\360\237\214\263"}, {":palm_tree:", "\360\237\214\264"},
    {":cactus:", "\360\237\214\265"}, {":blossom:", "\360\237\214\274"},
    {":cherry_blossom:", "\360\237\214\270"}, {":rose:", "\360\237\214\271"},
    {":hibiscus:", "\360\237\214\272"}, {":sunflower:", "\360\237\214\273"},
    {":bouquet:", "\360\237\222\220"}, {":mushroom:", "\360\237\215\204"},
    {":four_leaf_clover:", "\360\237\215\200"}, {":maple_leaf:", "\360\237\215\201"},
    {":fallen_leaf:", "\360\237\215\202"}, {":leaves:", "\360\237\215\203"},
    {":herb:", "\360\237\214\277"},

    // Flags
    {":flag_us:", "\360\237\207\272\360\237\207\270"},
    {":flag_gb:", "\360\237\207\254\360\237\207\247"},
    {":flag_de:", "\360\237\207\251\360\237\207\252"},
    {":flag_fr:", "\360\237\207\253\360\237\207\267"},
    {":flag_jp:", "\360\237\207\257\360\237\207\265"},
    {":flag_cn:", "\360\237\207\250\360\237\207\263"},
    {":flag_in:", "\360\237\207\256\360\237\207\263"},
    {":flag_br:", "\360\237\207\247\360\237\207\267"},
    {":flag_au:", "\360\237\207\246\360\237\207\272"},
    {":flag_ca:", "\360\237\207\250\360\237\207\246"},
    {":flag_it:", "\360\237\207\256\360\237\207\271"},
    {":flag_es:", "\360\237\207\252\360\237\207\270"},
    {":flag_ru:", "\360\237\207\267\360\237\207\272"},
    {":flag_kr:", "\360\237\207\260\360\237\207\267"},
    {":flag_nl:", "\360\237\207\263\360\237\207\261"},
    {":flag_se:", "\360\237\207\270\360\237\207\252"},
    {":flag_no:", "\360\237\207\263\360\237\207\264"},
    {":flag_dk:", "\360\237\207\251\360\237\207\260"},
    {":flag_fi:", "\360\237\207\253\360\237\207\256"},
    {":flag_be:", "\360\237\207\247\360\237\207\252"},
    {":flag_at:", "\360\237\207\246\360\237\207\271"},
    {":flag_ch:", "\360\237\207\250\360\237\207\255"},
    {":flag_pl:", "\360\237\207\265\360\237\207\261"},
    {":flag_ua:", "\360\237\207\272\360\237\207\246"},
    {":flag_mx:", "\360\237\207\262\360\237\207\275"},
    {":flag_ar:", "\360\237\207\246\360\237\207\267"},
    {":flag_za:", "\360\237\207\277\360\237\207\246"},
    {":flag_ng:", "\360\237\207\263\360\237\207\254"},
    {":flag_eg:", "\360\237\207\252\360\237\207\254"},
    {":flag_tr:", "\360\237\207\271\360\237\207\267"},
    {":flag_sa:", "\360\237\207\270\360\237\207\246"},
    {":flag_ae:", "\360\237\207\246\360\237\207\252"},
    {":checkered_flag:", "\360\237\217\201"},
    {":rainbow_flag:", "\360\237\217\263\357\270\217\342\200\215\360\237\214\210"},
    {":pirate_flag:", "\360\237\217\264\342\200\215\342\230\240\357\270\217"},
    {":triangular_flag:", "\360\237\232\251"},
};

// ============================================================================
// Composite HTML Composer - High-Level API
// ============================================================================

class HtmlComposer {
public:
    // Compose a full email message from plain text, optionally with quoting
    struct ComposeOptions {
        std::string plain_text;
        std::string html_text;            // if provided, used instead of converting
        std::string subject;
        std::string reply_author;
        std::string reply_timestamp;
        std::string reply_text;           // text being replied to
        bool reply_is_html = false;
        bool is_forwarded = false;
        std::string forward_author;
        std::string forward_timestamp;
        std::string forward_subject;
        bool use_responsive_template = false;
        bool auto_linkify = true;
        bool expand_emoji = true;
        bool detect_signature = true;
        bool fold_long_quotes = true;
        std::vector<InlineImageHandler::ImageInfo> inline_images;
        std::vector<MultipartMimeBuilder::MimePart> attachments;
    };

    // Compose a complete MIME message
    static std::string compose_mime(const ComposeOptions& opts,
                                     const std::string& from,
                                     const std::string& to) {
        // Build HTML body
        std::string html_body = build_html_body(opts);

        // Build plain text body
        std::string plain_body = opts.plain_text;
        if (opts.expand_emoji) {
            plain_body = EmojiExpander::expand(plain_body);
        }

        // Build MIME message
        MultipartMimeBuilder::MimeMessage msg;
        msg.from = from;
        msg.to = to;
        msg.subject = opts.subject;

        if (opts.html_text.empty()) {
            msg.html_text = html_body;
            msg.plain_text = plain_body;
        } else {
            msg.html_text = opts.html_text;
            msg.plain_text = HtmlToPlainText::convert(opts.html_text);
        }

        // Add reply headers if applicable
        if (!opts.reply_text.empty()) {
            msg.in_reply_to = "<reply-" + std::to_string(std::time(nullptr)) + "@delta>";
        }

        // Add inline images
        for (const auto& img : opts.inline_images) {
            auto part = InlineImageHandler::create_mime_part(img);
            msg.inline_images.push_back(part);
        }

        // Add attachments
        for (const auto& att : opts.attachments) {
            msg.attachments.push_back(att);
        }

        return MultipartMimeBuilder::build(msg);
    }

    // Build HTML body with all features
    static std::string build_html_body(const ComposeOptions& opts) {
        std::ostringstream ss;

        // New message content
        std::string new_content;
        if (!opts.html_text.empty()) {
            new_content = HtmlSanitizer::sanitize(opts.html_text);
        } else {
            std::string text = opts.plain_text;

            // Detect and remove signature
            if (opts.detect_signature) {
                auto sig_info = SignatureDetector::detect_plain(text);
                if (sig_info.has_signature) {
                    text = sig_info.text_before;
                }
            }

            // Expand emoji
            if (opts.expand_emoji) {
                text = EmojiExpander::expand(text);
            }

            // Convert to HTML
            new_content = PlainTextToHtml::convert(text, opts.auto_linkify);
        }

        ss << "<div class=\"new-message\">\n";
        ss << new_content;
        ss << "\n</div>\n";

        // Reply/quote section
        if (!opts.reply_text.empty()) {
            ss << "\n<hr class=\"signature-sep\">\n\n";

            // Attribution
            ss << QuoteDetector::build_attribution(
                opts.reply_author, opts.reply_timestamp);

            // Quoted text
            std::string quote_html;
            if (opts.reply_is_html) {
                quote_html = HtmlSanitizer::sanitize(opts.reply_text);
            } else {
                quote_html = PlainTextToHtml::convert(opts.reply_text, false);
            }

            if (opts.fold_long_quotes) {
                quote_html = QuoteDetector::fold_quotes_html(quote_html);
            }

            ss << "<blockquote>\n" << quote_html << "\n</blockquote>\n";
        }

        // Forwarded section
        if (opts.is_forwarded) {
            ForwardedMessageFormatter::ForwardedMsg fwd;
            fwd.text = opts.forward_author.empty() ? opts.plain_text : "";
            fwd.author = opts.forward_author;
            fwd.timestamp = opts.forward_timestamp;
            fwd.subject = opts.forward_subject;
            fwd.is_html = !opts.html_text.empty();

            ss << "\n" << ForwardedMessageFormatter::format_html(fwd) << "\n";
        }

        std::string body = ss.str();

        // Wrap in responsive template if requested
        if (opts.use_responsive_template) {
            body = CssInliner::wrap_email_template(body, opts.subject);
        }

        return body;
    }

    // Quick compose for simple text messages
    static std::string quick_compose(const std::string& text) {
        ComposeOptions opts;
        opts.plain_text = text;
        opts.auto_linkify = true;
        opts.expand_emoji = true;
        return build_html_body(opts);
    }

    // Compose a reply
    static std::string compose_reply_html(const std::string& new_text,
                                           const std::string& quoted_text,
                                           const std::string& author,
                                           const std::string& timestamp) {
        ComposeOptions opts;
        opts.plain_text = new_text;
        opts.reply_text = quoted_text;
        opts.reply_author = author;
        opts.reply_timestamp = timestamp;
        opts.fold_long_quotes = true;
        return build_html_body(opts);
    }

    // Compose a forwarded message
    static std::string compose_forward_html(const std::string& text,
                                             const std::string& author,
                                             const std::string& timestamp,
                                             const std::string& subject) {
        ComposeOptions opts;
        opts.plain_text = text;
        opts.is_forwarded = true;
        opts.forward_author = author;
        opts.forward_timestamp = timestamp;
        opts.forward_subject = subject;
        return build_html_body(opts);
    }
};

// ============================================================================
// Display Renderer - for in-app message display
// ============================================================================

class DisplayRenderer {
public:
    // Render a message for in-app display with full HTML support
    static std::string render_message(const std::string& html,
                                       const std::string& plain_text = "",
                                       bool is_system_message = false) {
        if (is_system_message) {
            std::ostringstream ss;
            ss << "<div class=\"system-msg\">"
               << escape_html(plain_text) << "</div>";
            return ss.str();
        }

        if (!html.empty()) {
            // Sanitize HTML for safe display
            std::string sanitized = HtmlSanitizer::sanitize(html);

            // Wrap in a display container
            std::ostringstream ss;
            ss << "<div class=\"message-body-display\">\n";
            ss << sanitized;
            ss << "\n</div>";
            return ss.str();
        }

        if (!plain_text.empty()) {
            std::string text = EmojiExpander::expand_html(plain_text);
            return PlainTextToHtml::convert(text, true);
        }

        return "";
    }

    // Render a message bubble (typical chat UI)
    static std::string render_bubble(const std::string& content,
                                      bool is_outgoing,
                                      const std::string& author = "",
                                      const std::string& timestamp = "",
                                      bool is_encrypted = false,
                                      const std::string& status = "") {
        std::ostringstream ss;

        std::string bubble_class = is_outgoing ? "msg-outgoing" : "msg-incoming";
        std::string bg_color = is_outgoing ? "#dcf8c6" : "#ffffff";
        std::string align = is_outgoing ? "right" : "left";

        ss << "<div class=\"msg-bubble " << bubble_class << "\"";
        ss << " style=\"max-width: 80%; margin: 8px 0; padding: 8px 12px; ";
        ss << "border-radius: 12px; background: " << bg_color << "; ";
        ss << "float: " << align << "; clear: both; ";
        ss << "box-shadow: 0 1px 3px rgba(0,0,0,0.1);\">\n";

        if (!author.empty() && !is_outgoing) {
            ss << "  <div style=\"font-size: 12px; font-weight: bold; "
               << "color: " << assign_author_color(author) << "; margin-bottom: 2px;\">"
               << escape_html(author) << "</div>\n";
        }

        ss << "  <div style=\"font-size: 14px; line-height: 1.4;\">";
        ss << render_message(content);
        ss << "</div>\n";

        // Footer: timestamp + status + encryption
        ss << "  <div style=\"margin-top: 4px; font-size: 11px; color: #999; "
           << "display: flex; justify-content: space-between;\">\n";
        ss << "    <span>";
        if (is_encrypted) ss << "\360\237\224\222 ";
        if (!status.empty()) ss << status << " ";
        ss << "</span>\n";
        if (!timestamp.empty()) {
            ss << "    <span>" << escape_html(timestamp) << "</span>\n";
        }
        ss << "  </div>\n";

        ss << "</div>\n";

        // Clear float
        ss << "<div style=\"clear: both;\"></div>\n";

        return ss.str();
    }

    // Render a conversation thread
    static std::string render_thread(
        const std::vector<std::tuple<std::string, std::string, std::string, bool>>& messages) {
        // messages: {content, author, timestamp, is_outgoing}
        std::ostringstream ss;

        ss << "<div class=\"chat-thread\" style=\"padding: 10px; "
           << "background: #e5ddd5; min-height: 200px; overflow-y: auto;\">\n";

        std::string last_author;
        for (const auto& [content, author, timestamp, is_outgoing] : messages) {
            bool show_author = (!is_outgoing && author != last_author);
            ss << render_bubble(content, is_outgoing,
                                show_author ? author : "",
                                timestamp);
            last_author = author;
        }

        ss << "</div>";
        return ss.str();
    }

    // Render a rich preview card (e.g., for links)
    static std::string render_preview_card(const std::string& url,
                                            const std::string& title,
                                            const std::string& description,
                                            const std::string& image_url = "",
                                            const std::string& site_name = "") {
        std::ostringstream ss;

        ss << "<div class=\"preview-card\" style=\"border: 1px solid #e0e0e0; "
           << "border-radius: 8px; overflow: hidden; margin: 8px 0; max-width: 400px;\">\n";

        if (!image_url.empty()) {
            ss << "  <div style=\"width: 100%; height: 180px; overflow: hidden; "
               << "background: #f0f0f0;\">\n";
            ss << "    <img src=\"" << escape_html(image_url) << "\"";
            ss << " alt=\"" << escape_html(title) << "\"";
            ss << " style=\"width: 100%; height: 100%; object-fit: cover;\"";
            ss << " onerror=\"this.style.display='none'\">";
            ss << "\n  </div>\n";
        }

        ss << "  <div style=\"padding: 12px;\">\n";
        if (!site_name.empty()) {
            ss << "    <div style=\"font-size: 11px; color: #888; "
               << "text-transform: uppercase; margin-bottom: 4px;\">"
               << escape_html(site_name) << "</div>\n";
        }
        if (!title.empty()) {
            ss << "    <div style=\"font-size: 14px; font-weight: bold; "
               << "margin-bottom: 4px;\">" << escape_html(title) << "</div>\n";
        }
        if (!description.empty()) {
            ss << "    <div style=\"font-size: 13px; color: #555; "
               << "line-height: 1.3;\">" << escape_html(description) << "</div>\n";
        }
        ss << "    <a href=\"" << escape_html(url) << "\" "
           << "style=\"font-size: 12px; color: #1e90ff; display: block; "
           << "margin-top: 6px;\">" << escape_html(url) << "</a>\n";
        ss << "  </div>\n";

        ss << "</div>";
        return ss.str();
    }

    // Render an attachment preview
    static std::string render_attachment_preview(const std::string& filename,
                                                   const std::string& mime_type,
                                                   int64_t file_size) {
        std::ostringstream ss;

        std::string icon = get_attachment_icon(mime_type);
        std::string size_str = format_file_size(file_size);

        ss << "<div class=\"attachment-preview\" style=\"display: flex; "
           << "align-items: center; padding: 10px; border: 1px solid #e0e0e0; "
           << "border-radius: 8px; margin: 4px 0; background: #fafafa;\">\n";
        ss << "  <div style=\"font-size: 28px; margin-right: 12px;\">"
           << icon << "</div>\n";
        ss << "  <div style=\"flex: 1;\">\n";
        ss << "    <div style=\"font-size: 13px; font-weight: bold;\">"
           << escape_html(filename) << "</div>\n";
        ss << "    <div style=\"font-size: 11px; color: #888;\">"
           << size_str << " \302\267 " << mime_type << "</div>\n";
        ss << "  </div>\n";
        ss << "</div>";

        return ss.str();
    }

private:
    static std::string assign_author_color(const std::string& author) {
        static const char* kColors[] = {
            "#E17076", "#7BC862", "#65AADD", "#A695E7",
            "#EE7AAE", "#6EC9CB", "#FAA356", "#A0A0A0",
            "#56C596", "#E88948", "#76B5E8", "#E8913A"
        };

        size_t hash = 0;
        for (char c : author) {
            hash = hash * 31 + static_cast<unsigned char>(c);
        }
        return kColors[hash % 12];
    }

    static std::string get_attachment_icon(const std::string& mime_type) {
        if (mime_type.find("image/") == 0) return "\360\237\226\274";  // framed picture
        if (mime_type.find("video/") == 0) return "\360\237\216\254";  // clapper
        if (mime_type.find("audio/") == 0) return "\360\237\216\265";  // musical note
        if (mime_type.find("pdf") != std::string::npos) return "\360\237\223\204";  // page
        if (mime_type.find("zip") != std::string::npos ||
            mime_type.find("rar") != std::string::npos ||
            mime_type.find("tar") != std::string::npos ||
            mime_type.find("gzip") != std::string::npos) return "\360\237\227\234";  // file folder
        if (mime_type.find("text/") == 0) return "\360\237\223\235";  // memo
        return "\360\237\223\216";  // paperclip (default)
    }

    static std::string format_file_size(int64_t bytes) {
        if (bytes < 1024) return std::to_string(bytes) + " B";
        if (bytes < 1024 * 1024) return std::to_string(bytes / 1024) + " KB";
        if (bytes < 1024LL * 1024 * 1024)
            return std::to_string(bytes / (1024 * 1024)) + " MB";
        return std::to_string(bytes / (1024LL * 1024 * 1024)) + " GB";
    }
};

// ============================================================================
// Testing Utilities
// ============================================================================

class HtmlComposerTest {
public:
    // Run basic self-test to verify functionality
    static bool run_tests() {
        bool all_pass = true;

        auto check = [&](bool result, const std::string& test_name) {
            if (!result) {
                std::cerr << "FAIL: " << test_name << std::endl;
                all_pass = false;
            }
        };

        // Test HTML escaping
        check(escape_html("<b>hello</b>") == "&lt;b&gt;hello&lt;/b&gt;",
              "escape_html basic");
        check(escape_html("a & b") == "a &amp; b",
              "escape_html ampersand");

        // Test HTML to plain text
        std::string plain = HtmlToPlainText::convert("<p>Hello <b>World</b></p>");
        check(!plain.empty(), "HtmlToPlainText basic");
        check(plain.find("Hello") != std::string::npos, "HtmlToPlainText content");
        check(plain.find("<b>") == std::string::npos, "HtmlToPlainText strip tags");

        // Test plain to HTML conversion
        std::string html = PlainTextToHtml::convert("Hello World");
        check(html.find("Hello World") != std::string::npos, "PlainTextToHtml basic");

        // Test URL linkification
        std::string linked = PlainTextToHtml::convert("Visit https://example.com");
        check(linked.find("<a href=\"https://example.com\"") != std::string::npos,
              "linkification");

        // Test signature detection
        auto sig_info = SignatureDetector::detect_plain("Hello\n-- \nJohn Doe");
        check(sig_info.has_signature, "SignatureDetector detect");
        check(sig_info.signature_text == "John Doe", "SignatureDetector content");

        // Test markdown to HTML
        std::string md_html = MarkdownToHtml::convert("**bold** and *italic*");
        check(md_html.find("<strong>bold</strong>") != std::string::npos,
              "Markdown bold");
        check(md_html.find("<em>italic</em>") != std::string::npos,
              "Markdown italic");

        // Test emoji expansion
        std::string emoji = EmojiExpander::expand("Hello :smile:");
        check(emoji.find("\360\237\230\204") != std::string::npos,
              "Emoji expansion");

        // Test quote detection
        auto quote_analysis = QuoteDetector::analyze_plain("Hello\n> Quoted text\nWorld");
        check(quote_analysis.has_quotes, "QuoteDetector has quotes");
        check(quote_analysis.quotes.size() == 1, "QuoteDetector one quote");
        check(quote_analysis.main_text.find("Hello") != std::string::npos,
              "QuoteDetector main text");

        // Test quote folding
        std::string long_quote;
        for (int i = 0; i < 20; ++i) {
            long_quote += "Line " + std::to_string(i) + " of quoted text.\n";
        }
        std::string folded = QuoteDetector::fold_quotes_html(long_quote);
        check(folded.find("quote-collapsed") != std::string::npos,
              "QuoteDetector fold");

        // Test MIME builder
        MultipartMimeBuilder::MimeMessage mime_msg;
        mime_msg.from = "test@example.com";
        mime_msg.to = "recipient@example.com";
        mime_msg.subject = "Test";
        mime_msg.plain_text = "Hello plain";
        mime_msg.html_text = "<p>Hello HTML</p>";
        std::string mime = MultipartMimeBuilder::build(mime_msg);
        check(mime.find("multipart/alternative") != std::string::npos,
              "MIME multipart/alternative");
        check(mime.find("Hello plain") != std::string::npos,
              "MIME plain text content");
        check(mime.find("Hello HTML") != std::string::npos,
              "MIME HTML content");

        // Test rich text composer
        check(RichTextComposer::bold("hello") == "<strong>hello</strong>",
              "RichText bold");
        check(RichTextComposer::italic("hello") == "<em>hello</em>",
              "RichText italic");

        // Test HTML sanitizer
        std::string sanitized = HtmlSanitizer::sanitize(
            "<p>Safe</p><script>alert('xss')</script>");
        check(sanitized.find("<script>") == std::string::npos,
              "HtmlSanitizer script removal");
        check(sanitized.find("<p>") != std::string::npos,
              "HtmlSanitizer allowed tag");
        check(sanitized.find("Safe") != std::string::npos,
              "HtmlSanitizer content preserved");

        // Test forwarded message formatting
        ForwardedMessageFormatter::ForwardedMsg fwd;
        fwd.author = "Alice";
        fwd.timestamp = "2026-01-01";
        fwd.subject = "Hello";
        fwd.text = "Message body";
        std::string fwd_html = ForwardedMessageFormatter::format_html(fwd);
        check(fwd_html.find("Alice") != std::string::npos,
              "ForwardedMessage author");
        check(fwd_html.find("Message body") != std::string::npos,
              "ForwardedMessage body");

        // Test system messages
        std::string sys_msg = SystemMessageFormatter::format_html(
            SystemMessageFormatter::Type::MemberAdded, {"Alice"});
        check(sys_msg.find("Alice") != std::string::npos,
              "SystemMessage member added");

        // Test responsive template
        std::string templated = CssInliner::wrap_email_template(
            "<p>Content</p>", "Subject");
        check(templated.find("<!DOCTYPE html>") != std::string::npos,
              "Template doctype");
        check(templated.find("Content") != std::string::npos,
              "Template content");

        if (all_pass) {
            std::cerr << "All HtmlComposer tests passed." << std::endl;
        }

        return all_pass;
    }
};

}  // namespace deltachat
}  // namespace progressive
