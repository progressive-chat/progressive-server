// progressive::xml_parser.cpp — Full XML/DOM parser with SAX events
// Part of progressive-server. All rights reserved.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace progressive {

// ============================================================================
// Forward declarations
// ============================================================================
class XmlLexer;
class XmlSaxParser;
class XmlDomParser;
class XmlNode;
class XmlDocument;
class XmlElement;
class XmlAttribute;
class XmlText;
class XmlComment;
class XmlProcessingInstruction;
class XmlCData;
class XmlEntityResolver;
class XmlNamespaceContext;

// ============================================================================
// Error types
// ============================================================================

/// Represents a specific position in source XML text.
struct XmlSourcePosition {
    std::size_t line = 1;
    std::size_t column = 1;
    std::size_t offset = 0;
    std::string context; ///< Nearby text for diagnostics
};

/// Exception thrown for XML parse errors.
class XmlParseException : public std::runtime_error {
public:
    XmlParseException(const std::string& message, XmlSourcePosition pos = {})
        : std::runtime_error(format_message(message, pos))
        , position_(pos)
        , message_(message)
    {}

    const XmlSourcePosition& position() const noexcept { return position_; }
    const std::string& raw_message() const noexcept { return message_; }

private:
    static std::string format_message(const std::string& msg, const XmlSourcePosition& pos) {
        std::ostringstream oss;
        oss << "XML parse error at line " << pos.line << ", column " << pos.column
            << " (offset " << pos.offset << "): " << msg;
        if (!pos.context.empty()) {
            oss << "\n  near: " << pos.context;
        }
        return oss.str();
    }

    XmlSourcePosition position_;
    std::string message_;
};

/// Exception thrown for XML validation / well-formedness errors.
class XmlValidationException : public XmlParseException {
public:
    using XmlParseException::XmlParseException;
};

/// Exception thrown for XPath parsing errors.
class XPathParseException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// ============================================================================
// XML Token types (internal for lexer / SAX)
// ============================================================================

/// Low-level token kinds emitted by the lexer.
enum class XmlTokenKind : uint8_t {
    None = 0,
    /// '<'
    TagOpen,
    /// '</'
    TagClose,
    /// '/>'
    TagSelfClose,
    /// '>'
    TagEnd,
    /// '?>'
    PIEnd,
    /// '='
    Equals,
    /// Attribute name
    AttrName,
    /// Attribute value (quoted)
    AttrValue,
    /// Element / PI name
    Name,
    /// Text content between tags
    Text,
    /// <!-- ... -->
    Comment,
    /// <![CDATA[ ... ]]>
    CData,
    /// Raw character data content
    Characters,
    /// Entity reference &name;
    EntityRef,
    /// Processing instruction target
    PITarget,
    /// DOCTYPE declaration
    DocType,
    /// End of input
    Eof,
    /// Error token
    Error,
};

/// A single token from the XML lexer.
struct XmlToken {
    XmlTokenKind kind = XmlTokenKind::None;
    std::string value;
    XmlSourcePosition pos;
    /// For attribute tokens: the quote character used (' or ")
    char quote_char = '"';
};

namespace {
    const char* token_kind_name(XmlTokenKind k) {
        switch (k) {
            case XmlTokenKind::None:        return "None";
            case XmlTokenKind::TagOpen:      return "TagOpen";
            case XmlTokenKind::TagClose:     return "TagClose";
            case XmlTokenKind::TagSelfClose: return "TagSelfClose";
            case XmlTokenKind::TagEnd:       return "TagEnd";
            case XmlTokenKind::PIEnd:        return "PIEnd";
            case XmlTokenKind::Equals:       return "Equals";
            case XmlTokenKind::AttrName:     return "AttrName";
            case XmlTokenKind::AttrValue:    return "AttrValue";
            case XmlTokenKind::Name:         return "Name";
            case XmlTokenKind::Text:         return "Text";
            case XmlTokenKind::Comment:      return "Comment";
            case XmlTokenKind::CData:        return "CData";
            case XmlTokenKind::Characters:   return "Characters";
            case XmlTokenKind::EntityRef:    return "EntityRef";
            case XmlTokenKind::PITarget:     return "PITarget";
            case XmlTokenKind::DocType:      return "DocType";
            case XmlTokenKind::Eof:          return "Eof";
            case XmlTokenKind::Error:        return "Error";
            default: return "Unknown";
        }
    }
} // anonymous namespace

// ============================================================================
// SAX Event types
// ============================================================================

/// Kinds of events the SAX parser emits to handlers.
enum class SaxEventType : uint8_t {
    StartDocument,
    EndDocument,
    StartElement,
    EndElement,
    Characters,
    Comment,
    ProcessingInstruction,
    CData,
    DocType,
    StartPrefixMapping,
    EndPrefixMapping,
    IgnorableWhitespace,
    SkippedEntity,
    Error,
    FatalError,
    Warning,
};

/// A single SAX event containing all relevant data for the callback.
struct SaxEvent {
    SaxEventType type = SaxEventType::Error;
    std::string local_name;        ///< Local name (without prefix)
    std::string qualified_name;    ///< Prefixed name
    std::string namespace_uri;     ///< Resolved namespace URI
    std::string value;             ///< Character data, comment text, etc.
    std::string prefix;            ///< Namespace prefix
    std::string pi_target;         ///< Processing instruction target
    std::string pi_data;           ///< Processing instruction data
    std::string public_id;         ///< DOCTYPE public identifier
    std::string system_id;         ///< DOCTYPE system identifier
    std::string notation_name;     ///< Notation name if relevant
    XmlSourcePosition position;
    std::map<std::string, std::string> attributes; ///< Attr name -> value
    std::vector<std::pair<std::string,std::string>> ordered_attributes;
    std::vector<std::pair<std::string,std::string>> namespace_declarations;
};

// ============================================================================
// SAX Handler interface
// ============================================================================

/// Abstract handler interface for SAX-style event-driven XML parsing.
/// Override any of these methods to receive parsing events.
class SaxHandler {
public:
    virtual ~SaxHandler() = default;

    virtual void start_document() {}
    virtual void end_document() {}

    virtual void start_element(const std::string& uri,
                               const std::string& local_name,
                               const std::string& qname,
                               const std::map<std::string,std::string>& attrs) {}
    virtual void end_element(const std::string& uri,
                             const std::string& local_name,
                             const std::string& qname) {}

    virtual void characters(const std::string& text) {}
    virtual void ignorable_whitespace(const std::string& whitespace) {}
    virtual void comment(const std::string& text) {}
    virtual void processing_instruction(const std::string& target,
                                        const std::string& data) {}
    virtual void cdata(const std::string& data) {}
    virtual void doctype(const std::string& name,
                         const std::string& public_id,
                         const std::string& system_id) {}

    virtual void start_prefix_mapping(const std::string& prefix,
                                      const std::string& uri) {}
    virtual void end_prefix_mapping(const std::string& prefix) {}

    virtual void skipped_entity(const std::string& name) {}
    virtual void warning(const std::string& message,
                         const XmlSourcePosition& pos) {}
    virtual void error(const std::string& message,
                       const XmlSourcePosition& pos) {}
    virtual void fatal_error(const std::string& message,
                             const XmlSourcePosition& pos) {}
};

// ============================================================================
// Entity resolver
// ============================================================================

/// Resolves XML entity references.
class XmlEntityResolver {
public:
    virtual ~XmlEntityResolver() = default;

    /// Resolve a named entity reference. Returns the replacement text
    /// or std::nullopt if the entity is unknown.
    virtual std::optional<std::string> resolve_entity(const std::string& name) {
        static const std::unordered_map<std::string, std::string> builtins = {
            {"lt",   "<"},
            {"gt",   ">"},
            {"amp",  "&"},
            {"apos", "'"},
            {"quot", "\""},
        };
        auto it = builtins.find(name);
        if (it != builtins.end()) return it->second;
        if (!name.empty() && name[0] == '#') {
            return resolve_numeric_entity(name);
        }
        return std::nullopt;
    }

    /// Resolve a numeric character entity (&#NNN; or &#xHHH;).
    std::optional<std::string> resolve_numeric_entity(const std::string& name) {
        if (name.size() < 2) return std::nullopt;
        try {
            char32_t cp = 0;
            if (name[1] == 'x' || name[1] == 'X') {
                cp = static_cast<char32_t>(std::stoul(name.substr(2), nullptr, 16));
            } else {
                cp = static_cast<char32_t>(std::stoul(name.substr(1), nullptr, 10));
            }
            return encode_utf8(cp);
        } catch (...) {
            return std::nullopt;
        }
    }

    /// Encode a Unicode code point into a UTF-8 string.
    static std::string encode_utf8(char32_t cp) {
        std::string result;
        if (cp <= 0x7F) {
            result.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7FF) {
            result.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
            result.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp <= 0xFFFF) {
            result.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
            result.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp <= 0x10FFFF) {
            result.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
            result.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        return result;
    }

    /// Decode a single UTF-8 sequence. Returns code point and number of bytes consumed.
    static std::pair<char32_t, int> decode_utf8(const char* data, std::size_t len) {
        if (len == 0) return {0, 0};
        unsigned char c = static_cast<unsigned char>(data[0]);
        if ((c & 0x80) == 0) return {c, 1};
        if ((c & 0xE0) == 0xC0 && len >= 2) {
            char32_t cp = ((c & 0x1F) << 6) | (static_cast<unsigned char>(data[1]) & 0x3F);
            return {cp, 2};
        }
        if ((c & 0xF0) == 0xE0 && len >= 3) {
            char32_t cp = ((c & 0x0F) << 12)
                        | ((static_cast<unsigned char>(data[1]) & 0x3F) << 6)
                        | (static_cast<unsigned char>(data[2]) & 0x3F);
            return {cp, 3};
        }
        if ((c & 0xF8) == 0xF0 && len >= 4) {
            char32_t cp = ((c & 0x07) << 18)
                        | ((static_cast<unsigned char>(data[1]) & 0x3F) << 12)
                        | ((static_cast<unsigned char>(data[2]) & 0x3F) << 6)
                        | (static_cast<unsigned char>(data[3]) & 0x3F);
            return {cp, 4};
        }
        return {0, 0};
    }
};

// ============================================================================
// XML Lexer (tokenizer)
// ============================================================================

/// Low-level XML lexer. Converts raw text into a stream of XmlToken objects
/// for consumption by the SAX or DOM parser.
class XmlLexer {
public:
    XmlLexer()
        : input_(nullptr)
        , input_size_(0)
        , pos_(0)
        , line_(1)
        , column_(1)
        , in_dtd_(false)
        , expand_entities_(true)
    {}

    /// Reset lexer to parse new input.
    void reset(const std::string& text) {
        input_ = text.data();
        input_size_ = text.size();
        pos_ = 0;
        line_ = 1;
        column_ = 1;
        in_dtd_ = false;
        buffered_.clear();
    }

    /// Reset with a string_view for zero-copy scanning.
    void reset_view(std::string_view text) {
        input_ = text.data();
        input_size_ = text.size();
        pos_ = 0;
        line_ = 1;
        column_ = 1;
        in_dtd_ = false;
        buffered_.clear();
    }

    /// Get the next token from the input stream.
    XmlToken next_token() {
        if (!buffered_.empty()) {
            XmlToken tok = std::move(buffered_.front());
            buffered_.pop_front();
            return tok;
        }
        return scan_token();
    }

    /// Push a token back to be re-read.
    void push_back(XmlToken tok) {
        buffered_.push_front(std::move(tok));
    }

    /// Peek at the next token without consuming it.
    XmlToken peek_token() {
        XmlToken tok = next_token();
        push_back(tok);
        return tok;
    }

    /// Set the entity resolver.
    void set_entity_resolver(std::shared_ptr<XmlEntityResolver> resolver) {
        entity_resolver_ = std::move(resolver);
    }

    /// Enable or disable entity expansion.
    void set_expand_entities(bool expand) { expand_entities_ = expand; }

    /// Whether the lexer is in a DTD section.
    bool in_dtd() const { return in_dtd_; }
    void set_in_dtd(bool v) { in_dtd_ = v; }

private:
    /// Peek at the current character without advancing.
    char peek() const {
        if (pos_ >= input_size_) return '\0';
        return input_[pos_];
    }

    /// Peek ahead n characters.
    char peek_ahead(std::size_t n) const {
        if (pos_ + n >= input_size_) return '\0';
        return input_[pos_ + n];
    }

    /// Consume and return the current character.
    char advance() {
        if (pos_ >= input_size_) return '\0';
        char c = input_[pos_++];
        if (c == '\n') {
            line_++;
            column_ = 1;
        } else {
            column_++;
        }
        return c;
    }

    /// Skip characters while predicate is true.
    template<typename Pred>
    void skip_while(Pred pred) {
        while (pos_ < input_size_ && pred(peek())) advance();
    }

    /// Check if we are at end of input.
    bool eof() const { return pos_ >= input_size_; }

    /// Make a source position at the current location.
    XmlSourcePosition current_position() const {
        XmlSourcePosition p;
        p.line = line_;
        p.column = column_;
        p.offset = pos_;
        // Capture some context for error messages
        std::size_t ctx_start = (pos_ >= 20) ? pos_ - 20 : 0;
        std::size_t ctx_len = std::min<std::size_t>(40, input_size_ - ctx_start);
        p.context = std::string(input_ + ctx_start, ctx_len);
        return p;
    }

    /// Match a specific string at the current position, advancing if matched.
    bool match(const char* str) {
        std::size_t len = std::strlen(str);
        if (pos_ + len > input_size_) return false;
        if (std::strncmp(input_ + pos_, str, len) != 0) return false;
        for (std::size_t i = 0; i < len; ++i) advance();
        return true;
    }

    /// Check if a string matches at current position without consuming.
    bool matches(const char* str) const {
        std::size_t len = std::strlen(str);
        if (pos_ + len > input_size_) return false;
        return std::strncmp(input_ + pos_, str, len) == 0;
    }

    /// Read a Name as defined by XML spec.
    std::string read_name() {
        std::string name;
        while (pos_ < input_size_) {
            char c = peek();
            if (std::isalnum(static_cast<unsigned char>(c)) ||
                c == '_' || c == '-' || c == '.' || c == ':') {
                name.push_back(advance());
            } else {
                break;
            }
        }
        return name;
    }

    /// Read an NCName (Name without colons, for namespace processing).
    std::string read_ncname() {
        std::string name;
        while (pos_ < input_size_) {
            char c = peek();
            if (std::isalnum(static_cast<unsigned char>(c)) ||
                c == '_' || c == '-' || c == '.') {
                name.push_back(advance());
            } else {
                break;
            }
        }
        return name;
    }

    /// Read characters until a delimiter string is found.
    std::string read_until(const char* delim) {
        std::size_t delim_len = std::strlen(delim);
        std::string result;
        while (pos_ < input_size_) {
            if (pos_ + delim_len <= input_size_ &&
                std::strncmp(input_ + pos_, delim, delim_len) == 0) {
                break;
            }
            result.push_back(advance());
        }
        return result;
    }

    /// Read a quoted string value (either ' or ").
    std::string read_quoted(char& quote_char_out) {
        char quote = advance(); // consume opening quote
        quote_char_out = quote;
        std::string value;
        while (pos_ < input_size_) {
            char c = peek();
            if (c == quote) {
                advance(); // consume closing quote
                return value;
            }
            if (c == '&') {
                // Handle entity references inside attribute values
                value += read_entity_reference();
            } else if (c == '<') {
                // '<' not allowed in attribute values
                return value;
            } else {
                value.push_back(advance());
            }
        }
        return value; // unterminated quote is handled by parser
    }

    /// Read an entity reference starting with '&'.
    std::string read_entity_reference() {
        advance(); // consume '&'
        std::string name;
        while (pos_ < input_size_) {
            char c = peek();
            if (c == ';') {
                advance();
                break;
            }
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '#') {
                name.push_back(advance());
            } else {
                break;
            }
        }
        if (expand_entities_ && entity_resolver_) {
            auto resolved = entity_resolver_->resolve_entity(name);
            if (resolved) return *resolved;
        }
        // If we can't resolve, return the literal reference
        return "&" + name + ";";
    }

    /// Skip whitespace.
    void skip_whitespace() {
        while (pos_ < input_size_) {
            char c = peek();
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                advance();
            } else {
                break;
            }
        }
    }

    /// Scan the next token.
    XmlToken scan_token() {
        if (eof()) {
            return make_token(XmlTokenKind::Eof, "");
        }

        // Check for buffered tokens from tag parsing
        char c = peek();

        // Text content
        if (c != '<') {
            return scan_characters();
        }

        // We have a '<'
        XmlSourcePosition tag_pos = current_position();
        advance(); // consume '<'

        if (eof()) {
            return make_token(XmlTokenKind::Error, "Unexpected end of input after '<'");
        }

        c = peek();

        // Processing instruction: <?
        if (c == '?') {
            return scan_processing_instruction(tag_pos);
        }

        // End tag: </
        if (c == '/') {
            advance(); // consume '/'
            XmlToken tok = make_token(XmlTokenKind::TagClose, "");
            tok.pos = tag_pos;
            return tok;
        }

        // Comment: <!--
        if (c == '!') {
            advance(); // consume '!'
            if (matches("--")) {
                return scan_comment(tag_pos);
            }
            if (matches("[CDATA[")) {
                return scan_cdata(tag_pos);
            }
            if (matches("DOCTYPE")) {
                return scan_doctype(tag_pos);
            }
            // Unrecognized <! sequence
            return make_token(XmlTokenKind::Error, "Unrecognized '<!' construct");
        }

        // Start tag or self-closing tag: <name
        return scan_start_tag(tag_pos);
    }

    /// Scan text content between tags.
    XmlToken scan_characters() {
        XmlSourcePosition pos = current_position();
        std::string text;
        bool has_non_space = false;

        while (pos_ < input_size_) {
            char c = peek();
            if (c == '<') break;
            if (c == '&') {
                std::string entity = read_entity_reference();
                text += entity;
                if (entity.find_first_not_of(" \t\n\r") != std::string::npos) {
                    has_non_space = true;
                }
            } else {
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    has_non_space = true;
                }
                text.push_back(advance());
            }
        }

        // Optimize: skip pure whitespace text nodes if we're not preserving them
        if (!has_non_space && text.empty()) {
            XmlToken tok = make_token(XmlTokenKind::Characters, "");
            tok.pos = pos;
            return tok;
        }

        XmlToken tok = make_token(XmlTokenKind::Characters, text);
        tok.pos = pos;
        return tok;
    }

    /// Scan a processing instruction: <?target data?>
    XmlToken scan_processing_instruction(const XmlSourcePosition& pos) {
        advance(); // consume '?'
        std::string target = read_name();

        // Skip whitespace between target and data
        skip_whitespace();

        std::string data = read_until("?>");
        if (matches("?>")) {
            advance(); advance(); // consume '?>'
        }

        XmlToken tok = make_token(XmlTokenKind::PITarget, target);
        tok.pos = pos;
        tok.quote_char = '\0';
        // We store the PI data in the next token
        XmlToken data_tok = make_token(XmlTokenKind::Characters, data);
        data_tok.pos = pos;
        buffered_.push_back(std::move(data_tok));

        return tok;
    }

    /// Scan a comment: <!-- ... -->
    XmlToken scan_comment(const XmlSourcePosition& pos) {
        advance(); advance(); // consume '--'
        std::string text;
        while (pos_ < input_size_) {
            if (matches("--")) {
                advance(); advance(); // consume '--'
                if (peek() == '>') {
                    advance(); // consume '>'
                    break;
                }
                text += "--";
            } else {
                text.push_back(advance());
            }
        }
        XmlToken tok = make_token(XmlTokenKind::Comment, text);
        tok.pos = pos;
        return tok;
    }

    /// Scan a CDATA section: <![CDATA[ ... ]]>
    XmlToken scan_cdata(const XmlSourcePosition& pos) {
        advance(); advance(); advance(); advance(); advance(); advance(); advance(); // consume '[CDATA['
        std::string text = read_until("]]>");
        if (matches("]]>")) {
            advance(); advance(); advance(); // consume ']]>'
        }
        XmlToken tok = make_token(XmlTokenKind::CData, text);
        tok.pos = pos;
        return tok;
    }

    /// Scan a DOCTYPE declaration.
    XmlToken scan_doctype(const XmlSourcePosition& pos) {
        advance(); advance(); advance(); advance(); advance(); advance(); advance(); // consume 'DOCTYPE'
        skip_whitespace();
        std::string name = read_name();

        // Store the name and set up buffered tokens for the full DOCTYPE info
        XmlToken tok = make_token(XmlTokenKind::DocType, name);
        tok.pos = pos;

        // Push the rest of the DOCTYPE as a single token value
        skip_whitespace();
        std::string rest;
        int depth = 0;
        while (pos_ < input_size_) {
            char c = peek();
            if (c == '[') { depth++; rest.push_back(advance()); }
            else if (c == ']') {
                if (depth == 0 && matches("]>")) {
                    advance(); // consume ']'
                    advance(); // consume '>'
                    break;
                }
                depth--;
                rest.push_back(advance());
            }
            else if (c == '>' && depth == 0) {
                advance();
                break;
            }
            else {
                rest.push_back(advance());
            }
        }

        XmlToken rest_tok = make_token(XmlTokenKind::Characters, rest);
        rest_tok.pos = pos;
        buffered_.push_back(std::move(rest_tok));

        return tok;
    }

    /// Scan a start tag or self-closing tag: <name ...
    XmlToken scan_start_tag(const XmlSourcePosition& pos) {
        std::string name = read_name();

        if (name.empty()) {
            return make_token(XmlTokenKind::Error, "Expected element name");
        }

        // Check if this is a namespace-aware name
        XmlToken tok = make_token(XmlTokenKind::Name, name);
        tok.pos = pos;
        return tok;
    }

    /// Helper to create a token.
    XmlToken make_token(XmlTokenKind kind, std::string value) {
        XmlToken tok;
        tok.kind = kind;
        tok.value = std::move(value);
        tok.pos = current_position();
        return tok;
    }

    const char* input_;
    std::size_t input_size_;
    std::size_t pos_;
    std::size_t line_;
    std::size_t column_;
    bool in_dtd_;
    bool expand_entities_;
    std::deque<XmlToken> buffered_;
    std::shared_ptr<XmlEntityResolver> entity_resolver_;
};

// ============================================================================
// Namespace context stack
// ============================================================================

/// Maintains the in-scope namespace prefix-to-URI mappings.
class XmlNamespaceContext {
public:
    XmlNamespaceContext() {
        // Always define xml: prefix
        declare_prefix("xml", "http://www.w3.org/XML/1998/namespace");
    }

    /// Start a new scope (enter an element).
    void push_scope() {
        scopes_.push_back({});
    }

    /// End the current scope (leave an element).
    void pop_scope() {
        if (!scopes_.empty()) {
            for (const auto& decl : scopes_.back().declarations) {
                // Remove from prefix->uri cache
                auto it = prefix_to_uri_.find(decl.first);
                if (it != prefix_to_uri_.end() && it->second == decl.second) {
                    prefix_to_uri_.erase(it);
                }
                // Remove from uri->prefix cache
                auto uit = uri_to_prefix_.find(decl.second);
                if (uit != uri_to_prefix_.end() && uit->second == decl.first) {
                    uri_to_prefix_.erase(uit);
                }
            }
            scopes_.pop_back();
        }
    }

    /// Declare a namespace prefix in the current scope.
    void declare_prefix(const std::string& prefix, const std::string& uri) {
        if (!scopes_.empty()) {
            scopes_.back().declarations.emplace_back(prefix, uri);
            scopes_.back().mappings[prefix] = uri;
        }
        prefix_to_uri_[prefix] = uri;
        uri_to_prefix_[uri] = prefix;
    }

    /// Look up the URI for a prefix.
    std::string resolve_prefix(const std::string& prefix) const {
        auto it = prefix_to_uri_.find(prefix);
        if (it != prefix_to_uri_.end()) return it->second;
        return "";
    }

    /// Look up a prefix for a URI.
    std::string resolve_uri(const std::string& uri) const {
        auto it = uri_to_prefix_.find(uri);
        if (it != uri_to_prefix_.end()) return it->second;
        return "";
    }

    /// Split a qualified name into prefix and local name.
    static std::pair<std::string, std::string> split_qname(const std::string& qname) {
        auto colon = qname.find(':');
        if (colon == std::string::npos) {
            return {"", qname};
        }
        return {qname.substr(0, colon), qname.substr(colon + 1)};
    }

    /// Get all prefixes declared in the current scope.
    std::vector<std::pair<std::string,std::string>> current_declarations() const {
        if (scopes_.empty()) return {};
        return scopes_.back().declarations;
    }

private:
    struct Scope {
        std::map<std::string, std::string> mappings;
        std::vector<std::pair<std::string,std::string>> declarations;
    };
    std::vector<Scope> scopes_;
    std::map<std::string, std::string> prefix_to_uri_;
    std::map<std::string, std::string> uri_to_prefix_;
};

// ============================================================================
// XML Node types for DOM
// ============================================================================

/// Type of XML DOM node.
enum class XmlNodeType : uint8_t {
    None = 0,
    Document,
    Element,
    Text,
    Comment,
    ProcessingInstruction,
    CData,
    DocumentType,
    Attribute,
    Namespace,
    EntityReference,
};

/// Base class for all XML DOM nodes.
class XmlNode {
public:
    XmlNode() = default;
    virtual ~XmlNode() = default;

    // unique_ptr children prevent copy - use clone() instead
    // clone() declared below at line 1022
    XmlNode(const XmlNode&) = delete;
    XmlNode& operator=(const XmlNode&) = delete;
    XmlNode(XmlNode&&) = default;
    XmlNode& operator=(XmlNode&&) = default;

    virtual XmlNodeType type() const = 0;
    virtual std::string node_name() const = 0;
    virtual std::string node_value() const { return ""; }

    /// Parent node (null for document).
    XmlNode* parent() const { return parent_; }
    void set_parent(XmlNode* p) { parent_ = p; }

    /// First child.
    XmlNode* first_child() const {
        return children_.empty() ? nullptr : children_.front().get();
    }

    /// Last child.
    XmlNode* last_child() const {
        return children_.empty() ? nullptr : children_.back().get();
    }

    /// Next sibling.
    XmlNode* next_sibling() const {
        if (!parent_) return nullptr;
        const auto& siblings = parent_->children_;
        for (std::size_t i = 0; i + 1 < siblings.size(); ++i) {
            if (siblings[i].get() == this) return siblings[i + 1].get();
        }
        return nullptr;
    }

    /// Previous sibling.
    XmlNode* previous_sibling() const {
        if (!parent_) return nullptr;
        const auto& siblings = parent_->children_;
        for (std::size_t i = 1; i < siblings.size(); ++i) {
            if (siblings[i].get() == this) return siblings[i - 1].get();
        }
        return nullptr;
    }

    /// Number of children.
    std::size_t child_count() const { return children_.size(); }

    /// Child at index.
    XmlNode* child_at(std::size_t index) const {
        if (index >= children_.size()) return nullptr;
        return children_[index].get();
    }

    /// Append a child node.
    void append_child(std::unique_ptr<XmlNode> child) {
        child->set_parent(this);
        children_.push_back(std::move(child));
    }

    /// Insert a child at a specific index.
    void insert_child(std::size_t index, std::unique_ptr<XmlNode> child) {
        if (index > children_.size()) index = children_.size();
        child->set_parent(this);
        children_.insert(children_.begin() + static_cast<long>(index), std::move(child));
    }

    /// Remove a child node.
    std::unique_ptr<XmlNode> remove_child(XmlNode* child) {
        for (auto it = children_.begin(); it != children_.end(); ++it) {
            if (it->get() == child) {
                auto removed = std::move(*it);
                children_.erase(it);
                removed->set_parent(nullptr);
                return removed;
            }
        }
        return nullptr;
    }

    /// Remove all children.
    void remove_all_children() {
        for (auto& child : children_) {
            child->set_parent(nullptr);
        }
        children_.clear();
    }

    /// Clone this node (deep copy of subtree).
    virtual std::unique_ptr<XmlNode> clone() const = 0;

    /// Get child elements (convenience).
    std::vector<XmlElement*> child_elements() const;

    /// Get owner document. Returns null if not attached to a document.
    XmlDocument* owner_document() const;

    /// Serialize this node and children to a string.
    virtual void serialize(std::ostream& os, int indent = 0, bool pretty = false) const = 0;

    /// Serialize to string (convenience).
    std::string to_string(bool pretty = false) const {
        std::ostringstream oss;
        serialize(oss, 0, pretty);
        return oss.str();
    }

protected:
    XmlNode* parent_ = nullptr;
    std::vector<std::unique_ptr<XmlNode>> children_;
};

// ============================================================================
// XML Attribute
// ============================================================================

/// Represents an attribute on an XML element.
class XmlAttribute : public XmlNode {
public:
    XmlAttribute() = default;
    XmlAttribute(const std::string& name, const std::string& value,
                 const std::string& ns_uri = "")
        : name_(name), value_(value), namespace_uri_(ns_uri) {}

    XmlNodeType type() const override { return XmlNodeType::Attribute; }
    std::string node_name() const override { return name_; }
    std::string node_value() const override { return value_; }

    const std::string& name() const { return name_; }
    const std::string& value() const { return value_; }
    const std::string& namespace_uri() const { return namespace_uri_; }

    void set_name(const std::string& n) { name_ = n; }
    void set_value(const std::string& v) { value_ = v; }
    void set_namespace_uri(const std::string& uri) { namespace_uri_ = uri; }

    /// Get the local name (without prefix).
    std::string local_name() const {
        auto colon = name_.find(':');
        if (colon == std::string::npos) return name_;
        return name_.substr(colon + 1);
    }

    /// Get the prefix (empty if none).
    std::string prefix() const {
        auto colon = name_.find(':');
        if (colon == std::string::npos) return "";
        return name_.substr(0, colon);
    }

    std::unique_ptr<XmlNode> clone() const override {
        return std::make_unique<XmlAttribute>(name_, value_, namespace_uri_);
    }

    void serialize(std::ostream& os, int, bool) const override {
        os << name_ << "=\"" << escaped_value() << "\"";
    }

private:
    std::string escaped_value() const {
        std::string result;
        result.reserve(value_.size());
        for (char c : value_) {
            switch (c) {
                case '"':  result += "&quot;"; break;
                case '&':  result += "&amp;";  break;
                case '<':  result += "&lt;";   break;
                case '>':  result += "&gt;";   break;
                default:   result.push_back(c); break;
            }
        }
        return result;
    }

    std::string name_;
    std::string value_;
    std::string namespace_uri_;
};

// ============================================================================
// XML Element
// ============================================================================

class XmlElement : public XmlNode {
public:
    XmlElement() = default;
    explicit XmlElement(const std::string& name, const std::string& ns_uri = "")
        : name_(name), namespace_uri_(ns_uri) {}

    XmlNodeType type() const override { return XmlNodeType::Element; }
    std::string node_name() const override { return name_; }
    std::string node_value() const override {
        std::string text;
        for (const auto& child : children_) {
            if (child->type() == XmlNodeType::Text ||
                child->type() == XmlNodeType::CData) {
                text += child->node_value();
            }
        }
        return text;
    }

    const std::string& name() const { return name_; }
    void set_name(const std::string& n) { name_ = n; }

    const std::string& namespace_uri() const { return namespace_uri_; }
    void set_namespace_uri(const std::string& uri) { namespace_uri_ = uri; }

    /// Local name (without prefix).
    std::string local_name() const {
        auto colon = name_.find(':');
        if (colon == std::string::npos) return name_;
        return name_.substr(colon + 1);
    }

    /// Prefix (empty if none).
    std::string prefix() const {
        auto colon = name_.find(':');
        if (colon == std::string::npos) return "";
        return name_.substr(0, colon);
    }

    // --- Attribute access ---

    /// Set an attribute.
    void set_attribute(const std::string& name, const std::string& value) {
        auto it = attributes_.find(name);
        if (it != attributes_.end()) {
            it->second->set_value(value);
        } else {
            auto attr = std::make_unique<XmlAttribute>(name, value);
            XmlAttribute* ptr = attr.get();
            attributes_[name] = std::move(attr);
            attribute_order_.push_back(ptr);
        }
    }

    /// Get an attribute value.
    std::string get_attribute(const std::string& name) const {
        auto it = attributes_.find(name);
        if (it != attributes_.end()) return it->second->value();
        return "";
    }

    /// Check if an attribute exists.
    bool has_attribute(const std::string& name) const {
        return attributes_.find(name) != attributes_.end();
    }

    /// Remove an attribute.
    void remove_attribute(const std::string& name) {
        auto it = attributes_.find(name);
        if (it != attributes_.end()) {
            attribute_order_.erase(
                std::remove(attribute_order_.begin(), attribute_order_.end(), it->second.get()),
                attribute_order_.end());
            attributes_.erase(it);
        }
    }

    /// Get all attribute names.
    std::vector<std::string> attribute_names() const {
        std::vector<std::string> names;
        names.reserve(attributes_.size());
        for (const auto& [name, attr] : attributes_) {
            names.push_back(name);
        }
        return names;
    }

    /// Get ordered attributes.
    const std::vector<XmlAttribute*>& ordered_attributes() const { return attribute_order_; }

    /// Get the number of attributes.
    std::size_t attribute_count() const { return attributes_.size(); }

    // --- Element lookup ---

    /// Find the first child element with a given tag name.
    XmlElement* first_child_element(const std::string& name) const {
        for (const auto& child : children_) {
            if (child->type() == XmlNodeType::Element) {
                auto* elem = static_cast<XmlElement*>(child.get());
                if (elem->name() == name) return elem;
            }
        }
        return nullptr;
    }

    /// Find all child elements with a given tag name.
    std::vector<XmlElement*> child_elements_by_name(const std::string& name) const {
        std::vector<XmlElement*> result;
        for (const auto& child : children_) {
            if (child->type() == XmlNodeType::Element) {
                auto* elem = static_cast<XmlElement*>(child.get());
                if (elem->name() == name) result.push_back(elem);
            }
        }
        return result;
    }

    /// Find a descendant element by a sequence of tag names (path-like).
    XmlElement* find_element_by_path(const std::vector<std::string>& path, std::size_t idx = 0) const {
        if (idx >= path.size()) return const_cast<XmlElement*>(this);
        for (const auto& child : children_) {
            if (child->type() == XmlNodeType::Element) {
                auto* elem = static_cast<XmlElement*>(child.get());
                if (elem->name() == path[idx]) {
                    if (idx + 1 == path.size()) return elem;
                    auto* found = elem->find_element_by_path(path, idx + 1);
                    if (found) return found;
                }
            }
        }
        return nullptr;
    }

    /// Recursively find all elements with a given tag name.
    std::vector<XmlElement*> find_all_elements(const std::string& name) const {
        std::vector<XmlElement*> result;
        collect_elements(name, result);
        return result;
    }

    std::unique_ptr<XmlNode> clone() const override {
        auto elem = std::make_unique<XmlElement>(name_, namespace_uri_);
        for (const auto* attr : attribute_order_) {
            elem->set_attribute(attr->name(), attr->value());
        }
        for (const auto& child : children_) {
            elem->append_child(child->clone());
        }
        return elem;
    }

    void serialize(std::ostream& os, int indent, bool pretty) const override {
        do_indent(os, indent, pretty);
        os << "<" << name_;
        for (const auto* attr : attribute_order_) {
            os << " ";
            attr->serialize(os, 0, false);
        }
        if (children_.empty()) {
            os << "/>";
            if (pretty) os << "\n";
        } else {
            os << ">";
            if (pretty && children_.size() == 1 &&
                (children_[0]->type() == XmlNodeType::Text ||
                 children_[0]->type() == XmlNodeType::CData)) {
                children_[0]->serialize(os, 0, false);
            } else {
                if (pretty) os << "\n";
                for (const auto& child : children_) {
                    child->serialize(os, indent + 1, pretty);
                }
                do_indent(os, indent, pretty);
            }
            os << "</" << name_ << ">";
            if (pretty) os << "\n";
        }
    }

private:
    void collect_elements(const std::string& name, std::vector<XmlElement*>& out) const {
        for (const auto& child : children_) {
            if (child->type() == XmlNodeType::Element) {
                auto* elem = static_cast<XmlElement*>(child.get());
                if (elem->name() == name) out.push_back(elem);
                elem->collect_elements(name, out);
            }
        }
    }

    static void do_indent(std::ostream& os, int indent, bool pretty) {
        if (pretty) {
            for (int i = 0; i < indent; ++i) os << "  ";
        }
    }

    std::string name_;
    std::string namespace_uri_;
    std::map<std::string, std::unique_ptr<XmlAttribute>> attributes_;
    std::vector<XmlAttribute*> attribute_order_;
};

// XmlNode::child_elements() implementation
inline std::vector<XmlElement*> XmlNode::child_elements() const {
    std::vector<XmlElement*> result;
    for (const auto& child : children_) {
        if (child->type() == XmlNodeType::Element) {
            result.push_back(static_cast<XmlElement*>(child.get()));
        }
    }
    return result;
}

// ============================================================================
// XML Text Node
// ============================================================================

class XmlText : public XmlNode {
public:
    XmlText() = default;
    explicit XmlText(const std::string& data) : data_(data) {}

    XmlNodeType type() const override { return XmlNodeType::Text; }
    std::string node_name() const override { return "#text"; }
    std::string node_value() const override { return data_; }

    const std::string& data() const { return data_; }
    void set_data(const std::string& d) { data_ = d; }

    bool is_whitespace() const {
        return data_.find_first_not_of(" \t\n\r") == std::string::npos;
    }

    std::unique_ptr<XmlNode> clone() const override {
        return std::make_unique<XmlText>(data_);
    }

    void serialize(std::ostream& os, int indent, bool pretty) const override {
        if (pretty && !is_whitespace()) {
            do_indent(os, indent);
        }
        os << escaped_data();
    }

private:
    static void do_indent(std::ostream& os, int indent) {
        for (int i = 0; i < indent; ++i) os << "  ";
    }

    std::string escaped_data() const {
        std::string result;
        result.reserve(data_.size());
        for (char c : data_) {
            switch (c) {
                case '&':  result += "&amp;";  break;
                case '<':  result += "&lt;";   break;
                case '>':  result += "&gt;";   break;
                case '\r': result += "&#13;";  break;
                default:   result.push_back(c); break;
            }
        }
        return result;
    }

    std::string data_;
};

// ============================================================================
// XML Comment Node
// ============================================================================

class XmlComment : public XmlNode {
public:
    XmlComment() = default;
    explicit XmlComment(const std::string& data) : data_(data) {}

    XmlNodeType type() const override { return XmlNodeType::Comment; }
    std::string node_name() const override { return "#comment"; }
    std::string node_value() const override { return data_; }

    const std::string& data() const { return data_; }
    void set_data(const std::string& d) { data_ = d; }

    std::unique_ptr<XmlNode> clone() const override {
        return std::make_unique<XmlComment>(data_);
    }

    void serialize(std::ostream& os, int indent, bool pretty) const override {
        if (pretty) {
            for (int i = 0; i < indent; ++i) os << "  ";
        }
        os << "<!--" << data_ << "-->";
        if (pretty) os << "\n";
    }

private:
    std::string data_;
};

// ============================================================================
// XML Processing Instruction Node
// ============================================================================

class XmlProcessingInstruction : public XmlNode {
public:
    XmlProcessingInstruction() = default;
    XmlProcessingInstruction(const std::string& target, const std::string& data)
        : target_(target), data_(data) {}

    XmlNodeType type() const override { return XmlNodeType::ProcessingInstruction; }
    std::string node_name() const override { return target_; }
    std::string node_value() const override { return data_; }

    const std::string& target() const { return target_; }
    const std::string& data() const { return data_; }
    void set_target(const std::string& t) { target_ = t; }
    void set_data(const std::string& d) { data_ = d; }

    std::unique_ptr<XmlNode> clone() const override {
        return std::make_unique<XmlProcessingInstruction>(target_, data_);
    }

    void serialize(std::ostream& os, int indent, bool pretty) const override {
        if (pretty) {
            for (int i = 0; i < indent; ++i) os << "  ";
        }
        os << "<?" << target_;
        if (!data_.empty()) os << " " << data_;
        os << "?>";
        if (pretty) os << "\n";
    }

private:
    std::string target_;
    std::string data_;
};

// ============================================================================
// XML CDATA Node
// ============================================================================

class XmlCData : public XmlNode {
public:
    XmlCData() = default;
    explicit XmlCData(const std::string& data) : data_(data) {}

    XmlNodeType type() const override { return XmlNodeType::CData; }
    std::string node_name() const override { return "#cdata-section"; }
    std::string node_value() const override { return data_; }

    const std::string& data() const { return data_; }
    void set_data(const std::string& d) { data_ = d; }

    std::unique_ptr<XmlNode> clone() const override {
        return std::make_unique<XmlCData>(data_);
    }

    void serialize(std::ostream& os, int indent, bool pretty) const override {
        if (pretty) {
            for (int i = 0; i < indent; ++i) os << "  ";
        }
        os << "<![CDATA[" << data_ << "]]>";
        if (pretty) os << "\n";
    }

private:
    std::string data_;
};

// ============================================================================
// XML Document Type Node
// ============================================================================

class XmlDocumentType : public XmlNode {
public:
    XmlDocumentType() = default;
    XmlDocumentType(const std::string& name,
                    const std::string& public_id,
                    const std::string& system_id)
        : name_(name), public_id_(public_id), system_id_(system_id) {}

    XmlNodeType type() const override { return XmlNodeType::DocumentType; }
    std::string node_name() const override { return name_; }
    std::string node_value() const override { return ""; }

    const std::string& name() const { return name_; }
    const std::string& public_id() const { return public_id_; }
    const std::string& system_id() const { return system_id_; }

    std::unique_ptr<XmlNode> clone() const override {
        return std::make_unique<XmlDocumentType>(name_, public_id_, system_id_);
    }

    void serialize(std::ostream& os, int, bool pretty) const override {
        os << "<!DOCTYPE " << name_;
        if (!public_id_.empty()) {
            os << " PUBLIC \"" << public_id_ << "\"";
        }
        if (!system_id_.empty()) {
            os << " \"" << system_id_ << "\"";
        }
        os << ">";
        if (pretty) os << "\n";
    }

private:
    std::string name_;
    std::string public_id_;
    std::string system_id_;
};

// ============================================================================
// XML Document (root of DOM tree)
// ============================================================================

class XmlDocument : public XmlNode {
public:
    XmlDocument() { version_ = "1.0"; encoding_ = "UTF-8"; }

    XmlNodeType type() const override { return XmlNodeType::Document; }
    std::string node_name() const override { return "#document"; }

    /// Get the document element (root element).
    XmlElement* document_element() const {
        for (const auto& child : children_) {
            if (child->type() == XmlNodeType::Element) {
                return static_cast<XmlElement*>(child.get());
            }
        }
        return nullptr;
    }

    /// Set the document element.
    void set_document_element(std::unique_ptr<XmlElement> elem) {
        // Remove any existing element children
        children_.erase(
            std::remove_if(children_.begin(), children_.end(),
                [](const auto& c) { return c->type() == XmlNodeType::Element; }),
            children_.end());
        append_child(std::move(elem));
    }

    /// Get/set XML version.
    const std::string& version() const { return version_; }
    void set_version(const std::string& v) { version_ = v; }

    /// Get/set encoding.
    const std::string& encoding() const { return encoding_; }
    void set_encoding(const std::string& e) { encoding_ = e; }

    /// Get/set standalone.
    bool standalone() const { return standalone_; }
    void set_standalone(bool s) { standalone_ = s; }

    /// Create a new element (not attached to tree).
    std::unique_ptr<XmlElement> create_element(const std::string& name) {
        return std::make_unique<XmlElement>(name);
    }

    /// Create a new text node.
    std::unique_ptr<XmlText> create_text_node(const std::string& data) {
        return std::make_unique<XmlText>(data);
    }

    /// Create a new comment node.
    std::unique_ptr<XmlComment> create_comment(const std::string& data) {
        return std::make_unique<XmlComment>(data);
    }

    /// Create a new CDATA node.
    std::unique_ptr<XmlCData> create_cdata(const std::string& data) {
        return std::make_unique<XmlCData>(data);
    }

    /// Create a new PI node.
    std::unique_ptr<XmlProcessingInstruction> create_processing_instruction(
        const std::string& target, const std::string& data) {
        return std::make_unique<XmlProcessingInstruction>(target, data);
    }

    /// Create a new attribute.
    std::unique_ptr<XmlAttribute> create_attribute(const std::string& name,
                                                    const std::string& value) {
        return std::make_unique<XmlAttribute>(name, value);
    }

    std::unique_ptr<XmlNode> clone() const override {
        auto doc = std::make_unique<XmlDocument>();
        doc->version_ = version_;
        doc->encoding_ = encoding_;
        doc->standalone_ = standalone_;
        for (const auto& child : children_) {
            doc->append_child(child->clone());
        }
        return doc;
    }

    void serialize(std::ostream& os, int indent, bool pretty) const override {
        os << "<?xml version=\"" << version_ << "\" encoding=\"" << encoding_ << "\"";
        if (standalone_) os << " standalone=\"yes\"";
        os << "?>";
        if (pretty) os << "\n";
        for (const auto& child : children_) {
            child->serialize(os, indent, pretty);
        }
    }

    /// Parse an XML string into this document.
    void parse(const std::string& xml_text);

    /// Find elements by tag name (convenience).
    std::vector<XmlElement*> get_elements_by_tag_name(const std::string& name) const {
        std::vector<XmlElement*> result;
        auto* root = document_element();
        if (root) {
            if (root->name() == name) result.push_back(root);
            auto children = root->find_all_elements(name);
            result.insert(result.end(), children.begin(), children.end());
        }
        return result;
    }

    /// Find an element by ID (looks for xml:id or id attributes).
    XmlElement* get_element_by_id(const std::string& id) const {
        return find_by_id_recursive(document_element(), id);
    }

private:
    XmlElement* find_by_id_recursive(XmlElement* elem, const std::string& id) const {
        if (!elem) return nullptr;
        // Check xml:id attribute
        if (elem->get_attribute("xml:id") == id) return elem;
        if (elem->get_attribute("id") == id) return elem;
        for (const auto& child : elem->child_elements()) {
            auto* found = find_by_id_recursive(child, id);
            if (found) return found;
        }
        return nullptr;
    }

    std::string version_;
    std::string encoding_;
    bool standalone_ = false;
};

// ============================================================================
// SAX Parser (event-driven)
// ============================================================================

/// Streaming SAX-style XML parser. Drives the lexer and translates tokens
/// into high-level events delivered to a SaxHandler.
class XmlSaxParser {
public:
    XmlSaxParser()
        : handler_(nullptr)
        , expand_entities_(true)
        , validate_(true)
        , preserve_whitespace_(false)
    {
        lexer_.set_expand_entities(expand_entities_);
    }

    /// Set the event handler. The handler must outlive the parser or be
    /// removed before destruction.
    void set_handler(SaxHandler* handler) { handler_ = handler; }
    SaxHandler* handler() const { return handler_; }

    /// Set the entity resolver.
    void set_entity_resolver(std::shared_ptr<XmlEntityResolver> resolver) {
        entity_resolver_ = std::move(resolver);
        lexer_.set_entity_resolver(entity_resolver_);
    }

    /// Enable or disable entity expansion.
    void set_expand_entities(bool expand) {
        expand_entities_ = expand;
        lexer_.set_expand_entities(expand);
    }

    /// Enable or disable validation.
    void set_validate(bool v) { validate_ = v; }
    bool validate() const { return validate_; }

    /// Whether to preserve ignorable whitespace.
    void set_preserve_whitespace(bool p) { preserve_whitespace_ = p; }
    bool preserve_whitespace() const { return preserve_whitespace_; }

    /// Parse XML text, delivering events to the handler.
    void parse(const std::string& xml_text) {
        parse_view(std::string_view(xml_text));
    }

    /// Parse from a string_view.
    void parse_view(std::string_view xml_text) {
        namespace_context_ = XmlNamespaceContext();
        element_stack_.clear();
        has_root_element_ = false;
        current_text_.clear();

        lexer_.reset_view(xml_text);

        if (handler_) {
            handler_->start_document();
        }

        parse_content();

        if (handler_) {
            handler_->end_document();
        }
    }

    /// Get the namespace context (useful for post-parse inspection).
    const XmlNamespaceContext& namespace_context() const {
        return namespace_context_;
    }

private:
    /// Parse the main content of the document.
    void parse_content() {
        XmlToken tok;
        while (true) {
            tok = lexer_.next_token();
            switch (tok.kind) {
                case XmlTokenKind::Eof:
                    if (validate_ && !has_root_element_) {
                        error("Document has no root element", tok.pos);
                    }
                    return;

                case XmlTokenKind::PITarget:
                    handle_processing_instruction(tok);
                    break;

                case XmlTokenKind::Comment:
                    flush_text();
                    if (handler_) handler_->comment(tok.value);
                    break;

                case XmlTokenKind::DocType:
                    handle_doctype(tok);
                    break;

                case XmlTokenKind::Name:
                    handle_start_element(tok);
                    break;

                case XmlTokenKind::TagClose:
                    handle_end_element(tok);
                    break;

                case XmlTokenKind::Characters:
                    if (!tok.value.empty()) {
                        current_text_ += tok.value;
                    }
                    break;

                case XmlTokenKind::CData:
                    flush_text();
                    if (handler_) handler_->cdata(tok.value);
                    break;

                case XmlTokenKind::Error:
                    error(tok.value, tok.pos);
                    return;

                default:
                    // Unexpected token in content
                    {
                        std::ostringstream oss;
                        oss << "Unexpected token in content: " << token_kind_name(tok.kind);
                        error(oss.str(), tok.pos);
                    }
                    return;
            }
        }
    }

    /// Handle a processing instruction.
    void handle_processing_instruction(XmlToken& target_tok) {
        flush_text();
        std::string target = target_tok.value;
        std::string data;

        // XML declaration handling
        if (target == "xml") {
            parse_xml_declaration();
            return;
        }

        // Read PI data token
        XmlToken data_tok = lexer_.next_token();
        if (data_tok.kind == XmlTokenKind::Characters) {
            data = data_tok.value;
        } else {
            lexer_.push_back(std::move(data_tok));
        }

        if (handler_) {
            handler_->processing_instruction(target, data);
        }
    }

    /// Parse XML declaration attributes.
    void parse_xml_declaration() {
        // We already consumed the 'xml' PI target.
        // The PI data should contain version, encoding, standalone.
        XmlToken data_tok = lexer_.next_token();
        std::string data;
        if (data_tok.kind == XmlTokenKind::Characters) {
            data = data_tok.value;
        }

        // Parse pseudo-attributes from the declaration
        std::string version = "1.0";
        std::string encoding = "UTF-8";
        bool standalone = false;

        auto attrs = parse_pseudo_attributes(data);
        for (const auto& [key, value] : attrs) {
            if (key == "version") version = value;
            else if (key == "encoding") encoding = value;
            else if (key == "standalone") standalone = (value == "yes");
        }

        // Store in document properties
        version_ = version;
        encoding_ = encoding;
        standalone_ = standalone;
    }

    /// Parse pseudo-attributes from a string like 'version="1.0" encoding="UTF-8"'
    std::map<std::string, std::string> parse_pseudo_attributes(const std::string& data) {
        std::map<std::string, std::string> attrs;
        std::size_t pos = 0;
        while (pos < data.size()) {
            // Skip whitespace
            while (pos < data.size() && std::isspace(static_cast<unsigned char>(data[pos]))) {
                ++pos;
            }
            if (pos >= data.size()) break;

            // Read attribute name
            std::size_t name_start = pos;
            while (pos < data.size() && !std::isspace(static_cast<unsigned char>(data[pos]))
                   && data[pos] != '=') {
                ++pos;
            }
            std::string name = data.substr(name_start, pos - name_start);
            if (name.empty()) break;

            // Skip '=' and optional whitespace
            while (pos < data.size() && std::isspace(static_cast<unsigned char>(data[pos]))) ++pos;
            if (pos < data.size() && data[pos] == '=') ++pos;
            while (pos < data.size() && std::isspace(static_cast<unsigned char>(data[pos]))) ++pos;

            // Read quoted value
            if (pos < data.size() && (data[pos] == '"' || data[pos] == '\'')) {
                char quote = data[pos++];
                std::size_t val_start = pos;
                while (pos < data.size() && data[pos] != quote) ++pos;
                std::string value = data.substr(val_start, pos - val_start);
                if (pos < data.size()) ++pos; // skip closing quote
                attrs[name] = value;
            }
        }
        return attrs;
    }

    /// Handle a DOCTYPE declaration.
    void handle_doctype(XmlToken& tok) {
        flush_text();
        std::string name = tok.value;

        // Get the rest of the DOCTYPE data
        XmlToken rest_tok = lexer_.next_token();
        std::string rest;
        if (rest_tok.kind == XmlTokenKind::Characters) {
            rest = rest_tok.value;
        }

        // Parse PUBLIC/SYSTEM identifiers
        std::string public_id, system_id;
        parse_doctype_ids(rest, public_id, system_id);

        if (handler_) {
            handler_->doctype(name, public_id, system_id);
        }
    }

    /// Extract PUBLIC and SYSTEM IDs from DOCTYPE declaration text.
    void parse_doctype_ids(const std::string& text,
                           std::string& public_id,
                           std::string& system_id) {
        auto upper = [](std::string s) {
            std::transform(s.begin(), s.end(), s.begin(),
                [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
            return s;
        };

        std::string upper_text = upper(text);

        auto pub_pos = upper_text.find("PUBLIC");
        auto sys_pos = upper_text.find("SYSTEM");

        if (pub_pos != std::string::npos) {
            // Read public ID (quoted)
            std::size_t qpos = text.find_first_of("\"'", pub_pos + 6);
            if (qpos != std::string::npos) {
                char quote = text[qpos];
                std::size_t end = text.find(quote, qpos + 1);
                if (end != std::string::npos) {
                    public_id = text.substr(qpos + 1, end - qpos - 1);
                    // Look for system ID after public ID
                    std::size_t after = end + 1;
                    qpos = text.find_first_of("\"'", after);
                    if (qpos != std::string::npos) {
                        quote = text[qpos];
                        end = text.find(quote, qpos + 1);
                        if (end != std::string::npos) {
                            system_id = text.substr(qpos + 1, end - qpos - 1);
                        }
                    }
                }
            }
        } else if (sys_pos != std::string::npos) {
            std::size_t qpos = text.find_first_of("\"'", sys_pos + 6);
            if (qpos != std::string::npos) {
                char quote = text[qpos];
                std::size_t end = text.find(quote, qpos + 1);
                if (end != std::string::npos) {
                    system_id = text.substr(qpos + 1, end - qpos - 1);
                }
            }
        }
    }

    /// Handle a start element tag.
    void handle_start_element(XmlToken& name_tok) {
        flush_text();

        if (validate_ && has_root_element_) {
            // Multiple root elements - this is okay if there was a preceding PI/comment,
            // but multiple element roots are not allowed.
            if (element_stack_.empty()) {
                error("Multiple root elements", name_tok.pos);
            }
        }

        std::string qname = name_tok.value;
        std::string uri;
        std::string local_name;
        auto [prefix, lname] = XmlNamespaceContext::split_qname(qname);
        local_name = lname;
        uri = namespace_context_.resolve_prefix(prefix);

        // Parse attributes
        std::map<std::string, std::string> attrs;
        std::vector<std::pair<std::string,std::string>> ordered_attrs;
        bool self_closing = false;

        parse_attributes(attrs, ordered_attrs, self_closing);

        // Push namespace scope before handler callback
        namespace_context_.push_scope();

        // Process namespace declarations in attributes
        for (const auto& [attr_name, attr_value] : ordered_attrs) {
            if (attr_name == "xmlns") {
                namespace_context_.declare_prefix("", attr_value);
                if (handler_) {
                    handler_->start_prefix_mapping("", attr_value);
                }
            } else if (attr_name.compare(0, 6, "xmlns:") == 0) {
                std::string ns_prefix = attr_name.substr(6);
                namespace_context_.declare_prefix(ns_prefix, attr_value);
                if (handler_) {
                    handler_->start_prefix_mapping(ns_prefix, attr_value);
                }
            }
        }

        // Re-resolve URI after namespace declarations are in scope
        uri = namespace_context_.resolve_prefix(prefix);

        has_root_element_ = true;
        element_stack_.push_back({qname, local_name, uri});

        if (handler_) {
            handler_->start_element(uri, local_name, qname, attrs);
        }

        if (self_closing) {
            // Self-closing element: emit end_element immediately
            element_stack_.pop_back();

            // Pop namespace declarations
            auto decls = namespace_context_.current_declarations();
            namespace_context_.pop_scope();

            if (handler_) {
                handler_->end_element(uri, local_name, qname);
                for (const auto& [ns_prefix, ns_uri] : decls) {
                    handler_->end_prefix_mapping(ns_prefix);
                }
            }
        }
    }

    /// Parse attributes of the current element (after name has been consumed).
    void parse_attributes(std::map<std::string,std::string>& attrs,
                          std::vector<std::pair<std::string,std::string>>& ordered,
                          bool& self_closing) {
        while (true) {
            // Skip whitespace between tokens in the tag
            XmlToken tok = lexer_.next_token();

            if (tok.kind == XmlTokenKind::TagEnd) {
                // Regular end of start tag: >
                return;
            }

            if (tok.kind == XmlTokenKind::TagSelfClose) {
                // Self-closing tag: />
                self_closing = true;
                return;
            }

            if (tok.kind == XmlTokenKind::Name || tok.kind == XmlTokenKind::AttrName) {
                std::string attr_name = tok.value;

                // Expect '='
                XmlToken eq_tok = lexer_.next_token();
                if (eq_tok.kind != XmlTokenKind::Equals) {
                    // Could be a bare attribute (SGML-style) or end of tag
                    if (eq_tok.kind == XmlTokenKind::TagEnd) {
                        // Bare attribute with no value
                        attrs[attr_name] = attr_name;
                        ordered.emplace_back(attr_name, attr_name);
                        return;
                    }
                    if (eq_tok.kind == XmlTokenKind::TagSelfClose) {
                        attrs[attr_name] = attr_name;
                        ordered.emplace_back(attr_name, attr_name);
                        self_closing = true;
                        return;
                    }
                    // Push back and treat as bare attribute
                    lexer_.push_back(std::move(eq_tok));
                    attrs[attr_name] = attr_name;
                    ordered.emplace_back(attr_name, attr_name);
                    continue;
                }

                // Expect quoted value
                XmlToken val_tok = lexer_.next_token();
                if (val_tok.kind != XmlTokenKind::AttrValue) {
                    // Might have been parsed as characters or something else
                    std::string val = val_tok.value;
                    attrs[attr_name] = val;
                    ordered.emplace_back(attr_name, val);
                } else {
                    attrs[attr_name] = val_tok.value;
                    ordered.emplace_back(attr_name, val_tok.value);
                }
                continue;
            }

            // Unexpected token in attribute parsing
            if (tok.kind == XmlTokenKind::Eof || tok.kind == XmlTokenKind::Error) {
                error("Unexpected end of input in element tag", tok.pos);
                return;
            }

            // Skip unknown tokens, try to recover
        }
    }

    /// Handle an end element tag.
    void handle_end_element(XmlToken& tok) {
        flush_text();

        // Read the element name
        XmlToken name_tok = lexer_.next_token();
        if (name_tok.kind != XmlTokenKind::Name) {
            error("Expected element name in end tag", name_tok.pos);
            return;
        }

        std::string qname = name_tok.value;

        // Consume the '>'
        XmlToken end_tok = lexer_.next_token();
        if (end_tok.kind != XmlTokenKind::TagEnd) {
            error("Expected '>' in end tag", end_tok.pos);
            return;
        }

        if (validate_ && !element_stack_.empty()) {
            if (element_stack_.back().qname != qname) {
                std::ostringstream oss;
                oss << "Mismatched end tag: expected </" << element_stack_.back().qname
                    << "> but got </" << qname << ">";
                error(oss.str(), name_tok.pos);
            }
        }

        if (element_stack_.empty()) {
            error("Unexpected end tag with no open element", name_tok.pos);
            return;
        }

        auto elem_info = element_stack_.back();
        element_stack_.pop_back();

        // Pop namespace declarations
        auto decls = namespace_context_.current_declarations();
        namespace_context_.pop_scope();

        if (handler_) {
            handler_->end_element(elem_info.uri, elem_info.local_name, elem_info.qname);
            for (const auto& [ns_prefix, ns_uri] : decls) {
                handler_->end_prefix_mapping(ns_prefix);
            }
        }
    }

    /// Flush accumulated text content to handler.
    void flush_text() {
        if (current_text_.empty()) return;

        bool all_whitespace = current_text_.find_first_not_of(" \t\n\r") == std::string::npos;

        if (handler_) {
            if (all_whitespace && !preserve_whitespace_ && !element_stack_.empty()) {
                handler_->ignorable_whitespace(current_text_);
            } else {
                handler_->characters(current_text_);
            }
        }

        current_text_.clear();
    }

    /// Report an error to the handler.
    void error(const std::string& message, const XmlSourcePosition& pos) {
        if (handler_) {
            handler_->fatal_error(message, pos);
        }
        throw XmlParseException(message, pos);
    }

    struct ElementInfo {
        std::string qname;
        std::string local_name;
        std::string uri;
    };

    SaxHandler* handler_;
    XmlLexer lexer_;
    XmlNamespaceContext namespace_context_;
    std::shared_ptr<XmlEntityResolver> entity_resolver_;
    std::vector<ElementInfo> element_stack_;
    std::string current_text_;
    bool expand_entities_;
    bool validate_;
    bool preserve_whitespace_;
    bool has_root_element_;

    // XML declaration info
    std::string version_;
    std::string encoding_;
    bool standalone_;

    friend class XmlDomParser;
    friend class XmlDocument;
};

// ============================================================================
// DOM Parser (builds XmlDocument from SAX events)
// ============================================================================

/// SAX handler that builds a DOM tree.
class DomBuilderHandler : public SaxHandler {
public:
    DomBuilderHandler() : current_element_(nullptr) {
        document_ = std::make_unique<XmlDocument>();
    }

    std::unique_ptr<XmlDocument> release_document() {
        return std::move(document_);
    }

    void start_document() override {
        current_element_ = nullptr;
    }

    void end_document() override {
        current_element_ = nullptr;
    }

    void start_element(const std::string& uri,
                       const std::string& local_name,
                       const std::string& qname,
                       const std::map<std::string,std::string>& attrs) override {
        auto elem = std::make_unique<XmlElement>(qname, uri);
        XmlElement* elem_ptr = elem.get();

        for (const auto& [name, value] : attrs) {
            elem->set_attribute(name, value);
        }

        if (current_element_) {
            current_element_->append_child(std::move(elem));
        } else if (!document_->document_element()) {
            document_->append_child(std::move(elem));
        } else {
            // This shouldn't happen in well-formed XML
            document_->append_child(std::move(elem));
        }

        current_element_ = elem_ptr;
    }

    void end_element(const std::string&, const std::string&, const std::string&) override {
        if (current_element_) {
            current_element_ = static_cast<XmlElement*>(current_element_->parent());
        }
    }

    void characters(const std::string& text) override {
        if (current_element_) {
            current_element_->append_child(std::make_unique<XmlText>(text));
        }
    }

    void ignorable_whitespace(const std::string& ws) override {
        // Optionally skip pure whitespace
        if (current_element_) {
            current_element_->append_child(std::make_unique<XmlText>(ws));
        }
    }

    void comment(const std::string& text) override {
        if (current_element_) {
            current_element_->append_child(std::make_unique<XmlComment>(text));
        } else {
            document_->append_child(std::make_unique<XmlComment>(text));
        }
    }

    void processing_instruction(const std::string& target,
                                const std::string& data) override {
        auto pi = std::make_unique<XmlProcessingInstruction>(target, data);
        if (current_element_) {
            current_element_->append_child(std::move(pi));
        } else {
            document_->append_child(std::move(pi));
        }
    }

    void cdata(const std::string& data) override {
        if (current_element_) {
            current_element_->append_child(std::make_unique<XmlCData>(data));
        }
    }

    void doctype(const std::string& name,
                 const std::string& public_id,
                 const std::string& system_id) override {
        document_->append_child(
            std::make_unique<XmlDocumentType>(name, public_id, system_id));
    }

private:
    std::unique_ptr<XmlDocument> document_;
    XmlElement* current_element_;
};

/// DOM-based XML parser. Uses SAX parser internally and builds a DOM tree.
class XmlDomParser {
public:
    XmlDomParser() {
        sax_parser_.set_handler(&dom_handler_);
    }

    /// Parse XML text and return a document.
    std::unique_ptr<XmlDocument> parse(const std::string& xml_text) {
        dom_handler_ = DomBuilderHandler();
        sax_parser_.set_handler(&dom_handler_);

        try {
            sax_parser_.parse(xml_text);
        } catch (...) {
            sax_parser_.set_handler(nullptr);
            throw;
        }

        return dom_handler_.release_document();
    }

    /// Set the entity resolver.
    void set_entity_resolver(std::shared_ptr<XmlEntityResolver> resolver) {
        sax_parser_.set_entity_resolver(std::move(resolver));
    }

    /// Enable or disable entity expansion.
    void set_expand_entities(bool expand) {
        sax_parser_.set_expand_entities(expand);
    }

    /// Whether to preserve ignorable whitespace in DOM.
    void set_preserve_whitespace(bool preserve) {
        sax_parser_.set_preserve_whitespace(preserve);
    }

    /// Get the underlying SAX parser (for advanced usage).
    XmlSaxParser& sax_parser() { return sax_parser_; }

private:
    XmlSaxParser sax_parser_;
    DomBuilderHandler dom_handler_;
};

// XmlDocument::parse implementation
void XmlDocument::parse(const std::string& xml_text) {
    XmlDomParser dom_parser;
    auto doc = dom_parser.parse(xml_text);
    // Steal the parsed document's content
    *this = std::move(*doc);
}

// ============================================================================
// XPath-like expression engine for DOM queries
// ============================================================================

/// Simple XPath-like path expression node.
struct XPathStep {
    enum class Axis : uint8_t {
        Child,
        Descendant,
        Self,
        Parent,
        Ancestor,
        FollowingSibling,
        PrecedingSibling,
        Attribute,
    };

    Axis axis = Axis::Child;
    std::string node_test; ///< Element name or '*' for any
    bool is_wildcard = false;
    bool is_text_node = false;
    bool is_comment = false;

    /// Optional predicate: [@attr='value']
    struct Predicate {
        enum Op { Equals, NotEquals, Contains, Exists };
        std::string attr_name;
        std::string value;
        Op op = Exists;
    };
    std::vector<Predicate> predicates;

    /// Optional index predicate [N] (1-based)
    int index_predicate = -1;
};

/// A compiled XPath-like expression.
class XPathExpression {
public:
    /// Compile a path expression.
    static XPathExpression compile(const std::string& path) {
        XPathExpression expr;
        expr.parse(path);
        return expr;
    }

    /// Evaluate this expression against a context node.
    std::vector<XmlNode*> evaluate(XmlNode* context) const {
        std::vector<XmlNode*> current_set = {context};
        for (const auto& step : steps_) {
            current_set = evaluate_step(step, current_set);
        }
        return current_set;
    }

    /// Evaluate and return only elements.
    std::vector<XmlElement*> evaluate_elements(XmlNode* context) const {
        auto nodes = evaluate(context);
        std::vector<XmlElement*> elements;
        for (auto* node : nodes) {
            if (node && node->type() == XmlNodeType::Element) {
                elements.push_back(static_cast<XmlElement*>(node));
            }
        }
        return elements;
    }

    /// Evaluate and return string values.
    std::vector<std::string> evaluate_strings(XmlNode* context) const {
        auto nodes = evaluate(context);
        std::vector<std::string> values;
        for (auto* node : nodes) {
            if (node) {
                values.push_back(node->node_value());
            }
        }
        return values;
    }

    /// Evaluate and return the first match.
    XmlNode* evaluate_first(XmlNode* context) const {
        auto nodes = evaluate(context);
        return nodes.empty() ? nullptr : nodes[0];
    }

    /// Get text content of the first match.
    std::string evaluate_first_text(XmlNode* context) const {
        auto* node = evaluate_first(context);
        return node ? node->node_value() : "";
    }

    /// Parse an XPath-like expression.
    void parse(const std::string& path) {
        steps_.clear();
        if (path.empty()) return;

        std::string remaining = path;

        // Handle absolute paths
        if (!remaining.empty() && remaining[0] == '/') {
            remaining = remaining.substr(1);
        }

        while (!remaining.empty()) {
            if (remaining[0] == '/') {
                remaining = remaining.substr(1);
                continue;
            }

            XPathStep step;

            // Check for axis specifiers
            if (remaining.compare(0, 4, "//") == 0) {
                step.axis = XPathStep::Axis::Descendant;
                remaining = remaining.substr(2);
            } else if (remaining.compare(0, 2, "..") == 0) {
                step.axis = XPathStep::Axis::Parent;
                step.is_wildcard = true;
                remaining = remaining.substr(2);
                steps_.push_back(step);
                if (!remaining.empty() && remaining[0] == '/') {
                    remaining = remaining.substr(1);
                }
                continue;
            } else if (remaining.compare(0, 3, "../") == 0) {
                step.axis = XPathStep::Axis::Parent;
                step.is_wildcard = true;
                remaining = remaining.substr(3);
                steps_.push_back(step);
                continue;
            } else if (remaining[0] == '.') {
                step.axis = XPathStep::Axis::Self;
                step.is_wildcard = true;
                remaining = remaining.substr(1);
                steps_.push_back(step);
                if (!remaining.empty() && remaining[0] == '/') {
                    remaining = remaining.substr(1);
                }
                continue;
            }

            // Check for attribute axis: @
            if (remaining[0] == '@') {
                step.axis = XPathStep::Axis::Attribute;
                remaining = remaining.substr(1);
            }

            // Read node test (name or *)
            if (remaining.empty()) break;

            if (remaining[0] == '*') {
                step.is_wildcard = true;
                remaining = remaining.substr(1);
            } else if (remaining == "text()") {
                step.is_text_node = true;
                remaining.clear();
            } else if (remaining == "comment()") {
                step.is_comment = true;
                remaining.clear();
            } else if (remaining == "node()") {
                step.is_wildcard = true;
                step.node_test = "*";
                remaining.clear();
            } else {
                // Read element name
                std::size_t i = 0;
                while (i < remaining.size() &&
                       std::isalnum(static_cast<unsigned char>(remaining[i])) ||
                       remaining[i] == '_' || remaining[i] == '-' ||
                       remaining[i] == '.' || remaining[i] == ':') {
                    i++;
                }
                step.node_test = remaining.substr(0, i);
                remaining = remaining.substr(i);
            }

            // Parse predicates
            while (!remaining.empty() && remaining[0] == '[') {
                remaining = remaining.substr(1);
                auto pred = parse_predicate(remaining);
                step.predicates.push_back(pred);
                if (!remaining.empty() && remaining[0] == ']') {
                    remaining = remaining.substr(1);
                }
            }

            steps_.push_back(step);

            if (!remaining.empty() && remaining[0] == '/') {
                remaining = remaining.substr(1);
            }
        }
    }

    /// Number of steps in the path.
    std::size_t step_count() const { return steps_.size(); }

    /// Get a specific step.
    const XPathStep& step(std::size_t i) const { return steps_[i]; }

private:
    XPathStep::Predicate parse_predicate(std::string& remaining) {
        XPathStep::Predicate pred;

        // Skip whitespace
        auto skip_ws = [](std::string& s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s[0]))) {
                s = s.substr(1);
            }
        };
        skip_ws(remaining);

        // Check if it's just a number
        if (!remaining.empty() && std::isdigit(static_cast<unsigned char>(remaining[0]))) {
            std::size_t i = 0;
            while (i < remaining.size() && std::isdigit(static_cast<unsigned char>(remaining[i]))) {
                i++;
            }
            pred.attr_name = remaining.substr(0, i);
            pred.op = XPathStep::Predicate::Exists;
            pred.value = pred.attr_name;
            remaining = remaining.substr(i);
            skip_ws(remaining);
            return pred;
        }

        // Check for @attr or attr
        bool has_at = false;
        if (!remaining.empty() && remaining[0] == '@') {
            has_at = true;
            remaining = remaining.substr(1);
        }

        // Read attribute name
        std::size_t i = 0;
        while (i < remaining.size() &&
               (std::isalnum(static_cast<unsigned char>(remaining[i])) ||
                remaining[i] == '_' || remaining[i] == '-')) {
            i++;
        }
        if (i == 0) {
            // Not an attr predicate, might be position or other
            return pred;
        }
        pred.attr_name = remaining.substr(0, i);
        remaining = remaining.substr(i);
        skip_ws(remaining);

        // Check for operator
        if (!remaining.empty()) {
            if (remaining[0] == '=') {
                remaining = remaining.substr(1);
                pred.op = XPathStep::Predicate::Equals;
            } else if (remaining.size() >= 2 && remaining[0] == '!' && remaining[1] == '=') {
                remaining = remaining.substr(2);
                pred.op = XPathStep::Predicate::NotEquals;
            }

            if (pred.op != XPathStep::Predicate::Exists) {
                skip_ws(remaining);
                // Read quoted value
                if (!remaining.empty() && (remaining[0] == '\'' || remaining[0] == '"')) {
                    char quote = remaining[0];
                    remaining = remaining.substr(1);
                    std::size_t end = remaining.find(quote);
                    if (end != std::string::npos) {
                        pred.value = remaining.substr(0, end);
                        remaining = remaining.substr(end + 1);
                    }
                }
            }
        }

        skip_ws(remaining);
        return pred;
    }

    static std::vector<XmlNode*> evaluate_step(const XPathStep& step,
                                                const std::vector<XmlNode*>& context_set) {
        std::vector<XmlNode*> result;
        for (auto* node : context_set) {
            if (!node) continue;
            auto matched = apply_step(step, node);
            result.insert(result.end(), matched.begin(), matched.end());
        }
        return result;
    }

    static std::vector<XmlNode*> apply_step(const XPathStep& step, XmlNode* node) {
        std::vector<XmlNode*> candidates;

        switch (step.axis) {
            case XPathStep::Axis::Child:
                collect_children(node, candidates, step);
                break;
            case XPathStep::Axis::Descendant:
                collect_descendants(node, candidates, step);
                break;
            case XPathStep::Axis::Self:
                if (matches_node_test(node, step)) {
                    candidates.push_back(node);
                }
                break;
            case XPathStep::Axis::Parent:
                if (auto* parent = node->parent()) {
                    if (matches_node_test(parent, step)) {
                        candidates.push_back(parent);
                    }
                }
                break;
            case XPathStep::Axis::Ancestor:
                collect_ancestors(node, candidates, step);
                break;
            case XPathStep::Axis::Attribute:
                collect_attributes(node, candidates, step);
                break;
            case XPathStep::Axis::FollowingSibling:
                collect_following_siblings(node, candidates, step);
                break;
            case XPathStep::Axis::PrecedingSibling:
                collect_preceding_siblings(node, candidates, step);
                break;
        }

        // Apply predicates
        if (!step.predicates.empty()) {
            candidates = apply_predicates(candidates, step.predicates);
        }

        return candidates;
    }

    static bool matches_node_test(XmlNode* node, const XPathStep& step) {
        if (!node) return false;

        if (step.is_wildcard) return true;
        if (step.is_text_node) return node->type() == XmlNodeType::Text;
        if (step.is_comment) return node->type() == XmlNodeType::Comment;

        return node->node_name() == step.node_test;
    }

    static void collect_children(XmlNode* node, std::vector<XmlNode*>& out,
                                  const XPathStep& step) {
        for (std::size_t i = 0; i < node->child_count(); ++i) {
            auto* child = node->child_at(i);
            if (matches_node_test(child, step)) {
                out.push_back(child);
            }
        }
    }

    static void collect_descendants(XmlNode* node, std::vector<XmlNode*>& out,
                                     const XPathStep& step) {
        for (std::size_t i = 0; i < node->child_count(); ++i) {
            auto* child = node->child_at(i);
            if (matches_node_test(child, step)) {
                out.push_back(child);
            }
            collect_descendants(child, out, step);
        }
    }

    static void collect_ancestors(XmlNode* node, std::vector<XmlNode*>& out,
                                   const XPathStep& step) {
        auto* current = node->parent();
        while (current) {
            if (matches_node_test(current, step)) {
                out.push_back(current);
            }
            current = current->parent();
        }
    }

    static void collect_attributes(XmlNode* node, std::vector<XmlNode*>& out,
                                    const XPathStep& step) {
        if (node->type() != XmlNodeType::Element) return;
        auto* elem = static_cast<XmlElement*>(node);
        for (const auto* attr : elem->ordered_attributes()) {
            // We return the attribute nodes
            if (step.is_wildcard || attr->name() == step.node_test) {
                // Need to return const-safe pointers; attributes are stored in the element
                out.push_back(const_cast<XmlAttribute*>(attr));
            }
        }
    }

    static void collect_following_siblings(XmlNode* node, std::vector<XmlNode*>& out,
                                            const XPathStep& step) {
        auto* next = node->next_sibling();
        while (next) {
            if (matches_node_test(next, step)) {
                out.push_back(next);
            }
            next = next->next_sibling();
        }
    }

    static void collect_preceding_siblings(XmlNode* node, std::vector<XmlNode*>& out,
                                            const XPathStep& step) {
        auto* prev = node->previous_sibling();
        while (prev) {
            if (matches_node_test(prev, step)) {
                out.push_back(prev);
            }
            prev = prev->previous_sibling();
        }
    }

    static std::vector<XmlNode*> apply_predicates(
        const std::vector<XmlNode*>& nodes,
        const std::vector<XPathStep::Predicate>& predicates) {
        std::vector<XmlNode*> result;
        for (auto* node : nodes) {
            if (!node) continue;
            bool matches = true;
            for (const auto& pred : predicates) {
                if (!check_predicate(node, pred)) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                result.push_back(node);
            }
        }
        return result;
    }

    static bool check_predicate(XmlNode* node, const XPathStep::Predicate& pred) {
        if (node->type() != XmlNodeType::Element) return false;
        auto* elem = static_cast<XmlElement*>(node);

        switch (pred.op) {
            case XPathStep::Predicate::Exists:
                return elem->has_attribute(pred.attr_name);

            case XPathStep::Predicate::Equals:
                return elem->get_attribute(pred.attr_name) == pred.value;

            case XPathStep::Predicate::NotEquals:
                return elem->get_attribute(pred.attr_name) != pred.value;

            case XPathStep::Predicate::Contains: {
                std::string attr_val = elem->get_attribute(pred.attr_name);
                return attr_val.find(pred.value) != std::string::npos;
            }
        }
        return false;
    }

    std::vector<XPathStep> steps_;
};

// ============================================================================
// XML Schema / DTD validation support
// ============================================================================

/// Represents an element declaration from DTD or schema.
struct ElementDeclaration {
    std::string name;
    enum ContentModel {
        Any, Empty, Mixed, ElementContent
    } content_model = Any;
    std::vector<std::string> allowed_children;
    bool mixed_content = false;
};

/// Represents an attribute declaration.
struct AttributeDeclaration {
    std::string name;
    std::string element_name;
    enum Type {
        CData, ID, IDREF, IDREFS, NMTOKEN, NMTOKENS, Enumeration
    } type = CData;
    enum DefaultType {
        Required, Implied, Fixed, Default
    } default_type = Implied;
    std::string default_value;
    std::vector<std::string> enum_values;
};

/// Simple DTD parser for validation purposes.
class DtdParser {
public:
    /// Parse a DTD string and return element/attribute declarations.
    bool parse_dtd(const std::string& dtd_text) {
        // Minimal DTD parsing - enough for basic validation
        std::string_view text(dtd_text);

        // Parse <!ELEMENT ...> declarations
        std::size_t pos = 0;
        while (pos < text.size()) {
            auto elem_start = text.find("<!ELEMENT", pos);
            if (elem_start == std::string::npos) break;

            std::size_t decl_start = elem_start + 9; // after <!ELEMENT
            // Skip whitespace
            while (decl_start < text.size() && std::isspace(static_cast<unsigned char>(text[decl_start]))) {
                decl_start++;
            }

            // Read element name
            std::size_t name_end = decl_start;
            while (name_end < text.size() &&
                   (std::isalnum(static_cast<unsigned char>(text[name_end])) ||
                    text[name_end] == '_' || text[name_end] == '-' || text[name_end] == '.')) {
                name_end++;
            }

            std::string elem_name(text.substr(decl_start, name_end - decl_start));
            if (elem_name.empty()) {
                pos = elem_start + 1;
                continue;
            }

            ElementDeclaration decl;
            decl.name = elem_name;

            pos = name_end;
            // Skip to '>'
            std::size_t end = text.find('>', pos);
            if (end == std::string::npos) break;

            std::string content_spec(text.substr(pos, end - pos));

            // Parse content spec
            parse_content_spec(content_spec, decl);

            element_declarations_[elem_name] = decl;
            pos = end + 1;
        }

        // Parse <!ATTLIST ...> declarations
        pos = 0;
        while (pos < text.size()) {
            auto att_start = text.find("<!ATTLIST", pos);
            if (att_start == std::string::npos) break;

            pos = att_start + 9;
            // Find '>'
            std::size_t end = text.find('>', pos);
            if (end == std::string::npos) break;

            std::string attlist(text.substr(pos, end - pos));
            parse_attlist(attlist);

            pos = end + 1;
        }

        return true;
    }

    /// Check if an element is declared.
    bool has_element(const std::string& name) const {
        return element_declarations_.find(name) != element_declarations_.end();
    }

    /// Get an element declaration.
    const ElementDeclaration* get_element(const std::string& name) const {
        auto it = element_declarations_.find(name);
        if (it != element_declarations_.end()) return &it->second;
        return nullptr;
    }

    /// Check if an attribute is declared for an element.
    bool has_attribute(const std::string& element, const std::string& attr) const {
        auto range = attribute_declarations_.equal_range(element);
        for (auto it = range.first; it != range.second; ++it) {
            if (it->second.name == attr) return true;
        }
        return false;
    }

    /// Get attribute declarations for an element.
    std::vector<AttributeDeclaration> get_attributes(const std::string& element) const {
        std::vector<AttributeDeclaration> attrs;
        auto range = attribute_declarations_.equal_range(element);
        for (auto it = range.first; it != range.second; ++it) {
            attrs.push_back(it->second);
        }
        return attrs;
    }

private:
    void parse_content_spec(const std::string& spec, ElementDeclaration& decl) {
        std::string trimmed = trim(spec);
        if (trimmed == "EMPTY") {
            decl.content_model = ElementDeclaration::Empty;
        } else if (trimmed == "ANY") {
            decl.content_model = ElementDeclaration::Any;
        } else if (trimmed.find("#PCDATA") != std::string::npos) {
            decl.content_model = ElementDeclaration::Mixed;
            decl.mixed_content = true;
        } else {
            decl.content_model = ElementDeclaration::ElementContent;
        }
    }

    void parse_attlist(const std::string& attlist) {
        std::string remaining = trim(attlist);
        if (remaining.empty()) return;

        // First token is element name
        std::size_t space = remaining.find_first_of(" \t\n\r");
        if (space == std::string::npos) return;

        std::string elem_name = remaining.substr(0, space);
        remaining = trim(remaining.substr(space + 1));

        // Parse attribute declarations
        while (!remaining.empty()) {
            AttributeDeclaration attr;
            attr.element_name = elem_name;

            // Attribute name
            space = remaining.find_first_of(" \t\n\r");
            if (space == std::string::npos) break;
            attr.name = remaining.substr(0, space);
            remaining = trim(remaining.substr(space + 1));

            // Attribute type
            space = remaining.find_first_of(" \t\n\r");
            if (space == std::string::npos) break;
            std::string type_str = remaining.substr(0, space);
            attr.type = parse_attr_type(type_str);
            remaining = trim(remaining.substr(space + 1));

            // Default type
            space = remaining.find_first_of(" \t\n\r");
            if (space == std::string::npos) {
                // Might be last token
                parse_default_type(remaining, attr);
                attribute_declarations_.emplace(elem_name, attr);
                break;
            }

            std::string default_str = remaining.substr(0, space);
            parse_default_type(default_str, attr);

            // If default/fixed, read value
            if (attr.default_type == AttributeDeclaration::Fixed ||
                attr.default_type == AttributeDeclaration::Default) {
                remaining = trim(remaining.substr(space + 1));
                attr.default_value = strip_quotes(remaining);
                break;
            }

            remaining = trim(remaining.substr(space + 1));
            attribute_declarations_.emplace(elem_name, attr);
        }
    }

    static AttributeDeclaration::Type parse_attr_type(const std::string& type_str) {
        if (type_str == "CDATA") return AttributeDeclaration::CData;
        if (type_str == "ID") return AttributeDeclaration::ID;
        if (type_str == "IDREF") return AttributeDeclaration::IDREF;
        if (type_str == "IDREFS") return AttributeDeclaration::IDREFS;
        if (type_str == "NMTOKEN") return AttributeDeclaration::NMTOKEN;
        if (type_str == "NMTOKENS") return AttributeDeclaration::NMTOKENS;
        return AttributeDeclaration::CData;
    }

    static void parse_default_type(const std::string& str, AttributeDeclaration& attr) {
        if (str == "#REQUIRED") attr.default_type = AttributeDeclaration::Required;
        else if (str == "#IMPLIED") attr.default_type = AttributeDeclaration::Implied;
        else if (str == "#FIXED") attr.default_type = AttributeDeclaration::Fixed;
        else {
            // It's a default value
            attr.default_type = AttributeDeclaration::Default;
            attr.default_value = strip_quotes(str);
        }
    }

    static std::string strip_quotes(const std::string& s) {
        std::string t = trim(s);
        if (t.size() >= 2 && ((t[0] == '"' && t.back() == '"') ||
                               (t[0] == '\'' && t.back() == '\''))) {
            return t.substr(1, t.size() - 2);
        }
        return t;
    }

    static std::string trim(const std::string& s) {
        auto start = s.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) return "";
        auto end = s.find_last_not_of(" \t\n\r");
        return s.substr(start, end - start + 1);
    }

    std::map<std::string, ElementDeclaration> element_declarations_;
    std::multimap<std::string, AttributeDeclaration> attribute_declarations_;
};

// ============================================================================
// XML Writer / Serializer (programmatic construction)
// ============================================================================

/// Helper for building XML documents programmatically with a fluent API.
class XmlWriter {
public:
    XmlWriter() {
        doc_ = std::make_unique<XmlDocument>();
        current_ = doc_.get();
    }

    /// Start a document.
    XmlWriter& start_document(const std::string& version = "1.0",
                              const std::string& encoding = "UTF-8",
                              bool standalone = false) {
        doc_->set_version(version);
        doc_->set_encoding(encoding);
        doc_->set_standalone(standalone);
        return *this;
    }

    /// Start a new element as a child of the current node.
    XmlWriter& start_element(const std::string& name) {
        auto elem = std::make_unique<XmlElement>(name);
        XmlElement* ptr = elem.get();
        if (current_->type() == XmlNodeType::Document) {
            auto* doc = static_cast<XmlDocument*>(current_);
            if (!doc->document_element()) {
                doc->set_document_element(std::move(elem));
            } else {
                doc->document_element()->append_child(std::move(elem));
            }
        } else if (current_->type() == XmlNodeType::Element) {
            static_cast<XmlElement*>(current_)->append_child(std::move(elem));
        }
        current_ = ptr;
        return *this;
    }

    /// End the current element (move to parent).
    XmlWriter& end_element() {
        if (current_ && current_->parent()) {
            current_ = current_->parent();
        }
        return *this;
    }

    /// Write an attribute on the current element.
    XmlWriter& attribute(const std::string& name, const std::string& value) {
        if (current_->type() == XmlNodeType::Element) {
            static_cast<XmlElement*>(current_)->set_attribute(name, value);
        }
        return *this;
    }

    /// Write text content.
    XmlWriter& text(const std::string& data) {
        if (current_->type() == XmlNodeType::Element) {
            static_cast<XmlElement*>(current_)->append_child(
                std::make_unique<XmlText>(data));
        }
        return *this;
    }

    /// Write a CDATA section.
    XmlWriter& cdata(const std::string& data) {
        if (current_->type() == XmlNodeType::Element) {
            static_cast<XmlElement*>(current_)->append_child(
                std::make_unique<XmlCData>(data));
        }
        return *this;
    }

    /// Write a comment.
    XmlWriter& comment(const std::string& data) {
        if (current_->type() == XmlNodeType::Element ||
            current_->type() == XmlNodeType::Document) {
            current_->append_child(std::make_unique<XmlComment>(data));
        }
        return *this;
    }

    /// Write a processing instruction.
    XmlWriter& processing_instruction(const std::string& target,
                                       const std::string& data) {
        if (current_->type() == XmlNodeType::Element ||
            current_->type() == XmlNodeType::Document) {
            current_->append_child(
                std::make_unique<XmlProcessingInstruction>(target, data));
        }
        return *this;
    }

    /// Get the built document.
    std::unique_ptr<XmlDocument> document() {
        return std::move(doc_);
    }

    /// Serialize to string.
    std::string to_string(bool pretty = false) const {
        return doc_->to_string(pretty);
    }

private:
    std::unique_ptr<XmlDocument> doc_;
    XmlNode* current_;
};

// ============================================================================
// Utility: XML document pretty-printer
// ============================================================================

/// Utility for reformatting XML with configurable indentation.
class XmlPrettyPrinter {
public:
    struct Config {
        int indent_size = 2;
        bool use_tabs = false;
        bool newline_before_attributes = false;
        int max_attributes_per_line = 0;
        bool preserve_empty_lines = false;
        bool sort_attributes = false;
    };

    XmlPrettyPrinter() : config_() {}
    explicit XmlPrettyPrinter(Config cfg) : config_(cfg) {}

    /// Reformat an XML string.
    std::string format(const std::string& xml_text) {
        XmlDomParser parser;
        auto doc = parser.parse(xml_text);
        if (!doc) return xml_text;
        return doc->to_string(true);
    }

    /// Reformat an XmlDocument.
    std::string format_document(const XmlDocument& doc) {
        return doc.to_string(true);
    }

private:
    Config config_;
};

// ============================================================================
// Utility: XML diff
// ============================================================================

/// Represents a single difference between two XML documents.
struct XmlDiff {
    enum class DiffType : uint8_t {
        Added, Removed, Modified, Moved
    };

    DiffType type;
    std::string xpath;
    std::string old_value;
    std::string new_value;
};

/// Compare two XML documents and produce a list of differences.
class XmlDiffer {
public:
    /// Compare two XML documents.
    std::vector<XmlDiff> diff(const XmlDocument& doc1, const XmlDocument& doc2) {
        diffs_.clear();
        compare_nodes(doc1.document_element(), doc2.document_element(), "");
        return diffs_;
    }

    /// Compare two XML strings.
    std::vector<XmlDiff> diff_strings(const std::string& xml1,
                                       const std::string& xml2) {
        XmlDomParser parser;
        auto doc1 = parser.parse(xml1);
        auto doc2 = parser.parse(xml2);
        return diff(*doc1, *doc2);
    }

private:
    void compare_nodes(const XmlNode* n1, const XmlNode* n2,
                       const std::string& path) {
        if (!n1 && !n2) return;

        if (!n1) {
            add_diff(XmlDiff::DiffType::Added, path, "", n2->to_string());
            return;
        }
        if (!n2) {
            add_diff(XmlDiff::DiffType::Removed, path, n1->to_string(), "");
            return;
        }

        if (n1->type() != n2->type()) {
            add_diff(XmlDiff::DiffType::Modified, path,
                     n1->to_string(), n2->to_string());
            return;
        }

        if (n1->type() == XmlNodeType::Element) {
            compare_elements(static_cast<const XmlElement*>(n1),
                             static_cast<const XmlElement*>(n2), path);
        } else if (n1->type() == XmlNodeType::Text ||
                   n1->type() == XmlNodeType::CData) {
            if (n1->node_value() != n2->node_value()) {
                add_diff(XmlDiff::DiffType::Modified, path,
                         n1->node_value(), n2->node_value());
            }
        }
    }

    void compare_elements(const XmlElement* e1, const XmlElement* e2,
                          const std::string& path) {
        std::string elem_path = path + "/" + e1->name();

        // Compare attributes
        auto names1 = e1->attribute_names();
        auto names2 = e2->attribute_names();
        std::set<std::string> all_attrs(names1.begin(), names1.end());
        all_attrs.insert(names2.begin(), names2.end());

        for (const auto& attr_name : all_attrs) {
            std::string val1 = e1->get_attribute(attr_name);
            std::string val2 = e2->get_attribute(attr_name);
            if (val1 != val2) {
                add_diff(XmlDiff::DiffType::Modified,
                         elem_path + "[@" + attr_name + "]", val1, val2);
            }
        }

        // Compare children
        std::size_t max_children = std::max(e1->child_count(), e2->child_count());
        for (std::size_t i = 0; i < max_children; ++i) {
            auto* c1 = e1->child_at(i);
            auto* c2 = e2->child_at(i);
            if (c1 && c1->type() == XmlNodeType::Element) {
                compare_nodes(c1, c2, elem_path);
            } else {
                compare_nodes(c1, c2, elem_path + "/text()[" + std::to_string(i) + "]");
            }
        }
    }

    void add_diff(XmlDiff::DiffType type, const std::string& path,
                  const std::string& old_val, const std::string& new_val) {
        XmlDiff d;
        d.type = type;
        d.xpath = path;
        d.old_value = old_val;
        d.new_value = new_val;
        diffs_.push_back(d);
    }

    std::vector<XmlDiff> diffs_;
};

// ============================================================================
// Utility: XML normalizer (canonical form)
// ============================================================================

/// Produces a canonical (normalized) form of an XML document for comparison.
class XmlCanonicalizer {
public:
    /// Canonicalize an XML document.
    std::string canonicalize(const XmlDocument& doc) {
        std::ostringstream oss;
        auto* root = doc.document_element();
        if (root) {
            canonicalize_element(root, oss);
        }
        return oss.str();
    }

    /// Canonicalize an XML string.
    std::string canonicalize_string(const std::string& xml_text) {
        XmlDomParser parser;
        auto doc = parser.parse(xml_text);
        return canonicalize(*doc);
    }

private:
    void canonicalize_element(const XmlElement* elem, std::ostream& os) {
        os << "<" << elem->name();

        // Sort attributes for canonical form
        auto attr_names = elem->attribute_names();
        std::sort(attr_names.begin(), attr_names.end());

        for (const auto& name : attr_names) {
            os << " " << name << "=\"" << escape_attr(elem->get_attribute(name)) << "\"";
        }

        if (elem->child_count() == 0) {
            os << "/>";
            return;
        }

        os << ">";

        for (std::size_t i = 0; i < elem->child_count(); ++i) {
            auto* child = elem->child_at(i);
            if (child->type() == XmlNodeType::Element) {
                canonicalize_element(static_cast<const XmlElement*>(child), os);
            } else if (child->type() == XmlNodeType::Text) {
                os << escape_text(child->node_value());
            } else if (child->type() == XmlNodeType::CData) {
                os << child->node_value();
            }
        }

        os << "</" << elem->name() << ">";
    }

    static std::string escape_attr(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '&': result += "&amp;"; break;
                case '"': result += "&quot;"; break;
                case '<': result += "&lt;"; break;
                case '>': result += "&gt;"; break;
                case '\n': result += "&#xA;"; break;
                case '\r': result += "&#xD;"; break;
                default: result.push_back(c); break;
            }
        }
        return result;
    }

    static std::string escape_text(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '&': result += "&amp;"; break;
                case '<': result += "&lt;"; break;
                case '>': result += "&gt;"; break;
                case '\r': result += "&#xD;"; break;
                default: result.push_back(c); break;
            }
        }
        return result;
    }
};

// ============================================================================
// SAX event stream for chained processing
// ============================================================================

/// A SAX handler that records all events for replay or inspection.
class SaxEventRecorder : public SaxHandler {
public:
    void start_document() override {
        events_.push_back({SaxEventType::StartDocument, "", "", "", "", "", "", "", "", "", "", {}});
    }

    void end_document() override {
        events_.push_back({SaxEventType::EndDocument, "", "", "", "", "", "", "", "", "", "", {}});
    }

    void start_element(const std::string& uri,
                       const std::string& local_name,
                       const std::string& qname,
                       const std::map<std::string,std::string>& attrs) override {
        SaxEvent ev;
        ev.type = SaxEventType::StartElement;
        ev.namespace_uri = uri;
        ev.local_name = local_name;
        ev.qualified_name = qname;
        ev.attributes = attrs;
        events_.push_back(std::move(ev));
    }

    void end_element(const std::string& uri,
                     const std::string& local_name,
                     const std::string& qname) override {
        SaxEvent ev;
        ev.type = SaxEventType::EndElement;
        ev.namespace_uri = uri;
        ev.local_name = local_name;
        ev.qualified_name = qname;
        events_.push_back(std::move(ev));
    }

    void characters(const std::string& text) override {
        SaxEvent ev;
        ev.type = SaxEventType::Characters;
        ev.value = text;
        events_.push_back(std::move(ev));
    }

    void ignorable_whitespace(const std::string& ws) override {
        SaxEvent ev;
        ev.type = SaxEventType::IgnorableWhitespace;
        ev.value = ws;
        events_.push_back(std::move(ev));
    }

    void comment(const std::string& text) override {
        SaxEvent ev;
        ev.type = SaxEventType::Comment;
        ev.value = text;
        events_.push_back(std::move(ev));
    }

    void processing_instruction(const std::string& target,
                                const std::string& data) override {
        SaxEvent ev;
        ev.type = SaxEventType::ProcessingInstruction;
        ev.pi_target = target;
        ev.pi_data = data;
        events_.push_back(std::move(ev));
    }

    void cdata(const std::string& data) override {
        SaxEvent ev;
        ev.type = SaxEventType::CData;
        ev.value = data;
        events_.push_back(std::move(ev));
    }

    void doctype(const std::string& name,
                 const std::string& public_id,
                 const std::string& system_id) override {
        SaxEvent ev;
        ev.type = SaxEventType::DocType;
        ev.qualified_name = name;
        ev.public_id = public_id;
        ev.system_id = system_id;
        events_.push_back(std::move(ev));
    }

    void start_prefix_mapping(const std::string& prefix,
                              const std::string& uri) override {
        SaxEvent ev;
        ev.type = SaxEventType::StartPrefixMapping;
        ev.prefix = prefix;
        ev.namespace_uri = uri;
        events_.push_back(std::move(ev));
    }

    void end_prefix_mapping(const std::string& prefix) override {
        SaxEvent ev;
        ev.type = SaxEventType::EndPrefixMapping;
        ev.prefix = prefix;
        events_.push_back(std::move(ev));
    }

    /// Get all recorded events.
    const std::vector<SaxEvent>& events() const { return events_; }

    /// Clear recorded events.
    void clear() { events_.clear(); }

    /// Replay events to another handler.
    void replay_to(SaxHandler& handler) const {
        for (const auto& ev : events_) {
            switch (ev.type) {
                case SaxEventType::StartDocument:
                    handler.start_document();
                    break;
                case SaxEventType::EndDocument:
                    handler.end_document();
                    break;
                case SaxEventType::StartElement:
                    handler.start_element(ev.namespace_uri, ev.local_name,
                                          ev.qualified_name, ev.attributes);
                    break;
                case SaxEventType::EndElement:
                    handler.end_element(ev.namespace_uri, ev.local_name,
                                        ev.qualified_name);
                    break;
                case SaxEventType::Characters:
                    handler.characters(ev.value);
                    break;
                case SaxEventType::IgnorableWhitespace:
                    handler.ignorable_whitespace(ev.value);
                    break;
                case SaxEventType::Comment:
                    handler.comment(ev.value);
                    break;
                case SaxEventType::ProcessingInstruction:
                    handler.processing_instruction(ev.pi_target, ev.pi_data);
                    break;
                case SaxEventType::CData:
                    handler.cdata(ev.value);
                    break;
                case SaxEventType::DocType:
                    handler.doctype(ev.qualified_name, ev.public_id, ev.system_id);
                    break;
                case SaxEventType::StartPrefixMapping:
                    handler.start_prefix_mapping(ev.prefix, ev.namespace_uri);
                    break;
                case SaxEventType::EndPrefixMapping:
                    handler.end_prefix_mapping(ev.prefix);
                    break;
                default:
                    break;
            }
        }
    }

private:
    std::vector<SaxEvent> events_;
};

// ============================================================================
// Statistics / metrics collector
// ============================================================================

/// Collects statistics about an XML document.
struct XmlStatistics {
    std::size_t element_count = 0;
    std::size_t text_node_count = 0;
    std::size_t comment_count = 0;
    std::size_t pi_count = 0;
    std::size_t cdata_count = 0;
    std::size_t attribute_count = 0;
    std::size_t max_depth = 0;
    std::size_t total_size = 0;
    std::map<std::string, std::size_t> element_frequencies;
    std::size_t namespace_declarations = 0;
};

/// Analyzes an XML document and collects statistics.
class XmlAnalyzer {
public:
    /// Analyze a DOM document.
    XmlStatistics analyze(const XmlDocument& doc) {
        XmlStatistics stats;
        stats.total_size = estimate_size(doc);
        auto* root = doc.document_element();
        if (root) {
            analyze_element(root, stats, 0);
        }
        return stats;
    }

    /// Analyze an XML string.
    XmlStatistics analyze_string(const std::string& xml_text) {
        XmlDomParser parser;
        auto doc = parser.parse(xml_text);
        return analyze(*doc);
    }

private:
    void analyze_element(const XmlElement* elem, XmlStatistics& stats,
                         std::size_t depth) {
        stats.element_count++;
        stats.element_frequencies[elem->name()]++;
        stats.attribute_count += elem->attribute_count();

        if (depth > stats.max_depth) {
            stats.max_depth = depth;
        }

        // Count namespace declarations
        auto names = elem->attribute_names();
        for (const auto& name : names) {
            if (name == "xmlns" || name.compare(0, 6, "xmlns:") == 0) {
                stats.namespace_declarations++;
            }
        }

        for (std::size_t i = 0; i < elem->child_count(); ++i) {
            auto* child = elem->child_at(i);
            switch (child->type()) {
                case XmlNodeType::Element:
                    analyze_element(static_cast<const XmlElement*>(child),
                                    stats, depth + 1);
                    break;
                case XmlNodeType::Text:
                    stats.text_node_count++;
                    break;
                case XmlNodeType::Comment:
                    stats.comment_count++;
                    break;
                case XmlNodeType::CData:
                    stats.cdata_count++;
                    break;
                case XmlNodeType::ProcessingInstruction:
                    stats.pi_count++;
                    break;
                default:
                    break;
            }
        }
    }

    std::size_t estimate_size(const XmlDocument& doc) {
        std::ostringstream oss;
        doc.serialize(oss, 0, false);
        return oss.str().size();
    }
};

// ============================================================================
// Streaming XML writer (for generating large documents)
// ============================================================================

/// Low-level streaming writer for emitting XML without building a DOM.
class XmlStreamWriter {
public:
    explicit XmlStreamWriter(std::ostream& os) : os_(os) {}

    /// Write XML declaration.
    XmlStreamWriter& declaration(const std::string& version = "1.0",
                                 const std::string& encoding = "UTF-8") {
        os_ << "<?xml version=\"" << version << "\" encoding=\"" << encoding << "\"?>\n";
        return *this;
    }

    /// Start an element (writes <name).
    XmlStreamWriter& start_element(const std::string& name) {
        close_pending_tag();
        if (!element_stack_.empty() && !last_was_text_) {
            os_ << "\n";
            write_indent();
        }
        os_ << "<" << name;
        element_stack_.push_back(name);
        pending_close_ = true;
        last_was_text_ = false;
        return *this;
    }

    /// Write an attribute (must be called after start_element before any content).
    XmlStreamWriter& attribute(const std::string& name, const std::string& value) {
        os_ << " " << name << "=\"";
        write_escaped_attr(value);
        os_ << "\"";
        return *this;
    }

    /// Write text content.
    XmlStreamWriter& text(const std::string& data) {
        close_pending_tag();
        write_escaped_text(data);
        last_was_text_ = true;
        return *this;
    }

    /// Write a CDATA section.
    XmlStreamWriter& cdata(const std::string& data) {
        close_pending_tag();
        os_ << "<![CDATA[" << data << "]]>";
        last_was_text_ = true;
        return *this;
    }

    /// Write a comment.
    XmlStreamWriter& comment(const std::string& data) {
        close_pending_tag();
        os_ << "<!--" << data << "-->";
        return *this;
    }

    /// End the current element.
    XmlStreamWriter& end_element() {
        if (element_stack_.empty()) return *this;
        std::string name = element_stack_.back();
        element_stack_.pop_back();

        if (pending_close_) {
            os_ << "/>";
            pending_close_ = false;
        } else {
            if (!last_was_text_) {
                os_ << "\n";
                write_indent();
            }
            os_ << "</" << name << ">";
        }
        last_was_text_ = false;
        return *this;
    }

    /// Flush output.
    XmlStreamWriter& flush() {
        os_.flush();
        return *this;
    }

    /// Set indent string.
    XmlStreamWriter& set_indent(const std::string& indent) {
        indent_str_ = indent;
        return *this;
    }

    /// Enable/disable pretty printing.
    XmlStreamWriter& set_pretty(bool pretty) {
        pretty_ = pretty;
        return *this;
    }

private:
    void close_pending_tag() {
        if (pending_close_) {
            os_ << ">";
            pending_close_ = false;
        }
    }

    void write_indent() {
        if (pretty_) {
            for (std::size_t i = 0; i < element_stack_.size(); ++i) {
                os_ << indent_str_;
            }
        }
    }

    void write_escaped_attr(const std::string& s) {
        for (char c : s) {
            switch (c) {
                case '"': os_ << "&quot;"; break;
                case '&': os_ << "&amp;"; break;
                case '<': os_ << "&lt;"; break;
                case '>': os_ << "&gt;"; break;
                default: os_.put(c); break;
            }
        }
    }

    void write_escaped_text(const std::string& s) {
        for (char c : s) {
            switch (c) {
                case '&': os_ << "&amp;"; break;
                case '<': os_ << "&lt;"; break;
                case '>': os_ << "&gt;"; break;
                default: os_.put(c); break;
            }
        }
    }

    std::ostream& os_;
    std::vector<std::string> element_stack_;
    bool pending_close_ = false;
    bool last_was_text_ = false;
    bool pretty_ = true;
    std::string indent_str_ = "  ";
};

// ============================================================================
// XML Filter / Transform pipeline
// ============================================================================

/// Base class for XML filters that intercept and potentially modify SAX events.
class SaxFilter : public SaxHandler {
public:
    explicit SaxFilter(SaxHandler* parent = nullptr) : parent_(parent) {}

    void set_parent(SaxHandler* parent) { parent_ = parent; }
    SaxHandler* parent() const { return parent_; }

    void start_document() override {
        if (parent_) parent_->start_document();
    }
    void end_document() override {
        if (parent_) parent_->end_document();
    }
    void start_element(const std::string& uri,
                       const std::string& local_name,
                       const std::string& qname,
                       const std::map<std::string,std::string>& attrs) override {
        if (parent_) parent_->start_element(uri, local_name, qname, attrs);
    }
    void end_element(const std::string& uri,
                     const std::string& local_name,
                     const std::string& qname) override {
        if (parent_) parent_->end_element(uri, local_name, qname);
    }
    void characters(const std::string& text) override {
        if (parent_) parent_->characters(text);
    }
    void comment(const std::string& text) override {
        if (parent_) parent_->comment(text);
    }
    void processing_instruction(const std::string& target,
                                const std::string& data) override {
        if (parent_) parent_->processing_instruction(target, data);
    }
    void cdata(const std::string& data) override {
        if (parent_) parent_->cdata(data);
    }

protected:
    SaxHandler* parent_;
};

/// A SAX filter that strips namespace declarations.
class NamespaceStrippingFilter : public SaxFilter {
public:
    using SaxFilter::SaxFilter;

    void start_element(const std::string& uri,
                       const std::string& local_name,
                       const std::string& qname,
                       const std::map<std::string,std::string>& attrs) override {
        // Filter out xmlns:* attributes
        std::map<std::string,std::string> filtered;
        for (const auto& [key, value] : attrs) {
            if (key != "xmlns" && key.compare(0, 6, "xmlns:") != 0) {
                filtered[key] = value;
            }
        }
        if (parent_) {
            parent_->start_element(uri, local_name,
                                   strip_prefix(qname), filtered);
        }
    }

    void end_element(const std::string& uri,
                     const std::string& local_name,
                     const std::string& qname) override {
        if (parent_) {
            parent_->end_element(uri, local_name, strip_prefix(qname));
        }
    }

    void start_prefix_mapping(const std::string&, const std::string&) override {}
    void end_prefix_mapping(const std::string&) override {}

private:
    static std::string strip_prefix(const std::string& qname) {
        auto pos = qname.find(':');
        if (pos == std::string::npos) return qname;
        return qname.substr(pos + 1);
    }
};

/// A SAX filter that validates element/attribute counts.
class ValidationFilter : public SaxFilter {
public:
    using SaxFilter::SaxFilter;

    void start_element(const std::string& uri,
                       const std::string& local_name,
                       const std::string& qname,
                       const std::map<std::string,std::string>& attrs) override {
        if (depth_ >= max_depth_) {
            throw XmlValidationException("Maximum element depth exceeded");
        }
        depth_++;
        if (parent_) parent_->start_element(uri, local_name, qname, attrs);
    }

    void end_element(const std::string& uri,
                     const std::string& local_name,
                     const std::string& qname) override {
        depth_--;
        if (parent_) parent_->end_element(uri, local_name, qname);
    }

    void set_max_depth(std::size_t depth) { max_depth_ = depth; }
    std::size_t max_depth() const { return max_depth_; }

private:
    std::size_t depth_ = 0;
    std::size_t max_depth_ = 256;
};

// ============================================================================
// Convenience functions (non-member, in namespace progressive)
// ============================================================================

/// Parse an XML string and return a DOM document.
inline std::unique_ptr<XmlDocument> parse_xml(const std::string& xml_text) {
    XmlDomParser parser;
    return parser.parse(xml_text);
}

/// Parse XML with a SAX handler.
inline void parse_xml_sax(const std::string& xml_text, SaxHandler& handler) {
    XmlSaxParser parser;
    parser.set_handler(&handler);
    parser.parse(xml_text);
}

/// Serialize an XML node to a string.
inline std::string serialize_xml(const XmlNode& node, bool pretty = false) {
    return node.to_string(pretty);
}

/// Query elements by XPath-like expression.
inline std::vector<XmlElement*> query_xml(XmlNode* context,
                                           const std::string& xpath_expr) {
    auto expr = XPathExpression::compile(xpath_expr);
    return expr.evaluate_elements(context);
}

/// Query a single element by XPath.
inline XmlElement* query_xml_first(XmlNode* context,
                                    const std::string& xpath_expr) {
    auto expr = XPathExpression::compile(xpath_expr);
    auto nodes = expr.evaluate_elements(context);
    return nodes.empty() ? nullptr : nodes.front();
}

/// Query text content by XPath.
inline std::string query_xml_text(XmlNode* context,
                                   const std::string& xpath_expr) {
    auto expr = XPathExpression::compile(xpath_expr);
    return expr.evaluate_first_text(context);
}

/// Build a document using the fluent writer API.
inline std::unique_ptr<XmlDocument> build_xml(
    const std::function<void(XmlWriter&)>& build_fn) {
    XmlWriter writer;
    build_fn(writer);
    return writer.document();
}

/// Canonicalize an XML document for comparison.
inline std::string canonicalize_xml(const std::string& xml_text) {
    XmlCanonicalizer canonicalizer;
    return canonicalizer.canonicalize_string(xml_text);
}

/// Compare two XML strings, returning differences.
inline std::vector<XmlDiff> diff_xml(const std::string& xml1,
                                      const std::string& xml2) {
    XmlDiffer differ;
    return differ.diff_strings(xml1, xml2);
}

/// Pretty-print an XML string.
inline std::string pretty_print_xml(const std::string& xml_text) {
    XmlPrettyPrinter printer;
    return printer.format(xml_text);
}

/// Analyze XML and return statistics.
inline XmlStatistics analyze_xml(const std::string& xml_text) {
    XmlAnalyzer analyzer;
    return analyzer.analyze_string(xml_text);
}

/// Get owner document. Returns null if not attached to a document.
XmlDocument* XmlNode::owner_document() const {
    const XmlNode* node = this;
    while (node && node->type() != XmlNodeType::Document) {
        node = node->parent();
    }
    return const_cast<XmlDocument*>(static_cast<const XmlDocument*>(node));
}

} // namespace progressive
