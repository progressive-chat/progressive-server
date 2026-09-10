// proxy.hpp — translation of Conduit commit b2d55160's proxy support
// (`src/database.rs` ProxyConfig, refactored into `src/database/proxy.rs`
// by c53cc03f "address pr comments").
//
// Upstream added `ProxyConfig` to Conduit's `Config` so federation traffic
// (reqwest client in `Globals`) can go through a proxy:
//
//   proxy = "none"            # default, direct connection
//   proxy = "<url>"           # global proxy for all federation traffic
//   proxy = by-domain rules   # per-domain include/exclude lists
//
// The C++ port has no TOML config layer (see Data::load_or_create), so the
// same shapes are accepted as a `--proxy` CLI value / `CONDUIT_PROXY` env
// value (see ProxyConfig::parse):
//
//   "none" | ""                              -> None
//   "<url>" e.g. "http://proxy:8080"         -> Global
//   '{"global":"<url>"}'                     -> Global
//   '{"by_domain":[{...}, ...]}'             -> ByDomain
//   '[{...}, ...]'                           -> ByDomain
//
// NOTE on transport: upstream enables reqwest's `socks` feature
// (tokio-socks) so `socks5://` URLs work. This port's HTTP layer is
// cpp-httplib, which only speaks HTTP proxies (`Client::set_proxy`), so
// a configured proxy is applied as host:port regardless of scheme.
// The domain-matching semantics below are a faithful port.
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace proxy {

// Parsed proxy endpoint (upstream: reqwest::Url).
struct ProxyUrl {
  std::string scheme;  // e.g. "http", "socks5"
  std::string host;
  int port = 0;

  // Parses "<scheme>://<host>[:port]" (port defaults per scheme).
  // Returns nullopt on malformed input.
  static std::optional<ProxyUrl> parse(const std::string& s);
  std::string to_string() const;
};

// A domain name, optionally with a `*` first subdomain
// (upstream: WildCardedDomain in database.rs / database/proxy.rs).
class WildCardedDomain {
 public:
  enum class Kind { WildCard, WildCarded, Exact };

  static WildCardedDomain wildcard() { return WildCardedDomain(Kind::WildCard, ""); }
  // Upstream FromStr: "*.<rest>" -> WildCarded(".<rest>"), "*" ->
  // WildCarded(""), anything else -> Exact.
  static WildCardedDomain parse(const std::string& s);

  Kind kind() const { return kind_; }
  bool matches(const std::string& domain) const;
  bool more_specific_than(const WildCardedDomain& other) const;
  bool operator==(const WildCardedDomain& other) const {
    return kind_ == other.kind_ && value_ == other.value_;
  }
  bool operator!=(const WildCardedDomain& other) const { return !(*this == other); }

 private:
  WildCardedDomain(Kind kind, std::string value)
      : kind_(kind), value_(std::move(value)) {}
  Kind kind_;
  std::string value_;  // WildCarded: suffix incl. leading dot ("" matches all)
                       // Exact: full domain
};

struct PartialProxyConfig {
  ProxyUrl url;
  std::vector<WildCardedDomain> include;  // empty == "*" (upstream for_url)
  std::vector<WildCardedDomain> exclude;

  // Upstream PartialProxyConfig::for_url: most-specific include must beat
  // the most-specific exclude for the proxy to apply.
  std::optional<ProxyUrl> for_url(const std::string& url_or_host) const;
};

// Upstream ProxyConfig enum (None | Global { url } | ByDomain(...)).
class ProxyConfig {
 public:
  enum class Type { None, Global, ByDomain };

  // Upstream Default impl: ProxyConfig::None.
  ProxyConfig() = default;

  static ProxyConfig none() { return ProxyConfig(); }
  static ProxyConfig global(ProxyUrl url);
  static ProxyConfig by_domain(std::vector<PartialProxyConfig> rules);

  // Parses the `--proxy` / `CONDUIT_PROXY` value documented above.
  // Unknown/invalid input falls back to None (never throws).
  static ProxyConfig parse(const std::string& s);

  Type type() const { return type_; }
  bool is_none() const { return type_ == Type::None; }

  // Upstream to_proxy(), resolved per destination: None for direct,
  // otherwise the proxy endpoint to use for `url_or_host`.
  std::optional<ProxyUrl> proxy_for(const std::string& url_or_host) const;

 private:
  Type type_ = Type::None;
  ProxyUrl global_url_;
  std::vector<PartialProxyConfig> rules_;
};

// Extracts the host part from a URL ("https://host:port/path") or returns
// the input unchanged when it is already a bare host.
std::string host_of(const std::string& url_or_host);

}  // namespace proxy
