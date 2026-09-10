// proxy.cpp — translation of Conduit b2d55160 + c53cc03f
// (src/database.rs ProxyConfig, later src/database/proxy.rs).

#include "proxy.hpp"

#include <nlohmann/json.hpp>

#include <cctype>

namespace proxy {
namespace {

int default_port_for(const std::string& scheme) {
  if (scheme == "http") return 80;
  if (scheme == "https") return 443;
  if (scheme == "socks5" || scheme == "socks5h") return 1080;
  return 8080;
}

std::string trim(std::string s) {
  size_t b = 0;
  while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
  size_t e = s.size();
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
  return s.substr(b, e - b);
}

bool parse_rules_array(const nlohmann::json& arr,
                       std::vector<PartialProxyConfig>* out) {
  if (!arr.is_array()) return false;
  for (const auto& entry : arr) {
    if (!entry.is_object() || !entry.contains("url") ||
        !entry["url"].is_string())
      return false;
    auto url = ProxyUrl::parse(entry["url"].get<std::string>());
    if (!url) return false;
    PartialProxyConfig rule;
    rule.url = *url;
    if (entry.contains("include") && entry["include"].is_array()) {
      for (const auto& d : entry["include"]) {
        if (!d.is_string()) return false;
        rule.include.push_back(
            WildCardedDomain::parse(d.get<std::string>()));
      }
    }
    if (entry.contains("exclude") && entry["exclude"].is_array()) {
      for (const auto& d : entry["exclude"]) {
        if (!d.is_string()) return false;
        rule.exclude.push_back(
            WildCardedDomain::parse(d.get<std::string>()));
      }
    }
    out->push_back(std::move(rule));
  }
  return true;
}

}  // namespace

// --- ProxyUrl ---------------------------------------------------------------

std::optional<ProxyUrl> ProxyUrl::parse(const std::string& s) {
  std::string v = trim(s);
  auto scheme_end = v.find("://");
  if (scheme_end == std::string::npos) return std::nullopt;
  ProxyUrl out;
  out.scheme = v.substr(0, scheme_end);
  std::string rest = v.substr(scheme_end + 3);
  // Strip path/query.
  if (auto slash = rest.find('/'); slash != std::string::npos)
    rest = rest.substr(0, slash);
  if (rest.empty()) return std::nullopt;
  // Split host/port (last ':' wins; bracketed IPv6 supported).
  if (!rest.empty() && rest.front() == '[') {
    auto close = rest.find(']');
    if (close == std::string::npos) return std::nullopt;
    out.host = rest.substr(1, close - 1);
    std::string tail = rest.substr(close + 1);
    if (!tail.empty()) {
      if (tail.front() != ':') return std::nullopt;
      try {
        out.port = std::stoi(tail.substr(1));
      } catch (...) {
        return std::nullopt;
      }
    } else {
      out.port = default_port_for(out.scheme);
    }
  } else if (auto colon = rest.rfind(':');
             colon != std::string::npos &&
             rest.find_first_not_of("0123456789", colon + 1) ==
                 std::string::npos &&
             colon + 1 < rest.size()) {
    out.host = rest.substr(0, colon);
    try {
      out.port = std::stoi(rest.substr(colon + 1));
    } catch (...) {
      return std::nullopt;
    }
  } else {
    out.host = rest;
    out.port = default_port_for(out.scheme);
  }
  if (out.host.empty() || out.port <= 0 || out.port > 65535)
    return std::nullopt;
  return out;
}

std::string ProxyUrl::to_string() const {
  return scheme + "://" + host + ":" + std::to_string(port);
}

// --- WildCardedDomain --------------------------------------------------------

WildCardedDomain WildCardedDomain::parse(const std::string& s) {
  // Upstream FromStr verbatim.
  if (s.rfind("*.", 0) == 0) return WildCardedDomain(Kind::WildCarded, s.substr(1));
  if (s == "*") return WildCardedDomain(Kind::WildCarded, "");
  return WildCardedDomain(Kind::Exact, s);
}

bool WildCardedDomain::matches(const std::string& domain) const {
  switch (kind_) {
    case Kind::WildCard:
      return true;
    case Kind::WildCarded:
      // Upstream: domain.ends_with(d), where d starts with '.' (or is "").
      if (value_.empty()) return true;
      if (domain.size() < value_.size()) return false;
      return domain.compare(domain.size() - value_.size(), value_.size(),
                            value_) == 0;
    case Kind::Exact:
      return domain == value_;
  }
  return false;
}

bool WildCardedDomain::more_specific_than(
    const WildCardedDomain& other) const {
  if (kind_ == Kind::WildCard && other.kind_ == Kind::WildCard) return false;
  if (other.kind_ == Kind::WildCard) return true;
  if (kind_ == Kind::Exact && other.kind_ == Kind::WildCarded)
    return other.matches(value_);
  if (kind_ == Kind::WildCarded && other.kind_ == Kind::WildCarded) {
    if (value_ == other.value_) return false;
    if (value_.size() < other.value_.size()) return false;
    return value_.compare(value_.size() - other.value_.size(),
                          other.value_.size(), other.value_) == 0;
  }
  return false;
}

// --- PartialProxyConfig ------------------------------------------------------

std::optional<ProxyUrl> PartialProxyConfig::for_url(
    const std::string& url_or_host) const {
  const std::string domain = host_of(url_or_host);
  if (domain.empty()) return std::nullopt;

  // Upstream for_url verbatim: empty include list means "*".
  const WildCardedDomain* included_because = nullptr;
  WildCardedDomain wildcard_sentinel = WildCardedDomain::wildcard();
  if (include.empty()) {
    included_because = &wildcard_sentinel;
  }
  // NOTE: upstream keeps references into self.include / self.exclude; we
  // track indices instead so the empty-include sentinel above stays valid.
  int included_idx = include.empty() ? -2 : -1;  // -2 = wildcard sentinel
  for (size_t i = 0; i < include.size(); ++i) {
    if (include[i].matches(domain)) {
      if (included_idx >= 0 &&
          !include[i].more_specific_than(include[included_idx])) {
        continue;
      }
      included_idx = static_cast<int>(i);
    }
  }
  if (included_idx >= 0) included_because = &include[included_idx];

  const WildCardedDomain* excluded_because = nullptr;
  int excluded_idx = -1;
  for (size_t i = 0; i < exclude.size(); ++i) {
    if (exclude[i].matches(domain)) {
      if (excluded_idx >= 0 &&
          !exclude[i].more_specific_than(exclude[excluded_idx])) {
        continue;
      }
      excluded_idx = static_cast<int>(i);
    }
  }
  if (excluded_idx >= 0) excluded_because = &exclude[excluded_idx];

  if (included_because && excluded_because) {
    // Included for a more specific reason than excluded.
    if (included_because->more_specific_than(*excluded_because))
      return url;
    return std::nullopt;
  }
  if (included_because) return url;
  return std::nullopt;
}

// --- ProxyConfig --------------------------------------------------------------

ProxyConfig ProxyConfig::global(ProxyUrl url) {
  ProxyConfig cfg;
  cfg.type_ = Type::Global;
  cfg.global_url_ = std::move(url);
  return cfg;
}

ProxyConfig ProxyConfig::by_domain(std::vector<PartialProxyConfig> rules) {
  ProxyConfig cfg;
  cfg.type_ = Type::ByDomain;
  cfg.rules_ = std::move(rules);
  return cfg;
}

ProxyConfig ProxyConfig::parse(const std::string& s) {
  std::string v = trim(s);
  if (v.empty() || v == "none") return ProxyConfig::none();
  // JSON shapes first (contain '{' or start with '[').
  if (!v.empty() && (v.front() == '{' || v.front() == '[')) {
    nlohmann::json j = nlohmann::json::parse(v, nullptr, false);
    if (!j.is_discarded()) {
      if (j.is_object() && j.contains("global") && j["global"].is_string()) {
        if (auto url = ProxyUrl::parse(j["global"].get<std::string>()))
          return ProxyConfig::global(*url);
        return ProxyConfig::none();
      }
      const nlohmann::json* arr = nullptr;
      if (j.is_array()) {
        arr = &j;
      } else if (j.contains("by_domain")) {
        arr = &j["by_domain"];
      }
      if (arr) {
        std::vector<PartialProxyConfig> rules;
        if (parse_rules_array(*arr, &rules))
          return ProxyConfig::by_domain(std::move(rules));
      }
      return ProxyConfig::none();
    }
    return ProxyConfig::none();
  }
  // Bare URL -> global proxy (upstream TOML `proxy = "<url>"` shape).
  if (auto url = ProxyUrl::parse(v)) return ProxyConfig::global(*url);
  return ProxyConfig::none();
}

std::optional<ProxyUrl> ProxyConfig::proxy_for(
    const std::string& url_or_host) const {
  switch (type_) {
    case Type::None:
      return std::nullopt;
    case Type::Global:
      return global_url_;
    case Type::ByDomain: {
      // Upstream: first matching proxy (find_map over rules).
      for (const auto& rule : rules_) {
        if (auto hit = rule.for_url(url_or_host)) return hit;
      }
      return std::nullopt;
    }
  }
  return std::nullopt;
}

// --- host_of -------------------------------------------------------------------

std::string host_of(const std::string& url_or_host) {
  std::string v = trim(url_or_host);
  auto scheme_end = v.find("://");
  std::string rest =
      scheme_end == std::string::npos ? v : v.substr(scheme_end + 3);
  if (auto slash = rest.find('/'); slash != std::string::npos)
    rest = rest.substr(0, slash);
  if (!rest.empty() && rest.front() == '[') {
    auto close = rest.find(']');
    if (close == std::string::npos) return "";
    return rest.substr(1, close - 1);
  }
  if (auto colon = rest.rfind(':');
      colon != std::string::npos &&
      rest.find_first_not_of("0123456789", colon + 1) ==
          std::string::npos &&
      colon + 1 < rest.size())
    return rest.substr(0, colon);
  return rest;
}

}  // namespace proxy
