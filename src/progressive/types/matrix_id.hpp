#pragma once
#include <string>
#include <string_view>
#include <optional>
#include <stdexcept>
#include <algorithm>
#include <cctype>

namespace progressive {

struct InvalidMatrixId : std::runtime_error {
  using std::runtime_error::runtime_error;
};

template<char Sigil>
class DomainSpecificString {
public:
  static constexpr char sigil = Sigil;

  DomainSpecificString(std::string localpart, std::string domain)
    : localpart_(std::move(localpart))
    , domain_(std::move(domain))
    , id_(sigil + localpart_ + ':' + domain_)
  {
    validate();
  }

  static DomainSpecificString from_string(std::string_view s) {
    if (s.empty() || s[0] != sigil) {
      throw InvalidMatrixId("expected sigil " + std::string(1, sigil));
    }
    auto colon = s.find(':', 1);
    if (colon == std::string_view::npos) {
      throw InvalidMatrixId("missing ':' in Matrix ID");
    }
    return DomainSpecificString(
      std::string(s.substr(1, colon - 1)),
      std::string(s.substr(colon + 1))
    );
  }

  const std::string& localpart() const { return localpart_; }
  const std::string& domain() const { return domain_; }
  const std::string& to_string() const { return id_; }

  bool operator==(const DomainSpecificString& o) const { return id_ == o.id_; }
  bool operator!=(const DomainSpecificString& o) const { return id_ != o.id_; }
  bool operator<(const DomainSpecificString& o) const { return id_ < o.id_; }

  struct hash {
    size_t operator()(const DomainSpecificString& s) const {
      return std::hash<std::string>{}(s.id_);
    }
  };

private:
  void validate() {
    if (localpart_.empty()) throw InvalidMatrixId("empty localpart");
    if (domain_.empty()) throw InvalidMatrixId("empty domain");
    for (char c : localpart_) {
      if (c == '\x00' || static_cast<unsigned char>(c) > 0x7F)
        throw InvalidMatrixId("invalid byte in localpart");
    }
  }

  std::string localpart_;
  std::string domain_;
  std::string id_;
};

using UserID    = DomainSpecificString<'@'>;
using RoomID    = DomainSpecificString<'!'>;
using RoomAlias = DomainSpecificString<'#'>;
using EventID   = DomainSpecificString<'$'>;

}
