#pragma once
#include <string>
#include <string_view>

namespace progressive::sso {

struct OidcConfig {
  std::string issuer;
  std::string client_id;
  std::string client_secret;
  std::string discovery_url;
  bool enabled = false;
};

struct SamlConfig {
  std::string idp_metadata_url;
  std::string sp_entity_id;
  bool enabled = false;
};

struct CasConfig {
  std::string server_url;
  bool enabled = false;
};

struct SsoConfig {
  OidcConfig oidc;
  SamlConfig saml;
  CasConfig cas;
};

}  // namespace progressive::sso
