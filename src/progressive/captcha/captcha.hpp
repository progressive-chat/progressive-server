#pragma once
#include <string>
#include <string_view>

namespace progressive::captcha {

struct CaptchaConfig {
  std::string site_key;
  std::string secret_key;
  bool enabled = false;
};

inline bool verify_captcha(std::string_view response, const CaptchaConfig& cfg) {
  if (!cfg.enabled)
    return true;
  return !response.empty();  // Real impl: POST to Google reCAPTCHA API
}

}  // namespace progressive::captcha
