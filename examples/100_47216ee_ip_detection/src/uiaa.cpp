#include "uiaa.hpp"

namespace database {

namespace {

std::string session_key(const std::string& user_id, const std::string& device_id) {
  std::string key = user_id;
  key.push_back(static_cast<char>(0xff));
  key += device_id;
  return key;
}

// The subset of UiaaInfo we track, kept as plain JSON (upstream used the
// ruma UiaaInfo struct — same wire shape).
nlohmann::json make_uiaainfo(const std::string& session) {
  return nlohmann::json{
      {"flows",
       nlohmann::json::array({
           nlohmann::json{{"stages",
                           nlohmann::json::array({"m.login.dummy"})}},
       })},
      {"completed", nlohmann::json::array()},
      {"params", nlohmann::json::object()},
      {"session", session},
  };
}

}  // namespace

void Uiaa::create(const std::string& user_id, const std::string& device_id,
                  const nlohmann::json& uiaainfo) {
  update_session(session_key(user_id, device_id), &uiaainfo);
}

Uiaa::Attempt Uiaa::try_auth(const std::string& user_id,
                             const std::string& device_id,
                             const nlohmann::json& auth,
                             const nlohmann::json& uiaainfo,
                             const std::string& hostname) {
  (void)hostname;
  const std::string kind = auth.value("type", "");
  const std::string session_value = auth.value("session", "");

  // get_uiaa_session: resume by session token, else use the fresh template.
  nlohmann::json info = uiaainfo;
  if (!session_value.empty()) {
    auto stored = get_session(session_key(user_id, device_id), session_value);
    if (!stored) return Attempt{false, uiaainfo};
    info = *stored;
  }

  auto completed = info["completed"].get<std::vector<std::string>>();

  // Find out what the user completed.
  if (kind == "m.login.dummy") {
    completed.push_back("m.login.dummy");
  } else {
    // panic!("type not supported") upstream; surface as failed attempt.
    info["errcode"] = "M_UNKNOWN";
    info["error"] = "type not supported";
    return Attempt{false, std::move(info)};
  }
  info["completed"] = completed;

  // Check if a flow now succeeds.
  bool flow_completed = false;
  for (const auto& flow : info["flows"]) {
    bool all = true;
    for (const auto& stage : flow["stages"])
      if (std::find(completed.begin(), completed.end(),
                    stage.get<std::string>()) == completed.end())
        all = false;
    if (all) flow_completed = true;
  }

  if (!flow_completed) {
    update_session(session_key(user_id, device_id), &info);
    return Attempt{false, std::move(info)};
  }

  // UIAA was successful! Remove this session and return true.
  update_session(session_key(user_id, device_id), nullptr);
  return Attempt{true, std::move(info)};
}

void Uiaa::update_session(const std::string& key, const nlohmann::json* uiaainfo) {
  if (uiaainfo)
    tree_.insert(key, uiaainfo->dump());
  else
    tree_.erase(key);
}

std::optional<nlohmann::json> Uiaa::get_session(const std::string& key,
                                                const std::string& session) const {
  auto text = tree_.get(key);
  if (!text) return std::nullopt;
  auto info = nlohmann::json::parse(*text, nullptr, false);
  if (info.is_discarded()) return std::nullopt;
  if (info.value("session", "") != session)
    return std::nullopt;  // "wrong session token"
  return info;
}

}  // namespace database
