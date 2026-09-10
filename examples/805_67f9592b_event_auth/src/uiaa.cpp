#include "uiaa.hpp"

namespace database {

namespace {

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

std::string Uiaa::make_key(const std::string& user_id,
                           const std::string& device_id,
                           const std::string& session) const {
  std::string key = user_id;
  key.push_back(static_cast<char>(0xff));
  key += device_id;
  key.push_back(static_cast<char>(0xff));
  key += session;
  return key;
}

void Uiaa::create(const std::string& user_id, const std::string& device_id,
                  const std::string& session, const nlohmann::json& uiaainfo) {
  update_session(make_key(user_id, device_id, session), &uiaainfo);
}

Uiaa::Attempt Uiaa::try_auth(const std::string& user_id,
                             const std::string& device_id,
                             const nlohmann::json& auth,
                             const nlohmann::json& uiaainfo,
                             const std::string& hostname) {
  (void)hostname;
  const std::string kind = auth.value("type", "");
  const std::string session = auth.value("session", "");

  if (session.empty()) {
    return Attempt{false, uiaainfo};
  }

  const std::string key = make_key(user_id, device_id, session);

  // NEW in cf94b8e7: if session doesn't exist yet, create a fresh one.
  auto stored = get_session(key, session);
  nlohmann::json info;
  if (!stored) {
    info = make_uiaainfo(session);
    if (!uiaainfo.is_null() && uiaainfo.contains("flows")) {
      info["flows"] = uiaainfo["flows"];
    }
    if (!uiaainfo.is_null() && uiaainfo.contains("params")) {
      info["params"] = uiaainfo["params"];
    }
    update_session(make_key(user_id, device_id, session), &info);
    // Store the original request for later reference
    set_uiaa_request(user_id, device_id, session, auth);
  } else {
    info = *stored;
  }

  auto completed = info["completed"].get<std::vector<std::string>>();

  // Find out what the user completed.
  if (kind == "m.login.dummy") {
    completed.push_back("m.login.dummy");
  } else {
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
    update_session(key, &info);
    return Attempt{false, std::move(info)};
  }

  // UIAA was successful! Remove this session and return true.
  update_session(key, nullptr);
  return Attempt{true, std::move(info)};
}

void Uiaa::set_uiaa_request(const std::string& user_id, const std::string& device_id,
                            const std::string& session,
                            const nlohmann::json& request) {
  std::string key = user_id;
  key.push_back(static_cast<char>(0xff));
  key += device_id;
  key.push_back(static_cast<char>(0xff));
  key += session;
  request_tree_.insert(key, request.dump());
}

std::optional<nlohmann::json> Uiaa::get_uiaa_request(
    const std::string& user_id, const std::string& device_id,
    const std::string& session) const {
  std::string key = user_id;
  key.push_back(static_cast<char>(0xff));
  key += device_id;
  key.push_back(static_cast<char>(0xff));
  key += session;
  auto text = request_tree_.get(key);
  if (!text) return std::nullopt;
  try {
    return nlohmann::json::parse(*text);
  } catch (...) {
    return std::nullopt;
  }
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
  try {
    auto info = nlohmann::json::parse(*text, nullptr, false);
    if (info.is_discarded()) return std::nullopt;
    if (info.value("session", "") != session)
      return std::nullopt;  // "wrong session token"
    return info;
  } catch (...) {
    return std::nullopt;
  }
}

}  // namespace database
