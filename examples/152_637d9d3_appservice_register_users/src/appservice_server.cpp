#include "appservice_server.hpp"
#include "crypto.hpp"
#include "data.hpp"
#include "ruma_wrapper.hpp"

#include <nlohmann/json.hpp>
#include <mutex>
#include <random>

namespace appservice {

AppserviceManager::AppserviceManager(class Data& data) : data_(data) {}

// Generate a random token
static std::string generate_token() {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string token;
    token.reserve(32);
    thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, sizeof(alphanum) - 2);
    for (size_t i = 0; i < 32; ++i) {
        token += alphanum[dist(rng)];
    }
    return token;
}

nlohmann::json AppserviceManager::register_appservice(
    const nlohmann::json& request) {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));

    // Generate tokens
    std::string as_token = generate_token();
    std::string hs_token = generate_token();

    // Generate appservice ID
    std::string appservice_id = "appsvc_" + generate_token();

    // Create appservice registration
    AppserviceRegistration reg;
    reg.id = appservice_id;
    reg.url = request.value("url", "");
    reg.as_token = as_token;
    reg.hs_token = hs_token;
    reg.sender_localpart = request.value("sender_localpart", "");
    // Parse users namespace
    reg.namespaces_users = request.value("namespaces", nlohmann::json::object()).value("users", std::vector<std::string>{});
    
    // Parse aliases namespace - can be array of objects with regex field
    auto aliases_json = request.value("namespaces", nlohmann::json::object()).value("aliases", nlohmann::json::array());
    if (aliases_json.is_array()) {
        for (const auto& alias : aliases_json) {
            if (alias.contains("regex") && alias["regex"].is_string()) {
                reg.namespaces_aliases.push_back(alias["regex"].get<std::string>());
            } else if (alias.is_string()) {
                // Backward compatibility: single regex string
                reg.namespaces_aliases.push_back(alias.get<std::string>());
            }
        }
    } else if (aliases_json.is_object()) {
        // Single alias object with regex
        if (aliases_json.contains("regex") && aliases_json["regex"].is_string()) {
            reg.namespaces_aliases.push_back(aliases_json["regex"].get<std::string>());
        }
    } else if (aliases_json.is_string()) {
        // Backward compatibility: single regex string
        reg.namespaces_aliases.push_back(aliases_json.get<std::string>());
    }
    
    // Parse rooms namespace
    reg.namespaces_rooms = request.value("namespaces", nlohmann::json::object()).value("rooms", std::vector<std::string>{});
    reg.rate_limited = request.value("rate_limited", false);

    appservices_[appservice_id] = std::move(reg);

    nlohmann::json response;
    response["id"] = appservice_id;
    response["as_token"] = as_token;
    response["hs_token"] = hs_token;
    response["sender_localpart"] = request.value("sender_localpart", "");

    return response;
}

std::optional<AppserviceRegistration> AppserviceManager::get_appservice(
    const std::string& appservice_id) const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
    auto it = appservices_.find(appservice_id);
    if (it != appservices_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// NEW in 637d9d3: look up an appservice by its as_token.
std::optional<AppserviceRegistration> AppserviceManager::find_by_as_token(
    const std::string& as_token) const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
    for (const auto& [id, reg] : appservices_) {
        if (reg.as_token == as_token) return reg;
    }
    return std::nullopt;
}

nlohmann::json AppserviceManager::handle_transaction(
    const std::string& appservice_id,
    const nlohmann::json& request) {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));

    auto it = appservices_.find(appservice_id);
    if (it == appservices_.end()) {
        // Return error response
        nlohmann::json error;
        error["errcode"] = "M_NOT_FOUND";
        error["error"] = "Appservice not found";
        return error;
    }

    const auto& appservice = it->second;

    // Verify hs_token
    // TODO: Verify hs_token from request

    nlohmann::json response;
    response["pdus"] = nlohmann::json::object();

    // Process each PDU in the transaction
    if (request.contains("pdus") && request["pdus"].is_array()) {
        for (const auto& pdu : request["pdus"]) {
            // TODO: Process each PDU
            // This is a simplified implementation
        }
    }

    return response;
}

}  // namespace appservice