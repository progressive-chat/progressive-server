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
std::string generate_token() {
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
    std::lock_guard<std::mutex> lock(mutex_);

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
    reg.namespaces_users = request.value("namespaces", nlohmann::json::object()).value("users", std::vector<std::string>{});
    reg.namespaces_aliases = request.value("namespaces", nlohmann::json::object()).value("aliases", std::vector<std::string>{});
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
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = appservices_.find(appservice_id);
    if (it != appservices_.end()) {
        return it->second;
    }
    return std::nullopt;
}

const std::map<std::string, AppserviceRegistration>& AppserviceManager::get_all_appservices() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return appservices_;
}

nlohmann::json AppserviceManager::handle_transaction(
    const std::string& appservice_id,
    const nlohmann::json& request) {
    std::lock_guard<std::mutex> lock(mutex_);

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

    nlohmann::json response;
    response["pdus"] = nlohmann::json::object();
    return response;
}

}  // namespace appservice
EOF