#pragma once

#include "data.hpp"
#include "ruma_wrapper.hpp"

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace appservice {

struct AppserviceRegistration {
    std::string id;
    std::string url;
    std::string as_token;
    std::string hs_token;
    std::string sender_localpart;
    std::vector<std::string> namespaces_users;
    std::vector<std::string> namespaces_aliases;
    std::vector<std::string> namespaces_rooms;
    bool rate_limited = false;
};

struct AppserviceRegistrationResponse {
    std::string id;
    std::string as_token;
    std::string hs_token;
    std::string sender_localpart;
};

struct SendTransactionMessageResponse {
    nlohmann::json pdus = nlohmann::json::object();
};

class AppserviceManager {
public:
    AppserviceManager(class Data& data);

    // Register a new appservice
    nlohmann::json register_appservice(
        const nlohmann::json& request);

    // Get appservice info
    std::optional<AppserviceRegistration> get_appservice(const std::string& appservice_id) const;

    // Handle appservice transaction
    nlohmann::json handle_transaction(
        const std::string& appservice_id,
        const nlohmann::json& request);

private:
    class Data& data_;
    std::mutex mutex_;
    std::map<std::string, AppserviceRegistration> appservices_;
};

}  // namespace appservice