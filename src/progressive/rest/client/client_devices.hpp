#pragma once
// client_rest_devices.hpp - devices, keys, push, notifications, receipts, tags, etc.
#include "rest_base.hpp"
namespace progressive::rest {

// ====== DevicesRestServlet ======
class DevicesRestServlet : public ClientV1RestServlet {
public:
  explicit DevicesRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/devices","/_matrix/client/v3/devices/{deviceId}",
            "/_matrix/client/v3/delete_devices"};
  }
  std::vector<std::string> methods() const override { return {"GET","PUT","DELETE","POST"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse get_devices(const HttpRequest& req);
  HttpResponse get_device(const std::string& device_id);
  HttpResponse update_device(const HttpRequest& req, const std::string& device_id);
  HttpResponse delete_device(const HttpRequest& req, const std::string& device_id);
  HttpResponse delete_devices(const HttpRequest& req);
  storage::DatabasePool& db_;
};

// ====== KeysRestServlet (E2E keys) ======
class KeysRestServlet : public ClientV1RestServlet {
public:
  explicit KeysRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/keys/upload","/_matrix/client/v3/keys/query",
            "/_matrix/client/v3/keys/claim","/_matrix/client/v3/keys/device_signing/upload",
            "/_matrix/client/v3/keys/signatures/upload","/_matrix/client/v3/keys/changes"};
  }
  std::vector<std::string> methods() const override { return {"GET","POST"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse upload_keys(const HttpRequest& req);
  HttpResponse query_keys(const HttpRequest& req);
  HttpResponse claim_keys(const HttpRequest& req);
  HttpResponse upload_signing_keys(const HttpRequest& req);
  HttpResponse upload_signatures(const HttpRequest& req);
  HttpResponse get_key_changes(const HttpRequest& req);
  storage::DatabasePool& db_;
};

// ====== PushRulesRestServlet ======
class PushRulesRestServlet : public ClientV1RestServlet {
public:
  explicit PushRulesRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/pushrules","/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}",
            "/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/actions",
            "/_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}/enabled"};
  }
  std::vector<std::string> methods() const override { return {"GET","PUT","DELETE"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse get_push_rules(const HttpRequest& req);
  HttpResponse get_push_rule(const std::string& scope, const std::string& kind, const std::string& rule_id);
  HttpResponse set_push_rule(const HttpRequest& req, const std::string& scope, const std::string& kind, const std::string& rule_id);
  HttpResponse delete_push_rule(const std::string& scope, const std::string& kind, const std::string& rule_id);
  HttpResponse set_rule_actions(const HttpRequest& req, const std::string& scope, const std::string& kind, const std::string& rule_id);
  HttpResponse set_rule_enabled(const HttpRequest& req, const std::string& scope, const std::string& kind, const std::string& rule_id);
  storage::DatabasePool& db_;
};

// ====== PusherRestServlet ======
class PusherRestServlet : public ClientV1RestServlet {
public:
  explicit PusherRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/pushers/set","/_matrix/client/v3/pushers"};
  }
  std::vector<std::string> methods() const override { return {"GET","POST"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse get_pushers(const HttpRequest& req);
  HttpResponse set_pusher(const HttpRequest& req);
  storage::DatabasePool& db_;
};

// ====== NotificationsRestServlet ======
class NotificationsRestServlet : public ClientV1RestServlet {
public:
  explicit NotificationsRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/notifications"};
  }
  std::vector<std::string> methods() const override { return {"GET"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  storage::DatabasePool& db_;
};

// ====== ReceiptsRestServlet ======
class ReceiptsRestServlet : public ClientV1RestServlet {
public:
  explicit ReceiptsRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}",
            "/_matrix/client/v3/rooms/{roomId}/read_markers"};
  }
  std::vector<std::string> methods() const override { return {"POST"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  storage::DatabasePool& db_;
};

// ====== TagsRestServlet ======
class TagsRestServlet : public ClientV1RestServlet {
public:
  explicit TagsRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags",
            "/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}"};
  }
  std::vector<std::string> methods() const override { return {"GET","PUT","DELETE"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse get_tags(const std::string& user_id, const std::string& room_id);
  HttpResponse add_tag(const HttpRequest& req, const std::string& user_id, const std::string& room_id, const std::string& tag);
  HttpResponse delete_tag(const std::string& user_id, const std::string& room_id, const std::string& tag);
  storage::DatabasePool& db_;
};

// ====== SearchRestServlet ======
class SearchRestServlet : public ClientV1RestServlet {
public:
  explicit SearchRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/search","/_matrix/client/v3/user_directory/search"};
  }
  std::vector<std::string> methods() const override { return {"POST","GET"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse search(const HttpRequest& req);
  HttpResponse search_user_directory(const HttpRequest& req);
  storage::DatabasePool& db_;
};

// ====== PresenceRestServlet ======
class PresenceRestServlet : public ClientV1RestServlet {
public:
  explicit PresenceRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/presence/{userId}/status",
            "/_matrix/client/v3/presence/list/{userId}"};
  }
  std::vector<std::string> methods() const override { return {"GET","PUT","POST"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse get_presence(const std::string& user_id);
  HttpResponse set_presence(const HttpRequest& req, const std::string& user_id);
  HttpResponse get_presence_list(const std::string& user_id);
  HttpResponse modify_presence_list(const HttpRequest& req, const std::string& user_id);
  storage::DatabasePool& db_;
};

} // namespace
