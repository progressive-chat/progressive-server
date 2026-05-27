#pragma once
// client_rest_auth.hpp - auth, register, login, logout, account REST servlets
#include "rest_base.hpp"
#include "progressive/storage/databases/main/registration.hpp"

namespace progressive::rest {

// ====== RegisterRestServlet ======
class RegisterRestServlet : public ClientV1RestServlet {
public:
  explicit RegisterRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/register", "/_matrix/client/v1/register"};
  }
  std::vector<std::string> methods() const override { return {"POST", "GET"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse on_POST(const HttpRequest& req);
  HttpResponse on_GET(const HttpRequest& req);
  storage::DatabasePool& db_;
};

// ====== LoginRestServlet ======
class LoginRestServlet : public ClientV1RestServlet {
public:
  explicit LoginRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/login", "/_matrix/client/v1/login"};
  }
  std::vector<std::string> methods() const override { return {"POST", "GET"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse on_POST_login(const HttpRequest& req);
  HttpResponse on_GET_login(const HttpRequest& req);
  storage::DatabasePool& db_;
};

// ====== LogoutRestServlet ======
class LogoutRestServlet : public ClientV1RestServlet {
public:
  explicit LogoutRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/logout", "/_matrix/client/v1/logout"};
  }
  std::vector<std::string> methods() const override { return {"POST"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  storage::DatabasePool& db_;
};

// ====== AuthRestServlet (GET /login flows) ======
class AuthRestServlet : public ClientV1RestServlet {
public:
  explicit AuthRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/login"};
  }
  std::vector<std::string> methods() const override { return {"GET"}; }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  storage::DatabasePool& db_;
};

// ====== AccountRestServlet ======
class AccountRestServlet : public ClientV1RestServlet {
public:
  explicit AccountRestServlet(storage::DatabasePool& db);
  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/account/whoami",
            "/_matrix/client/v3/account/password",
            "/_matrix/client/v3/account/deactivate",
            "/_matrix/client/v3/account/3pid",
            "/_matrix/client/v3/account/3pid/add",
            "/_matrix/client/v3/account/3pid/bind",
            "/_matrix/client/v3/account/3pid/delete",
            "/_matrix/client/v3/account/3pid/unbind",
            "/_matrix/client/v3/account/3pid/email/requestToken",
            "/_matrix/client/v3/account/3pid/msisdn/requestToken"};
  }
  std::vector<std::string> methods() const override {
    return {"GET", "POST", "PUT", "DELETE"};
  }
  HttpResponse on_request(const HttpRequest& req) override;
private:
  HttpResponse whoami(const HttpRequest& req);
  HttpResponse change_password(const HttpRequest& req);
  HttpResponse deactivate_account(const HttpRequest& req);
  HttpResponse get_threepids(const HttpRequest& req);
  HttpResponse add_threepid(const HttpRequest& req);
  HttpResponse bind_threepid(const HttpRequest& req);
  HttpResponse delete_threepid(const HttpRequest& req);
  HttpResponse request_email_token(const HttpRequest& req);
  storage::DatabasePool& db_;
};

} // namespace
