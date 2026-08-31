// routes.hpp — route logic shared between server and tests (upstream:
// client_server.rs exercised via rocket::local::Client).

#pragma once

#include "data.hpp"
#include "ruma_wrapper.hpp"

struct Context {
  Data* data;
};

std::optional<std::string> extract_token(const httplib::Request& req);

ruma::MatrixResult<ruma::RegisterResponse> register_route(
    Context* ctx, const ruma::RegisterRequest& body);
ruma::MatrixResult<ruma::LoginResponse> login_route(Context* ctx,
                                                    const ruma::LoginRequest& body);

void handle_register(Context* ctx, const httplib::Request& req, httplib::Response& res);
void handle_login(Context* ctx, const httplib::Request& req, httplib::Response& res);
