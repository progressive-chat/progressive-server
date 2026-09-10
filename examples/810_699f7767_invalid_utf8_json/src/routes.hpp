// routes.hpp — route logic shared between server and tests (upstream:
// client_server.rs exercised via rocket::local::Client).

#pragma once

#include "data.hpp"
#include "ruma_wrapper.hpp"
#include "waiting_servers.hpp"
#include "appservice_server.hpp"

// Forward declaration
struct Context;

struct Context {
  Data* data;
  // NEW in ab33236: track servers with pending federation requests
  // to avoid sending duplicate requests to servers that are already waiting
  federation::WaitingServersTracker waiting_servers;
  // NEW in 6e5b35e: appservice management
  appservice::AppserviceManager appservice_manager;

  Context(Data* d) : data(d), appservice_manager(*d) {}
};

std::optional<std::string> extract_token(const httplib::Request& req);

ruma::MatrixResult<ruma::RegisterResponse> register_route(
    Context* ctx, const ruma::RegisterRequest& body);
ruma::MatrixResult<ruma::LoginResponse> login_route(Context* ctx,
                                                    const ruma::LoginRequest& body);

void handle_register(Context* ctx, const httplib::Request& req, httplib::Response& res);
void handle_login(Context* ctx, const httplib::Request& req, httplib::Response& res);
