// test.cpp — translation of Conduit commit fa9e127a's src/test.rs
//
// Upstream (rocket::local::Client, in-process):
//   register_login:                          first POST /register -> 401 + flows
//   login_after_register_correct_password:   dummy-auth register -> login 200
//   login_after_register_incorrect_password: register -> login -> M_FORBIDDEN 403
//
// The 401-first assertion exercises UIAA, which this branch hasn't translated
// yet (it arrived upstream in the skipped Apr 6-10 batch), so here the first
// register succeeds directly. Everything else matches.
//
// Environment note: this sandbox only routes loopback connections between
// separate processes, so the harness spawns ./server as a child process
// instead of using an in-process client.

#include "ruma_wrapper.hpp"

#include <httplib.h>

#include <csignal>
#include <sys/wait.h>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

namespace {

constexpr const char* kPort = "18099";

int failures = 0;

void expect(bool condition, const char* what) {
  std::cout << (condition ? "[PASS] " : "[FAIL] ") << what << std::endl;
  if (!condition) ++failures;
}

void registration_init(std::string* body) {
  // fn registration_init() -> &'static str
  *body = R"({
    "username": "cheeky_monkey",
    "password": "ilovebananas",
    "device_id": "GHTYAJCE",
    "initial_device_display_name": "Jungle Phone",
    "inhibit_login": false
  })";
}

void login_with_password(const char* password, std::string* body) {
  nlohmann::json j{
      {"type", "m.login.password"},
      {"identifier", {{"type", "m.id.user"}, {"user", "cheeky_monkey"}}},
      {"password", password},
      {"initial_device_display_name", "Jungle Phone"},
  };
  *body = j.dump();
}

std::string server_url() { return std::string("http://127.0.0.1:") + kPort; }

bool wait_for_server(httplib::Client& client) {
  for (int i = 0; i < 100; ++i) {
    if (auto r = client.Get("/_matrix/client/versions")) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  return false;
}

}  // namespace

int main() {
  const char* home = ::getenv("HOME");
  const std::filesystem::path data_dir =
      (home ? std::filesystem::path{home} : std::filesystem::path{"/tmp"}) /
      ".local/share/conduit-step07-tests";
  std::filesystem::remove_all(data_dir);  // Database::try_remove("temp")

  // Spawn the real server binary as a child process.
  const std::string cmd = std::string(TEST_SERVER_BINARY) + " --port " + kPort +
                          " --data-dir " + data_dir.string() +
                          " > /dev/null 2>&1 & echo $!";
  FILE* pipe = ::popen(cmd.c_str(), "r");
  if (!pipe) {
    std::cout << "FATAL: cannot spawn server\n";
    return 2;
  }
  pid_t server_pid = 0;
  char buf[64] = {};
  if (::fgets(buf, sizeof(buf), pipe)) server_pid = static_cast<pid_t>(::atoi(buf));
  ::pclose(pipe);
  std::cout << "[dbg] server pid: " << server_pid << std::endl;

  httplib::Client client(server_url());
  client.set_read_timeout(std::chrono::seconds(30));

  if (!wait_for_server(client)) {
    std::cout << "FATAL: server did not come up\n";
    if (server_pid) ::kill(server_pid, SIGKILL);
    return 2;
  }

  // ---- register (adapted: no UIAA yet, direct success) ----------------------
  std::string reg_body;
  registration_init(&reg_body);
  auto r = client.Post("/_matrix/client/r0/register", reg_body, "application/json");
  expect(r && r->status == 200, "register returns 200");

  // ---- login_after_register_correct_password --------------------------------
  std::string good;
  login_with_password("ilovebananas", &good);
  r = client.Post("/_matrix/client/r0/login", good, "application/json");
  expect(r && r->status == 200, "login with correct password returns 200");

  // ---- login_after_register_incorrect_password ------------------------------
  std::string bad;
  login_with_password("idontlovebananas", &bad);
  r = client.Post("/_matrix/client/r0/login", bad, "application/json");
  bool forbidden =
      r && r->status == 403 && r->body.find("M_FORBIDDEN") != std::string::npos;
  expect(forbidden, "login with incorrect password returns M_FORBIDDEN 403");

  if (server_pid) ::kill(server_pid, SIGTERM);

  std::cout << (failures ? "TESTS FAILED\n" : "ALL TESTS PASSED\n");
  return failures ? 1 : 0;
}
