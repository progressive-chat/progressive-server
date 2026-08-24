cmake_minimum_required(VERSION 3.22)
project(conduit_cd777af4_simple_endpoint_handlers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# serde_json -> nlohmann/json (same version the parent project pins).
FetchContent_Declare(nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.12.0
  GIT_SHALLOW TRUE
)
# Rocket -> cpp-httplib.
FetchContent_Declare(httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.20.1
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(nlohmann_json httplib)

find_package(Threads REQUIRED)

add_executable(server
  src/main.cpp
  src/ruma_wrapper.cpp
)
target_link_libraries(server PRIVATE
  nlohmann_json::nlohmann_json
  httplib::httplib
  Threads::Threads
)
