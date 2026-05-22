cmake_minimum_required(VERSION 3.22)
project(progressive-server
  VERSION 0.1.0
  DESCRIPTION "Progressive Matrix homeserver in C++"
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PROGRESSIVE_BUILD_TESTS "Build tests" ON)
option(PROGRESSIVE_USE_POSTGRES "Enable PostgreSQL support" ON)
option(PROGRESSIVE_USE_SQLITE "Enable SQLite support" ON)

include(FetchContent)

# nlohmann_json
FetchContent_Declare(nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.12.0
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# Googletest
if(PROGRESSIVE_BUILD_TESTS)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.17.0
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(googletest)
endif()

find_package(Boost CONFIG REQUIRED COMPONENTS url json)
find_package(OpenSSL REQUIRED)

if(PROGRESSIVE_USE_SQLITE)
  find_package(SQLite3 QUIET)
  if(NOT SQLite3_FOUND)
    # Fallback: try pkg-config
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
      pkg_check_modules(SQLite3 IMPORTED_TARGET sqlite3)
    endif()
  endif()
endif()

# Subdirectories
add_subdirectory(src)
if(PROGRESSIVE_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
