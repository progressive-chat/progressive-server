cmake_minimum_required(VERSION 3.22)
project(conduit_44_3e0378755_ci LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.12.0
  GIT_SHALLOW TRUE
)
FetchContent_Declare(httplib
  GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
  GIT_TAG v0.20.1
  GIT_SHALLOW TRUE
)

find_package(RocksDB QUIET)
if(NOT RocksDB_FOUND)
  set(WITH_GFLAGS OFF CACHE BOOL "" FORCE)
  set(WITH_TESTS OFF CACHE BOOL "" FORCE)
  set(WITH_TOOLS OFF CACHE BOOL "" FORCE)
  set(WITH_BENCHMARK_TOOLS OFF CACHE BOOL "" FORCE)
  set(WITH_CORE_TOOLS OFF CACHE BOOL "" FORCE)
  set(WITH_TRACE_TOOLS OFF CACHE BOOL "" FORCE)
  set(WITH_ZLIB OFF CACHE BOOL "" FORCE)
  set(WITH_ZSTD OFF CACHE BOOL "" FORCE)
  set(WITH_LZ4 OFF CACHE BOOL "" FORCE)
  set(WITH_BZ2 OFF CACHE BOOL "" FORCE)
  set(WITH_SNAPPY OFF CACHE BOOL "" FORCE)
  set(PORTABLE ON CACHE BOOL "" FORCE)
  set(FAIL_ON_WARNINGS OFF CACHE BOOL "" FORCE)
  set(ROCKSDB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(RocksDB
    GIT_REPOSITORY https://github.com/facebook/rocksdb.git
    GIT_TAG v11.8.1
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(RocksDB)
  set(ROCKSDB_TARGET rocksdb)
else()
  set(ROCKSDB_TARGET RocksDB::rocksdb)
endif()

# rust `argon2` crate -> libargon2 (P-H-C reference implementation),
# compiled in directly (the 20190702 tag ships no CMake library target).
FetchContent_Declare(argon2
  GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
  GIT_TAG 20190702
  GIT_SHALLOW TRUE
)
FetchContent_GetProperties(argon2)
if(NOT argon2_POPULATED)
  FetchContent_Populate(argon2)
endif()
set(ARGON2_SRC_DIR ${argon2_SOURCE_DIR})

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

FetchContent_MakeAvailable(nlohmann_json httplib)

find_package(Threads REQUIRED)

add_library(conduit_core STATIC
  src/handlers.cpp
  src/uiaa.cpp
  src/server_server.cpp
  ${ARGON2_SRC_DIR}/src/argon2.c
  ${ARGON2_SRC_DIR}/src/core.c
  ${ARGON2_SRC_DIR}/src/encoding.c
  ${ARGON2_SRC_DIR}/src/ref.c
  ${ARGON2_SRC_DIR}/src/thread.c
  ${ARGON2_SRC_DIR}/src/blake2/blake2b.c
  src/ruma_wrapper.cpp
  src/sled.cpp
  src/data.cpp
  src/utils.cpp
  src/database.cpp
  src/crypto.cpp
  src/media.cpp
)
target_compile_definitions(conduit_core PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(conduit_core PUBLIC
  nlohmann_json::nlohmann_json
  httplib::httplib
  ${ROCKSDB_TARGET}
  OpenSSL::Crypto
  Threads::Threads
)
target_include_directories(conduit_core PUBLIC ${ARGON2_SRC_DIR}/include)
target_compile_options(conduit_core PRIVATE -Wno-unused-parameter)

add_executable(server src/main.cpp)
target_link_libraries(server PRIVATE conduit_core)

add_executable(tests src/test.cpp)
target_link_libraries(tests PRIVATE conduit_core)
set(SERVER_BINARY_PATH $<TARGET_FILE:server>)
target_compile_definitions(tests PRIVATE TEST_SERVER_BINARY="${SERVER_BINARY_PATH}")
