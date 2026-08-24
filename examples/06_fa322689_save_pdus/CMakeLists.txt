cmake_minimum_required(VERSION 3.22)
project(conduit_fa322689_save_pdus LANGUAGES CXX)

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

# sled -> RocksDB (the engine conduwuit/tuwunel actually migrated to).
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

FetchContent_MakeAvailable(nlohmann_json httplib)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

add_executable(server
  src/main.cpp
  src/ruma_wrapper.cpp
  src/sled.cpp
  src/data.cpp
  src/utils.cpp
  src/database.cpp
  src/crypto.cpp
)
target_link_libraries(server PRIVATE
  nlohmann_json::nlohmann_json
  httplib::httplib
  ${ROCKSDB_TARGET}
  OpenSSL::Crypto
  Threads::Threads
)
