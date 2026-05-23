# Progressive server library
add_library(progressive STATIC
  progressive/types/matrix_id.cpp
  progressive/types/requester.cpp
  progressive/types/state_map.cpp
  progressive/config/config.cpp
  progressive/config/server_config.cpp
  progressive/config/database_config.cpp
  progressive/config/yaml.cpp
  progressive/events/event.cpp
  progressive/events/event_factory.cpp
  progressive/events/unsafe_event.cpp
  progressive/events/signatures.cpp
  progressive/json/canonical.cpp
  progressive/json/json_writer.cpp
  progressive/crypto/signing.cpp
  progressive/crypto/key.cpp
  progressive/storage/database.cpp
  progressive/storage/engine.cpp
  progressive/storage/schema.cpp
  progressive/storage/migration.cpp
  progressive/http/server.cpp
  progressive/http/router.cpp
  progressive/auth/auth.cpp
  progressive/rest/client/endpoints.cpp
  progressive/media/media.cpp
  progressive/federation/auth.cpp
  progressive/federation/federation_server.cpp
  progressive/federation/federation_client.cpp
  progressive/ratelimit/ratelimit.cpp
  progressive/rest/key/v2/server_key.cpp
  progressive/state/room_version.cpp
  progressive/state/event_auth.cpp
  progressive/state/state_resolution.cpp
  progressive/push/types.cpp
  progressive/push/utils.cpp
  progressive/push/evaluator.cpp
  progressive/push/base_rules.cpp
  progressive/server/server.cpp
  progressive/util/random.cpp
  progressive/util/time.cpp
  progressive/util/token.cpp
)

target_include_directories(progressive PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_BINARY_DIR}/.."
)

target_link_libraries(progressive PUBLIC
  Boost::boost
  Boost::url
  Boost::json
  nlohmann_json::nlohmann_json
  OpenSSL::SSL
  OpenSSL::Crypto
)

target_compile_definitions(progressive PRIVATE
  BOOST_BEAST_USE_STD_STRING_VIEW=1
)

target_compile_options(progressive PRIVATE -Wno-error=return-type)

if(SQLite3_FOUND OR TARGET PkgConfig::SQLite3)
  if(TARGET SQLite::SQLite3)
    target_link_libraries(progressive PUBLIC SQLite::SQLite3)
  elseif(TARGET PkgConfig::SQLite3)
    target_link_libraries(progressive PUBLIC PkgConfig::SQLite3)
  endif()
  target_compile_definitions(progressive PUBLIC PROGRESSIVE_HAS_SQLITE=1)
endif()

if(PostgreSQL_FOUND)
  target_link_libraries(progressive PUBLIC PostgreSQL::PostgreSQL)
  target_compile_definitions(progressive PUBLIC PROGRESSIVE_HAS_POSTGRES=1)
endif()

# Main executable
add_executable(progressive-server
  main.cpp
)
target_link_libraries(progressive-server PRIVATE progressive)
