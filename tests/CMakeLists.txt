include(GoogleTest)

set(TEST_SOURCES
  test_types.cpp
  test_state.cpp
  test_push.cpp
  test_protocol.cpp
  test_matrix_full.cpp
  test_batch2.cpp
  test_synapse_port.cpp
  test_real_synapse.cpp
)

foreach(test_src ${TEST_SOURCES})
  get_filename_component(test_name ${test_src} NAME_WE)
  add_executable(${test_name} ${test_src})
  target_link_libraries(${test_name} PRIVATE progressive GTest::gtest GTest::gtest_main)
  target_include_directories(${test_name} PRIVATE "${CMAKE_SOURCE_DIR}/src")
  gtest_discover_tests(${test_name})
endforeach()
