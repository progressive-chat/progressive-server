cmake_minimum_required(VERSION 3.22)
project(step06_save_pdus LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(conduit_step06
  main.cpp
  ruma_wrapper.cpp
  database.cpp
  data.cpp
  utils.cpp
  json_value.cpp
  crypto.cpp
)
