cmake_minimum_required(VERSION 3.22)
project(step05_auth LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(conduit_step05
  main.cpp
  ruma_wrapper.cpp
  database.cpp
  data.cpp
  utils.cpp
)
