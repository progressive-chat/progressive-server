cmake_minimum_required(VERSION 3.22)
project(step02_simple_endpoint_handlers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(conduit_step02
  main.cpp
  ruma_wrapper.cpp
)
