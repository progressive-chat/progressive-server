cmake_minimum_required(VERSION 3.22)
project(step03_database LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(conduit_step03
  main.cpp
  ruma_wrapper.cpp
  database.cpp
)
