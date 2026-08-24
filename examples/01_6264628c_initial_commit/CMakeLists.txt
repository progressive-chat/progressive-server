cmake_minimum_required(VERSION 3.22)
project(step01_initial_commit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(conduit_step01
  main.cpp
  ruma_wrapper.cpp
)
