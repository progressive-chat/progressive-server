cmake_minimum_required(VERSION 3.22)
project(step04_data_layer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(conduit_step04
  main.cpp
  ruma_wrapper.cpp
  database.cpp
  data.cpp
)
