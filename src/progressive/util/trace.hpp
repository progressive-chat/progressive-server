#pragma once
#include <chrono>
#include <iostream>
#include <string>
#include <string_view>

namespace progressive::trace {

struct Span {
  std::string name;
  std::string trace_id;
  std::string span_id;
  std::chrono::steady_clock::time_point start;

  Span(std::string_view n) : name(n), start(std::chrono::steady_clock::now()) {}
  ~Span() {
    auto dur = std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::steady_clock::now() - start)
                   .count();
    std::cerr << "[trace] " << name << " " << dur << "us\n";
  }
};

}  // namespace progressive::trace
