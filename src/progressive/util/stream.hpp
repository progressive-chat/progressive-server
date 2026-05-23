#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

namespace progressive::util {

inline std::atomic<uint64_t> g_stream_counter{0};
inline uint64_t next_stream_id() {
  return ++g_stream_counter;
}

inline std::string timestamp_ms() {
  auto now = std::chrono::system_clock::now();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
  return std::to_string(ms);
}

}  // namespace progressive::util
