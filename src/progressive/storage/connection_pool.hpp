#pragma once
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>

#include "../storage/database.hpp"

namespace progressive::storage {

class ConnectionPool {
public:
  ConnectionPool(std::string_view conn_string, int pool_size = 4);
  std::unique_ptr<DatabasePool> acquire();
  void release(std::unique_ptr<DatabasePool> conn);

private:
  std::string conn_string_;
  int pool_size_;
  std::queue<std::unique_ptr<DatabasePool>> available_;
  std::mutex mutex_;
};

}  // namespace progressive::storage
