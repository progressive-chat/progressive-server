#include "connection_pool.hpp"

#include <thread>

namespace progressive::storage {

ConnectionPool::ConnectionPool(std::string_view conn_string, int pool_size)
    : conn_string_(conn_string), pool_size_(pool_size) {
  for (int i = 0; i < pool_size; i++)
    available_.push(DatabasePool::create(conn_string_));
}

std::unique_ptr<DatabasePool> ConnectionPool::acquire() {
  std::lock_guard lock(mutex_);
  if (available_.empty())
    return DatabasePool::create(conn_string_);
  auto conn = std::move(available_.front());
  available_.pop();
  return conn;
}

void ConnectionPool::release(std::unique_ptr<DatabasePool> conn) {
  std::lock_guard lock(mutex_);
  available_.push(std::move(conn));
}

}  // namespace progressive::storage
