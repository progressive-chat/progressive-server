#include "database.hpp"

namespace progressive::storage {

// ConnectionPool implementation — defined as virtual base in database.hpp
// The real pooling is in DatabasePool via ConnectionPool virtual interface.
// This file provides the factory function make_pool.

std::unique_ptr<ConnectionPool> make_pool(
    const std::string& /*database_name*/,
    const std::string& /*connection_string*/,
    std::shared_ptr<BaseDatabaseEngine> /*engine*/,
    const std::string& /*server_name*/,
    std::function<void(DatabaseConnection&)> /*on_new_connection*/) {
  // Return a minimal pool — the real implementation uses SQLite/Postgres specific pools
  // For now, return nullptr (the DatabasePool will handle connections directly)
  return nullptr;
}

}  // namespace progressive::storage
