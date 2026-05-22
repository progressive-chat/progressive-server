#pragma once
#include <functional>
#include <string>
#include <string_view>

#include "database.hpp"

namespace progressive::storage {

class MigrationRunner {
public:
  MigrationRunner(DatabasePool& db, std::string_view schema_dir);

  int current_version();
  void upgrade();

private:
  DatabasePool& db_;
  std::string schema_dir_;
};

void apply_schema(DatabasePool& db);

}  // namespace progressive::storage
