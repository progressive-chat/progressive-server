#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace progressive::storage {

struct SchemaVersion {
  int version;
  std::vector<std::string> sql;
};

std::vector<SchemaVersion> load_schema_versions(std::string_view schema_dir);

}  // namespace progressive::storage
