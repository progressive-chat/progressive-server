#include "schema.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>

namespace progressive::storage {

std::vector<SchemaVersion> load_schema_versions(std::string_view schema_dir) {
  std::vector<SchemaVersion> versions;
  namespace fs = std::filesystem;

  if (!fs::exists(schema_dir)) return versions;

  for (auto& entry : fs::directory_iterator(schema_dir)) {
    if (!entry.is_directory()) continue;
    auto name = entry.path().filename().string();

    int ver = 0;
    try { ver = std::stoi(name); } catch (...) { continue; }

    SchemaVersion sv;
    sv.version = ver;

    for (auto& f : fs::directory_iterator(entry.path())) {
      if (f.path().extension() != ".sql") continue;
      std::ifstream in(f.path());
      std::stringstream ss;
      ss << in.rdbuf();
      sv.sql.push_back(ss.str());
    }

    versions.push_back(std::move(sv));
  }

  std::sort(versions.begin(), versions.end(),
    [](auto& a, auto& b) { return a.version < b.version; });

  return versions;
}

}
