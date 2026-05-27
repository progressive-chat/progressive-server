#pragma once
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "database.hpp"

namespace progressive::storage {

class MigrationRunner {
public:
  MigrationRunner(DatabasePool& db, std::string_view schema_dir);

  // Version information
  int current_version();
  int schema_compat_version();
  void set_schema_compat_version(int version);

  // Core migration operations
  void upgrade();
  void rollback(int target_version);
  void bootstrap();

  // Schema dump
  std::string dump_schema();
  void write_schema_dump(const std::string& output_path);

  // Validation
  void validate_migrations();

  // Background updates
  void run_background_update(const std::string& update_name);
  void complete_background_update(const std::string& update_name);
  void register_background_update(
      const std::string& update_name,
      const std::string& depends_on = "",
      int ordering = 0,
      int batch_size = 100,
      bool run_as_background_process = false);
  std::string get_background_update_progress(const std::string& update_name);
  void update_background_progress(const std::string& update_name,
                                   const std::string& progress_json);
  void list_pending_background_updates();

  // History
  void list_applied_migrations();

private:
  // Internal helpers
  struct MigrationFile;
  struct MigrationLogEntry;

  std::vector<MigrationFile> load_migration_files() const;
  bool is_migration_applied(int version, const std::string& file_name);
  void record_migration_applied(int version, const std::string& file_name);
  void record_migration_rolled_back(int version, const std::string& file_name);
  void log_migration(int version, const std::string& direction,
                     bool success, const std::string& error_message);

  DatabasePool& db_;
  std::string schema_dir_;
};

void apply_schema(DatabasePool& db);

}  // namespace progressive::storage
