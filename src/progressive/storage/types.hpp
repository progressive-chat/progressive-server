#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace progressive::storage {

// PEP-249 DBAPI2 compatible type aliases
// SQLQueryParameters: Sequence[Any] | Mapping[str, Any]
using SQLParam = std::variant<std::string, int64_t, double, std::nullptr_t>;
using SQLQueryParameters = std::vector<SQLParam>;
using SQLNamedParameters = std::vector<std::pair<std::string, SQLParam>>;

// DBAPI2 Exception hierarchy
enum class DBErrorClass {
  Warning,
  Error,
  InterfaceError,
  DatabaseError,
  DataError,
  OperationalError,
  IntegrityError,
  InternalError,
  ProgrammingError,
  NotSupportedError,
};

class DBException : public std::runtime_error {
public:
  DBErrorClass error_class;
  DBException(DBErrorClass cls, const std::string& msg)
      : std::runtime_error(msg), error_class(cls) {}
};

class DataError : public DBException {
public:
  explicit DataError(const std::string& msg = "")
      : DBException(DBErrorClass::DataError, msg) {}
};

class OperationalError : public DBException {
public:
  explicit OperationalError(const std::string& msg = "")
      : DBException(DBErrorClass::OperationalError, msg) {}
};

class IntegrityError : public DBException {
public:
  explicit IntegrityError(const std::string& msg = "")
      : DBException(DBErrorClass::IntegrityError, msg) {}
};

class InternalError : public DBException {
public:
  explicit InternalError(const std::string& msg = "")
      : DBException(DBErrorClass::InternalError, msg) {}
};

class ProgrammingError : public DBException {
public:
  explicit ProgrammingError(const std::string& msg = "")
      : DBException(DBErrorClass::ProgrammingError, msg) {}
};

class NotSupportedError : public DBException {
public:
  explicit NotSupportedError(const std::string& msg = "")
      : DBException(DBErrorClass::NotSupportedError, msg) {}
};

// A database row is a collection of column values
struct ColumnValue {
  std::string name;
  std::optional<std::string> value;
};

using Row = std::vector<ColumnValue>;
using RowList = std::vector<Row>;

// Transaction isolation levels
enum class IsolationLevel : int {
  READ_COMMITTED = 1,
  REPEATABLE_READ = 2,
  SERIALIZABLE = 3,
};

// Auto-increment primary key placeholder used in schema files
static constexpr const char* AUTO_INCREMENT_PRIMARY_KEY_PLACEHOLDER =
    "$%AUTO_INCREMENT_PRIMARY_KEY%$";

// Maximum transaction ID value (Python: MAX_TXN_ID = 2**63 - 1)
static constexpr int64_t MAX_TXN_ID = INT64_MAX;

// Callback types
using AfterCallback = std::function<void()>;
using AsyncAfterCallback = std::function<std::function<void()>()>;
using ExceptionCallback = std::function<void()>;

// SQL execution result
struct SQLResult {
  RowList rows;
  int64_t row_count = 0;
  int64_t last_insert_id = -1;
};

// Forward declarations
class DatabaseConnection;
class DatabaseTransaction;
class BaseDatabaseEngine;
class LoggingDatabaseConnection;
class LoggingTransaction;

}  // namespace progressive::storage
