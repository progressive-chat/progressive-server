// json_value.hpp — minimal recursive JSON for step 6 (fa322689)
//
// Reference hashes require CANONICAL JSON: recursively sorted keys, no
// whitespace. The flat JsonObject from earlier steps can't do that, so here is
// a tiny JsonValue tree (what serde_json::Value is upstream). ~200 lines that
// normally live inside serde/nlohmann.

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace json {

class Value;
using Array = std::vector<Value>;
// std::map keeps keys sorted — canonical order for free.
using Object = std::map<std::string, Value>;

class Value {
 public:
  using Storage =
      std::variant<std::nullptr_t, bool, double, std::string, Array, Object>;

  Value() : storage_(nullptr) {}
  Value(std::nullptr_t) : storage_(nullptr) {}
  Value(bool b) : storage_(b) {}
  Value(double d) : storage_(d) {}
  Value(int i) : storage_(static_cast<double>(i)) {}
  Value(uint64_t u) : storage_(static_cast<double>(u)) {}
  Value(const char* s) : storage_(std::string(s)) {}
  Value(std::string s) : storage_(std::move(s)) {}
  Value(Array a) : storage_(std::move(a)) {}
  Value(Object o) : storage_(std::move(o)) {}

  bool is_null() const { return std::holds_alternative<std::nullptr_t>(storage_); }
  bool is_string() const { return std::holds_alternative<std::string>(storage_); }
  bool is_object() const { return std::holds_alternative<Object>(storage_); }

  const std::string& as_string() const { return std::get<std::string>(storage_); }
  double as_double() const { return std::get<double>(storage_); }
  const Object& as_object() const { return std::get<Object>(storage_); }
  Object& as_object_mut() { return std::get<Object>(storage_); }
  const Array& as_array() const { return std::get<Array>(storage_); }
  Array& as_array_mut() { return std::get<Array>(storage_); }

  // Parse a complete JSON document; throws std::runtime_error on garbage.
  static Value parse(const std::string& text);

  // Canonical form: sorted keys (std::map already), no insignificant spaces.
  std::string canonical() const;

 private:
  Storage storage_;

  static Value parse_value(const std::string& s, size_t& i);
  static void dump(const Value& v, std::string& out);
};

}  // namespace json
