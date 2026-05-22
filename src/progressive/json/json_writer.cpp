#include "json_writer.hpp"

namespace progressive::json {

std::string encode_canonical(const nlohmann::json& value) {
  return value.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

}  // namespace progressive::json
