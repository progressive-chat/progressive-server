// rooms_alias.hpp — mirrors Conduit's service/rooms/alias/mod.rs get_alias_helper,
// which 21af83e relocated out of client_server/alias.rs. In Conduit it also
// performs federation alias lookup and appservice alias queries; our server does
// not implement those yet, so the helper resolves local aliases only (the
// adapted behaviour).
#pragma once
#include <optional>
#include <string>

struct Data;

namespace rooms_alias {

// Resolves a room alias to a room id. Returns nullopt if no local mapping
// exists (Conduit would fall back to federation / appservice lookup here).
std::optional<std::string> get_alias_helper(Data* data,
                                            const std::string& room_alias);

}  // namespace rooms_alias
