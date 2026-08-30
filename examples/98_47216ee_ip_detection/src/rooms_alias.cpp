// rooms_alias.cpp — see rooms_alias.hpp for the 21af83e correspondence note.
#include "rooms_alias.hpp"

#include "data.hpp"

namespace rooms_alias {

std::optional<std::string> get_alias_helper(Data* data,
                                            const std::string& room_alias) {
  // Local alias resolution only. Federation / appservice alias lookup is adapted
  // away (not yet implemented in this server).
  return data->id_from_alias(room_alias);
}

}  // namespace rooms_alias
