// state_res.cpp — translation of Conduit commit c4f5a0a6's state-res
// integration (Aug 6, 2020).
//
// SIMPLIFIED implementation: tracks the latest state hash per room
// but does NOT implement the full ruma/state-res algorithm. The full
// state resolution comes in step 83 (d71d94a).

#include "state_res.hpp"
#include "crypto.hpp"
#include "utils.hpp"

#include <algorithm>
#include <openssl/sha.h>

namespace state_res {

StateHash new_state_hash(const std::vector<std::string>& pdu_ids) {
  if (pdu_ids.empty()) {
    return "";
  }
  // Sort the IDs for deterministic hashing
  std::vector<std::string> sorted = pdu_ids;
  std::sort(sorted.begin(), sorted.end());

  // Concatenate all IDs with 0xff separator (matches Conduit's key format)
  std::string combined;
  for (size_t i = 0; i < sorted.size(); ++i) {
    if (i > 0) combined.push_back(static_cast<char>(0xff));
    combined += sorted[i];
  }

  // SHA-256 hash, hex-encode for readability
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(combined.c_str()),
         combined.size(), hash);
  std::string result;
  char buf[3];
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    snprintf(buf, sizeof(buf), "%02x", hash[i]);
    result += buf;
  }
  return result;
}

std::vector<std::string> reverse_topological_power_sort(
    const std::string& room_id,
    const std::vector<std::string>& event_ids,
    const std::vector<nlohmann::json>& events,
    class Data* db,
    const std::vector<std::string>& auth_diff) {
  // SIMPLIFIED: just return event_ids in input order.
  // The full ruma/state-res algorithm:
  // 1. Builds the auth event graph
  // 2. Sorts events topologically (parents before children)
  // 3. Applies power level tiebreakers
  // This simplified version preserves the API but doesn't do the
  // actual topological sort. Real state resolution requires the
  // full algorithm (see step 83).
  (void)room_id;
  (void)events;
  (void)db;
  (void)auth_diff;
  return event_ids;
}

}  // namespace state_res
