#pragma once
// event_federation.hpp - C++ translation of event_federation.py (2,561 lines)

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"

namespace progressive::storage {
using json = nlohmann::json;

struct EventFederationInfo {
  std::string event_id;
  std::string room_id;
  std::string sender;
  int64_t min_depth{0};
  std::vector<std::string> prev_event_ids;
  std::vector<std::string> auth_event_ids;
  bool outlier{false};
};

// Worker store (read-only queries for workers)
class EventFederationWorkerStore {
public:
  explicit EventFederationWorkerStore(DatabasePool& db);
  // Get event federation info for backfill
  std::optional<EventFederationInfo> get_event_federation_info(
      const std::string& event_id);
  // Get room federation info
  struct RoomFederationInfo {
    std::optional<int64_t> min_depth;
    std::optional<std::string> room_version;
    std::vector<std::string> forward_extremities;
    int64_t event_count{0};
  };
  RoomFederationInfo get_room_federation_info(const std::string& room_id);
  // Get events that reference a given event as prev_event
  std::vector<std::string> get_events_which_are_prevs(
      const std::vector<std::string>& event_ids);
  // Get the prev events for a set of events
  std::map<std::string, std::vector<std::string>> get_prev_events_for_events(
      const std::vector<std::string>& event_ids);
  // Get auth chain differences
  struct AuthChainDiff { std::set<std::string> added; std::set<std::string> removed; };
  AuthChainDiff get_auth_chain_difference(
      const std::set<std::string>& state_sets,
      const std::set<std::string>& auth_events);
  // Get all auth events for a set of events (recursively walks auth chain)
  std::set<std::string> get_auth_chain(
      const std::string& room_id,
      const std::set<std::string>& event_ids);
  // Get event to room id mappings
  std::map<std::string, std::string> get_event_to_room_ids(
      const std::set<std::string>& event_ids);
  // Get missing events from a list
  std::set<std::string> get_missing_events(
      const std::set<std::string>& event_ids);
  // Get backward extremeties
  std::vector<std::string> get_backward_extremeties(
      const std::string& room_id);
  // Insert into event auth chain if not present
  void insert_event_auth_chain_if_missing(
      LoggingTransaction& txn, const std::string& event_id,
      const std::vector<std::string>& auth_event_ids,
      const std::string& room_id);
  // Get events that don't have auth chain
  std::vector<std::string> get_events_missing_auth_chain(
      const std::string& room_id, int limit);
protected:
  DatabasePool& db_;
};

// Background update store
class EventFederationBackgroundUpdateStore : public EventFederationWorkerStore {
public:
  explicit EventFederationBackgroundUpdateStore(DatabasePool& db);
  void run_background_event_auth_chain();
  void run_background_event_federation_extremities();
  void run_background_event_chain_cover_index();
};

// Full store
class EventFederationStore : public EventFederationBackgroundUpdateStore {
public:
  explicit EventFederationStore(DatabasePool& db);
  // Persist event auth chain
  void persist_event_auth_chain(
      const std::string& event_id,
      const std::vector<std::string>& auth_event_ids,
      const std::string& room_id);
  // Update event federation info after backfill
  void update_federation_info(const std::string& room_id,
      const std::vector<std::string>& new_events,
      const std::vector<std::string>& new_extremities);
  // Store auth chain for a batch of events
  void store_auth_chain_batch(
      const std::map<std::string, std::vector<std::string>>& auth_chains,
      const std::string& room_id);
  // Remove events from forward_extremities
  void remove_forward_extremities(const std::string& room_id,
      const std::vector<std::string>& event_ids);
  // Add forward_extremities
  void add_forward_extremities(const std::string& room_id,
      const std::vector<std::string>& event_ids);
  // Update backward extremeties
  void update_backward_extremeties(const std::string& room_id,
      const std::vector<std::string>& event_ids);
  // Get rooms that may have missing auth
  std::vector<std::string> get_rooms_missing_auth(int limit);
  // Delete old extremity events
  void delete_old_extremities(const std::string& room_id, int64_t before_depth);
  // Get the auth chain in topological order
  std::vector<std::string> get_auth_chain_ordered(
      const std::string& room_id,
      const std::set<std::string>& event_ids);
  // Batch-get auth chain for multiple rooms
  std::map<std::string, std::set<std::string>> get_bulk_auth_chain(
      const std::map<std::string, std::set<std::string>>& room_events);
  // Get chain cover index values
  struct ChainCoverEntry {
    int64_t chain_id{0};
    int64_t sequence_number{0};
  };
  std::optional<ChainCoverEntry> get_chain_cover_for_event(
      const std::string& event_id);
  std::map<std::string, ChainCoverEntry> get_chain_cover_for_events(
      const std::set<std::string>& event_ids);
  // Store chain cover entries
  void persist_chain_cover(
      const std::map<std::string, std::pair<int64_t, int64_t>>& chain_covers);
  // Compute auth chain difference using chain cover
  AuthChainDiff get_auth_chain_difference_using_cover(
      const std::set<std::string>& state_set_ids,
      const std::set<std::string>& event_ids);
private:
  // Walk auth chain recursively
  void walk_auth_chain(LoggingTransaction& txn,
      std::set<std::string>& seen,
      std::vector<std::string>& result,
      const std::string& event_id,
      const std::string& room_id);
};
} // namespace progressive::storage
