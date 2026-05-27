#pragma once
// receipts.hpp - C++ translation of receipts.py
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage { using json = nlohmann::json;

struct ReadReceipt {
  std::string room_id;
  std::string user_id;
  std::string event_id;
  std::string receipt_type; // "m.read", "m.read.private"
  int64_t stream_ordering{0};
  int64_t thread_id{0}; // 0 = main timeline
};

class ReceiptsStore {
public:
  explicit ReceiptsStore(DatabasePool& db);
  // Insert receipt
  void insert_receipt(const std::string& room_id, const std::string& user_id,
      const std::string& event_id, const std::string& receipt_type,
      int64_t stream_ordering, int64_t thread_id = 0);
  // Get receipts for a room (since a given stream ordering)
  std::vector<ReadReceipt> get_receipts_for_room(const std::string& room_id,
      int64_t from_stream_ordering, int64_t to_stream_ordering);
  // Get user's receipt for room
  std::optional<ReadReceipt> get_user_receipt(const std::string& room_id,
      const std::string& user_id, const std::string& receipt_type = "m.read");
  // Get all users who have read up to an event
  std::vector<std::string> get_users_with_read_receipts_for_event(
      const std::string& room_id, const std::string& event_id);
  // Get receipts for multiple rooms
  std::map<std::string, std::vector<ReadReceipt>> get_receipts_for_rooms(
      const std::set<std::string>& room_ids, int64_t from_stream);
  // Get the max receipt stream ordering
  int64_t get_max_receipt_stream_ordering();
  // Get linearized receipt for user/room
  std::optional<ReadReceipt> get_linearized_receipt(const std::string& room_id,
      const std::string& user_id, const std::string& receipt_type = "m.read");
  // Insert graph receipt
  void insert_graph_receipt(const std::string& room_id, const std::string& user_id,
      const std::string& event_id, const std::string& receipt_type);
  // Update receipt stream position
  void update_receipt_stream_position(int64_t stream_id);
private:
  DatabasePool& db_;
};
} // namespace
