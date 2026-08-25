// data.hpp — translation of Conduit commit fa322689's src/data.rs
//
// pub struct Data { hostname: String, db: Database }
//
// PDU storage — the room event DAG in three trees:
//   pduid_pdus        'd'+room+'#'+index -> pdu json ('n'+room -> counter)
//   roomid_pduleaves  current graph leaves
//   eventid_pduid     event id -> pdu id
#pragma once

#include "database.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

class Data {
 public:
  static Data load_or_create(const std::filesystem::path& dir);

  void set_hostname(const std::string& hostname);
  const std::string& hostname() const;

  bool user_exists(const std::string& user_id) const;
  void user_add(const std::string& user_id, const std::optional<std::string>& password);
  std::optional<std::string> user_from_token(const std::string& token) const;
  std::optional<std::string> password_get(const std::string& user_id) const;
  void device_add(const std::string& user_id, const std::string& device_id);
  void token_replace(const std::string& user_id, const std::string& device_id,
                     const std::string& token);

  std::optional<std::string> pdu_get(const std::string& event_id) const;
  std::vector<std::string> pdu_leaves_replace(const std::string& room_id,
                                              const std::string& event_id);
  void pdu_append(const std::string& event_id, const std::string& room_id,
                  nlohmann::json event);
  std::vector<std::string> pdus_all() const;

 private:
  explicit Data(const std::filesystem::path& dir);

  // OWNERSHIP NOTE (the C++ lesson of this step): Database's trees point into
  // db_storage_'s column families, so db_storage_ is declared first and never
  // moves afterwards. Rust makes this impossible to get wrong; C++ encodes it
  // in declaration order.
  std::string hostname_;
  sled::Db db_storage_;
  stubdb::Database db_;
};
