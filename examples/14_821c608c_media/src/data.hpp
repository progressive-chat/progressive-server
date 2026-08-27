// data.hpp — translation of Conduit commit abcce95d's src/data.rs
//
// NEW in this commit:
//   users_all()                       — iterate registered user ids
//   room_state(room_id)               — current state from roomstateid_pdu
//   room_invite / rooms_invited       — invite flow via userid_inviteroomids
//   pdu_append writes state events    — 'd'+room+0xff+type+0xff+state_key
//   token storage moves to userdeviceid_token (user + 0xff + device)
//
// Folded prerequisites from skipped intermediate commits (needed context):
//   room_join/room_users/rooms_joined via roomid_userids/userid_roomids,
//   pdus_since(room, since) for per-room sync.
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
  /// NEW in b0d9ccdb: raw Ed25519 seed, generated on first boot and persisted
  /// in the database root (utils::generate_keypair + update_and_fetch).
  const std::string& keypair() const;
  // temporary debug access
  std::vector<std::pair<std::string, std::string>> debug_userid_roomids() const;
  std::vector<std::pair<std::string, std::string>> debug_userid_leftroomids() const;

  bool user_exists(const std::string& user_id) const;
  void user_add(const std::string& user_id, const std::string& hash);
  // NEW: all registered user ids (user directory search).
  std::vector<std::string> users_all() const;
  std::optional<std::string> user_from_token(const std::string& token) const;
  std::optional<std::string> password_hash_get(const std::string& user_id) const;
  void device_add(const std::string& user_id, const std::string& device_id);
  void token_replace(const std::string& user_id, const std::string& device_id,
                     const std::string& token);

  // --- membership (folded prerequisite) --------------------------------------
  void room_join(const std::string& room_id, const std::string& user_id);
  /// NEW in 23cb550d (folded leave flow): leave + forget.
  void room_leave(const std::string& room_id, const std::string& user_id);
  void room_forget(const std::string& room_id, const std::string& user_id);
  size_t room_users(const std::string& room_id) const;
  std::vector<std::string> rooms_joined(const std::string& user_id) const;

  // --- PDU graph --------------------------------------------------------------
  std::optional<std::string> pdu_get(const std::string& event_id) const;
  std::vector<std::string> pdu_leaves_replace(const std::string& room_id,
                                              const std::string& event_id);
  void pdu_append(const std::string& event_id, const std::string& room_id,
                  nlohmann::json event);
  std::vector<std::string> pdus_all() const;
  /// NEW in 23cb550d: backwards pagination — PDUs of a room older than `until`.
  std::vector<std::string> pdus_until(const std::string& room_id,
                                      uint64_t until) const;
  /// NEW: is the given pdu index the first event of the room?
  bool room_pdu_first(const std::string& room_id, uint64_t pdu_index) const;
  /// NEW: last used stream index of a room (= current end position).
  uint64_t last_pdu_index(const std::string& room_id) const;

  /// NEW in 821c608c: media repository access.
  void media_create(const std::string& mxc, const std::optional<std::string>& filename,
                    const std::string& content_type, const std::string& file);
  std::optional<database::Media::File> media_get(const std::string& mxc) const;
  // NEW: all pdus of one room with stream index > since.
  std::vector<std::string> pdus_since(const std::string& room_id,
                                      uint64_t since) const;

  // --- displayname (folded prerequisite + fa9e127a-era semantics) -------------
  std::optional<std::string> displayname_get(const std::string& user_id) const;
  /// Set a new displayname. NEW in 4cc0a070: required (not optional) and
  /// broadcasts an m.room.member join event carrying it to every joined room.
  void displayname_set(const std::string& user_id, const std::string& displayname);
  void displayname_remove(const std::string& user_id);

  // --- NEW in abcce95d: invites & state ----------------------------------------
  // Current state events of a room, as raw canonical JSON strings.
  std::vector<std::string> room_state(const std::string& room_id) const;
  void room_invite(const std::string& sender, const std::string& room_id,
                   const std::string& user_id);
  std::vector<std::string> rooms_invited(const std::string& user_id) const;

 private:
  explicit Data(const std::filesystem::path& dir);

  std::string hostname_;
  std::string keypair_;  // raw 32-byte Ed25519 seed
  sled::Db db_storage_;
  database::Database db_;
};
