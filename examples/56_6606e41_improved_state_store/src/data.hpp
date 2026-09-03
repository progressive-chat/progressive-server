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

// NEW in db8a0c5: ClosestParent types for PDU insertion ordering
struct ClosestParentAppend {};
struct ClosestParentInsert {
    uint64_t count;
};

using ClosestParent = std::variant<ClosestParentAppend, ClosestParentInsert>;

class Data {
 public:
  static Data load_or_create(const std::filesystem::path& dir, uint64_t cache_capacity = 1024 * 1024 * 1024);

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
  /// NEW in b106d139: remove_device — deletes the (user, device) binding and
  /// its access token. Returns false when the token belongs to nobody.
  void remove_device(const std::string& user_id, const std::string& device_id);
  bool remove_device_by_token(const std::string& token);
  /// NEW in 67a1f21f: current access token bound to a device (nullopt if none).
  std::optional<std::string> token_for_device(const std::string& user_id,
                                              const std::string& device_id) const;
  /// NEW in 67a1f21f: Argon2id-hash and store a new password.
  bool set_password(const std::string& user_id, const std::string& password);
  /// NEW in b8193984: account deactivation — removes all devices and blanks
  /// the password (empty string marks a deactivated account).
  void deactivate_account(const std::string& user_id);
  bool is_deactivated(const std::string& user_id) const;
  /// NEW in 67a1f21f: all devices of a user.
  std::vector<std::string> all_device_ids(const std::string& user_id) const;

  // --- membership (folded prerequisite) --------------------------------------
  /// b6c0e9bf: appends the join member event; trees updated post-auth.
  bool room_join(const std::string& room_id, const std::string& user_id);
  /// NEW in 23cb550d (folded leave flow): leave + forget.
  bool room_leave(const std::string& room_id, const std::string& user_id);
  void room_forget(const std::string& room_id, const std::string& user_id);
  size_t room_users(const std::string& room_id) const;
  std::vector<std::string> rooms_joined(const std::string& user_id) const;

  // --- PDU graph --------------------------------------------------------------
  std::optional<std::string> pdu_get(const std::string& event_id) const;
  /// NEW in 18bf6774: replace a PDU with its redacted form.
  void redact_pdu(const std::string& event_id);
  std::vector<std::string> pdu_leaves_replace(const std::string& room_id,
                                              const std::string& event_id);
  /// b6c0e9bf: returns false (and stores nothing) when unauthorized.
  /// NEW in 12b0efa: pre-computed count and pdu_id for consistency between
  /// pdu storage and state append.
  bool pdu_append(const std::string& event_id, const std::string& room_id,
                  nlohmann::json event, uint64_t count = 0,
                  const std::string& pdu_id = "");
  std::vector<std::string> pdus_all() const;
  /// NEW in 23cb550d: backwards pagination — PDUs of a room older than `until`.
  std::vector<std::string> pdus_until(const std::string& room_id,
                                      uint64_t until) const;
  /// NEW: is the given pdu index the first event of the room?
  bool room_pdu_first(const std::string& room_id, uint64_t pdu_index) const;
  /// NEW: last used stream index of a room (= current end position).
  uint64_t last_pdu_index(const std::string& room_id) const;
  /// NEW in 1f292c09: is this room known to us (has any PDU been stored)?
  bool room_exists(const std::string& room_id) const;

  // --- NEW in 12a8c9ba: federation (server-side PDU serving) -----------------
  /// Current full state of a room as a list of PDU JSON objects.
  std::vector<nlohmann::json> federation_full_state(const std::string& room_id) const;
  /// Transitive auth-chain PDUs for the given (seed) event ids.
  std::vector<nlohmann::json> federation_auth_chain(
      const std::string& room_id, const std::vector<std::string>& event_ids) const;
  /// All PDUs of a room (used by /backfill), as JSON objects.
  std::vector<nlohmann::json> federation_pdus_of_room(const std::string& room_id) const;
// NEW in 71500b1: get participating servers in a room
  std::vector<std::string> room_servers(const std::string& room_id) const;

  // NEW in db8a0c5: find closest parent for PDU insertion ordering
  std::optional<std::variant<ClosestParentAppend, ClosestParentInsert>> get_closest_parent(
      const std::string& room_id,
      const std::vector<std::string>& incoming_prev_ids,
      const std::map<std::string, nlohmann::json>& their_state) const;

  // NEW in db8a0c5: helper methods for PDU lookup
  std::optional<std::string> get_pdu_id(const std::string& event_id) const;
  uint64_t pdu_count(const std::string& pdu_id) const;

  // --- NEW in b6c0e9bf: access control ----------------------------------------
  bool is_joined(const std::string& user_id, const std::string& room_id) const;
  std::optional<std::string> membership_of(const std::string& room_id,
                                           const std::string& user_id) const;
  void update_membership(const std::string& room_id, const std::string& user_id,
                         const std::string& membership);

  /// NEW in c85d363d: UIAA session storage passthrough. The user id here is
  /// "@pending:<session>" until registration completes (upstream keyed by the
  /// parsed UserId; we key by pending-session since registration has no user yet).
  void uiaa_create(const std::string& key_user, const std::string& device,
                   const nlohmann::json& uiaainfo) {
    db_.uiaa.create(key_user, device, uiaainfo);
  }

  /// NEW in 7031240a: all state events of one type in a room.
// REMOVED in 6606e41: room_state_type was removed in favor of filtering
  // room_state() by type. The Conduit commit adds a statekey_short tree for
  // efficiency; we filter in-memory for now.

  // --- NEW in 3aa0c8ed (+ 9c26e22a): aliases & visibility ----------------------
  void set_alias(const std::string& alias, const std::string& room_id);
  void remove_alias(const std::string& alias);
  std::optional<std::string> id_from_alias(const std::string& alias) const;
  std::vector<std::string> room_aliases(const std::string& room_id) const;
  void set_public(const std::string& room_id, bool is_public);
  /// All rooms marked public (3aa0c8ed).
  std::vector<std::string> public_rooms() const;

  // --- NEW in 3f4cb753: key backup store (folded base + remaining) --------
  std::string backup_create(const std::string& user_id, const nlohmann::json& algorithm);
  std::optional<std::string> backup_latest(const std::string& user_id) const;
  std::optional<nlohmann::json> backup_get(const std::string& user_id,
                                           const std::string& version) const;
  void backup_update(const std::string& user_id, const std::string& version,
                     const nlohmann::json& algorithm);
  std::string backup_add_key(const std::string& user_id, const std::string& version,
                             const std::string& room_id, const std::string& session_id,
                             const nlohmann::json& key_data);
  size_t backup_count(const std::string& user_id, const std::string& version) const;
  std::string backup_etag(const std::string& user_id, const std::string& version) const;
  nlohmann::json backup_get_keys(const std::string& user_id,
                                const std::string& version) const;
  void backup_delete(const std::string& user_id, const std::string& version);
  nlohmann::json backup_get_room(const std::string& user_id, const std::string& version,
                                const std::string& room_id) const;
  std::optional<nlohmann::json> backup_get_session(const std::string& user_id,
                                                  const std::string& version,
                                                  const std::string& room_id,
                                                  const std::string& session_id) const;
  void backup_delete_all_keys(const std::string& user_id, const std::string& version);
  void backup_delete_room_keys(const std::string& user_id, const std::string& version,
                              const std::string& room_id);
  void backup_delete_room_key(const std::string& user_id, const std::string& version,
                             const std::string& room_id, const std::string& session_id);

  // --- NEW in 4954df3c: transaction id deduplication ------------------------
  /// Device id associated with an access token (user+device lookup).
  std::optional<std::string> device_from_token(const std::string& token) const;
  /// Store the response bytes for a (user, device, txn_id) triple.
  void add_txnid(const std::string& user_id, const std::string& device_id,
                 const std::string& txn_id, const std::string& data);
  /// Retrieve previously stored response bytes, or nullopt if unseen.
  std::optional<std::string> existing_txnid(const std::string& user_id,
                                            const std::string& device_id,
                                            const std::string& txn_id) const;

  // --- NEW in df55e8ed: room upgrade ----------------------------------------
  /// Users that have ever joined this room (for predecessor carry-over).
  std::vector<std::string> room_useroncejoined(const std::string& room_id) const;
  bool once_joined(const std::string& user_id, const std::string& room_id) const;
  /// Current state event content for (type, state_key); nullopt if absent.
  std::optional<nlohmann::json> room_state_get(const std::string& room_id,
                                               const std::string& type,
                                               const std::string& state_key) const;
  bool is_public(const std::string& room_id) const;

  /// NEW in 821c608c: media repository access.
  void media_create(const std::string& mxc, const std::optional<std::string>& filename,
                    const std::string& content_type, const std::string& file);
  std::optional<database::Media::File> media_get(const std::string& mxc) const;
  // NEW in aa5e9e6: upload thumbnail with dimensions
  void media_upload_thumbnail(const std::string& mxc,
                              const std::optional<std::string>& filename,
                              const std::string& content_type,
                              uint32_t width, uint32_t height,
                              const std::string& file);
  // NEW: all pdus of one room with stream index > since.
  std::vector<std::string> pdus_since(const std::string& room_id,
                                      uint64_t since) const;

  // --- displayname (folded prerequisite + fa9e127a-era semantics) -------------
  std::optional<std::string> displayname_get(const std::string& user_id) const;
  /// Set a new displayname. NEW in 4cc0a070: required (not optional) and
  /// broadcasts an m.room.member join event carrying it to every joined room.
  bool displayname_set(const std::string& user_id, const std::string& displayname);
  void displayname_remove(const std::string& user_id);

  // --- NEW in abcce95d: invites & state ----------------------------------------
  // Current state events of a room, as raw canonical JSON strings.
  std::vector<std::string> room_state(const std::string& room_id) const;
  bool room_invite(const std::string& sender, const std::string& room_id,
                   const std::string& user_id);
  std::vector<std::string> rooms_invited(const std::string& user_id) const;

 private:
  explicit Data(const std::filesystem::path& dir, uint64_t cache_capacity);

  std::string hostname_;
  std::string keypair_;  // raw 32-byte Ed25519 seed
  sled::Db db_storage_;
  database::Database db_;
};
