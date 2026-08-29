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
  const std::string& admin_alias() const;  // NEW in 144d548: #admins:<server>

  // NEW in c1f69565: host /.well-known/matrix/{client,server} from Conduit.
  // Optional overrides mirror conduit.toml [global.well_known]; when unset we
  // fall back to the sane Conduit defaults (https://<host> and <host>:443).
  void set_well_known_client(const std::string& v);
  void set_well_known_server(const std::string& v);
  std::string well_known_client() const;
  std::string well_known_server() const;
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
  /// NEW in a888c7cb16: OpenID — mint an OpenID access token for `user_id` and
  /// persist it (token -> expires_at + user_id). Returns (token, expires_in_secs).
  std::pair<std::string, uint64_t> create_openid_token(const std::string& user_id);
  /// Reverse lookup: which user (if any, and unexpired) owns an OpenID token.
  std::optional<std::string> find_from_openid_token(const std::string& token);
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
  bool room_leave(const std::string& room_id, const std::string& user_id,
                 const std::string& reason = "");
  void room_forget(const std::string& room_id, const std::string& user_id);
  size_t room_users(const std::string& room_id) const;
  std::vector<std::string> rooms_joined(const std::string& user_id) const;

  // --- NEW in d8badaf: membership reason-aware kick/ban/unban ----------------
  /// Kick `target` (set membership=leave). No-op if already left with the same
  /// reason. Mirrors Conduit's kick_user_route.
  bool room_kick(const std::string& sender, const std::string& room_id,
                 const std::string& target, const std::string& reason = "");
  /// Ban `target` (set membership=ban), preserving displayname/avatar/blurhash.
  /// No-op if already banned with the same reason. Mirrors ban_user_route.
  bool room_ban(const std::string& sender, const std::string& room_id,
                const std::string& target, const std::string& reason = "");
  /// Unban `target` (set membership=leave). No-op if already left with the same
  /// reason. Mirrors unban_user_route.
  bool room_unban(const std::string& sender, const std::string& room_id,
                  const std::string& target, const std::string& reason = "");
  /// Full stored m.room.member content for (room, user), or nullopt.
  std::optional<nlohmann::json> get_member_content(const std::string& room_id,
                                                  const std::string& user_id) const;

  // --- PDU graph --------------------------------------------------------------
  std::optional<std::string> pdu_get(const std::string& event_id) const;
  /// NEW in 18bf6774: replace a PDU with its redacted form.
  void redact_pdu(const std::string& event_id);
  std::vector<std::string> pdu_leaves_replace(const std::string& room_id,
                                              const std::string& event_id);
  /// b6c0e9bf: returns false (and stores nothing) when unauthorized.
  bool pdu_append(const std::string& event_id, const std::string& room_id,
                  nlohmann::json event);
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
  /// NEW in f7816b11d: participating servers of a room (federation).
  void add_room_server(const std::string& room_id, const std::string& server);
  std::vector<std::string> room_servers(const std::string& room_id) const;

  // --- NEW in 12a8c9ba: federation (server-side PDU serving) -----------------
  /// Current full state of a room as a list of PDU JSON objects.
  std::vector<nlohmann::json> federation_full_state(const std::string& room_id) const;
  /// Transitive auth-chain PDUs for the given (seed) event ids.
  std::vector<nlohmann::json> federation_auth_chain(
      const std::string& room_id, const std::vector<std::string>& event_ids) const;
  /// All PDUs of a room (used by /backfill), as JSON objects.
  std::vector<nlohmann::json> federation_pdus_of_room(const std::string& room_id) const;

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
  std::vector<std::string> room_state_type(const std::string& room_id,
                                           const std::string& type) const;

  // --- NEW in 3aa0c8ed (+ 9c26e22a): aliases & visibility ----------------------
  void set_alias(const std::string& alias, const std::string& room_id,
                 const std::string& user_id);
  void remove_alias(const std::string& alias,
                    [[maybe_unused]] const std::string& user_id);
  std::optional<std::string> id_from_alias(const std::string& alias) const;
  std::optional<std::string> who_created_alias(const std::string& alias) const;
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
  // NEW: all pdus of one room with stream index > since.
  std::vector<std::string> pdus_since(const std::string& room_id,
                                      uint64_t since) const;

  // --- displayname (folded prerequisite + fa9e127a-era semantics) -------------
  std::optional<std::string> displayname_get(const std::string& user_id) const;
  /// Set a new displayname. NEW in 4cc0a070: required (not optional) and
  /// broadcasts an m.room.member join event carrying it to every joined room.
  bool displayname_set(const std::string& user_id, const std::string& displayname);
  void displayname_remove(const std::string& user_id);

  // --- admin (9db1f5a13c-era) -------------------------------------------------
  void admin_add(const std::string& user_id);
  bool user_is_admin(const std::string& user_id) const;

  // --- NEW in abcce95d: invites & state ----------------------------------------
  // Current state events of a room, as raw canonical JSON strings.
  std::vector<std::string> room_state(const std::string& room_id) const;
  bool room_invite(const std::string& sender, const std::string& room_id,
                    const std::string& user_id, const std::string& reason = "");
  // NEW in 21af83e: a local user knocks on a room (membership "knock" state
  // event); an admin can later resolve it by inviting the user.
  bool room_knock(const std::string& room_id, const std::string& user_id,
                  const std::string& reason = "");
  std::vector<std::string> rooms_invited(const std::string& user_id) const;

 private:
  explicit Data(const std::filesystem::path& dir);

  std::string hostname_;
  std::string admin_alias_;  // NEW in 144d548: #admins:<server>
  std::string well_known_client_override_;
  std::string well_known_server_override_;
  std::string keypair_;  // raw 32-byte Ed25519 seed
  sled::Db db_storage_;
  database::Database db_;
};
