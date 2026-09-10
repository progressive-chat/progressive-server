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
#include "proxy.hpp"

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
  // NEW in 9d4fa9a2: cache_capacity (bytes, 1GB default) is replaced by
  // db_cache_capacity_mb (200MB default, wired to the RocksDB block cache).
  static Data load_or_create(const std::filesystem::path& dir,
                             double db_cache_capacity_mb = 200.0);

  void set_hostname(const std::string& hostname);
  const std::string& hostname() const;
  /// NEW in b0d9ccdb: raw Ed25519 seed, generated on first boot and persisted
  /// in the database root (utils::generate_keypair + update_and_fetch).
  const std::string& keypair() const;
  // NEW in b2d55160: arbitrary proxy support (upstream Config::proxy).
  // Default None (direct); set from --proxy / CONDUIT_PROXY. Held in memory
  // only (like other runtime globals), not persisted in the database.
  void set_proxy_config(proxy::ProxyConfig cfg) { proxy_config_ = std::move(cfg); }
  const proxy::ProxyConfig& proxy_config() const { return proxy_config_; }
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
  /// NEW in 71ed1b29: devicelist version (stream_id for federation
  /// /user/devices), bumped on device add/remove. Nullopt = never changed.
  std::optional<uint64_t> get_devicelist_version(const std::string& user_id) const;

  // --- membership (folded prerequisite) --------------------------------------
  /// b6c0e9bf: appends the join member event; trees updated post-auth.
  bool room_join(const std::string& room_id, const std::string& user_id);
  /// NEW in 23cb550d (folded leave flow): leave + forget.
  bool room_leave(const std::string& room_id, const std::string& user_id);
  void room_forget(const std::string& room_id, const std::string& user_id);
  size_t room_users(const std::string& room_id) const;
  std::vector<std::string> rooms_joined(const std::string& user_id) const;
  /// NEW in 2479389: rooms both users have joined (upstream get_shared_rooms).
  std::vector<std::string> shared_rooms(const std::string& user_a,
                                        const std::string& user_b) const;

  // --- NEW in 2479389: presence ----------------------------------------------
  /// Store the latest presence event for (user, room). Upstream keeps a
  /// count-stamped history plus a per-user last-update timestamp; this port
  /// keeps the single latest event, which is all GET /presence reads.
  void update_presence(const std::string& user_id, const std::string& room_id,
                       const nlohmann::json& presence);
  /// Latest stored presence event for (user, room), if any.
  std::optional<nlohmann::json> get_last_presence_event(
      const std::string& user_id, const std::string& room_id) const;

  // --- PDU graph --------------------------------------------------------------
  std::optional<std::string> pdu_get(const std::string& event_id) const;
  /// NEW in 18bf6774: replace a PDU with its redacted form.
  /// NEW in ddcf1a71: unsigned.redacted_because is the redaction event as a
  /// JSON *object* (upstream fixed it being emitted as a JSON-encoded string).
  void redact_pdu(const std::string& event_id,
                  const std::optional<nlohmann::json>& redaction_event = std::nullopt);
  std::vector<std::string> pdu_leaves_replace(const std::string& room_id,
                                               const std::string& event_id);
  // NEW in 58463bba: read-only current leaves (prev_events source for the
  // outgoing remote-invite PDU, which must not disturb the leaf set).
  std::vector<std::string> pdu_leaves(const std::string& room_id) const;
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
                         const std::string& membership,
                         const std::optional<nlohmann::json>& invite_state = std::nullopt);
  // NEW in 7fa54e44: shared default power levels (upstream ruma
  // PowerLevelsEventContent::default(): ban/invite/kick/redact 50, zeros
  // elsewhere, events:{}, notifications:{room:50}); creator gets 100 when set.
  static nlohmann::json default_power_levels(const std::string& creator);

  /// NEW in c85d363d: UIAA session storage passthrough. The user id here is
  /// "@pending:<session>" until registration completes (upstream keyed by the
  /// parsed UserId; we key by pending-session since registration has no user yet).
  void uiaa_create(const std::string& key_user, const std::string& device,
                   const std::string& session, const nlohmann::json& uiaainfo) {
    db_.uiaa.create(key_user, device, session, uiaainfo);
  }

  /// NEW in 7031240a: all state events of one type in a room.
  std::vector<std::string> room_state_type(const std::string& room_id,
                                           const std::string& type) const;

  // --- NEW in 3aa0c8ed (+ 9c26e22a): aliases & visibility ----------------------
  void set_alias(const std::string& alias, const std::string& room_id);
  void remove_alias(const std::string& alias);
  std::optional<std::string> id_from_alias(const std::string& alias) const;
  std::vector<std::string> room_aliases(const std::string& room_id) const;
  void set_public(const std::string& room_id, bool is_public);
  /// All rooms marked public (3aa0c8ed).
  std::vector<std::string> public_rooms() const;
  // NEW in 3c3062a3: single public-room directory chunk built from targeted
  // state lookups (no full-state scan): canonical_alias/name/topic,
  // num_joined_members, world_readable (history_visibility), guest_can_join
  // (guest_access), avatar_url.
  nlohmann::json public_room_chunk(const std::string& room_id) const;

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

  // NEW in e50f2864: save state for send_join pdu
  /// Save the current room state for a PDU and return the state hash ID
  std::optional<std::string> append_to_state(const std::string& room_id,
                                             const nlohmann::json& event);
  /// Set the room's current state hash
  void set_room_state(const std::string& room_id, const std::string& state_hash);

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
  // NEW in 58463bba: invite content carries the target's displayname and the
  // is_direct flag (upstream MemberEventContent); avatar_url omitted (no
  // avatar store in C++ yet).
  bool room_invite(const std::string& sender, const std::string& room_id,
                   const std::string& user_id, bool is_direct = false);
  std::vector<std::string> rooms_invited(const std::string& user_id) const;

  // --- NEW in 8773e501: incoming invites over federation ----------------------
  // Invite state (stripped state events) stored per (user, room), plus a
  // per-(room, user) invite count used for sync filtering
  // (`if since >= invite_count { skip }`). rooms_invited_with_state mirrors
  // upstream `rooms_invited() -> (RoomId, Vec<Raw<AnyStrippedStateEvent>>)`.
  std::vector<std::pair<std::string, nlohmann::json>> rooms_invited_with_state(
      const std::string& user_id) const;
  std::optional<uint64_t> get_invite_count(const std::string& room_id,
                                            const std::string& user_id) const;
  // NEW in bc98425d: raw stored invite_state for (user, room), used as a hint
  // for which servers to ask when joining (upstream Rooms::invite_state).
  std::optional<nlohmann::json> invite_state(const std::string& user_id,
                                              const std::string& room_id) const;
  /// Server names hinted by an invite_state's event senders (@user:server).
  static std::vector<std::string> invite_state_servers(const nlohmann::json& state);
  /// Build invite_state from current room state (create, join_rules,
  /// canonical_alias, avatar, name) as stripped events, like upstream
  /// update_membership does.
  nlohmann::json build_invite_state(const std::string& room_id) const;
  /// Store an invite with explicit invite_state (federation or local).
  void store_invite(const std::string& room_id, const std::string& user_id,
                    const nlohmann::json& invite_state);
  /// Handle an incoming federation invite: validate, sign, store. Returns the
  /// signed event to return to the sender, or nullopt + errcode/error on failure.
  struct InviteResult {
    bool ok = false;
    nlohmann::json event;  // signed event on success
    std::string errcode;   // on failure
    std::string error;     // on failure
  };
  InviteResult handle_incoming_invite(const std::string& room_id,
                                      nlohmann::json event,
                                      nlohmann::json invite_room_state);

  // --- NEW in 662a0cf1: efficient notification/highlight counts -------------
  // Bumped on PDU append per push-rule evaluation, reset on read, served by
  // sync as unread_notifications (replaces scanning PDUs since last read).
  uint64_t notification_count(const std::string& user_id,
                              const std::string& room_id) const;
  uint64_t highlight_count(const std::string& user_id,
                           const std::string& room_id) const;
  void reset_notification_counts(const std::string& user_id,
                                 const std::string& room_id);

  // --- NEW in 6da4022: signing keys -------------------------------------------
  struct VerifyKey {
      std::string key;  // base64 encoded
  };
  struct ServerSigningKeys {
      std::map<std::string, VerifyKey> verify_keys;
  };
  /// Get signing keys for a server (cached or fetched)
  std::map<std::string, std::string> get_signing_keys(const std::string& server_name) const;
  /// Add signing keys for a server to cache
  void add_signing_key(const std::string& server_name, const ServerSigningKeys& keys);

  // --- NEW in 6da4022: forward extremities ------------------------------------
  /// Get forward extremities for a room
  std::vector<std::string> get_forward_extremities(const std::string& room_id) const;
  /// Set forward extremities for a room
  void set_forward_extremities(const std::string& room_id, const std::vector<std::string>& extremities);

  // --- NEW in a77fcd1: state_ids federation endpoint -------------------------
  /// Get shortstatehash for an event ID
  std::optional<uint64_t> pdu_shortstatehash(const std::string& event_id) const;
  /// Get all state event IDs for a shortstatehash
  std::vector<std::string> state_full_ids(uint64_t shortstatehash) const;

  // --- NEW in fe744c85: push rules -----------------------------------------
  /// Set push rules for a user
  void set_push_rules(const std::string& user_id, const nlohmann::json& rules);
  /// Get push rules for a user
  std::optional<nlohmann::json> get_push_rules(const std::string& user_id) const;

  /// Add a pusher for a user
  void add_pusher(const std::string& user_id, const std::string& pusher_id, const nlohmann::json& pusher);
  /// Get a pusher for a user
  std::optional<nlohmann::json> get_pusher(const std::string& user_id, const std::string& pusher_id) const;
  /// Get all pushers for a user
  std::vector<std::pair<std::string, nlohmann::json>> get_pushers(const std::string& user_id) const;
  /// Remove a pusher
  void remove_pusher(const std::string& user_id, const std::string& pusher_id);

  // --- NEW in e50f2864: room account data ---------------------------------
  /// Set room account data for a user
  void set_room_account_data(const std::string& room_id, const std::string& user_id,
                             const std::string& type, const nlohmann::json& data);
  /// Get room account data for a user
  std::optional<nlohmann::json> get_room_account_data(const std::string& room_id,
                                                      const std::string& user_id,
                                                      const std::string& type) const;

 private:
  explicit Data(const std::filesystem::path& dir, double db_cache_capacity_mb);

  std::string hostname_;
  std::string keypair_;  // raw 32-byte Ed25519 seed
  proxy::ProxyConfig proxy_config_;  // NEW in b2d55160 (default: None)
  sled::Db db_storage_;
  database::Database db_;
};
