# stepbystep — Conduit commit-by-commit in C++

Each directory is a standalone C++23 translation of one specific commit from
[`timokoesters/conduit`](https://github.com/timokoesters/conduit) — the origin
of the entire Conduit → conduwuit → tuwunel/continuwuity lineage. The
directory name binds the step number to the source SHA so you always know what
happened when.

## Translation table (this is NOT a zero-dependency project)

The goal is a *full C++ project* using real equivalents of everything upstream
used:

| Upstream (Rust) | This project (C++) | Since step |
|---|---|---|
| [Rocket](https://rocket.rs) web framework | [cpp-httplib](https://github.com/yhirose/cpp-httplib) | 1 |
| [serde_json](https://serde.rs) + `serde::Serialize` derive | [nlohmann/json](https://github.com/nlohmann/json) (sorted keys ⇒ canonical dumps) | 1 |
| [sled](https://github.com/spacejam/sled) embedded KV store | **RocksDB** column families behind a thin `src/sled.hpp` adapter (sled's API; RocksDB is what conduwuit migrated to and tuwunel ships) | 3 |
| ruma-client-api types | hand-written structs in `src/ruma_wrapper.*` (same as upstream's pre-ruma-split layout) | 1 |
| `ruma_signatures::reference_hash` | OpenSSL SHA-256 + hand-written redaction/base64url (`src/crypto.*`) | 6 |
| argon2 crate (PHC) | **libargon2** compiled from source (`argon2id_hash_encoded` / `argon2id_verify`) | 7 |

Dependencies are pulled by CMake FetchContent, same style as the parent
project. If `find_package(RocksDB)` succeeds on your system, no RocksDB build
is needed.

## Timeline

| Step | Conduit commit | Date | Message | Directory |
|---|---|---|---|---|
| 1 | `6264628c` | 2020-02-15 | Initial commit | `01_6264628c_initial_commit` |
| 2 | `cd777af4` | 2020-02-18 | feat: simple endpoint handlers | `02_cd777af4_simple_endpoint_handlers` |
| 3 | `c2c18b46` | 2020-02-20 | feat: database (sled→RocksDB, plaintext passwords, login) | `03_c2c18b46_database` |
| 4 | `34a53ce2` | 2020-03-28 | Better database structure (`data.rs`, hostname) | `04_34a53ce2_data_layer` |
| 5 | `533260ed` | 2020-03-29 | Add auth (four-tree model, tokens, password check) | `05_533260ed_auth` |
| 6 | `fa322689` | 2020-04-03 | feat: save pdus (event DAG, reference-hash event ids) | `06_fa322689_save_pdus` |
| 7 | `fa9e127a` | 2020-04-14 | Store hashed passwords (Argon2id + integration tests) | `07_fa9e127a_store_hashed_passwords` |
| 8 | `abcce95d` | 2020-04-14 | Invites, room state tree, public directory, user search | `08_abcce95d_invites_user_search` |
| 9 | `b0d9ccdb` | 2020-04-22 | Signing, basis for federation (Ed25519, X-Matrix) | `09_b0d9ccdb_signing` |
| 10 | `1af6dd98` | 2020-04-22 | Federation server identity (well-known, version, signed key doc) | `10_1af6dd98_federation_server` |
| 11 | `720cc0cf` | 2020-04-25 | Federated room directory (content-key signing, port 8448) | `11_720cc0cf_federated_directory` |
| 12 | `4cc0a070` | 2020-04-26 | User renaming (displayname broadcast, unsigned.prev_content) | `12_4cc0a070_user_renaming` |
| 13 | `23cb550d` | 2020-04-28 | Forget rooms, load history (/messages back-pagination) | `13_23cb550d_forget_history` |
| 14 | `821c608c` | 2020-05-18 | feat: media (mxc upload/download/thumbnails) | `14_821c608c_media` |
| 15 | `b106d139` | 2020-05-24 | Add logout route (remove_device invalidates tokens) | `15_b106d139_logout` |
| 16 | `b6c0e9bf` | 2020-05-24 | Access control (auth rules, power levels, membership matrix) | `16_b6c0e9bf_access_control` |
| 17 | `c85d363d` | 2020-06-06 | User-interactive authentication (UIAA sessions) | `17_c85d363d_uiaa` |
| 18 | `b4d65ab6` | 2020-06-06 | Optimize /sync (skip empty rooms, limited flag, incremental) | `18_b4d65ab6_sync_optimize` |
| 19 | `7031240a` | 2020-06-14 | /members route with membership enforcement | `19_7031240a_members` |
| 20 | `67a1f21f` | 2020-07-02 | Password changing (UIAA + logout others) | `20_67a1f21f_password_change` |
| 21 | `b8193984` | 2020-07-05 | Account deactivation (empty-hash marker) | `21_b8193984_deactivate` |
| 22 | `469071e1` | 2020-07-11 | GET /event/<id> route with membership check | `22_469071e1_event_route` |
| 23 | `18bf6774` | 2020-05-26 | feat: redaction (m.room.redaction + PDU stripping) | `23_18bf6774_redaction` |
| 24 | `3aa0c8ed` | 2020-05-26 | room aliases + visibility (incl. 9c26e22a, 4e507ef7) | `24_3aa0c8ed_aliases_visibility` |
| 25 | `df55e8ed` | 2020-08-06 | room upgrade (tombstone, predecessor, copy state/aliases) | `25_df55e8ed_room_upgrade` |
| 26 | `4954df3c` | 2020-08-25 | handle transaction ids (txn dedup on /send) | `26_4954df3c_txn_ids` |
| 27 | `3f4cb753` | 2020-08-27 | key backup store (folded base create/add/get + remaining endpoints: delete version/keys, per-room/session get/delete) | `27_3f4cb753_key_backup` |
| 28 | `515465f9` | 2020-08-31 | GET /profile/{user_id} returns 404 (M_NOT_FOUND) when the user does not exist | `28_515465f9_profile_404` |
| 29 | `12a8c9ba` | 2020-09-12 | federation: serve room PDUs to peers + attempt remote joins (send_join/state_ids/event/backfill/query/directory) | `29_12a8c9ba_federation_join` |
| 30 | `1f292c09` | 2020-09-12 | federation /send transaction endpoint: append delivered PDUs only if the room exists locally | `30_1f292c09_federation_send` |
| 31 | `c5313b3e` | 2020-09-14 | federation join: try each candidate server until one answers send_join | `31_c5313b3e_multi_server_join` |
| 32 | `4e44fedbc` | 2020-09-14 | federation /publicRooms endpoint: serve our public rooms to peers | `32_4e44fedbc_fed_publicrooms` |
| 33 | `aa5e9e607` | 2020-09-14 | federation media: serve media/thumbnails to peers (download/thumbnail) | `33_aa5e9e60_fed_media` |
| 34 | `9f05ef926` | 2020-09-14 | public-room directory honours filter.generic_search_term (client + federation) | `34_9f05ef926_pubroom_filter` |
| 35 | `f7816b11d` | 2020-09-14 | federation: track room servers (roomserverids) + best-effort PDU delivery to remotes | `35_f7816b11d_fed_sendmsg` |
| 36 | `71500b14b` | 2020-09-15 | fix: send to all servers (done in #35) + media store `allow_remote` guard | `36_71500b14b_fed_sendall` |
| 37 | `0b263208e` | 2020-09-15 | fix: don't panic on bad server names (validate federation destination) | `37_0b263208e_badname` |
| 38 | `b7ab57897` | 2020-09-15 | fix: sending slowness — hand PDU federation delivery to a detached background thread | `38_b7ab57897_sendslow` |
| 39 | `1bf614b0f` | 2020-09-15 | fix: strip unsigned.transaction_id from PDUs sent over federation | `39_1bf614b0f_notxn` |
| 40 | `005e00e9b` | 2020-09-15 | fix: remove well-known — no-op here (our /.well-known returns dynamic server name) | `40_005e00e9b_nowellknown` |
| 41 | `dd749b8ae` | 2020-09-15 | fix: server-name-with-port destination resolution in federation send | `41_dd749b8ae_srvport` |
| 42 | `f4078a29e` | 2020-09-16 | fix: add `origin` to PDUs sent over federation (synapse interop) | `42_f4078a29e_origin` |
| 43 | `a567cd81d` | 2020-09-16 | improvement: better logs on federation deserialization errors | `43_a567cd81d_logs` |
| 44 | `3e0378755` | 2020-09-16 | Add Complement dockerfile / move sytest dir — CI only, no server change | `44_3e0378755_ci` |
| 45 | `c1f695653` | 2024-05-02 | feat: support hosting .well-known from Conduit (client + server discovery, default host:443) | `45_c1f695653_wellknown_host` |
| 46 | `63ba157ef6` | 2024-05-02 | feat(auth): check if X-Matrix destination is correct if present | `46_63ba157ef6_xmatrix_dest` |
| 47 | `965b6df83d` | 2024-05-02 | fix: make media response match spec (normalise Content-Type to octet-stream, sanitise thumbnails) | `47_965b6df83d_media_contenttype` |
| 48 | `1dbb3433e0` | 2024-06-03 | fix(media): use CSP instead of modifying content-type (revert 965b6df83, add global Content-Security-Policy header) | `48_1dbb3433e0_media_csp` |
| 49 | `27d6d94355` | 2024-08-24 | feat: add support for authenticated media requests (MSC3916 client v1 media endpoints, auth-gated) | `49_27d6d94355_authenticated_media` |
| 50 | `a6797ca0a2` | 2024-09-21 | fix: add missing msc3916 unstable feature in version response | `50_a6797ca0a2_versions_msc3916` |
| 51 | `1fc82477c5` | 2025-05-12 | chore(/versions): declare support for matrix <= v1.12 | `51_1fc82477c5_versions_v112` |
| 52 | `3248efbe4b` | 2025-06-22 | fix(registration): enforce the strict user ID grammar | `52_3248efbe4b_register_grammar` |
| 53 | `a87f4b6171` | 2025-07-04 | fix: respond with HTTP 413 when request size is too big | `53_a87f4b6171_req_size_413` |

Skipped upstream commits (nothing or too little to translate):

- `6fffcecf` 2020-03-27 "Updates" — Cargo.lock dependency bump only
- `1679da77` / `6d27f155` 2020-03-27/28 — logging defaults/tracing only
- `744e0adf` 2020-03-28 "Try to impl auth in ruma_wrapper" — WIP superseded by step 5
- `1183105f`, `18ed991b` 2020-03-29 — trait plumbing / merge commit
- `dba6c466`, `b508b4d1`, `22cca206` 2020-03-30 — prefix_search refactor,
  todo!() stubs; folded into steps 5/6
- Apr 3–10 dummies (`f9cfede2`…`040296c7`) — async migration, PduEvent struct,
  dummy endpoints for Riot compatibility
- Candidates beyond: typing/receipts EDUs (`3debb620`, `3b9cadee`), profile endpoints (`062c5521`)

## Source file ↔ upstream file mapping

Each directory mirrors the files present in upstream at that commit:

```
Cargo.toml            <-> CMakeLists.txt
src/main.rs           <-> src/main.cpp
src/ruma_wrapper.rs   <-> src/ruma_wrapper.{hpp,cpp}
src/data.rs           <-> src/data.{hpp,cpp}          (step 4+)
src/utils.rs          <-> src/utils.{hpp,cpp}         (step 5+)
src/database.rs       <-> src/database.{hpp,cpp}      (step 6+)
(sled crate)          <-> src/sled.{hpp,cpp}          (steps 3+, adapter)
(ruma_signatures)     <-> src/crypto.{hpp,cpp}        (step 6, adapter)
```

Every directory builds independently:

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server
```
