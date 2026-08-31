# stepbystep — Conduit commit-by-commit in C++

Each directory is a standalone C++23 translation of one specific commit from
[`timokoesters/conduit`](https://github.com/timokoesters/conduit) — the origin
of the entire Conduit → conduwuit → tuwunel/continuwuty lineage. The
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

**Numbered steps (1-54):** All from 2020. Hard step numbers because these commits are stable and the user wants chronological correspondence to Conduit's 2020 development.

**Date-based steps (post-54):** Conduit commits from 2024+. Named `YYYY-MM-DD_HASH_description` so they can be sorted and re-ordered as Conduit evolves.

| Step | Conduit commit | Date | Message | Directory |
|---|---|---|---|---|
| 1 | `6264628c` | 2020-02-15 | Initial commit | `01_6264628c_initial_commit` |
| 2 | `cd777af4` | 2020-02-18 | feat: simple endpoint handlers | `02_cd777af4_simple_endpoint_handlers` |
| 3 | `c2c18b46` | 2020-02-20 | feat: database | `03_c2c18b46_database` |
| 4 | `34a53ce2` | 2020-03-28 | Better database structure | `04_34a53ce2_data_layer` |
| 5 | `533260ed` | 2020-03-29 | Add auth | `05_533260ed_auth` |
| 6 | `fa322689` | 2020-04-03 | feat: save pdus | `06_fa322689_save_pdus` |
| 7 | `abcce95d` | 2020-04-14 | feat: invites, better public room dir, user search | `07_abcce95d_invites_user_search` |
| 8 | `fa9e127a` | 2020-04-14 | Store hashed passwords (#7) | `08_fa9e127a_store_hashed_passwords` |
| 9 | `b0d9ccdb` | 2020-04-29 | Signing, basis for federation | `09_b0d9ccdb_signing` |
| 10 | `1af6dd98` | 2020-04-29 | More work on federation | `10_1af6dd98_federation_server` |
| 11 | `720cc0cf` | 2020-04-29 | feat: federated room directory | `11_720cc0cf_federated_directory` |
| 12 | `4cc0a070` | 2020-04-29 | feat: user renaming | `12_4cc0a070_user_renaming` |
| 13 | `23cb550d` | 2020-04-29 | forget rooms, load history | `13_23cb550d_forget_history` |
| 14 | `821c608c` | 2020-05-18 | feat: media | `14_821c608c_media` |
| 15 | `b106d139` | 2020-05-24 | Add logout route and database methods (#21) | `15_b106d139_logout` |
| 16 | `b6c0e9bf` | 2020-05-25 | feat: access control | `16_b6c0e9bf_access_control` |
| 17 | `18bf6774` | 2020-05-31 | feat: redaction | `17_18bf6774_redaction` |
| 18 | `3aa0c8ed` | 2020-05-31 | Merge pull request 'Room visibility, aliases and redaction' (#40) from alias into master | `18_3aa0c8ed_aliases_visibility` |
| 19 | `c85d363d` | 2020-06-08 | feat: user interactive authentication | `19_c85d363d_uiaa` |
| 20 | `b4d65ab6` | 2020-06-08 | improvement: optimize /sync response | `20_b4d65ab6_sync_optimize` |
| 21 | `7031240a` | 2020-06-16 | improvement: /members route | `21_7031240a_members` |
| 22 | `67a1f21f` | 2020-07-02 | feat: implement password changing (#138) | `22_67a1f21f_password_change` |
| 23 | `b8193984` | 2020-07-05 | feat: account deactivation (#137) | `23_b8193984_deactivate` |
| 24 | `469071e1` | 2020-07-11 | feat: implement /event (#144) | `24_469071e1_event_route` |
| 25 | `4954df3c` | 2020-08-25 | feat: handle txn ids | `25_4954df3c_txn_ids` |
| 26 | `3f4cb753` | 2020-08-27 | improvement: add remaining key backup endpoints | `26_3f4cb753_key_backup` |
| 27 | `df55e8ed` | 2020-08-31 | Add room upgrade. | `27_df55e8ed_room_upgrade` |
| 28 | `515465f9` | 2020-08-31 | fix: make element not show "unknown user" warning | `28_515465f9_profile_404` |
| 29 | `12a8c9ba` | 2020-09-12 | fix: join rooms over federation | `29_12a8c9ba_federation_join` |
| 30 | `1f292c09` | 2020-09-14 | improvement: better federation joins | `30_1f292c09_federation_send` |
| 31 | `c5313b3e` | 2020-09-14 | improvement: try out multiple servers when joining remote rooms | `31_c5313b3e_multi_server_join` |
| 32 | `4e44fedbc` | 2020-09-14 | fix: room list over federation | `32_4e44fedbc_fed_publicrooms` |
| 33 | `aa5e9e60` | 2020-09-14 | feat: download media and thumbnails over federation | `33_aa5e9e60_fed_media` |
| 34 | `9f05ef926` | 2020-09-14 | fix: filter public room dir | `34_9f05ef926_pubroom_filter` |
| 35 | `f7816b11d` | 2020-09-15 | feat: send messages over federation | `35_f7816b11d_fed_sendmsg` |
| 36 | `71500b14b` | 2020-09-15 | fix: send to all servers and fix media store | `36_71500b14b_fed_sendall` |
| 37 | `0b263208e` | 2020-09-15 | fix: don't panic on bad server names | `37_0b263208e_badname` |
| 38 | `b7ab57897` | 2020-09-15 | fix: sending slowness | `38_b7ab57897_sendslow` |
| 39 | `1bf614b0f` | 2020-09-15 | fix: remove transaction_id from pdus over federation | `39_1bf614b0f_notxn` |
| 40 | `005e00e9b` | 2020-09-15 | fix: remove well-known | `40_005e00e9b_nowellknown` |
| 41 | `dd749b8ae` | 2020-09-16 | fix: server keys and destination resolution when server name contains port | `41_dd749b8ae_srvport` |
| 42 | `f4078a29e` | 2020-09-16 | fix: synapse complains about missing origin | `42_f4078a29e_origin` |
| 43 | `a567cd81d` | 2020-09-16 | improvement: better logs on deserialization errors | `43_a567cd81d_logs` |
| 44 | `3e0378755` | 2020-09-16 | Add Complement dockerfile and move sytest dir | `44_3e0378755_ci` |
| 45 | `c4f5a0a6` | 2020-08-23 | Keep track of State at event for state resolution | `45_c4f5a0a6_keep_track_of_state` |
| 46 | `cb68bf9` | 2020-08-23 | Use ring crate to generate StatHashes when saving stateid/statehash | `46_cb68bf9_ring_stat_hashes` |
| 47 | `846a009` | 2020-08-23 | Split append_pdu -> append_pdu and build_and_append | `47_846a009_split_append_pdu` |
| 48 | `d73c6aa` | 2020-08-23 | Add roomid_statehash tree, clean up review issues | `48_d73c6aa_roomid_statehash` |
| 49 | `64fb037` | 2020-08-23 | Use Vec<u8> instead of string for digest bytes and add roomid_statehash | `49_64fb037_vec_u8_digest` |
| 50 | `ea20032` | 2020-08-23 | Helper for join_room_by_id route so routes aren't calling routes | `50_ea20032_join_room_helper` |
| 51 | `5ccdd36` | 2020-08-23 | Add helper function for get_alias route | `51_5ccdd36_get_alias_helper` |
| 52 | `fe795d3` | 2020-08-23 | Replace route calling routes with helpers | `52_fe795d3_route_helpers` |
| 53 | `672bf4f` | 2020-08-23 | Cargo lock update and a few doc additions | `53_672bf4f_cargo_lock` |
| 54 | `972babb` | 2020-08-23 | fix: set limited to true when skipping messages in /sync | `54_972babb_sync_limited` |
| tail | `63ba157ef6` | 2024-05-02 | feat(auth): check if X-Matrix destination is correct if present | `2024-05-02_63ba157ef6_xmatrix_dest` |
| tail | `9db1f5a13c` | 2024-05-02 | fix(admin): don't allow creation of remote users | `2024-05-02_9db1f5a13c_admin` |
| tail | `c1f695653` | 2024-05-02 | feat: support hosting .well-known from Conduit | `2024-05-02_c1f695653_wellknown_host` |
| tail | `d8badaf` | 2024-05-05 | fix(membership): always set reason & allow new events if reason changed | `2024-05-05_d8badaf_membership_reason` |
| tail | `965b6df83d` | 2024-05-06 | fix: make media response match spec | `2024-05-06_965b6df83d_media_contenttype` |
| tail | `a888c7cb16` | 2024-05-28 | OpenID routes | `2024-05-28_a888c7cb16_openid` |
| tail | `59d7674` | 2024-05-29 | fix: clarify that 3pids are currently unsupported | `2024-05-29_59d7674_threepid_unsupported` |
| tail | `1dbb3433e0` | 2024-06-03 | fix(media): use csp instead of modifying content-type | `2024-06-03_1dbb3433e0_media_csp` |
| tail | `144d548` | 2024-06-12 | fix: permission checks for aliases | `2024-06-12_144d548_alias_permissions` |
| tail | `423b092` | 2024-08-22 | use ruma content disposition type in place of string | `2024-08-22_423b092_media_content_disposition` |
| tail | `27d6d94355` | 2024-08-28 | feat: add support for authenticated media requests | `2024-08-28_27d6d94355_authenticated_media` |
| tail | `a6797ca0a2` | 2024-09-21 | fix: add missing msc3916 unstable feature in version response | `2024-09-21_a6797ca0a2_versions_msc3916` |
| tail | `65fe6b0` | 2024-09-25 | fix: Empty content dispositions could create problems | `2024-09-25_65fe6b0_empty_content_disposition` |
| tail | `30855ce` | 2025-02-04 | fix(media): return an error when content is failed to be parsed as an image | `2025-02-04_30855ce_thumbnail_parse_error` |
| tail | `21af83e` | 2025-03-03 | feat: knocking | `2025-03-03_21af83e_knocking` |
| tail | `42d8e88` | 2025-03-03 | Merge branch 'membership-refactor' into 'next' | `2025-03-03_42d8e88_keys_upload_validation` |
| tail | `4dc15a4` | 2025-03-08 | refactor: set send_request matrix versions in a single constant | `2025-03-08_4dc15a4_matrix_versions_constant` |
| tail | `dc5abd6` | 2025-03-08 | feat(appservice): pinging | `2025-03-08_dc5abd6_appservice_pinging` |
| tail | `3171b77` | 2025-05-06 | feat(media): save user id of uploader | `2025-05-06_3171b77_media_save_uploader` |
| tail | `66a14ac` | 2025-05-06 | feat: freeze unauthenticated media | `2025-05-06_66a14ac_freeze_unauthenticated_media` |
| tail | `70d7f77` | 2025-05-06 | feat(media): use file's sha256 for on-disk name & make directory configurable | `2025-05-06_70d7f77_media_sha256_ondisk` |
| tail | `594fe5f` | 2025-05-07 | feat(media): blocking | `2025-05-07_594fe5f_media_blocking` |
| tail | `a189b66` | 2025-05-07 | feat(admin): show media command | `2025-05-07_a189b66_admin_show_media` |
| tail | `c3fb1b0` | 2025-05-07 | feat(media): retention policies | `2025-05-07_c3fb1b0_media_retention` |
| tail | `d766370` | 2025-05-07 | feat(admin): commands for purging media | `2025-05-07_d766370_media_purge` |
| tail | `fd16e9c` | 2025-05-07 | feat(admin): list & query information about media | `2025-05-07_fd16e9c_admin_media_info` |
| tail | `1fc82477c5` | 2025-05-12 | chore(/versions): declare support for matrix <= v1.12 | `2025-05-12_1fc82477c5_versions_v112` |
| tail | `09e1713` | 2025-06-06 | feat(devices): update the device last seen timestamp on usage | `2025-06-06_09e1713_device_last_seen` |
| tail | `3248efbe4b` | 2025-06-22 | fix(registration): enforce the strict user ID grammar | `2025-06-22_3248efbe4b_register_grammar` |
| tail | `a87f4b6171` | 2025-07-04 | fix: Respond with HTTP code 413, when request size is too big | `2025-07-04_a87f4b6171_req_size_413` |
| tail | `b5e3185` | 2025-08-10 | feat: MSC4289, Explicitly privilege room creators (1/2) | `2025-08-10_b5e3185_msc4289_creator_privilege` |
| tail | `f6d14fd` | 2025-08-10 | feat: MSC4291, Room IDs as hashes of the create event (1/2) | `2025-08-10_f6d14fd_msc4291_room_id_hash` |
| tail | `532b17a` | 2025-08-11 | feat: MSC4311, Ensuring the create event is available on invites and knocks | `2025-08-11_532b17a_msc4311_create_event_invites` |
| tail | `660dd9c` | 2025-08-11 | feat: room version 12 | `2025-08-11_660dd9c_room_version_12` |
| tail | `bc5145f092` | 2025-08-11 | feat(client-api): support `format` query parameter for `GET /state/` | `2025-08-11_bc5145f092_state_format` |
| tail | `bd8686e` | 2025-08-11 | feat: MSC4291, Room IDs as hashes of the create event (2/2) | `2025-08-11_bd8686e_msc4291_room_id_hash_2` |
| tail | `d71d94a` | 2025-08-11 | feat: MSC4297, State Resolution v2.1 | `2025-08-11_d71d94a_msc4297_state_res_v2` |
| tail | `03dfa72` | 2025-08-16 | fix: don't lookup create event when converting stripped state | `2025-08-16_03dfa72_fix_stripped_state` |
| tail | `1f7f74a` | 2025-08-28 | fix(service/media): create directory for media file only on new file creation | `2025-08-28_1f7f74a_media_dir_creation` |
| tail | `470e477` | 2025-08-28 | refactor(service/admin): improve readability for command processing | `2025-08-28_470e477_admin_refactor` |
| tail | `5f3bda8` | 2025-08-28 | refactor(service/media): make all fs operations async | `2025-08-28_5f3bda8_media_async_fs` |
| tail | `6d22701` | 2025-08-28 | feat(service/media): add S3 support | `2025-08-28_6d22701_media_s3_support` |
| tail | `1c6b2e0` | 2025-09-12 | feat: updated MSC4311 support | `2025-09-12_1c6b2e0_msc4311_updated` |
| tail | `e757a98` | 2025-09-12 | fix: set previous creators to max power level if "upgraded" room doesn't support creator power level | `2025-09-12_e757a98_upgrade_creator_power` |
| tail | `3db42bd` | 2025-12-22 | fix: use append_member_pdu for `/invite` | `2025-12-22_3db42bd_federation_invite_refactor` |
| tail | `346913268f` | 2025-12-30 | fix: don't ignore content of membership template | `2025-12-30_346913268f_membership_template_content` |
| tail | `82b7cf6261` | 2025-12-30 | fix: use populate_membership_template for `/leave` | `2025-12-30_82b7cf6261_leave_template` |
| tail | `98e2bed` | 2026-01-22 | fix: don't perform identity assertion on appservice-only endpoints | `2026-01-22_98e2bed_appservice_auth_fix` |
| tail | `d058dab` | 2026-02-12 | feat: add option to ignore specific server signing keys | `2026-02-12_d058dab_ignored_signing_keys` |
| tail | `8def22bfb8` | 2026-03-05 | feat: Add user agent string | `2026-03-05_8def22bfb8_fed_user_agent` |
| tail | `11a9d053b0` | 2026-07-17 | feat: rate-limiting | `2026-07-17_11a9d053b0_rate_limiting` |
| tail | `422bd24` | 2026-07-17 | refactor: move configuration to it's own crate | `2026-07-17_422bd24_config_refactor` |
| tail | `47216ee` | 2026-07-17 | feat: make IP address detection method configurable | `2026-07-17_47216ee_ip_detection` |
| tail | `08366bf` | 2026-08-26 | fix: only allow request to pass auth with token query if auth type is None | `2026-08-26_08366bf_auth_token_query` |

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

## Skipped upstream commits

- All `Cargo.toml`/`Cargo.lock` dependency bumps
- All `chore:` / `ci:` / `docs:` / `refactor:` / `perf:` / `style:` commits
- All Merge commits
- `Revert` commits where the reverted feature was never implemented (MSC3575 sliding sync)
- Rust 2024 edition / rust 1.88 / virtual workspace migration
- S3 / media_storage infrastructure
- Systemd lockdown, Docker tag, cross-target-triple, Nix flake, mdbook additions

## Naming scheme

- **Numbered steps (1-54)**: `NN_HASH_description/` where NN is sequential
- **Date-based steps (post-54)**: `YYYY-MM-DD_HASH_description/` for Conduit commits from 2024+

The boundary: anything from 2020 in numbered (in chronological order),
anything from 2021+ in date-based tail (in date order).