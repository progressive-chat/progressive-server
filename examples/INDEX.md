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

Skipped upstream commits (nothing or too little to translate):

- `6fffcecf` 2020-03-27 "Updates" — Cargo.lock dependency bump only
- `1679da77` / `6d27f155` 2020-03-27/28 — logging defaults/tracing only
- `744e0adf` 2020-03-28 "Try to impl auth in ruma_wrapper" — WIP superseded by step 5
- `1183105f`, `18ed991b` 2020-03-29 — trait plumbing / merge commit
- `dba6c466`, `b508b4d1`, `22cca206` 2020-03-30 — prefix_search refactor,
  todo!() stubs; folded into steps 5/6
- Apr 3–10 dummies (`f9cfede2`…`040296c7`) — async migration, PduEvent struct,
  dummy endpoints for Riot compatibility
- Candidates for a future step 7: `abcce95d` invites/user search (Apr 14),
  `fa9e127a` hashed passwords (Apr 14)

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
