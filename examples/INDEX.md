# stepbystep — Conduit commit-by-commit in C++

Each directory is a standalone C++23 translation of one specific commit from
[`timokoesters/conduit`](https://github.com/timokoesters/conduit) — the origin
of the entire Conduit → conduwuit → tuwunel/continuwuity lineage. The
directory name binds the step number to the source SHA so you always know what
happened when.

| Step | Conduit commit | Date | Message | Directory |
|---|---|---|---|---|
| 1 | `6264628c` | 2020-02-15 | Initial commit | `01_6264628c_initial_commit` |
| 2 | `cd777af4` | 2020-02-18 | feat: simple endpoint handlers | `02_cd777af4_simple_endpoint_handlers` |
| 3 | `c2c18b46` | 2020-02-20 | feat: database (sled, plaintext passwords, login) | `03_c2c18b46_database` |
| 4 | `34a53ce2` | 2020-03-28 | Better database structure (Data layer, hostname) | `04_34a53ce2_data_layer` |

Skipped upstream commits (nothing or too little to translate):

- `6fffcecf` 2020-03-27 "Updates" — Cargo.lock dependency bump only
- `1679da77` 2020-03-27 "RUST_LOG=info by default" — logging default
- `6d27f155` 2020-03-28 "More logging" — tracing only
- `744e0adf` 2020-03-28 "Try to impl auth in ruma_wrapper" — WIP, superseded
- `1183105f`, `18ed991b` 2020-03-29 — trait plumbing / merge commit

Every directory builds independently:

```console
$ cd <dir>
$ g++ -std=c++23 -Wall -Wextra *.cpp -o server   # or cmake -B build -S . && cmake --build build
```
