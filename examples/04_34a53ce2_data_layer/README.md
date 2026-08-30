# Step 4 — "Better database structure" (Conduit `34a53ce2`)

Source: [`timokoesters/conduit@34a53ce2`](https://github.com/timokoesters/conduit/commit/34a53ce2) (2020-03-28)

## What changed vs step 3

| Rust change | C++ translation |
|---|---|
| Refactors the data layer into a `Data` class with `hostname`, `user_exists`, `user_add` methods. Adds the `username_password` tree and the full 7-version list r0.0.1..r0.6.0 in `/versions`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
