# Step 778 — media_retention

Source: [`timokoesters/conduit@c3fb1b0`](https://github.com/timokoesters/conduit/commit/c3fb1b0) (2025-05-07)

## What changed vs step 777

| Rust change | C++ translation |
|---|---|
| Adds admin endpoint to set per-server retention policies; media older than retention is purged on access. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
