# Step 48 — "fix(membership): always set reason & allow new events if reason changed" (Conduit `d8badaf`)

Source: [`timokoesters/conduit@d8badaf`](https://github.com/timokoesters/conduit/commit/d8badaf) (2024-05-05)

## What changed vs step 60

| Rust change | C++ translation |
|---|---|
| Leave/ban/kick/invite routes always set the `reason` field on the membership content. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
