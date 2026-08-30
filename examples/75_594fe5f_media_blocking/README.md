# Step 75 — "feat(media): blocking" (Conduit `594fe5f`)

Source: [`timokoesters/conduit@594fe5f`](https://github.com/timokoesters/conduit/commit/594fe5f) (2025-05-07)

## What changed vs step 74

| Rust change | C++ translation |
|---|---|
| Adds `blocked_servername_mediaid` and `blocked_filehash` sled trees; admin endpoints to block/unblock. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
