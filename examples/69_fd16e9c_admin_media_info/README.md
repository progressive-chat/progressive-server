# Step 69 — "feat(admin): list & query information about media" (Conduit `fd16e9c`)

Source: [`timokoesters/conduit@fd16e9c`](https://github.com/timokoesters/conduit/commit/fd16e9c) (2025-05-07)

## What changed vs step 76

| Rust change | C++ translation |
|---|---|
| Adds admin `GET /_matrix/client/v1/admin/media` (list) and `GET .../info` (query) endpoints. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
