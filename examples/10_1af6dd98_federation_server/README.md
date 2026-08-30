# Step 10 — "More work on federation" (Conduit `1af6dd98`)

Source: [`timokoesters/conduit@1af6dd98`](https://github.com/timokoesters/conduit/commit/1af6dd98) (2020-04-29)

## What changed vs step 9

| Rust change | C++ translation |
|---|---|
| Adds `GET /.well-known/matrix/server`, `GET /_matrix/federation/v1/version`, and `GET /_matrix/key/v2/server` (with self-sign). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
