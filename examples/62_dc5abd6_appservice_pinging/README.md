# Step 62 — "feat(appservice): pinging" (Conduit `dc5abd6`)

Source: [`timokoesters/conduit@dc5abd6`](https://github.com/timokoesters/conduit/commit/dc5abd6) (2025-03-08)

## What changed vs step 69

| Rust change | C++ translation |
|---|---|
| Adds `POST /_matrix/client/v1/appservice/{id}/ping` with `appservice_id_from_token` auth check. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
