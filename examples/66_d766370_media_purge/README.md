# Step 66 — "feat(admin): commands for purging media" (Conduit `d766370`)

Source: [`timokoesters/conduit@d766370`](https://github.com/timokoesters/conduit/commit/d766370) (2025-05-07)

## What changed vs step 73

| Rust change | C++ translation |
|---|---|
| Adds admin `POST /_matrix/client/v1/admin/purge_media/{server}/{media_id}` removing a media file from disk and DB. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
