# 2024/2025-tail — "feat(admin): show media command" (Conduit `a189b66`)

Source: [`timokoesters/conduit@a189b66`](https://github.com/timokoesters/conduit/commit/a189b66) (2025-05-07)

## What changed vs step 44 (last 2020 step)

| Rust change | C++ translation |
|---|---|
| Adds admin `GET /_matrix/client/v1/admin/show_media/{server}/{media_id}` returning metadata. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
