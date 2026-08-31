# 2026-tail — "feat: make IP address detection method configurable" (Conduit `47216ee`)

Source: [`timokoesters/conduit@47216ee`](https://github.com/timokoesters/conduit/commit/47216ee) (2026-07-17)

## What changed vs step 93 (last numbered step)

| Rust change | C++ translation |
|---|---|
| Adds `WELL_KNOWN_CLIENT`/`WELL_KNOWN_SERVER` env vars to override defaults; respects `X-Forwarded-For` for client IP. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
