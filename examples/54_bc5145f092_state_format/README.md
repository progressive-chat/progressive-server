# Step 54 — "feat(client-api): support `format` query parameter for `GET /state/`" (Conduit `bc5145f092`)

Source: [`timokoesters/conduit@bc5145f092`](https://github.com/timokoesters/conduit/commit/bc5145f092) (2025-08-11)

## What changed vs step 53

| Rust change | C++ translation |
|---|---|
| `get_state_events_for_key_route` accepts `?format=...` (event|content) for `GET /state/{type}/{key}`. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
