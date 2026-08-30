# Step 53 — "fix: Respond with HTTP code 413, when request size is too big" (Conduit `a87f4b6171`)

Source: [`timokoesters/conduit@a87f4b6171`](https://github.com/timokoesters/conduit/commit/a87f4b6171) (2025-07-04)

## What changed vs step 52

| Rust change | C++ translation |
|---|---|
| `set_pre_routing_handler` checks Content-Length and returns 413 M_TOO_LARGE; `set_payload_max_length(20MB)` backstops chunked bodies. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
