# Step 51 — "fix: clarify that 3pids are currently unsupported" (Conduit `59d7674`)

Source: [`timokoesters/conduit@59d7674`](https://github.com/timokoesters/conduit/commit/59d7674) (2024-05-29)

## What changed vs step 61

| Rust change | C++ translation |
|---|---|
| 3pid add/remove/delegate endpoints return `M_THREEPID_UNSUPPORTED` with a clear error message. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
