# Step 762 — media_csp

Source: [`timokoesters/conduit@1dbb3433e0`](https://github.com/timokoesters/conduit/commit/1dbb3433e0) (2024-06-03)

## What changed vs step 761

| Rust change | C++ translation |
|---|---|
| Reverts content-type forcing and adds a `set_post_routing_handler` injecting `Content-Security-Policy: sandbox; ...` on every response. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
