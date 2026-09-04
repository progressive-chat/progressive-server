# Step 757 — wellknown_host

Source: [`timokoesters/conduit@c1f695653`](https://github.com/timokoesters/conduit/commit/c1f695653) (2024-05-02)

## What changed vs step 756

| Rust change | C++ translation |
|---|---|
| Adds `/.well-known/matrix/client` (m.homeserver + MSC3575 proxy) and `/.well-known/matrix/server` (m.server delegation). | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
