# Step 97 — "feat: Add user agent string" (Conduit `8def22bfb8`)

Source: [`timokoesters/conduit@8def22bfb8`](https://github.com/timokoesters/conduit/commit/8def22bfb8) (2026-03-05)

## What changed vs step 96

| Rust change | C++ translation |
|---|---|
| Outgoing federation requests include `User-Agent: Conduit/0.11.0-alpha (V1_13)` header. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
