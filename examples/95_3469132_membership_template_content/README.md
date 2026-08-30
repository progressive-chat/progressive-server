# Step 95 — "fix: don't ignore content of membership template" (Conduit `3469132`)

Source: [`timokoesters/conduit@3469132`](https://github.com/timokoesters/conduit/commit/3469132) (2025-12-30)

## What changed vs step 94

| Rust change | C++ translation |
|---|---|
| No-op — we don't have `populate_membership_template`; our local events build content from scratch. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
