# Step 57 — "fix: don't ignore content of membership template" (Conduit `346913268f`)

Source: [`timokoesters/conduit@346913268f`](https://github.com/timokoesters/conduit/commit/346913268f) (2025-12-30)

## What changed vs step 56

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
