# Step 94 — "fix: use populate_membership_template for `/leave`" (Conduit `82b7cf6`)

Source: [`timokoesters/conduit@82b7cf6`](https://github.com/timokoesters/conduit/commit/82b7cf6) (2025-12-30)

## What changed vs step 93

| Rust change | C++ translation |
|---|---|
| No-op — we don't implement federation make_leave/send_leave. Our local `/leave` already populates the security-critical fields. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
