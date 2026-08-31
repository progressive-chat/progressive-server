# Step 45 — "feat(auth): check if X-Matrix destination is correct if present" (Conduit `63ba157ef6`)

Source: [`timokoesters/conduit@63ba157ef6`](https://github.com/timokoesters/conduit/commit/63ba157ef6) (2024-05-02)

## What changed vs step 45

| Rust change | C++ translation |
|---|---|
| Adds `xmatrix_destination_ok()` validating the `destination="..."` field of the X-Matrix Authorization header. | Translated to C++ with the same wire shape and behavior. |

## Implementation details

- All Conduit code changes are translated to the C++ architecture (httplib + RocksDB + nlohmann::json)
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
