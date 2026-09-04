# Step 46 — "Use ring crate to generate StatHashes when saving stateid/statehash" (Conduit `cb68bf9e`)

Source: [`timokoesters/conduit@cb68bf9e`](https://github.com/timokoesters/conduit/commit/cb68bf9e) (2020-08-18)

## What changed vs step 45.5

| Rust change | C++ translation |
|---|---|
| Replaces the placeholder `DefaultHasher` with `ring::SHA256` for deterministic state hash generation. | **No-op for us** — our C++ code already covers this functionality via `state_res::new_state_hash()` using SHA-256. |

## Implementation details

- **No-op for us** — our C++ `state_res::new_state_hash()` already uses SHA-256 via OpenSSL (implemented in step 791).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```