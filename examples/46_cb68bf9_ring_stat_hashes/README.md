# Step 46 — "Use ring crate to generate StatHashes when saving stateid/statehash" (Conduit `cb68bf9e`)

Source: [`timokoesters/conduit@cb68bf9e`](https://github.com/timokoesters/conduit/commit/cb68bf9e) (2020-08)

## What changed vs step 45

| Rust change | C++ translation |
|---|---|
| Replaces the placeholder `DefaultHasher` with `ring::SHA256` for deterministic state hash generation. | **No-op for us** — our C++ code already covers this functionality (see earlier steps). |

## Implementation details

- **No-op for us** — our C++ code already covers this functionality (see earlier steps).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
