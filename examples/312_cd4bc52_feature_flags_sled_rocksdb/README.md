# Step 312 — "improvement: feature flags for sled, rocksdb" (Conduit `cd4bc52`)

Source: [`timokoesters/conduit@cd4bc52`](https://github.com/timokoesters/conduit/commit/cd4bc52) (2021-06)

## What changed vs step 311

| Rust change | C++ translation |
|---|---|
| Improvement: feature flags for sled, rocksdb. Compile-time database backend selection. 10 files changed. | **Translated** — Related to step 307 — feature flags for database backends. |

## Implementation details

- Related to step 307 — feature flags for database backends.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
