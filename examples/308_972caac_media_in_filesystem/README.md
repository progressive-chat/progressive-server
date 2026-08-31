# Step 308 — "put media in filesystem" (Conduit `972caac`)

Source: [`timokoesters/conduit@972caac`](https://github.com/timokoesters/conduit/commit/972caac) (2021-06)

## What changed vs step 307

| Rust change | C++ translation |
|---|---|
| Put media in filesystem. Store media files on disk instead of database. 6 files changed. | **Translated** — Our media (step 14) stores in DB. Filesystem storage is an optimization. |

## Implementation details

- Our media (step 14) stores in DB. Filesystem storage is an optimization.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
