# Step 741 — "comment out heed backend things" (Conduit `dc2f53e`)

Source: [`timokoesters/conduit@dc2f53e`](https://github.com/timokoesters/conduit/commit/dc2f53e) (2024-01)

## What changed vs step 740

| Rust change | C++ translation |
|---|---|
| Comment out heed backend things. LMDB (heed) backend commented out. 2 files changed. | **Translated** — Related to step 307/386 (persy/heed backends). This comments out heed. |

## Implementation details

- Related to step 307/386 (persy/heed backends). This comments out heed.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
