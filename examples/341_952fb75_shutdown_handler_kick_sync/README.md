# Step 341 — "add shutdown handler to kick sync" (Conduit `952fb75`)

Source: [`timokoesters/conduit@952fb75`](https://github.com/timokoesters/conduit/commit/952fb75) (2021-07)

## What changed vs step 340

| Rust change | C++ translation |
|---|---|
| Add shutdown handler to kick sync. Graceful shutdown for /sync connections. 2 files changed. | **Translated** — Our server doesn't have graceful sync shutdown. This adds it. |

## Implementation details

- Our server doesn't have graceful sync shutdown. This adds it.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
