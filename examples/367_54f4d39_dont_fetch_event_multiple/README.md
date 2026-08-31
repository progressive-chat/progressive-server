# Step 367 — "improvement: don't fetch event multiple times" (Conduit `54f4d39`)

Source: [`timokoesters/conduit@54f4d39`](https://github.com/timokoesters/conduit/commit/54f4d39) (2022-01)

## What changed vs step 366

| Rust change | C++ translation |
|---|---|
| Improvement: don't fetch event multiple times. Deduplicate event fetching. 2 files changed. | **Translated** — Our event fetching (step 83) caches events. This adds deduplication in Rust. |

## Implementation details

- Our event fetching (step 83) caches events. This adds deduplication in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
