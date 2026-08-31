# Step 339 — "improvement: efficient /sync, mutex for federation transactions" (Conduit `e15e6d4`)

Source: [`timokoesters/conduit@e15e6d4`](https://github.com/timokoesters/conduit/commit/e15e6d4) (2021-07)

## What changed vs step 338

| Rust change | C++ translation |
|---|---|
| Improvement: efficient /sync, mutex for federation transactions. Better sync performance and thread safety. 5 files changed. | **Translated** — Our /sync (step 6) and federation (step 29) cover this. Mutex improvements. |

## Implementation details

- Our /sync (step 6) and federation (step 29) cover this. Mutex improvements.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
