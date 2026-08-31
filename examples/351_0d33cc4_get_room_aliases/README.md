# Step 351 — "Implement getting room aliases" (Conduit `0d33cc4`)

Source: [`timokoesters/conduit@0d33cc4`](https://github.com/timokoesters/conduit/commit/0d33cc4) (2021-07)

## What changed vs step 350

| Rust change | C++ translation |
|---|---|
| Implement getting room aliases. Room alias lookup API. 2 files changed. | **Translated** — Our aliases (step 10) support lookup. This adds the Rust implementation. |

## Implementation details

- Our aliases (step 10) support lookup. This adds the Rust implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
