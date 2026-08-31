# Step 313 — "improvement: show more users in our user directory" (Conduit `e8f6708`)

Source: [`timokoesters/conduit@e8f6708`](https://github.com/timokoesters/conduit/commit/e8f6708) (2021-06)

## What changed vs step 312

| Rust change | C++ translation |
|---|---|
| Improvement: show more users in our user directory. User directory query returns more results. 3 files changed. | **Translated** — Our user directory (step 253) returns users. This increases the limit. |

## Implementation details

- Our user directory (step 253) returns users. This increases the limit.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
