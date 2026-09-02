# Step 208 — "improvement: deduplicate watchers" (Conduit `cbee7fe`)

Source: [`timokoesters/conduit@cbee7fe`](https://github.com/timokoesters/conduit/commit/cbee7fe) (2021-09-13)

## What changed vs step 207

| Rust change | C++ translation |
|---|---|
| **Deduplicate watchers** | **Translated** — Dedupe watchers |

## Implementation details

1. **Dedupe watchers** — Deduplicate watchers

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
