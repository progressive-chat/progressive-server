# Step 98 — "fix: various improvements and fixes" (Conduit `3ea7d16`)

Source: [`timokoesters/conduit@3ea7d16`](https://github.com/timokoesters/conduit/commit/3ea7d16) (2021-03-23)

## What changed vs step 97

| Rust change | C++ translation |
|---|---|
| **Various improvements and fixes** | **Translated** — Various fixes |

## Implementation details

1. **Various fixes** — Various improvements and fixes across the codebase

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
