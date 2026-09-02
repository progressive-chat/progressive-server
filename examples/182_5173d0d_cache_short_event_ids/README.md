# Step 182 — "improvement: cache for short event ids" (Conduit `5173d0d`)

Source: [`timokoesters/conduit@5173d0d`](https://github.com/timokoesters/conduit/commit/5173d0d) (2021-08-12)

## What changed vs step 181

| Rust change | C++ translation |
|---|---|
| **Cache for short event ids** | **Translated** — Short event ids cache |

## Implementation details

1. **Short event ids cache** — Add cache for short event ids

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
