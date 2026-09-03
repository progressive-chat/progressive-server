# Step 257 — "fix: crash on empty search" (Conduit `eb0b2c4`)

Source: [`timokoesters/conduit@eb0b2c4`](https://github.com/timokoesters/conduit/commit/eb0b2c4) (2022-02-04)

## What changed vs step 256

| Rust change | C++ translation |
|---|---|
| **Empty search crash** | **Translated** — Empty search crash |

## Implementation details

1. **Empty search crash** — Fix crash on empty search

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
