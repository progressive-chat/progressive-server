# Step 161 — "Speed up release builds" (Conduit `0080932`)

Source: [`timokoesters/conduit@0080932`](https://github.com/timokoesters/conduit/commit/0080932) (2021-07-12)

## What changed vs step 160

| Rust change | C++ translation |
|---|---|
| **Speed up release builds** | **Translated** — Build speedup |

## Implementation details

1. **Build speedup** — Speed up release builds (cargo incremental builds)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
