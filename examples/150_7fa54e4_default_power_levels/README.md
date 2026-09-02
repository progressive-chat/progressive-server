# Step 150 — "Use Ruma-provided default power levels for shorter code" (Conduit `7fa54e4`)

Source: [`timokoesters/conduit@7fa54e4`](https://github.com/timokoesters/conduit/commit/7fa54e4) (2021-06-17)

## What changed vs step 149

| Rust change | C++ translation |
|---|---|
| **Default power levels** | **Translated** — Default power levels |

## Implementation details

1. **Default power levels** — Use Ruma-provided default power levels for shorter code

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
