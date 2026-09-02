# Step 164 — "change to f64" (Conduit `ec44f3d`)

Source: [`timokoesters/conduit@ec44f3d`](https://github.com/timokoesters/conduit/commit/ec44f3d) (2021-07-20)

## What changed vs step 163

| Rust change | C++ translation |
|---|---|
| **Change to f64** | **Translated** — Use f64 |

## Implementation details

1. **Use f64** — Change to f64

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
