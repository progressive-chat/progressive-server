# Step 246 — "Fix incorrect HTTP method in doc comments of two media routes" (Conduit `52873c8`)

Source: [`timokoesters/conduit@52873c8`](https://github.com/timokoesters/conduit/commit/52873c8) (2022-01-27)

## What changed vs step 245

| Rust change | C++ translation |
|---|---|
| **Fix HTTP method docs** | **Translated** — Fix HTTP method docs |

## Implementation details

1. **Fix HTTP method docs** — Fix incorrect HTTP method in doc comments of two media routes

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
