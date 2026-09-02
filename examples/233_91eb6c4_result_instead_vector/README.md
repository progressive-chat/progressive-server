# Step 233 — "Return a Result instead of a vector" (Conduit `91eb6c4`)

Source: [`timokoesters/conduit@91eb6c4`](https://github.com/timokoesters/conduit/commit/91eb6c4) (2022-01-15)

## What changed vs step 232

| Rust change | C++ translation |
|---|---|
| **Return Result instead of vector** | **Translated** — Result instead of vector |

## Implementation details

1. **Result instead of vector** — Return a Result instead of a vector

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
