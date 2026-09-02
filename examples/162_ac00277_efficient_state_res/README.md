# Step 162 — "improvement: more efficient state res" (Conduit `ac00277`)

Source: [`timokoesters/conduit@ac00277`](https://github.com/timokoesters/conduit/commit/ac00277) (2021-07-14)

## What changed vs step 161

| Rust change | C++ translation |
|---|---|
| **More efficient state res** | **Translated** — Efficient state res |

## Implementation details

1. **Efficient state res** — More efficient state resolution

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
