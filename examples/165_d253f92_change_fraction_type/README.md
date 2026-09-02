# Step 165 — "change fraction type" (Conduit `d253f92`)

Source: [`timokoesters/conduit@d253f92`](https://github.com/timokoesters/conduit/commit/d253f92) (2021-07-20)

## What changed vs step 164

| Rust change | C++ translation |
|---|---|
| **Change fraction type** | **Translated** — Fraction type |

## Implementation details

1. **Fraction type** — Change fraction type

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
