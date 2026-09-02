# Step 144 — "add migrations" (Conduit `2385bd1`)

Source: [`timokoesters/conduit@2385bd1`](https://github.com/timokoesters/conduit/commit/2385bd1) (2021-06-09)

## What changed vs step 143

| Rust change | C++ translation |
|---|---|
| **Add migrations** | **Translated** — Database migrations |

## Implementation details

1. **Database migrations** — Add migrations support

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
