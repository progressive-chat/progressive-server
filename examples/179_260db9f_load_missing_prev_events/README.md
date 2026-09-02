# Step 179 — "improvement: try to load missing prev events" (Conduit `260db9f`)

Source: [`timokoesters/conduit@260db9f`](https://github.com/timokoesters/conduit/commit/260db9f) (2021-08-09)

## What changed vs step 178

| Rust change | C++ translation |
|---|---|
| **Load missing prev events** | **Translated** — Load prev events |

## Implementation details

1. **Load prev events** — Try to load missing prev events

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
