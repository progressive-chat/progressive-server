# Step 230 — "improvement: better default cache capacity" (Conduit `80e5198`)

Source: [`timokoesters/conduit@80e5198`](https://github.com/timokoesters/conduit/commit/80e5198) (2022-01-14)

## What changed vs step 229

| Rust change | C++ translation |
|---|---|
| **Better default cache capacity** | **Translated** — Default cache capacity |

## Implementation details

1. **Default cache capacity** — Better default cache capacity

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
