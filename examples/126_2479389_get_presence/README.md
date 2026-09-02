# Step 126 — "feat: implement GET /presence" (Conduit `2479389`)

Source: [`timokoesters/conduit@2479389`](https://github.com/timokoesters/conduit/commit/2479389) (2021-05-14)

## What changed vs step 125

| Rust change | C++ translation |
|---|---|
| **GET /presence** | **Translated** — GET /presence endpoint |

## Implementation details

1. **GET /presence** — Implement GET /presence endpoint

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
