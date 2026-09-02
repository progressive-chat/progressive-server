# Step 238 — "Fix warnings in database::abstraction" (Conduit `c6277c7`)

Source: [`timokoesters/conduit@c6277c7`](https://github.com/timokoesters/conduit/commit/c6277c7) (2022-01-18)

## What changed vs step 237

| Rust change | C++ translation |
|---|---|
| **Fix warnings in abstraction** | **Translated** — Fix warnings |

## Implementation details

1. **Fix warnings** — Fix warnings in database::abstraction

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
