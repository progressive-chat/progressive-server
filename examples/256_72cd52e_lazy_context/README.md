# Step 256 — "fix: lazy loading for /context" (Conduit `72cd52e`)

Source: [`timokoesters/conduit@72cd52e`](https://github.com/timokoesters/conduit/commit/72cd52e) (2022-02-04)

## What changed vs step 255

| Rust change | C++ translation |
|---|---|
| **Lazy loading for /context** | **Translated** — Lazy context |

## Implementation details

1. **Lazy context** — Fix lazy loading for /context

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
