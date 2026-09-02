# Step 187 — "Use full optimizations for master and faster config else" (Conduit `9c3a8ed`)

Source: [`timokoesters/conduit@9c3a8ed`](https://github.com/timokoesters/conduit/commit/9c3a8ed) (2021-08-14)

## What changed vs step 186

| Rust change | C++ translation |
|---|---|
| **Full optimizations** | **Translated** — Full optimizations |

## Implementation details

1. **Full optimizations** — Use full optimizations for master and faster config else

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
