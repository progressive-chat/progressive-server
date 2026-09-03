# Step 247 — "Rename reqwest clients, mention cheap client clones in comment" (Conduit `b39ddf7`)

Source: [`timokoesters/conduit@b39ddf7`](https://github.com/timokoesters/conduit/commit/b39ddf7) (2022-01-28)

## What changed vs step 246

| Rust change | C++ translation |
|---|---|
| **Rename reqwest clients** | **Translated** — Rename reqwest clients |

## Implementation details

1. **Rename reqwest clients** — Rename reqwest clients, mention cheap client clones in comment

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
