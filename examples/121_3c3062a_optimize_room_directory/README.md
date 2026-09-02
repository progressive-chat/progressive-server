# Step 121 — "improvement: optimize room directory" (Conduit `3c3062a`)

Source: [`timokoesters/conduit@3c3062a`](https://github.com/timokoesters/conduit/commit/3c3062a) (2021-04-28)

## What changed vs step 120

| Rust change | C++ translation |
|---|---|
| **Optimize room directory** | **Translated** — Room directory optimization |

## Implementation details

1. **Room directory optimization** — Optimize room directory

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
