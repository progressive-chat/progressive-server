# Step 167 — "improvement: upgrade ruma and implement blurhashes" (Conduit `f5273f7`)

Source: [`timokoesters/conduit@f5273f7`](https://github.com/timokoesters/conduit/commit/f5273f7) (2021-07-20)

## What changed vs step 166

| Rust change | C++ translation |
|---|---|
| **Upgrade ruma and implement blurhashes** | **Translated** — Blurhashes |

## Implementation details

1. **Blurhashes** — Upgrade ruma and implement blurhashes

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
