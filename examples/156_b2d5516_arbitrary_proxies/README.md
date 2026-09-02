# Step 156 — "add support for arbitrary proxies" (Conduit `b2d5516`)

Source: [`timokoesters/conduit@b2d5516`](https://github.com/timokoesters/conduit/commit/b2d5516) (2021-07-01)

## What changed vs step 155

| Rust change | C++ translation |
|---|---|
| **Arbitrary proxies** | **Translated** — Proxy support |

## Implementation details

1. **Proxy support** — Add support for arbitrary proxies

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
