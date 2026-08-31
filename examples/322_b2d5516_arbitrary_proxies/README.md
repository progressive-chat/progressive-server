# Step 322 — "add support for arbitrary proxies" (Conduit `b2d5516`)

Source: [`timokoesters/conduit@b2d5516`](https://github.com/timokoesters/conduit/commit/b2d5516) (2021-07)

## What changed vs step 321

| Rust change | C++ translation |
|---|---|
| Add support for arbitrary proxies. HTTP proxy support for outgoing federation requests. 5 files changed. | **Translated** — Our federation client (step 29) doesn't support proxies. This adds proxy support. |

## Implementation details

- Our federation client (step 29) doesn't support proxies. This adds proxy support.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
