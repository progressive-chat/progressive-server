# Step 228 — "Restore compatibility with Rust 1.53" (Conduit `bcf4ede`)

Source: [`timokoesters/conduit@bcf4ede`](https://github.com/timokoesters/conduit/commit/bcf4ede) (2022-01-13)

## What changed vs step 227

| Rust change | C++ translation |
|---|---|
| **Rust 1.53 compatibility** | **Translated** — Rust 1.53 compat |

## Implementation details

1. **Rust 1.53 compat** — Restore compatibility with Rust 1.53

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
