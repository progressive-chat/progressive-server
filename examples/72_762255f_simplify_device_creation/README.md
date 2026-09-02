# Step 72 — "Simplify device creation logic during login" (Conduit `762255f`)

Source: [`timokoesters/conduit@762255f`](https://github.com/timokoesters/conduit/commit/762255f) (2021-01-17)

## What changed vs step 71

| Rust change | C++ translation |
|---|---|
| **Simplify device creation logic** | **Translated** — Cleaner device creation |

## Implementation details

1. **Device creation logic** — Simplified device creation during login

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
