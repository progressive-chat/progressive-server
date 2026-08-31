# Step 189 — "improvement: better appservice compatibility and optimizations" (Conduit `6924dfc`)

Source: [`timokoesters/conduit@6924dfc`](https://github.com/timokoesters/conduit/commit/6924dfc) (2021-02)

## What changed vs step 188

| Rust change | C++ translation |
|---|---|
| Improvement: better appservice compatibility and optimizations. 9 files changed. | **Translated** — Our appservice (steps 96, 149, 154) covers the core. This adds compatibility fixes. |

## Implementation details

- Our appservice (steps 96, 149, 154) covers the core. This adds compatibility fixes.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
