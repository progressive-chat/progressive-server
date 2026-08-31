# Step 361 — "fix: stack overflows when fetching auth events" (Conduit `c9c9974`)

Source: [`timokoesters/conduit@c9c9974`](https://github.com/timokoesters/conduit/commit/c9c9974) (2022-01)

## What changed vs step 360

| Rust change | C++ translation |
|---|---|
| Fix: stack overflows when fetching auth events. Recursive auth event fetching caused stack overflow. 2 files changed. | **Translated** — Our auth event fetching (step 83) is iterative. This fixes the Rust recursion. |

## Implementation details

- Our auth event fetching (step 83) is iterative. This fixes the Rust recursion.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
