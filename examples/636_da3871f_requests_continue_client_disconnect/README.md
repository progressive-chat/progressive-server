# Step 636 — "fix: let requests continue event if client disconnects" (Conduit `da3871f`)

Source: [`timokoesters/conduit@da3871f`](https://github.com/timokoesters/conduit/commit/da3871f) (2023-03)

## What changed vs step 635

| Rust change | C++ translation |
|---|---|
| Fix: let requests continue even if client disconnects. Don't cancel federation requests on client disconnect. | **Translated** — Our federation (step 29) continues on disconnect. This fixes the Rust version. |

## Implementation details

- Our federation (step 29) continues on disconnect. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
