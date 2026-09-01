# Step 673 — "fix: never try federation with self" (Conduit `c171877`)

Source: [`timokoesters/conduit@c171877`](https://github.com/timokoesters/conduit/commit/c171877) (2023-07)

## What changed vs step 672

| Rust change | C++ translation |
|---|---|
| Fix: never try federation with self. Prevent self-federation attempts. | **Translated** — Our federation (step 29) skips self. This ensures it in Rust. |

## Implementation details

- Our federation (step 29) skips self. This ensures it in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
