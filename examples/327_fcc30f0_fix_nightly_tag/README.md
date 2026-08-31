# Step 327 — "Fix: Nightly release tag name should not be a branch name" (Conduit `fcc30f0`)

Source: [`timokoesters/conduit@fcc30f0`](https://github.com/timokoesters/conduit/commit/fcc30f0) (2021-07)

## What changed vs step 326

| Rust change | C++ translation |
|---|---|
| Fix: Nightly release tag name should not be a branch name. CI/CD tag fix. | **No-op for us** — Rust CI/CD — N/A for C++. |

## Implementation details

- Rust CI/CD — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
