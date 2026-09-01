# Step 743 — "fix `cargo doc` lints" (Conduit `0d17aed`)

Source: [`timokoesters/conduit@0d17aed`](https://github.com/timokoesters/conduit/commit/0d17aed) (2024-01)

## What changed vs step 742

| Rust change | C++ translation |
|---|---|
| Fix `cargo doc` lints. Documentation lint fixes. 2 files changed. | **No-op for us** — Rust doc lints — N/A for C++. |

## Implementation details

- Rust doc lints — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
