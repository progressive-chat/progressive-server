# Step 402 — "Delete rust-toolchain file" (Conduit `6e32271`)

Source: [`timokoesters/conduit@6e32271`](https://github.com/timokoesters/conduit/commit/6e32271) (2022-01)

## What changed vs step 401

| Rust change | C++ translation |
|---|---|
| Delete rust-toolchain file. Remove pinned Rust version file. | **No-op for us** — Rust toolchain file — N/A for C++. |

## Implementation details

- Rust toolchain file — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
