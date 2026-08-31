# Step 279 — "fix rustup pls" (Conduit `80f1844`)

Source: [`timokoesters/conduit@80f1844`](https://github.com/timokoesters/conduit/commit/80f1844) (2021-05)

## What changed vs step 278

| Rust change | C++ translation |
|---|---|
| Fix rustup pls. CI/tooling fix. | **No-op for us** — Rust toolchain management — N/A for C++. |

## Implementation details

- Rust toolchain management — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
