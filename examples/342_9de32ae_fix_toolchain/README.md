# Step 342 — "fix toolchain" (Conduit `9de32ae`)

Source: [`timokoesters/conduit@9de32ae`](https://github.com/timokoesters/conduit/commit/9de32ae) (2021-07)

## What changed vs step 341

| Rust change | C++ translation |
|---|---|
| Fix toolchain. Rust toolchain configuration fix. | **No-op for us** — Rust toolchain — N/A for C++. |

## Implementation details

- Rust toolchain — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
