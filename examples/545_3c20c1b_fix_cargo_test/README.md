# Step 545 — "fix `cargo test`" (Conduit `3c20c1b`)

Source: [`timokoesters/conduit@3c20c1b`](https://github.com/timokoesters/conduit/commit/3c20c1b) (2022-10)

## What changed vs step 544

| Rust change | C++ translation |
|---|---|
| Fix `cargo test`. Test compilation fix. | **No-op for us** — Rust test fix — N/A for C++. |

## Implementation details

- Rust test fix — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
