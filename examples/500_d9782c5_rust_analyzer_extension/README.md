# Step 500 — "rust-analyzer-extension moved to rust-lang" (Conduit `d9782c5`)

Source: [`timokoesters/conduit@d9782c5`](https://github.com/timokoesters/conduit/commit/d9782c5) (2022-06)

## What changed vs step 499

| Rust change | C++ translation |
|---|---|
| rust-analyzer-extension moved to rust-lang. Tooling change. | **No-op for us** — Rust tooling — N/A for C++. |

## Implementation details

- Rust tooling — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
