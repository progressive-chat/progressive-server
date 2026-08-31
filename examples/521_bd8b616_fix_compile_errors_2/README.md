# Step 521 — "Fixed more compile time errors" (Conduit `bd8b616`)

Source: [`timokoesters/conduit@bd8b616`](https://github.com/timokoesters/conduit/commit/bd8b616) (2022-10)

## What changed vs step 520

| Rust change | C++ translation |
|---|---|
| Fixed more compile time errors. Second batch. 103 files changed. | **No-op for us** — Rust compile fixes — N/A for C++. |

## Implementation details

- Rust compile fixes — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
