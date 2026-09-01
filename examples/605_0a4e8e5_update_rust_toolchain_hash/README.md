# Step 605 — "update rust toolchain hash" (Conduit `0a4e8e5`)

Source: [`timokoesters/conduit@0a4e8e5`](https://github.com/timokoesters/conduit/commit/0a4e8e5) (2022-12)

## What changed vs step 604

| Rust change | C++ translation |
|---|---|
| Update rust toolchain hash. Toolchain update. | **No-op for us** — Rust toolchain — N/A for C++. |

## Implementation details

- Rust toolchain — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
