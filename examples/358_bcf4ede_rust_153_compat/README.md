# Step 358 — "Restore compatibility with Rust 1.53" (Conduit `bcf4ede`)

Source: [`timokoesters/conduit@bcf4ede`](https://github.com/timokoesters/conduit/commit/bcf4ede) (2022-01)

## What changed vs step 357

| Rust change | C++ translation |
|---|---|
| Restore compatibility with Rust 1.53. Minimum Rust version support. | **No-op for us** — Rust version compatibility — our C++ uses C++17. |

## Implementation details

- Rust version compatibility — our C++ uses C++17.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
