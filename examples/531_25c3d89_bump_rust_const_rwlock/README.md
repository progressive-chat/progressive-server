# Step 531 — "Bump rust version for const fn RwLock::new" (Conduit `25c3d89`)

Source: [`timokoesters/conduit@25c3d89`](https://github.com/timokoesters/conduit/commit/25c3d89) (2022-10)

## What changed vs step 530

| Rust change | C++ translation |
|---|---|
| Bump rust version for const fn RwLock::new. Rust version requirement for const RwLock. | **No-op for us** — Rust version requirement — our C++ uses C++17. |

## Implementation details

- Rust version requirement — our C++ uses C++17.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
