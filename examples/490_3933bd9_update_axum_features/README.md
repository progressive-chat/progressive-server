# Step 490 — "Update axum feature set used" (Conduit `3933bd9`)

Source: [`timokoesters/conduit@3933bd9`](https://github.com/timokoesters/conduit/commit/3933bd9) (2022-03)

## What changed vs step 489

| Rust change | C++ translation |
|---|---|
| Update axum feature set used. Feature flag updates for axum 0.5. 2 files changed. | **No-op for us** — Rust axum features — N/A for C++. |

## Implementation details

- Rust axum features — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
