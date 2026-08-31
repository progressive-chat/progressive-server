# Step 441 — "feat: allow disabling jemalloc via feature" (Conduit `8d8eddd`)

Source: [`timokoesters/conduit@8d8eddd`](https://github.com/timokoesters/conduit/commit/8d8eddd) (2022-02)

## What changed vs step 440

| Rust change | C++ translation |
|---|---|
| Feat: allow disabling jemalloc via feature. Optional jemalloc allocator. 2 files changed. | **No-op for us** — Rust jemalloc feature — our C++ uses system allocator. |

## Implementation details

- Rust jemalloc feature — our C++ uses system allocator.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
