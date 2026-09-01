# Step 592 — "fix: rejoining restricted rooms over federation" (Conduit `b9fd612`)

Source: [`timokoesters/conduit@b9fd612`](https://github.com/timokoesters/conduit/commit/b9fd612) (2022-11)

## What changed vs step 591

| Rust change | C++ translation |
|---|---|
| Fix: rejoining restricted rooms over federation. Restricted room rejoin fix. 4 files changed. | **Translated** — Our restricted joins (step 564) work. This fixes rejoin in Rust. |

## Implementation details

- Our restricted joins (step 564) work. This fixes rejoin in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
