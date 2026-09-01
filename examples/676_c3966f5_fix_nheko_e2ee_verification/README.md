# Step 676 — "fix: nheko e2ee verification bug" (Conduit `c3966f5`)

Source: [`timokoesters/conduit@c3966f5`](https://github.com/timokoesters/conduit/commit/c3966f5) (2023-07)

## What changed vs step 675

| Rust change | C++ translation |
|---|---|
| Fix: nheko e2ee verification bug. E2EE verification compatibility with Nheko client. 2 files changed. | **Translated** — Our E2EE (step 337, 550) works. This fixes Nheko compatibility in Rust. |

## Implementation details

- Our E2EE (step 337, 550) works. This fixes Nheko compatibility in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
