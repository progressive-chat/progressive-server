# Step 469 — "update ruma" (Conduit `e9f87e1`)

Source: [`timokoesters/conduit@e9f87e1`](https://github.com/timokoesters/conduit/commit/e9f87e1) (2022-02)

## What changed vs step 468

| Rust change | C++ translation |
|---|---|
| Update ruma. Major Ruma upgrade. 42 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
