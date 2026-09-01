# Step 710 — "bump rusqlite to 0.29.0" (Conduit `fbb256d`)

Source: [`timokoesters/conduit@fbb256d`](https://github.com/timokoesters/conduit/commit/fbb256d) (2023-08)

## What changed vs step 709

| Rust change | C++ translation |
|---|---|
| Bump rusqlite to 0.29.0. SQLite dependency upgrade. 2 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
