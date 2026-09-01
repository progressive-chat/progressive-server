# Step 740 — "declare 1.5 support" (Conduit `835f4ad`)

Source: [`timokoesters/conduit@835f4ad`](https://github.com/timokoesters/conduit/commit/835f4ad) (2024-01)

## What changed vs step 739

| Rust change | C++ translation |
|---|---|
| Declare 1.5 support. Rust version support declaration. | **Skipped** — Rust version declaration only. |

## Implementation details

- Rust version declaration only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
