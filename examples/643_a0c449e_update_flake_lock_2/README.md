# Step 643 — "update flake.lock" (Conduit `a0c449e`)

Source: [`timokoesters/conduit@a0c449e`](https://github.com/timokoesters/conduit/commit/a0c449e) (2023-04)

## What changed vs step 642

| Rust change | C++ translation |
|---|---|
| Update flake.lock. Nix flake update. | **Skipped** — Nix only. |

## Implementation details

- Nix only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
