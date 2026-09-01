# Step 746 — "update flake.lock" (Conduit `f8bdfd8`)

Source: [`timokoesters/conduit@f8bdfd8`](https://github.com/timokoesters/conduit/commit/f8bdfd8) (2024-01)

## What changed vs step 745

| Rust change | C++ translation |
|---|---|
| Update flake.lock. Nix flake update. 2 files changed. | **Skipped** — Nix only. |

## Implementation details

- Nix only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
