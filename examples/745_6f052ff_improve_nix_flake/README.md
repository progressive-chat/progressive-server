# Step 745 — "improve nix flake" (Conduit `6f052ff`)

Source: [`timokoesters/conduit@6f052ff`](https://github.com/timokoesters/conduit/commit/6f052ff) (2024-01)

## What changed vs step 744

| Rust change | C++ translation |
|---|---|
| Improve nix flake. Nix flake improvements. 2 files changed. | **Skipped** — Nix only. |

## Implementation details

- Nix only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
