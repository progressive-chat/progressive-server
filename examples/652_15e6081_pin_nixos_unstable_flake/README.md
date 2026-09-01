# Step 652 — "pin nixos-unstable, update flake.lock" (Conduit `15e6081`)

Source: [`timokoesters/conduit@15e6081`](https://github.com/timokoesters/conduit/commit/15e6081) (2023-06)

## What changed vs step 651

| Rust change | C++ translation |
|---|---|
| Pin nixos-unstable, update flake.lock. Nix channel pinning. 2 files changed. | **Skipped** — Nix only. |

## Implementation details

- Nix only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
