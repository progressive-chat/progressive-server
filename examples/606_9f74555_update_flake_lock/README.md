# Step 606 — "update flake.lock" (Conduit `9f74555`)

Source: [`timokoesters/conduit@9f74555`](https://github.com/timokoesters/conduit/commit/9f74555) (2022-12)

## What changed vs step 605

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
