# Step 680 — "update flake.lock" (Conduit `fa3b1fd`)

Source: [`timokoesters/conduit@fa3b1fd`](https://github.com/timokoesters/conduit/commit/fa3b1fd) (2023-07)

## What changed vs step 679

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
