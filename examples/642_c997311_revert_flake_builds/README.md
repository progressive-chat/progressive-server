# Step 642 — "Revert "build(nix): fix flake builds"" (Conduit `c997311`)

Source: [`timokoesters/conduit@c997311`](https://github.com/timokoesters/conduit/commit/c997311) (2023-04)

## What changed vs step 641

| Rust change | C++ translation |
|---|---|
| Revert "build(nix): fix flake builds". Revert Nix build fix. | **No-op for us** — Nix build revert — N/A for C++. |

## Implementation details

- Nix build revert — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
