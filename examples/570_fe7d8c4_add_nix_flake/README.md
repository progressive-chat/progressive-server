# Step 570 — "add nix flake" (Conduit `fe7d8c4`)

Source: [`timokoesters/conduit@fe7d8c4`](https://github.com/timokoesters/conduit/commit/fe7d8c4) (2022-10)

## What changed vs step 569

| Rust change | C++ translation |
|---|---|
| Add nix flake. Nix package manager support. 5 files changed. | **Skipped** — Nix packaging only. |

## Implementation details

- Nix packaging only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
