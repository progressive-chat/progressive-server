# Step 750 — "add crane binary cache" (Conduit `bd2b146`)

Source: [`timokoesters/conduit@bd2b146`](https://github.com/timokoesters/conduit/commit/bd2b146) (2024-01)

## What changed vs step 749

| Rust change | C++ translation |
|---|---|
| Add crane binary cache. Nix binary cache tool. | **Skipped** — Nix/CI only. |

## Implementation details

- Nix/CI only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
