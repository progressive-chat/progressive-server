# Step 571 — "add nix/nixos deployment documentation" (Conduit `716f82d`)

Source: [`timokoesters/conduit@716f82d`](https://github.com/timokoesters/conduit/commit/716f82d) (2022-10)

## What changed vs step 570

| Rust change | C++ translation |
|---|---|
| Add nix/nixos deployment documentation. Documentation. 3 files changed. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
