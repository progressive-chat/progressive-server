# Step 609 — "fix nix docs" (Conduit `391bedd`)

Source: [`timokoesters/conduit@391bedd`](https://github.com/timokoesters/conduit/commit/391bedd) (2023-01)

## What changed vs step 608

| Rust change | C++ translation |
|---|---|
| Fix nix docs. Nix documentation fix. | **Skipped** — Nix documentation only. |

## Implementation details

- Nix documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
