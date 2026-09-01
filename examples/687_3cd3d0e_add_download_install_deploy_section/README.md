# Step 687 — "Add section about how to download/install/deploy" (Conduit `3cd3d0e`)

Source: [`timokoesters/conduit@3cd3d0e`](https://github.com/timokoesters/conduit/commit/3cd3d0e) (2023-07)

## What changed vs step 686

| Rust change | C++ translation |
|---|---|
| Add section about how to download/install/deploy. Documentation. | **Skipped** — Documentation only. |

## Implementation details

- Documentation only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
