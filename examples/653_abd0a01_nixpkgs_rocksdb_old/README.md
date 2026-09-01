# Step 653 — "nixpkgs' rocksdb is too old :(" (Conduit `abd0a01`)

Source: [`timokoesters/conduit@abd0a01`](https://github.com/timokoesters/conduit/commit/abd0a01) (2023-06)

## What changed vs step 652

| Rust change | C++ translation |
|---|---|
| Nixpkgs' rocksdb is too old. Nix dependency issue. | **No-op for us** — Nix dependency — N/A for C++. |

## Implementation details

- Nix dependency — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
