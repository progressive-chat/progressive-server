# Step 681 — "nixpkgs' rocksdb is now new enough :)" (Conduit `abd8e1b`)

Source: [`timokoesters/conduit@abd8e1b`](https://github.com/timokoesters/conduit/commit/abd8e1b) (2023-07)

## What changed vs step 680

| Rust change | C++ translation |
|---|---|
| Nixpkgs' rocksdb is now new enough. Nix dependency update. | **No-op for us** — Nix dependency — N/A for C++. |

## Implementation details

- Nix dependency — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
