# Step 512 — "Upgrade dependencies" (Conduit `0c8e51e`)

Source: [`timokoesters/conduit@0c8e51e`](https://github.com/timokoesters/conduit/commit/0c8e51e) (2022-06)

## What changed vs step 511

| Rust change | C++ translation |
|---|---|
| Upgrade dependencies. General dependency version bump. 2 files changed. | **Skipped** — Rust dependency upgrades — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrades — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
