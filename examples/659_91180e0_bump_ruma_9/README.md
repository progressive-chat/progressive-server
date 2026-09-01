# Step 659 — "bump ruma" (Conduit `91180e0`)

Source: [`timokoesters/conduit@91180e0`](https://github.com/timokoesters/conduit/commit/91180e0) (2023-06)

## What changed vs step 658

| Rust change | C++ translation |
|---|---|
| Bump ruma. Dependency version bump. 2 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
