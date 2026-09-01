# Step 671 — "bump ruma" (Conduit `4b7d3e2`)

Source: [`timokoesters/conduit@4b7d3e2`](https://github.com/timokoesters/conduit/commit/4b7d3e2) (2023-07)

## What changed vs step 670

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
