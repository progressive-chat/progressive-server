# Step 602 — "Bump ruma" (Conduit `c7a7c91`)

Source: [`timokoesters/conduit@c7a7c91`](https://github.com/timokoesters/conduit/commit/c7a7c91) (2022-12)

## What changed vs step 601

| Rust change | C++ translation |
|---|---|
| Bump ruma. Dependency version bump. 3 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
