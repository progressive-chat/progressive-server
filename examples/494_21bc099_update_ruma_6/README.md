# Step 494 — "Update ruma" (Conduit `21bc099`)

Source: [`timokoesters/conduit@21bc099`](https://github.com/timokoesters/conduit/commit/21bc099) (2022-04)

## What changed vs step 493

| Rust change | C++ translation |
|---|---|
| Update ruma. Dependency version bump. 4 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
