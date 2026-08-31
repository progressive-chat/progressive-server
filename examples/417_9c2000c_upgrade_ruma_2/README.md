# Step 417 — "Upgrade Ruma" (Conduit `9c2000c`)

Source: [`timokoesters/conduit@9c2000c`](https://github.com/timokoesters/conduit/commit/9c2000c) (2022-01)

## What changed vs step 416

| Rust change | C++ translation |
|---|---|
| Upgrade Ruma. Dependency version bump. 3 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
