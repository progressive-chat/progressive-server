# Step 455 — "update ruma" (Conduit `0ed1e42`)

Source: [`timokoesters/conduit@0ed1e42`](https://github.com/timokoesters/conduit/commit/0ed1e42) (2022-02)

## What changed vs step 454

| Rust change | C++ translation |
|---|---|
| Update ruma. Dependency version bump. 2 files changed. | **Skipped** — Rust dependency upgrade — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrade — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
