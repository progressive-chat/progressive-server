# Step 355 — "Upgrade Ruma" (Conduit `349865d`)

Source: [`timokoesters/conduit@349865d`](https://github.com/timokoesters/conduit/commit/349865d) (2022-01)

## What changed vs step 354

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
