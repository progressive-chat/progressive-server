# Step 714 — "fix: nheko e2ee verification bug" (Conduit `c3966f5`)

Source: [`timokoesters/conduit@c3966f5`](https://github.com/timokoesters/conduit/commit/c3966f5) (2023-07)

## What changed vs step 713

| Rust change | C++ translation |
|---|---|
| Duplicate of step 676 (fix nheko e2ee verification). | **Skipped** — Duplicate of step 676. |

## Implementation details

- Duplicate of step 676.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
