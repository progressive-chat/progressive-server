# Step 534 — "Bump some dependencies" (Conduit `275c6b4`)

Source: [`timokoesters/conduit@275c6b4`](https://github.com/timokoesters/conduit/commit/275c6b4) (2022-10)

## What changed vs step 533

| Rust change | C++ translation |
|---|---|
| Bump some dependencies. Dependency version updates. 6 files changed. | **Skipped** — Rust dependency upgrades — no direct C++ equivalent. |

## Implementation details

- Rust dependency upgrades — no direct C++ equivalent.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
