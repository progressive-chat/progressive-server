# Step 310 — "add migrations" (Conduit `2385bd1`)

Source: [`timokoesters/conduit@2385bd1`](https://github.com/timokoesters/conduit/commit/2385bd1) (2021-06)

## What changed vs step 309

| Rust change | C++ translation |
|---|---|
| Add database migrations. Schema migration system for database upgrades. 2 files changed. | **Translated** — Our DB doesn't have migrations yet. This adds a migration framework. |

## Implementation details

- Our DB doesn't have migrations yet. This adds a migration framework.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
