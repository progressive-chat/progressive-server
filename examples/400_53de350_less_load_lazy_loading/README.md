# Step 400 — "fix: less load when lazy loading" (Conduit `53de350`)

Source: [`timokoesters/conduit@53de350`](https://github.com/timokoesters/conduit/commit/53de350) (2022-01)

## What changed vs step 399

| Rust change | C++ translation |
|---|---|
| Fix: less load when lazy loading. Optimize lazy loading to reduce database queries. | **Translated** — Related to step 369 (lazy loading). This optimizes the lazy loading. |

## Implementation details

- Related to step 369 (lazy loading). This optimizes the lazy loading.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
