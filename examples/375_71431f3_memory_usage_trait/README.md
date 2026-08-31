# Step 375 — "Add memory_usage() to DatabaseEngine trait" (Conduit `71431f3`)

Source: [`timokoesters/conduit@71431f3`](https://github.com/timokoesters/conduit/commit/71431f3) (2022-01)

## What changed vs step 374

| Rust change | C++ translation |
|---|---|
| Add memory_usage() to DatabaseEngine trait. Database trait method for memory reporting. | **Translated** — Related to step 307/374 (swappable DB backend). Adds memory_usage to the trait. |

## Implementation details

- Related to step 307/374 (swappable DB backend). Adds memory_usage to the trait.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
