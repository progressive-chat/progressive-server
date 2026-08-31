# Step 393 — "Add some debug/info if user was found" (Conduit `52284ef`)

Source: [`timokoesters/conduit@52284ef`](https://github.com/timokoesters/conduit/commit/52284ef) (2022-01)

## What changed vs step 392

| Rust change | C++ translation |
|---|---|
| Add some debug/info if user was found. Logging for user lookup. | **Translated** — Our user lookup (step 10) logs. This adds debug logging in Rust. |

## Implementation details

- Our user lookup (step 10) logs. This adds debug logging in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
