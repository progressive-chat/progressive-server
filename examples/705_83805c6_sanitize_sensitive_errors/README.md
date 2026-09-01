# Step 705 — "sanitise potentially sensitive errors" (Conduit `83805c6`)

Source: [`timokoesters/conduit@83805c6`](https://github.com/timokoesters/conduit/commit/83805c6) (2023-07)

## What changed vs step 704

| Rust change | C++ translation |
|---|---|
| Sanitise potentially sensitive errors. Don't leak sensitive data in error messages. 2 files changed. | **Translated** — Our error handling (step 8) sanitizes. This ensures sensitive data isn't leaked. |

## Implementation details

- Our error handling (step 8) sanitizes. This ensures sensitive data isn't leaked.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
