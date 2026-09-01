# Step 729 — "Sliding sync improvements and redaction fixes" (Conduit `75c80df`)

Source: [`timokoesters/conduit@75c80df`](https://github.com/timokoesters/conduit/commit/75c80df) (2023-09)

## What changed vs step 728

| Rust change | C++ translation |
|---|---|
| Sliding sync improvements and redaction fixes. Sliding sync + redaction fixes. 11 files changed. MAJOR. | **Translated** — Follows step 670/672/689/690 (sliding sync). Improvements and redaction fixes. |

## Implementation details

- Follows step 670/672/689/690 (sliding sync). Improvements and redaction fixes.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
