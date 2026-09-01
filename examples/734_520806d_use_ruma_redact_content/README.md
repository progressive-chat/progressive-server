# Step 734 — "Use Ruma's redact_content_in_place instead of custom implementation" (Conduit `520806d`)

Source: [`timokoesters/conduit@520806d`](https://github.com/timokoesters/conduit/commit/520806d) (2023-12)

## What changed vs step 733

| Rust change | C++ translation |
|---|---|
| Use Ruma's redact_content_in_place instead of custom implementation. Use library redaction function. 2 files changed. | **Translated** — Our redaction (step 17) uses custom logic. This uses library function. |

## Implementation details

- Our redaction (step 17) uses custom logic. This uses library function.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
