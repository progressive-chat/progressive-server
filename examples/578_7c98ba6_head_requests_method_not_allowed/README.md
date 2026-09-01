# Step 578 — "fix: HEAD requests should produce METHOD_NOT_ALLOWED" (Conduit `7c98ba6`)

Source: [`timokoesters/conduit@7c98ba6`](https://github.com/timokoesters/conduit/commit/7c98ba6) (2022-10)

## What changed vs step 577

| Rust change | C++ translation |
|---|---|
| Fix: HEAD requests should produce METHOD_NOT_ALLOWED. HEAD method handling. 3 files changed. | **Translated** — Our httplib handles HEAD. This ensures 405 for unsupported endpoints. |

## Implementation details

- Our httplib handles HEAD. This ensures 405 for unsupported endpoints.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
