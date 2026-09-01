# Step 576 — "Return 403 to 3pid token routes to signal not implemented" (Conduit `3bc0a19`)

Source: [`timokoesters/conduit@3bc0a19`](https://github.com/timokoesters/conduit/commit/3bc0a19) (2022-10)

## What changed vs step 575

| Rust change | C++ translation |
|---|---|
| Return 403 to 3pid token routes to signal not implemented. 3PID (email/phone) token endpoints not implemented. 2 files changed. | **Translated** — Our 3PID routes (step 8) return 403. This ensures proper signaling. |

## Implementation details

- Our 3PID routes (step 8) return 403. This ensures proper signaling.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
