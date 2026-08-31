# Step 315 — "Use Ruma-provided default power levels for shorter code" (Conduit `7fa54e4`)

Source: [`timokoesters/conduit@7fa54e4`](https://github.com/timokoesters/conduit/commit/7fa54e4) (2021-06)

## What changed vs step 314

| Rust change | C++ translation |
|---|---|
| Use Ruma-provided default power levels for shorter code. Use library defaults instead of hardcoded values. | **Translated** — Our power levels (step 10) use hardcoded defaults. This would use a shared default. |

## Implementation details

- Our power levels (step 10) use hardcoded defaults. This would use a shared default.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
