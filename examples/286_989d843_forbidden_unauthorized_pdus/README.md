# Step 286 — "fix: unauthorized pdus will be responded to with FORBIDDEN" (Conduit `989d843`)

Source: [`timokoesters/conduit@989d843`](https://github.com/timokoesters/conduit/commit/989d843) (2021-05)

## What changed vs step 285

| Rust change | C++ translation |
|---|---|
| Fix: unauthorized pdus will be responded to with FORBIDDEN. Proper error code for auth failures. | **Translated** — Our federation handler returns 403 for auth failures. This standardizes the Rust version. |

## Implementation details

- Our federation handler returns 403 for auth failures. This standardizes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
