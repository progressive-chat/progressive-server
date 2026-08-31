# Step 292 — "fix: Forbidden instead of InvalidParam when joining" (Conduit `90cd11d`)

Source: [`timokoesters/conduit@90cd11d`](https://github.com/timokoesters/conduit/commit/90cd11d) (2021-05)

## What changed vs step 291

| Rust change | C++ translation |
|---|---|
| Fix: Forbidden instead of InvalidParam when joining. Correct error code for join failures. | **Translated** — Our join returns 403 for auth failures. This fixes the Rust version. |

## Implementation details

- Our join returns 403 for auth failures. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
