# Step 303 — "fix: putting global account data works now" (Conduit `59dd367`)

Source: [`timokoesters/conduit@59dd367`](https://github.com/timokoesters/conduit/commit/59dd367) (2021-05)

## What changed vs step 302

| Rust change | C++ translation |
|---|---|
| Fix: putting global account data works now. Account data (global) storage fix. | **Translated** — Our account_data (step 30, 234) works. This fixes the Rust version. |

## Implementation details

- Our account_data (step 30, 234) works. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
