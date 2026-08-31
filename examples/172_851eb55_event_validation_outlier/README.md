# Step 172 — "Abstract event validation/fetching, add outlier and signing key DB trees" (Conduit `851eb55`)

Source: [`timokoesters/conduit@851eb55`](https://github.com/timokoesters/conduit/commit/851eb55) (2021-01)

## What changed vs step 171

| Rust change | C++ translation |
|---|---|
| Abstract event validation/fetching, add `outlier` and `signing_key` DB trees. 7 files changed. | **Translated** — Our outlier detection comes in step 83. Signing key DB is in our crypto module. |

## Implementation details

- Our outlier detection comes in step 83. Signing key DB is in our crypto module.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
