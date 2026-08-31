# Step 349 — "fix: check events in timeline (not only state) for member changes" (Conduit `1587f2c`)

Source: [`timokoesters/conduit@1587f2c`](https://github.com/timokoesters/conduit/commit/1587f2c) (2021-07)

## What changed vs step 348

| Rust change | C++ translation |
|---|---|
| Fix: check events in timeline (not only state) for member changes. Membership changes from timeline events. 2 files changed. | **Translated** — Our membership (step 16) checks both. This fixes the Rust version. |

## Implementation details

- Our membership (step 16) checks both. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
