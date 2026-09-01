# Step 589 — "Clean some noisy logs" (Conduit `a3a1db1`)

Source: [`timokoesters/conduit@a3a1db1`](https://github.com/timokoesters/conduit/commit/a3a1db1) (2022-11)

## What changed vs step 588

| Rust change | C++ translation |
|---|---|
| Clean some noisy logs. Reduce log verbosity. 2 files changed. | **Translated** — Matches steps 555-558 — log level reduction. |

## Implementation details

- Matches steps 555-558 — log level reduction.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
