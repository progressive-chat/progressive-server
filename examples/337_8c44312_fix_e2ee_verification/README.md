# Step 337 — "fix: e2ee verification" (Conduit `8c44312`)

Source: [`timokoesters/conduit@8c44312`](https://github.com/timokoesters/conduit/commit/8c44312) (2021-07)

## What changed vs step 336

| Rust change | C++ translation |
|---|---|
| Fix: e2ee verification. End-to-end encryption verification fixes. 5 files changed. | **Translated** — We don't have E2EE yet. This fixes the Rust implementation. |

## Implementation details

- We don't have E2EE yet. This fixes the Rust implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
