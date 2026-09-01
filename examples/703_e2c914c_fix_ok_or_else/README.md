# Step 703 — "fix: s/ok_or/ok_or_else in relevant places" (Conduit `e2c914c`)

Source: [`timokoesters/conduit@e2c914c`](https://github.com/timokoesters/conduit/commit/e2c914c) (2023-07)

## What changed vs step 702

| Rust change | C++ translation |
|---|---|
| Fix: s/ok_or/ok_or_else in relevant places. Error handling improvement. 4 files changed. | **Translated** — Our error handling uses Result. This is a Rust-specific ok_or -> ok_or_else fix. |

## Implementation details

- Our error handling uses Result. This is a Rust-specific ok_or -> ok_or_else fix.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
