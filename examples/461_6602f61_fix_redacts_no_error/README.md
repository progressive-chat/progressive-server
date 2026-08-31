# Step 461 — "fix: redacts can't error anymore" (Conduit `6602f61`)

Source: [`timokoesters/conduit@6602f61`](https://github.com/timokoesters/conduit/commit/6602f61) (2022-02)

## What changed vs step 460

| Rust change | C++ translation |
|---|---|
| Fix: redacts can't error anymore. Redaction error handling fix. 2 files changed. | **Translated** — Our redaction (step 17) handles errors. This fixes a Rust redaction bug. |

## Implementation details

- Our redaction (step 17) handles errors. This fixes a Rust redaction bug.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
