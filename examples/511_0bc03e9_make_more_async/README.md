# Step 511 — "improvement: make more things async" (Conduit `0bc03e9`)

Source: [`timokoesters/conduit@0bc03e9`](https://github.com/timokoesters/conduit/commit/0bc03e9) (2022-06)

## What changed vs step 510

| Rust change | C++ translation |
|---|---|
| Improvement: make more things async. Async refactoring for better concurrency. 7 files changed. | **Translated** — Our server is async (httplib). This is a Rust async refactoring. |

## Implementation details

- Our server is async (httplib). This is a Rust async refactoring.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
