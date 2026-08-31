# Step 542 — "improvement: more efficient /claim" (Conduit `0290f1f`)

Source: [`timokoesters/conduit@0290f1f`](https://github.com/timokoesters/conduit/commit/0290f1f) (2022-10)

## What changed vs step 541

| Rust change | C++ translation |
|---|---|
| Improvement: more efficient /claim. Key claim endpoint optimization. 1 file changed. | **Translated** — Our /claim (step 301) exists. This optimizes the Rust implementation. |

## Implementation details

- Our /claim (step 301) exists. This optimizes the Rust implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
