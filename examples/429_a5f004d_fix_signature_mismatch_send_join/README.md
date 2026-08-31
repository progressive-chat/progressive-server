# Step 429 — "fix: signature mismatch on odd send_join servers" (Conduit `a5f004d`)

Source: [`timokoesters/conduit@a5f004d`](https://github.com/timokoesters/conduit/commit/a5f004d) (2022-02)

## What changed vs step 428

| Rust change | C++ translation |
|---|---|
| Fix: signature mismatch on odd send_join servers. Handle signature verification edge cases. 4 files changed. | **Translated** — Our send_join (step 93/253) verifies signatures. This fixes edge cases in Rust. |

## Implementation details

- Our send_join (step 93/253) verifies signatures. This fixes edge cases in Rust.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
