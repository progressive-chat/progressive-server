# Step 543 — "fix: make join should not send event id" (Conduit `dd8f468`)

Source: [`timokoesters/conduit@dd8f468`](https://github.com/timokoesters/conduit/commit/dd8f468) (2022-10)

## What changed vs step 542

| Rust change | C++ translation |
|---|---|
| Fix: make_join should not send event id. make_join response format fix. | **Translated** — Our make_join (step 253) returns correct format. This fixes the Rust version. |

## Implementation details

- Our make_join (step 253) returns correct format. This fixes the Rust version.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
