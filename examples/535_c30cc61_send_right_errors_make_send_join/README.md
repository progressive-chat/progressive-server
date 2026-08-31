# Step 535 — "fix: send right errors on make/send join in restricted rooms" (Conduit `c30cc61`)

Source: [`timokoesters/conduit@c30cc61`](https://github.com/timokoesters/conduit/commit/c30cc61) (2022-10)

## What changed vs step 534

| Rust change | C++ translation |
|---|---|
| Fix: send right errors on make/send join in restricted rooms. Proper error codes for restricted room joins. | **Translated** — Our join handling (step 25, 93) returns errors. This fixes the error codes for restricted rooms. |

## Implementation details

- Our join handling (step 25, 93) returns errors. This fixes the error codes for restricted rooms.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
