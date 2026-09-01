# Step 562 — "fix: send unrecognized error on wrong http methods" (Conduit `3a45628`)

Source: [`timokoesters/conduit@3a45628`](https://github.com/timokoesters/conduit/commit/3a45628) (2022-10)

## What changed vs step 561

| Rust change | C++ translation |
|---|---|
| Fix: send unrecognized error on wrong HTTP methods. Proper 405 Method Not Allowed. 7 files changed. | **Translated** — Our httplib (step 6) returns 405. This ensures Rust does too. |

## Implementation details

- Our httplib (step 6) returns 405. This ensures Rust does too.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
