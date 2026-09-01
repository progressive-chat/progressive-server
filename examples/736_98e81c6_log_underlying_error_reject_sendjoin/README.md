# Step 736 — "Log underlying error when rejecting sendjoin response" (Conduit `98e81c6`)

Source: [`timokoesters/conduit@98e81c6`](https://github.com/timokoesters/conduit/commit/98e81c6) (2023-12)

## What changed vs step 735

| Rust change | C++ translation |
|---|---|
| Log underlying error when rejecting sendjoin response. Better error logging for sendjoin. | **Translated** — Our sendjoin (step 253, 93) logs errors. This adds underlying error logging. |

## Implementation details

- Our sendjoin (step 253, 93) logs errors. This adds underlying error logging.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
