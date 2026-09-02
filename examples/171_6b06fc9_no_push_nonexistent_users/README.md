# Step 171 — "fix: don't run push rules for users that don't exist" (Conduit `6b06fc9`)

Source: [`timokoesters/conduit@6b06fc9`](https://github.com/timokoesters/conduit/commit/6b06fc9) (2021-08-03)

## What changed vs step 170

| Rust change | C++ translation |
|---|---|
| **Don't run push rules for non-existent users** | **Translated** — Push rules check |

## Implementation details

1. **Push rules check** — Don't run push rules for users that don't exist

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
