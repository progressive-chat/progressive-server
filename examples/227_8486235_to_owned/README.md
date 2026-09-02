# Step 227 — "Replace to_string calls on string literals with to_owned" (Conduit `8486235`)

Source: [`timokoesters/conduit@8486235`](https://github.com/timokoesters/conduit/commit/8486235) (2022-01-13)

## What changed vs step 226

| Rust change | C++ translation |
|---|---|
| **to_owned instead of to_string** | **Translated** — to_owned |

## Implementation details

1. **to_owned** — Replace to_string calls on string literals with to_owned

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
