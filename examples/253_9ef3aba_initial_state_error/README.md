# Step 253 — "fix: initial state deserialize->serialize error" (Conduit `9ef3aba`)

Source: [`timokoesters/conduit@9ef3aba`](https://github.com/timokoesters/conduit/commit/9ef3aba) (2022-02-03)

## What changed vs step 252

| Rust change | C++ translation |
|---|---|
| **Initial state error** | **Translated** — Initial state error |

## Implementation details

1. **Initial state error** — Fix initial state deserialize->serialize error

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
