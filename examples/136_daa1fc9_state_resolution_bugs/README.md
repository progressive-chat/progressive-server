# Step 136 — "fix: state resolution bugs" (Conduit `daa1fc9`)

Source: [`timokoesters/conduit@daa1fc9`](https://github.com/timokoesters/conduit/commit/daa1fc9) (2021-05-27)

## What changed vs step 135

| Rust change | C++ translation |
|---|---|
| **State resolution bugs** | **Translated** — State res bug fixes |

## Implementation details

1. **State res bug fixes** — Fix state resolution bugs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
