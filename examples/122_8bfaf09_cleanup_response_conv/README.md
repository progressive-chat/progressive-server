# Step 122 — "Clean up reqwest::Response to http::Response conversion" (Conduit `8bfaf09`)

Source: [`timokoesters/conduit@8bfaf09`](https://github.com/timokoesters/conduit/commit/8bfaf09) (2021-04-29)

## What changed vs step 121

| Rust change | C++ translation |
|---|---|
| **Clean up response conversion** | **Translated** — Response conversion cleanup |

## Implementation details

1. **Response conversion cleanup** — Clean up reqwest::Response to http::Response conversion

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
