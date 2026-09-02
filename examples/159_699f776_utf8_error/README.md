# Step 159 — "Return proper error in case of invalid UTF-8 in json_body" (Conduit `699f776`)

Source: [`timokoesters/conduit@699f776`](https://github.com/timokoesters/conduit/commit/699f776) (2021-07-11)

## What changed vs step 158

| Rust change | C++ translation |
|---|---|
| **Proper error for invalid UTF-8** | **Translated** — UTF-8 error handling |

## Implementation details

1. **UTF-8 error handling** — Return proper error in case of invalid UTF-8 in json_body

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
