# Step 184 — "fix: long prev event fetch times for huge rooms" (Conduit `9410d3e`)

Source: [`timokoesters/conduit@9410d3e`](https://github.com/timokoesters/conduit/commit/9410d3e) (2021-08-12)

## What changed vs step 183

| Rust change | C++ translation |
|---|---|
| **Long prev event fetch fix** | **Translated** — Long prev events fix |

## Implementation details

1. **Long prev events fix** — Fix long prev event fetch times for huge rooms

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
