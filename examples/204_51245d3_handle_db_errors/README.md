# Step 204 — "fix(database): handle errors in config parsing or database creation" (Conduit `51245d3`)

Source: [`timokoesters/conduit@51245d3`](https://github.com/timokoesters/conduit/commit/51245d3) (2021-09-08)

## What changed vs step 203

| Rust change | C++ translation |
|---|---|
| **Handle db errors** | **Translated** — Handle db errors |

## Implementation details

1. **Handle db errors** — Handle errors in config parsing or database creation (fixes #121)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
