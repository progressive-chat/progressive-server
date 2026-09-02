# Step 207 — "Get rid of more unnecessary intermediate collections" (Conduit `910ad7f`)

Source: [`timokoesters/conduit@910ad7f`](https://github.com/timokoesters/conduit/commit/910ad7f) (2021-09-13)

## What changed vs step 206

| Rust change | C++ translation |
|---|---|
| **No intermediate collections** | **Translated** — Cleaner code |

## Implementation details

1. **Cleaner code** — Get rid of more unnecessary intermediate collections

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
