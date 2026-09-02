# Step 142 — "put media in filesystem" (Conduit `972caac`)

Source: [`timokoesters/conduit@972caac`](https://github.com/timokoesters/conduit/commit/972caac) (2021-06-09)

## What changed vs step 141

| Rust change | C++ translation |
|---|---|
| **Put media in filesystem** | **Translated** — Media filesystem storage |

## Implementation details

1. **Media filesystem storage** — Put media in filesystem instead of database

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
