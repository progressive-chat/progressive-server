# Step 194 — "improvement: more efficient auth chain cache" (Conduit `dd87066`)

Source: [`timokoesters/conduit@dd87066`](https://github.com/timokoesters/conduit/commit/dd87066) (2021-08-24)

## What changed vs step 193

| Rust change | C++ translation |
|---|---|
| **More efficient auth chain cache** | **Translated** — Efficient auth chain cache |

## Implementation details

1. **Efficient auth chain cache** — More efficient auth chain cache

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
