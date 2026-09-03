# Step 244 — "fix: make sure that libatomic is linked statically" (Conduit `acf1585`)

Source: [`timokoesters/conduit@acf1585`](https://github.com/timokoesters/conduit/commit/acf1585) (2022-01-24)

## What changed vs step 243

| Rust change | C++ translation |
|---|---|
| **libatomic static link** | **Translated** — libatomic static |

## Implementation details

1. **libatomic static** — Make sure that libatomic is linked statically

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
