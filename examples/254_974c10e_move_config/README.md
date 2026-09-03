# Step 254 — "Move Config out of database module" (Conduit `974c10e`)

Source: [`timokoesters/conduit@974c10e`](https://github.com/timokoesters/conduit/commit/974c10e) (2022-02-03)

## What changed vs step 253

| Rust change | C++ translation |
|---|---|
| **Config out of database** | **Translated** — Config out of database |

## Implementation details

1. **Config out of database** — Move Config out of database module

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
