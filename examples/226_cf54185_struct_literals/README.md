# Step 226 — "Use struct literals for consistency" (Conduit `cf54185`)

Source: [`timokoesters/conduit@cf54185`](https://github.com/timokoesters/conduit/commit/cf54185) (2022-01-13)

## What changed vs step 225

| Rust change | C++ translation |
|---|---|
| **Struct literals for consistency** | **Translated** — Struct literals |

## Implementation details

1. **Struct literals** — Use struct literals for consistency

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
