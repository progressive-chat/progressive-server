# Step 245 — "Implement media download with custom filename" (Conduit `8472eff`)

Source: [`timokoesters/conduit@8472eff`](https://github.com/timokoesters/conduit/commit/8472eff) (2022-01-27)

## What changed vs step 244

| Rust change | C++ translation |
|---|---|
| **Media custom filename** | **Translated** — Media custom filename |

## Implementation details

1. **Media custom filename** — Implement media download with custom filename

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
