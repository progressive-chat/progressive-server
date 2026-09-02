# Step 186 — "fix: delta calculation" (Conduit `38effda`)

Source: [`timokoesters/conduit@38effda`](https://github.com/timokoesters/conduit/commit/38effda) (2021-08-14)

## What changed vs step 185

| Rust change | C++ translation |
|---|---|
| **Delta calculation fix** | **Translated** — Delta fix |

## Implementation details

1. **Delta fix** — Fix delta calculation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
