# Step 234 — "Updated function documentation" (Conduit `3e79d15`)

Source: [`timokoesters/conduit@3e79d15`](https://github.com/timokoesters/conduit/commit/3e79d15) (2022-01-16)

## What changed vs step 233

| Rust change | C++ translation |
|---|---|
| **Function documentation** | **Translated** — Function docs |

## Implementation details

1. **Function docs** — Updated function documentation

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
