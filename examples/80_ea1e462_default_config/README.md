# Step 80 — "fix: default config options" (Conduit `ea1e462`)

Source: [`timokoesters/conduit@ea1e462`](https://github.com/timokoesters/conduit/commit/ea1e462) (2021-02-07)

## What changed vs step 79

| Rust change | C++ translation |
|---|---|
| **Default config options fix** | **Translated** — Default config fixes |

## Implementation details

1. **Default config options** — Fixed default config options

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
