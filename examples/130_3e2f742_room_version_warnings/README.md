# Step 130 — "fix: room version warnings and other bugs when joining rooms" (Conduit `3e2f742`)

Source: [`timokoesters/conduit@3e2f742`](https://github.com/timokoesters/conduit/commit/3e2f742) (2021-05-21)

## What changed vs step 129

| Rust change | C++ translation |
|---|---|
| **Room version warnings** | **Translated** — Room version warnings |
| **Other join room bugs** | **Translated** — Join room bug fixes |

## Implementation details

1. **Room version warnings** — Fix room version warnings and other bugs when joining rooms

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
