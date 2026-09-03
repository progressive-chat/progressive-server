# Step 242 — "fix: linking against libatomic is no longer required since the library path is fixed" (Conduit `bfef94f`)

Source: [`timokoesters/conduit@bfef94f`](https://github.com/timokoesters/conduit/commit/bfef94f) (2022-01-21)

## What changed vs step 241

| Rust change | C++ translation |
|---|---|
| **libatomic fix** | **Translated** — libatomic fix |

## Implementation details

1. **libatomic fix** — Fix: linking against libatomic is no longer required since the library path is fixed

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
