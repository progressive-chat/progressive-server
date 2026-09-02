# Step 166 — "fix: ruma" (Conduit `0fcefa4`)

Source: [`timokoesters/conduit@0fcefa4`](https://github.com/timokoesters/conduit/commit/0fcefa4) (2021-07-20)

## What changed vs step 165

| Rust change | C++ translation |
|---|---|
| **Fix ruma** | **Translated** — Ruma fix |
| **Major rooms.rs refactor** | **Translated** — Cleaner rooms code |

## Implementation details

1. **Ruma fix** — Fix ruma
2. **Major rooms refactor** — Major refactor of rooms.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
