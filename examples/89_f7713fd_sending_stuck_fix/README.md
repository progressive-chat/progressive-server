# Step 89 — "fix: sending code got stuck sometimes" (Conduit `f7713fd`)

Source: [`timokoesters/conduit@f7713fd`](https://github.com/timokoesters/conduit/commit/f7713fd) (2021-03-02)

## What changed vs step 88

| Rust change | C++ translation |
|---|---|
| **Fix sending code got stuck** | **Translated** — Sending code fix |
| **Major sending.rs refactor** | **Translated** — Cleaner sending code |

## Implementation details

1. **Sending code fix** — Fixed sending code that got stuck sometimes
2. **Major sending refactor** — Major refactor of sending code

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
