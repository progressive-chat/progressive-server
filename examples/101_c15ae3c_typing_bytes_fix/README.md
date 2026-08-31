# Step 101 — "fix: invalid typing bytes because of 0xff in numbers" (Conduit `c15ae3c`)

Source: [`timokoesters/conduit@c15ae3c`](https://github.com/timokoesters/conduit/commit/c15ae3c) (2020-10)

## What changed vs step 100

| Rust change | C++ translation |
|---|---|
| Fix: invalid typing bytes because of 0xff in numbers (the byte 0xff is used as a key separator, so it can't appear in values). | **Translated** — Our key encoding uses 0xff as separator consistently (step 6 onwards). |

## Implementation details

- Our key encoding uses 0xff as separator consistently (step 6 onwards).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
