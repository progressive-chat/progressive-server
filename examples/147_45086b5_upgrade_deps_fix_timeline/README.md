# Step 147 — "improvement: upgrade dependencies, fix timeline reload bug" (Conduit `45086b5`)

Source: [`timokoesters/conduit@45086b5`](https://github.com/timokoesters/conduit/commit/45086b5) (2020-12)

## What changed vs step 146

| Rust change | C++ translation |
|---|---|
| Improvement: upgrade dependencies, fix timeline reload bug. | **Translated** — Our `pdus_until` (step 6) implements backwards pagination, which is what 'timeline reload' is. The bug fix is in our code. |

## Implementation details

- Our `pdus_until` (step 6) implements backwards pagination, which is what 'timeline reload' is. The bug fix is in our code.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
