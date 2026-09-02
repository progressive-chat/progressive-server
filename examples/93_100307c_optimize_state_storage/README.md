# Step 93 — "improvement: optimize state storage" (Conduit `100307c`)

Source: [`timokoesters/conduit@100307c`](https://github.com/timokoesters/conduit/commit/100307c) (2021-03-17)

## What changed vs step 92

| Rust change | C++ translation |
|---|---|
| **Optimize state storage** | **Translated** — State storage optimizations |
| **Major rooms.rs refactor** | **Translated** — Better rooms storage |
| **Sync improvements** | **Translated** — Sync optimizations |

## Implementation details

1. **State storage optimization** — Optimize state storage
2. **Major rooms refactor** — Major refactor of rooms storage
3. **Sync improvements** — Sync optimizations

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
