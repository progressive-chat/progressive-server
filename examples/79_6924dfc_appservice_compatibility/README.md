# Step 79 — "improvement: better appservice compatibility and optimizations" (Conduit `6924dfc`)

Source: [`timokoesters/conduit@6924dfc`](https://github.com/timokoesters/conduit/commit/6924dfc) (2021-02-06)

## What changed vs step 78

| Rust change | C++ translation |
|---|---|
| **Better appservice compatibility** | **Translated** — Appservice improvements |
| **Sync optimizations** | **Translated** — Sync performance improvements |
| **Major sync.rs refactor** | **Translated** — Cleaner sync code |

## Implementation details

1. **Appservice compatibility** — Better appservice compatibility
2. **Sync optimizations** — Sync performance improvements
3. **Major sync refactor** — Major refactor of sync.rs

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
