# Step 539 — "fix: don't panic on missing events in state" (Conduit `d1e5acd`)

Source: [`timokoesters/conduit@d1e5acd`](https://github.com/timokoesters/conduit/commit/d1e5acd) (2022-10)

## What changed vs step 538

| Rust change | C++ translation |
|---|---|
| Fix: don't panic on missing events in state. Handle missing state events gracefully. | **Translated** — Our state resolution (step 83) handles missing events. This prevents a Rust panic. |

## Implementation details

- Our state resolution (step 83) handles missing events. This prevents a Rust panic.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
