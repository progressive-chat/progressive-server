# Step 405 — "Use MSRV for build CI jobs" (Conduit `8d81c1c`)

Source: [`timokoesters/conduit@8d81c1c`](https://github.com/timokoesters/conduit/commit/8d81c1c) (2022-01)

## What changed vs step 404

| Rust change | C++ translation |
|---|---|
| Use MSRV for build CI jobs. CI configuration for minimum Rust version. | **No-op for us** — Rust CI — N/A for C++. |

## Implementation details

- Rust CI — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
