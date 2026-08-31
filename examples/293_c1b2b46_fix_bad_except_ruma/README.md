# Step 293 — "fix: bad except in ruma wrapper" (Conduit `c1b2b46`)

Source: [`timokoesters/conduit@c1b2b46`](https://github.com/timokoesters/conduit/commit/c1b2b46) (2021-05)

## What changed vs step 292

| Rust change | C++ translation |
|---|---|
| Fix: bad except in ruma wrapper. Rust exception handling fix. | **No-op for us** — Rust error handling internals — N/A for C++. |

## Implementation details

- Rust error handling internals — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
