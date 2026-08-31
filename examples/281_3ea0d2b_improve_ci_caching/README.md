# Step 281 — "Try to improve CI build times by caching" (Conduit `3ea0d2b`)

Source: [`timokoesters/conduit@3ea0d2b`](https://github.com/timokoesters/conduit/commit/3ea0d2b) (2021-05)

## What changed vs step 280

| Rust change | C++ translation |
|---|---|
| Try to improve CI build times by caching. CI optimization. | **No-op for us** — CI/CD optimization — N/A for C++. |

## Implementation details

- CI/CD optimization — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
