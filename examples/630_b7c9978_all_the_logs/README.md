# Step 630 — "All the logs" (Conduit `b7c9978`)

Source: [`timokoesters/conduit@b7c9978`](https://github.com/timokoesters/conduit/commit/b7c9978) (2023-03)

## What changed vs step 629

| Rust change | C++ translation |
|---|---|
| All the logs. Comprehensive logging addition. 2 files changed. | **No-op for us** — Comprehensive logging — our logging is simpler. |

## Implementation details

- Comprehensive logging — our logging is simpler.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
