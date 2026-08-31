# Step 477 — "Log caught Ctrl+C or SIGTERM for operator feedback" (Conduit `3b2b35a`)

Source: [`timokoesters/conduit@3b2b35a`](https://github.com/timokoesters/conduit/commit/3b2b35a) (2022-02)

## What changed vs step 476

| Rust change | C++ translation |
|---|---|
| Log caught Ctrl+C or SIGTERM for operator feedback. Graceful shutdown logging. | **Translated** — Our server handles SIGTERM. This adds logging for operator feedback. |

## Implementation details

- Our server handles SIGTERM. This adds logging for operator feedback.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
