# Step 629 — "Even more logging" (Conduit `2316d89`)

Source: [`timokoesters/conduit@2316d89`](https://github.com/timokoesters/conduit/commit/2316d89) (2023-03)

## What changed vs step 628

| Rust change | C++ translation |
|---|---|
| Even more logging. Additional debug logging. | **No-op for us** — Extra logging — our logging is controlled. |

## Implementation details

- Extra logging — our logging is controlled.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
