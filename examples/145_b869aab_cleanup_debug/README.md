# Step 145 — "Cleanup removing debug printing and logging, append non state events" (Conduit `b869aab`)

Source: [`timokoesters/conduit@b869aab`](https://github.com/timokoesters/conduit/commit/b869aab) (2020-12)

## What changed vs step 144

| Rust change | C++ translation |
|---|---|
| Cleanup: remove debug printing and logging, append non-state events. | **No-op for us** — Our logging is intentional (via std::cerr in handlers). The debug cleanup is a Rust-specific concern. |

## Implementation details

- Our logging is intentional (via std::cerr in handlers). The debug cleanup is a Rust-specific concern.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
