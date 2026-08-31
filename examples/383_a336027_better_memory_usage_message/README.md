# Step 383 — "fix: better memory usage message" (Conduit `a336027`)

Source: [`timokoesters/conduit@a336027`](https://github.com/timokoesters/conduit/commit/a336027) (2022-01)

## What changed vs step 382

| Rust change | C++ translation |
|---|---|
| Fix: better memory usage message. Improve memory reporting output. | **Translated** — Related to steps 375-378. Better formatting for memory reports. |

## Implementation details

- Related to steps 375-378. Better formatting for memory reports.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
