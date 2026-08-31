# Step 128 — "fix: logging thread crash when admin room does not exist" (Conduit `e691e88`)

Source: [`timokoesters/conduit@e691e88`](https://github.com/timokoesters/conduit/commit/e691e88) (2020-12)

## What changed vs step 127

| Rust change | C++ translation |
|---|---|
| Fix: logging thread crash when admin room does not exist. Checks if admin room exists before logging to it. | **Translated** — Our admin subsystem (step 60) handles missing admin room gracefully. |

## Implementation details

- Our admin subsystem (step 60) handles missing admin room gracefully.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
