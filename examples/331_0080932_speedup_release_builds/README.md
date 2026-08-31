# Step 331 — "Speed up release builds" (Conduit `0080932`)

Source: [`timokoesters/conduit@0080932`](https://github.com/timokoesters/conduit/commit/0080932) (2021-07)

## What changed vs step 330

| Rust change | C++ translation |
|---|---|
| Speed up release builds. Compiler optimization flags for faster builds. | **No-op for us** — Rust compiler flags — our CMake handles optimization. |

## Implementation details

- Rust compiler flags — our CMake handles optimization.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
