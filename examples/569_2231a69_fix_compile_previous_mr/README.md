# Step 569 — "fix: make previous MR compile" (Conduit `2231a69`)

Source: [`timokoesters/conduit@2231a69`](https://github.com/timokoesters/conduit/commit/2231a69) (2022-10)

## What changed vs step 568

| Rust change | C++ translation |
|---|---|
| Fix: make previous MR compile. Compilation fix for merge request. | **No-op for us** — Rust compile fix — N/A for C++. |

## Implementation details

- Rust compile fix — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
