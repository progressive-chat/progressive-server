# Step 525 — "127 errors left" (Conduit `44fe6d1`)

Source: [`timokoesters/conduit@44fe6d1`](https://github.com/timokoesters/conduit/commit/44fe6d1) (2022-10)

## What changed vs step 524

| Rust change | C++ translation |
|---|---|
| 127 errors left. Progress tracking. 65 files changed. | **No-op for us** — Rust refactor progress — N/A for C++. |

## Implementation details

- Rust refactor progress — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
