# Step 526 — "37 errors left" (Conduit `33a2b2b`)

Source: [`timokoesters/conduit@33a2b2b`](https://github.com/timokoesters/conduit/commit/33a2b2b) (2022-10)

## What changed vs step 525

| Rust change | C++ translation |
|---|---|
| 37 errors left. Progress tracking. 19 files changed. | **No-op for us** — Rust refactor progress — N/A for C++. |

## Implementation details

- Rust refactor progress — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
