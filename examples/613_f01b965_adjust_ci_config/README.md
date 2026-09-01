# Step 613 — "fix: adjust CI config to runner requirements" (Conduit `f01b965`)

Source: [`timokoesters/conduit@f01b965`](https://github.com/timokoesters/conduit/commit/f01b965) (2023-01)

## What changed vs step 612

| Rust change | C++ translation |
|---|---|
| Fix: adjust CI config to runner requirements. CI configuration. | **No-op for us** — Rust CI — N/A for C++. |

## Implementation details

- Rust CI — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
