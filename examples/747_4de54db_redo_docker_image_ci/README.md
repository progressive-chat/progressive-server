# Step 747 — "redo docker image and build it in ci" (Conduit `4de54db`)

Source: [`timokoesters/conduit@4de54db`](https://github.com/timokoesters/conduit/commit/4de54db) (2024-01)

## What changed vs step 746

| Rust change | C++ translation |
|---|---|
| Redo docker image and build it in ci. Docker CI rebuild. 3 files changed. | **Skipped** — Docker CI only. |

## Implementation details

- Docker CI only.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
