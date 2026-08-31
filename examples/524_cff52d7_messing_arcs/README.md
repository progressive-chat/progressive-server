# Step 524 — "messing around with arcs" (Conduit `cff52d7`)

Source: [`timokoesters/conduit@cff52d7`](https://github.com/timokoesters/conduit/commit/cff52d7) (2022-10)

## What changed vs step 523

| Rust change | C++ translation |
|---|---|
| Messing around with arcs. Arc (atomic reference counting) experimentation. 77 files changed. | **No-op for us** — Rust Arc experimentation — our C++ uses shared_ptr. |

## Implementation details

- Rust Arc experimentation — our C++ uses shared_ptr.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
