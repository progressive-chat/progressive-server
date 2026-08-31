# Step 484 — "fix(ci): Fix musl builds" (Conduit `5a9462c`)

Source: [`timokoesters/conduit@5a9462c`](https://github.com/timokoesters/conduit/commit/5a9462c) (2022-03)

## What changed vs step 483

| Rust change | C++ translation |
|---|---|
| Fix(ci): Fix musl builds. CI fix for musl libc builds. 2 files changed. | **No-op for us** — Rust musl CI — our C++ doesn't target musl. |

## Implementation details

- Rust musl CI — our C++ doesn't target musl.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
