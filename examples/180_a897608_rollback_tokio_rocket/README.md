# Step 180 — "Roll back tokio and rocket update since ruma's request is at 0.2 tokio" (Conduit `a897608`)

Source: [`timokoesters/conduit@a897608`](https://github.com/timokoesters/conduit/commit/a897608) (2021-01)

## What changed vs step 179

| Rust change | C++ translation |
|---|---|
| Roll back tokio and rocket update since ruma's request is at 0.2 tokio. 4 files changed. | **Skipped** — Rust dependency version rollback — no code we can reuse. |

## Implementation details

- Rust dependency version rollback — no code we can reuse.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
