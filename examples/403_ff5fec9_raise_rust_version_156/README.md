# Step 403 — "Raise minimum supported Rust version to 1.56" (Conduit `ff5fec9`)

Source: [`timokoesters/conduit@ff5fec9`](https://github.com/timokoesters/conduit/commit/ff5fec9) (2022-01)

## What changed vs step 402

| Rust change | C++ translation |
|---|---|
| Raise minimum supported Rust version to 1.56. MSRV bump. | **No-op for us** — Rust version bump — our C++ uses C++17. |

## Implementation details

- Rust version bump — our C++ uses C++17.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
