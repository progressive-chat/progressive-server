# Step 396 — "CI: Fix cargo-test" (Conduit `10f1da1`)

Source: [`timokoesters/conduit@10f1da1`](https://github.com/timokoesters/conduit/commit/10f1da1) (2022-01)

## What changed vs step 395

| Rust change | C++ translation |
|---|---|
| CI: Fix cargo-test. Rust test configuration fix. | **No-op for us** — Rust CI test — N/A for C++. |

## Implementation details

- Rust CI test — N/A for C++.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
