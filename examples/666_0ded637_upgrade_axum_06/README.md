# Step 666 — "Upgrade axum to 0.6" (Conduit `0ded637`)

Source: [`timokoesters/conduit@0ded637`](https://github.com/timokoesters/conduit/commit/0ded637) (2023-06)

## What changed vs step 665

| Rust change | C++ translation |
|---|---|
| Upgrade axum to 0.6. Web framework version upgrade. 4 files changed. | **No-op for us** — Rust axum upgrade — our httplib is different. |

## Implementation details

- Rust axum upgrade — our httplib is different.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
