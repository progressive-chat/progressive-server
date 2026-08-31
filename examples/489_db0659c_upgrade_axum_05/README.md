# Step 489 — "Upgrade axum to 0.5" (Conduit `db0659c`)

Source: [`timokoesters/conduit@db0659c`](https://github.com/timokoesters/conduit/commit/db0659c) (2022-03)

## What changed vs step 488

| Rust change | C++ translation |
|---|---|
| Upgrade axum to 0.5. Web framework version upgrade. 3 files changed. | **No-op for us** — Rust axum upgrade — our httplib is different. |

## Implementation details

- Rust axum upgrade — our httplib is different.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
