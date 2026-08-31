# Step 454 — "Fix axum route conflicts" (Conduit `7bf538f`)

Source: [`timokoesters/conduit@7bf538f`](https://github.com/timokoesters/conduit/commit/7bf538f) (2022-02)

## What changed vs step 453

| Rust change | C++ translation |
|---|---|
| Fix axum route conflicts. Route registration fixes after Rocket->axum migration. 1 file changed. | **No-op for us** — Rust axum routing — our httplib routes don't conflict. |

## Implementation details

- Rust axum routing — our httplib routes don't conflict.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
