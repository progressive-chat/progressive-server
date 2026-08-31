# Step 453 — "Generalize RumaHandler" (Conduit `a5757ab`)

Source: [`timokoesters/conduit@a5757ab`](https://github.com/timokoesters/conduit/commit/a5757ab) (2022-02)

## What changed vs step 452

| Rust change | C++ translation |
|---|---|
| Generalize RumaHandler. Framework handler abstraction. 1 file changed. | **No-op for us** — Rust axum handler abstraction — our httplib is different. |

## Implementation details

- Rust axum handler abstraction — our httplib is different.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
