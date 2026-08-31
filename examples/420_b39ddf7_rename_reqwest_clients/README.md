# Step 420 — "Rename reqwest clients, mention cheap client clones in comment" (Conduit `b39ddf7`)

Source: [`timokoesters/conduit@b39ddf7`](https://github.com/timokoesters/conduit/commit/b39ddf7) (2022-01)

## What changed vs step 419

| Rust change | C++ translation |
|---|---|
| Rename reqwest clients, mention cheap client clones in comment. HTTP client naming and documentation. 4 files changed. | **No-op for us** — Rust reqwest client naming — our httplib is different. |

## Implementation details

- Rust reqwest client naming — our httplib is different.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
