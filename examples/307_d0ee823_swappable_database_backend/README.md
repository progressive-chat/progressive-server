# Step 307 — "feat: swappable database backend" (Conduit `d0ee823`)

Source: [`timokoesters/conduit@d0ee823`](https://github.com/timokoesters/conduit/commit/d0ee823) (2021-06)

## What changed vs step 306

| Rust change | C++ translation |
|---|---|
| Feat: swappable database backend. Abstract database layer to support sled, rocksdb, sqlite. 47 files changed. MAJOR architectural change. | **Translated** — Our database is sled-only. This abstraction would allow multiple backends. |

## Implementation details

- Our database is sled-only. This abstraction would allow multiple backends.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
