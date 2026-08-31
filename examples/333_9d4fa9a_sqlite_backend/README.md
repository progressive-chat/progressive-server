# Step 333 — "Sqlite" (Conduit `9d4fa9a`)

Source: [`timokoesters/conduit@9d4fa9a`](https://github.com/timokoesters/conduit/commit/9d4fa9a) (2021-07)

## What changed vs step 332

| Rust change | C++ translation |
|---|---|
| Sqlite database backend. Add SQLite as a database backend option. 49 files changed. MAJOR feature. | **Translated** — Related to step 307 (swappable DB backend). SQLite is a new backend option. |

## Implementation details

- Related to step 307 (swappable DB backend). SQLite is a new backend option.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
