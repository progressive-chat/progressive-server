# Step 601 — "tweak default rocksdb settings" (Conduit `76a8233`)

Source: [`timokoesters/conduit@76a8233`](https://github.com/timokoesters/conduit/commit/76a8233) (2022-12)

## What changed vs step 600

| Rust change | C++ translation |
|---|---|
| Tweak default rocksdb settings. RocksDB configuration tuning. 1 file changed. | **Translated** — Related to step 359/360 (rocksdb). This tweaks defaults. |

## Implementation details

- Related to step 359/360 (rocksdb). This tweaks defaults.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
