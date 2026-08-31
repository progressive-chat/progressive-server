# Step 374 — "feat: database backend selection at runtime" (Conduit `fa6d7f7`)

Source: [`timokoesters/conduit@fa6d7f7`](https://github.com/timokoesters/conduit/commit/fa6d7f7) (2022-01)

## What changed vs step 373

| Rust change | C++ translation |
|---|---|
| Feat: database backend selection at runtime. Choose DB backend (sled/rocksdb/sqlite) at startup. 7 files changed. MAJOR feature. | **Translated** — Related to step 307 (swappable DB backend). This adds runtime selection. |

## Implementation details

- Related to step 307 (swappable DB backend). This adds runtime selection.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
