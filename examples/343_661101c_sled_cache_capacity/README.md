# Step 343 — "add sled cache_capacity back" (Conduit `661101c`)

Source: [`timokoesters/conduit@661101c`](https://github.com/timokoesters/conduit/commit/661101c) (2021-07)

## What changed vs step 342

| Rust change | C++ translation |
|---|---|
| Add sled cache_capacity back. Database cache size configuration. 3 files changed. | **Translated** — Our sled config can set cache capacity. This restores the option. |

## Implementation details

- Our sled config can set cache capacity. This restores the option.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
