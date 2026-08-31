# Step 115 — "feat: configurable cache capacity" (Conduit `6b3934e`)

Source: [`timokoesters/conduit@6b3934e`](https://github.com/timokoesters/conduit/commit/6b3934e) (2020-10)

## What changed vs step 114

| Rust change | C++ translation |
|---|---|
| Adds configurable cache capacity (image cache, DNS cache, etc.). | **No-op for us** — Our sled adapter doesn't have explicit cache configuration. The default sled cache is fine. |

## Implementation details

- Our sled adapter doesn't have explicit cache configuration. The default sled cache is fine.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
