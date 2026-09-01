# Step 689 — "slightly better sliding sync" (Conduit `caddc65`)

Source: [`timokoesters/conduit@caddc65`](https://github.com/timokoesters/conduit/commit/caddc65) (2023-07)

## What changed vs step 688

| Rust change | C++ translation |
|---|---|
| Slightly better sliding sync. Sliding sync improvements. 4 files changed. | **Translated** — Follows step 670 (sliding sync). This improves the implementation. |

## Implementation details

- Follows step 670 (sliding sync). This improves the implementation.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
