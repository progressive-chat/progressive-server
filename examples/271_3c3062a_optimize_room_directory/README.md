# Step 271 — "improvement: optimize room directory" (Conduit `3c3062a`)

Source: [`timokoesters/conduit@3c3062a`](https://github.com/timokoesters/conduit/commit/3c3062a) (2021-04)

## What changed vs step 270

| Rust change | C++ translation |
|---|---|
| Improvement: optimize room directory. Faster room directory queries. 1 file changed. | **Translated** — Our room directory (step 253 `eedac4f_make_join_send_join_directory`) queries rooms. This optimizes it. |

## Implementation details

- Our room directory (step 253 `eedac4f_make_join_send_join_directory`) queries rooms. This optimizes it.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
