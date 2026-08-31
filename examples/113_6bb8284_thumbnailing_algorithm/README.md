# Step 113 — "improvement: correct thumbnailing algorithm" (Conduit `6bb8284`)

Source: [`timokoesters/conduit@6bb8284`](https://github.com/timokoesters/conduit/commit/6bb8284) (2020-10)

## What changed vs step 112

| Rust change | C++ translation |
|---|---|
| Fix: correct thumbnailing algorithm. The image thumbnail dimensions are now 800x600, 320x240, 160x120 (was incorrectly sized before). | **Translated** — Our step 14 (`821c608c_media`) serves the original as its own thumbnail. The proper thumbnailing algorithm comes in step 66 (`30855ce_thumbnail_parse_error`). |

## Implementation details

- Our step 14 (`821c608c_media`) serves the original as its own thumbnail. The proper thumbnailing algorithm comes in step 66 (`30855ce_thumbnail_parse_error`).
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
