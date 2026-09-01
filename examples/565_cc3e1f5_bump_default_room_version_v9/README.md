# Step 565 — "Bump default room version to V9; per matrix spec recommendation" (Conduit `cc3e1f5`)

Source: [`timokoesters/conduit@cc3e1f5`](https://github.com/timokoesters/conduit/commit/cc3e1f5) (2022-10)

## What changed vs step 564

| Rust change | C++ translation |
|---|---|
| Bump default room version to V9; per matrix spec recommendation. New default room version. 3 files changed. | **Translated** — Our room versions (steps 80-87) support up to v4. v9 is newer. |

## Implementation details

- Our room versions (steps 80-87) support up to v4. v9 is newer.
- No external Rust dependencies carried over (Cargo.toml changes are skipped)

## Smoke test

```console
$ cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
$ ./build/server & ./build/tests
```
